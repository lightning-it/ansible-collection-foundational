import base64
import hashlib
import socket
import struct
import sys

import pytest

from ansible.errors import AnsibleActionFail

from plugins.action import onepassword_ssh_key_item as plugin


ACCOUNT_ID = "a" * 26
VAULT_ID = "v" * 26
ITEM_ID = "i" * 26
ITEM_VERSION = 1
SUBJECT = "host01.example.test"
KEY_BLOB = (
    struct.pack(">I", len(b"ssh-ed25519"))
    + b"ssh-ed25519"
    + struct.pack(">I", 32)
    + (b"K" * 32)
)
PUBLIC_KEY = "ssh-ed25519 {0} recovery@test".format(
    base64.b64encode(KEY_BLOB).decode("ascii")
)
FINGERPRINT = "SHA256:{0}".format(
    base64.b64encode(hashlib.sha256(KEY_BLOB).digest()).decode("ascii").rstrip("=")
)


def _arguments(**overrides):
    arguments = {
        "operation": "plan",
        "cli_path": "/usr/local/bin/op",
        "cli_version": "2.38.1",
        "account_id": ACCOUNT_ID,
        "account_sign_in_address": "example.1password.com",
        "vault_id": VAULT_ID,
        "item_id": "",
        "item_version": 0,
        "item_title": "host01.example.test Dropbear recovery",
        "category": "SSH Key",
        "tags": ["breakglass", "recovery"],
        "subject": SUBJECT,
        "schema_version": 1,
        "key_type": "ed25519",
        "expected_fingerprint": "",
        "allow_create": False,
        "confirmation": "",
        "ssh_add_path": "/usr/bin/ssh-add",
        "ssh_keygen_path": "/usr/bin/ssh-keygen",
        "agent_socket_path": "/tmp/onepassword-agent.sock",
    }
    arguments.update(overrides)
    return arguments


class _FakeClient:
    def __init__(self, exists=False, fingerprint=FINGERPRINT):
        self.exists = exists
        self.fingerprint = fingerprint
        self.calls = []

    def _run(self, arguments, operation, discard_stdout=False):
        self.calls.append((list(arguments), operation, discard_stdout))
        return b"2.38.1\n"

    def metadata(self, arguments, operation):
        self.calls.append((list(arguments), operation, False))
        assert "private" not in " ".join(arguments).lower()
        assert "--reveal" not in arguments
        if arguments[0] == "whoami":
            return {"account_uuid": ACCOUNT_ID, "url": "example.1password.com"}
        if arguments[:2] == ["vault", "get"]:
            return {"id": VAULT_ID}
        if arguments[:2] == ["item", "list"]:
            if not self.exists:
                return []
            return [
                {
                    "id": ITEM_ID,
                    "version": ITEM_VERSION,
                    "title": "host01.example.test Dropbear recovery",
                    "category": "SSH_KEY",
                    "tags": ["breakglass", "recovery"],
                }
            ]
        if arguments[:2] == ["item", "get"]:
            return [
                {"label": "subject", "value": SUBJECT},
                {"label": "schema_version", "value": "1"},
                {"label": "public key", "value": PUBLIC_KEY},
                {"label": "fingerprint", "value": self.fingerprint},
            ]
        raise AssertionError("unexpected metadata request")

    def discard(self, arguments, operation):
        self.calls.append((list(arguments), operation, True))
        assert "--category=ssh" in arguments
        assert "--ssh-generate-key=ed25519" in arguments
        assert "private" not in " ".join(arguments).lower()
        self.exists = True


def test_apply_generates_key_inside_onepassword_and_returns_only_public_identity(monkeypatch):
    client = _FakeClient(exists=False)
    monkeypatch.setattr(
        plugin._OnePasswordSSHKeyItemStore,
        "verify_agent",
        staticmethod(
            lambda config, identity: identity["fingerprint"] == FINGERPRINT
        ),
    )
    result = plugin._OnePasswordSSHKeyItemStore(client).run(
        plugin._normalize_arguments(
            _arguments(
                operation="apply",
                allow_create=True,
                confirmation="CREATE-ONEPASSWORD-SSH-KEY:" + SUBJECT,
            )
        )
    )

    assert result == {
        "changed": True,
        "created": True,
        "exists": True,
        "item_id": ITEM_ID,
        "item_version": ITEM_VERSION,
        "planned": False,
        "public_key": PUBLIC_KEY,
        "fingerprint": FINGERPRINT,
        "agent_verified": True,
    }
    assert "private" not in repr(result).lower()
    assert [call for call in client.calls if call[1] == "SSH item creation"]


def test_read_public_requires_pinned_item_id_and_fingerprint():
    with pytest.raises(AnsibleActionFail):
        plugin._normalize_arguments(_arguments(operation="read_public"))


def test_fingerprint_is_recomputed_and_mismatch_fails_closed():
    client = _FakeClient(exists=True, fingerprint="SHA256:wrong")
    with pytest.raises(AnsibleActionFail):
        plugin._OnePasswordSSHKeyItemStore(client).run(
            plugin._normalize_arguments(
                _arguments(
                    operation="read_public",
                    item_id=ITEM_ID,
                    item_version=ITEM_VERSION,
                    expected_fingerprint=FINGERPRINT,
                )
            )
        )


def test_check_mode_apply_does_not_generate_a_key():
    client = _FakeClient(exists=False)
    result = plugin._OnePasswordSSHKeyItemStore(client).run(
        plugin._normalize_arguments(
            _arguments(
                operation="apply",
                allow_create=True,
                confirmation="CREATE-ONEPASSWORD-SSH-KEY:" + SUBJECT,
            )
        ),
        check_mode=True,
    )
    assert result["planned"] is True
    assert not [call for call in client.calls if call[1] == "SSH item creation"]


def test_apply_rejects_a_preexisting_unpinned_key():
    client = _FakeClient(exists=True)
    with pytest.raises(AnsibleActionFail):
        plugin._OnePasswordSSHKeyItemStore(client).run(
            plugin._normalize_arguments(
                _arguments(
                    operation="apply",
                    allow_create=True,
                    confirmation="CREATE-ONEPASSWORD-SSH-KEY:" + SUBJECT,
                )
            )
        )


def test_agent_verification_requires_exact_socket_and_public_identity(tmp_path):
    agent_socket_path = tmp_path / "agent.sock"
    agent_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    agent_socket.bind(str(agent_socket_path))
    ssh_add = tmp_path / "ssh-add"
    ssh_add.write_text(
        "#!{0}\nprint({1!r})\n".format(sys.executable, PUBLIC_KEY),
        encoding="utf-8",
    )
    ssh_add.chmod(0o700)
    ssh_keygen = tmp_path / "ssh-keygen"
    challenge_marker = tmp_path / "challenge-proof"
    ssh_keygen.write_text(
        "#!{0}\n"
        "import pathlib, sys\n"
        "mode = sys.argv[sys.argv.index('-Y') + 1]\n"
        "challenge = sys.stdin.buffer.read()\n"
        "with pathlib.Path({1!r}).open('a', encoding='ascii') as stream:\n"
        "    stream.write(mode + '\\n')\n"
        "if len(challenge) != 32:\n"
        "    raise SystemExit(8)\n"
        "if mode == 'sign':\n"
        "    sys.stdout.write('-----BEGIN SSH SIGNATURE-----\\nFAKE\\n-----END SSH SIGNATURE-----\\n')\n"
        "elif mode == 'verify':\n"
        "    signature = pathlib.Path(sys.argv[sys.argv.index('-s') + 1]).read_text(encoding='ascii')\n"
        "    if signature != '-----BEGIN SSH SIGNATURE-----\\nFAKE\\n-----END SSH SIGNATURE-----\\n':\n"
        "        raise SystemExit(9)\n"
        "else:\n"
        "    raise SystemExit(10)\n".format(
            sys.executable,
            str(challenge_marker),
        ),
        encoding="utf-8",
    )
    ssh_keygen.chmod(0o700)
    config = plugin._normalize_arguments(
        _arguments(
            operation="verify_agent",
            item_id=ITEM_ID,
            item_version=ITEM_VERSION,
            expected_fingerprint=FINGERPRINT,
            ssh_add_path=str(ssh_add),
            ssh_keygen_path=str(ssh_keygen),
            agent_socket_path=str(agent_socket_path),
        )
    )
    try:
        assert plugin._OnePasswordSSHKeyItemStore.verify_agent(
            config,
            {"public_key": PUBLIC_KEY, "fingerprint": FINGERPRINT},
        )
        assert challenge_marker.read_text(encoding="ascii").splitlines() == [
            "sign",
            "verify",
        ]
    finally:
        agent_socket.close()


@pytest.mark.parametrize(
    "overrides",
    [
        {"key_type": "rsa"},
        {"category": "Password"},
        {"tags": ["recovery", "recovery"]},
        {"tags": []},
        {"item_id": ITEM_ID},
        {"item_version": ITEM_VERSION},
        {"operation": "apply", "allow_create": True, "confirmation": "wrong"},
        {
            "operation": "read_public",
            "item_id": ITEM_ID,
            "item_version": ITEM_VERSION,
            "expected_fingerprint": "SHA256:wrong",
        },
    ],
)
def test_invalid_ssh_key_contracts_fail_before_cli_use(overrides):
    with pytest.raises(AnsibleActionFail):
        plugin._normalize_arguments(_arguments(**overrides))
