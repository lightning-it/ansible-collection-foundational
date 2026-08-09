import os
import stat
import sys
from types import SimpleNamespace

import pytest

from ansible.errors import AnsibleActionFail

from plugins.action import onepassword_ssh_secret_stdin as plugin


ACCOUNT_ID = "a" * 26
VAULT_ID = "v" * 26
PASSWORD_ITEM_ID = "p" * 26
PASSWORD_ITEM_VERSION = 1
SSH_ITEM_ID = "i" * 26
SSH_ITEM_VERSION = 1
SUBJECT = "host01.example.test"
FINGERPRINT = "SHA256:" + ("A" * 43)
SECRET = b"S" * 64
PUBLIC_KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFNTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NT test"


def _arguments(tmp_path, **overrides):
    arguments = {
        "cli_path": "/usr/local/bin/op",
        "cli_version": "2.38.1",
        "account_id": ACCOUNT_ID,
        "account_sign_in_address": "example.1password.com",
        "vault_id": VAULT_ID,
        "password_item_id": PASSWORD_ITEM_ID,
        "password_item_version": PASSWORD_ITEM_VERSION,
        "password_item_title": SUBJECT + " LUKS recovery",
        "password_field_id": "password",
        "password_tags": ["breakglass", "recovery"],
        "password_length": 64,
        "ssh_item_id": SSH_ITEM_ID,
        "ssh_item_version": SSH_ITEM_VERSION,
        "ssh_item_title": SUBJECT + " Dropbear recovery",
        "ssh_tags": ["breakglass", "recovery"],
        "ssh_expected_fingerprint": FINGERPRINT,
        "subject": SUBJECT,
        "schema_version": 1,
        "ssh_path": str(tmp_path / "ssh"),
        "ssh_add_path": str(tmp_path / "ssh-add"),
        "ssh_keygen_path": str(tmp_path / "ssh-keygen"),
        "agent_socket_path": str(tmp_path / "agent.sock"),
        "known_hosts_path": str(tmp_path / "known_hosts"),
        "destination_host": SUBJECT,
        "destination_user": "root",
        "destination_port": 2222,
        "remote_command": "/bin/cryptroot-unlock",
        "confirmation": "UNLOCK:" + SUBJECT,
    }
    arguments.update(overrides)
    return arguments


def _write_executable(path, source):
    path.write_text("#!{0}\n{1}".format(sys.executable, source), encoding="utf-8")
    path.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)


def test_consumer_keeps_secret_out_of_result_and_process_arguments(tmp_path, monkeypatch):
    marker = tmp_path / "ssh-success"
    op_path = tmp_path / "op"
    ssh_path = tmp_path / "ssh"
    known_hosts_path = tmp_path / "known_hosts"
    known_hosts_path.write_text("synthetic host pin\n", encoding="utf-8")
    known_hosts_path.chmod(0o600)
    _write_executable(
        op_path,
        "import os, sys\n"
        "args = sys.argv[1:]\n"
        "descriptor = int(args[args.index('--out-file') + 1].rsplit('/', 1)[1])\n"
        "os.write(descriptor, {0!r})\n".format(SECRET),
    )
    _write_executable(
        ssh_path,
        "import pathlib, sys\n"
        "value = sys.stdin.buffer.read()\n"
        "required = {0!r}\n"
        "if not required.issubset(set(sys.argv[1:])):\n"
        "    raise SystemExit(7)\n"
        "if sys.argv[-1] != '/bin/cryptroot-unlock':\n"
        "    raise SystemExit(8)\n"
        "if value != {1!r}:\n"
        "    raise SystemExit(9)\n"
        "pathlib.Path({2!r}).write_text('ok', encoding='utf-8')\n".format(
            {
                "-T",
                "BatchMode=yes",
                "ClearAllForwardings=yes",
                "ControlMaster=no",
                "ControlPath=none",
                "ControlPersist=no",
                "GlobalKnownHostsFile=/dev/null",
                "IdentitiesOnly=yes",
                "KbdInteractiveAuthentication=no",
                "NumberOfPasswordPrompts=0",
                "PasswordAuthentication=no",
                "PreferredAuthentications=publickey",
                "ProxyCommand=none",
                "ProxyJump=none",
                "RequestTTY=no",
                "StrictHostKeyChecking=yes",
                "UpdateHostKeys=no",
            },
            SECRET,
            str(marker),
        ),
    )
    config = plugin._normalize_arguments(
        _arguments(tmp_path, cli_path=str(op_path), ssh_path=str(ssh_path))
    )
    fake_client = SimpleNamespace(
        binary=str(op_path),
        environment={"HOME": str(tmp_path), "PATH": os.environ["PATH"]},
    )
    monkeypatch.setattr(
        plugin,
        "_inspect_boundaries",
        lambda unused_config: (
            fake_client,
            {"public_key": PUBLIC_KEY, "fingerprint": FINGERPRINT},
        ),
    )
    monkeypatch.setattr(plugin, "_revalidate_password_item", lambda client, config: None)
    monkeypatch.setattr(
        plugin,
        "_revalidate_ssh_item",
        lambda client, config, public_identity: None,
    )

    result = plugin._consume(config)

    assert result["unlocked"] is True
    assert result["changed"] is True
    assert marker.read_text(encoding="utf-8") == "ok"
    assert SECRET.decode("ascii") not in repr(result)


def test_check_mode_never_reads_or_connects(tmp_path, monkeypatch):
    ssh_path = tmp_path / "ssh"
    known_hosts_path = tmp_path / "known_hosts"
    _write_executable(ssh_path, "raise SystemExit(99)\n")
    known_hosts_path.write_text("synthetic host pin\n", encoding="utf-8")
    known_hosts_path.chmod(0o600)
    config = plugin._normalize_arguments(_arguments(tmp_path, ssh_path=str(ssh_path)))
    monkeypatch.setattr(
        plugin,
        "_inspect_boundaries",
        lambda unused_config: (
            object(),
            {"public_key": PUBLIC_KEY, "fingerprint": FINGERPRINT},
        ),
    )

    result = plugin._consume(config, check_mode=True)

    assert result["unlocked"] is False
    assert result["changed"] is False


def test_ssh_identity_is_revalidated_after_secret_transport(monkeypatch):
    class _Store:
        @staticmethod
        def inspect(config):
            return {
                "exists": True,
                "item_id": config["item_id"],
                "item_version": config["item_version"],
            }

        @staticmethod
        def public_metadata(config, item_id, item_version):
            return {"public_key": PUBLIC_KEY, "fingerprint": "SHA256:" + ("B" * 43)}

    monkeypatch.setattr(plugin, "_OnePasswordSSHKeyItemStore", lambda client: _Store())
    ssh_config = {"item_id": SSH_ITEM_ID, "item_version": SSH_ITEM_VERSION}

    with pytest.raises(AnsibleActionFail):
        plugin._revalidate_ssh_item(
            object(),
            ssh_config,
            {"public_key": PUBLIC_KEY, "fingerprint": FINGERPRINT},
        )


def test_known_hosts_hard_link_is_rejected(tmp_path):
    ssh_path = tmp_path / "ssh"
    known_hosts_path = tmp_path / "known_hosts"
    second_link = tmp_path / "known_hosts.link"
    _write_executable(ssh_path, "raise SystemExit(99)\n")
    known_hosts_path.write_text("synthetic host pin\n", encoding="utf-8")
    known_hosts_path.chmod(0o600)
    os.link(known_hosts_path, second_link)
    config = plugin._normalize_arguments(_arguments(tmp_path, ssh_path=str(ssh_path)))

    with pytest.raises(AnsibleActionFail):
        plugin._validate_controller_paths(config)


@pytest.mark.parametrize(
    "overrides",
    [
        {"confirmation": "wrong"},
        {"ssh_expected_fingerprint": "SHA256:wrong"},
        {"password_item_id": "not-an-id"},
        {"password_item_version": 0},
        {"ssh_item_version": 0},
        {"password_tags": []},
        {"destination_port": 0},
        {"remote_command": "cryptroot-unlock"},
    ],
)
def test_invalid_contracts_fail_before_any_secret_read(tmp_path, overrides):
    with pytest.raises(AnsibleActionFail):
        plugin._normalize_arguments(_arguments(tmp_path, **overrides))
