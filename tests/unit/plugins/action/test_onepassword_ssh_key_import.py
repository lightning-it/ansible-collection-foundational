import json

import pytest

from ansible.errors import AnsibleActionFail

from plugins.action import onepassword_ssh_key_import as plugin
from tests.unit.plugins.action.test_onepassword_ssh_key_item import (
    ACCOUNT_ID,
    FINGERPRINT,
    SUBJECT,
    USER_UUID,
    VAULT_ID,
)


def _private_key(tmp_path, mode=0o600):
    path = tmp_path / "source-key"
    path.write_text(
        "-----BEGIN OPENSSH PRIVATE KEY-----\n"
        "synthetic-unit-test-only\n"
        "-----END OPENSSH PRIVATE KEY-----\n",
        encoding="ascii",
    )
    path.chmod(mode)
    return path


def _arguments(tmp_path, **overrides):
    arguments = {
        "action": "plan",
        "cli_path": "/usr/local/bin/op",
        "cli_sha256": "0" * 64,
        "cli_version": "2.38.1",
        "account_id": ACCOUNT_ID,
        "account_sign_in_address": "example.1password.com",
        "authorized_user_uuids": [USER_UUID],
        "vault_id": VAULT_ID,
        "item_id": "",
        "item_version": 0,
        "item_title": "svc_ansible@example.test",
        "category": "SSH Key",
        "tags": ["approval-authority", "automation", "ssh"],
        "subject": SUBJECT,
        "schema_version": 1,
        "key_type": "ed25519",
        "expected_fingerprint": FINGERPRINT,
        "allow_import": False,
        "confirmation": "",
        "private_key_path": str(_private_key(tmp_path)),
        "ssh_add_path": "/usr/bin/ssh-add",
        "ssh_add_sha256": "1" * 64,
        "ssh_keygen_path": "/usr/bin/ssh-keygen",
        "ssh_keygen_sha256": "2" * 64,
        "agent_socket_path": "/tmp/onepassword-agent.sock",
    }
    arguments.update(overrides)
    return arguments


def test_plan_normalizes_exact_source_and_target(tmp_path):
    config = plugin._normalize_import_arguments(_arguments(tmp_path))
    assert config["action"] == "plan"
    assert config["expected_fingerprint"] == FINGERPRINT
    assert config["private_key_path"] == str(tmp_path / "source-key")


def test_apply_requires_exact_fingerprint_bound_confirmation(tmp_path):
    arguments = _arguments(tmp_path, action="apply", allow_import=True)
    with pytest.raises(AnsibleActionFail):
        plugin._normalize_import_arguments(arguments)

    arguments["confirmation"] = "IMPORT-ONEPASSWORD-SSH-KEY:{0}:{1}".format(
        SUBJECT, FINGERPRINT
    )
    assert plugin._normalize_import_arguments(arguments)["action"] == "apply"


def test_private_key_must_be_owner_only(tmp_path):
    path = tmp_path / "insecure-source-key"
    path.write_text(
        "-----BEGIN OPENSSH PRIVATE KEY-----\n"
        "synthetic-unit-test-only\n"
        "-----END OPENSSH PRIVATE KEY-----\n",
        encoding="ascii",
    )
    path.chmod(0o640)
    with pytest.raises(AnsibleActionFail):
        plugin._normalize_import_arguments(
            _arguments(tmp_path, private_key_path=str(path))
        )


def test_import_template_keeps_private_key_out_of_arguments():
    class Client:
        def __init__(self):
            self.arguments = None
            self.payload = None

        @staticmethod
        def metadata(arguments, operation):
            assert arguments == [
                "item",
                "template",
                "get",
                "SSH Key",
                "--format",
                "json",
            ]
            assert operation == "SSH Key template inspection"
            return {
                "category": "SSH_KEY",
                "fields": [
                    {
                        "id": "private_key",
                        "label": "private key",
                        "type": "SSHKEY",
                    }
                ],
            }

        def discard(self, arguments, operation, stdin_payload=None):
            self.arguments = list(arguments)
            self.payload = stdin_payload
            assert operation == "SSH private-key import"

    client = Client()
    config = {
        "account_id": ACCOUNT_ID,
        "vault_id": VAULT_ID,
        "item_title": "svc_ansible@example.test",
        "tags": ["automation", "ssh"],
        "subject": SUBJECT,
        "schema_version": 1,
    }
    private_key = b"-----BEGIN OPENSSH PRIVATE KEY-----\nprivate\n"
    plugin._import_template(client, config, private_key)

    assert b"private" in client.payload
    assert "private" not in " ".join(client.arguments)
    parsed = json.loads(client.payload.decode("ascii"))
    assert parsed["fields"][0]["value"] == private_key.decode("ascii")
