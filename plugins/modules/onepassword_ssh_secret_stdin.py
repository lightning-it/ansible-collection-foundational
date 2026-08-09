# Copyright: (c) 2026, Lightning IT
# SPDX-License-Identifier: MIT

"""Documentation stub for the controller-local SSH secret-consumer action."""

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: onepassword_ssh_secret_stdin
short_description: Stream one pinned 1Password secret into one pinned SSH session
version_added: "1.34.0"
description:
  - Executes only through the controller-side action plugin.
  - Does not expose the Password value to Ansible variables, facts, output, or files.
options:
  cli_path:
    type: path
    required: true
  cli_sha256:
    type: str
    required: true
  cli_version:
    type: str
    required: true
  account_id:
    type: str
    required: true
  account_sign_in_address:
    type: str
    required: true
  authorized_user_uuids:
    type: list
    elements: str
    required: true
  vault_id:
    type: str
    required: true
  password_item_id:
    type: str
    required: true
  password_item_version:
    type: int
    required: true
  password_item_title:
    type: str
    required: true
  password_field_id:
    type: str
    default: password
  password_tags:
    type: list
    elements: str
    required: true
  password_length:
    type: int
    required: true
  ssh_item_id:
    type: str
    required: true
  ssh_item_version:
    type: int
    required: true
  ssh_item_title:
    type: str
    required: true
  ssh_tags:
    type: list
    elements: str
    required: true
  ssh_expected_fingerprint:
    type: str
    required: true
  subject:
    type: str
    required: true
  schema_version:
    type: int
    default: 1
  ssh_path:
    type: path
    required: true
  ssh_sha256:
    type: str
    required: true
  ssh_add_path:
    type: path
    required: true
  ssh_add_sha256:
    type: str
    required: true
  ssh_keygen_path:
    type: path
    required: true
  ssh_keygen_sha256:
    type: str
    required: true
  agent_socket_path:
    type: path
    required: true
  known_hosts_path:
    type: path
    required: true
  known_hosts_sha256:
    description: Complete lowercase SHA-256 digest of the exact known-hosts file.
    type: str
    required: true
  destination_host:
    type: str
    required: true
  destination_user:
    type: str
    default: root
  destination_port:
    type: int
    required: true
  destination_host_fingerprint:
    type: str
    required: true
  remote_command:
    type: str
    choices: [/bin/cryptroot-unlock]
    required: true
  approval_authority:
    description:
      - Independently configured Ed25519 Approval Authority with exact signer, file, verifier, and digest pins.
      - The fixed signature namespace is C(lit-onepassword-approval-v1).
      - Pins the one canonical controller-only replay directory that the approval must match exactly.
    type: dict
    required: true
  approval:
    description:
      - Expiring asymmetric signature over the complete normalized unlock contract.
      - Replay is global to the Authority, execution ID, and nonce, independent of target and payload.
    type: dict
    required: true
author:
  - Lightning IT (@lightning-it)
"""

EXAMPLES = r"""
---
- name: Validate the exact external recovery boundary in check mode
  lit.foundational.onepassword_ssh_secret_stdin:
    cli_path: /usr/local/bin/op
    cli_sha256: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    cli_version: 2.38.1
    account_id: aaaaaaaaaaaaaaaaaaaaaaaaaa
    account_sign_in_address: example.1password.com
    authorized_user_uuids: [uuuuuuuuuuuuuuuuuuuuuuuuuu]
    vault_id: vvvvvvvvvvvvvvvvvvvvvvvvvv
    password_item_id: pppppppppppppppppppppppppp
    password_item_version: 1
    password_item_title: host01.example.test LUKS recovery
    password_tags: [breakglass, recovery]
    password_length: 64
    ssh_item_id: iiiiiiiiiiiiiiiiiiiiiiiiii
    ssh_item_version: 1
    ssh_item_title: host01.example.test Dropbear recovery
    ssh_tags: [breakglass, recovery]
    ssh_expected_fingerprint: SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
    subject: host01.example.test
    ssh_path: /usr/bin/ssh
    ssh_sha256: bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
    ssh_add_path: /usr/bin/ssh-add
    ssh_add_sha256: cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
    ssh_keygen_path: /usr/bin/ssh-keygen
    ssh_keygen_sha256: dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd
    agent_socket_path: /absolute/path/to/1password/agent.sock
    known_hosts_path: /absolute/path/to/dropbear-known-hosts
    known_hosts_sha256: eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee
    destination_host: host01.example.test
    destination_port: 2222
    destination_host_fingerprint: SHA256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB
    remote_command: /bin/cryptroot-unlock
    approval_authority:
      schema_version: 1
      identity: approval-authority@example.test
      namespace: lit-onepassword-approval-v1
      fingerprint: SHA256:CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC
      allowed_signers_path: /absolute/controller-only/approval_allowed_signers
      allowed_signers_sha256: ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
      ssh_keygen_path: /usr/bin/ssh-keygen
      ssh_keygen_sha256: dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd
      replay_directory: /absolute/controller-only/approval-replay
    approval:
      schema_version: 1
      execution_id: unlock-20260809-001
      commit_shas: {foundational: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa}
      nonce: cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
      issued_at: "2026-08-09T10:00:00Z"
      expires_at: "2026-08-09T10:05:00Z"
      replay_directory: /absolute/controller-only/approval-replay
      signature: |
        -----BEGIN SSH SIGNATURE-----
        <base64-signature>
        -----END SSH SIGNATURE-----
  check_mode: true
"""

RETURN = r"""
unlocked:
  type: bool
  returned: always
  description: Whether the guarded SSH stdin operation completed successfully.
password_item_id:
  type: str
  returned: always
  description: Validated non-sensitive Password item ID.
password_item_version:
  type: int
  returned: always
  description: Validated non-sensitive Password item version.
ssh_item_id:
  type: str
  returned: always
  description: Validated non-sensitive SSH Key item ID.
ssh_item_version:
  type: int
  returned: always
  description: Validated non-sensitive SSH Key item version.
ssh_fingerprint:
  type: str
  returned: always
  description: Externally pinned and revalidated public-key fingerprint.
destination:
  type: str
  returned: always
  description: Non-sensitive SSH destination identity.
"""


def main():
    """Refuse a remote fallback when the action plugin is unavailable."""
    from ansible.module_utils.basic import AnsibleModule

    module = AnsibleModule(
        argument_spec={
            "cli_path": {"type": "path", "required": True},
            "cli_sha256": {"type": "str", "required": True},
            "cli_version": {"type": "str", "required": True},
            "account_id": {"type": "str", "required": True},
            "account_sign_in_address": {"type": "str", "required": True},
            "authorized_user_uuids": {
                "type": "list",
                "elements": "str",
                "required": True,
            },
            "vault_id": {"type": "str", "required": True},
            "password_item_id": {"type": "str", "required": True},
            "password_item_version": {"type": "int", "required": True},
            "password_item_title": {"type": "str", "required": True},
            "password_field_id": {"type": "str", "default": "password"},
            "password_tags": {"type": "list", "elements": "str", "required": True},
            "password_length": {"type": "int", "required": True},
            "ssh_item_id": {"type": "str", "required": True},
            "ssh_item_version": {"type": "int", "required": True},
            "ssh_item_title": {"type": "str", "required": True},
            "ssh_tags": {"type": "list", "elements": "str", "required": True},
            "ssh_expected_fingerprint": {"type": "str", "required": True},
            "subject": {"type": "str", "required": True},
            "schema_version": {"type": "int", "default": 1},
            "ssh_path": {"type": "path", "required": True},
            "ssh_sha256": {"type": "str", "required": True},
            "ssh_add_path": {"type": "path", "required": True},
            "ssh_add_sha256": {"type": "str", "required": True},
            "ssh_keygen_path": {"type": "path", "required": True},
            "ssh_keygen_sha256": {"type": "str", "required": True},
            "agent_socket_path": {"type": "path", "required": True},
            "known_hosts_path": {"type": "path", "required": True},
            "known_hosts_sha256": {"type": "str", "required": True},
            "destination_host": {"type": "str", "required": True},
            "destination_user": {"type": "str", "default": "root"},
            "destination_port": {"type": "int", "required": True},
            "destination_host_fingerprint": {"type": "str", "required": True},
            "remote_command": {
                "type": "str",
                "required": True,
                "choices": ["/bin/cryptroot-unlock"],
            },
            "approval_authority": {
                "type": "dict",
                "required": True,
                "options": {
                    "schema_version": {"type": "int", "required": True},
                    "identity": {"type": "str", "required": True},
                    "namespace": {"type": "str", "required": True},
                    "fingerprint": {"type": "str", "required": True},
                    "allowed_signers_path": {"type": "path", "required": True},
                    "allowed_signers_sha256": {"type": "str", "required": True},
                    "ssh_keygen_path": {"type": "path", "required": True},
                    "ssh_keygen_sha256": {"type": "str", "required": True},
                    "replay_directory": {"type": "path", "required": True},
                },
            },
            "approval": {
                "type": "dict",
                "required": True,
                "options": {
                    "schema_version": {"type": "int", "required": True},
                    "execution_id": {"type": "str", "required": True},
                    "commit_shas": {"type": "dict", "required": True},
                    "nonce": {"type": "str", "required": True, "no_log": True},
                    "issued_at": {"type": "str", "required": True},
                    "expires_at": {"type": "str", "required": True},
                    "replay_directory": {"type": "path", "required": True},
                    "signature": {"type": "str", "required": True},
                },
            },
        },
        supports_check_mode=True,
    )
    module.fail_json(
        msg=(
            "onepassword_ssh_secret_stdin requires its controller-side action "
            "plugin; no remote fallback is permitted"
        )
    )


if __name__ == "__main__":
    main()
