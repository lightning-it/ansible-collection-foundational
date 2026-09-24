# Copyright: (c) 2026, Lightning IT
# SPDX-License-Identifier: MIT

"""Documentation stub for the controller-local SSH-key action plugin."""

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: onepassword_ssh_key_item
short_description: Plan, create, or inspect one exact 1Password SSH Key item
version_added: "1.34.0"
description:
  - Executes only through the controller-side action plugin.
  - Creates Ed25519 material inside 1Password and never requests or returns the private key.
options:
  operation:
    type: str
    choices: [plan, apply, read_public, verify_agent]
    required: true
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
  item_id:
    type: str
    default: ""
  item_version:
    type: int
    default: 0
  item_title:
    type: str
    required: true
  category:
    type: str
    choices: [SSH Key]
    default: SSH Key
  tags:
    type: list
    elements: str
    required: true
  subject:
    type: str
    required: true
  schema_version:
    type: int
    default: 1
  key_type:
    type: str
    choices: [ed25519]
    default: ed25519
  expected_fingerprint:
    type: str
    default: ""
  allow_create:
    type: bool
    default: false
  approval_authority:
    type: dict
    default: {}
    description:
      - Independently configured Ed25519 Approval Authority for apply.
      - Pins the signer, allowed-signers file, and C(ssh-keygen) verifier.
      - Pins the one canonical controller-only replay directory that the approval must match exactly.
  approval:
    type: dict
    default: {}
    description: Expiring asymmetric signature over the full apply contract.
  ssh_add_path:
    type: path
    default: ""
  ssh_add_sha256:
    type: str
    default: ""
  ssh_keygen_path:
    type: path
    default: ""
  ssh_keygen_sha256:
    type: str
    default: ""
  agent_socket_path:
    type: path
    default: ""
author:
  - Lightning IT (@lightning-it)
"""

EXAMPLES = r"""
---
- name: Read only the public identity of a pinned SSH Key item
  lit.foundational.onepassword_ssh_key_item:
    operation: read_public
    cli_path: /usr/local/bin/op
    cli_sha256: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    cli_version: 2.38.1
    account_id: AAAAAAAAAAAAAAAAAAAAAAAAAA
    account_sign_in_address: example.1password.com
    authorized_user_uuids: [UUUUUUUUUUUUUUUUUUUUUUUUUU]
    vault_id: vvvvvvvvvvvvvvvvvvvvvvvvvv
    item_id: iiiiiiiiiiiiiiiiiiiiiiiiii
    item_version: 1
    item_title: host01.example.test Dropbear recovery
    tags: [breakglass, recovery]
    subject: host01.example.test
    expected_fingerprint: SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
    ssh_add_path: /usr/bin/ssh-add
    ssh_keygen_path: /usr/bin/ssh-keygen
    agent_socket_path: /absolute/path/to/1password/agent.sock
"""

RETURN = r"""
created:
  type: bool
  returned: always
  description: Whether apply created the absent item.
exists:
  type: bool
  returned: always
  description: Whether the exact item exists.
item_id:
  type: str
  returned: always
  description: Exact non-sensitive item ID when present.
item_version:
  type: int
  returned: always
  description: Exact non-sensitive item version when present.
planned:
  type: bool
  returned: always
  description: Whether creation remains pending.
public_key:
  type: str
  returned: when the item exists
  description: Validated OpenSSH Ed25519 public key.
fingerprint:
  type: str
  returned: when the item exists
  description: Locally recomputed SHA-256 public-key fingerprint.
agent_verified:
  type: bool
  returned: when the item exists
  description:
    - Whether the exact key was uniquely available and completed a fresh signing challenge through the approved SSH
      Agent socket.
"""


def main():
    """Refuse a remote fallback when the action plugin is unavailable."""
    from ansible.module_utils.basic import AnsibleModule

    module = AnsibleModule(
        argument_spec={
            "operation": {
                "type": "str",
                "required": True,
                "choices": ["plan", "apply", "read_public", "verify_agent"],
            },
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
            "item_id": {"type": "str", "default": ""},
            "item_version": {"type": "int", "default": 0},
            "item_title": {"type": "str", "required": True},
            "category": {
                "type": "str",
                "default": "SSH Key",
                "choices": ["SSH Key"],
            },
            "tags": {"type": "list", "elements": "str", "required": True},
            "subject": {"type": "str", "required": True},
            "schema_version": {"type": "int", "default": 1},
            "key_type": {
                "type": "str",
                "default": "ed25519",
                "choices": ["ed25519"],
            },
            "expected_fingerprint": {"type": "str", "default": ""},
            "allow_create": {"type": "bool", "default": False},
            "approval_authority": {
                "type": "dict",
                "default": {},
                "options": {
                    "schema_version": {"type": "int"},
                    "identity": {"type": "str"},
                    "namespace": {"type": "str"},
                    "fingerprint": {"type": "str"},
                    "allowed_signers_path": {"type": "path"},
                    "allowed_signers_sha256": {"type": "str"},
                    "ssh_keygen_path": {"type": "path"},
                    "ssh_keygen_sha256": {"type": "str"},
                    "replay_directory": {"type": "path"},
                },
            },
            "approval": {
                "type": "dict",
                "default": {},
                "options": {
                    "schema_version": {"type": "int"},
                    "execution_id": {"type": "str"},
                    "commit_shas": {"type": "dict"},
                    "nonce": {"type": "str", "no_log": True},
                    "issued_at": {"type": "str"},
                    "expires_at": {"type": "str"},
                    "replay_directory": {"type": "path"},
                    "signature": {"type": "str"},
                },
            },
            "ssh_add_path": {"type": "path", "default": ""},
            "ssh_add_sha256": {"type": "str", "default": ""},
            "ssh_keygen_path": {"type": "path", "default": ""},
            "ssh_keygen_sha256": {"type": "str", "default": ""},
            "agent_socket_path": {"type": "path", "default": ""},
        },
        supports_check_mode=True,
    )
    module.fail_json(
        msg=(
            "onepassword_ssh_key_item requires its controller-side action plugin; "
            "no remote fallback is permitted"
        )
    )


if __name__ == "__main__":
    main()
