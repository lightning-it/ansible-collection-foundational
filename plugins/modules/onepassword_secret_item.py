# Copyright: (c) 2026, Lightning IT
# SPDX-License-Identifier: MIT

"""Documentation stub for the controller-local action plugin."""

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: onepassword_secret_item
short_description: Plan or create one exact 1Password Password item
version_added: "1.34.0"
description:
  - Executes only through the controller-side action plugin.
  - Creates an absent Password item only through 1Password-internal generation.
  - Never reads or returns the protected value.
options:
  operation:
    type: str
    choices: [plan, apply]
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
  field_id:
    type: str
    default: password
  category:
    type: str
    choices: [Password]
    default: Password
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
  password_recipe:
    type: str
    required: true
  password_length:
    type: int
    required: true
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
author:
  - Lightning IT (@lightning-it)
"""

EXAMPLES = r"""
---
- name: Plan an exact externally escrowed password item
  lit.foundational.onepassword_secret_item:
    operation: plan
    cli_path: /usr/local/bin/op
    cli_sha256: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    cli_version: 2.38.1
    account_id: AAAAAAAAAAAAAAAAAAAAAAAAAA
    account_sign_in_address: example.1password.com
    authorized_user_uuids: [UUUUUUUUUUUUUUUUUUUUUUUUUU]
    vault_id: vvvvvvvvvvvvvvvvvvvvvvvvvv
    item_title: host01.example.test recovery
    tags: [breakglass, recovery]
    subject: host01.example.test
    password_recipe: letters,digits,symbols,64
    password_length: 64
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
"""


def main():
    """Refuse a remote fallback when the action plugin is unavailable."""
    from ansible.module_utils.basic import AnsibleModule

    module = AnsibleModule(
        argument_spec={
            "operation": {
                "type": "str",
                "required": True,
                "choices": ["plan", "apply"],
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
            "field_id": {"type": "str", "default": "password"},
            "category": {
                "type": "str",
                "default": "Password",
                "choices": ["Password"],
            },
            "tags": {"type": "list", "elements": "str", "required": True},
            "subject": {"type": "str", "required": True},
            "schema_version": {"type": "int", "default": 1},
            "password_recipe": {"type": "str", "required": True},
            "password_length": {"type": "int", "required": True},
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
        },
        supports_check_mode=True,
    )
    module.fail_json(
        msg=(
            "onepassword_secret_item requires its controller-side action plugin; "
            "no remote fallback is permitted"
        )
    )


if __name__ == "__main__":
    main()
