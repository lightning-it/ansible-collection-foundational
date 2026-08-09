# Copyright: (c) 2026, Lightning IT
# SPDX-License-Identifier: MIT

"""Documentation and fail-closed remote fallback for onepassword_vault_co_manager."""

from __future__ import absolute_import, division, print_function

__metaclass__ = type


DOCUMENTATION = r"""
---
module: onepassword_vault_co_manager
short_description: Verify or grant exact 1Password vault Co-Manager access
version_added: "1.34.0"
description:
  - Controller-only action that verifies one exact user's direct vault access.
  - C(apply) idempotently grants C(allow_viewing), C(allow_editing), and C(allow_managing) after one-time approval.
  - The remote module fallback always fails closed.
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
  user_uuid:
    type: str
    required: true
  user_email:
    type: str
    required: true
  allow_grant:
    type: bool
    default: false
  approval_authority:
    type: dict
    default: {}
    description:
      - Independently configured Ed25519 Approval Authority for apply.
      - Pins signer, verifier, allowed-signers file, and one canonical replay directory.
  approval:
    type: dict
    default: {}
    description: Expiring asymmetric signature over the complete permission-grant contract.
author:
  - Lightning IT (@lightning-it)
"""

EXAMPLES = r"""
---
- name: Verify a vault Co-Manager
  lit.foundational.onepassword_vault_co_manager:
    operation: plan
    cli_path: /usr/local/bin/op
    cli_sha256: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    cli_version: 2.38.1
    account_id: aaaaaaaaaaaaaaaaaaaaaaaaaa
    account_sign_in_address: example.1password.com
    authorized_user_uuids: [oooooooooooooooooooooooooo]
    vault_id: vvvvvvvvvvvvvvvvvvvvvvvvvv
    user_uuid: uuuuuuuuuuuuuuuuuuuuuuuuuu
    user_email: custodian@example.com
"""

RETURN = r"""
approval:
  type: dict
  returned: C(operation=apply)
  description: Non-secret digest, authority, commit, and validity metadata for the supplied apply approval.
changed:
  type: bool
  returned: always
  description: Whether apply granted missing permissions.
exists:
  type: bool
  returned: always
  description: Whether the target user has direct access to the vault.
missing_permissions:
  type: list
  elements: str
  returned: always
  description: Required permissions still absent.
observed_permissions:
  type: list
  elements: str
  returned: always
  description: Sorted permissions observed for the target user.
operator_user_uuid:
  type: str
  returned: always
  description: Allowlisted 1Password operator observed during validation.
planned:
  type: bool
  returned: always
  description: Whether a grant remains pending.
required_permissions:
  type: list
  elements: str
  returned: always
  description: Fixed Co-Manager permission set.
user_uuid:
  type: str
  returned: always
  description: Exact target user UUID.
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
            "user_uuid": {"type": "str", "required": True},
            "user_email": {"type": "str", "required": True},
            "allow_grant": {"type": "bool", "default": False},
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
            "onepassword_vault_co_manager requires its controller-side action "
            "plugin; no remote fallback is permitted"
        )
    )


if __name__ == "__main__":
    main()
