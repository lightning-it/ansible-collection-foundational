# Copyright: (c) 2026, Lightning IT
# SPDX-License-Identifier: MIT

"""Documentation stub for the controller-only SSH key import action."""

from __future__ import absolute_import, division, print_function

__metaclass__ = type

from ansible.module_utils.basic import AnsibleModule


DOCUMENTATION = r"""
---
module: onepassword_ssh_key_import
short_description: Import one exact local Ed25519 key into 1Password
version_added: "1.34.0"
description:
  - Imports one owner-only, unencrypted OpenSSH Ed25519 private key through a JSON template on standard input.
  - Never places private key material in command arguments, Ansible results, logs, Git, or evidence.
  - Validates the exact source fingerprint and requires target-bound confirmation before initial import.
  - Verifies the imported key through the pinned 1Password SSH Agent before returning success.
options:
  action:
    type: str
    choices: [plan, apply]
    required: true
  private_key_path:
    type: path
    required: true
  expected_fingerprint:
    type: str
    required: true
  allow_import:
    type: bool
    required: true
  confirmation:
    type: str
    required: true
author:
  - Lightning IT
"""


EXAMPLES = r"""
- name: Import one approved local SSH key
  lit.foundational.onepassword_ssh_key_import:
    action: apply
    private_key_path: /absolute/controller/key
    expected_fingerprint: SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
    allow_import: true
    confirmation: IMPORT-ONEPASSWORD-SSH-KEY:svc_example:SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
    account_id: AAAAAAAAAAAAAAAAAAAAAAAAAA
    account_sign_in_address: example.1password.com
    authorized_user_uuids: [UUUUUUUUUUUUUUUUUUUUUUUUUU]
    vault_id: vvvvvvvvvvvvvvvvvvvvvvvvvv
    item_id: ""
    item_version: 0
    item_title: svc_example
    category: SSH Key
    tags: [automation, ssh]
    subject: svc_example
    schema_version: 1
    key_type: ed25519
    cli_path: /usr/local/bin/op
    cli_sha256: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    cli_version: 2.38.1
    ssh_add_path: /usr/bin/ssh-add
    ssh_add_sha256: bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
    ssh_keygen_path: /usr/bin/ssh-keygen
    ssh_keygen_sha256: cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
    agent_socket_path: /absolute/controller/agent.sock
  no_log: true
"""


RETURN = r"""
item_id:
  description: Imported non-sensitive 1Password item ID.
  type: str
item_version:
  description: Positive imported item version.
  type: int
fingerprint:
  description: Validated public SHA-256 fingerprint.
  type: str
agent_verified:
  description: Whether the exact key passed the pinned SSH Agent challenge.
  type: bool
"""


def main():
    module = AnsibleModule(
        argument_spec={
            "account_id": {"type": "str", "required": True},
            "account_sign_in_address": {"type": "str", "required": True},
            "action": {
                "type": "str",
                "required": True,
                "choices": ["plan", "apply"],
            },
            "agent_socket_path": {"type": "path", "required": True},
            "allow_import": {"type": "bool", "required": True},
            "authorized_user_uuids": {
                "type": "list",
                "elements": "str",
                "required": True,
            },
            "category": {
                "type": "str",
                "default": "SSH Key",
                "choices": ["SSH Key"],
            },
            "cli_path": {"type": "path", "required": True},
            "cli_sha256": {"type": "str", "required": True},
            "cli_version": {"type": "str", "required": True},
            "confirmation": {"type": "str", "required": True},
            "expected_fingerprint": {"type": "str", "required": True},
            "item_id": {"type": "str", "default": ""},
            "item_title": {"type": "str", "required": True},
            "item_version": {"type": "int", "default": 0},
            "key_type": {
                "type": "str",
                "default": "ed25519",
                "choices": ["ed25519"],
            },
            "private_key_path": {"type": "path", "required": True},
            "schema_version": {"type": "int", "default": 1},
            "ssh_add_path": {"type": "path", "required": True},
            "ssh_add_sha256": {"type": "str", "required": True},
            "ssh_keygen_path": {"type": "path", "required": True},
            "ssh_keygen_sha256": {"type": "str", "required": True},
            "subject": {"type": "str", "required": True},
            "tags": {"type": "list", "elements": "str", "required": True},
            "vault_id": {"type": "str", "required": True},
        },
        supports_check_mode=True,
    )
    module.fail_json(msg="onepassword_ssh_key_import requires its controller action plugin")


if __name__ == "__main__":
    main()
