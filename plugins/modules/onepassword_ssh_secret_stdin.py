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
  cli_version:
    type: str
    required: true
  account_id:
    type: str
    required: true
  account_sign_in_address:
    type: str
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
  ssh_add_path:
    type: path
    required: true
  ssh_keygen_path:
    type: path
    required: true
  agent_socket_path:
    type: path
    required: true
  known_hosts_path:
    type: path
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
  remote_command:
    type: str
    choices: [/bin/cryptroot-unlock]
    required: true
  confirmation:
    type: str
    required: true
author:
  - Lightning IT (@lightning-it)
"""

EXAMPLES = r"""
---
- name: Validate the exact external recovery boundary in check mode
  lit.foundational.onepassword_ssh_secret_stdin:
    cli_path: /usr/local/bin/op
    cli_version: 2.38.1
    account_id: aaaaaaaaaaaaaaaaaaaaaaaaaa
    account_sign_in_address: example.1password.com
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
    ssh_add_path: /usr/bin/ssh-add
    ssh_keygen_path: /usr/bin/ssh-keygen
    agent_socket_path: /absolute/path/to/1password/agent.sock
    known_hosts_path: /absolute/path/to/dropbear-known-hosts
    destination_host: host01.example.test
    destination_port: 2222
    remote_command: /bin/cryptroot-unlock
    confirmation: UNLOCK:host01.example.test
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
            "cli_version": {"type": "str", "required": True},
            "account_id": {"type": "str", "required": True},
            "account_sign_in_address": {"type": "str", "required": True},
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
            "ssh_add_path": {"type": "path", "required": True},
            "ssh_keygen_path": {"type": "path", "required": True},
            "agent_socket_path": {"type": "path", "required": True},
            "known_hosts_path": {"type": "path", "required": True},
            "destination_host": {"type": "str", "required": True},
            "destination_user": {"type": "str", "default": "root"},
            "destination_port": {"type": "int", "required": True},
            "remote_command": {
                "type": "str",
                "required": True,
                "choices": ["/bin/cryptroot-unlock"],
            },
            "confirmation": {"type": "str", "required": True},
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
