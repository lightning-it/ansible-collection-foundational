# Copyright: (c) 2026, Lightning IT
# SPDX-License-Identifier: MIT

"""Documentation stub for the controller-only onepassword_approval action."""

from __future__ import absolute_import, division, print_function

__metaclass__ = type

from ansible.module_utils.basic import AnsibleModule


DOCUMENTATION = r"""
---
module: onepassword_approval
short_description: Sign one short-lived controller-local 1Password approval
version_added: "1.34.0"
description:
  - Creates an expiring SSHSIG approval bound to exact commits, target, operation, and immutable action binding.
  - The signing key remains outside Ansible data and the returned authorization must be consumed exactly once.
options:
  approval_authority:
    type: dict
    required: true
  binding:
    type: raw
    required: true
  commit_shas:
    type: dict
    required: true
  execution_id_prefix:
    type: str
    required: true
  operation:
    type: str
    required: true
  signing_agent_socket_path:
    type: path
    required: true
  signing_ssh_add_path:
    type: path
    required: true
  signing_ssh_add_sha256:
    type: str
    required: true
  target:
    type: str
    required: true
  validity_seconds:
    type: int
    required: true
author:
  - Lightning IT
"""

EXAMPLES = r"""
- name: Sign a one-time approval
  lit.foundational.onepassword_approval:
    approval_authority: "{{ approval_authority }}"
    binding: "{{ exact_binding }}"
    commit_shas: "{{ exact_commits }}"
    execution_id_prefix: WBX-1P-CREATE
    operation: create-onepassword-secret
    signing_agent_socket_path: /absolute/controller-only/agent.sock
    signing_ssh_add_path: /usr/bin/ssh-add
    signing_ssh_add_sha256: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    target: host01.example.test
    validity_seconds: 600
  no_log: true
"""

RETURN = r"""
approval:
  description: Complete short-lived signed approval transport.
  type: dict
approval_metadata:
  description: Non-secret digest and authority metadata.
  type: dict
"""


def main():
    module = AnsibleModule(
        argument_spec={
            "approval_authority": {"type": "dict", "required": True},
            "binding": {"type": "raw", "required": True},
            "commit_shas": {"type": "dict", "required": True},
            "execution_id_prefix": {"type": "str", "required": True},
            "operation": {"type": "str", "required": True},
            "signing_agent_socket_path": {"type": "path", "required": True},
            "signing_ssh_add_path": {"type": "path", "required": True},
            "signing_ssh_add_sha256": {"type": "str", "required": True},
            "target": {"type": "str", "required": True},
            "validity_seconds": {"type": "int", "required": True},
        },
        supports_check_mode=True,
    )
    module.fail_json(msg="onepassword_approval requires its controller action plugin")


if __name__ == "__main__":
    main()
