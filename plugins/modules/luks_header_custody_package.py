# Copyright: (c) 2026, Lightning IT
# SPDX-License-Identifier: MIT
"""Controller action documentation; no managed-node fallback."""

DOCUMENTATION = r"""
---
module: luks_header_custody_package
short_description: Export or read an immutable ciphertext-only provider handoff
version_added: "1.34.0"
description:
  - Uses private no-follow, create-only local storage and exact producer checksums.
  - Read mode needs no Ansible Vault decryption identity and works with the existing memory-only AppRole profile.
  - Never writes plaintext header or credential material.
options:
  operation:
    type: str
    choices: [export, read, materialize]
    required: true
    description: Export creates an absent package; read verifies it; materialize writes only its ciphertext for recovery.
  path:
    type: path
    required: true
    description: Canonical private controller package path.
  package_sha256:
    type: str
    required: true
    description: Exact independently retained producer checksum.
  subject:
    type: str
    required: true
    description: Expected source host.
  source_machine_id:
    type: str
    required: true
    description: Expected source machine identity.
  luks_uuid:
    type: str
    required: true
    description: Expected original disk UUID.
  package:
    type: dict
    description: Ciphertext-only package from the authenticated producer; required only for export.
author:
  - Lightning IT (@lightning-it)
"""
EXAMPLES = r"""
- name: Read the independently pinned ciphertext handoff without a Vault password
  lit.foundational.luks_header_custody_package:
    operation: read
    path: "{{ header_package_path }}"
    package_sha256: "{{ header_package_sha256 }}"
    subject: "{{ source_subject }}"
    source_machine_id: "{{ source_machine_id }}"
    luks_uuid: "{{ source_luks_uuid }}"
  no_log: true
"""
RETURN = r"""
verified:
  type: bool
  returned: always
  description: Whether the existing ciphertext-only handoff was fully verified.
package:
  type: dict
  returned: success
  description: Verified ciphertext-only package, with no raw header or credential.
"""


def main():
    from ansible.module_utils.basic import AnsibleModule

    module = AnsibleModule(
        argument_spec={
            "operation": {
                "type": "str",
                "required": True,
                "choices": ["export", "read", "materialize"],
            },
            "path": {"type": "path", "required": True},
            "package_sha256": {"type": "str", "required": True},
            "subject": {"type": "str", "required": True},
            "source_machine_id": {"type": "str", "required": True},
            "luks_uuid": {"type": "str", "required": True},
            "package": {"type": "dict", "no_log": True},
        },
        supports_check_mode=True,
    )
    module.fail_json(
        msg="Ciphertext handoff requires the controller action; no remote fallback."
    )


if __name__ == "__main__":
    main()
