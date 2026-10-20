# Copyright: (c) 2026, Lightning IT
# SPDX-License-Identifier: MIT
"""Documentation for the controller-only package preparation action."""

DOCUMENTATION = r"""
---
module: luks_header_custody_prepare
short_description: Prepare a ciphertext-only header custody package
version_added: "1.34.0"
description:
  - Uses the loaded Ansible Vault identity to authenticate the exact header schema, disk and payload.
  - Returns ciphertext and non-secret source/custody metadata; never the raw header or password.
options:
  path:
    type: path
    required: true
    description: Existing protected encrypted header file on the EE controller.
  subject:
    type: str
    required: true
    description: Exact source host identity.
  luks_uuid:
    type: str
    required: true
    description: Exact source LUKS2 UUID.
  ciphertext_sha256:
    type: str
    required: true
    description: Independently pinned encrypted-file checksum.
  source_machine_id:
    type: str
    required: true
    description: Exact source machine identity proven during capture.
  owner:
    type: str
    required: true
    description: Actual recovery custodian.
  retention:
    type: str
    required: true
    description: Approved retention contract.
  key_retrieval_reference:
    type: str
    required: true
    description: Independent reference for envelope decryption, without the key value.
author:
  - Lightning IT (@lightning-it)
"""
EXAMPLES = r"""
- name: Prepare a pinned ciphertext package
  lit.foundational.luks_header_custody_prepare:
    path: "{{ encrypted_header_path }}"
    subject: "{{ recovery_subject }}"
    luks_uuid: "{{ recovery_luks_uuid }}"
    ciphertext_sha256: "{{ encrypted_header_sha256 }}"
    source_machine_id: "{{ recovery_machine_id }}"
    owner: "{{ recovery_owner }}"
    retention: "{{ recovery_retention }}"
    key_retrieval_reference: "{{ recovery_key_reference }}"
  no_log: true
"""
RETURN = r"""
package:
  type: dict
  returned: success
  description: Protected ciphertext-only package, suitable for provider publication.
package_sha256:
  type: str
  returned: success
  description: Exact canonical package checksum.
"""


def main():
    from ansible.module_utils.basic import AnsibleModule

    module = AnsibleModule(
        argument_spec={
            "path": {"type": "path", "required": True},
            "subject": {"type": "str", "required": True},
            "luks_uuid": {"type": "str", "required": True},
            "ciphertext_sha256": {"type": "str", "required": True},
            "source_machine_id": {"type": "str", "required": True},
            "owner": {"type": "str", "required": True},
            "retention": {"type": "str", "required": True},
            "key_retrieval_reference": {"type": "str", "required": True},
        },
        supports_check_mode=True,
    )
    module.fail_json(
        msg="Package preparation requires its controller action; no remote fallback."
    )


if __name__ == "__main__":
    main()
