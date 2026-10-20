# Copyright: (c) 2026, Lightning IT
# SPDX-License-Identifier: MIT
"""Isolated regular-file LUKS header restore; never accepts a restore-device path."""

import signal
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.lit.foundational.plugins.module_utils.luks_header_recovery import (
    restore_drill,
)

DOCUMENTATION = r"""
---
module: luks_header_restore_drill
short_description: Prove a LUKS2 header restore on an independent witness
version_added: "1.34.0"
description:
  - Restores only into a newly allocated private regular file on witness tmpfs.
  - Checks exact source identity, real header UUID, metadata, passphrase and a wrong key.
  - Never accepts a block-device target, modifies a production keyslot, or reboots.
options:
  document:
    type: dict
    required: true
    description: Protected schema1 header document from the pinned ciphertext reader.
  subject:
    type: str
    required: true
    description: Expected original host identity.
  luks_uuid:
    type: str
    required: true
    description: Expected original LUKS UUID.
  source_machine_id:
    type: str
    required: true
    description: Original machine ID; cannot equal the witness.
  witness_machine_id:
    type: str
    required: true
    description: Exact expected witness machine ID, compared before writes.
  passphrase:
    type: str
    required: true
    description: Existing recovery passphrase; passed through protected memory only.
  temporary_root:
    type: path
    default: /run
    description: Canonical owner-protected tmpfs directory for private scratch.
author:
  - Lightning IT (@lightning-it)
"""
EXAMPLES = r"""
- name: Verify recovery using protected variables on the independent witness
  lit.foundational.luks_header_restore_drill:
    document: "{{ encrypted_header.document }}"
    subject: "{{ recovery_source_subject }}"
    luks_uuid: "{{ recovery_source_luks_uuid }}"
    source_machine_id: "{{ recovery_source_machine_id }}"
    witness_machine_id: "{{ recovery_witness_machine_id }}"
    passphrase: "{{ recovery_secret }}"
  no_log: true
"""
RETURN = r"""
verified:
  type: bool
  returned: always
  description: True only after real restore, valid/invalid key tests and cleanup.
scratch_removed:
  type: bool
  returned: success
  description: All owned scratch files have been removed.
"""


def main():
    module = AnsibleModule(
        argument_spec=dict(
            document=dict(type="dict", required=True, no_log=True),
            subject=dict(type="str", required=True),
            luks_uuid=dict(type="str", required=True),
            source_machine_id=dict(type="str", required=True),
            witness_machine_id=dict(type="str", required=True),
            passphrase=dict(type="str", required=True, no_log=True),
            temporary_root=dict(type="path", default="/run"),
        ),
        supports_check_mode=True,
    )

    def interrupted(signum, frame):
        raise InterruptedError("Recovery drill interrupted.")

    signal.signal(signal.SIGTERM, interrupted)
    try:
        result = restore_drill(**module.params, check_mode=module.check_mode)
    except Exception:
        module.fail_json(
            msg="Isolated header recovery verification failed; sensitive output suppressed."
        )
    module.exit_json(**result)


if __name__ == "__main__":
    main()
