# Copyright: (c) 2026, Lightning IT
# SPDX-License-Identifier: MIT
"""Documentation for the controller-only encrypted header reader."""

DOCUMENTATION = r"""
---
module: luks_header_escrow_read
short_description: Read an identity-pinned encrypted LUKS header into protected memory
version_added: "1.34.0"
description:
  - Requires task-level no_log, an already loaded Ansible Vault identity and exact ciphertext checksum.
  - Rejects symlinks, hardlinks, insecure files, wrong source, UUID, schema, size and raw checksum.
  - Has no managed-host connection and never writes plaintext to controller files.
options:
  path:
    type: path
    required: true
    description: Canonical absolute ciphertext file path.
  subject:
    type: str
    required: true
    description: Exact expected original host identity.
  luks_uuid:
    type: str
    required: true
    description: Exact expected original LUKS UUID.
  ciphertext_sha256:
    type: str
    required: true
    description: Independently retained SHA256 of the encrypted artifact.
author:
  - Lightning IT (@lightning-it)
"""
EXAMPLES = r"""
- name: Read the independently retained ciphertext into protected memory
  lit.foundational.luks_header_escrow_read:
    path: "{{ recovery_ciphertext_path }}"
    subject: "{{ recovery_subject }}"
    luks_uuid: "{{ recovery_luks_uuid }}"
    ciphertext_sha256: "{{ recovery_ciphertext_sha256 }}"
  no_log: true
"""
RETURN = r"""
document:
  type: dict
  returned: success
  description: Sensitive header document; only usable in protected no_log tasks.
"""
