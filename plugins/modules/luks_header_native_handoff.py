# Copyright: (c) 2026, Lightning IT
# SPDX-License-Identifier: MIT
"""Documentation for the controller-local ciphertext-only exchange action."""

DOCUMENTATION = r"""
---
module: luks_header_native_handoff
short_description: Exchange encrypted header packages with a native desktop client
version_added: "1.34.0"
description:
  - Prepares a closed ciphertext-only request in the execution environment.
  - Consumes the exact response of the separately admitted native desktop adapter.
  - Never launches a desktop process, SSH server, host Ansible or recovery password retrieval.
options:
  operation:
    description: Prepare exports an immutable request; consume validates its exact native response.
    type: str
    choices: [prepare, consume]
    required: true
  request:
    description:
      - Closed schema-version-1 native provider contract with exchange, operation, provider_config, package, read_pins,
        allow_create, approval_authority and approval.
      - Read pins bind package_sha256, subject, source_machine_id and luks_uuid.
      - An independent read has an empty package and retained exact Document ID/version.
      - Only apply may carry the existing one-time signed creation authority.
      - Exchange binds execution_id, unique 256-bit nonce and UTC issued_at/expires_at with at most 900 seconds validity.
    type: dict
    required: true
  request_path:
    description: New immutable owner-only request file in a protected directory shared with the outer transport.
    type: path
    required: true
  response_path:
    description: Distinct owner-only file containing the trusted native execution response.
    type: path
    required: true
notes:
  - This action executes only on the Ansible controller inside its approved EE and requires task-level no_log.
  - Run the Collection's scripts/luks-header-native-custody.py through the trusted native launcher with python3 -I -S.
  - The outer launcher must pin the complete published Collection and retain actual native execution evidence.
  - A response file, hash or verified flag alone is not a signed execution receipt or recovery acceptance.
  - No Mac binary is mounted or executed inside Linux; no SSH access to the desktop is required.
author:
  - Lightning IT (@lightning-it)
"""

EXAMPLES = r"""
- name: Prepare an encrypted package request for the native desktop
  lit.foundational.luks_header_native_handoff:
    operation: prepare
    request: "{{ approved_native_header_request }}"
    request_path: /runner/native-handoff/request.json
    response_path: /runner/native-handoff/response.json
  no_log: true
"""

RETURN = r"""
request_sha256:
  description: Canonical exact request binding to pass to the native adapter.
  type: str
  returned: always
verified:
  description: True only when a supplied native provider response verifies a complete copy.
  type: bool
  returned: always
"""
