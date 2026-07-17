# Copyright: (c) 2026, Lightning IT
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Documentation stub for the controller-local action plugin."""

from __future__ import absolute_import, division, print_function

__metaclass__ = type


DOCUMENTATION = r"""
---
module: ansible_vault_secret_document
short_description: Create an immutable local Ansible Vault secret document
version_added: "1.27.0"
description:
  - Creates one encrypted YAML document on the Ansible controller.
  - Uses the Vault identity already loaded by Ansible; no Vault password is accepted as an argument.
  - Existing documents are immutable and must decrypt and match the requested schema exactly.
options:
  path:
    description:
      - Controller-local path of the encrypted document.
    type: path
    required: true
  subject:
    description:
      - Identity that the encrypted document is bound to.
    type: str
    required: true
  schema_version:
    description:
      - Expected document schema version.
    type: int
    default: 1
  secret_field:
    description:
      - Name of the field containing the generated secret.
    type: str
    default: recovery_passphrase
  secret_length:
    description:
      - Length of a newly generated alphanumeric secret.
    type: int
    default: 64
attributes:
  action:
    description: The action executes entirely on the controller.
    support: full
  check_mode:
    description: Existing documents are validated; absent documents report that creation is needed.
    support: full
  connection:
    description: No managed-host connection is used.
    support: none
  diff_mode:
    description: Secret material and ciphertext are never returned as diff data.
    support: none
notes:
  - This documentation stub has no remote implementation; all behavior is provided by the matching action plugin.
  - Check mode never generates or encrypts a secret for an absent document.
author:
  - Lightning IT (@lightning-it)
"""

EXAMPLES = r"""
---
- name: Ensure the encrypted recovery document exists
  lit.foundational.ansible_vault_secret_document:
    path: /secure/inventory/recovery/example.vault.yml
    subject: "{{ inventory_hostname }}"
"""

RETURN = r"""
created:
  description: Whether this invocation won the create-if-absent operation.
  returned: always
  type: bool
exists:
  description: Whether a valid encrypted document exists after this invocation.
  returned: always
  type: bool
path:
  description: Absolute controller-local document path.
  returned: always
  type: str
ciphertext_sha256:
  description: SHA-256 of the persisted ciphertext, or null for an absent document in check mode.
  returned: always
  type: str
"""
