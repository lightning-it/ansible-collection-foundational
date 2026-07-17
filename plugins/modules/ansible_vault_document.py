# Copyright: (c) 2026, Lightning IT
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Documentation stub for the controller-local action plugin."""

from __future__ import absolute_import, division, print_function

__metaclass__ = type


DOCUMENTATION = r"""
---
module: ansible_vault_document
short_description: Persist an exact immutable mapping as Ansible Vault ciphertext
version_added: "1.27.0"
description:
  - Persists an exact JSON/YAML-safe mapping as an encrypted file on the Ansible controller.
  - Uses the Vault identities already loaded by Ansible; no Vault password argument is accepted.
  - Existing documents are immutable and must decrypt to a type-exact match of the requested mapping.
options:
  path:
    description:
      - Normalized absolute controller-local path of the encrypted document.
    type: path
    required: true
  document:
    description:
      - Exact mapping to encrypt or validate.
      - Keys must be strings. Values may contain only JSON-safe scalars, mappings, and lists.
      - The task must set C(no_log=true); the action fails closed before inspecting this value otherwise.
    type: dict
    required: true
  vault_id:
    version_added: "1.29.0"
    description:
      - Loaded Ansible Vault identity label to use when creating an absent document.
      - The label may contain only ASCII letters, digits, dots, underscores, and hyphens.
      - The action never accepts or loads Vault password material.
      - Existing documents are validated with the identities already loaded by Ansible.
    type: str
attributes:
  action:
    description: The action executes entirely on the controller.
    support: full
  check_mode:
    description: Existing documents are validated; absent documents report pending creation without side effects.
    support: full
  connection:
    description: No managed-host connection is used.
    support: none
  diff_mode:
    description: Plaintext and ciphertext are never returned as diff data.
    support: none
notes:
  - This documentation stub has no remote implementation; all behavior is provided by the matching action plugin.
  - The action never accepts a Vault password or password-file argument.
  - Set C(vault_id) when more than one identity is loaded so creation cannot silently use the wrong identity.
  - The action requires task-level C(no_log=true) to suppress secret task arguments at every callback verbosity.
  - Plaintext is serialized, encrypted, decrypted, and compared only in controller process memory.
  - Serialized plaintext has a fixed 192 MiB safety limit and ciphertext has a fixed 512 MiB safety limit.
  - The safety limits are not caller-configurable.
  - Check mode never creates a directory, serializes the mapping, or invokes Vault encryption for an absent path.
author:
  - Lightning IT (@lightning-it)
"""

EXAMPLES = r"""
---
- name: Persist an immutable encrypted bootstrap document
  lit.foundational.ansible_vault_document:
    path: /secure/inventory/bootstrap/service01.vault.yml
    vault_id: production
    document:
      schema_version: 1
      subject: service01.example.test
      bootstrap_values: "{{ service01_bootstrap_values }}"
  no_log: true
"""

RETURN = r"""
created:
  description: Whether this invocation won the atomic create-if-absent operation.
  returned: always
  type: bool
exists:
  description: Whether an exact valid encrypted document exists after this invocation.
  returned: always
  type: bool
path:
  description: Normalized absolute controller-local document path.
  returned: always
  type: str
ciphertext_sha256:
  description: SHA-256 of persisted ciphertext, or null for an absent document in check mode.
  returned: always
  type: str
"""
