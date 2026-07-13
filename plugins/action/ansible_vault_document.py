# Copyright: (c) 2026, Lightning IT
# SPDX-License-Identifier: MIT

"""Persist one exact immutable mapping as controller-local Ansible Vault ciphertext."""

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import os

from ansible.parsing.vault import VaultLib
from ansible.plugins.action import ActionBase

from .ansible_vault_secret_document import (
    _VaultDocumentStore,
    _fail,
    _normalize_document_mapping,
)


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
notes:
  - This action never contacts a managed host and never accepts a Vault password or password-file argument.
  - The action requires task-level C(no_log=true) to suppress secret task arguments at every callback verbosity.
  - Plaintext is serialized, encrypted, decrypted, and compared only in controller process memory.
  - Plaintext and ciphertext each have a fixed 128 MiB safety limit; the limit is not caller-configurable.
  - Check mode validates an existing document. An absent document reports pending creation without creating a
    directory, serializing the mapping, or invoking Vault encryption.
author:
  - Lightning IT (@lightning-it)
"""

EXAMPLES = r"""
---
- name: Persist an immutable encrypted bootstrap document
  lit.foundational.ansible_vault_document:
    path: /secure/inventory/bootstrap/service01.vault.yml
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


_EXPECTED_ARGS = frozenset(("path", "document"))
_MAX_DOCUMENT_BYTES = 128 * 1024 * 1024


def _normalize_arguments(args):
    unknown = set(args).difference(_EXPECTED_ARGS)
    if unknown:
        _fail("Unsupported arguments: {0}.".format(", ".join(sorted(unknown))))

    path = args.get("path")
    if not isinstance(path, str) or not path.strip():
        _fail("path must be a non-empty string.")
    if "\x00" in path or "\r" in path or "\n" in path:
        _fail("path contains an invalid character.")
    if not os.path.isabs(path):
        _fail("path must be absolute.")
    normalized_path = os.path.normpath(path)
    if normalized_path != path:
        _fail("path must be a normalized absolute path.")
    if normalized_path == os.path.sep or not os.path.basename(normalized_path):
        _fail("path must identify a file, not a directory.")

    if "document" not in args:
        _fail("document is required.")
    document = _normalize_document_mapping(args["document"])

    return {
        "path": normalized_path,
        "document": document,
    }


def _require_task_no_log(task):
    if getattr(task, "no_log", None) is not True:
        task.no_log = True
        _fail("ansible_vault_document requires task-level no_log to be true.")


def _new_document_store(vault):
    return _VaultDocumentStore(
        vault,
        max_ciphertext_bytes=_MAX_DOCUMENT_BYTES,
        max_plaintext_bytes=_MAX_DOCUMENT_BYTES,
    )


class ActionModule(ActionBase):
    """Ansible controller-only action-plugin entry point."""

    TRANSFERS_FILES = False
    _requires_connection = False
    _supports_check_mode = True
    _VALID_ARGS = _EXPECTED_ARGS

    def run(self, tmp=None, task_vars=None):
        if task_vars is None:
            task_vars = {}
        _require_task_no_log(self._task)
        super(ActionModule, self).run(tmp, task_vars)

        config = _normalize_arguments(dict(self._task.args))
        vault = getattr(self._loader, "_vault", None)
        if not isinstance(vault, VaultLib) or not getattr(vault, "secrets", None):
            _fail("An Ansible Vault identity must already be loaded for this action.")

        return _new_document_store(vault).ensure_exact(
            path=config["path"],
            document=config["document"],
            check_mode=bool(self._task.check_mode),
        )
