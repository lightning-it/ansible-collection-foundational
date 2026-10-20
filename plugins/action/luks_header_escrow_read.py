# Copyright: (c) 2026, Lightning IT
# SPDX-License-Identifier: MIT
"""Read a pinned encrypted header only into protected Ansible memory."""

import hashlib
import os
import re

from ansible.errors import AnsibleActionFail
from ansible.parsing.vault import VaultLib
from ansible.plugins.action import ActionBase
from ansible.utils.unsafe_proxy import wrap_var
from ..module_utils.luks_header_recovery import validate_document
from .ansible_vault_secret_document import _VaultDocumentStore


class ActionModule(ActionBase):
    TRANSFERS_FILES = False
    _requires_connection = False
    _supports_check_mode = True

    def run(self, tmp=None, task_vars=None):
        if getattr(self._task, "no_log", None) is not True:
            self._task.no_log = True
            raise AnsibleActionFail(
                "Header escrow reads require task-level no_log=true."
            )
        super().run(tmp, task_vars or {})
        arguments = dict(self._task.args)
        required = {"path", "subject", "luks_uuid", "ciphertext_sha256"}
        if set(arguments) != required:
            raise AnsibleActionFail("The complete pinned header contract is required.")
        path, digest = arguments["path"], arguments["ciphertext_sha256"]
        if (
            not isinstance(path, str)
            or not os.path.isabs(path)
            or os.path.normpath(path) != path
            or "\x00" in path
            or "\n" in path
            or "\r" in path
            or not isinstance(digest, str)
            or not re.fullmatch("[0-9a-f]{64}", digest)
        ):
            raise AnsibleActionFail("Invalid encrypted header path or checksum.")
        vault = getattr(self._loader, "_vault", None)
        if not isinstance(vault, VaultLib) or not vault.secrets:
            raise AnsibleActionFail(
                "A trusted Ansible Vault identity must already be loaded."
            )
        store = _VaultDocumentStore(vault, max_ciphertext_bytes=128 * 1024 * 1024)
        ciphertext = store._read_existing(path)
        if ciphertext is None or hashlib.sha256(ciphertext).hexdigest() != digest:
            raise AnsibleActionFail(
                "The encrypted header is absent or differs from its pinned checksum."
            )
        document = store._decrypt_ciphertext(ciphertext)
        try:
            validate_document(document, arguments["subject"], arguments["luks_uuid"])
        except (ValueError, TypeError, KeyError):
            raise AnsibleActionFail(
                "The encrypted header identity or payload is invalid."
            ) from None
        return {
            "changed": False,
            "document": wrap_var(document),
            "_ansible_no_log": True,
        }
