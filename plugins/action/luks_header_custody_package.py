# Copyright: (c) 2026, Lightning IT
# SPDX-License-Identifier: MIT
"""Immutable ciphertext-only handoff between capture and provider credentials."""

import os
from ansible.errors import AnsibleActionFail
from ansible.plugins.action import ActionBase
from ansible.utils.unsafe_proxy import wrap_var
from .ansible_vault_secret_document import _VaultDocumentStore
from ..module_utils.luks_header_custody import (
    MAX_PACKAGE,
    decode_package,
    digest,
    validate_package,
)


class ActionModule(ActionBase):
    TRANSFERS_FILES = False
    _requires_connection = False
    _supports_check_mode = True

    def run(self, tmp=None, task_vars=None):
        if getattr(self._task, "no_log", None) is not True:
            self._task.no_log = True
            raise AnsibleActionFail(
                "Ciphertext package operations require task-level no_log=true."
            )
        super().run(tmp, task_vars or {})
        args = dict(self._task.args)
        required = {
            "operation",
            "path",
            "package_sha256",
            "subject",
            "source_machine_id",
            "luks_uuid",
        }
        if set(args) not in (required, required | {"package"}):
            raise AnsibleActionFail(
                "A closed pinned ciphertext handoff contract is required."
            )
        path, expected = args["path"], args["package_sha256"]
        if (
            not isinstance(path, str)
            or not os.path.isabs(path)
            or os.path.normpath(path) != path
        ):
            raise AnsibleActionFail(
                "An exact absolute ciphertext package path is required."
            )
        if args["operation"] not in ("export", "read", "materialize"):
            raise AnsibleActionFail(
                "Ciphertext handoff operation must be export, read or materialize."
            )
        store = _VaultDocumentStore(None, max_ciphertext_bytes=MAX_PACKAGE)
        current = store._read_existing(path)
        changed = False
        try:
            if args["operation"] in ("export", "materialize"):
                raw = validate_package(args["package"])
                if digest(raw) != expected:
                    raise ValueError(
                        "Ciphertext package differs from producer receipt."
                    )
                if any(
                    args["package"]["manifest"][key] != args[key]
                    for key in ("subject", "source_machine_id", "luks_uuid")
                ):
                    raise ValueError("Ciphertext handoff source identity mismatch.")
                if args["operation"] == "materialize":
                    raw = args["package"]["ciphertext"].encode("ascii")
                if current is not None and current != raw:
                    raise ValueError("Existing ciphertext handoff is immutable.")
                if current is None:
                    if self._task.check_mode:
                        return {
                            "changed": True,
                            "verified": False,
                            "package_sha256": expected,
                        }
                    changed = store._exclusive_create(path, raw)
                    current = store._read_existing(path)
                if args["operation"] == "materialize":
                    if current != raw:
                        raise ValueError(
                            "Retrieved ciphertext changed during materialization."
                        )
                    return {
                        "changed": changed,
                        "verified": True,
                        "path": path,
                        "package_sha256": expected,
                        "ciphertext_sha256": digest(raw),
                        "_ansible_no_log": True,
                    }
            if current is None or digest(current) != expected:
                raise ValueError("Ciphertext handoff is absent or changed.")
            import json

            package = json.loads(current)
            decode_package(current, validate_package(package))
            if any(
                package["manifest"][key] != args[key]
                for key in ("subject", "source_machine_id", "luks_uuid")
            ):
                raise ValueError("Ciphertext handoff source identity mismatch.")
        except (ValueError, TypeError, KeyError, UnicodeError):
            raise AnsibleActionFail(
                "Ciphertext handoff verification failed closed."
            ) from None
        return {
            "changed": changed,
            "verified": True,
            "package": wrap_var(package),
            "package_sha256": expected,
            "path": path,
            "_ansible_no_log": True,
        }
