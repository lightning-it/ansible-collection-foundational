# Copyright: (c) 2026, Lightning IT
# SPDX-License-Identifier: MIT
"""Prepare and consume a ciphertext-only native desktop provider exchange."""

import os
from pathlib import Path
import stat

from ansible.errors import AnsibleActionFail
from ansible.plugins.action import ActionBase
from ansible.utils.unsafe_proxy import wrap_var

from .ansible_vault_secret_document import _VaultDocumentStore
from ..module_utils.onepassword_boundary import _validate_parent_chain
from ..module_utils.luks_header_native_handoff import (
    MAX_HANDOFF,
    canonical,
    decode,
    validate_request,
    validate_response,
)


class ActionModule(ActionBase):
    TRANSFERS_FILES = False
    _requires_connection = False
    _supports_check_mode = True

    def run(self, tmp=None, task_vars=None):
        if getattr(self._task, "no_log", None) is not True:
            self._task.no_log = True
            raise AnsibleActionFail("Native handoff requires task-level no_log=true.")
        super().run(tmp, task_vars or {})
        args = dict(self._task.args)
        try:
            if set(args) != {"operation", "request", "request_path", "response_path"}:
                raise ValueError("A closed native handoff contract is required.")
            if args["operation"] not in ("prepare", "consume"):
                raise ValueError("Invalid native handoff action.")
            request = args["request"]
            sha = validate_request(request)
            for name in ("request_path", "response_path"):
                path = args[name]
                if (
                    not isinstance(path, str)
                    or not os.path.isabs(path)
                    or os.path.normpath(path) != path
                    or any(c in path for c in "\x00\r\n")
                ):
                    raise ValueError(
                        "Exact absolute native exchange paths are required."
                    )
                parent = Path(path).parent
                _validate_parent_chain(parent, name)
                info = os.lstat(parent)
                if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
                    raise ValueError(
                        "Native exchange requires an existing owner-only directory."
                    )
            store = _VaultDocumentStore(None, max_ciphertext_bytes=MAX_HANDOFF)
            # _read_existing and _exclusive_create require canonical owner-only
            # files/directories, reject symlink/hardlink/race paths, never overwrite.
            existing = store._read_existing(args["request_path"])
            raw = canonical(request)
            if args["request_path"] == args["response_path"]:
                raise ValueError("Native request and response paths must differ.")
            if existing is not None and existing != raw:
                raise ValueError(
                    "Native request is immutable; use a new operation path."
                )
            if args["operation"] == "prepare":
                changed = existing is None
                if changed and not self._task.check_mode:
                    store._exclusive_create(args["request_path"], raw)
                    if store._read_existing(args["request_path"]) != raw:
                        raise ValueError("Native request changed during export.")
                return {
                    "changed": changed,
                    "verified": False,
                    "request_sha256": sha,
                    "request_path": args["request_path"],
                    "status": "native_execution_and_response_still_required",
                    "_ansible_no_log": True,
                }
            if self._task.check_mode:
                raise ValueError("Check mode cannot accept a native provider response.")
            if existing is None:
                raise ValueError("The exact exported native request is required.")
            response = store._read_existing(args["response_path"])
            if response is None:
                raise ValueError("Native execution response is missing.")
            result = validate_response(request, decode(response))
            return {**wrap_var(result), "request_sha256": sha, "_ansible_no_log": True}
        except Exception:
            raise AnsibleActionFail(
                "Native handoff rejected; retain the exact request and independently verified native execution receipt."
            ) from None
