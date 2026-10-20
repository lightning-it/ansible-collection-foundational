# Copyright: (c) 2026, Lightning IT
# SPDX-License-Identifier: MIT
"""Prepare ciphertext-only provider data from a decrypted, verified local header."""

from ansible.errors import AnsibleActionFail
from ansible.utils.unsafe_proxy import wrap_var
from .luks_header_escrow_read import ActionModule as HeaderReader
from .ansible_vault_secret_document import _VaultDocumentStore
from ..module_utils.luks_header_custody import digest, validate_package


class ActionModule(HeaderReader):
    def run(self, tmp=None, task_vars=None):
        args = dict(self._task.args)
        reader_keys = {"path", "subject", "luks_uuid", "ciphertext_sha256"}
        metadata_keys = {
            "source_machine_id",
            "owner",
            "retention",
            "key_retrieval_reference",
        }
        if set(args) != reader_keys | metadata_keys:
            raise AnsibleActionFail(
                "A complete pinned header and custody contract is required."
            )
        try:
            self._task.args = {key: args[key] for key in reader_keys}
            read = super().run(tmp, task_vars)
        finally:
            self._task.args = args
        document = read["document"]
        ciphertext = _VaultDocumentStore(
            self._loader._vault, max_ciphertext_bytes=64 * 1024 * 1024
        )._read_existing(args["path"])
        if ciphertext is None or digest(ciphertext) != args["ciphertext_sha256"]:
            raise AnsibleActionFail(
                "Pinned header ciphertext changed during preparation."
            )
        package = {
            "manifest": {
                "schema_version": 1,
                "subject": args["subject"],
                "luks_uuid": args["luks_uuid"],
                "source_machine_id": args["source_machine_id"],
                "ciphertext_sha256": args["ciphertext_sha256"],
                "luks_header_sha256_raw": document["luks_header_sha256_raw"],
                "luks_header_raw_size_bytes": document["luks_header_raw_size_bytes"],
                **{
                    key: args[key]
                    for key in ("owner", "retention", "key_retrieval_reference")
                },
            },
            "ciphertext": ciphertext.decode("ascii"),
        }
        try:
            raw = validate_package(package)
        except (ValueError, TypeError, KeyError):
            raise AnsibleActionFail(
                "Invalid ciphertext-only custody package."
            ) from None
        return {
            "changed": False,
            "package": wrap_var(package),
            "package_sha256": digest(raw),
            "_ansible_no_log": True,
        }
