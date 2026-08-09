# Copyright: (c) 2026, Lightning IT
# SPDX-License-Identifier: MIT

"""Create one short-lived SSHSIG approval on the Ansible controller."""

from __future__ import absolute_import, division, print_function

__metaclass__ = type

from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import tempfile

from ansible.errors import AnsibleActionFail
from ansible.plugins.action import ActionBase

from ._onepassword_boundary import (
    _validate_parent_chain,
    _write_private_file,
    approval_signing_payload,
    normalize_approval,
    normalize_approval_authority,
    safe_approval_metadata,
    trusted_executable,
)


_EXPECTED_ARGS = frozenset(
    {
        "approval_authority",
        "binding",
        "commit_shas",
        "execution_id_prefix",
        "operation",
        "signing_key_path",
        "target",
        "validity_seconds",
    }
)
_COMMIT_PATTERN = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z", re.ASCII)
_NAME_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,127}\Z", re.ASCII)
_EXECUTION_PREFIX_PATTERN = re.compile(
    r"[A-Za-z0-9][A-Za-z0-9._:-]{0,79}\Z", re.ASCII
)


def _fail(message):
    raise AnsibleActionFail(message)


def _normalize_commit_shas(value):
    if (
        not isinstance(value, dict)
        or not value
        or len(value) > 32
        or any(
            not isinstance(name, str)
            or not _NAME_PATTERN.fullmatch(name)
            or not isinstance(commit, str)
            or not _COMMIT_PATTERN.fullmatch(commit)
            for name, commit in value.items()
        )
    ):
        _fail("commit_shas must contain exact repository names and full Git SHAs.")
    return dict(sorted(value.items()))


def _trusted_signing_key(path):
    if (
        not isinstance(path, str)
        or not os.path.isabs(path)
        or os.path.normpath(path) != path
        or any(character in path for character in "\x00\r\n")
    ):
        _fail("signing_key_path must be one normalized absolute path.")
    try:
        resolved = Path(path).resolve(strict=True)
    except OSError:
        _fail("signing_key_path does not exist.")
    if str(resolved) != path:
        _fail("signing_key_path must be canonical and may not be a symbolic link.")
    _validate_parent_chain(resolved.parent, "signing_key_path")
    status = os.lstat(path)
    if (
        not stat.S_ISREG(status.st_mode)
        or stat.S_ISLNK(status.st_mode)
        or status.st_uid not in {0, os.getuid()}
        or status.st_mode & 0o077
        or status.st_nlink != 1
    ):
        _fail("signing_key_path must be one owner-only regular file.")
    return str(resolved)


def _normalize_arguments(args, now=None):
    if not isinstance(args, dict) or set(args) != _EXPECTED_ARGS:
        _fail("onepassword_approval arguments do not match the closed schema.")
    authority = normalize_approval_authority(args["approval_authority"])
    operation = args["operation"]
    target = args["target"]
    prefix = args["execution_id_prefix"]
    validity = args["validity_seconds"]
    if not isinstance(operation, str) or not _NAME_PATTERN.fullmatch(operation):
        _fail("operation is invalid.")
    if not isinstance(target, str) or not target or len(target) > 253:
        _fail("target is invalid.")
    if not isinstance(prefix, str) or not _EXECUTION_PREFIX_PATTERN.fullmatch(prefix):
        _fail("execution_id_prefix is invalid.")
    if not isinstance(validity, int) or not 60 <= validity <= 900:
        _fail("validity_seconds must be between 60 and 900.")
    now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc).replace(
        microsecond=0
    )
    approval = {
        "schema_version": 1,
        "execution_id": "{0}-{1}-{2}".format(
            prefix,
            now.strftime("%Y%m%dT%H%M%SZ"),
            secrets.token_hex(4),
        ),
        "commit_shas": _normalize_commit_shas(args["commit_shas"]),
        "nonce": secrets.token_hex(32),
        "issued_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "expires_at": (now + timedelta(seconds=validity)).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        ),
        "replay_directory": authority["replay_directory"],
    }
    return {
        "approval": approval,
        "authority": authority,
        "binding": args["binding"],
        "operation": operation,
        "signing_key_path": _trusted_signing_key(args["signing_key_path"]),
        "target": target,
        "now": now,
    }


def _sign(config):
    payload = approval_signing_payload(
        config["approval"],
        config["authority"],
        config["operation"],
        config["target"],
        config["binding"],
    )
    ssh_keygen = trusted_executable(
        config["authority"]["_requested_ssh_keygen_path"],
        config["authority"]["ssh_keygen_sha256"],
        "approval_ssh_keygen_path",
    )
    temporary_root = tempfile.mkdtemp(prefix="lit-onepassword-approval-sign-")
    os.chmod(temporary_root, 0o700)
    payload_path = os.path.join(temporary_root, "approval.json")
    signature_path = payload_path + ".sig"
    try:
        _write_private_file(payload_path, payload)
        try:
            completed = subprocess.run(
                [
                    ssh_keygen,
                    "-Y",
                    "sign",
                    "-f",
                    config["signing_key_path"],
                    "-n",
                    config["authority"]["namespace"],
                    payload_path,
                ],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                env={"LANG": "C", "LC_ALL": "C"},
                check=False,
                timeout=30,
            )
        except (OSError, subprocess.SubprocessError):
            _fail("Approval signing could not be executed.")
        if completed.returncode != 0:
            _fail("Approval signing failed closed.")
        try:
            signature = Path(signature_path).read_text(encoding="ascii")
        except (OSError, UnicodeError):
            _fail("Approval signature could not be read.")
        signed = dict(config["approval"])
        signed["signature"] = signature
        normalized = normalize_approval(
            signed,
            {
                "schema_version": config["authority"]["schema_version"],
                "identity": config["authority"]["identity"],
                "namespace": config["authority"]["namespace"],
                "fingerprint": config["authority"]["fingerprint"],
                "allowed_signers_path": config["authority"][
                    "_requested_allowed_signers_path"
                ],
                "allowed_signers_sha256": config["authority"][
                    "allowed_signers_sha256"
                ],
                "ssh_keygen_path": config["authority"][
                    "_requested_ssh_keygen_path"
                ],
                "ssh_keygen_sha256": config["authority"]["ssh_keygen_sha256"],
                "replay_directory": config["authority"]["replay_directory"],
            },
            config["operation"],
            config["target"],
            config["binding"],
            now=config["now"],
        )
        return {
            "changed": False,
            "approval": signed,
            "approval_metadata": safe_approval_metadata(normalized),
        }
    finally:
        for path in (signature_path, payload_path):
            if os.path.lexists(path):
                os.unlink(path)
        os.rmdir(temporary_root)


class ActionModule(ActionBase):
    """Controller-only approval signer."""

    TRANSFERS_FILES = False
    _requires_connection = False
    _supports_check_mode = True
    _VALID_ARGS = _EXPECTED_ARGS

    def run(self, tmp=None, task_vars=None):
        if task_vars is None:
            task_vars = {}
        self._task.no_log = True
        super(ActionModule, self).run(tmp, task_vars)
        return _sign(_normalize_arguments(dict(self._task.args)))
