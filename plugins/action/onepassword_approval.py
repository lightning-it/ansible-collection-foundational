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
import subprocess
import tempfile

from ansible.errors import AnsibleActionFail
from ansible.plugins.action import ActionBase

from ._onepassword_boundary import (
    _write_private_file,
    approval_signing_payload,
    normalize_approval,
    normalize_approval_authority,
    safe_approval_metadata,
    trusted_agent_socket,
    trusted_executable,
)


_EXPECTED_ARGS = frozenset(
    {
        "approval_authority",
        "binding",
        "commit_shas",
        "execution_id_prefix",
        "operation",
        "signing_agent_socket_path",
        "signing_ssh_add_path",
        "signing_ssh_add_sha256",
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


def _authority_public_key(authority):
    try:
        rows = authority["_allowed_signers_payload"].decode(
            "ascii", errors="strict"
        ).splitlines()
    except (KeyError, UnicodeError):
        _fail("Approval Authority public-key material is invalid.")
    entries = [
        row.strip()
        for row in rows
        if row.strip() and not row.lstrip().startswith("#")
    ]
    if len(entries) != 1:
        _fail("Approval Authority must contain exactly one signer entry.")
    fields = entries[0].split()
    if len(fields) not in (3, 4):
        _fail("Approval Authority signer entry is invalid.")
    return "{0} {1}".format(fields[1], fields[2])


def _verified_agent_signer(config):
    ssh_add = trusted_executable(
        config["signing_ssh_add_path"],
        config["signing_ssh_add_sha256"],
        "signing_ssh_add_path",
    )
    agent_socket = trusted_agent_socket(
        config["signing_agent_socket_path"], "signing_agent_socket_path"
    )
    environment = {
        "LANG": "C",
        "LC_ALL": "C",
        "SSH_AUTH_SOCK": agent_socket,
    }
    try:
        completed = subprocess.run(
            [ssh_add, "-L"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env=environment,
            check=False,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError):
        _fail("The approved signing SSH Agent could not be inspected safely.")
    if completed.returncode != 0 or len(completed.stdout) > 65536:
        _fail("The approved signing SSH Agent is unavailable or locked.")
    try:
        rows = completed.stdout.decode("ascii", errors="strict").splitlines()
    except UnicodeError:
        _fail("The approved signing SSH Agent returned invalid public metadata.")
    expected_public_key = config["signing_public_key"]
    matches = [
        row
        for row in rows
        if " ".join(row.strip().split()[:2]) == expected_public_key
    ]
    if len(matches) != 1:
        _fail(
            "The exact Approval Authority key is not uniquely available from "
            "the approved signing SSH Agent."
        )
    return agent_socket


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
        "signing_agent_socket_path": args["signing_agent_socket_path"],
        "signing_ssh_add_path": args["signing_ssh_add_path"],
        "signing_ssh_add_sha256": args["signing_ssh_add_sha256"],
        "signing_public_key": _authority_public_key(authority),
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
    public_key_path = os.path.join(temporary_root, "signer.pub")
    signature_path = payload_path + ".sig"
    try:
        _write_private_file(payload_path, payload)
        _write_private_file(
            public_key_path, (config["signing_public_key"] + "\n").encode("ascii")
        )
        agent_socket = _verified_agent_signer(config)
        try:
            completed = subprocess.run(
                [
                    ssh_keygen,
                    "-Y",
                    "sign",
                    "-f",
                    public_key_path,
                    "-n",
                    config["authority"]["namespace"],
                    payload_path,
                ],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                env={
                    "LANG": "C",
                    "LC_ALL": "C",
                    "SSH_AUTH_SOCK": agent_socket,
                },
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
        for path in (signature_path, public_key_path, payload_path):
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
