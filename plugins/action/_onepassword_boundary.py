# Copyright: (c) 2026, Lightning IT
# SPDX-License-Identifier: MIT

"""Controller-local trust boundaries shared by the 1Password actions."""

from __future__ import absolute_import, division, print_function

__metaclass__ = type

from datetime import datetime, timezone
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import stat

from ansible.errors import AnsibleActionFail


_DIGEST_PATTERN = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_EXECUTION_ID_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z", re.ASCII)
_GIT_SHA_PATTERN = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z", re.ASCII)
_NONCE_PATTERN = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_REPOSITORY_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,127}\Z", re.ASCII)
_TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
_MAX_APPROVAL_SECONDS = 900
_MAX_CLOCK_SKEW_SECONDS = 60
_APPROVAL_KEYS = frozenset(
    (
        "schema_version",
        "execution_id",
        "commit_shas",
        "nonce",
        "issued_at",
        "expires_at",
        "replay_directory",
        "confirmation",
    )
)


def _fail(message):
    raise AnsibleActionFail(message)


def normalize_sha256(value, name):
    """Require one complete lowercase SHA-256 digest."""
    if not isinstance(value, str) or not _DIGEST_PATTERN.fullmatch(value):
        _fail("{0} must be one complete lowercase SHA-256 digest.".format(name))
    return value


def normalize_object_id_list(value, name):
    """Require a unique, non-empty allowlist of 1Password object IDs."""
    pattern = re.compile(r"[a-z0-9]{26}\Z", re.ASCII)
    if (
        not isinstance(value, list)
        or not value
        or len(value) > 32
        or len(value) != len(set(value))
        or any(
            not isinstance(item, str) or not pattern.fullmatch(item)
            for item in value
        )
    ):
        _fail(
            "{0} must be a unique non-empty list of exact 1Password user "
            "UUIDs.".format(name)
        )
    return list(value)


def _safe_owner(status, name, controller_only=False):
    allowed = {os.getuid()} if controller_only else {0, os.getuid()}
    if status.st_uid not in allowed:
        _fail("{0} has an untrusted owner.".format(name))
    if status.st_mode & 0o022:
        _fail("{0} must not be group- or world-writable.".format(name))


def _validate_parent_chain(path, name):
    """Reject mutable parent directories except the root-owned sticky convention."""
    current = path
    while True:
        status = os.lstat(str(current))
        if not stat.S_ISDIR(status.st_mode):
            _fail("A parent of {0} is not a directory.".format(name))
        if status.st_uid not in (0, os.getuid()):
            _fail("A parent of {0} has an untrusted owner.".format(name))
        if status.st_mode & 0o022:
            if not (status.st_uid == 0 and status.st_mode & stat.S_ISVTX):
                _fail("A parent of {0} is group- or world-writable.".format(name))
        if current.parent == current:
            break
        current = current.parent


def trusted_executable(path, expected_sha256, name):
    """Resolve, inspect, hash, and return one approved executable."""
    expected_sha256 = normalize_sha256(expected_sha256, "{0}_sha256".format(name))
    if not isinstance(path, str) or not path or not os.path.isabs(path):
        _fail("{0} must be a non-empty absolute path.".format(name))
    if os.path.normpath(path) != path or any(
        character in path for character in "\x00\r\n"
    ):
        _fail("{0} must be an exact normalized path.".format(name))
    try:
        resolved = Path(path).resolve(strict=True)
    except OSError:
        _fail("{0} does not resolve to an existing controller file.".format(name))
    _validate_parent_chain(resolved.parent, name)
    flags = os.O_RDONLY
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(str(resolved), flags)
    except OSError:
        _fail(
            "{0} could not be opened without following a final symbolic "
            "link.".format(name)
        )
    digest = hashlib.sha256()
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or not before.st_mode & 0o111:
            _fail("{0} must resolve to an executable regular file.".format(name))
        _safe_owner(before, name)
        if before.st_nlink != 1:
            _fail("{0} must have exactly one filesystem link.".format(name))
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
        after = os.fstat(descriptor)
        if (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ):
            _fail("{0} changed while its digest was verified.".format(name))
    finally:
        os.close(descriptor)
    if not hmac.compare_digest(digest.hexdigest(), expected_sha256):
        _fail("{0} does not match its approved SHA-256 digest.".format(name))
    return str(resolved)


def trusted_agent_socket(path, name="agent_socket_path"):
    """Resolve the supported macOS alias and return one controller-owned socket."""
    if not isinstance(path, str) or not path or not os.path.isabs(path):
        _fail("{0} must be a non-empty absolute path.".format(name))
    if os.path.normpath(path) != path or any(
        character in path for character in "\x00\r\n"
    ):
        _fail("{0} must be an exact normalized path.".format(name))
    try:
        resolved = Path(path).resolve(strict=True)
    except OSError:
        _fail("{0} does not resolve to an existing controller socket.".format(name))
    _validate_parent_chain(resolved.parent, name)
    status = os.lstat(str(resolved))
    if not stat.S_ISSOCK(status.st_mode):
        _fail("{0} must resolve to a Unix-domain socket.".format(name))
    _safe_owner(status, name, controller_only=True)
    if status.st_nlink != 1:
        _fail("{0} must have exactly one filesystem link.".format(name))
    return str(resolved)


def trusted_regular_file(path, name, maximum_size=1048576):
    """Read one bounded, canonical, immutable regular controller file."""
    if not isinstance(path, str) or not path or not os.path.isabs(path):
        _fail("{0} must be a non-empty absolute path.".format(name))
    if os.path.normpath(path) != path or any(
        character in path for character in "\x00\r\n"
    ):
        _fail("{0} must be an exact normalized path.".format(name))
    try:
        resolved = Path(path).resolve(strict=True)
    except OSError:
        _fail("{0} does not resolve to an existing controller file.".format(name))
    if str(resolved) != path:
        _fail("{0} must be canonical and may not be a symbolic link.".format(name))
    _validate_parent_chain(resolved.parent, name)
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        descriptor = os.open(path, flags)
    except OSError:
        _fail("{0} could not be opened safely.".format(name))
    payload = bytearray()
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            _fail("{0} must be a regular file.".format(name))
        _safe_owner(before, name)
        if before.st_nlink != 1:
            _fail("{0} must have exactly one filesystem link.".format(name))
        if before.st_size < 1 or before.st_size > maximum_size:
            _fail("{0} size is outside the approved boundary.".format(name))
        while len(payload) <= maximum_size:
            chunk = os.read(descriptor, min(65536, maximum_size + 1 - len(payload)))
            if not chunk:
                break
            payload.extend(chunk)
        after = os.fstat(descriptor)
        if len(payload) > maximum_size:
            _fail("{0} exceeds the approved size boundary.".format(name))
        if (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ):
            _fail("{0} changed while it was read.".format(name))
    finally:
        os.close(descriptor)
    return str(resolved), payload


def _utc_timestamp(value, name):
    if not isinstance(value, str):
        _fail("{0} must be an exact UTC timestamp.".format(name))
    try:
        parsed = datetime.strptime(value, _TIMESTAMP_FORMAT).replace(tzinfo=timezone.utc)
    except ValueError:
        _fail("{0} must use YYYY-MM-DDTHH:MM:SSZ.".format(name))
    return parsed


def _canonical_json_value(value, name):
    if value is None or isinstance(value, (bool, int, str)):
        return value
    if isinstance(value, list):
        return [_canonical_json_value(item, name) for item in value]
    if isinstance(value, dict):
        normalized = {}
        for key, item in value.items():
            if not isinstance(key, str) or not key:
                _fail("{0} contains an invalid mapping key.".format(name))
            normalized[key] = _canonical_json_value(item, name)
        return normalized
    _fail("{0} must contain only JSON-safe scalar, list, or mapping values.".format(name))


def _normalize_approval_fields(approval):
    if not isinstance(approval, dict) or set(approval) != _APPROVAL_KEYS:
        _fail("approval must contain exactly the documented one-time authorization fields.")
    if approval.get("schema_version") != 1:
        _fail("approval.schema_version must be exactly 1.")
    execution_id = approval.get("execution_id")
    if not isinstance(execution_id, str) or not _EXECUTION_ID_PATTERN.fullmatch(execution_id):
        _fail("approval.execution_id is invalid.")
    commit_shas = approval.get("commit_shas")
    if (
        not isinstance(commit_shas, dict)
        or not commit_shas
        or len(commit_shas) > 32
        or any(
            not isinstance(repository, str)
            or not _REPOSITORY_PATTERN.fullmatch(repository)
            or not isinstance(commit_sha, str)
            or not _GIT_SHA_PATTERN.fullmatch(commit_sha)
            for repository, commit_sha in commit_shas.items()
        )
    ):
        _fail(
            "approval.commit_shas must pin one or more repositories to full "
            "lowercase Git SHAs."
        )
    nonce = approval.get("nonce")
    if not isinstance(nonce, str) or not _NONCE_PATTERN.fullmatch(nonce):
        _fail("approval.nonce must be 32 random bytes encoded as lowercase hexadecimal.")
    issued_at = _utc_timestamp(approval.get("issued_at"), "approval.issued_at")
    expires_at = _utc_timestamp(approval.get("expires_at"), "approval.expires_at")
    lifetime = (expires_at - issued_at).total_seconds()
    if lifetime <= 0 or lifetime > _MAX_APPROVAL_SECONDS:
        _fail("approval lifetime must be greater than zero and no longer than 15 minutes.")
    replay_directory = approval.get("replay_directory")
    if (
        not isinstance(replay_directory, str)
        or not replay_directory
        or not os.path.isabs(replay_directory)
    ):
        _fail("approval.replay_directory must be a non-empty absolute path.")
    if os.path.normpath(replay_directory) != replay_directory:
        _fail("approval.replay_directory must be normalized.")
    try:
        resolved_replay_directory = Path(replay_directory).resolve(strict=True)
    except OSError:
        _fail("approval.replay_directory does not exist.")
    if str(resolved_replay_directory) != replay_directory:
        _fail("approval.replay_directory must be canonical and may not be a symbolic link.")
    status = os.lstat(replay_directory)
    if not stat.S_ISDIR(status.st_mode):
        _fail("approval.replay_directory must be a directory.")
    _safe_owner(status, "approval.replay_directory", controller_only=True)
    if status.st_mode & 0o077:
        _fail("approval.replay_directory must be accessible only by the controller identity.")
    _validate_parent_chain(resolved_replay_directory.parent, "approval.replay_directory")
    confirmation = approval.get("confirmation")
    if not isinstance(confirmation, str):
        _fail("approval.confirmation must be a string.")
    return {
        "schema_version": 1,
        "execution_id": execution_id,
        "commit_shas": dict(sorted(commit_shas.items())),
        "nonce": nonce,
        "issued_at": issued_at,
        "issued_at_text": approval["issued_at"],
        "expires_at": expires_at,
        "expires_at_text": approval["expires_at"],
        "replay_directory": replay_directory,
        "confirmation": confirmation,
    }


def _approval_payload(normalized, operation, target, binding):
    return {
        "schema_version": normalized["schema_version"],
        "execution_id": normalized["execution_id"],
        "commit_shas": normalized["commit_shas"],
        "nonce": normalized["nonce"],
        "issued_at": normalized["issued_at_text"],
        "expires_at": normalized["expires_at_text"],
        "replay_directory": normalized["replay_directory"],
        "operation": operation,
        "target": target,
        "binding": _canonical_json_value(binding, "approval binding"),
    }


def approval_confirmation(approval, operation, target, binding):
    """Build the exact confirmation string for external approval tooling."""
    if not isinstance(approval, dict):
        _fail("approval must be a mapping.")
    candidate = dict(approval)
    candidate.setdefault("confirmation", "")
    normalized = _normalize_approval_fields(candidate)
    payload = _approval_payload(normalized, operation, target, binding)
    serialized = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")
    digest = hashlib.sha256(serialized).hexdigest()
    return "APPROVE:{0}:{1}".format(normalized["execution_id"], digest)


def normalize_approval(approval, operation, target, binding, now=None):
    """Validate an expiring approval and prepare its replay-safe claim."""
    normalized = _normalize_approval_fields(approval)
    if not isinstance(operation, str) or not operation:
        _fail("approval operation binding is invalid.")
    if not isinstance(target, str) or not target:
        _fail("approval target binding is invalid.")
    expected = approval_confirmation(approval, operation, target, binding)
    if not hmac.compare_digest(normalized["confirmation"], expected):
        _fail("approval.confirmation does not match the bound execution contract.")
    current = datetime.now(timezone.utc) if now is None else now
    if current.tzinfo is None:
        _fail("approval validation time must be timezone-aware.")
    if current < normalized["issued_at"]:
        if (normalized["issued_at"] - current).total_seconds() > _MAX_CLOCK_SKEW_SECONDS:
            _fail("approval is not yet valid.")
    if current >= normalized["expires_at"]:
        _fail("approval has expired.")
    payload = _approval_payload(normalized, operation, target, binding)
    serialized = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")
    approval_digest = hashlib.sha256(serialized).hexdigest()
    marker = os.path.join(normalized["replay_directory"], approval_digest + ".used")
    if os.path.lexists(marker):
        _fail("approval nonce has already been consumed.")
    return {
        "execution_id": normalized["execution_id"],
        "commit_shas": normalized["commit_shas"],
        "issued_at": normalized["issued_at_text"],
        "expires_at": normalized["expires_at_text"],
        "approval_digest": approval_digest,
        "_replay_directory": normalized["replay_directory"],
    }


def claim_approval(normalized, now=None):
    """Atomically consume one normalized approval before a mutating operation."""
    current = datetime.now(timezone.utc) if now is None else now
    issued_at = _utc_timestamp(normalized.get("issued_at"), "approval.issued_at")
    expires_at = _utc_timestamp(normalized.get("expires_at"), "approval.expires_at")
    if current.tzinfo is None:
        _fail("approval validation time must be timezone-aware.")
    if (
        current < issued_at
        and (issued_at - current).total_seconds() > _MAX_CLOCK_SKEW_SECONDS
    ):
        _fail("approval is not yet valid at claim time.")
    if current >= expires_at:
        _fail("approval expired before it could be consumed.")
    replay_directory = normalized.get("_replay_directory")
    approval_digest = normalized.get("approval_digest")
    normalize_sha256(approval_digest, "approval_digest")
    directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    directory_flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        directory_descriptor = os.open(replay_directory, directory_flags)
    except OSError:
        _fail("approval replay directory could not be opened safely.")
    marker_name = approval_digest + ".used"
    marker_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    marker_flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    marker_descriptor = -1
    try:
        directory_status = os.fstat(directory_descriptor)
        _safe_owner(directory_status, "approval.replay_directory", controller_only=True)
        if directory_status.st_mode & 0o077:
            _fail("approval.replay_directory permissions changed before claim.")
        try:
            marker_descriptor = os.open(
                marker_name,
                marker_flags,
                0o600,
                dir_fd=directory_descriptor,
            )
        except FileExistsError:
            _fail("approval nonce has already been consumed.")
        except OSError:
            _fail("approval nonce could not be claimed atomically.")
        evidence = json.dumps(
            {
                "schema_version": 1,
                "execution_id": normalized.get("execution_id"),
                "commit_shas": normalized.get("commit_shas"),
                "issued_at": normalized.get("issued_at"),
                "expires_at": normalized.get("expires_at"),
                "approval_digest": approval_digest,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
        offset = 0
        while offset < len(evidence):
            written = os.write(marker_descriptor, evidence[offset:])
            if written <= 0:
                _fail("approval replay evidence could not be written completely.")
            offset += written
        os.fsync(marker_descriptor)
        os.fsync(directory_descriptor)
    finally:
        if marker_descriptor >= 0:
            os.close(marker_descriptor)
        os.close(directory_descriptor)
    return True


def safe_approval_metadata(normalized):
    """Return only the non-secret, non-replayable approval evidence."""
    return {
        "execution_id": normalized["execution_id"],
        "commit_shas": dict(normalized["commit_shas"]),
        "issued_at": normalized["issued_at"],
        "expires_at": normalized["expires_at"],
        "approval_digest": normalized["approval_digest"],
    }
