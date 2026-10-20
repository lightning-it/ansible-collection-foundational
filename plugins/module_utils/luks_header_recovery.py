# Copyright: (c) 2026, Lightning IT
# SPDX-License-Identifier: MIT
"""Validate a bounded header envelope and restore only into an owned scratch file."""

import base64
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import tempfile
import uuid

MAX_HEADER = 20 * 1024 * 1024
FIELDS = {
    "schema_version",
    "subject",
    "luks_format",
    "luks_uuid",
    "luks_header_b64",
    "luks_header_raw_size_bytes",
    "luks_header_sha256_raw",
}


def validate_document(document, subject, luks_uuid):
    """Reject the wrong subject, disk or bytes before any temporary write."""
    if not isinstance(document, dict) or set(document) != FIELDS:
        raise ValueError("Unexpected encrypted header schema.")
    if not isinstance(subject, str) or not re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9._-]{0,252}", subject
    ):
        raise ValueError("An exact source subject is required.")
    if not isinstance(luks_uuid, str) or str(uuid.UUID(luks_uuid)) != luks_uuid:
        raise ValueError("A canonical source LUKS UUID is required.")
    if (
        type(document["schema_version"]) is not int
        or document["schema_version"] != 1
        or document["subject"] != subject
        or document["luks_uuid"] != luks_uuid
        or document["luks_format"] != "luks2"
    ):
        raise ValueError("The header does not match the exact source identity.")
    size = document["luks_header_raw_size_bytes"]
    encoded = document["luks_header_b64"]
    digest = document["luks_header_sha256_raw"]
    if (
        type(size) is not int
        or not 0 < size <= MAX_HEADER
        or not isinstance(encoded, str)
        or len(encoded) != ((size + 2) // 3) * 4
        or not isinstance(digest, str)
        or not re.fullmatch("[0-9a-f]{64}", digest)
    ):
        raise ValueError("The header exceeds its validated envelope.")
    try:
        raw = base64.b64decode(encoded, validate=True)
    except (ValueError, UnicodeError):
        raise ValueError("Invalid header encoding.") from None
    if len(raw) != size or hashlib.sha256(raw).hexdigest() != digest:
        raise ValueError("The header bytes do not match their checksum.")
    return raw


def witness_identity(source_machine_id, witness_machine_id):
    for identity in (source_machine_id, witness_machine_id):
        if not isinstance(identity, str) or not re.fullmatch("[0-9a-f]{32}", identity):
            raise ValueError("Pinned source and witness machine IDs are required.")
    if source_machine_id == witness_machine_id:
        raise ValueError("The recovery witness must be independent of the source.")
    if Path("/etc/machine-id").read_text().strip() != witness_machine_id:
        raise ValueError("Wrong recovery witness.")


def protected_tmpfs(root):
    if (
        not isinstance(root, str)
        or not os.path.isabs(root)
        or os.path.realpath(root) != root
    ):
        raise ValueError("The scratch root must be an existing canonical directory.")
    info = os.lstat(root)
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.geteuid()
        or info.st_mode & 0o022
    ):
        raise ValueError("The scratch root must be private to its effective owner.")
    mounts = []
    for line in Path("/proc/self/mountinfo").read_text().splitlines():
        before, after = line.split(" - ", 1)
        mount = before.split()[4].replace("\\040", " ")
        if root == mount or root.startswith(mount.rstrip("/") + "/"):
            mounts.append((len(mount), after.split()[0]))
    if not mounts or max(mounts)[1] != "tmpfs":
        raise ValueError("Raw recovery scratch must reside on tmpfs.")


def cryptsetup(*arguments, secret=None, accept_failure=False):
    result = subprocess.run(
        ["/usr/sbin/cryptsetup", *arguments],
        input=secret,
        capture_output=True,
        timeout=30,
        check=False,
        env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"},
    )
    if result.returncode and not accept_failure:
        raise RuntimeError("LUKS scratch verification failed; output suppressed.")
    return result


def write_private(path, content=None, size=None):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        if content is not None:
            with os.fdopen(os.dup(fd), "wb") as stream:
                stream.write(content)
                stream.flush()
        if size is not None:
            os.ftruncate(fd, size)
        os.fsync(fd)
    finally:
        os.close(fd)


def restore_drill(
    document,
    subject,
    luks_uuid,
    source_machine_id,
    witness_machine_id,
    passphrase,
    temporary_root="/run",
    check_mode=False,
):
    raw = validate_document(document, subject, luks_uuid)
    witness_identity(source_machine_id, witness_machine_id)
    protected_tmpfs(temporary_root)
    if (
        not isinstance(passphrase, str)
        or not 40 <= len(passphrase) <= 4096
        or "\x00" in passphrase
    ):
        raise ValueError(
            "An approved recovery passphrase must be supplied in protected memory."
        )
    tool = os.stat("/usr/sbin/cryptsetup")
    if not stat.S_ISREG(tool.st_mode) or tool.st_uid != 0 or tool.st_mode & 0o022:
        raise ValueError("The installed cryptsetup binary is not protected.")
    if check_mode:
        return {"changed": False, "verified": False, "check_mode": True}
    directory = None
    try:
        with tempfile.TemporaryDirectory(
            prefix="lit-luks-restore-", dir=temporary_root
        ) as directory:
            os.chmod(directory, 0o700)
            header, scratch = os.path.join(directory, "header.luks"), os.path.join(
                directory, "scratch.img"
            )
            write_private(header, content=raw)
            if cryptsetup("luksUUID", header).stdout.decode().strip() != luks_uuid:
                raise ValueError(
                    "The actual backup UUID differs from the expected source."
                )
            metadata = json.loads(
                cryptsetup("luksDump", "--dump-json-metadata", header).stdout
            )
            for keyslot in metadata.get("keyslots", {}).values():
                if int(keyslot.get("kdf", {}).get("memory", 0)) > 1048576:
                    raise ValueError(
                        "The header exceeds the witness KDF memory ceiling."
                    )
            offsets = [
                int(segment["offset"]) for segment in metadata["segments"].values()
            ]
            size = max(len(raw), max(offsets)) + 16 * 1024 * 1024
            if size > 128 * 1024 * 1024:
                raise ValueError("The header requires an oversized scratch device.")
            write_private(scratch, size=size)
            cryptsetup(
                "luksHeaderRestore",
                scratch,
                "--header-backup-file",
                header,
                "--batch-mode",
            )
            if cryptsetup("luksUUID", scratch).stdout.decode().strip() != luks_uuid:
                raise ValueError("Scratch restore UUID verification failed.")
            restored = json.loads(
                cryptsetup("luksDump", "--dump-json-metadata", scratch).stdout
            )
            if restored != metadata:
                raise ValueError("Scratch restore changed the expected LUKS2 metadata.")
            cryptsetup(
                "open",
                "--test-passphrase",
                "--key-file=-",
                scratch,
                secret=passphrase.encode(),
            )
            negative = cryptsetup(
                "open",
                "--test-passphrase",
                "--key-file=-",
                scratch,
                secret=secrets.token_bytes(64),
                accept_failure=True,
            )
            if negative.returncode != 2:
                raise ValueError(
                    "The invalid recovery key was not conclusively rejected."
                )
    finally:
        raw = None
    if directory is None or os.path.exists(directory):
        raise RuntimeError("Private scratch cleanup was not confirmed.")
    return {
        "changed": False,
        "verified": True,
        "luks_uuid": luks_uuid,
        "witness_machine_id": witness_machine_id,
        "wrong_key_rejected": True,
        "scratch_removed": True,
    }
