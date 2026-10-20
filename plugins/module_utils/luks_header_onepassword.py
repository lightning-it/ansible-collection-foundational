# Copyright: (c) 2026, Lightning IT
# SPDX-License-Identifier: MIT
"""Native desktop Document transport; only encrypted header packages cross it."""

import json
import os
import platform
import re
import selectors
import subprocess
import time

from .luks_header_custody import (
    MAX_PACKAGE,
    decode_package,
    digest,
    validate_package,
    validate_read_pins,
    verify_download,
)
from .onepassword_boundary import claim_approval, normalize_approval, trusted_executable


class NativeCLI:
    def __init__(self, config):
        self.config = config
        if (
            os.geteuid() != config["executor_uid"]
            or platform.node() != config["executor_node"]
        ):
            raise ValueError("Wrong native 1Password executor identity.")
        if any(
            value
            for name, value in os.environ.items()
            if name
            in ("OP_SERVICE_ACCOUNT_TOKEN", "OP_CONNECT_TOKEN", "OP_CONNECT_HOST")
            or name.startswith("OP_SESSION_")
        ):
            raise ValueError("Only the approved desktop integration is permitted.")
        self.env = {
            key: os.environ[key]
            for key in ("HOME", "PATH", "TMPDIR", "LANG", "LC_ALL")
            if os.environ.get(key)
        }
        if not self.env.get("HOME"):
            raise ValueError("Native desktop HOME is required.")

    def run(self, arguments, payload=b"", limit=1024 * 1024):
        binary = trusted_executable(
            self.config["cli_path"], self.config["cli_sha256"], "cli_path"
        )
        process = subprocess.Popen(
            [binary, *arguments],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env=self.env,
            start_new_session=True,
        )
        output = bytearray()
        offset = 0
        deadline = time.monotonic() + 60
        try:
            with selectors.DefaultSelector() as selector:
                os.set_blocking(process.stdout.fileno(), False)
                os.set_blocking(process.stdin.fileno(), False)
                selector.register(process.stdout, selectors.EVENT_READ)
                if payload:
                    selector.register(process.stdin, selectors.EVENT_WRITE)
                else:
                    process.stdin.close()
                while selector.get_map():
                    if time.monotonic() >= deadline:
                        raise ValueError(
                            "1Password operation timed out; inspect outcome before retry."
                        )
                    for key, event in selector.select(timeout=0.2):
                        if event & selectors.EVENT_WRITE:
                            written = os.write(key.fd, payload[offset : offset + 65536])
                            offset += written
                            if offset == len(payload):
                                selector.unregister(key.fileobj)
                                process.stdin.close()
                        else:
                            data = os.read(key.fd, min(65536, limit + 1 - len(output)))
                            if not data:
                                selector.unregister(key.fileobj)
                            else:
                                output.extend(data)
                                if len(output) > limit:
                                    raise ValueError(
                                        "1Password response exceeded its bound."
                                    )
                code = process.wait(timeout=max(0.1, deadline - time.monotonic()))
                if code:
                    raise ValueError(
                        "1Password operation failed; no automatic write retry."
                    )
                return bytes(output)
        finally:
            if process.poll() is None:
                process.kill()
            process.wait()
            process.stdout.close()
            if not process.stdin.closed:
                process.stdin.close()

    def metadata(self, arguments):
        return json.loads(self.run(arguments))

    def metadata_create(self, arguments, payload):
        return json.loads(self.run(arguments, payload=payload))


CONFIG_FIELDS = {
    "cli_path",
    "cli_sha256",
    "cli_version",
    "account_id",
    "account_sign_in_address",
    "authorized_user_uuids",
    "vault_id",
    "item_title",
    "item_id",
    "item_version",
    "executor_uid",
    "executor_node",
}


def validate_config(config):
    if not isinstance(config, dict) or set(config) != CONFIG_FIELDS:
        raise ValueError("The complete closed native 1Password contract is required.")
    for key in ("account_id",):
        if not isinstance(config[key], str) or not re.fullmatch(
            r"[A-Z0-9]{26}", config[key]
        ):
            raise ValueError("Invalid 1Password account identity.")
    if not re.fullmatch(r"[a-z0-9]{26}", config["vault_id"]):
        raise ValueError("Invalid 1Password vault identity.")
    if (
        type(config["executor_uid"]) is not int
        or config["executor_uid"] <= 0
        or not isinstance(config["executor_node"], str)
        or not config["executor_node"]
    ):
        raise ValueError("Exact native executor UID and node are required.")
    if (
        not re.fullmatch(r"[0-9a-f]{64}", config["cli_sha256"])
        or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", config["cli_version"])
        or not isinstance(config["cli_path"], str)
        or not config["cli_path"].startswith("/")
    ):
        raise ValueError("Exact approved CLI bytes and version are required.")
    if not re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9.-]{0,251}", config["account_sign_in_address"]
    ):
        raise ValueError("Exact 1Password sign-in address is required.")
    users = config["authorized_user_uuids"]
    if (
        not isinstance(users, list)
        or not users
        or len(users) != len(set(users))
        or any(
            not isinstance(user, str) or not re.fullmatch(r"[A-Z0-9]{26}", user)
            for user in users
        )
    ):
        raise ValueError("Exact allowed operator identities are required.")
    title = config["item_title"]
    if (
        not isinstance(title, str)
        or not 1 <= len(title) <= 250
        or title != title.strip()
        or any(ord(c) < 32 for c in title)
    ):
        raise ValueError("An exact safe Document title is required.")
    identity, version = config["item_id"], config["item_version"]
    if (
        type(version) is not int
        or version < 0
        or bool(identity) != bool(version)
        or identity
        and not re.fullmatch(r"[a-z0-9]{26}", identity)
    ):
        raise ValueError("Pin an exact existing item and positive version together.")


def inspect(cli, config, sha):
    if cli.run(["--version"]).decode("ascii").strip() != config["cli_version"]:
        raise ValueError("Native 1Password CLI version drift.")
    account = ["--account", config["account_id"]]
    identity = cli.metadata(["whoami", *account, "--format", "json"])
    if (
        identity.get("account_uuid") != config["account_id"]
        or identity.get("user_uuid") not in config["authorized_user_uuids"]
        or identity.get("url", "").lower().rstrip("/")
        != "https://" + config["account_sign_in_address"].lower()
    ):
        raise ValueError("Native account or operator identity drift.")
    vault = cli.metadata(
        ["vault", "get", config["vault_id"], *account, "--format", "json"]
    )
    if vault.get("id") != config["vault_id"]:
        raise ValueError("Native vault identity drift.")
    rows = cli.metadata(
        ["item", "list", "--vault", config["vault_id"], *account, "--format", "json"]
    )
    if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
        raise ValueError("Invalid native item metadata.")
    matches = [
        row
        for row in rows
        if row.get("title") == config["item_title"]
        or config["item_id"]
        and row.get("id") == config["item_id"]
    ]
    if not matches:
        if config["item_id"]:
            raise ValueError("The pinned native header object is missing.")
        return None
    if len(matches) != 1:
        raise ValueError("Ambiguous native header objects; no creation or overwrite.")
    row = matches[0]
    if (
        row.get("title") != config["item_title"]
        or row.get("category") != "DOCUMENT"
        or not re.fullmatch(r"[a-z0-9]{26}", row.get("id", ""))
        or type(row.get("version")) is not int
        or row["version"] < 1
        or sorted(row.get("tags", [])) != sorted(["luks-header-custody", sha])
        or config["item_id"]
        and (row["id"] != config["item_id"] or row["version"] != config["item_version"])
    ):
        raise ValueError(
            "Native header object identity, version, type or checksum tag drift."
        )
    return {key: row[key] for key in ("id", "version")}


def onepassword_read_custody(cli, config, pins):
    """Retrieve without a local artifact, using a separately retained exact receipt."""
    validate_config(config)
    validate_read_pins(pins)
    if not config["item_id"] or config["item_version"] <= 0:
        raise ValueError(
            "Independent retrieval requires the exact retained Document ID and version."
        )
    current = inspect(cli, config, pins["package_sha256"])
    if current is None:
        raise ValueError("The independent native header copy is absent.")
    raw = cli.run(
        [
            "document",
            "get",
            current["id"],
            "--account",
            config["account_id"],
            "--vault",
            config["vault_id"],
        ],
        limit=MAX_PACKAGE,
    )
    package = verify_download(raw, pins)
    if inspect(cli, config, pins["package_sha256"]) != current:
        raise ValueError("Native header revision changed during independent retrieval.")
    return {
        "changed": False,
        "verified": True,
        "package": package,
        "package_sha256": pins["package_sha256"],
        "item_id": current["id"],
        "item_version": current["version"],
    }


def onepassword_custody(
    cli,
    config,
    package,
    operation="verify",
    check_mode=False,
    allow_create=False,
    approval=None,
    authority=None,
):
    validate_config(config)
    if operation not in ("plan", "apply", "verify"):
        raise ValueError("Invalid custody operation.")
    raw = validate_package(package)
    sha = digest(raw)
    current = inspect(cli, config, sha)
    changed = False
    if current is None and operation == "verify":
        raise ValueError("The independent 1Password header copy is missing.")
    if current is None and operation == "apply" and not check_mode:
        if allow_create is not True:
            raise ValueError("Native header creation is not enabled.")
        binding = {"config": config, "package_sha256": sha, "allow_create": True}
        normalized = normalize_approval(
            approval,
            authority,
            "create-onepassword-header-document",
            package["manifest"]["subject"],
            binding,
        )
        if inspect(cli, config, sha) is not None:
            raise ValueError(
                "Native custody changed during approval validation; re-plan."
            )
        claim_approval(normalized)
        result = cli.metadata_create(
            [
                "document",
                "create",
                "-",
                "--account",
                config["account_id"],
                "--vault",
                config["vault_id"],
                "--title",
                config["item_title"],
                "--tags",
                "luks-header-custody," + sha,
                "--file-name",
                sha + ".json",
                "--format",
                "json",
            ],
            raw,
        )
        current = inspect(cli, config, sha)
        if current is None or result.get("id") != current["id"]:
            raise ValueError(
                "Native creation outcome is not uniquely verified; inspect before retry."
            )
        changed = True
    if current is not None:
        downloaded = cli.run(
            [
                "document",
                "get",
                current["id"],
                "--account",
                config["account_id"],
                "--vault",
                config["vault_id"],
            ],
            limit=MAX_PACKAGE,
        )
        decode_package(downloaded, raw)
        if inspect(cli, config, sha) != current:
            raise ValueError("Native header revision changed during document readback.")
    return {
        "changed": changed,
        "verified": current is not None,
        "planned": current is None,
        "package_sha256": sha,
        "item_id": current["id"] if current else None,
        "item_version": current["version"] if current else None,
    }
