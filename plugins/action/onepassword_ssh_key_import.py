# Copyright: (c) 2026, Lightning IT
# SPDX-License-Identifier: MIT

"""Import one exact local Ed25519 key into 1Password without exporting it."""

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile

from ansible.errors import AnsibleActionFail
from ansible.plugins.action import ActionBase

from ._onepassword_boundary import (
    _write_private_file,
    trusted_executable,
    trusted_regular_file,
)
from .onepassword_ssh_key_item import (
    _FINGERPRINT_PATTERN,
    _OnePasswordCLI,
    _OnePasswordSSHKeyItemStore,
    _normalize_arguments,
    _public_identity,
)


_EXPECTED_ARGS = frozenset(
    {
        "account_id",
        "account_sign_in_address",
        "action",
        "agent_socket_path",
        "allow_import",
        "authorized_user_uuids",
        "category",
        "cli_path",
        "cli_sha256",
        "cli_version",
        "confirmation",
        "expected_fingerprint",
        "item_id",
        "item_title",
        "item_version",
        "key_type",
        "private_key_path",
        "schema_version",
        "ssh_add_path",
        "ssh_add_sha256",
        "ssh_keygen_path",
        "ssh_keygen_sha256",
        "subject",
        "tags",
        "vault_id",
    }
)


def _fail(message):
    raise AnsibleActionFail(message)


def _private_key_path(path):
    if (
        not isinstance(path, str)
        or not os.path.isabs(path)
        or os.path.normpath(path) != path
        or any(character in path for character in "\x00\r\n")
    ):
        _fail("private_key_path must be one normalized absolute path.")
    try:
        resolved = Path(path).resolve(strict=True)
    except OSError:
        _fail("private_key_path does not exist.")
    if str(resolved) != path:
        _fail("private_key_path must be canonical and may not be a symbolic link.")
    status = os.lstat(path)
    if (
        not stat.S_ISREG(status.st_mode)
        or stat.S_ISLNK(status.st_mode)
        or status.st_uid not in {0, os.getuid()}
        or status.st_mode & 0o077
        or status.st_nlink != 1
    ):
        _fail("private_key_path must be one owner-only regular file.")
    return str(resolved)


def _normalize_import_arguments(args):
    if not isinstance(args, dict) or set(args) != _EXPECTED_ARGS:
        _fail("onepassword_ssh_key_import arguments do not match the closed schema.")
    action = args["action"]
    if action not in ("plan", "apply"):
        _fail("action must be plan or apply.")
    expected_fingerprint = args["expected_fingerprint"]
    if (
        not isinstance(expected_fingerprint, str)
        or not _FINGERPRINT_PATTERN.fullmatch(expected_fingerprint)
    ):
        _fail("expected_fingerprint must be one exact SHA-256 fingerprint.")
    allow_import = args["allow_import"]
    if not isinstance(allow_import, bool):
        _fail("allow_import must be a boolean.")
    confirmation = args["confirmation"]
    expected_confirmation = "IMPORT-ONEPASSWORD-SSH-KEY:{0}:{1}".format(
        args["subject"], expected_fingerprint
    )
    if action == "apply" and (
        not allow_import or confirmation != expected_confirmation
    ):
        _fail("apply requires the exact target- and fingerprint-bound confirmation.")
    if action == "plan" and (allow_import or confirmation):
        _fail("plan may not permit import or carry an apply confirmation.")
    base = {
        name: value
        for name, value in args.items()
        if name
        not in {
            "action",
            "allow_import",
            "confirmation",
            "private_key_path",
        }
    }
    base.update(
        {
            "operation": "plan",
            "allow_create": False,
            "approval_authority": {},
            "approval": {},
        }
    )
    config = _normalize_arguments(base)
    if config["item_id"] or config["item_version"]:
        _fail("Initial import requires an unpinned item ID and version.")
    config.update(
        {
            "action": action,
            "allow_import": allow_import,
            "confirmation": confirmation,
            "private_key_path": _private_key_path(args["private_key_path"]),
            "expected_fingerprint": expected_fingerprint,
        }
    )
    return config


def _source_key(config):
    path, payload = trusted_regular_file(
        config["private_key_path"], "private_key_path", maximum_size=65536
    )
    if not payload.startswith(b"-----BEGIN OPENSSH PRIVATE KEY-----\n"):
        _fail("private_key_path must contain one OpenSSH private key.")
    temporary_root = tempfile.mkdtemp(prefix="lit-onepassword-key-import-")
    os.chmod(temporary_root, 0o700)
    key_path = os.path.join(temporary_root, "source.key")
    _write_private_file(key_path, payload)
    try:
        ssh_keygen = trusted_executable(
            config["ssh_keygen_path"],
            config["ssh_keygen_sha256"],
            "ssh_keygen_path",
        )
        completed = subprocess.run(
            [ssh_keygen, "-y", "-P", "", "-f", key_path],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env={"LANG": "C", "LC_ALL": "C"},
            check=False,
            timeout=30,
        )
        if completed.returncode != 0 or len(completed.stdout) > 2048:
            _fail("The source key could not be validated without a passphrase.")
        try:
            public_key, fingerprint = _public_identity(
                completed.stdout.decode("ascii", errors="strict").strip()
            )
        except UnicodeError:
            _fail("The source key returned invalid public metadata.")
        if fingerprint != config["expected_fingerprint"]:
            _fail("The source key does not match expected_fingerprint.")
        return payload, public_key
    finally:
        os.unlink(key_path)
        os.rmdir(temporary_root)


def _import_template(client, config, private_payload):
    template = client.metadata(
        ["item", "template", "get", "SSH Key", "--format", "json"],
        "SSH Key template inspection",
    )
    if not isinstance(template, dict) or template.get("category") != "SSH_KEY":
        _fail("1Password returned an invalid SSH Key template.")
    fields = template.get("fields")
    if not isinstance(fields, list):
        _fail("1Password returned an invalid SSH Key field set.")
    private_fields = [
        field
        for field in fields
        if isinstance(field, dict)
        and field.get("id") == "private_key"
        and field.get("type") == "SSHKEY"
    ]
    if len(private_fields) != 1:
        _fail("1Password SSH Key template has no unique private-key field.")
    try:
        private_fields[0]["value"] = private_payload.decode("ascii", errors="strict")
    except UnicodeError:
        _fail("The source private key must be strict ASCII OpenSSH data.")
    template["title"] = config["item_title"]
    template.pop("tags", None)
    encoded = json.dumps(
        template, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")
    arguments = [
        "item",
        "create",
        "--account",
        config["account_id"],
        "--vault",
        config["vault_id"],
        "--title",
        config["item_title"],
        "--tags",
        ",".join(config["tags"]),
        "-",
        "subject[text]={0}".format(config["subject"]),
        "schema_version[text]={0}".format(config["schema_version"]),
    ]
    client.discard(arguments, "SSH private-key import", stdin_payload=encoded)


def _require_same_public_key(observed, expected):
    if observed.split()[:2] != expected.split()[:2]:
        _fail("The imported SSH item does not match the exact source public key.")


class ActionModule(ActionBase):
    """Controller-only existing-key importer."""

    TRANSFERS_FILES = False
    _requires_connection = False
    _supports_check_mode = True
    _VALID_ARGS = _EXPECTED_ARGS

    def run(self, tmp=None, task_vars=None):
        if task_vars is None:
            task_vars = {}
        self._task.no_log = True
        super(ActionModule, self).run(tmp, task_vars)
        config = _normalize_import_arguments(dict(self._task.args))
        client = _OnePasswordCLI(
            config["cli_path"], config["cli_sha256"], config["account_id"]
        )
        store = _OnePasswordSSHKeyItemStore(client)
        observed = store.inspect(config, allow_tag_mismatch=True)
        private_payload, source_public_key = _source_key(config)
        metadata_repaired = False
        if observed["exists"] and not observed["tags_match"]:
            if config["action"] == "plan" or self._task.check_mode:
                return {
                    "changed": True,
                    "created": False,
                    "exists": True,
                    "planned": True,
                    "metadata_repair_required": True,
                    "item_id": observed["item_id"],
                    "item_version": observed["item_version"],
                    "fingerprint": config["expected_fingerprint"],
                }
            client.discard(
                [
                    "item",
                    "edit",
                    observed["item_id"],
                    "--account",
                    config["account_id"],
                    "--vault",
                    config["vault_id"],
                    "--tags",
                    ",".join(config["tags"]),
                ],
                "SSH item metadata repair",
            )
            observed = store.inspect(config)
            metadata_repaired = True
        if observed["exists"]:
            public_identity = store.public_metadata(
                config, observed["item_id"], observed["item_version"]
            )
            _require_same_public_key(public_identity["public_key"], source_public_key)
            agent_verified = False
            if config["action"] == "apply" and not self._task.check_mode:
                agent_verified = store.verify_agent(config, public_identity)
            return {
                "changed": metadata_repaired,
                "created": False,
                "exists": True,
                "item_id": observed["item_id"],
                "item_version": observed["item_version"],
                "fingerprint": public_identity["fingerprint"],
                "public_key": public_identity["public_key"],
                "agent_verified": agent_verified,
                "source_public_key_matches": True,
                "metadata_repaired": metadata_repaired,
            }
        if config["action"] == "plan" or self._task.check_mode:
            return {
                "changed": True,
                "created": False,
                "exists": False,
                "planned": True,
                "fingerprint": config["expected_fingerprint"],
                "source_public_key": source_public_key,
            }
        _import_template(client, config, private_payload)
        observed = store.inspect(config)
        if not observed["exists"]:
            _fail("1Password did not return the imported SSH Key item.")
        public_identity = store.public_metadata(
            config, observed["item_id"], observed["item_version"]
        )
        _require_same_public_key(public_identity["public_key"], source_public_key)
        agent_verified = store.verify_agent(config, public_identity)
        return {
            "changed": True,
            "created": True,
            "exists": True,
            "item_id": observed["item_id"],
            "item_version": observed["item_version"],
            "fingerprint": public_identity["fingerprint"],
            "public_key": public_identity["public_key"],
            "agent_verified": agent_verified,
            "source_public_key_matches": True,
            "metadata_repaired": metadata_repaired,
        }
