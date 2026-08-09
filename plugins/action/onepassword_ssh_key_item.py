# Copyright: (c) 2026, Lightning IT
# SPDX-License-Identifier: MIT

"""Manage one exact 1Password SSH Key item without reading its private key."""

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import base64
import binascii
import hashlib
import json
import os
import re
import struct
import subprocess
import tempfile

from ansible.errors import AnsibleActionFail
from ansible.plugins.action import ActionBase

from ._onepassword_boundary import (
    claim_approval,
    normalize_approval,
    normalize_object_id_list,
    normalize_sha256,
    safe_approval_metadata,
    trusted_agent_socket,
    trusted_executable,
)


DOCUMENTATION = r"""
---
module: onepassword_ssh_key_item
short_description: Plan, create, or inspect one exact 1Password SSH Key item
version_added: "1.34.0"
description:
  - Validates one exact 1Password account, vault, SSH Key item, and public identity on the Ansible controller.
  - Creates an absent Ed25519 item only through 1Password-internal SSH key generation.
  - Requests only public key, fingerprint, and non-sensitive contract fields from an existing item.
  - Never requests or returns a private key and provides no private-key export operation.
options:
  operation:
    type: str
    choices: [plan, apply, read_public, verify_agent]
    required: true
  cli_path:
    type: path
    required: true
  cli_sha256:
    type: str
    required: true
  cli_version:
    type: str
    required: true
  account_id:
    type: str
    required: true
  account_sign_in_address:
    type: str
    required: true
  authorized_user_uuids:
    type: list
    elements: str
    required: true
  vault_id:
    type: str
    required: true
  item_id:
    type: str
    default: ""
  item_version:
    description:
      - Exact immutable 1Password item version.
      - Use C(0) only for discovery or initial creation, then pin the positive version returned by the action.
    type: int
    default: 0
  item_title:
    type: str
    required: true
  category:
    type: str
    choices: [SSH Key]
    default: SSH Key
  tags:
    type: list
    elements: str
    required: true
  subject:
    type: str
    required: true
  schema_version:
    type: int
    default: 1
  key_type:
    type: str
    choices: [ed25519]
    default: ed25519
  expected_fingerprint:
    type: str
    default: ""
    description: Externally pinned SHA-256 fingerprint; required after initial discovery or creation.
  allow_create:
    type: bool
    default: false
  approval:
    type: dict
    default: {}
  ssh_add_path:
    type: path
    default: ""
  ssh_add_sha256:
    type: str
    default: ""
  ssh_keygen_path:
    type: path
    default: ""
  ssh_keygen_sha256:
    type: str
    default: ""
  agent_socket_path:
    type: path
    default: ""
notes:
  - Private-key use must occur through a separately verified 1Password SSH Agent boundary.
  - Public-key output is intentionally non-sensitive but remains pinned to the exact item contract.
  - The action does not update, rotate, archive, delete, or export an item.
author:
  - Lightning IT (@lightning-it)
"""

EXAMPLES = r"""
---
- name: Plan an absent externally escrowed Dropbear recovery key
  lit.foundational.onepassword_ssh_key_item:
    operation: plan
    cli_path: /usr/local/bin/op
    cli_version: 2.38.1
    account_id: aaaaaaaaaaaaaaaaaaaaaaaaaa
    account_sign_in_address: example.1password.com
    vault_id: vvvvvvvvvvvvvvvvvvvvvvvvvv
    item_title: host01.example.test Dropbear recovery
    tags: [breakglass, recovery]
    subject: host01.example.test
    key_type: ed25519
    cli_sha256: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    authorized_user_uuids: [uuuuuuuuuuuuuuuuuuuuuuuuuu]
"""

RETURN = r"""
created:
  type: bool
  returned: always
  description: Whether apply created the absent item.
exists:
  type: bool
  returned: always
  description: Whether the exact SSH Key item exists.
item_id:
  type: str
  returned: always
  description: Exact non-sensitive item ID when present.
item_version:
  type: int
  returned: always
  description: Exact non-sensitive item version when present.
planned:
  type: bool
  returned: always
  description: Whether creation remains pending.
public_key:
  type: str
  returned: when the item exists
  description: Validated OpenSSH Ed25519 public key.
fingerprint:
  type: str
  returned: when the item exists
  description: Locally recomputed SHA-256 public-key fingerprint.
agent_verified:
  type: bool
  returned: when the item exists
  description:
    - Whether the exact key was uniquely available and completed a fresh signing challenge through the approved SSH
      Agent socket.
operator_user_uuid:
  type: str
  returned: always
  description: Allowlisted 1Password operator observed during validation.
"""


_EXPECTED_ARGS = frozenset(
    (
        "operation",
        "cli_path",
        "cli_sha256",
        "cli_version",
        "account_id",
        "account_sign_in_address",
        "authorized_user_uuids",
        "vault_id",
        "item_id",
        "item_version",
        "item_title",
        "category",
        "tags",
        "subject",
        "schema_version",
        "key_type",
        "expected_fingerprint",
        "allow_create",
        "approval",
        "ssh_add_path",
        "ssh_add_sha256",
        "ssh_keygen_path",
        "ssh_keygen_sha256",
        "agent_socket_path",
    )
)
_OBJECT_ID_PATTERN = re.compile(r"[a-z0-9]{26}\Z", re.ASCII)
_VERSION_PATTERN = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+\Z", re.ASCII)
_FINGERPRINT_PATTERN = re.compile(r"SHA256:[A-Za-z0-9+/]{43}\Z", re.ASCII)
_HOST_PATTERN = re.compile(
    r"[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?\Z", re.ASCII
)
_SUBJECT_PATTERN = re.compile(
    r"[A-Za-z0-9](?:[A-Za-z0-9._-]{0,251}[A-Za-z0-9])?\Z", re.ASCII
)
_TAG_PATTERN = re.compile(
    r"[A-Za-z0-9](?:[A-Za-z0-9._/-]{0,61}[A-Za-z0-9])?\Z", re.ASCII
)
_FORBIDDEN_AUTH_ENVIRONMENT = frozenset(
    ("OP_SERVICE_ACCOUNT_TOKEN", "OP_CONNECT_HOST", "OP_CONNECT_TOKEN")
)
_PROCESS_TIMEOUT_SECONDS = 30


def _fail(message):
    raise AnsibleActionFail(message)


def _plain_text(value):
    if isinstance(value, str):
        return str.__str__(value)
    return value


def _normalize_integer(value, name):
    if isinstance(value, bool):
        _fail("{0} must be an integer.".format(name))
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value and value.isascii() and value.isdecimal():
        return int(value, 10)
    _fail("{0} must be an integer.".format(name))


def _normalize_boolean(value, name):
    if isinstance(value, bool):
        return value
    if isinstance(value, str) and value in ("true", "false"):
        return value == "true"
    _fail("{0} must be a boolean.".format(name))


def _normalize_sign_in_address(value):
    normalized = value.strip().lower()
    for prefix in ("https://", "http://"):
        if normalized.startswith(prefix):
            normalized = normalized[len(prefix) :]
    return normalized.rstrip("/")


def _normalize_arguments(args):
    unknown = set(args).difference(_EXPECTED_ARGS)
    if unknown:
        _fail("Unsupported arguments: {0}.".format(", ".join(sorted(unknown))))
    operation = _plain_text(args.get("operation"))
    if operation not in ("plan", "apply", "read_public", "verify_agent"):
        _fail("operation must be plan, apply, read_public, or verify_agent.")

    cli_path = _plain_text(args.get("cli_path"))
    if not isinstance(cli_path, str) or not cli_path or not os.path.isabs(cli_path):
        _fail("cli_path must be a non-empty absolute path.")
    if "\x00" in cli_path or "\r" in cli_path or "\n" in cli_path:
        _fail("cli_path contains an invalid character.")
    normalized_cli_path = os.path.normpath(cli_path)
    if normalized_cli_path != cli_path:
        _fail("cli_path must be normalized.")

    cli_version = _plain_text(args.get("cli_version"))
    if not isinstance(cli_version, str) or not _VERSION_PATTERN.fullmatch(cli_version):
        _fail("cli_version must be an exact semantic version.")
    cli_sha256 = normalize_sha256(args.get("cli_sha256"), "cli_sha256")
    authorized_user_uuids = normalize_object_id_list(
        args.get("authorized_user_uuids"), "authorized_user_uuids"
    )

    account_id = _plain_text(args.get("account_id"))
    vault_id = _plain_text(args.get("vault_id"))
    item_id = _plain_text(args.get("item_id", ""))
    item_version = _normalize_integer(args.get("item_version", 0), "item_version")
    for name, value in (("account_id", account_id), ("vault_id", vault_id)):
        if not isinstance(value, str) or not _OBJECT_ID_PATTERN.fullmatch(value):
            _fail("{0} must be an exact 1Password object ID.".format(name))
    if not isinstance(item_id, str) or (item_id and not _OBJECT_ID_PATTERN.fullmatch(item_id)):
        _fail("item_id must be empty or an exact 1Password object ID.")
    if item_version < 0:
        _fail("item_version must be zero or a positive integer.")
    if bool(item_id) != bool(item_version):
        _fail("item_id and a positive item_version must be pinned together.")

    sign_in_address = _plain_text(args.get("account_sign_in_address"))
    if not isinstance(sign_in_address, str) or not _HOST_PATTERN.fullmatch(sign_in_address):
        _fail("account_sign_in_address must be an exact host name.")
    item_title = _plain_text(args.get("item_title"))
    if (
        not isinstance(item_title, str)
        or not 1 <= len(item_title) <= 128
        or "\r" in item_title
        or "\n" in item_title
    ):
        _fail("item_title must be a safe non-empty exact title.")
    if _plain_text(args.get("category", "SSH Key")) != "SSH Key":
        _fail("category must be exactly SSH Key.")
    if _plain_text(args.get("key_type", "ed25519")) != "ed25519":
        _fail("key_type must be exactly ed25519.")

    tags = args.get("tags", [])
    if (
        not isinstance(tags, list)
        or not tags
        or len(tags) > 10
        or len(tags) != len(set(tags))
        or any(
            not isinstance(tag, str) or not _TAG_PATTERN.fullmatch(_plain_text(tag))
            for tag in tags
        )
    ):
        _fail("tags must be a unique list of safe non-sensitive values.")
    tags = [_plain_text(tag) for tag in tags]

    subject = _plain_text(args.get("subject"))
    if not isinstance(subject, str) or not _SUBJECT_PATTERN.fullmatch(subject):
        _fail("subject must be a safe non-empty exact identity.")
    schema_version = _normalize_integer(args.get("schema_version", 1), "schema_version")
    if schema_version != 1:
        _fail("schema_version must be exactly 1.")
    expected_fingerprint = _plain_text(args.get("expected_fingerprint", ""))
    if not isinstance(expected_fingerprint, str) or (
        expected_fingerprint
        and not _FINGERPRINT_PATTERN.fullmatch(expected_fingerprint)
    ):
        _fail("expected_fingerprint must be empty or an exact SHA-256 SSH fingerprint.")

    allow_create = _normalize_boolean(args.get("allow_create", False), "allow_create")
    if operation == "plan" and allow_create:
        _fail("plan cannot permit creation.")
    if operation == "plan" and item_id and not expected_fingerprint:
        _fail("a pinned plan requires the externally pinned fingerprint.")
    if operation in ("read_public", "verify_agent"):
        if not item_id:
            _fail("read_public and verify_agent require a pinned exact item_id.")
        if not expected_fingerprint:
            _fail("read_public and verify_agent require an externally pinned fingerprint.")
        if allow_create:
            _fail("read_public and verify_agent cannot permit creation.")
    if operation == "apply":
        if item_id or item_version or expected_fingerprint:
            _fail(
                "apply requires empty item_id and expected_fingerprint values "
                "and item_version=0."
            )
        if not allow_create:
            _fail("apply requires allow_create=true.")

    ssh_add_path = _plain_text(args.get("ssh_add_path", ""))
    ssh_add_sha256 = _plain_text(args.get("ssh_add_sha256", ""))
    ssh_keygen_path = _plain_text(args.get("ssh_keygen_path", ""))
    ssh_keygen_sha256 = _plain_text(args.get("ssh_keygen_sha256", ""))
    agent_socket_path = _plain_text(args.get("agent_socket_path", ""))
    for name, value in (
        ("ssh_add_path", ssh_add_path),
        ("ssh_keygen_path", ssh_keygen_path),
        ("agent_socket_path", agent_socket_path),
    ):
        if value and (
            not isinstance(value, str)
            or not os.path.isabs(value)
            or os.path.normpath(value) != value
            or "\x00" in value
            or "\r" in value
            or "\n" in value
        ):
            _fail("{0} must be an exact normalized absolute path.".format(name))
    if operation in ("apply", "verify_agent") and (
        not ssh_add_path
        or not ssh_keygen_path
        or not agent_socket_path
        or not ssh_add_sha256
        or not ssh_keygen_sha256
    ):
        _fail(
            "apply and verify_agent require exact ssh-add, ssh-keygen, and SSH "
            "Agent dependency paths."
        )
    if ssh_add_sha256:
        ssh_add_sha256 = normalize_sha256(ssh_add_sha256, "ssh_add_sha256")
    if ssh_keygen_sha256:
        ssh_keygen_sha256 = normalize_sha256(ssh_keygen_sha256, "ssh_keygen_sha256")
    config = {
        "operation": operation,
        "cli_path": normalized_cli_path,
        "cli_sha256": cli_sha256,
        "cli_version": cli_version,
        "account_id": account_id,
        "account_sign_in_address": sign_in_address,
        "authorized_user_uuids": authorized_user_uuids,
        "vault_id": vault_id,
        "item_id": item_id,
        "item_version": item_version,
        "item_title": item_title,
        "category": "SSH Key",
        "tags": tags,
        "subject": subject,
        "schema_version": schema_version,
        "key_type": "ed25519",
        "expected_fingerprint": expected_fingerprint,
        "allow_create": allow_create,
        "ssh_add_path": ssh_add_path,
        "ssh_add_sha256": ssh_add_sha256,
        "ssh_keygen_path": ssh_keygen_path,
        "ssh_keygen_sha256": ssh_keygen_sha256,
        "agent_socket_path": agent_socket_path,
    }
    approval = args.get("approval", {})
    if operation == "apply":
        config["approval"] = normalize_approval(
            approval,
            operation="create-onepassword-ssh-key",
            target=subject,
            binding=_approval_binding(config),
        )
    else:
        if approval not in ({}, None):
            _fail("approval is accepted only for apply.")
        config["approval"] = None
    return config


def _approval_binding(config):
    return {
        "account_id": config["account_id"],
        "account_sign_in_address": config["account_sign_in_address"],
        "agent_socket_path": config["agent_socket_path"],
        "authorized_user_uuids": config["authorized_user_uuids"],
        "cli_sha256": config["cli_sha256"],
        "item_title": config["item_title"],
        "key_type": config["key_type"],
        "schema_version": config["schema_version"],
        "ssh_add_sha256": config["ssh_add_sha256"],
        "ssh_keygen_sha256": config["ssh_keygen_sha256"],
        "subject": config["subject"],
        "tags": config["tags"],
        "vault_id": config["vault_id"],
    }


class _OnePasswordCLI:
    """Minimal desktop-integrated 1Password CLI transport."""

    def __init__(self, binary, binary_sha256, account_id, process_environment=None):
        self.requested_binary = binary
        self.binary_sha256 = binary_sha256
        self.binary = trusted_executable(binary, binary_sha256, "cli_path")
        self.account_id = account_id
        self.environment = self._minimal_environment(
            os.environ if process_environment is None else process_environment
        )

    @staticmethod
    def _minimal_environment(process_environment):
        if any(process_environment.get(name) for name in _FORBIDDEN_AUTH_ENVIRONMENT):
            _fail(
                "1Password service-account or Connect authentication is forbidden; "
                "use the unlocked desktop CLI integration."
            )
        if any(
            name.startswith("OP_SESSION_") and value
            for name, value in process_environment.items()
        ):
            _fail(
                "1Password shell-session tokens are forbidden; use the unlocked "
                "desktop CLI integration."
            )
        environment = {
            name: process_environment[name]
            for name in ("HOME", "PATH", "TMPDIR", "LANG", "LC_ALL")
            if process_environment.get(name)
        }
        if not environment.get("HOME"):
            _fail("HOME is required for the 1Password desktop CLI integration.")
        return environment

    def _run(self, arguments, operation, discard_stdout=False):
        self.binary = trusted_executable(
            self.requested_binary, self.binary_sha256, "cli_path"
        )
        try:
            completed = subprocess.run(
                [self.binary] + list(arguments),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL if discard_stdout else subprocess.PIPE,
                stderr=subprocess.DEVNULL if discard_stdout else subprocess.PIPE,
                env=self.environment,
                check=False,
                timeout=_PROCESS_TIMEOUT_SECONDS,
            )
        except (OSError, subprocess.SubprocessError):
            _fail("1Password {0} could not be executed safely.".format(operation))
        if completed.returncode != 0:
            _fail(
                "1Password {0} failed closed with exit code {1}.".format(
                    operation, completed.returncode
                )
            )
        return b"" if discard_stdout else completed.stdout

    def metadata(self, arguments, operation):
        payload = self._run(arguments, operation)
        try:
            return json.loads(payload.decode("utf-8", errors="strict"))
        except (UnicodeDecodeError, ValueError):
            _fail("1Password returned invalid public metadata for {0}.".format(operation))

    def discard(self, arguments, operation):
        self._run(arguments, operation, discard_stdout=True)


def _field_values(payload):
    rows = payload if isinstance(payload, list) else [payload]
    values = {}
    for row in rows:
        if not isinstance(row, dict):
            _fail("1Password returned invalid selected-field metadata.")
        label = row.get("label")
        value = row.get("value")
        if not isinstance(label, str) or not isinstance(value, (str, int)):
            _fail("1Password returned invalid selected-field metadata.")
        normalized_label = label.strip().lower()
        if normalized_label in values:
            _fail("1Password returned duplicate selected-field metadata.")
        values[normalized_label] = str(value)
    return values


def _public_identity(public_key):
    if (
        not isinstance(public_key, str)
        or not public_key.isascii()
        or len(public_key) > 1024
    ):
        _fail("1Password returned an invalid SSH public key.")
    if "\r" in public_key or "\n" in public_key or "\x00" in public_key:
        _fail("1Password returned an invalid SSH public key.")
    parts = public_key.split()
    if len(parts) not in (2, 3) or parts[0] != "ssh-ed25519":
        _fail("1Password did not return an Ed25519 OpenSSH public key.")
    try:
        blob = base64.b64decode(parts[1], validate=True)
    except (binascii.Error, ValueError):
        _fail("1Password returned an invalid SSH public-key encoding.")
    if len(blob) != 51:
        _fail("1Password returned an invalid Ed25519 public-key blob.")
    try:
        algorithm_length = struct.unpack(">I", blob[0:4])[0]
        algorithm = blob[4 : 4 + algorithm_length]
        key_length_offset = 4 + algorithm_length
        key_length = struct.unpack(">I", blob[key_length_offset : key_length_offset + 4])[0]
        key = blob[key_length_offset + 4 :]
    except (struct.error, ValueError):
        _fail("1Password returned an invalid Ed25519 public-key blob.")
    if algorithm != b"ssh-ed25519" or key_length != 32 or len(key) != 32:
        _fail("1Password returned an invalid Ed25519 public-key blob.")
    fingerprint = base64.b64encode(hashlib.sha256(blob).digest()).decode("ascii").rstrip("=")
    return " ".join(parts), "SHA256:{0}".format(fingerprint)


def _write_controller_file(path, payload):
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as stream:
            stream.write(payload)
            stream.flush()
    finally:
        os.close(descriptor)


class _OnePasswordSSHKeyItemStore:
    """Validate metadata and create immutable Ed25519 SSH Key items."""

    def __init__(self, client):
        self.client = client

    def _assert_current_version(self, config, item_id, item_version):
        items = self.client.metadata(
            [
                "item", "list", "--vault", config["vault_id"], "--account",
                config["account_id"], "--long", "--format", "json",
            ],
            "SSH item revision revalidation",
        )
        if not isinstance(items, list):
            _fail("1Password returned invalid SSH item revision metadata.")
        matches = [
            item for item in items
            if isinstance(item, dict) and item.get("id") == item_id
        ]
        if (
            len(matches) != 1
            or matches[0].get("title") != config["item_title"]
            or matches[0].get("version") != item_version
        ):
            _fail("The 1Password SSH item changed during immutable contract validation.")

    def inspect(self, config):
        try:
            version = (
                self.client._run(["--version"], "version")
                .decode("ascii", errors="strict")
                .strip()
            )
        except UnicodeDecodeError:
            _fail("The controller 1Password CLI returned an invalid version.")
        if version != config["cli_version"]:
            _fail("The controller 1Password CLI version does not match cli_version.")

        identity = self.client.metadata(
            ["whoami", "--account", config["account_id"], "--format", "json"],
            "desktop identity verification",
        )
        if not isinstance(identity, dict) or identity.get("account_uuid") != config["account_id"]:
            _fail("The signed-in 1Password account does not match account_id.")
        if (
            _normalize_sign_in_address(str(identity.get("url", "")))
            != config["account_sign_in_address"].lower()
        ):
            _fail("The signed-in 1Password account does not match the sign-in address.")
        operator_user_uuid = identity.get("user_uuid")
        if (
            not isinstance(operator_user_uuid, str)
            or not _OBJECT_ID_PATTERN.fullmatch(operator_user_uuid)
            or operator_user_uuid not in config["authorized_user_uuids"]
        ):
            _fail("The signed-in 1Password operator is not authorized for this action.")

        vault = self.client.metadata(
            [
                "vault", "get", config["vault_id"], "--account", config["account_id"],
                "--format", "json",
            ],
            "vault verification",
        )
        if not isinstance(vault, dict) or vault.get("id") != config["vault_id"]:
            _fail("The selected 1Password vault does not match vault_id.")
        items = self.client.metadata(
            [
                "item", "list", "--vault", config["vault_id"], "--account",
                config["account_id"], "--long", "--format", "json",
            ],
            "SSH item metadata inspection",
        )
        if not isinstance(items, list):
            _fail("1Password returned invalid item-list metadata.")
        matches = [
            item for item in items
            if isinstance(item, dict) and item.get("title") == config["item_title"]
        ]
        if len(matches) > 1:
            _fail("item_title is not unique inside the exact vault.")
        if not matches:
            if config["item_id"]:
                _fail("The pinned SSH item_id is absent from the exact vault.")
            return {
                "exists": False,
                "item_id": None,
                "item_version": None,
                "operator_user_uuid": operator_user_uuid,
            }
        item = matches[0]
        observed_item_id = item.get("id")
        if not isinstance(observed_item_id, str) or not _OBJECT_ID_PATTERN.fullmatch(observed_item_id):
            _fail("The 1Password SSH item has no exact object ID.")
        if config["item_id"] and config["item_id"] != observed_item_id:
            _fail("item_title resolves to a different SSH item_id.")
        observed_item_version = item.get("version")
        if (
            isinstance(observed_item_version, bool)
            or not isinstance(observed_item_version, int)
            or observed_item_version < 1
        ):
            _fail("The 1Password SSH item has no exact positive item version.")
        if config["item_version"] and config["item_version"] != observed_item_version:
            _fail("The 1Password SSH item version does not match the immutable pin.")
        observed_category = str(item.get("category", "")).upper().replace(" ", "_")
        if observed_category != "SSH_KEY":
            _fail("The 1Password item category is not SSH Key.")
        observed_tags = item.get("tags", [])
        if not isinstance(observed_tags, list) or sorted(observed_tags) != sorted(config["tags"]):
            _fail("The 1Password SSH item tags do not match.")
        return {
            "exists": True,
            "item_id": observed_item_id,
            "item_version": observed_item_version,
            "operator_user_uuid": operator_user_uuid,
        }

    def public_metadata(self, config, item_id, item_version):
        fields = self.client.metadata(
            [
                "item", "get", item_id, "--vault", config["vault_id"], "--account",
                config["account_id"], "--fields",
                "label=subject,label=schema_version,label=public key,label=fingerprint",
                "--format", "json",
            ],
            "selected SSH public-field verification",
        )
        values = _field_values(fields)
        if values.get("subject") != config["subject"]:
            _fail("The 1Password SSH item subject metadata does not match.")
        if values.get("schema_version") != str(config["schema_version"]):
            _fail("The 1Password SSH item schema metadata does not match.")
        public_key, fingerprint = _public_identity(values.get("public key"))
        if values.get("fingerprint") != fingerprint:
            _fail("The 1Password SSH item fingerprint does not match its public key.")
        if config["expected_fingerprint"] and fingerprint != config["expected_fingerprint"]:
            _fail("The 1Password SSH item does not match the externally pinned fingerprint.")
        self._assert_current_version(config, item_id, item_version)
        return {"public_key": public_key, "fingerprint": fingerprint}

    @staticmethod
    def verify_agent(config, public_identity):
        expected_fingerprint = public_identity["fingerprint"]
        expected_public_key = public_identity["public_key"]
        environment = {
            "HOME": os.environ.get("HOME", ""),
            "PATH": os.environ.get("PATH", ""),
        }
        for name in ("LANG", "LC_ALL"):
            if os.environ.get(name):
                environment[name] = os.environ[name]
        if not environment["HOME"]:
            _fail("HOME is required for 1Password SSH Agent verification.")
        try:
            ssh_add = trusted_executable(
                config["ssh_add_path"],
                config["ssh_add_sha256"],
                "ssh_add_path",
            )
            agent_socket = trusted_agent_socket(config["agent_socket_path"])
            environment["SSH_AUTH_SOCK"] = agent_socket
            completed = subprocess.run(
                [ssh_add, "-L"],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=environment,
                check=False,
                timeout=_PROCESS_TIMEOUT_SECONDS,
            )
        except (OSError, subprocess.SubprocessError):
            _fail("The approved 1Password SSH Agent could not be inspected safely.")
        if completed.returncode != 0:
            _fail("The approved 1Password SSH Agent is unavailable or locked.")
        if len(completed.stdout) > 65536:
            _fail("The approved 1Password SSH Agent returned excessive public metadata.")
        try:
            public_rows = completed.stdout.decode("utf-8", errors="strict").splitlines()
        except UnicodeDecodeError:
            _fail("The approved 1Password SSH Agent returned invalid public metadata.")
        matched_fingerprints = []
        for row in public_rows:
            if not row.strip():
                continue
            try:
                unused_key, fingerprint = _public_identity(row.strip())
            except AnsibleActionFail:
                continue
            if fingerprint == expected_fingerprint:
                matched_fingerprints.append(fingerprint)
        if len(matched_fingerprints) != 1:
            _fail("The exact pinned SSH key is not uniquely available from the approved SSH Agent socket.")

        challenge = bytearray(os.urandom(32))
        namespace = "agent-proof@l-it.io"
        principal = "onepassword-agent@l-it.io"
        temporary_root = tempfile.mkdtemp(prefix="lit-onepassword-agent-proof-")
        os.chmod(temporary_root, 0o700)
        public_key_path = os.path.join(temporary_root, "identity.pub")
        allowed_signers_path = os.path.join(temporary_root, "allowed_signers")
        signature_path = os.path.join(temporary_root, "challenge.sig")
        try:
            _write_controller_file(
                public_key_path, (expected_public_key + "\n").encode("ascii")
            )
            _write_controller_file(
                allowed_signers_path,
                (principal + " " + expected_public_key + "\n").encode("ascii"),
            )
            try:
                ssh_keygen = trusted_executable(
                    config["ssh_keygen_path"],
                    config["ssh_keygen_sha256"],
                    "ssh_keygen_path",
                )
                agent_socket = trusted_agent_socket(config["agent_socket_path"])
                environment["SSH_AUTH_SOCK"] = agent_socket
                signed = subprocess.run(
                    [
                        ssh_keygen,
                        "-Y",
                        "sign",
                        "-f",
                        public_key_path,
                        "-n",
                        namespace,
                        "-O",
                        "hashalg=sha256",
                    ],
                    input=bytes(challenge),
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    env=environment,
                    check=False,
                    timeout=_PROCESS_TIMEOUT_SECONDS,
                )
            except (OSError, subprocess.SubprocessError):
                _fail("The approved SSH Agent signing challenge could not be executed safely.")
            if (
                signed.returncode != 0
                or not signed.stdout.startswith(b"-----BEGIN SSH SIGNATURE-----\n")
                or not signed.stdout.endswith(b"-----END SSH SIGNATURE-----\n")
                or len(signed.stdout) > 65536
            ):
                _fail("The approved SSH Agent did not produce a valid signing challenge response.")
            _write_controller_file(signature_path, signed.stdout)
            try:
                ssh_keygen = trusted_executable(
                    config["ssh_keygen_path"],
                    config["ssh_keygen_sha256"],
                    "ssh_keygen_path",
                )
                agent_socket = trusted_agent_socket(config["agent_socket_path"])
                environment["SSH_AUTH_SOCK"] = agent_socket
                verified = subprocess.run(
                    [
                        ssh_keygen,
                        "-Y",
                        "verify",
                        "-f",
                        allowed_signers_path,
                        "-I",
                        principal,
                        "-n",
                        namespace,
                        "-s",
                        signature_path,
                    ],
                    input=bytes(challenge),
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    env=environment,
                    check=False,
                    timeout=_PROCESS_TIMEOUT_SECONDS,
                )
            except (OSError, subprocess.SubprocessError):
                _fail("The approved SSH Agent signing challenge could not be verified safely.")
            if verified.returncode != 0:
                _fail("The approved SSH Agent failed the exact-key signing challenge.")
        finally:
            for index in range(len(challenge)):
                challenge[index] = 0
            for path in (signature_path, allowed_signers_path, public_key_path):
                if os.path.lexists(path):
                    os.unlink(path)
            os.rmdir(temporary_root)
        return True

    def run(self, config, check_mode=False):
        observed = self.inspect(config)
        operation = config["operation"]
        if operation == "apply" and observed["exists"]:
            _fail(
                "apply found a pre-existing unpinned SSH item; review and pin its "
                "item ID, positive item version, and fingerprint before a separate "
                "validation operation."
            )
        if operation == "plan" or (operation == "apply" and check_mode):
            result = {
                "changed": not observed["exists"], "created": False,
                "exists": observed["exists"], "item_id": observed["item_id"],
                "item_version": observed["item_version"],
                "operator_user_uuid": observed["operator_user_uuid"],
                "planned": not observed["exists"],
            }
            if observed["exists"]:
                result.update(
                    self.public_metadata(
                        config, observed["item_id"], observed["item_version"]
                    )
                )
            if config["approval"] is not None:
                result["approval"] = safe_approval_metadata(config["approval"])
            return result

        created = False
        if operation == "apply":
            claim_approval(config["approval"])
            creation_arguments = [
                "item", "create", "--account", config["account_id"], "--vault",
                config["vault_id"], "--category=ssh", "--title", config["item_title"],
                "--ssh-generate-key=ed25519",
                "subject[text]={0}".format(config["subject"]),
                "schema_version[text]={0}".format(config["schema_version"]),
            ]
            if config["tags"]:
                creation_arguments[9:9] = ["--tags", ",".join(config["tags"])]
            self.client.discard(creation_arguments, "SSH item creation")
            observed = self.inspect(config)
            if not observed["exists"]:
                _fail("1Password did not return the created SSH item metadata.")
            created = True
        if not observed["exists"]:
            _fail("The exact SSH Key item is absent.")
        public_identity = self.public_metadata(
            config, observed["item_id"], observed["item_version"]
        )
        agent_verified = False
        if operation in ("apply", "verify_agent"):
            agent_verified = self.verify_agent(config, public_identity)
        result = {
            "changed": created, "created": created, "exists": True,
            "item_id": observed["item_id"], "planned": False,
            "item_version": observed["item_version"],
            "operator_user_uuid": observed["operator_user_uuid"],
            "public_key": public_identity["public_key"],
            "fingerprint": public_identity["fingerprint"],
            "agent_verified": agent_verified,
        }
        if config["approval"] is not None:
            result["approval"] = safe_approval_metadata(config["approval"])
        return result


class ActionModule(ActionBase):
    """Ansible controller-only action-plugin entry point."""

    TRANSFERS_FILES = False
    _requires_connection = False
    _supports_check_mode = True
    _VALID_ARGS = _EXPECTED_ARGS

    def run(self, tmp=None, task_vars=None):
        if task_vars is None:
            task_vars = {}
        self._task.no_log = True
        super(ActionModule, self).run(tmp, task_vars)
        config = _normalize_arguments(dict(self._task.args))
        client = _OnePasswordCLI(
            config["cli_path"], config["cli_sha256"], config["account_id"]
        )
        return _OnePasswordSSHKeyItemStore(client).run(
            config, check_mode=bool(self._task.check_mode)
        )
