# Copyright: (c) 2026, Lightning IT
# SPDX-License-Identifier: MIT

"""Plan or create one exact 1Password Password item without reading it."""

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import json
import os
import re
import subprocess

from ansible.errors import AnsibleActionFail
from ansible.plugins.action import ActionBase

from ._onepassword_boundary import (
    claim_approval,
    normalize_approval,
    normalize_object_id_list,
    normalize_sha256,
    safe_approval_metadata,
    trusted_executable,
)


DOCUMENTATION = r"""
---
module: onepassword_secret_item
short_description: Plan or create one exact 1Password Password item
version_added: "1.34.0"
description:
  - Validates one exact 1Password account, vault, item, and field on the Ansible controller.
  - Creates an absent Password item only through 1Password-internal password generation.
  - Never reads or returns the generated password; secret-consuming actions must use a dedicated descriptor-to-process
    boundary that does not expose the value to Ansible variables or facts.
  - Rejects service-account, Connect, and shell-session token environments so desktop CLI integration is explicit.
options:
  operation:
    description:
      - C(plan) performs metadata-only inspection.
      - C(apply) creates an absent item and returns its non-sensitive item ID without reading the password.
    type: str
    choices:
      - plan
      - apply
    required: true
  cli_path:
    description: Absolute path to the approved 1Password CLI binary.
    type: path
    required: true
  cli_sha256:
    description: Complete lowercase SHA-256 digest of the approved CLI executable.
    type: str
    required: true
  cli_version:
    description: Exact approved 1Password CLI version.
    type: str
    required: true
  account_id:
    description: Exact 1Password account ID.
    type: str
    required: true
  account_sign_in_address:
    description: Exact expected account sign-in address.
    type: str
    required: true
  authorized_user_uuids:
    description: Exact allowlist of 1Password operator user UUIDs.
    type: list
    elements: str
    required: true
  vault_id:
    description: Exact 1Password vault ID.
    type: str
    required: true
  item_id:
    description: Exact item ID; it must be empty for initial creation and pinned for later validation.
    type: str
    default: ""
  item_version:
    description:
      - Exact immutable 1Password item version.
      - Use C(0) only for discovery or initial creation, then pin the positive version returned by the action.
    type: int
    default: 0
  item_title:
    description: Exact unique item title within the selected vault.
    type: str
    required: true
  field_id:
    description: Built-in Password item field ID.
    type: str
    default: password
  category:
    description: Exact item category.
    type: str
    choices:
      - Password
    default: Password
  tags:
    description: Exact non-sensitive item tags.
    type: list
    elements: str
    required: true
  subject:
    description: Exact non-sensitive subject recorded in the item.
    type: str
    required: true
  schema_version:
    description: Exact schema version recorded in the item.
    type: int
    default: 1
  password_recipe:
    description: Exact 1Password internal-generation recipe.
    type: str
    required: true
  password_length:
    description: Exact expected password length.
    type: int
    required: true
  allow_create:
    description: Explicitly permit creation during C(apply).
    type: bool
    default: false
  approval_authority:
    description:
      - Independently configured Approval Authority for C(apply).
      - Pins one Ed25519 signer, the allowed-signers file, and the C(ssh-keygen) verifier by full SHA-256 digest.
      - The fixed signature namespace is C(lit-onepassword-approval-v1).
      - Pins one canonical controller-only replay directory that C(approval.replay_directory) must match exactly.
    type: dict
    default: {}
  approval:
    description:
      - Expiring, signed, one-time approval for C(apply).
      - The signature covers the authority, execution ID, repository commits, operation, target, and complete
        normalized non-secret action contract.
    type: dict
    default: {}
attributes:
  action:
    description: The action executes entirely on the controller.
    support: full
  check_mode:
    description: C(apply) is reduced to metadata-only planning; no item is created.
    support: full
  connection:
    description: No managed-host connection is used.
    support: none
  diff_mode:
    description: Secret material and item content are never returned as diff data.
    support: none
notes:
  - C(plan) and C(apply) return non-sensitive identity metadata only.
  - The action does not update, rotate, archive, or delete an existing item.
  - Creation has no cross-controller transaction primitive. Use one serialized controller and pin the returned item
    ID and positive item version before any secret-consuming operation.
  - The controller must already have an unlocked 1Password desktop CLI integration for the exact account.
author:
  - Lightning IT (@lightning-it)
"""

EXAMPLES = r"""
---
- name: Plan one independently escrowed recovery item
  lit.foundational.onepassword_secret_item:
    operation: plan
    cli_path: /usr/local/bin/op
    cli_sha256: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    cli_version: 2.38.1
    account_id: aaaaaaaaaaaaaaaaaaaaaaaaaa
    account_sign_in_address: example.1password.com
    authorized_user_uuids: [uuuuuuuuuuuuuuuuuuuuuuuuuu]
    vault_id: vvvvvvvvvvvvvvvvvvvvvvvvvv
    item_id: ""
    item_title: host01.example.test LUKS recovery
    field_id: password
    category: Password
    tags:
      - recovery
    subject: host01.example.test
    schema_version: 1
    password_recipe: letters,digits,symbols,64
    password_length: 64
"""

RETURN = r"""
created:
  description: Whether C(apply) created the absent item.
  returned: always
  type: bool
exists:
  description: Whether the exact item exists after the operation.
  returned: always
  type: bool
item_id:
  description: Exact non-sensitive item ID, or null when absent during C(plan).
  returned: always
  type: str
item_version:
  description: Exact non-sensitive item version, or null when absent during C(plan).
  returned: always
  type: int
planned:
  description: Whether creation remains pending after metadata-only planning.
  returned: always
  type: bool
operator_user_uuid:
  description: Allowlisted 1Password operator observed during validation.
  returned: always
  type: str
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
        "field_id",
        "category",
        "tags",
        "subject",
        "schema_version",
        "password_recipe",
        "password_length",
        "allow_create",
        "approval_authority",
        "approval",
    )
)
_OBJECT_ID_PATTERN = re.compile(r"[a-z0-9]{26}\Z", re.ASCII)
_VERSION_PATTERN = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+\Z", re.ASCII)
_HOST_PATTERN = re.compile(
    r"[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?\Z",
    re.ASCII,
)
_SUBJECT_PATTERN = re.compile(
    r"[A-Za-z0-9](?:[A-Za-z0-9._-]{0,251}[A-Za-z0-9])?\Z",
    re.ASCII,
)
_TAG_PATTERN = re.compile(
    r"[A-Za-z0-9](?:[A-Za-z0-9._/-]{0,61}[A-Za-z0-9])?\Z",
    re.ASCII,
)
_FORBIDDEN_AUTH_ENVIRONMENT = frozenset(
    (
        "OP_SERVICE_ACCOUNT_TOKEN",
        "OP_CONNECT_HOST",
        "OP_CONNECT_TOKEN",
    )
)
_MAX_SECRET_BYTES = 64
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
    if operation not in ("plan", "apply"):
        _fail("operation must be plan or apply.")

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
    if not isinstance(item_id, str) or (
        item_id and not _OBJECT_ID_PATTERN.fullmatch(item_id)
    ):
        _fail("item_id must be empty or an exact 1Password object ID.")
    if item_version < 0:
        _fail("item_version must be zero or a positive integer.")
    if bool(item_id) != bool(item_version):
        _fail("item_id and a positive item_version must be pinned together.")

    sign_in_address = _plain_text(args.get("account_sign_in_address"))
    if not isinstance(sign_in_address, str) or not _HOST_PATTERN.fullmatch(
        sign_in_address
    ):
        _fail("account_sign_in_address must be an exact host name.")

    item_title = _plain_text(args.get("item_title"))
    if (
        not isinstance(item_title, str)
        or not 1 <= len(item_title) <= 128
        or "\r" in item_title
        or "\n" in item_title
    ):
        _fail("item_title must be a safe non-empty exact title.")

    field_id = _plain_text(args.get("field_id", "password"))
    category = _plain_text(args.get("category", "Password"))
    if field_id != "password":
        _fail("field_id must be exactly password.")
    if category != "Password":
        _fail("category must be exactly Password.")

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
    password_length = _normalize_integer(args.get("password_length"), "password_length")
    if password_length < 1 or password_length > _MAX_SECRET_BYTES:
        _fail("password_length must be between 1 and 64.")
    password_recipe = _plain_text(args.get("password_recipe"))
    if password_recipe != "letters,digits,symbols,{0}".format(password_length):
        _fail("password_recipe must match the approved 1Password internal generator.")

    allow_create = _normalize_boolean(args.get("allow_create", False), "allow_create")
    if operation == "plan" and allow_create:
        _fail("plan cannot permit creation.")
    if operation == "apply":
        if item_id or item_version:
            _fail(
                "apply requires empty item_id and zero item_version values and "
                "may only create a new item."
            )
        if not allow_create:
            _fail("apply requires allow_create=true.")
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
        "field_id": field_id,
        "category": category,
        "tags": tags,
        "subject": subject,
        "schema_version": schema_version,
        "password_recipe": password_recipe,
        "password_length": password_length,
        "allow_create": allow_create,
    }
    approval = args.get("approval", {})
    if operation == "apply":
        config["approval"] = normalize_approval(
            approval,
            args.get("approval_authority"),
            operation="create-onepassword-secret",
            target=subject,
            binding=_approval_binding(config),
        )
    else:
        if args.get("approval_authority") not in ({}, None):
            _fail("approval_authority is accepted only for apply.")
        if approval not in ({}, None):
            _fail("approval is accepted only for apply.")
        config["approval"] = None
    return config


def _approval_binding(config):
    return {
        "operation": config["operation"],
        "allow_create": config["allow_create"],
        "account_id": config["account_id"],
        "account_sign_in_address": config["account_sign_in_address"],
        "authorized_user_uuids": config["authorized_user_uuids"],
        "category": config["category"],
        "cli_path": config["cli_path"],
        "cli_sha256": config["cli_sha256"],
        "cli_version": config["cli_version"],
        "field_id": config["field_id"],
        "item_id": config["item_id"],
        "item_title": config["item_title"],
        "item_version": config["item_version"],
        "password_length": config["password_length"],
        "password_recipe": config["password_recipe"],
        "schema_version": config["schema_version"],
        "subject": config["subject"],
        "tags": config["tags"],
        "vault_id": config["vault_id"],
    }


class _OnePasswordCLI:
    """Minimal 1Password CLI transport with no credential environment."""

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
                    operation,
                    completed.returncode,
                )
            )
        return b"" if discard_stdout else completed.stdout

    def metadata(self, arguments, operation):
        payload = self._run(arguments, operation)
        try:
            return json.loads(payload.decode("utf-8", errors="strict"))
        except (UnicodeDecodeError, ValueError):
            _fail(
                "1Password returned invalid non-sensitive metadata for {0}.".format(
                    operation
                )
            )

    def discard(self, arguments, operation):
        self._run(arguments, operation, discard_stdout=True)


def _field_values(payload):
    rows = payload if isinstance(payload, list) else [payload]
    values = {}
    for row in rows:
        if not isinstance(row, dict):
            _fail("1Password returned invalid item field metadata.")
        label = row.get("label")
        value = row.get("value")
        if not isinstance(label, str) or not isinstance(value, (str, int)):
            _fail("1Password returned invalid item field metadata.")
        if label in values:
            _fail("1Password returned duplicate item field metadata.")
        values[label] = str(value)
    return values


class _OnePasswordSecretItemStore:
    """Metadata validation and immutable item creation."""

    def __init__(self, client):
        self.client = client

    def _assert_current_version(self, config, item_id, item_version):
        items = self.client.metadata(
            [
                "item",
                "list",
                "--vault",
                config["vault_id"],
                "--account",
                config["account_id"],
                "--long",
                "--format",
                "json",
            ],
            "item revision revalidation",
        )
        if not isinstance(items, list):
            _fail("1Password returned invalid item revision metadata.")
        matches = [
            item
            for item in items
            if isinstance(item, dict) and item.get("id") == item_id
        ]
        if (
            len(matches) != 1
            or matches[0].get("title") != config["item_title"]
            or matches[0].get("version") != item_version
        ):
            _fail("The 1Password item changed during immutable contract validation.")

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
        if (
            not isinstance(identity, dict)
            or identity.get("account_uuid") != config["account_id"]
        ):
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
                "vault",
                "get",
                config["vault_id"],
                "--account",
                config["account_id"],
                "--format",
                "json",
            ],
            "vault verification",
        )
        if not isinstance(vault, dict) or vault.get("id") != config["vault_id"]:
            _fail("The selected 1Password vault does not match vault_id.")

        items = self.client.metadata(
            [
                "item",
                "list",
                "--vault",
                config["vault_id"],
                "--account",
                config["account_id"],
                "--long",
                "--format",
                "json",
            ],
            "item metadata inspection",
        )
        if not isinstance(items, list):
            _fail("1Password returned invalid item-list metadata.")
        matches = [
            item
            for item in items
            if isinstance(item, dict) and item.get("title") == config["item_title"]
        ]
        if len(matches) > 1:
            _fail("item_title is not unique inside the exact vault.")
        if not matches:
            if config["item_id"]:
                _fail("The pinned item_id is absent from the exact vault.")
            return {
                "exists": False,
                "item_id": None,
                "item_version": None,
                "operator_user_uuid": operator_user_uuid,
            }

        item = matches[0]
        observed_item_id = item.get("id")
        if not isinstance(observed_item_id, str) or not _OBJECT_ID_PATTERN.fullmatch(
            observed_item_id
        ):
            _fail("The 1Password item has no exact object ID.")
        if config["item_id"] and config["item_id"] != observed_item_id:
            _fail("item_title resolves to a different item_id.")
        observed_item_version = item.get("version")
        if (
            isinstance(observed_item_version, bool)
            or not isinstance(observed_item_version, int)
            or observed_item_version < 1
        ):
            _fail("The 1Password item has no exact positive item version.")
        if config["item_version"] and config["item_version"] != observed_item_version:
            _fail("The 1Password item version does not match the immutable pin.")
        if str(item.get("category", "")).lower() != config["category"].lower():
            _fail("The 1Password item category does not match.")
        observed_tags = item.get("tags", [])
        if not isinstance(observed_tags, list) or sorted(observed_tags) != sorted(
            config["tags"]
        ):
            _fail("The 1Password item tags do not match.")

        fields = self.client.metadata(
            [
                "item",
                "get",
                observed_item_id,
                "--vault",
                config["vault_id"],
                "--account",
                config["account_id"],
                "--fields",
                "label=subject,label=schema_version,label=expected_length",
                "--format",
                "json",
            ],
            "item contract verification",
        )
        if _field_values(fields) != {
            "expected_length": str(config["password_length"]),
            "schema_version": str(config["schema_version"]),
            "subject": config["subject"],
        }:
            _fail("The 1Password item subject or schema metadata does not match.")
        self._assert_current_version(config, observed_item_id, observed_item_version)
        return {
            "exists": True,
            "item_id": observed_item_id,
            "item_version": observed_item_version,
            "operator_user_uuid": operator_user_uuid,
        }

    def run(self, config, check_mode=False):
        observed = self.inspect(config)
        operation = config["operation"]
        if operation == "apply" and observed["exists"]:
            _fail(
                "apply found a pre-existing unpinned item; review and pin its item ID "
                "before using a separate plan operation."
            )
        if operation == "plan" or (operation == "apply" and check_mode):
            result = {
                "changed": not observed["exists"],
                "created": False,
                "exists": observed["exists"],
                "item_id": observed["item_id"],
                "item_version": observed["item_version"],
                "operator_user_uuid": observed["operator_user_uuid"],
                "planned": not observed["exists"],
            }
            if config["approval"] is not None:
                result["approval"] = safe_approval_metadata(config["approval"])
            return result

        created = False
        if operation == "apply":
            claim_approval(config["approval"])
            creation_arguments = [
                "item",
                "create",
                "--account",
                config["account_id"],
                "--vault",
                config["vault_id"],
                "--category",
                config["category"],
                "--title",
                config["item_title"],
                "--generate-password={0}".format(config["password_recipe"]),
                "subject[text]={0}".format(config["subject"]),
                "schema_version[text]={0}".format(config["schema_version"]),
                "expected_length[text]={0}".format(config["password_length"]),
            ]
            if config["tags"]:
                creation_arguments[10:10] = ["--tags", ",".join(config["tags"])]
            self.client.discard(
                creation_arguments,
                "item creation",
            )
            observed = self.inspect(config)
            if not observed["exists"]:
                _fail("1Password did not return the created item metadata.")
            created = True

        result = {
            "changed": created,
            "created": created,
            "exists": observed["exists"],
            "item_id": observed["item_id"],
            "item_version": observed["item_version"],
            "operator_user_uuid": observed["operator_user_uuid"],
            "planned": False,
        }
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
        return _OnePasswordSecretItemStore(client).run(
            config,
            check_mode=bool(self._task.check_mode),
        )
