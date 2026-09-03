# Copyright: (c) 2026, Lightning IT
# SPDX-License-Identifier: MIT

"""Verify or grant one exact user full Co-Manager access to one 1Password vault."""

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import os
import re

from ansible.errors import AnsibleActionFail
from ansible.plugins.action import ActionBase

from ._onepassword_boundary import (
    claim_approval,
    normalize_approval,
    normalize_user_uuid_list,
    normalize_sha256,
    safe_approval_metadata,
)
from .onepassword_secret_item import _OnePasswordCLI, _normalize_sign_in_address


DOCUMENTATION = r"""
---
module: onepassword_vault_co_manager
short_description: Verify or grant exact 1Password vault Co-Manager access
version_added: "1.34.0"
description:
  - Validates one exact 1Password account, vault, operator, and target user on the Ansible controller.
  - Verifies that the target user has C(allow_viewing), C(allow_editing), and C(allow_managing) on the exact vault.
  - C(apply) grants the complete fixed Co-Manager permission set only when one or more permissions are absent.
  - Uses an expiring, asymmetric, one-time approval before a permission mutation and revalidates state immediately
    before and after the grant.
  - Rejects service-account, Connect, and shell-session token environments so desktop CLI integration is explicit.
options:
  operation:
    description:
      - C(plan) performs metadata-only inspection.
      - C(apply) grants missing Co-Manager permissions when explicitly authorized.
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
    description: Exact allowlist of 1Password operator user UUIDs permitted to run this action.
    type: list
    elements: str
    required: true
  vault_id:
    description: Exact 1Password vault ID.
    type: str
    required: true
  user_uuid:
    description: Exact target 1Password user UUID.
    type: str
    required: true
  user_email:
    description: Exact target user email used as an additional public identity pin.
    type: str
    required: true
  allow_grant:
    description: Explicitly permit a missing-permission grant during C(apply).
    type: bool
    default: false
  approval_authority:
    description:
      - Independently configured Approval Authority for C(apply).
      - Pins one Ed25519 signer, the allowed-signers file, the C(ssh-keygen) verifier, and one replay directory.
    type: dict
    default: {}
  approval:
    description:
      - Expiring, signed, one-time approval for C(apply).
      - The signature covers the account, vault, target user, fixed permission set, executable, and Git commits.
    type: dict
    default: {}
attributes:
  action:
    description: The action executes entirely on the controller.
    support: full
  check_mode:
    description: C(apply) is reduced to metadata-only planning; no permission is granted.
    support: full
  connection:
    description: No managed-host connection is used.
    support: none
  diff_mode:
    description: No account response is returned as diff data.
    support: none
notes:
  - The action only adds the fixed Co-Manager permission set. It never revokes access or other permissions.
  - The controller must already have an unlocked 1Password desktop CLI integration for the exact account.
  - Returned data is limited to non-secret UUID, permission, state, and approval metadata.
author:
  - Lightning IT (@lightning-it)
"""

EXAMPLES = r"""
---
- name: Verify one vault Co-Manager
  lit.foundational.onepassword_vault_co_manager:
    operation: plan
    cli_path: /usr/local/bin/op
    cli_sha256: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    cli_version: 2.38.1
    account_id: AAAAAAAAAAAAAAAAAAAAAAAAAA
    account_sign_in_address: example.1password.com
    authorized_user_uuids: [OOOOOOOOOOOOOOOOOOOOOOOOOO]
    vault_id: vvvvvvvvvvvvvvvvvvvvvvvvvv
    user_uuid: uuuuuuuuuuuuuuuuuuuuuuuuuu
    user_email: custodian@example.com
"""

RETURN = r"""
approval:
  description: Non-secret digest, authority, commit, and validity metadata for the supplied apply approval.
  returned: C(operation=apply)
  type: dict
changed:
  description: Whether C(apply) granted missing permissions.
  returned: always
  type: bool
exists:
  description: Whether the target user has direct access to the exact vault.
  returned: always
  type: bool
missing_permissions:
  description: Co-Manager permissions still absent after the operation.
  returned: always
  type: list
  elements: str
observed_permissions:
  description: Sorted non-sensitive permissions observed for the target user.
  returned: always
  type: list
  elements: str
operator_user_uuid:
  description: Allowlisted 1Password operator observed during validation.
  returned: always
  type: str
planned:
  description: Whether a permission grant remains pending.
  returned: always
  type: bool
required_permissions:
  description: Fixed Co-Manager permission set enforced by this action.
  returned: always
  type: list
  elements: str
user_uuid:
  description: Exact target user UUID.
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
        "user_uuid",
        "user_email",
        "allow_grant",
        "approval_authority",
        "approval",
    )
)
_ACCOUNT_USER_UUID_PATTERN = re.compile(r"[A-Z0-9]{26}\Z", re.ASCII)
_VAULT_ID_PATTERN = re.compile(r"[a-z0-9]{26}\Z", re.ASCII)
_VERSION_PATTERN = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+\Z", re.ASCII)
_HOST_PATTERN = re.compile(
    r"[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?\Z",
    re.ASCII,
)
_EMAIL_PATTERN = re.compile(
    r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?\Z",
    re.ASCII,
)
_PERMISSION_PATTERN = re.compile(r"[a-z][a-z0-9_]{0,63}\Z", re.ASCII)
_REQUIRED_PERMISSIONS = (
    "allow_viewing",
    "allow_editing",
    "allow_managing",
)


def _fail(message):
    raise AnsibleActionFail(message)


def _plain_text(value):
    if isinstance(value, str):
        return str.__str__(value)
    return value


def _normalize_boolean(value, name):
    if isinstance(value, bool):
        return value
    if isinstance(value, str) and value in ("true", "false"):
        return value == "true"
    _fail("{0} must be a boolean.".format(name))


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
    authorized_user_uuids = normalize_user_uuid_list(
        args.get("authorized_user_uuids"), "authorized_user_uuids"
    )

    account_id = _plain_text(args.get("account_id"))
    vault_id = _plain_text(args.get("vault_id"))
    user_uuid = _plain_text(args.get("user_uuid"))
    for name, value in (("account_id", account_id), ("user_uuid", user_uuid)):
        if not isinstance(value, str) or not _ACCOUNT_USER_UUID_PATTERN.fullmatch(
            value
        ):
            _fail("{0} must be an exact 1Password UUID.".format(name))
    if not isinstance(vault_id, str) or not _VAULT_ID_PATTERN.fullmatch(vault_id):
        _fail("vault_id must be an exact 1Password vault ID.")

    sign_in_address = _plain_text(args.get("account_sign_in_address"))
    if not isinstance(sign_in_address, str) or not _HOST_PATTERN.fullmatch(
        sign_in_address
    ):
        _fail("account_sign_in_address must be an exact host name.")

    user_email = _plain_text(args.get("user_email"))
    if (
        not isinstance(user_email, str)
        or len(user_email) > 254
        or not _EMAIL_PATTERN.fullmatch(user_email)
    ):
        _fail("user_email must be an exact safe email address.")
    user_email = user_email.lower()

    allow_grant = _normalize_boolean(args.get("allow_grant", False), "allow_grant")
    if operation == "plan" and allow_grant:
        _fail("plan cannot permit a permission grant.")
    if operation == "apply" and not allow_grant:
        _fail("apply requires allow_grant=true.")

    config = {
        "operation": operation,
        "cli_path": normalized_cli_path,
        "cli_sha256": cli_sha256,
        "cli_version": cli_version,
        "account_id": account_id,
        "account_sign_in_address": sign_in_address.lower(),
        "authorized_user_uuids": authorized_user_uuids,
        "vault_id": vault_id,
        "user_uuid": user_uuid,
        "user_email": user_email,
        "allow_grant": allow_grant,
        "required_permissions": list(_REQUIRED_PERMISSIONS),
    }
    approval = args.get("approval", {})
    if operation == "apply":
        config["approval"] = normalize_approval(
            approval,
            args.get("approval_authority"),
            operation="grant-onepassword-vault-co-manager",
            target="{0}:{1}".format(vault_id, user_uuid),
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
        "allow_grant": config["allow_grant"],
        "account_id": config["account_id"],
        "account_sign_in_address": config["account_sign_in_address"],
        "authorized_user_uuids": config["authorized_user_uuids"],
        "cli_path": config["cli_path"],
        "cli_sha256": config["cli_sha256"],
        "cli_version": config["cli_version"],
        "required_permissions": config["required_permissions"],
        "user_email": config["user_email"],
        "user_uuid": config["user_uuid"],
        "vault_id": config["vault_id"],
    }


def _row_uuid(row, context):
    if not isinstance(row, dict):
        _fail("1Password returned invalid {0} metadata.".format(context))
    identifiers = [row.get(name) for name in ("uuid", "id") if row.get(name)]
    if (
        not identifiers
        or any(not isinstance(identifier, str) for identifier in identifiers)
        or len(set(identifiers)) != 1
        or not _ACCOUNT_USER_UUID_PATTERN.fullmatch(identifiers[0])
    ):
        _fail("1Password returned invalid {0} identity metadata.".format(context))
    return identifiers[0]


def _row_email(row, context):
    email = row.get("email") if isinstance(row, dict) else None
    if not isinstance(email, str) or not _EMAIL_PATTERN.fullmatch(email):
        _fail("1Password returned invalid {0} email metadata.".format(context))
    return email.lower()


def _row_permissions(row):
    permissions = row.get("permissions") if isinstance(row, dict) else None
    if (
        not isinstance(permissions, list)
        or any(
            not isinstance(permission, str)
            or not _PERMISSION_PATTERN.fullmatch(permission)
            for permission in permissions
        )
        or len(permissions) != len(set(permissions))
    ):
        _fail("1Password returned invalid vault-user permission metadata.")
    return sorted(permissions)


class _OnePasswordVaultCoManagerStore:
    """Metadata validation and idempotent fixed permission grant."""

    def __init__(self, client):
        self.client = client

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
            != config["account_sign_in_address"]
        ):
            _fail("The signed-in 1Password account does not match the sign-in address.")
        operator_user_uuid = identity.get("user_uuid")
        if (
            not isinstance(operator_user_uuid, str)
            or not _ACCOUNT_USER_UUID_PATTERN.fullmatch(operator_user_uuid)
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

        user = self.client.metadata(
            [
                "user",
                "get",
                config["user_uuid"],
                "--account",
                config["account_id"],
                "--format",
                "json",
            ],
            "target user verification",
        )
        if _row_uuid(user, "target user") != config["user_uuid"]:
            _fail("The selected 1Password user does not match user_uuid.")
        if _row_email(user, "target user") != config["user_email"]:
            _fail("The selected 1Password user does not match user_email.")
        if user.get("state") != "ACTIVE":
            _fail("The selected 1Password user is not ACTIVE.")

        rows = self.client.metadata(
            [
                "vault",
                "user",
                "list",
                config["vault_id"],
                "--account",
                config["account_id"],
                "--format",
                "json",
            ],
            "vault user access inspection",
        )
        if not isinstance(rows, list):
            _fail("1Password returned invalid vault-user access metadata.")
        matches = [
            row
            for row in rows
            if isinstance(row, dict)
            and (row.get("uuid") == config["user_uuid"] or row.get("id") == config["user_uuid"])
        ]
        if len(matches) > 1:
            _fail("The target user occurs more than once in vault-user access metadata.")
        if not matches:
            observed_permissions = []
            exists = False
        else:
            row = matches[0]
            if _row_uuid(row, "vault user") != config["user_uuid"]:
                _fail("The vault-user identity does not match user_uuid.")
            if _row_email(row, "vault user") != config["user_email"]:
                _fail("The vault-user identity does not match user_email.")
            if row.get("state") != "ACTIVE":
                _fail("The vault user is not ACTIVE.")
            observed_permissions = _row_permissions(row)
            exists = True
        missing_permissions = [
            permission
            for permission in config["required_permissions"]
            if permission not in observed_permissions
        ]
        return {
            "exists": exists,
            "missing_permissions": missing_permissions,
            "observed_permissions": observed_permissions,
            "operator_user_uuid": operator_user_uuid,
            "user_uuid": config["user_uuid"],
        }

    def _result(self, config, observed, changed, planned):
        result = {
            "changed": changed,
            "exists": observed["exists"],
            "missing_permissions": observed["missing_permissions"],
            "observed_permissions": observed["observed_permissions"],
            "operator_user_uuid": observed["operator_user_uuid"],
            "planned": planned,
            "required_permissions": list(config["required_permissions"]),
            "user_uuid": observed["user_uuid"],
        }
        if config["approval"] is not None:
            result["approval"] = safe_approval_metadata(config["approval"])
        return result

    def run(self, config, check_mode=False):
        observed = self.inspect(config)
        missing = bool(observed["missing_permissions"])
        if config["operation"] == "plan" or check_mode:
            return self._result(config, observed, changed=missing, planned=missing)
        if not missing:
            return self._result(config, observed, changed=False, planned=False)

        observed = self.inspect(config)
        if not observed["missing_permissions"]:
            return self._result(config, observed, changed=False, planned=False)
        claim_approval(config["approval"])
        self.client.discard(
            [
                "vault",
                "user",
                "grant",
                "--account",
                config["account_id"],
                "--vault",
                config["vault_id"],
                "--user",
                config["user_uuid"],
                "--permissions",
                ",".join(config["required_permissions"]),
                "--no-input",
            ],
            "vault Co-Manager permission grant",
        )
        observed = self.inspect(config)
        if observed["missing_permissions"]:
            _fail("1Password did not grant the complete Co-Manager permission set.")
        return self._result(config, observed, changed=True, planned=False)


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
        return _OnePasswordVaultCoManagerStore(client).run(
            config,
            check_mode=bool(self._task.check_mode),
        )
