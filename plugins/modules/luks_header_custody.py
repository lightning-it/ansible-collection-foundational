# Copyright: (c) 2026, Lightning IT
# SPDX-License-Identifier: MIT
"""Immutable encrypted-header publication and full provider readback."""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.lit.foundational.plugins.module_utils.luks_header_custody import (
    VaultHTTP,
    safe_path,
    validate_package,
    validate_read_pins,
    vault_custody,
    vault_read_custody,
)
from ansible_collections.lit.foundational.plugins.module_utils.luks_header_onepassword import (
    NativeCLI,
    onepassword_custody,
    onepassword_read_custody,
    validate_config,
)

DOCUMENTATION = r"""
---
module: luks_header_custody
short_description: Publish and verify an immutable encrypted header package
version_added: "1.34.0"
description:
  - Uses create-only Vault KV2 chunks and manifest, or an additional native 1Password Document.
  - Reads complete provider contents back and compares the canonical package and source bindings.
  - Never edits or deletes an existing provider object, reads a recovery password, or changes a disk.
options:
  provider:
    description: Explicit provider; no fallback is attempted.
    type: str
    choices: [hashicorp_vault, onepassword]
    required: true
  provider_config:
    description:
      - Closed non-secret provider contract. Vault requires C(mount) and C(prefix).
      - Native 1Password requires pinned CLI/account/operator/vault/object/executor fields documented in the role.
      - Vault authentication accepts explicit token or AppRole credentials with mandatory HTTPS and CA verification.
    type: dict
    required: true
  vault_auth:
    description: Protected explicit Vault credential/verified-HTTPS contract; never sent to the native provider.
    type: dict
    default: {}
    suboptions:
      url:
        type: str
        description: Exact HTTPS Vault origin.
      namespace:
        type: str
        description: Explicit optional Vault namespace.
      ca_cert:
        type: path
        description: Trusted CA file; verification is mandatory.
      timeout:
        type: int
        description: Bounded per-request timeout in seconds.
      auth_method:
        type: str
        description: Explicit token or approle authentication.
      auth_mount_point:
        type: str
        description: Exact AppRole authentication mount.
      token:
        type: str
        description: Existing scoped Vault token; never logged.
      role_id:
        type: str
        description: Existing scoped AppRole role ID; never logged.
      secret_id:
        type: str
        description: Existing scoped AppRole secret ID; never logged.
  package:
    description: Canonical encrypted package produced by C(luks_header_custody_prepare); never a raw header.
    type: dict
    default: {}
  read_pins:
    description: For independent read, exact retained package checksum, subject, machine ID and LUKS UUID.
    type: dict
    default: {}
  operation:
    description: Plan does not write; verify compares a supplied package; apply creates missing objects; read needs only retained pins.
    type: str
    choices: [plan, apply, verify, read]
    default: verify
  allow_create:
    description: Explicit permission to create missing objects during apply.
    type: bool
    default: false
  approval_authority:
    description: Existing independent Ed25519 authority on the native 1Password executor.
    type: dict
    default: {}
  approval:
    description: Expiring one-time signature bound to exact native configuration and package checksum.
    type: dict
    default: {}
notes:
  - Require task-level C(no_log=true). Provider errors never expose response bodies or credentials.
  - Delegate 1Password to an explicit trusted native desktop executor; do not install a Mac binary in the Linux EE.
  - Check mode performs read-only planning. A missing copy is never reported verified.
author:
  - Lightning IT (@lightning-it)
"""
EXAMPLES = r"""
- name: Verify a current header copy from Vault
  lit.foundational.luks_header_custody:
    provider: hashicorp_vault
    provider_config: "{{ approved_header_vault_location }}"
    vault_auth: "{{ approved_header_vault_auth }}"
    package: "{{ verified_header_package }}"
    operation: verify
  no_log: true
"""
RETURN = r"""
verified:
  type: bool
  returned: always
  description: Whether the full provider package was read back and matched.
package_sha256:
  type: str
  returned: success
  description: Exact canonical package binding shared by all provider receipts.
"""


def main():
    module = AnsibleModule(
        argument_spec={
            "provider": {
                "type": "str",
                "choices": ["hashicorp_vault", "onepassword"],
                "required": True,
            },
            "provider_config": {"type": "dict", "required": True},
            "vault_auth": {
                "type": "dict",
                "default": {},
                "options": {
                    "url": {"type": "str"},
                    "namespace": {"type": "str"},
                    "ca_cert": {"type": "path"},
                    "timeout": {"type": "int"},
                    "auth_method": {"type": "str"},
                    "auth_mount_point": {"type": "str"},
                    "token": {"type": "str", "no_log": True},
                    "role_id": {"type": "str", "no_log": True},
                    "secret_id": {"type": "str", "no_log": True},
                },
            },
            # The package contains ciphertext and public identity/receipt fields,
            # never plaintext credentials. Task-level no_log is enforced below;
            # scalar-wide no_log would corrupt returned version/identity pins.
            "package": {"type": "dict", "default": {}},
            "read_pins": {"type": "dict", "default": {}},
            "operation": {
                "type": "str",
                "choices": ["plan", "apply", "verify", "read"],
                "default": "verify",
            },
            "allow_create": {"type": "bool", "default": False},
            "approval_authority": {"type": "dict", "default": {}},
            "approval": {"type": "dict", "default": {}},
        },
        supports_check_mode=True,
    )
    if not module.no_log:
        module.fail_json(
            msg="Header provider operations require task-level no_log=true."
        )
    p = module.params
    auth = {key: value for key, value in p["vault_auth"].items() if value is not None}
    for key in ("nonce", "signature"):
        value = p["approval"].get(key)
        if isinstance(value, str) and value:
            module.no_log_values.add(value)
    try:
        if p["operation"] == "read":
            validate_read_pins(p["read_pins"])
            if p["package"] or p["allow_create"]:
                raise ValueError(
                    "Independent read accepts only pins and no creation permission."
                )
        else:
            validate_package(p["package"])
        config = p["provider_config"]
        if p["provider"] == "hashicorp_vault":
            if set(config) != {"mount", "prefix"}:
                raise ValueError("A closed Vault custody contract is required.")
            if (
                p["operation"] == "apply"
                and not module.check_mode
                and not p["allow_create"]
            ):
                raise ValueError("Vault header creation is not enabled.")
            safe_path(config["mount"])
            safe_path(config["prefix"])
            client = VaultHTTP(auth)
            result = (
                vault_read_custody(
                    client, config["mount"], config["prefix"], p["read_pins"]
                )
                if p["operation"] == "read"
                else vault_custody(
                    client,
                    config["mount"],
                    config["prefix"],
                    p["package"],
                    p["operation"],
                    module.check_mode,
                )
            )
        else:
            if auth:
                raise ValueError(
                    "Vault credentials must never be delegated to the native provider."
                )
            validate_config(config)
            client = NativeCLI(config)
            result = (
                onepassword_read_custody(client, config, p["read_pins"])
                if p["operation"] == "read"
                else onepassword_custody(
                    client,
                    config,
                    p["package"],
                    p["operation"],
                    module.check_mode,
                    p["allow_create"],
                    p["approval"],
                    p["approval_authority"],
                )
            )
    except Exception:
        module.fail_json(
            msg="Header custody failed closed; inspect provider state before any explicit retry."
        )
    module.exit_json(**result)


if __name__ == "__main__":
    main()
