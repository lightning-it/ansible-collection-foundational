===================================================
Lightning IT Collection Release Notes Release Notes
===================================================

.. contents:: Topics

v1.34.0
=======

Minor Changes
-------------

- Add ``onepassword_ssh_key_item`` for fail-closed Ed25519 creation, immutable ID/version/fingerprint validation, and an exact-Agent signing challenge while making private-key export structurally unavailable.
- Add the controller-only ``onepassword_secret_item`` action for 1Password-internal generation and immutable item ID/version validation without ever reading or returning the generated Password value.
- Add the controller-only ``onepassword_ssh_secret_stdin`` action and module contract for one-time, approval-bound, no-output SSH secret delivery.
- onepassword_approval - add a controller-only action that creates and verifies short-lived, commit-bound SSHSIG approvals through one exact, pinned SSH Agent key for one 1Password operation without exposing signing material.

Breaking Changes / Porting Guide
--------------------------------

- The two 1Password item actions now require executable SHA-256 pins and an authorized user UUID allowlist. Mutating creation operations require ``approval_authority`` plus an armored signature in the one-time ``approval`` mapping instead of static ``confirmation``. ``approval_authority.replay_directory`` is now mandatory and defines the only accepted replay domain.

Security Fixes
--------------

- Bind controller executables to complete SHA-256 digests and safe owner, mode, link, and parent-directory metadata; require an allowlisted ``op whoami`` user UUID and expose only that UUID as non-secret operator evidence.
- Preserve the exact 1Password secret bytes through stdin without appending a newline, and bind unlock execution to the approved host identity, command, item versions, signing authority, and replay claim.
- Replace publicly computable confirmation strings with expiring Ed25519 approvals verified by a digest-pinned ``ssh-keygen -Y verify`` executable against one exact, digest-pinned allowed-signers identity and fixed signature namespace. Sign the complete normalized non-secret contract, including repository commits, target, dependency paths and digests, account boundary, item identities, and Agent socket.
- Scope the atomic replay marker globally to Approval Authority, execution ID, and nonce, independently of action target or payload, so a re-signed cross-target or cross-binding request cannot reuse an already consumed approval. Pin the single canonical controller-only replay directory in ``approval_authority``, require the approval path to match it exactly, and fail closed if the directory identity changes between validation and atomic claim.
- Validate 1Password account and user UUIDs using their real uppercase 26-character CLI representation while retaining the lowercase contract for vault and item IDs. This prevents valid desktop identities from being rejected or incorrectly treated as vault/item identifiers.

Bugfixes
--------

- hetzner_rescue_validate - bind LUKS recovery validation explicitly to stdin and preserve the retained secret as exact bytes without an appended newline.

New Modules
-----------

- lit.foundational.onepassword_approval - Sign one short\-lived controller\-local 1Password approval.
- lit.foundational.onepassword_secret_item - Plan or create one exact 1Password Password item.
- lit.foundational.onepassword_ssh_key_item - Plan, create, or inspect one exact 1Password SSH Key item.
- lit.foundational.onepassword_ssh_secret_stdin - Stream one pinned 1Password secret into one pinned SSH session.

v1.33.0
=======

Minor Changes
-------------

- Delegate required Heavy execution to the pinned ``modulix-validation`` reusable workflow with an immutable candidate, meaningful success markers, owner-scoped cleanup, and normalized evidence.

v1.32.0
=======

Minor Changes
-------------

- ansible_vault_document - separate the non-configurable document safety bounds, setting them to 126 MiB for serialized plaintext and 512 MiB for Ansible Vault ciphertext, so bounded large recovery escrows fit within the ciphertext envelope with a conservative margin.
- vmware_vsphere - Add dedicated task entry points for creating and requesting guarded deletion of target VM folders.

Security Fixes
--------------

- vmware_vsphere - Route folder entry points through canonical management and fail closed instead of invoking vSphere's recursive folder deletion while a target folder exists.

Bugfixes
--------

- collection examples and fixture-only Molecule coverage now avoid writing controller artifacts to read-only system directories in hardened execution environments.

v1.31.0
=======

Bugfixes
--------

- collection - Lower the declared ``ansible.posix`` minimum to 2.1.0 so the collection can be resolved alongside ``fedora.linux_system_roles`` 1.127.2, which requires ``ansible.posix`` below 2.2.0.

v1.30.0
=======

Bugfixes
--------

- collection - Ignore root-level ``ansible_collections/`` directories created by local dependency installs so generated collection content does not pollute the Git working tree.
- collection - Pin ``community.hashi_vault`` 7.1.0 and make ``galaxy.yml`` the single source of truth for dependency versions so consumer dependency resolution cannot select the incompatible 6.x release line.
- secret_resolver - Treat a missing persistent Vault target as categorized read state without leaking internal Ansible rescue context into successful callers under ``community.hashi_vault`` 7.1.0.

v1.29.0
=======

Minor Changes
-------------

- luks_header_escrow - Add a guarded, distribution-neutral role that captures one installed LUKS2 header and persists exact immutable controller-side Ansible Vault ciphertext with explicit loaded-identity selection, canonical block-device and protected remote-temporary-path validation, cryptographic payload-to-metadata binding, and no controller plaintext.

v1.28.0
=======

Minor Changes
-------------

- ansible_vault_document - raise the fixed plaintext and ciphertext safety limit from 64 MiB to 128 MiB for larger encrypted documents.
- hetzner_cloud - Add controller-side, IPv4-only, declarative Hetzner Cloud reconciliation with official hetzner.hcloud modules for SSH keys, firewalls, Networks, subnetworks, Primary and Floating IPs, placement groups, servers, exact private Network attachments, firewall relationships, reverse DNS, guarded deletion, fixed-address adoption, dynamic-inventory guidance, and read-only guest Floating IP detection.
- hetzner_rescue_validate - add reusable controller trust, Rescue-system identity, disk, shared SMART, egress, data-plane, and installed-LUKS validation entrypoints.
- hetzner_robot_cac - add declarative Hetzner Robot resource reconciliation and read-only server, firewall, and vSwitch drift auditing through community.hrobot modules.
- hetzner_robot_ops - add separately gated Rescue boot and dedicated-server reset operations.

Breaking Changes / Porting Guide
--------------------------------

- collection - raise the minimum supported ansible-core release from 2.16 to 2.18, matching the supported floor of the required hetzner.hcloud 6.x collection.
- secret_resolver - rename the public ``lit_secret_resolver_*`` variables and outputs to the mandatory role-prefixed ``secret_resolver_*`` interface.

Bugfixes
--------

- hetzner_installimage - discover the single Hetzner installimage working directory when ``FOLD`` is not exported to the post-mount hook, and reject unsafe or ambiguous working directories.

v1.27.0
=======

Minor Changes
-------------

- Add the controller-local ``ansible_vault_secret_document`` action plugin for immutable, CAS-safe creation and validation of encrypted secret documents with Ansible's already-loaded Vault identity.
- Add the controller-only ``ansible_vault_document`` action plugin for atomic, immutable, type-exact persistence of structured mappings with Ansible's already-loaded Vault identities and no plaintext filesystem staging.
- docs - Apply the shared enterprise README structure.
- docs - Consolidate generated governance metadata and license policy on shared-assets-lit.
- hetzner_installimage - Add serial-bound Hetzner Rescue installation planning, immutable approval hashes, independent destructive gates, encrypted-layout support, recovery-password artifact sanitization, preserved-disk protection, Rescue SSH-key takeover validation, and optional checksummed post-install scripts.
- release_model - Add managed compatibility matrix documentation and structured release evidence fields.
- secret_resolver - Add controller-side, provider-independent secret resolution for HashiCorp Vault/HCP Vault, Ansible Vault, 1Password, environment, runtime, and generated values, with explicit fallback, Vault KV v2 write-back, controlled migration, validation, and non-sensitive metadata.

Breaking Changes / Porting Guide
--------------------------------

- collection - Align the declared ansible-core minimum with the existing community.general 11.x dependency by requiring ansible-core 2.16 or newer, and bound community.hashi_vault to the compatible 6.x release line.

Bugfixes
--------

- hetzner_installimage - Document every argument-spec option so ansible-doc accepts the role metadata on current execution images.

New Modules
-----------

- lit.foundational.ansible_vault_document - Persist an exact immutable mapping as Ansible Vault ciphertext.
- lit.foundational.ansible_vault_secret_document - Create an immutable local Ansible Vault secret document.

v1.26.0
=======

Minor Changes
-------------

- Added generic tls_assets, vault_pki_cert, secret_backend, and secret_kv foundational roles for reusable TLS and secret handling.
- Added the podman_systemd role for persistent Podman kube services through Quadlet and systemd.

Bugfixes
--------

- Fixed kubeplay explicit app task execution so per-app variables are passed into included task files and roles.

v1.24.0
=======

Minor Changes
-------------

- lit.foundational - Verify automated collection release workflow cycle 2.

v1.23.0
=======

Minor Changes
-------------

- lit.foundational - Verify automated collection release workflow cycle 1.

v1.22.0
=======

Minor Changes
-------------

- foundational - Add Molecule coverage for remote tmp, bridge VLAN membership, OOB Redfish, and Terraform state migration scenarios.
- vmware_vsphere - Improve VM asset, normalization, and management task handling.
- vmware_vsphere_guest_bootstrap - Expand guest bootstrap configuration and task handling.
- vmware_vsphere_packer_build - Add a role for VMware vSphere Packer template build automation.
