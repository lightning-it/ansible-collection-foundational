===================================================
Lightning IT Collection Release Notes Release Notes
===================================================

.. contents:: Topics

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
