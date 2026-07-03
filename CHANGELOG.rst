===================================================
Lightning IT Collection Release Notes Release Notes
===================================================

.. contents:: Topics

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
