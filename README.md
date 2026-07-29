# lit.foundational

<!-- BEGIN LIT_SHARED_RELEASE_MODEL -->

## Release and Quality Model

This repository follows the Lightning IT shared release and quality model.

See [RELEASE.md](./RELEASE.md) for:

- branch and release flow
- required quality checks
- test matrix
- release evidence
- artifact publishing
- supported repository-specific release behavior

Repository classification: **Ansible Collection**.
Required test profiles: `pre-commit, lint, light, molecule-light, release-validation`.
Publishing targets: `github-release, ansible-galaxy`.

## Supported and Tested Platforms

| Platform / Product |                  Status | Validation |
| ------------------ | ----------------------: | ---------- |
| ubuntu-latest      |               Supported | Molecule   |
| ansible-core       | Tested where applicable | Molecule   |
| molecule           | Tested where applicable | Molecule   |

<!-- END LIT_SHARED_RELEASE_MODEL -->

<!-- BEGIN LIT_QUALITY_BADGES -->

[![CI](https://github.com/lightning-it/ansible-collection-foundational/actions/workflows/collection-ci.yml/badge.svg?branch=develop)](https://github.com/lightning-it/ansible-collection-foundational/actions/workflows/collection-ci.yml)
[![Latest Release](https://img.shields.io/github/v/release/lightning-it/ansible-collection-foundational?sort=semver)](https://github.com/lightning-it/ansible-collection-foundational/releases/latest)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/lightning-it/ansible-collection-foundational/badge)](https://scorecard.dev/viewer/?uri=github.com/lightning-it/ansible-collection-foundational)
[![Ansible Galaxy](https://img.shields.io/ansible/collection/v/lit/foundational?label=Ansible%20Galaxy)](https://galaxy.ansible.com/ui/repo/published/lit/foundational/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)

<!-- END LIT_QUALITY_BADGES -->

Foundational Ansible collection for ModuLix.
It provides generic building blocks and orchestration helpers for consistent, repeatable automation.
The current collection compatibility baseline is `ansible-core` 2.18.0 or newer.

## What's inside

### Key roles

- `lit.foundational.hetzner_cloud`
  Reconciles IPv4-only Hetzner Cloud infrastructure from the controller with
  official `hetzner.hcloud` modules:
  - manages SSH keys, firewalls, Networks, subnetworks, Primary and Floating
    IPs, placement groups, servers, exact private attachments, and reverse DNS,
  - adopts fixed addresses safely, gates destructive state, and provides
    read-only guest Floating IP detection,
  - includes an `mgmt01` reference deployment and official dynamic inventory.

- `lit.foundational.hetzner_robot_cac`
  Reconciles configuration attached to existing Hetzner dedicated servers with
  official `community.hrobot` modules:
  - manages server names, firewalls, vSwitches, reverse DNS, Robot SSH keys,
    and failover-IP routing,
  - provides a read-only audit entrypoint for exact server, firewall, and
    vSwitch state,
  - gates destructive declarations and never logs Robot credentials or raw API
    responses.

- `lit.foundational.hetzner_rescue_validate`
  Validates a dedicated server in Hetzner Rescue:
  - pins Rescue SSH trust, validates exact deployment keys and physical disks,
    and applies one shared ATA/NVMe SMART policy,
  - provides separately gated extended SMART, temporary vSwitch data-plane,
    and installed-LUKS passphrase entrypoints,
  - keeps fleet selection and environment policy in the calling runbook and
    inventory.

- `lit.foundational.hetzner_robot_ops`
  Performs one separately authorized Robot boot or reset operation:
  - defaults to no action and requires one server-specific confirmation,
  - keeps Rescue activation, regular boot, and reset outside declarative
    configuration reconciliation,
  - uses only the official Robot boot and reset modules.

- `lit.foundational.secret_resolver`
  Resolves controller-side secret requests into provider-independent values:
  - supports HashiCorp Vault/HCP Vault, Ansible Vault, 1Password, environment,
    runtime, and generated providers,
  - keeps fallback explicit and disabled by default,
  - supports Vault KV v2 write-back and controlled bootstrap migration.

- `lit.foundational.luks_header_escrow`
  Persists one installed LUKS2 header as immutable controller-side Ansible
  Vault ciphertext:
  - validates one `crypttab` source, LUKS2 metadata, UUID, size, checksum, and
    controller path containment,
  - keeps raw header bytes off controller storage and always removes the
    protected managed-host temporary copy.

- `lit.foundational.terragrunt`
  Terragrunt wrapper that:
  - prepares a per-cluster working directory on the control host,
  - renders a dynamic `terragrunt.hcl`,
  - runs `terragrunt init`, `terragrunt plan`, and `terragrunt apply`
    with optional confirmation and auth support.

- `lit.foundational.terraform_state_migrate`
  Migrates local Terraform state files to an S3-compatible backend:
  - scans a local root for `*.tfstate*`,
  - uploads to S3/MinIO via `aws s3 cp`,
  - supports optional key prefix and region.

- `lit.foundational.oob_redfish_inventory`
  Vendor-neutral Redfish discovery (read-only):
  - discovers Redfish resource IDs (`System`, `Manager`, `Chassis`),
  - exposes a small `oob_redfish_inventory_redfish` summary dict for downstream tasks.

- `lit.foundational.oob_redfish_control`
  Vendor-neutral Redfish control actions:
  - power actions (on/off/reboot/graceful shutdown),
  - one-time or persistent boot override (PXE/CD/USB/HDD/UEFI targets),
  - optional virtual media insert/eject.

---

## Dependencies

### Hetzner dependencies

The Cloud role and inventory use official `hetzner.hcloud` 6.10.0 modules. The
dedicated-server roles use official `community.hrobot` 2.7.2 modules. Both are
fixed collection dependencies:

```yaml
dependencies:
  hetzner.hcloud: 6.10.0
  community.hrobot: 2.7.2
```

API operations run on the controller. Inject `HCLOUD_TOKEN` into the
controller or execution environment, or resolve a token with
`lit.foundational.secret_resolver`; never commit it to inventory.

Resolve Robot web-service credentials in the same way and inject them only at
runtime. See the role documentation under `roles/hetzner_robot_cac`,
`roles/hetzner_robot_ops`, and `roles/hetzner_rescue_validate` for resource
schemas, audit behavior, and operation gates.

### Redfish roles

The Redfish roles use the `community.general` collection.

Add this to your collection `galaxy.yml`:

```yaml
dependencies:
  community.general: ">=11.4.9,<12.0.0"
```

### Secret resolver

The secret resolver uses `community.general` for cryptographic generation and
optional 1Password lookups, and `community.hashi_vault` for HashiCorp
Vault/HCP Vault KV version 2 access. These collection dependencies are declared
by this collection:

```yaml
dependencies:
  community.general: ">=11.4.9,<12.0.0"
  community.hashi_vault: 7.1.0
```

`galaxy.yml` is the source of truth for collection dependency versions. The
repository does not duplicate those versions in a root
`collections/requirements.yml`; devtools, smoke, and lightweight Molecule
preparation install the dependency set directly from the collection metadata.
Scenario-local requirements remain allowed when a scenario intentionally
builds a dedicated test environment.

Vault access also requires the `hvac` Python package in the controller or
execution-environment interpreter. 1Password access requires an authenticated
`op` 2.x CLI on the controller PATH. Neither dependency is installed on
managed hosts, and the role does not install them automatically. Runtime,
environment, and already-decrypted Ansible Vault resolution require no
external provider client.

---

## Usage

Until this collection is published to Ansible Galaxy, you can install it directly
from GitHub (example: `main` branch):

```bash
ansible-galaxy collection install \
  git+https://github.com/lightning-it/ansible-collection-foundational.git,main
```

---

## Quick start

### Hetzner Cloud

```yaml
---
- name: Reconcile Hetzner Cloud infrastructure
  hosts: localhost
  gather_facts: false
  roles:
    - role: lit.foundational.hetzner_cloud
      vars:
        hetzner_cloud_validate_only: true
        hetzner_cloud_ipv4_only: true
```

See [`roles/hetzner_cloud/README.md`](roles/hetzner_cloud/README.md) for the
resource contract, safety gates, secrets, check mode, and guest behavior. The
complete `mgmt01` deployment is in
[`examples/hetzner_cloud/mgmt01.yml`](examples/hetzner_cloud/mgmt01.yml), with
official dynamic inventory in
[`examples/hetzner_cloud/mgmt01.hcloud.yml`](examples/hetzner_cloud/mgmt01.hcloud.yml).

### Redfish (OOB) inventory + control

**Inventory hosts should point to the BMC endpoint** (iDRAC / iLO / XCC / other BMCs).
Run Redfish tasks with a **local connection** (no SSH to the BMC required):

```ini
[oob]
idrac01 ansible_host=10.0.0.10
ilo01   ansible_host=10.0.0.11

[oob:vars]
ansible_connection=local
ansible_python_interpreter=/usr/bin/python3

oob_redfish_inventory_user=admin
oob_redfish_inventory_password=secret
oob_redfish_inventory_validate_certs=false
oob_redfish_control_user=admin
oob_redfish_control_password=secret
oob_redfish_control_validate_certs=false
```

#### Example: one-time PXE boot + reboot

```yaml
---
- hosts: oob
  gather_facts: false
  roles:
    - lit.foundational.oob_redfish_inventory
    - lit.foundational.oob_redfish_control
  vars:
    oob_redfish_control_boot_target: pxe
    oob_redfish_control_power_action: reboot
```

#### Example: mount ISO via VirtualMedia + boot CD + reboot

```yaml
---
- hosts: oob
  gather_facts: false
  roles:
    - lit.foundational.oob_redfish_control
  vars:
    oob_redfish_control_virtual_media_action: insert
    oob_redfish_control_virtual_media_category: Systems
    oob_redfish_control_virtual_media_image_url: "http://files.example.local/rhel-9.4.iso"

    oob_redfish_control_boot_target: cd
    oob_redfish_control_power_action: reboot
```

> Note: In a "real" unattended install, Redfish usually only does **boot selection + reboot**.
> The OS installation itself should be handled by PXE/Kickstart or an ISO workflow.

---

### Example: using `lit.foundational.terragrunt`

Minimal playbook to run `terragrunt` against a stubbed terragrunt binary (for
demo/smoke purposes). Replace the stub and `terragrunt_source` with your module
source in real use:

```yaml
---
- name: Example - lit.foundational.terragrunt
  hosts: localhost
  gather_facts: false

  vars:
    cluster_id: example
    terragrunt_source: "./module"
    terragrunt_skip_confirmation: true

  tasks:
    - name: Create terragrunt stub in PATH (demo only)
      ansible.builtin.copy:
        dest: /usr/local/bin/terragrunt
        mode: "0755"
        content: |
          #!/bin/sh
          echo "terragrunt stub $*"
          if [ "$1" = "plan" ]; then
            echo "No objects need to be destroyed"
          fi

    - name: Run lit.foundational.terragrunt
      ansible.builtin.include_role:
        name: "lit.foundational.terragrunt"
      vars:
        terragrunt_plan_file: /tmp/terragrunt.plan
        terragrunt_skip_confirmation: true
```

See also:

- `playbooks/terragrunt.yml`  - focused example only for `terragrunt`.
- `playbooks/example.yml`  - collection-level example playbook used as the
  canonical entrypoint in CI.

---

## Development

- `galaxy.yml` defines the collection metadata (namespace `lit`, name `foundational`).
- Roles live under `roles/` (e.g. `roles/terragrunt/`, `roles/oob_redfish_*`).
- The collection can be built locally with:

  ```bash
  ansible-galaxy collection build
  ```

- Molecule scenarios are located under `molecule/`, for example:

  - `molecule/terragrunt_basic/`  - runs the `terragrunt` role against a
    stubbed terragrunt binary to exercise `init` + `plan` + `apply`.
  - `molecule/vmware_vsphere_basic/`  - stubs the vmware_vsphere role (stub mode)
    so Molecule can run without a vSphere backend.

---

## Local checks

This repository uses **pre-commit** and a shared devtools container
(`ee-wunder-devtools-ubi9`) to keep linting and runtime tests consistent between
local development and CI.

### 1) Install pre-commit

```bash
pip install pre-commit
pre-commit install
```

### 2) Run all linters locally

```bash
pre-commit run --all-files
```

This will, among other things:

- run `yamllint` inside the `ee-wunder-devtools-ubi9` container,
- run `ansible-lint` inside the devtools container (after building/installing
  the collection),
- run all non-`*_heavy` Molecule scenarios inside the devtools container,
- lint `.github/workflows/*.yml` via `actionlint` (Docker),
- validate `renovate.json` via `renovate-config-validator` (Docker), if present.

Heavy scenarios such as Vagrant/RHEL9 tests are named with a `_heavy` suffix and
run via dedicated manual scripts and are not part of the default hook.

### 3) Run the collection smoke test

For a full **collection smoke test** (build + install + example playbook via
FQCN inside devtools):

```bash
pre-commit run collection-smoke --all-files --hook-stage manual
```

This hook calls `scripts/devtools-collection-prepare.sh` and
`scripts/devtools-collection-smoke.sh` internally, which:

1. build the `lit.foundational` collection inside the devtools container,
2. install the built tarball into `/tmp/wunder/collections`,
3. run the top-level example playbook:

   ```bash
   ansible-playbook -i localhost, playbooks/example.yml
   ```

   with `ANSIBLE_COLLECTIONS_PATH=/tmp/wunder/collections`.

Use this smoke test whenever you want to verify that the collection is:

- buildable,
- installable,
- and usable via FQCN before pushing or tagging a release.

## Security

See [SECURITY.md](./SECURITY.md) for supported versions and vulnerability reporting.

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md) for contribution and review expectations.

## License

See [LICENSE](./LICENSE).

<!-- BEGIN LIT_RELEASE_QUALITY_MODEL -->

## Release Validation Model

This repository follows the Lightning IT shared release and quality model.
The README shows the current supported and tested matrix.
Exact per-version validation proof is stored with each GitHub Release as `release-evidence.md` and `release-evidence.json`.
Releases are created from the protected `main` branch after a reviewed `develop -> main` release promotion.
Collection releases validate collection sanity, Molecule scenarios, build integrity, and Ansible Galaxy publishing where enabled.

See:

- [RELEASE.md](./RELEASE.md)
- [TESTING.md](./TESTING.md)
- [GitHub Releases](../../releases)

Repository classification: **Ansible Collection**.
Required test profiles: `pre-commit, lint, light, molecule-light, release-validation`.
Publishing targets: `github-release, ansible-galaxy`.

<!-- END LIT_RELEASE_QUALITY_MODEL -->

<!-- BEGIN LIT_COMPATIBILITY_MATRIX -->

## Compatibility Matrix

| Collection Version | Platform | Product | Validation |
|---|---|---|---|
| Latest release | ubuntu-latest | ansible-core, molecule | See release evidence |

| Scenario | Test Type | Validation |
|---|---|---|
| collection-sanity | Collection sanity | See release evidence |
| molecule-light | Molecule light | See release evidence |
| galaxy-build | Galaxy build/publish | See release evidence |

Validation proof for each released version is stored in the corresponding GitHub Release evidence.

<!-- END LIT_COMPATIBILITY_MATRIX -->

## Release Evidence

Every released version includes immutable release evidence attached to the corresponding GitHub Release.
The evidence records:

- tested matrix combinations
- GitHub Actions run links
- artifact references
- publish status
- security scan status

See [GitHub Releases](../../releases), [RELEASE.md](./RELEASE.md), and [TESTING.md](./TESTING.md) for the release process and validation model.
