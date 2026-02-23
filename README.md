# lit.foundational

Foundational Ansible collection for ModuLix.  
It provides generic building blocks and orchestration helpers for consistent, repeatable automation.

## What’s inside

### Key roles

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
  - power actions (on/off/reboot/graceful…),
  - one-time or persistent boot override (PXE/CD/USB/HDD/UEFI targets),
  - optional virtual media insert/eject.

---

## Dependencies

### Redfish roles

The Redfish roles use the `community.general` collection.

Add this to your collection `galaxy.yml`:

```yaml
dependencies:
  community.general: ">=10.6.0"
```

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

### Redfish (OOB) inventory + control

**Inventory hosts should point to the BMC endpoint** (iDRAC / iLO / XCC / …).  
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

> Note: In a “real” unattended install, Redfish usually only does **boot selection + reboot**.  
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

- `playbooks/terragrunt.yml` – focused example only for `terragrunt`.
- `playbooks/example.yml` – collection-level example playbook used as the
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

  - `molecule/terragrunt_basic/` – runs the `terragrunt` role against a
    stubbed terragrunt binary to exercise `init` + `plan` + `apply`.
  - `molecule/vmware_vsphere_basic/` – stubs the vmware_vsphere role (stub mode)
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
