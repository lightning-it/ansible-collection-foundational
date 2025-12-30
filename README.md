# lit.foundational

Foundational Ansible collection for ModuLix / Lightning IT. It provides generic
building blocks and orchestration helpers for consistent, repeatable automation.
The primary role in this collection is:

- `terragrunt` – a Terragrunt wrapper that:
  - prepares a per-cluster working directory on the control host,
  - renders a dynamic `terragrunt.hcl`,
  - runs `terragrunt init`, `terragrunt plan`, and `terragrunt apply` with
    optional confirmation and auth support.

---

## Usage

Until this collection is published to Ansible Galaxy, you can install it directly
from GitHub (example: `main` branch):

```bash
ansible-galaxy collection install \
  git+https://github.com/lightning-it/ansible-collection-foundational.git,main
```

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

- `galaxy.yml` defines the collection metadata (namespace `lit`, name
  `foundational`, license `GPL-2.0-only`).
- Roles live under `roles/` (e.g. `roles/terragrunt/`).
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
(`wunder-devtools-ee`) to keep linting and runtime tests consistent between
local development and CI.

### 1. Install pre-commit

If you haven’t already:

```bash
pip install pre-commit
pre-commit install
```

This installs the configured hooks for this repo (YAML, Ansible, Molecule, GitHub
Actions, Renovate, etc.).

### 2. Run all linters locally

To run all configured checks (YAML, ansible-lint, Molecule, GitHub Actions
workflow linting, Renovate config validation):

```bash
pre-commit run --all-files
```

This will, among other things:

- run `yamllint` inside the `wunder-devtools-ee` container,
- run `ansible-lint` inside the devtools container (after building/installing
  the collection),
- run all non-`*_heavy` Molecule scenarios inside the devtools container
  (e.g. `terragrunt_basic`),
- lint `.github/workflows/*.yml` via `actionlint` (Docker),
- validate `renovate.json` via `renovate-config-validator` (Docker), if present.

Heavy scenarios such as Vagrant/RHEL9 tests are named with a `_heavy` suffix and
run via dedicated manual scripts (e.g. `devtools-molecule-rhel9_rdp_heavy.sh`)
and are not part of the default hook.

### 3. Run the collection smoke test

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

   with `ANSIBLE_COLLECTIONS_PATHS=/tmp/wunder/collections`.

Use this smoke test whenever you want to verify that the collection is:

- buildable,
- installable,
- and usable via FQCN (e.g. `lit.foundational.terragrunt`) before pushing or
  tagging a release.
