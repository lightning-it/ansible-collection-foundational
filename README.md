# lit.foundational

Foundational Ansible collection for ModuLix / Lightning IT. It provides generic
building blocks and orchestration helpers for consistent, repeatable automation.
The initial role in this collection is:

- `tf_runner` – a generic Terraform runner role that:
  - prepares a Terraform working directory on the control host,
  - optionally cleans previous state,
  - writes variables into `terraform.tfvars.json`,
  - runs `terraform init` and `terraform apply` with configurable arguments.

---

## Usage

Until this collection is published to Ansible Galaxy, you can install it directly
from GitHub (example: `main` branch):

```bash
ansible-galaxy collection install \
  git+https://github.com/lightning-it/ansible-collection-foundational.git,main
```

### Example: using `lit.foundational.tf_runner`

Minimal playbook to run `tf_runner` against a very simple Terraform
configuration (no real resources, but fully exercises `init` + `apply`):

```yaml
---
- name: Example - lit.foundational.tf_runner
  hosts: localhost
  gather_facts: false

  vars:
    tf_runner_workdir: "/tmp/tf-runner-example"

  tasks:
    - name: Ensure Terraform working directory exists
      ansible.builtin.file:
        path: "{{ tf_runner_workdir }}"
        state: directory
        mode: "0750"

    - name: Write minimal Terraform configuration
      ansible.builtin.copy:
        dest: "{{ tf_runner_workdir }}/main.tf"
        mode: "0640"
        content: |
          terraform {
            required_version = ">= 1.3.0"
          }

    - name: Run lit.foundational.tf_runner
      ansible.builtin.include_role:
        name: "lit.foundational.tf_runner"
      vars:
        tf_runner_workdir: "{{ tf_runner_workdir }}"
        tf_runner_clean_state: true
        tf_runner_skip_apply: false
        tf_runner_vars: {}
```

See also:

- `playbooks/tf_runner.yml` – focused example only for `tf_runner`.
- `playbooks/example.yml` – collection-level example playbook used as the
  canonical entrypoint in CI.

---

## Development

- `galaxy.yml` defines the collection metadata (namespace `lit`, name
  `foundational`, license `GPL-2.0-only`).
- Roles live under `roles/` (e.g. `roles/tf_runner/`).
- The collection can be built locally with:

  ```bash
  ansible-galaxy collection build
  ```

- Molecule scenarios are located under `molecule/`, for example:

  - `molecule/tf_runner_basic/` – runs the `tf_runner` role against a
    minimal valid Terraform configuration to exercise `init` + `apply`.

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
  (e.g. `tf_runner_basic`),
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
- and usable via FQCN (e.g. `lit.foundational.tf_runner`) before pushing or
  tagging a release.
