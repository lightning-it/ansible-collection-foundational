# lit.foundational.tf_runner

Run a Terraform module from the control host. The role can render a simple
`main.tf` (via `tf_runner_module_source`) and pass variables via
`terraform.tfvars.json`. It is intended for lightweight CI/Molecule use where
Terraform is available on the controller.

## Requirements
- Terraform installed on the control host.
- Ansible >= 2.15.

## Role Variables (common)
- `tf_runner_workdir` (string, required): Work directory on the control host.
- `tf_runner_module_source` (string, default: `""`): Module source to render into main.tf.
- `tf_runner_vars` (dict, default: `{}`): Variables written to terraform.tfvars.json.
- `tf_runner_clean_state` (bool, default: `false`): Remove previous state before running.
- `tf_runner_skip_apply` (bool, default: `false`): If true, only run `terraform init`.
- `tf_runner_init_args` (list, default: `[]`): Extra args for `terraform init`.
- `tf_runner_apply_args` (list, default: `["-auto-approve"]`): Extra args for `terraform apply`.

## Example
```yaml
- hosts: localhost
  connection: local
  gather_facts: false
  vars:
    tf_runner_workdir: "/tmp/tf-runner-example"
  tasks:
    - name: Ensure workdir exists
      ansible.builtin.file:
        path: "{{ tf_runner_workdir }}"
        state: directory
        mode: "0750"

    - name: Run Terraform via tf_runner
      ansible.builtin.include_role:
        name: lit.foundational.tf_runner
      vars:
        tf_runner_module_source: "git::https://example.com/my/module.git"
        tf_runner_vars:
          foo: bar
```
