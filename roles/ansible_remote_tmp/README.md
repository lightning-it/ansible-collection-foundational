# lit.foundational.ansible_remote_tmp

Bootstrap and enforce the managed host directory used by Ansible for module
staging.

This is general Ansible runtime behavior, not AAP behavior. Use this role before
heavy roles when inventory sets `ansible_remote_tmp` to a custom path such as
`/appl/ansible-tmp`.

## Why This Role Uses Raw First

Normal Ansible modules need `ansible_remote_tmp` before they can run. If the
directory is missing or has restrictive permissions, even `file`, `setup`, and
`assert` can fail before a role has a chance to repair it.

This role therefore runs one small `raw` bootstrap command first, then enforces
the final state with normal Ansible modules.

## Variables

- `ansible_remote_tmp_enabled` (bool, default: `true`): Enable the role.
- `ansible_remote_tmp_path` (string): Directory to manage. Defaults to
  Ansible's `ansible_remote_tmp` inventory/config value.
- `ansible_remote_tmp_owner` / `ansible_remote_tmp_group` (default: `root`):
  Directory ownership.
- `ansible_remote_tmp_mode` (default: `"1777"`): Directory mode. Use `1777`
  for shared become-user workflows.
- `ansible_remote_tmp_bootstrap_raw` (bool, default: `true`): Run the raw
  bootstrap before normal modules.
- `ansible_remote_tmp_validate_users` (list, default: `[]`): Optional users
  that must be able to create temp directories there.

## Example

Use this in a pre-task before fact gathering or application roles:

```yaml
---
- name: Bootstrap Ansible runtime temp directory
  hosts: aap_hosts
  gather_facts: false
  roles:
    - role: lit.foundational.ansible_remote_tmp
      vars:
        ansible_remote_tmp_path: /appl/ansible-tmp
        ansible_remote_tmp_validate_users:
          - svc_ansible
          - aap
```

Then application roles can safely use:

```yaml
ansible_remote_tmp: /appl/ansible-tmp
```

## License

MIT
