# lit.foundational.kubeplay

Wrapper role to run application roles (vault, nexus, etc.) with a single list.
Apps can be specified by name (mapped to a role), by explicit role, or by a
local tasks file.

## Usage

```yaml
- name: Run platform apps
  hosts: kube
  gather_facts: false

  roles:
    - role: lit.foundational.kubeplay
      vars:
        kubeplay_apps:
          - vault
          - name: nexus
            vars:
              nexus_experimental_acknowledge: true
```

## App definition formats

```yaml
kubeplay_apps:
  # String name (resolved via kubeplay_app_map)
  - vault

  # Explicit role
  - name: nexus
    role: lit.supplementary.nexus
    vars:
      nexus_experimental_acknowledge: true

  # Local tasks file (relative to this role's tasks/ directory)
  - name: demo
    tasks: apps/demo.yml
```

## Variables

- `kubeplay_enabled` (bool, default: `true`): enable/disable the role.
- `kubeplay_apps` (list, default: `[]`): app list to execute.
- `kubeplay_app_map` (dict, default: includes `vault` and `nexus`): map of
  short names to roles.
- `kubeplay_fail_on_unknown` (bool, default: `true`): fail when an app has no
  role or tasks defined.

## Notes

- App entries can include `vars`, `tags`, `enabled`, and `when` keys.
- `tags` are applied to included role tasks via `apply`.
