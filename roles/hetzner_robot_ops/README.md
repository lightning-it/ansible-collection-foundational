# lit.foundational.hetzner_robot_ops

Performs one explicitly selected boot-configuration or reset operation against one existing Hetzner Robot dedicated
server. The role is intentionally separate from declarative Robot configuration and from destructive operating-system
installation workflows.

The safe default is `hetzner_robot_ops_action: none`. API operations run once on the Ansible controller, use only
`community.hrobot.boot` or `community.hrobot.reset`, and never expose Robot credentials or generated rescue passwords.

## Requirements

- Ansible matching this collection's `meta/runtime.yml` requirement.
- The fixed `community.hrobot` collection version declared by `lit.foundational`.
- A Robot web-service username and password, resolved before this role runs.
- A play containing exactly one host. Use a dedicated `localhost` operations play for the clearest safety boundary.
- For rescue activation, at least one SSH public key or fingerprint already registered in Hetzner Robot.

The role delegates API modules to `localhost`; it does not connect to the dedicated server. The Robot account must be
authorized for the selected server. Inject credentials from `lit.foundational.secret_resolver`, Ansible Vault, an
Automation Controller credential, or another secret backend. Do not store plaintext credentials in playbooks.

## Variables

All inputs and defaults are defined in [`defaults/main.yml`](defaults/main.yml). The principal variables are:

| Variable | Default | Purpose |
|---|---:|---|
| `hetzner_robot_ops_action` | `none` | `none`, `activate_rescue`, `set_regular_boot`, or `reset`. |
| `hetzner_robot_ops_hetzner_user` | empty | Secret Robot web-service username. |
| `hetzner_robot_ops_hetzner_password` | empty | Secret Robot web-service password. |
| `hetzner_robot_ops_server_number` | `0` | Positive numeric identifier of exactly one dedicated server. |
| `hetzner_robot_ops_server_ip` | empty | Main IPv4 that must belong to that numeric server. |
| `hetzner_robot_ops_rate_limit_retry_timeout` | `60` | Finite retry timeout for Robot API rate limiting. |
| `hetzner_robot_ops_boot_confirmation` | empty | Must equal `BOOT <server_number>` for either boot action. |
| `hetzner_robot_ops_rescue_os` | `linux` | Rescue-system operating-system identifier. |
| `hetzner_robot_ops_rescue_authorized_keys` | `[]` | Robot-registered keys installed in the rescue system. |
| `hetzner_robot_ops_reset_confirmation` | empty | Must equal `RESET <server_number>` for every reset. |
| `hetzner_robot_ops_reset_type` | `software` | `software`, `power`, `hardware`, or `manual`. |
| `hetzner_robot_ops_manual_reset_confirmation` | empty | Must additionally equal `MANUAL RESET <server_number>` for manual reset. |

`hetzner_robot_ops_result` is the only public output. It contains the action, target server number, change status,
check-mode status, and a non-sensitive operation type. Raw module responses are discarded because boot activation can
return a generated root password.

Before any active operation, the role queries the numeric server with
`community.hrobot.server_info` and requires its main IPv4 to equal
`hetzner_robot_ops_server_ip`. This binds an inventory-selected host to the
operator-confirmed Robot number and prevents a valid confirmation for one
server from being reused against another target.

Boot configuration and reset are deliberately separate operations. `activate_rescue` arranges the next boot but does
not reset the server. Invoke `reset` in a separate, independently confirmed play only when the reboot is intended.
Likewise, `set_regular_boot` removes special boot configuration but does not reboot the server.

The `reset` action is not idempotent: it performs the selected reset on every non-check-mode invocation. Boot
configuration uses an idempotent module, but still requires explicit action selection and confirmation. Check mode is
supported by both official modules and retains all safety validation.

## Dependencies

This role has no role dependencies. It uses the fixed `community.hrobot` collection dependency declared in the parent
collection's `galaxy.yml`.

## Example Playbook

Activate Linux rescue for one server without rebooting it:

```yaml
---
- name: Activate Hetzner rescue for one server
  hosts: localhost
  connection: local
  gather_facts: false
  roles:
    - role: lit.foundational.hetzner_robot_ops
      vars:
        hetzner_robot_ops_action: activate_rescue
        hetzner_robot_ops_hetzner_user: "{{ robot_credentials.username }}"
        hetzner_robot_ops_hetzner_password: "{{ robot_credentials.password }}"
        hetzner_robot_ops_server_number: 1234567
        hetzner_robot_ops_server_ip: 192.0.2.10
        hetzner_robot_ops_boot_confirmation: "BOOT 1234567"
        hetzner_robot_ops_rescue_os: linux
        hetzner_robot_ops_rescue_authorized_keys:
          - "SHA256:replace-with-a-registered-key-fingerprint"
```

Reset is a separate invocation and a separate approval decision:

```yaml
---
- name: Reset one server into its configured next-boot environment
  hosts: localhost
  connection: local
  gather_facts: false
  roles:
    - role: lit.foundational.hetzner_robot_ops
      vars:
        hetzner_robot_ops_action: reset
        hetzner_robot_ops_hetzner_user: "{{ robot_credentials.username }}"
        hetzner_robot_ops_hetzner_password: "{{ robot_credentials.password }}"
        hetzner_robot_ops_server_number: 1234567
        hetzner_robot_ops_server_ip: 192.0.2.10
        hetzner_robot_ops_reset_type: software
        hetzner_robot_ops_reset_confirmation: "RESET 1234567"
```

Use `--check` to validate the inputs and ask the official module for its change prediction without changing Robot or
resetting the server.

## License

MIT

## Author

Lightning IT
