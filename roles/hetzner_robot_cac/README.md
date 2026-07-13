# Hetzner Robot Configuration as Code

`lit.foundational.hetzner_robot_cac` reconciles configuration for already leased
Hetzner dedicated servers through the purpose-built modules in `community.hrobot`.
It does not purchase, cancel, reset, reboot, or reinstall servers.

All Robot calls run once on the controller, use module-level check-mode support,
and are protected with `no_log`. The public result contains only resource counts,
state semantics, and a combined changed flag.

## Requirements

- Ansible Core version from the collection's `meta/runtime.yml`.
- `community.hrobot` at the exact version declared by the collection.
- Network access from the automation controller to Hetzner Robot.
- A Robot web-service username and password resolved before role invocation.

The optional `molecule/hetzner-robot-live_heavy` scenario performs a read-only
server audit when all `HROBOT_LIVE_*` gates are supplied. It is excluded from
the default light suite and never reconciles or resets live infrastructure.

Use `lit.foundational.secret_resolver`, Ansible Vault, HashiCorp Vault, a controller
credential, or CI environment-backed credentials to populate the role inputs. Do
not store Robot credentials in playbooks or inventory plaintext.

The role manages configuration attached to existing products only:

- dedicated server display names;
- stateless firewalls on `main` or `kvm` ports;
- vSwitch membership and cancellation;
- reverse DNS;
- public SSH keys stored by Robot; and
- failover IP routing.

Server rescue activation, reset, and other day-two actions belong to
`lit.foundational.hetzner_robot_ops`. Rescue-host validation and installimage are
separate responsibilities as well.

## Variables

All defaults are documented in [`defaults/main.yml`](defaults/main.yml).

| Variable | Default | Purpose |
| --- | --- | --- |
| `hetzner_robot_cac_user` | `""` | Resolved Robot web-service username. |
| `hetzner_robot_cac_password` | `""` | Resolved Robot web-service password. |
| `hetzner_robot_cac_validate_only` | `false` | Validate and publish a plan without API calls or credentials. |
| `hetzner_robot_cac_state` | `present` | Default state inherited by resource items. |
| `hetzner_robot_cac_allow_destructive` | `false` | Mandatory approval for any effective `absent` item. |
| `hetzner_robot_cac_rate_limit_retry_timeout` | `120` | Non-negative bounded Robot rate-limit retry timeout. |
| `hetzner_robot_cac_server_metadata` | `[]` | Server-number-to-name declarations. |
| `hetzner_robot_cac_firewalls` | `[]` | Server firewall state and authoritative rules. |
| `hetzner_robot_cac_vswitches` | `[]` | Name/VLAN identities and optional server membership. |
| `hetzner_robot_cac_reverse_dns` | `[]` | Address-to-hostname declarations. |
| `hetzner_robot_cac_ssh_keys` | `[]` | Robot public SSH keys. |
| `hetzner_robot_cac_failover_ips` | `[]` | Failover IP routing declarations. |
| `hetzner_robot_cac_audit_servers` | `[]` | Exact server and optional firewall audit declarations. |
| `hetzner_robot_cac_audit_vswitches` | `[]` | Exact active vSwitch membership declarations. |

Each item may override `state`. A present failover IP maps to Robot state
`routed`; absent maps to `unrouted`. An absent firewall is disabled. An absent
vSwitch is cancelled at the end of the current day. Set `servers: []` on an
absent vSwitch to actively remove all members before cancellation.

Dedicated server metadata is present-only because `community.hrobot.server`
updates an already leased server and cannot delete it. Product cancellation is
deliberately outside this role.

Firewall rules are complete ordered rule sets. Supply both `rules.input` and
`rules.output`, using empty lists intentionally where required. The Robot
firewall is stateless; reply traffic must be allowed explicitly. Prefer
`server_number` because Hetzner deprecated firewall lookup by `server_ip`.

Removing reverse DNS from a server's main IPv4 is a Robot API exception: Hetzner
replaces it with a generated default name, so repeatedly declaring that entry
absent is not idempotent in the upstream module. Declare that generated or desired
name explicitly with `state: present` for main IPv4 addresses. Absent remains
suitable for other supported addresses.

`hetzner_robot_cac_result` is the stable, secret-free output. Raw module results
are cleared after reconciliation and are never logged.

### Read-only audit entrypoint

Invoke `tasks_from: audit` to replace ad hoc Robot server, firewall, and vSwitch
GET/assert blocks. The entrypoint queries `community.hrobot.server_info` once per
inventory-host role invocation, resolves every declared public IP to exactly one
numeric server number, and then queries firewalls using that number.

Firewall audit fields default to `status: active`, `port: main`,
`filter_ipv6: false`, and `allowlist_hos: false`. If `rules` is provided, both
ordered `input` and `output` lists are required and compared exactly after
normalization. Missing optional rule fields become null, and a bare IPv4 host in
`src_ip` or `dst_ip` becomes its equivalent `/32` CIDR before comparison.

The vSwitch audit calls `community.hrobot.v_switch` in forced check mode with an
exact declared `servers` list. A missing vSwitch, membership drift, or any member
whose status is not `ready` fails the audit without creating, changing, or
cancelling anything. The entrypoint delegates API calls to localhost but does not
use `run_once`, so per-inventory-host declarations remain valid.

On success, `hetzner_robot_cac_audit_result` contains only `changed: false`,
`queried`, `validated`, and resource counts. Raw server, firewall, and vSwitch
responses are protected by `no_log` and cleared in an `always` block.

## Dependencies

The collection declares a fixed `community.hrobot` dependency in `galaxy.yml`.
This role has no role dependencies and does not resolve credentials itself.

## Example Playbook

```yaml
---
- name: Reconcile dedicated server configuration
  hosts: localhost
  gather_facts: false
  vars:
    hetzner_robot_cac_user: "{{ resolved_robot_user }}"
    hetzner_robot_cac_password: "{{ resolved_robot_password }}"
    hetzner_robot_cac_server_metadata:
      - server_number: 1234567
        server_name: edge01.example.com
    hetzner_robot_cac_firewalls:
      - server_number: 1234567
        filter_ipv6: false
        allowlist_hos: true
        rules:
          input:
            - name: Allow established TCP replies
              ip_version: ipv4
              protocol: tcp
              tcp_flags: ack
              action: accept
            - name: Allow trusted SSH
              ip_version: ipv4
              src_ip: 192.0.2.0/24
              dst_port: "22"
              protocol: tcp
              action: accept
          output:
            - name: Allow outbound IPv4
              ip_version: ipv4
              action: accept
    hetzner_robot_cac_vswitches:
      - name: private-backend
        vlan: 4010
        servers:
          - "1234567"
    hetzner_robot_cac_reverse_dns:
      - ip: 192.0.2.10
        value: edge01.example.com
    hetzner_robot_cac_ssh_keys:
      - name: automation
        public_key: "{{ resolved_public_key }}"
    hetzner_robot_cac_failover_ips:
      - failover_ip: 192.0.2.20
        value: 192.0.2.10
  roles:
    - role: lit.foundational.hetzner_robot_cac
```

For validation in pull requests, set `hetzner_robot_cac_validate_only: true`.
Credentials are then optional, but all safety and schema assertions still run.

Use the audit entrypoint from a validation runbook:

```yaml
---
- name: Audit Robot state for each selected dedicated server
  hosts: hetzner_baremetal
  gather_facts: false
  tasks:
    - name: Audit Robot server, firewall, and shared vSwitch
      ansible.builtin.include_role:
        name: lit.foundational.hetzner_robot_cac
        tasks_from: audit
      vars:
        hetzner_robot_cac_user: "{{ resolved_robot_user }}"
        hetzner_robot_cac_password: "{{ resolved_robot_password }}"
        hetzner_robot_cac_audit_servers:
          - server_ip: "{{ ansible_host }}"
            server_name: "{{ inventory_hostname }}"
            firewall:
              rules:
                input:
                  - name: Allow trusted SSH
                    ip_version: ipv4
                    src_ip: 192.0.2.10
                    dst_ip: "{{ ansible_host }}"
                    dst_port: "22"
                    protocol: tcp
                    action: accept
                output:
                  - name: Allow outbound
                    action: accept
        hetzner_robot_cac_audit_vswitches:
          - name: private-backend
            vlan: 4010
            servers: "{{ groups['hetzner_baremetal'] | map('extract', hostvars, 'ansible_host') | list }}"
```

## License

MIT

## Author

Lightning IT
