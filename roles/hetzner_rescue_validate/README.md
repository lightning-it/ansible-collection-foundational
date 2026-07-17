# lit.foundational.hetzner_rescue_validate

Validates a leased Hetzner dedicated server while it runs in the Rescue system. The role separates reusable
target observation from Robot API reconciliation and from environment-specific fleet orchestration.

The default entrypoint proves the Rescue marker, exact deployment public keys, complete physical-disk identity,
SMART health and threshold policy, HTTPS egress, and optionally a temporary VLAN data plane. The VLAN probe refuses
interface or address collisions and removes only the interface it created in an `always` block.

Additional entrypoints are:

- `controller_trust`: independently scan, fingerprint, and pin one Rescue Ed25519 host key.
- `controller_preflight`: run `controller_trust`, prove every declared deployment identity is loaded in the
  controller SSH agent, and compare declared A, PTR, and CNAME observations through an explicit DNS resolver.
- `data_plane`: validate and exercise only the temporary VLAN probe without repeating disk or SMART observations.
- `inventory_contract`: validate fleet selection, bootstrap order, host identity, key classes, service placement,
  Robot firewall policy, and MGMT/netplan alignment without external calls.
- `extended_smart`: run fresh ATA or NVMe extended self-tests with an explicit per-host confirmation gate.
- `luks_passphrase`: prove a retained secret unlocks the one installed LUKS root backed by approved system disks.

## Requirements

- `ansible-core` 2.18 or newer.
- Direct root access to the expected Hetzner Rescue system for target-side validation.
- `lsblk`, `smartctl`, and `nvme` where the corresponding disk protocol is present.
- `ip` and `ping` only when the temporary data-plane probe is enabled.
- `ssh-keyscan`, `ssh-keygen`, `ssh-add`, and a forwarded `SSH_AUTH_SOCK` on the controller for controller preflight.
- `community.general` and its `dnspython` dependency on the controller for authoritative DNS observations.
- An existing canonical controller directory, owned by the controller user with mode `0700`, for the Rescue
  `known_hosts` file. The role refuses to create or chmod a caller-selected directory.

Use `hetzner_rescue_validate_only: true` to validate the declaration without reading or changing a target. The role
never mounts filesystems. Normal validation is read-only except for the explicitly enabled temporary VLAN probe,
which owns and cleans its unique interface, and the separately authorized `extended_smart` entrypoint.

## Variables

The complete schema is in `meta/argument_specs.yml`; defaults are in `defaults/main.yml`.

| Variable | Purpose |
|---|---|
| `hetzner_rescue_validate_expected_disks` | Exact serial, model, byte size, rotational state, and purpose |
| `hetzner_rescue_validate_deploy_ssh_public_keys` | Exact normalized Rescue key-file contents |
| `hetzner_rescue_validate_smart_policy` | ATA/NVMe health, history, sector, media, endurance, and spare thresholds |
| `hetzner_rescue_validate_smart_overrides` | Per-serial threshold overrides |
| `hetzner_rescue_validate_data_plane` | Optional owned VLAN interface, address, peers, gateway, VLAN ID, and MTU |
| `hetzner_rescue_validate_egress_url` | HTTPS endpoint used for DNS/TLS/egress observation |
| `hetzner_rescue_validate_known_hosts_path` | Private controller file that receives additive pinned host entries |
| `hetzner_rescue_validate_public_ipv4` | Rescue IPv4 whose live Ed25519 key must match the declared pin |
| `hetzner_rescue_validate_ssh_ed25519_sha256` | Independently obtained Rescue Ed25519 SHA-256 host-key pin |
| `hetzner_rescue_validate_controller_required_ssh_public_keys` | Public identities that must already exist in the controller agent |
| `hetzner_rescue_validate_controller_dns_resolver` | Explicit resolver used for every authoritative DNS observation |
| `hetzner_rescue_validate_controller_dns_records` | Exact A, PTR, and CNAME `{name, type, value}` observations |
| `hetzner_rescue_validate_inventory_contract` | Complete validation-only rendered inventory contract |

`controller_preflight` derives SHA-256 fingerprints from the public keys and compares only fingerprints with
`ssh-add -l`; it never logs key material, agent output, host-key material, or DNS answers. Its published result contains
only booleans and counts. DNS values are compared exactly as returned by `community.general.dig`; use fully qualified
names with the resolver's trailing-dot representation for PTR and CNAME values. With
`hetzner_rescue_validate_only: true`, the entrypoint performs schema and policy validation without keyscan, agent, DNS,
or filesystem operations.

When several inventory hosts share one `known_hosts` path, directory, file, and entry mutations are throttled to one
controller writer. Each verified entry is reconciled with `state: present`; entries for other hosts are not reset or
removed. The role never truncates a caller-supplied controller file. An existing file must be a non-symlink regular
file owned by the controller user with mode `0600`.

The standalone `data_plane` entrypoint requires `hetzner_rescue_validate_data_plane.enabled: true`, distinct safe
parent and VLAN interface names, VLAN ID 1-4094, MTU 1280-9216, valid IPv4 addressing, and a duplicate-free peer list
that excludes the local address and gateway. Validation-only mode executes no `ip` or `ping` commands.

The `inventory_contract` entrypoint is always local validation: it executes no commands, DNS queries, filesystem
operations, or API calls. It accepts this single canonical interface:

```yaml
hetzner_rescue_validate_inventory_contract:
  selected_hosts: []
  expected_fleet: []
  install_order: []
  prerequisite_hosts: []
  host:
    inventory_hostname: ""
    public_ipv4: ""
  installimage:
    hostname: ""
    public_ipv4: ""
    action: plan
  ssh_public_keys:
    deploy: []
    breakglass: []
  service_hosts:
    tang: ""
    vault: ""
  robot_firewall:
    enabled: true
    dropbear_port: 2222
    input_rules:
      - ip_version: ipv4
        protocol: tcp
        dst_port: "22"
        name: Allow bootstrap SSH
        action: accept
      - ip_version: ipv4
        protocol: tcp
        dst_port: "1905"
        name: Allow hardened SSH
        action: accept
      - ip_version: ipv4
        protocol: tcp
        dst_port: "2222"
        name: Allow Dropbear
        action: accept
      - ip_version: ipv4
        protocol: icmp
        name: Allow wildcard ICMP
        action: accept
    output_rules:
      - name: Authoritative outbound policy
        action: accept
  mgmt:
    transport:
      provider: hetzner_robot_vswitch
      state: active
      name: ""
      vlan_id: 0
      mtu: 0
    network:
      state: active
      parent_interface: ""
      vlan_interface: ""
      ipv4: ""
    subnet:
      prefix_length: 0
      gateway: ""
    netplan_vlan:
      name: ""
      id: 0
      link: ""
      mtu: 0
      addresses: []
```

`selected_hosts` must exactly equal `expected_fleet`; `install_order` must contain that same unique fleet.
`prerequisite_hosts` is an ordered, unique prefix of `install_order`, and the declared Tang and Vault hosts must be
members of that prefix. Deployment and breakglass key lists are validated independently and never published.

Robot input rules use the native `community.hrobot` fields `ip_version`, `protocol`, optional `src_ip`, `src_port`,
`dst_ip`, `dst_port`, and `tcp_flags`, plus required `name` and `action`. The enabled firewall may contain at most ten
input rules and must contain exactly one unrestricted IPv4 TCP accept rule for each of ports 22, 1905, and
`dropbear_port`, plus exactly one wildcard IPv4 ICMP accept rule. `output_rules` is the authoritative output
declaration and must be nonempty.

Extended tests require all of:

```yaml
hetzner_rescue_validate_extended_smart_allow: true
hetzner_rescue_validate_extended_smart_confirmation: "SMART_EXTENDED:{{ inventory_hostname }}"
```

The entrypoint refuses check mode, unknown target serials, ambiguous disk identity, unsupported transport, an
already active test, an unbounded duration, and duplicate NVMe controller/subsystem testing.

## Dependencies

None. Robot API operations belong to `lit.foundational.hetzner_robot_cac`; `community.hrobot` is not invoked by
this in-band validation role.

## Example Playbook

```yaml
---
- name: Validate one server in Hetzner Rescue
  hosts: hetzner_baremetal
  serial: 1
  gather_facts: false
  roles:
    - role: lit.foundational.hetzner_rescue_validate
      vars:
        hetzner_rescue_validate_expected_disks: "{{ baremetal_expected_disks }}"
        hetzner_rescue_validate_deploy_ssh_public_keys: "{{ deploy_ssh_public_keys }}"
```

Keep exact-host limits, fleet order, credentials, and operator approval in a thin inventory-driven runbook.

Controller-only preflight can be invoked from a fleet play while keeping orchestration outside the role:

```yaml
---
- name: Validate controller prerequisites for each Rescue host
  hosts: hetzner_baremetal
  gather_facts: false
  tasks:
    - name: Validate pinned trust, agent identities, and DNS
      ansible.builtin.include_role:
        name: lit.foundational.hetzner_rescue_validate
        tasks_from: controller_preflight
      vars:
        hetzner_rescue_validate_known_hosts_path: "{{ rescue_known_hosts_path }}"
        hetzner_rescue_validate_public_ipv4: "{{ ansible_host }}"
        hetzner_rescue_validate_ssh_ed25519_sha256: "{{ rescue_ssh_ed25519_sha256 }}"
        hetzner_rescue_validate_controller_required_ssh_public_keys: "{{ deploy_ssh_public_keys }}"
        hetzner_rescue_validate_controller_dns_resolver: "{{ authoritative_dns_resolver }}"
        hetzner_rescue_validate_controller_dns_records: "{{ rescue_dns_records }}"
```

## License

MIT

## Author

Lightning IT
