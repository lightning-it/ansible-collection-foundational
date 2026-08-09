# Root of Trust Validate

`lit.foundational.root_of_trust_validate` provides two generic, non-mutating
entrypoints for a single infrastructure root of trust:

- `g0_observe` queries one unambiguously identified Hetzner Robot server, its
  firewall, and one vSwitch. API failures and split or ambiguous numeric/IP
  identity fail the run. Server lifecycle, firewall, and vSwitch drift are
  returned as sanitized `findings` and do not fail the observation.
- `g2_plan` performs controller-local validation only. It requires
  `selection_scope: single_root_of_trust`, one exact selected target, the full
  unique fleet and install order, root-first prerequisite/Tang/Vault placement,
  a `ready` and non-cancelled provider lifecycle, and exact active eight-rule
  bootstrap and ten-rule hardened firewall plans.

The G2 firewall contract requires one exact controller IPv4 `/32` on TCP 22,
1905, and 2222 in bootstrap; that same source on TCP 1905 and 2222 with no TCP
22 in hardened mode; exactly three unique Tang IPv4 `/32` sources; and only the
reviewed stateless response-rule shapes. The provider firewall, main-interface
filter, IPv6 filter, Hetzner-services allowlist, and explicit output policy must
all be enabled. IPv6 input, arbitrary wildcard rules, broad controller/Tang
networks, nulls, empty values, and unrecognized rule fields fail closed.

## Requirements

- Ansible Core version from the collection's `meta/runtime.yml`.
- `community.hrobot` at the version declared in `galaxy.yml` for live G0.
- Controller connectivity to Hetzner Robot for live G0 only.
- Pre-resolved Robot web-service credentials for live G0.

G2 and `root_of_trust_validate_g0_validate_only: true` make no API, DNS,
filesystem, or managed-host calls.

## Variables

All defaults are documented in `defaults/main.yml`; entrypoint schemas are in
`meta/argument_specs.yml`.

| Variable | Purpose |
|---|---|
| `root_of_trust_validate_selection_scope` | Must be `single_root_of_trust` |
| `root_of_trust_validate_target` | Exact inventory identity plus ready, non-cancelled provider lifecycle |
| `root_of_trust_validate_g0_validate_only` | Validate G0 inputs without API calls |
| `root_of_trust_validate_robot_user` / `root_of_trust_validate_robot_password` | Resolved live G0 Robot credentials |
| `root_of_trust_validate_expected_firewall` | Expected firewall used for G0 findings |
| `root_of_trust_validate_expected_vswitch` | Expected vSwitch used for G0 findings |
| `root_of_trust_validate_selected_hosts` | Exact rendered G2 selection |
| `root_of_trust_validate_expected_fleet` | Complete governed fleet |
| `root_of_trust_validate_install_order` | Complete unique installation order |
| `root_of_trust_validate_prerequisite_hosts` | Ordered prerequisite prefix |
| `root_of_trust_validate_root_host` | Single root-of-trust inventory hostname |
| `root_of_trust_validate_tang_host` / `root_of_trust_validate_vault_host` | Service-placement identities |
| `root_of_trust_validate_controller_ipv4_cidr` | Approved controller as one canonical IPv4 `/32` |
| `root_of_trust_validate_firewall` | Complete active bootstrap, hardened, IPv6, and output policy |

Both entrypoints publish `root_of_trust_validate_result`. G0 exposes only
sanitized finding codes, resource classes, and severities; raw Robot responses
are cleared from controller facts in an `always` block.

## Dependencies

The collection declares `community.hrobot` in `galaxy.yml`. The role has no
role dependencies and does not resolve credentials itself.

## Example Playbook

```yaml
---
- name: Validate one local root-of-trust plan
  hosts: root_of_trust_candidates
  gather_facts: false
  connection: local
  tasks:
    - name: Validate the exact local plan
      ansible.builtin.include_role:
        name: lit.foundational.root_of_trust_validate
        tasks_from: g2_plan
      vars:
        root_of_trust_validate_selection_scope: single_root_of_trust
        root_of_trust_validate_target:
          inventory_hostname: root01.example.invalid
          server_number: 100001
          public_ipv4: 192.0.2.10
          status: ready
          cancelled: false
        root_of_trust_validate_selected_hosts: [root01.example.invalid]
        root_of_trust_validate_expected_fleet:
          - root01.example.invalid
          - client01.example.invalid
        root_of_trust_validate_install_order:
          - root01.example.invalid
          - client01.example.invalid
        root_of_trust_validate_prerequisite_hosts: [root01.example.invalid]
        root_of_trust_validate_root_host: root01.example.invalid
        root_of_trust_validate_tang_host: root01.example.invalid
        root_of_trust_validate_vault_host: root01.example.invalid
        root_of_trust_validate_controller_ipv4_cidr: 198.51.100.7/32
        root_of_trust_validate_firewall: "{{ complete_firewall_contract }}"
```

## License

MIT

## Author

Lightning IT
