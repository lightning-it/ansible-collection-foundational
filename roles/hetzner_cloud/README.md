# lit.foundational.hetzner_cloud

Declaratively provisions and manages IPv4-only Hetzner Cloud infrastructure with the official
`hetzner.hcloud` Ansible Collection. The role uses purpose-built collection modules; it does not issue raw REST
requests or use transient guest commands to declare infrastructure.

Supported resources are SSH keys, firewalls and firewall assignments, Networks, subnetworks, Primary IPs,
Floating IPs, spread placement groups, servers, exact server-to-Network attachments, and reverse DNS. Resources
can be created or adopted with `state: present`, or removed with explicitly authorized `state: absent`.

The main entrypoint is an infrastructure controller role. A separate `tasks_from: guest_floating_ip` entrypoint
only inspects a guest to report whether a Floating IPv4 address appears at runtime and in persistent network
configuration. It never changes the guest.

## Requirements

### Compatibility

| Component | Requirement |
|---|---|
| `ansible-core` | 2.18.0 or newer, as declared in `meta/runtime.yml` |
| `hetzner.hcloud` | 6.10.0, as declared in the collection `galaxy.yml` |
| Controller API access | HTTPS access to the Hetzner Cloud API |
| Dynamic inventory | `requests` 2.20 or newer and `python-dateutil` 2.7.5 or newer on the controller |
| Guest inspection | The guest `ip` command and read access to the configured persistent network paths |

The role is written for the `lit.foundational` namespace. Use the FQCN
`lit.foundational.hetzner_cloud`, not `lit.foundation.hetzner_cloud`.

### Test profiles

The mandatory controller-only scenario needs no cloud account and runs syntax, converge, idempotence, and policy
verification:

```console
bash scripts/devtools-molecule.sh hetzner-cloud-basic
```

`molecule/hetzner-cloud-incus_heavy` exercises the read-only guest entrypoint on Ubuntu 24.04. It is marked
`protected-incus`, requires an authorized Incus daemon and image access, and never adds a transient address. The
optional `molecule/hetzner_cloud_live_heavy` scenario creates billable disposable resources only when
`HCLOUD_LIVE_TEST=true`, a safe unique `HCLOUD_LIVE_TEST_ID`, and `HCLOUD_TOKEN` are all injected. It refuses names
containing `mgmt01`, verifies idempotence, and performs guarded reverse-order cleanup. Run it only in an isolated
Hetzner project with appropriate quotas; it is excluded from default CI and pre-commit discovery.

### Execution model

The main entrypoint validates inputs on the play host and delegates every API operation to `localhost` with
`become: false` and `run_once: true`. Run it in a dedicated `hosts: localhost`, `gather_facts: false` play for the
clearest variable and failure boundary. The Hetzner collection and its Python requirements belong in the Ansible
controller or execution environment, not on a provisioned server.

All API module tasks use `no_log: true`. The role accepts an explicit `hetzner_cloud_api_token`; when it is empty,
the official collection reads `HCLOUD_TOKEN` from the controller environment. The role does not retrieve secrets
itself. Compose it with `lit.foundational.secret_resolver` when a provider-independent input is required.

The `guest_floating_ip` entrypoint is different: it runs on the selected guest because it must inspect that guest's
runtime and filesystem state. Set `become: true` in the calling play when persistent network files are not readable
by the connection user.

### Hetzner permissions and prerequisites

Use a project-scoped Hetzner Cloud API token with only the permissions required by the declared resources. A
read-only token is sufficient for validation that performs API reads or for dynamic inventory; reconciliation
needs read/write permission. Fixed-address adoption requires the named or identified Primary IP or Floating IP to
exist in the same project before the role runs.

Server creation requires at least one declared SSH key by default. Setting
`hetzner_cloud_allow_server_root_password: true` permits the official module to create a server without SSH keys,
but this weakens the safe default and can cause Hetzner to return a generated root password. The role suppresses
API task output and removes generated password data from its published facts; SSH keys remain recommended.

### IPv4-only scope

This role deliberately requires `hetzner_cloud_ipv4_only: true` and always passes `enable_ipv6: false` to server
reconciliation. Primary IP and Floating IP declarations accept only `type: ipv4`; firewall, Network, subnetwork,
server-Network, reverse-DNS, and guest-detection inputs reject IPv6 syntax. It is not an IPv6 lifecycle role.

## Variables

The complete machine-readable interface is in `meta/argument_specs.yml`; role-owned defaults are in
`defaults/main.yml`.

### Global policy

| Variable | Default | Purpose |
|---|---|---|
| `hetzner_cloud_api_token` | `""` | Explicit token; an empty value lets official modules use `HCLOUD_TOKEN` |
| `hetzner_cloud_api_endpoint` | `https://api.hetzner.cloud/v1` | API endpoint passed to every official module |
| `hetzner_cloud_validate_only` | `false` | Validate and publish an API-free, secret-free resource-count plan |
| `hetzner_cloud_state` | `present` | Default item state when an item omits `state` |
| `hetzner_cloud_allow_destructive` | `false` | Mandatory opt-in if any effective state is `absent` |
| `hetzner_cloud_ipv4_only` | `true` | Mandatory IPv4-only policy gate |
| `hetzner_cloud_allow_server_root_password` | `false` | Allow server creation without an SSH key |

Every list item can override the global lifecycle with `state`. Apart from server lifecycle operations, item states
are `present` or `absent`. Server items also expose the idempotent official module states `created`, `started`, and
`stopped`; one-shot restart and rebuild actions are deliberately outside this declarative role interface.

### Resource lists

| Variable | Item identity and important fields |
|---|---|
| `hetzner_cloud_ssh_keys` | `id`, `name`, or `fingerprint`; `public_key`, `labels`, `force`, `state` |
| `hetzner_cloud_firewalls` | `id` or `name`; authoritative `rules`, `labels`, `force`, `state` |
| `hetzner_cloud_networks` | `id` or `name`; `ip_range`, `labels`, `delete_protection`, `state` |
| `hetzner_cloud_subnetworks` | `network`, `ip_range`, `type`, `network_zone`, optional `vswitch_id`, `state` |
| `hetzner_cloud_primary_ips` | `id` or `name`; IPv4 location/assignment, adoption, protection, labels, `state` |
| `hetzner_cloud_floating_ips` | `id` or `name`; IPv4 home/assignment, adoption, protection, labels, `state` |
| `hetzner_cloud_placement_groups` | `id` or `name`; `type: spread`, `labels`, `state` |
| `hetzner_cloud_servers` | `id` or `name`; type, image, location, keys, firewalls, Networks, labels, lifecycle |
| `hetzner_cloud_server_networks` | `server`, `network`, exact `ip`, `alias_ips`, optional `expected_ip`, `state` |
| `hetzner_cloud_firewall_resources` | `firewall`, and one or both of `servers` and `label_selectors`, `state` |
| `hetzner_cloud_reverse_dns` | One owner, `ip_address`, present-state `dns_ptr`, `state` |

All lists default to empty. Labels are arbitrary non-secret Hetzner labels. Do not place credentials, user data, or
other secret material in labels because labels are exposed by the API and dynamic inventory.

### SSH keys

Use `public_key` to create a named key. It is public material, but the private key must remain in an external secret
or SSH-agent workflow. `force: true` allows the official module to recreate a key whose public material differs;
review the effect on server bootstrap before enabling it. Servers refer to existing key names or IDs through their
`ssh_keys` list.

### Firewalls

`hetzner_cloud_firewalls[].rules` is the complete rule set sent to the official firewall module. Each rule contains:

- `direction`: `in` or `out`.
- `protocol`: `icmp`, `tcp`, `udp`, `esp`, or `gre`.
- `port`: required by this role for TCP and UDP rules.
- `source_ips`: IPv4 CIDRs for inbound rules.
- `destination_ips`: IPv4 CIDRs for outbound rules.
- `description`: an optional operator-facing purpose.

Hetzner Cloud firewalls are allowlists. When inbound rules are present and the firewall is attached to a server,
inbound traffic that matches no rule is dropped; an explicit catch-all deny rule is neither needed nor emitted.
The generated profile controls inbound traffic only and does not add an outbound restriction.

`hetzner_cloud_default_firewall` can append a generated secure IPv4 ingress firewall to the explicit firewall list:

| Field | Default | Behavior |
|---|---|---|
| `enabled` | `false` | Create/reconcile the generated firewall when true |
| `name` | `default-ipv4` | Firewall name |
| `labels` | `{}` | Non-secret labels |
| `ssh_source_ips` | `[]` | Trusted IPv4 CIDRs for TCP/22; no SSH rule when empty |
| `wireguard_source_ips` | `0.0.0.0/0` | Allowed IPv4 CIDRs for UDP/51820; no rule when empty |
| `allow_icmp` | `true` | Permit inbound IPv4 ICMP from `0.0.0.0/0` |

The generated firewall has no effect until it is attached. Supply its name in a server's `firewalls` list or manage
an incremental attachment with `hetzner_cloud_firewall_resources`. The `mgmt01` example uses the server's
authoritative `firewalls` list. Hetzner Cloud firewalls do not filter private Network traffic; enforce any required
east-west policy in the guest or with an architecture designed for private-network filtering.

### Networks and exact private addresses

A Network item manages the top-level private range. A subnetwork item manages a `server`, `cloud`, or `vswitch`
subnet inside it. A `vswitch` subnet also needs `vswitch_id`.

Do not put a Network in `hetzner_cloud_servers[].private_networks` when an exact initial address is required. That
server field lets Hetzner select an address during creation. Instead, declare the exact relationship separately:

```yaml
hetzner_cloud_server_networks:
  - server: mgmt01
    network: management
    ip: 172.16.10.4
    expected_ip: 172.16.10.4
```

The official `server_network` module uses `ip` only while initially attaching. It cannot change the primary private
address on an already attached Network. The role asserts `expected_ip` after reconciliation and fails rather than
silently accepting a different address. Changing an existing primary private address requires a separately planned,
explicitly destructive detach/reattach migration with an outage and dependency review.

### Primary and Floating IPv4 adoption

Hetzner allocates new addresses; callers cannot request an arbitrary public IPv4 during creation. Use the following
contract to protect a known address:

```yaml
hetzner_cloud_primary_ips:
  - name: mgmt01-primary-ipv4
    type: ipv4
    prevent_create: true
    expected_ip: 167.233.121.91
```

`prevent_create: true` triggers an official info-module preflight. Exactly one resource matching the supplied name
or ID must already exist, and its address must equal `expected_ip`. The role fails before the mutating module when
the resource is absent or mismatched. After reconciliation it checks the address again.

Use the same fields for a known Floating IPv4 address. If `prevent_create` is false and no matching resource exists,
the official module may allocate a new address. Supplying `expected_ip` without `prevent_create` then checks the
allocated address after creation, but it cannot make Hetzner allocate that value. For fixed production addresses,
always combine `prevent_create: true` and `expected_ip`.

`auto_delete: false` is recommended for a Primary IP that must survive server replacement. Provider-side
`delete_protection` is independent of this role's destructive gate and should be enabled for protected resources.

Assigning a Floating IP to a server through the API does not necessarily add it to the guest interface. See
[Guest Floating IP detection](#guest-floating-ip-detection) before putting the address into service.

### Servers and reverse DNS

Important server fields include `server_type`, `image`, `location`, `ssh_keys`, `firewalls`, `ipv4`,
`placement_group`, `backups`, `user_data`, `labels`, and the paired `delete_protection` and `rebuild_protection`
flags. The role forces IPv6 off regardless of an omitted item value. `user_data` is marked sensitive and API tasks
are not logged.

Each reverse-DNS item selects exactly one owning resource with `server`, `primary_ip`, or `floating_ip`, plus the
owned IPv4 in `ip_address`. Present state requires `dns_ptr`; absent state resets the provider default. This role
manages PTR records only. Forward DNS must be managed through the authoritative DNS provider in a separate role or
collection.

### Dependency-safe lifecycle

Present resources are reconciled in dependency order:

1. SSH keys and firewalls.
2. Placement groups, Networks, and subnetworks.
3. Primary IPs and servers.
4. Exact server-Network and firewall relationships.
5. Floating IP assignments and reverse DNS.

Absent resources are processed in reverse dependency order: reverse DNS, Floating IPs, relationships, servers,
Primary IPs, firewalls, subnetworks, Networks, placement groups, and SSH keys. The role only removes items declared
with an effective absent state; it does not enumerate and purge undeclared project resources.

Any global `hetzner_cloud_state: absent` or item-level `state: absent` fails validation unless
`hetzner_cloud_allow_destructive: true`. This role gate does not bypass Hetzner delete protection. Disable protection
as a reviewed lifecycle action before deletion when necessary. Floating IP deletion uses the official module's
forced detach only after the role's destructive gate has passed.

### Check mode and validation-only mode

`hetzner_cloud_validate_only: true` performs local schema and policy checks without requiring a token or making API
calls. It publishes `hetzner_cloud_plan` and a validation result with resource counts. Use it in untrusted pull
request checks and for fast input validation.

Normal `--check` mode is passed through to the official modules. It still needs an API token and network access
because adoption and current-state discovery perform reads. It also retains the destructive authorization gate.
An end-to-end check against an empty project can be limited by dependencies that do not yet exist in the API—for
example, a dry-run server cannot attach to a dry-run-only Network. Validate the complete declaration with
`hetzner_cloud_validate_only`, and use `--check` against an environment whose dependencies already exist.

### Outputs

The role publishes two non-cacheable facts:

- `hetzner_cloud_plan`: secret-free global policy, generated firewall rules, and declared resource counts.
- `hetzner_cloud_result`: `changed`, `validated`, and sanitized per-resource module results.

Validation-only mode returns counts under `hetzner_cloud_result.resources`. API mode returns lists for SSH keys,
firewalls, placement groups, Networks, subnetworks, Primary IPs, servers, server Networks, firewall relationships,
Floating IPs, and reverse DNS. Do not persist complete result facts to logs without applying your own data
classification; infrastructure identifiers and addresses may be operationally sensitive even though tokens and
generated passwords are removed.

### Secret resolution and injection

The role's token input is intentionally provider-neutral. Prefer a dedicated controller play that resolves one
request and passes only the normalized value:

```yaml
- name: Resolve and use a Hetzner Cloud token
  hosts: localhost
  gather_facts: false
  roles:
    - role: lit.foundational.secret_resolver
      vars:
        secret_resolver_provider: environment
        secret_resolver_requests:
          - name: hetzner_cloud_api_token
            environment:
              variable: HCLOUD_TOKEN
    - role: lit.foundational.hetzner_cloud
      vars:
        hetzner_cloud_api_token: "{{ secret_resolver_result.hetzner_cloud_api_token }}"
```

Change the resolver provider and request block without changing the infrastructure role:

| Source | Resolver configuration |
|---|---|
| HashiCorp Vault/HCP Vault | Provider `hashicorp_vault`; request path/key in `hashicorp_vault`; inject Vault auth |
| Ansible Vault | Provider `ansible_vault`; request `variable` names an already-decrypted inventory variable |
| 1Password | Provider `onepassword`; request `item`, `field`, and optional `vault`, `account`, `section` |
| Environment | Provider `environment`; request `variable: HCLOUD_TOKEN` |
| Semaphore/AAP | Inject a masked environment value, or use provider `runtime` with a credential-backed variable |
| GitHub Actions | Map `${{ secrets.HCLOUD_TOKEN }}` to the job environment and use provider `environment` |

For example, a Vault KV version 2 request is:

```yaml
secret_resolver_provider: hashicorp_vault
secret_resolver_vault_addr: https://vault.example.invalid
secret_resolver_requests:
  - name: hetzner_cloud_api_token
    hashicorp_vault:
      path: infrastructure/hetzner-cloud
      key: api_token
      mount_point: secret
```

An Ansible Vault file instead defines an encrypted `vault_hetzner_cloud_api_token` and uses:

```yaml
secret_resolver_provider: ansible_vault
secret_resolver_requests:
  - name: hetzner_cloud_api_token
    ansible_vault:
      variable: vault_hetzner_cloud_api_token
```

For 1Password, authenticate the controller-side `op` CLI or inject a service-account token before execution:

```yaml
secret_resolver_provider: onepassword
secret_resolver_requests:
  - name: hetzner_cloud_api_token
    onepassword:
      item: Hetzner Cloud
      field: api_token
      vault: Infrastructure
```

An AAP custom credential or Semaphore environment can inject `HCLOUD_TOKEN` without placing it in job-template
source. Alternatively, inject a protected runtime variable such as `hetzner_cloud_api_token_input` and select the
resolver's `runtime` provider. GitHub Actions should pass the secret as a masked job environment entry:

```yaml
env:
  HCLOUD_TOKEN: "${{ secrets.HCLOUD_TOKEN }}"
```

Never put a token in inventory committed to source control, command-line extra variables, labels, artifacts, or
dynamic-inventory files. Secret resolver fallback is disabled by default; if a bootstrap fallback is deliberately
enabled, restrict it to ordinary missing-secret categories so an authentication, authorization, TLS, or Vault
availability failure remains fail-closed.

### Dynamic inventory

Dynamic inventory is supplied by the official `hetzner.hcloud.hcloud` plugin, not implemented by this role. Its
source filename must end in `hcloud.yml` or `hcloud.yaml`. The repository example is
`examples/hetzner_cloud/mgmt01.hcloud.yml` and uses the server's non-secret `fqdn` label as both the inventory
hostname and composed `fqdn` host variable:

```yaml
---
plugin: hetzner.hcloud.hcloud
label_selector: managed_by=lit-foundational,fqdn
connect_with: public_ipv4
hostname: "{{ hcloud_labels.fqdn | default(hcloud_name, true) }}"
compose:
  fqdn: hcloud_labels.fqdn
strict: true
```

Inventory is built before any play runs, so `secret_resolver` cannot provide the token to that inventory source in
the same `ansible-playbook` invocation. Inject `HCLOUD_TOKEN` into the inventory process through the shell runner,
GitHub Actions secret, Semaphore environment, or an AAP inventory-source credential. Verify the source with:

```console
ansible-inventory -i examples/hetzner_cloud/mgmt01.hcloud.yml --graph
ansible-inventory -i examples/hetzner_cloud/mgmt01.hcloud.yml --host mgmt01.prd.edge.pub.l-it.io
```

### Guest Floating IP detection

Provider assignment and guest configuration are separate responsibilities. Invoke the read-only entrypoint against
the guest after an optional Floating IP has been assigned:

```yaml
- name: Inspect Floating IPv4 configuration
  hosts: mgmt01.prd.edge.pub.l-it.io
  gather_facts: false
  become: true
  tasks:
    - name: Detect Floating IPv4 state
      ansible.builtin.include_role:
        name: lit.foundational.hetzner_cloud
        tasks_from: guest_floating_ip
      vars:
        hetzner_cloud_guest_floating_ips:
          - name: mgmt01-floating-ipv4
            address: 116.203.2.108
        hetzner_cloud_guest_require_persistent: true
```

The entrypoint runs `ip -j -4 address show`, searches configured directories for persistent network files, and
publishes `hetzner_cloud_guest_floating_ip_status`. Each named address reports:

- `runtime_configured`: the address is currently present on an interface.
- `persistent_config_detected`: a searched file contains the exact address as a delimited token.
- `manual_configuration_required`: runtime state is absent, or persistence is required but was not detected.

Default persistent paths cover Netplan, ifupdown, and NetworkManager. Override paths and filename patterns for a
different guest network stack. Detection is evidence, not a parser for every network manager. This role never runs
`ip addr add`, writes Netplan, edits NetworkManager profiles, or restarts networking. A guest-OS networking role is
responsible for adding the Floating IP persistently, applying it safely, and handling rollback.

### Limitations and operational boundaries

- IPv6, volumes, routes, load balancers, certificates, and DNS zones are outside this role's resource interface.
- `enable_ipv6: false` governs server creation; the official server module does not remove an IPv6 Primary IP from
  an existing server. Adopt only already IPv4-only servers or use a separately reviewed replacement workflow.
- Server `user_data`, SSH key selection, Primary IP selection, and exact Network attachment have creation-time or
  provider-specific constraints; changing declarations does not imply that every field is mutable in place.
- A Primary IP or Floating IP cannot be created with a caller-selected address. Adopt a pre-existing fixed address
  with `prevent_create` and `expected_ip`.
- An attached server's primary private IPv4 cannot be changed in place by the official module. Plan a guarded
  detach/reattach migration and outage separately.
- Floating IP API assignment does not guarantee guest interface configuration. The guest entrypoint only detects
  state; persistent guest configuration remains the caller's responsibility.
- Reverse DNS here manages PTR records only; forward A records and DNSSEC belong to the authoritative DNS system.
- The role reconciles declared objects and relationships. It does not discover or delete undeclared resources.
- Dynamic inventory exposes API metadata to Ansible host variables. Keep labels non-secret and control inventory
  output, fact caching, and job artifacts according to infrastructure-data policy.
- Provider quotas, billing, image availability, server-type availability, and regional capacity remain Hetzner
  project and location concerns.

## Dependencies

The collection declares the exact official dependency in `galaxy.yml`:

```yaml
dependencies:
  hetzner.hcloud: 6.10.0
```

No role dependency is declared in `meta/main.yml`. `lit.foundational.secret_resolver` is an optional composition
pattern, not an implicit dependency: invoke it explicitly when required. The role neither installs controller
Python packages nor configures a guest operating system.

## Example Playbook

The complete reference deployment is
[`examples/hetzner_cloud/mgmt01.yml`](../../examples/hetzner_cloud/mgmt01.yml). It declares:

- `mgmt01` / `mgmt01.prd.edge.pub.l-it.io` on CPX22 in `fsn1`, using Ubuntu 24.04.
- The pre-existing Primary IPv4 `167.233.121.91`, adopted with `prevent_create` and `expected_ip`.
- Optional pre-existing Floating IPv4 `116.203.2.108`, also protected by the adoption contract.
- IPv6 disabled, the current exact private address `172.16.10.4`, and IPv4-only ingress policy.
- A `172.16.0.0/16` Network with a `172.16.10.0/24` server subnet, leaving `172.16.10.1` addressable later.
- FQDN labels, reverse DNS, SSH key, firewall, spread placement group, backup, and protection settings.

The server is intended to host the WireGuard VPN, SSH bastion, and management tooling, with optional Cloudflare
Tunnel, monitoring-agent, and backup-agent workloads. This infrastructure role provisions their cloud foundation;
installation and lifecycle of those guest services belong to separate guest-OS and application roles.

Supply `mgmt01_ssh_public_key` from inventory or another non-secret input and inject the API token externally. The
documentation-only `192.0.2.0/24` SSH source is reserved TEST-NET space; replace it with real trusted IPv4 CIDRs
before deployment. Enable the Floating IP only after the fixed address already exists under the declared name:

```console
ansible-playbook examples/hetzner_cloud/mgmt01.yml \
  -i examples/hetzner_cloud/mgmt01.hcloud.yml \
  -e @inventory/production/hetzner.yml
```

The initial deployment intentionally keeps `172.16.10.4`. It documents but does not execute migration to
`172.16.10.1`. Do not change the example's `ip` or `expected_ip` until the legacy gateway has been removed, a
maintenance window is approved, and a separate detach/reattach migration with rollback has been prepared.

A minimal generic declaration is:

```yaml
---
- name: Reconcile Hetzner Cloud resources
  hosts: localhost
  gather_facts: false
  roles:
    - role: lit.foundational.hetzner_cloud
      vars:
        hetzner_cloud_default_firewall:
          enabled: true
          name: bastion-ipv4
          ssh_source_ips:
            - 198.51.100.0/24
        hetzner_cloud_ssh_keys:
          - name: automation
            public_key: "{{ automation_ssh_public_key }}"
        hetzner_cloud_servers:
          - name: bastion01
            server_type: cpx22
            image: ubuntu-24.04
            location: fsn1
            ssh_keys:
              - automation
            firewalls:
              - bastion-ipv4
            enable_ipv6: false
```

To validate without credentials or API calls, add `hetzner_cloud_validate_only: true`. To delete declared
resources, set only the intended items to `state: absent`, set `hetzner_cloud_allow_destructive: true` for that
reviewed run, and retain reverse dependency order in the same declaration.

## License

MIT

## Author

Lightning IT
