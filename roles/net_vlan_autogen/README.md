# lit.foundational.net_vlan_autogen

Generate VLAN trunk subinterfaces and NetworkManager `network_connections` data
from a simple `net_ifaces` list. This role only sets facts and does not apply
network configuration itself.

## Usage

```yaml
- name: Build network connection facts
  hosts: all
  gather_facts: false

  roles:
    - role: lit.foundational.net_vlan_autogen
      vars:
        net_ifaces:
          - role: uplink
            iface: ens33
            dhcp4: true
          - role: mgmt
            iface: ens34
            ipv4: 10.10.30.1/24
            gw4: 10.10.30.254
            dns:
              - 1.1.1.1
          - role: trunk
            iface: ens36
            vlans:
              - id: 171
                ipv4: 10.10.10.1/24
              - id: 172
                ipv4: 10.10.11.1/24
```

## Inputs

- `net_ifaces` (list, required): input interface model. Allowed roles are
  `uplink`, `mgmt`, and `trunk` (each at most once). Example structure:

  ```yaml
  net_ifaces:
    - role: uplink
      iface: ens33
      dhcp4: true
      ipv4: 192.0.2.10/24   # optional if dhcp4: true
      gw4: 192.0.2.1        # optional
      dns: [1.1.1.1]        # optional
    - role: mgmt
      iface: ens34
      ipv4: 10.10.30.1/24
      gw4: 10.10.30.254     # optional
      dns: [1.1.1.1]        # optional
    - role: trunk
      iface: ens36
      vlans:
        - id: 171
          ipv4: 10.10.10.1/24
  ```

## Variables

- `net_vlan_autogen_enabled` (bool, default: `true`): enable/disable generation.
- `net_vlan_autogen_overwrite` (bool, default: `false`): overwrite existing
  `network_connections` facts when already defined.
- `net_vlan_autogen_wan_connection_name` (string, default: `"wan"`): name for
  the uplink connection.
- `net_vlan_autogen_admin_connection_name` (string, default: `"admin"`): name
  for the management connection.
- `net_vlan_autogen_trunk_connection_name` (string, default: `"trunk-parent"`):
  name for the trunk parent connection (VLANs refer to this).
- `net_vlan_autogen_trunk_parent_state` (string, default: `"present"`): state
  for the trunk parent connection (`present` or `up`).
- `net_trunk_parent_state` (string, optional): override trunk parent state for
  this role without changing defaults.

## Outputs

- `network_connections`: list of NetworkManager connection profiles for
  `fedora.linux_system_roles.network`.
- `net_lan_ifaces`: VLAN subinterface names (for example, firewall zones).

## Notes

- VLAN subinterfaces reference the trunk connection **name** so that
  `fedora.linux_system_roles.network` can resolve the parent profile.
- VLANs default to `present` when the trunk parent is `present` to avoid
  activation errors. Set the trunk parent state to `up` (or override
  `net_trunk_parent_state`) to activate VLANs.
