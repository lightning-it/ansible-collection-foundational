# lit.foundational.net_vlan_autogen

Generate VLAN trunk subinterfaces and NetworkManager `network_connections` data from a simple VLAN object list.

## What this role does

This role **only sets facts**:

- `network_connections` (for `fedora.linux_system_roles.network`)
- `net_lan_ifaces` (e.g., for firewall zone binding)

It does **not** apply network configuration itself.

## Inputs

Required when `net_vlan_autogen_vlan_configs` is non-empty:

- `net_wan_iface`
- `net_admin_iface`
- `net_trunk_parent`
- `net_admin_ip_cidr`
- `net_admin_gateway4`
- `net_vlan_autogen_vlan_configs` (list of `{id, ip_cidr}`)

Optional:

- `net_vlan_autogen_admin_dns` (list)
- `net_vlan_autogen_wan_dhcp4` (bool, default true)
- `net_vlan_autogen_wan_ip_cidr` (string, required when DHCP is disabled)
- `net_vlan_autogen_wan_gateway4` (string, optional gateway when DHCP is disabled)
- `net_vlan_autogen_wan_dns` (list, optional DNS when DHCP is disabled)
- `net_vlan_autogen_overwrite` (bool, default false)
- `net_vlan_autogen_wan_connection_name` (default `wan`)
- `net_vlan_autogen_admin_connection_name` (default `admin`)
- `net_vlan_autogen_trunk_connection_name` (default `trunk-parent`)
- `net_vlan_autogen_vlan_state` (up|present, default derived from trunk parent state)

Notes:

- VLAN subinterfaces reference the trunk **connection name** (not just the device, e.g., `trunk-parent`) so `fedora.linux_system_roles.network` can resolve the parent profile.
- VLANs default to `present` when the trunk parent is `present` to avoid activation errors; set the trunk parent state to `up` (or override `net_vlan_autogen_vlan_state`) to activate VLANs.

Example `net_vlan_autogen_vlan_configs`:

```yaml
net_vlan_autogen_vlan_configs:
  - id: 4051
    ip_cidr: "10.10.51.1/24"
  - id: 4052
    ip_cidr: "10.10.52.1/24"
