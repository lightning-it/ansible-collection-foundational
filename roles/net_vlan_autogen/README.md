# lit.foundational.net_vlan_autogen

Generate VLAN trunk subinterfaces and NetworkManager `network_connections` data from a simple VLAN object list.

## What this role does

This role **only sets facts**:

- `network_connections` (for `fedora.linux_system_roles.network`)
- `net_lan_ifaces` (e.g., for firewall zone binding)

It does **not** apply network configuration itself.

## Inputs

Required when `net_vlan_configs` is non-empty:

- `net_wan_iface`
- `net_admin_iface`
- `net_trunk_parent`
- `net_admin_ip_cidr`
- `net_admin_gateway4`
- `net_vlan_configs` (list of `{id, ip_cidr}`)

Optional:

- `net_admin_dns` (list)
- `net_wan_dhcp4` (bool, default true)
- `net_autogen_overwrite` (bool, default false)

Example `net_vlan_configs`:

```yaml
net_vlan_configs:
  - id: 4051
    ip_cidr: "10.10.51.1/24"
  - id: 4052
    ip_cidr: "10.10.52.1/24"
