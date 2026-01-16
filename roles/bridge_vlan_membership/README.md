# lit.foundational.bridge_vlan_membership

Ensures a linux bridge is VLAN-aware and that:
- the host stack is a member of VLANs on the bridge (`self`)
- the bridge ports accept the VLANs (`master`)
- optionally enables `vlan_filtering=1` runtime

## Example

```yaml
- name: Ensure bridge VLAN membership
  ansible.builtin.include_role:
    name: lit.foundational.bridge_vlan_membership
  vars:
    bridge_vlan_membership_bridge: br-trunk
    bridge_vlan_membership_ids: [191, 2501]
    bridge_vlan_membership_ports: [ens2f0, ens2f1]
```

---

## 3) Replace in your base playbook

This inline block:

- `ip link set … vlan_filtering 1`
- `bridge vlan add … self`
- `bridge vlan add … master`

replace with a **single** task:

```yaml
- name: Bridge VLAN membership (self + ports)
  ansible.builtin.include_role:
    name: lit.foundational.bridge_vlan_membership
  vars:
    bridge_vlan_membership_bridge: br-trunk
    bridge_vlan_membership_ids: [191, 2501]
    bridge_vlan_membership_ports: [ens2f0, ens2f1]
  tags: [network]
```
