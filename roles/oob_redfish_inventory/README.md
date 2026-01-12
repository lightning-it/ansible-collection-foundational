# lit.foundational.oob_redfish_inventory

Discover Redfish resource IDs (System/Manager/Chassis) using `community.general.redfish_info`.

## Typical usage

Inventory hosts = BMC endpoints (iDRAC/iLO/XCC/etc.):

```ini
[oob]
10.0.0.10
10.0.0.11

[oob:vars]
ansible_connection=local
ansible_python_interpreter=/usr/bin/python3
oob_user=admin
oob_password=secret
oob_validate_certs=false
```

Playbook:

```yaml
- hosts: oob
  gather_facts: false
  roles:
    - lit.foundational.oob_redfish_inventory
```

Outputs facts:
- `oob_system_id`, `oob_manager_id`, `oob_chassis_id`
- `oob_redfish` summary dict
