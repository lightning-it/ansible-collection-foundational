# lit.foundational.oob_redfish_control

Performs vendor-neutral Redfish actions using `community.general.redfish_command`:
- Power (on/off/reboot/...)
- Boot override (PXE/CD/...)
- Virtual media insert/eject

## Typical usage

```ini
[oob]
idrac01 ansible_host=10.0.0.10
ilo01   ansible_host=10.0.0.11

[oob:vars]
ansible_connection=local
ansible_python_interpreter=/usr/bin/python3
oob_user=admin
oob_password=secret
oob_validate_certs=false
```

Playbook examples:

### PXE boot once + reboot
```yaml
- hosts: oob
  gather_facts: false
  roles:
    - lit.foundational.oob_redfish_control
  vars:
    oob_boot_target: pxe
    oob_power_action: reboot
```

### Mount ISO via VirtualMedia (Systems) + boot from CD + reboot
```yaml
- hosts: oob
  gather_facts: false
  roles:
    - lit.foundational.oob_redfish_control
  vars:
    oob_virtual_media_action: insert
    oob_virtual_media_category: Systems
    oob_virtual_media_image_url: "http://files.example.local/rhel-9.4.iso"
    oob_boot_target: cd
    oob_power_action: reboot
```
