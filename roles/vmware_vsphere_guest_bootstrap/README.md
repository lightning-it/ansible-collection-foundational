# vmware_vsphere_guest_bootstrap

## Requirements

Requires vSphere API access, VMware Tools running in the guest, and a valid
guest login such as the installer/root bootstrap credentials.

## Variables

See `defaults/main.yml`. Key inputs are:

- `vmware_vsphere_guest_bootstrap_vm_name`: VM or template name to repair.
- `vmware_vsphere_guest_bootstrap_guest_username` /
  `vmware_vsphere_guest_bootstrap_guest_password`: guest credentials used by
  VMware Tools operations. Defaults map from `linux_bootstrap_user` and
  `linux_bootstrap_password`.
- `vmware_vsphere_guest_bootstrap_users_accounts`: users and SSH keys to place
  in the guest. Defaults to the inventory `users_accounts` structure.
- `vmware_vsphere_guest_bootstrap_mark_as_template`: power off and mark the VM
  as a reusable vSphere template after bootstrap.

## Dependencies

Uses `community.vmware` modules.

## Example Playbook

```yaml
- hosts: vmware_templates
  connection: local
  gather_facts: false
  roles:
    - role: lit.foundational.vmware_vsphere_guest_bootstrap
```

## License

MIT

## Author

Lightning IT
