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
- `vmware_vsphere_guest_bootstrap_guest_become`: run the bootstrap script with
  `sudo` from the guest user. Use this for templates where root guest
  operations are no longer available but a sudo-capable bootstrap user exists.
- `vmware_vsphere_guest_bootstrap_users_accounts`: users and SSH keys to place
  in the guest. Defaults to the inventory `users_accounts` plus
  `users_accounts_extra` structures.
- User entries with `passwordless_sudo: true` receive a validated
  `/etc/sudoers.d/<sudoers_name|name>` file with `NOPASSWD:ALL`. On Ubuntu and
  Debian guests, inventory group `wheel` is mapped to the local `sudo` group.
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
