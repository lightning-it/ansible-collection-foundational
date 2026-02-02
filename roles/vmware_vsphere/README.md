# VMware vSphere Role

Creates or destroys vSphere folders and virtual machines required for agent-based OpenShift installs, pulling credentials from Vault when available.

## Usage

```yaml
- hosts: localhost
  gather_facts: false
  roles:
    - role: lit.foundational.vmware_vsphere
      vars:
        vmware_vsphere_datacenter: DC1
        vmware_vsphere_folder_name: OpenShift/demo
        vmware_vsphere_vmware_guest_datastore: vsanDatastore
        vmware_vsphere_vmware_iso_datastore: iso-store
        vmware_vsphere_vmware_guest_networks:
          - name: "VM Network"
            ip: 192.0.2.10
            netmask: 255.255.255.0
            gateway: 192.0.2.1
        vmware_vsphere_username: administrator@vsphere.local
        vmware_vsphere_password: "{{ lookup('env','VSPHERE_PASSWORD') }}"
        vmware_vsphere_vmware_guest_hardware:
          num_cpus: 8
          memory_mb: 32768
        vmware_vsphere_vmware_guest_customization:
          hostname: demo01
          domain: example.com
          dns_servers: [1.1.1.1]
        vmware_vsphere_destroy: false
        vmware_vsphere_destroy_folder: false
```

## Variables

- `vmware_vsphere_datacenter`, `vmware_vsphere_folder_name`, `vmware_vsphere_resource_pool`, `vmware_vsphere_vmware_guest_datastore`, `vmware_vsphere_vmware_iso_datastore`, `vmware_vsphere_network`: describe where the role should create resources.
- `vmware_vsphere_module_defaults_vmware_*` and `vmware_vsphere_vmware_guest_*` structures let you tune CPU, memory, disks, and ISO/CD-ROM settings for created guests.
- `vmware_vsphere_vmware_guest_customization` (alias: `vmware_vsphere_customization`) and `vmware_vsphere_vmware_guest_customization_spec` (alias: `vmware_vsphere_customization_spec`) pass guest customization to vCenter for IP/DNS/hostname configuration.
- If `nic_setting_map` is present in the customization block, the role maps it onto `vmware_vsphere_vmware_guest_networks` and removes it before calling `vmware_guest` (module does not accept `nic_setting_map`).
- `vmware_vsphere_username`, `vmware_vsphere_password` can be supplied directly or pulled from Vault using `vmware_vsphere_vmware_username_lookup` / `vmware_vsphere_vmware_password_lookup`. These lookup vars default to empty strings (and are normalized in `tasks/assets.yaml`); set them to a valid Vault path to enable lookups. The role will fail early if neither direct values nor lookup paths are provided.
- Set `vmware_vsphere_destroy: true` to remove VMs instead of creating them. Folder deletion is skipped by default for safety; set `vmware_vsphere_destroy_folder: true` if you want the folder removed once it is empty. Additional tags (`create_vms`, `destroy_all`, etc.) gate individual task files.

### Required inputs

- `vmware_vsphere_datacenter`, `vmware_vsphere_folder_name`, `vmware_vsphere_vmware_guest_datastore`, `vmware_vsphere_vmware_iso_datastore`, `vmware_vsphere_network`
- Credentials via `vmware_vsphere_username` / `vmware_vsphere_password` **or** Vault lookup vars (`vmware_vsphere_vmware_username_lookup`, `vmware_vsphere_vmware_password_lookup`)

### Compatibility

- Tested with Ansible `>=2.15` and targeting EL9 runners.
- Guest customization requires VMware Tools/open-vm-tools in the template.
