# VMware vSphere Role

Creates or destroys vSphere folders and virtual machines required for agent-based OpenShift installs, pulling credentials from Vault when available.

## Usage

```yaml
- hosts: localhost
  gather_facts: false
  roles:
    - role: lit.foundation_services.vmware_vsphere
      vars:
        vvs_datacenter: DC1
        vvs_folder_name: OpenShift/demo
        vvs_vmware_guest_datastore: vsanDatastore
        vvs_vmware_iso_datastore: iso-store
        vvs_network: "VM Network"
        vvs_username: administrator@vsphere.local
        vvs_password: "{{ lookup('env','VSPHERE_PASSWORD') }}"
        vvs_vmware_guest_hardware:
          num_cpus: 8
          memory_mb: 32768
        vvs_destroy: false
```

## Variables

- `vvs_datacenter`, `vvs_folder_name`, `vvs_resource_pool`, `vvs_vmware_guest_datastore`, `vvs_vmware_iso_datastore`, `vvs_network`: describe where the role should create resources.
- `vvs_module_defaults_vmware_*` and `vvs_vmware_guest_*` structures let you tune CPU, memory, disks, and ISO/CD-ROM settings for created guests.
- `vvs_username`, `vvs_password` can be supplied directly or pulled from Vault using `vvs_vmware_username_lookup` / `vvs_vmware_password_lookup`.
- Set `vvs_destroy: true` to remove VMs/folders instead of creating them; additional tags (`create_vms`, `destroy_all`, etc.) gate individual task files.
