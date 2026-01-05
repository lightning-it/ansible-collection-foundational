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
        vmware_vsphere_network: "VM Network"
        vmware_vsphere_username: administrator@vsphere.local
        vmware_vsphere_password: "{{ lookup('env','VSPHERE_PASSWORD') }}"
        vmware_vsphere_vmware_guest_hardware:
          num_cpus: 8
          memory_mb: 32768
        vmware_vsphere_destroy: false
```

## Variables

- `vmware_vsphere_datacenter`, `vmware_vsphere_folder_name`, `vmware_vsphere_resource_pool`, `vmware_vsphere_vmware_guest_datastore`, `vmware_vsphere_vmware_iso_datastore`, `vmware_vsphere_network`: describe where the role should create resources.
- `vmware_vsphere_module_defaults_vmware_*` and `vmware_vsphere_vmware_guest_*` structures let you tune CPU, memory, disks, and ISO/CD-ROM settings for created guests.
- `vmware_vsphere_username`, `vmware_vsphere_password` can be supplied directly or pulled from Vault using `vmware_vsphere_vmware_username_lookup` / `vmware_vsphere_vmware_password_lookup`. These lookup vars default to empty strings (and are normalized in `tasks/assets.yaml`); set them to a valid Vault path to enable lookups. The role will fail early if neither direct values nor lookup paths are provided.
- Set `vmware_vsphere_destroy: true` to remove VMs/folders instead of creating them; additional tags (`create_vms`, `destroy_all`, etc.) gate individual task files.

### Required inputs

- `vmware_vsphere_datacenter`, `vmware_vsphere_folder_name`, `vmware_vsphere_vmware_guest_datastore`, `vmware_vsphere_vmware_iso_datastore`, `vmware_vsphere_network`
- Credentials via `vmware_vsphere_username` / `vmware_vsphere_password` **or** Vault lookup vars (`vmware_vsphere_vmware_username_lookup`, `vmware_vsphere_vmware_password_lookup`)

### Compatibility

- Tested with Ansible `>=2.15` and targeting EL9 runners.
