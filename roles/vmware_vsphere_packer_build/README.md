# VMware vSphere Packer Build Role

Builds a VMware vSphere source image with HashiCorp Packer from inventory-driven
values, then leaves clone and template normalization to the existing vSphere
runbooks.

## Requirements

- HashiCorp Packer must be installed on the delegated execution host.
- The delegated execution host must be able to read the Packer project directory.
- The Packer workspace should be a checkout of the vSphere image build repository, for example `packer-vsphere-template-sources`.

## Variables

- `vmware_vsphere_packer_build_project_dir`: path to the Packer workspace, for example `/runner/project/packer-vsphere-template-sources`.
- `vmware_vsphere_packer_build_kind`: `rhel` or `ubuntu`.
- `vmware_vsphere_packer_build_source_vm_name`: source object name to build, for example `rhel-8-minimal`.
- `vmware_vsphere_packer_build_rhel_major`: required when `vmware_vsphere_packer_build_kind` is `rhel`.
- `vmware_vsphere_packer_build_ubuntu_release`: required when `vmware_vsphere_packer_build_kind` is `ubuntu`.
- `vmware_vsphere_packer_build_installer_username`: temporary installer account used by Packer SSH.
- `vmware_vsphere_packer_build_installer_password`: temporary installer password used by Packer SSH.
- `vmware_vsphere_packer_build_installer_password_hash`: optional Ubuntu autoinstall password hash.
- `vmware_vsphere_packer_build_network`: optional explicit port group name. When omitted, the role tries to derive it from `vmware_vsphere_network`.
- `vmware_vsphere_packer_build_datastore`: optional override for the datastore. When omitted, the role falls back to `vmware_vsphere_vmware_guest_datastore`.
- `vmware_vsphere_packer_build_folder`: optional override for the folder. When omitted, the role falls back to `vmware_vsphere_folder_name`.
- `vmware_vsphere_packer_build_vars`: optional dictionary of extra or overriding Packer variables such as ISO paths, checksums, firmware, CPU, memory, and timeouts.
- `vmware_vsphere_packer_build_environment`: optional environment overrides for the Packer commands.
- `vmware_vsphere_packer_build_delegate_to`: host that runs local Packer commands.

The role also reuses the normal vSphere inventory values:

- `vmware_vsphere_hostname`
- `vmware_vsphere_username`
- `vmware_vsphere_password`
- `vmware_vsphere_validate_certs`
- `vmware_vsphere_datacenter`
- `vmware_vsphere_vmware_guest_cluster`
- `vmware_vsphere_resource_pool`
- `vmware_vsphere_vmware_guest_datastore`
- `vmware_vsphere_folder_name`
- `vmware_vsphere_network`

`vmware_vsphere_network` may be a plain port group name or a list whose first
item has a `name` key.

## Behavior

The role:

1. Validates the inventory and the Packer workspace.
2. Renders a temporary `.pkrvars.json` file from inventory values.
3. Runs `packer init`, `packer validate`, and `packer build`.
4. Removes the temporary variable file.

It does not clone the final template target or run VMware Tools guest bootstrap. Keep using `lit.foundational.vmware_vsphere` and `lit.foundational.vmware_vsphere_guest_bootstrap` for those later lifecycle steps.

## Example Playbook

```yaml
---
- name: Build a RHEL 8 source image on vSphere
  hosts: all
  connection: local
  gather_facts: false
  roles:
    - role: lit.foundational.vmware_vsphere_packer_build
      vars:
        vmware_vsphere_packer_build_project_dir: /runner/project/packer-vsphere-template-sources
        vmware_vsphere_packer_build_kind: rhel
        vmware_vsphere_packer_build_source_vm_name: rhel-8-minimal
        vmware_vsphere_packer_build_rhel_major: "8"
        vmware_vsphere_packer_build_installer_password: "{{ common_password_install }}"
        vmware_vsphere_packer_build_vars:
          rhel8_iso_path: "[datastore1] iso/rhel-8.10-x86_64-dvd.iso"
          rhel8_iso_checksum: "sha256:REPLACE-ME"
```

The final template host can then use `vmware_vsphere_template: rhel-8-minimal`
and `vmware_vsphere_vm_name: template-rhel-8-minimal` with the existing vSphere
clone and bootstrap runbooks.

## License

MIT

## Author

Lightning IT
