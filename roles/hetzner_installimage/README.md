# hetzner_installimage

Plans and, only after explicit immutable-plan approval, executes Hetzner Rescue
  `installimage` installations. The role resolves disks by serial number, verifies
the complete hardware and network identity, and never reboots the host.

## Requirements

- The managed host is running the Hetzner Rescue environment.
- `installimage`, its functions source, and the selected operating-system image
  are locally available on the Rescue host.
- Every physical disk has a stable, unique serial number.
- Encrypted layouts require an externally persisted recovery password. This role
  does not generate passwords or contact a secret backend.
- Run the role as root. Ansible check mode never invokes `installimage`.

The role intentionally has two phases. Run `plan` first and review its disk
selection, preserved disks, image checksum, post-install script checksum, and
SHA-256. A later `install` run must provide the exact prior SHA-256 and generated
confirmation phrase. Any relevant host, disk, image, script, or layout change
invalidates the approval.

## Variables

See `defaults/main.yml` for every input. Key variables are:

- `hetzner_installimage_action`: `plan` by default; `install` is destructive.
- `hetzner_installimage_expected_identity`: expected public IPv4 address,
  gateway, prefix length, primary MAC address, and firmware boot mode.
- `hetzner_installimage_expected_disks`: the complete physical-disk inventory.
  Use `purpose: system` for disks that may be erased and `purpose: preserve` for
  disks that must never become `DRIVE` entries. Device paths are discovered from
  serial numbers and are not inventory inputs.
- `hetzner_installimage_layout`: software RAID, partitions, and logical volumes
  rendered into the installimage configuration.
- `hetzner_installimage_post_install_script_path`: optional root-owned executable
  passed to installimage as `-x`. Its path and checksum are part of the plan.
- `hetzner_installimage_take_over_rescue_ssh_public_keys`: enabled by default.
  It requires a nonempty root-owned `/root/.ssh/robot_user_keys`, renders
  `TAKE_OVER_RESCUE_SYSTEM_SSH_PUBLIC_KEYS yes`, and includes the key-file
  checksum in the approval plan so first-boot SSH access is explicit.
- `hetzner_installimage_crypt_password`: recovery password resolved by the
  caller. It is written only to a mode `0600` temporary configuration, protected
  with `no_log`, and excluded from the plan hash. A versioned, checksummed
  `/post-mount` hook replaces its value with `[REDACTED]` before installimage
  saves `/installimage.conf`. Because upstream installimage ignores hook failures,
  the role requires a root-owned versioned success marker after exactly one
  password line is redacted. Newly created `/autosetup*`, `/post-install`,
  `/post-mount`, and marker artifacts are removed in an `always` block.
- `hetzner_installimage_allow_destructive`,
  `hetzner_installimage_approved_plan_sha256`, and
  `hetzner_installimage_confirmation`: all are required for `install`.

The published `hetzner_installimage_plan.required_confirmation` has this form:

```text
ERASE:<hostname>:<plan-sha256>
```

The plan is secret-free. The role publishes `hetzner_installimage_result` after
planning or installation. `reboot_performed` is always false; a successful
install does not mean the encrypted-root or network bootstrap is ready.

## Dependencies

None. The role uses Ansible built-ins and commands already present in Hetzner
Rescue.

## Example Playbook

Safe planning example:

```yaml
---
- name: Plan a Hetzner Rescue installation
  hosts: rescue_hosts
  gather_facts: false
  roles:
    - role: lit.foundational.hetzner_installimage
      vars:
        hetzner_installimage_action: plan
        hetzner_installimage_expected_identity:
          public_ipv4: 192.0.2.10
          gateway_ipv4: 192.0.2.1
          prefix_length: 24
          primary_mac: "02:00:00:00:00:10"
          boot_mode: bios
          system_uuid: ""
        hetzner_installimage_expected_disks:
          - serial: EXAMPLE-SYSTEM-A
            model: Example SSD
            size_bytes: 256060514304
            rotational: false
            purpose: system
          - serial: EXAMPLE-SYSTEM-B
            model: Example SSD
            size_bytes: 256060514304
            rotational: false
            purpose: system
        hetzner_installimage_layout:
          force_gpt: true
          bootloader: grub
          ipv4_only: true
          software_raid:
            enabled: true
            level: 1
          partitions:
            - mountpoint: /boot
              filesystem: ext4
              size: 2G
              crypt: false
            - mountpoint: lvm
              filesystem: vg0
              size: all
              crypt: true
          logical_volumes:
            - volume_group: vg0
              name: root
              mountpoint: /
              filesystem: ext4
              size: 64G
            - volume_group: vg0
              name: swap
              mountpoint: swap
              filesystem: swap
              size: 8G
```

Do not hardcode `hetzner_installimage_crypt_password` in a playbook. Resolve it
from the environment's declared secret backend immediately before an approved
install run.

## License

MIT

## Author

Lightning IT
