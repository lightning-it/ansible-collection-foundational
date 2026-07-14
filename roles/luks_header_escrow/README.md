# lit.foundational.luks_header_escrow

Persist the sole installed LUKS2 header declared by `crypttab` as an immutable,
controller-side Ansible Vault document. Raw header bytes exist only in a
protected temporary directory on the managed host and protected Ansible memory;
they are never written as controller plaintext.

## Requirements

- A Linux managed host with exactly one active `crypttab` source.
- `cryptsetup`, `findfs`, `readlink`, `id`, `awk`, and Bash at the declared absolute paths.
- Privilege to read and back up the installed LUKS2 header.
- An Ansible Vault identity already loaded by the controller. Select its label
  with `luks_header_escrow_vault_id`; the role never accepts password material.
- An existing, non-symlinked `0700` escrow root owned by the effective
  controller user, with the normalized absolute escrow path below it.
- Durable controller storage. In AAP, mount the escrow root into the execution
  environment from persistent, separately backed-up storage; job-local project
  and container filesystems are ephemeral and are not valid escrow targets.

The enabled role intentionally refuses check mode. Callers should also enforce
their own fleet-selection, operating-system, lifecycle-phase, and confirmation
policy before invoking it.

## Variables

See `defaults/main.yml` for the complete interface. Important inputs are:

- `luks_header_escrow_enabled`: explicit opt-in; defaults to `false`.
- `luks_header_escrow_path`: absolute controller ciphertext path.
- `luks_header_escrow_controller_root_path`: allowed canonical controller root.
- `luks_header_escrow_vault_id`: loaded Ansible Vault identity label used when
  creating an absent ciphertext document; it may contain only ASCII letters,
  digits, dots, underscores, and hyphens, and defaults to `default`.
- `luks_header_escrow_schema_version`: immutable document schema; currently `1`.
- `luks_header_escrow_max_raw_bytes`: approved raw-header ceiling, capped at 20 MiB.
- `luks_header_escrow_subject`: document subject; defaults to `inventory_hostname`.
- `luks_header_escrow_crypttab_path`: managed-host `crypttab` path.
- `luks_header_escrow_cryptsetup_path`: absolute `cryptsetup` path.
- `luks_header_escrow_remote_temporary_root`: protected managed-host temporary root.
- `luks_header_escrow_allow_regular_file_device`: test/lab-only opt-in for a
  regular-file LUKS2 source; production defaults require a canonical block device.

The managed-host temporary root must already be canonical, owned by the
effective execution user, grant that owner `rwx`, and deny group/other write
access. Every ancestor back to `/` must be owned by root or that user and either
deny group/other writes or use sticky-directory protection. The role validates
the allocated `0700` directory and binds the transferred base64 payload to the
remotely inspected byte size and SHA-256 before any immutable ciphertext is
published.

On success, `luks_header_escrow_result` contains only safe metadata: whether
ciphertext was created, existence, path, ciphertext SHA-256, and LUKS UUID. It
never contains the header or the plaintext escrow document.

The `preflight` task entrypoint validates the same role interface plus
controller path, ownership, and permission policy without contacting the
managed host.

The role captures and verifies an immutable header document; it does not restore
a header, rotate LUKS keys, prune escrow, or replace the required independent
backup and recovery procedure. Loss of the sole ciphertext or its Vault identity
makes this escrow unusable, so back up and recovery-test both separately.

## Dependencies

None. The role uses `lit.foundational.ansible_vault_document` from this
collection for atomic create-if-absent encryption and exact immutable readback.

## Example Playbook

```yaml
---
- name: Escrow one installed LUKS2 header
  hosts: encrypted_linux
  gather_facts: false
  become: true
  serial: 1

  roles:
    - role: lit.foundational.luks_header_escrow
      vars:
        luks_header_escrow_enabled: true
        # Pre-create and mount this 0700 directory from durable controller storage.
        luks_header_escrow_controller_root_path: /mnt/ansible-escrow
        luks_header_escrow_path: >-
          {{ '/mnt/ansible-escrow/luks-headers/'
             ~ inventory_hostname ~ '.vault.yml' }}
        luks_header_escrow_vault_id: production
```

## License

MIT

## Author

Lightning IT
