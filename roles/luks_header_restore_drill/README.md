# LUKS header restore drill

Verify an independently retained encrypted LUKS2 header without access to the
source host. The role decrypts only in controller memory and restores only into
a new private tmpfs regular file on a different pinned Linux witness. There is
no production restore-device argument. This is a keyslot/header drill; it does
not prove filesystem data restore, provider console, initramfs networking or boot.

## Requirements

An already loaded trusted Ansible Vault identity, a protected encrypted artifact
from `lit.foundational.luks_header_escrow`, independently retained ciphertext
SHA256/UUID/source identity, a prepared Linux witness with installed cryptsetup,
tmpfs scratch and a protected in-memory recovery passphrase. No packages, keys,
Vault objects or services are created. Keep all secret producer/caller tasks
`no_log: true`, disable persistent fact caching and never pass secret values on
the CLI. An unavailable key/provider fails; no password is generated or cached.

## Variables

See `defaults/main.yml`. Enablement defaults to false. Every enabled invocation
requires the exact subject, LUKS UUID, ciphertext path/SHA256 and distinct source
and witness machine IDs. Supply the existing passphrase through the approved
secret provider or encrypted variables; header encryption identity and recovery
secret backend are independent contracts. `temporary_root` defaults to `/run`
and must be canonical, owner-protected tmpfs. Check mode validates inputs and
the witness but reports `verified: false`; it is not a successful recovery test.

Successful execution verifies raw size/hash, real LUKS2 UUID and metadata, a
regular-file restore, the correct passphrase, rejection of a random incorrect
key and scratch cleanup. A repeated verified drill returns changed=false.
The secret-free `luks_header_restore_drill_result` binds the artifact and witness.

## Dependencies

Only this collection and ansible-core. Controller-only action
`luks_header_escrow_read` reuses the secure no-follow encrypted document reader.
No live source-host, Tang, HashiCorp Vault or production disk access is needed.

## Example Playbook

```yaml
- name: Verify independently retained recovery material
  hosts: recovery_witness
  gather_facts: false
  become: true
  roles:
    - role: lit.foundational.luks_header_restore_drill
```

Declare the exact non-secret contract in inventory and obtain the passphrase
from the existing approved provider in a protected caller. Retain the encrypted
artifact and its custody/owner/retention record off-host before accepting reboot.
An encrypted file on an unverified controller alone is not durable escrow.

## License

MIT

## Author

Lightning IT
