# Encrypted header provider custody

## Requirements

Run Ansible in the approved digest-bound EE. Require an authenticated header
capture, its exact source machine/LUKS UUID/checksum and real custody metadata.
Vault KV2 uses explicit scoped token/AppRole credentials, HTTPS and an explicit
trusted CA file. Ambient tokens, HTTP, redirect-following and retries are not
supported. The credential needs read access to data and metadata, and create
access with CAS=0 on the chosen dedicated prefix.

Additional 1Password custody is disabled by default. Enabling it requires an
explicit native desktop executor in inventory, SSH with strict host-key
verification, its exact effective UID/node, the approved CLI path/digest/version,
account/operator/vault pins and desktop CLI integration. The managed module runs
there; Ansible itself remains in the Linux EE. Do not mount an engine socket,
export a session/service-account token or substitute a native binary in the EE.
The executor needs no Vault credential or plaintext header. Existing desktop
account/vault access is validated, not granted by this role.

The loaded Ansible Vault identity authenticates capture. The existing
password-free memory-only AppRole profile cannot share that process. Export a
verified ciphertext-only handoff with `luks_header_custody_package`, then run
provider publication in a fresh credential phase with the handoff checksum.
Read mode needs no Ansible Vault identity and never decrypts the header.

## Variables

See [defaults/main.yml](defaults/main.yml). The role is opt-in and supports
`plan`, `apply` and `verify`; creating missing objects also requires
`luks_header_custody_cac_allow_create: true`.

Supply exactly one source: `*_path` plus `*_ciphertext_sha256` with a loaded
decryption identity, or `*_package_path` plus the independently retained
`*_package_sha256` for password-free provider publication. Pin subject,
machine ID, disk UUID, owner, retention and independent envelope-key reference.
The input package is ciphertext, not a secret password transport.

`*_vault` contains exactly `auth`, `mount` and `prefix`. Auth accepts `url`,
`namespace`, `ca_cert`, `timeout`, `auth_method`, and either `token` or
`role_id`/`secret_id`/`auth_mount_point`. Use a dedicated prefix: this format is
`luks-header-custody-v1` containing encrypted packages. It does not reinterpret
or replace legacy raw-header KV manifests.

For `*_onepassword_enabled: true`, set `*_onepassword_executor`,
`*_onepassword_title_prefix` and `*_onepassword` with exactly:

- `cli_path`, `cli_sha256`, `cli_version`;
- `account_id`, `account_sign_in_address`, `authorized_user_uuids`, `vault_id`;
- `executor_uid`, `executor_node`;
- `item_id`, `item_version` (empty/zero only for initial unique discovery).

The final Document title appends the package SHA256. Existing Documents must
match title, category, tags, pinned revision when supplied, and every byte.
An initial creation requires `*_approval` and `*_approval_authority`: the
existing independent Ed25519 signature/replay contract, with operation
`create-onepassword-header-document`, target=source subject, and binding equal
to the non-secret `onepassword_approval_binding` returned by `plan`. The
signature covers native configuration, package hash and explicit creation
permission. The authority/trust files belong on the native executor. They are
not installed, weakened or replaced by this role. Existing matching copies
are read-only and need no new creation approval.

`*_result` contains only provider object references/versions, package checksum,
verified flags and the public signing binding. It deliberately excludes module
invocations, credentials, ciphertext and raw header bytes. Fact caching is off.

## Dependencies

No new collection dependency. The packaged module uses Python's TLS/HTTP client
and the shared approval boundary; no native controller Ansible is required.
The optional native executor must already provide the pinned 1Password CLI and
the approved signature verifier. No private service is needed for local tests.

## Example Playbook

```yaml
- name: Verify the required header provider copies
  hosts: encrypted_hosts
  gather_facts: false
  roles:
    - role: lit.foundational.luks_header_custody_cac
      vars:
        luks_header_custody_cac_enabled: true
        luks_header_custody_cac_operation: verify
        # Supply the complete source, custody and provider inputs in inventory.
```

Both providers are preflighted before writes. The additional independent copy
is created first; Vault chunks use immutable content-addressed paths and CAS=0,
then the manifest commits last. Every required provider is read completely
again. Missing, conflicting, deleted/destroyed or ambiguous data fails closed.
A partial or unknown write is never an aggregate success. Inspect provider
state before an explicit retry; no retry, overwrite, archive or delete API is
exposed. Identical partial chunks may be reconciled without overwriting them.

Vault object layout is `prefix/package-sha/chunk-N` and `.../manifest`. Retain
both provider receipts independently. A provider checksum test does not prove
the envelope-key reference works, restore application data, cold-unlock a
disk, or authorize keyslot changes, reboot or provider deletion.

For independent retrieval, `luks_header_custody` also supports `operation: read`
without a local package. Supply `read_pins` with the independently retained
`package_sha256`, `subject`, `source_machine_id` and `luks_uuid`; the native
provider additionally requires the retained Document ID and positive version.
The full package is downloaded, reassembled where applicable and authenticated
against that receipt. No source-host access or Vault decryption key is needed.
Use `luks_header_custody_package` with `operation: materialize` to write only the
verified Ansible Vault ciphertext to a new protected restore-input path. An
existing different file is never overwritten. Loading the independent key and
running the actual restore/unlock test remain separate recovery requirements.

Component qualification uses a loopback HTTPS KV2 fixture, a native CLI process
fixture, real asymmetric approval verification and installed-package Ansible
tests. These are not a live 1Password or production-Vault acceptance. CLI
Document creation/download follow the [official command contract](https://www.1password.dev/cli/reference/management-commands/document).

## License

MIT

## Author

Lightning IT
