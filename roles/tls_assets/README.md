# tls_assets

Stages TLS certificate, key, and CA bundle files on a managed host.

Supported sources:

- `customer_files`: copy controller-side files or write inline PEM content.
- `vault_pki`: issue certificates through `lit.foundational.vault_pki_cert`
  and stage the issued cert/key/CA files.

The role is intentionally service-generic. Application roles should map their
service names and installer/runtime variables to `tls_assets_services`,
`tls_assets_target_files`, and `tls_assets_customer_files`.
