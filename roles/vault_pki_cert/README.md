# vault_pki_cert

Issues one or more service certificates from HashiCorp Vault PKI.

The role is service-generic. Each service entry defines `role_name`,
`common_name`, `alt_names`, and `ip_sans`. Results are exposed as:

- `vault_pki_cert_results`
- `vault_pki_cert_ca_entries`
- `vault_pki_cert_result` by default, configurable with
  `vault_pki_cert_result_fact`
