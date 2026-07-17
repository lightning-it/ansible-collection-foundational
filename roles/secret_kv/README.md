# secret_kv

Reads or writes generic KV secrets.

Currently supported backend:

- HashiCorp Vault KV v2

For Ansible Vault, decrypt values before calling application roles; this role
does not edit vault-encrypted files.
