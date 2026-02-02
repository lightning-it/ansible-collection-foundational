Terraform State Migrate
========================

Upload local Terraform state files to an S3-compatible backend.

Requirements
------------
- `aws` CLI available on the control host (role is typically run with `delegate_to: localhost`).

Role Variables
--------------
- `terraform_state_migrate_local_root`: Directory that contains local tfstate files (required).
- `terraform_state_migrate_s3_endpoint`: S3 endpoint URL (required).
- `terraform_state_migrate_s3_bucket`: S3 bucket name (required).
- `terraform_state_migrate_s3_access_key`: S3 access key (required).
- `terraform_state_migrate_s3_secret_key`: S3 secret key (required).
- `terraform_state_migrate_s3_region`: S3 region (optional).
- `terraform_state_migrate_s3_key_prefix`: Prefix inside the bucket (optional).
- `terraform_state_migrate_globs`: List of tfstate filename patterns to migrate.
- `terraform_state_migrate_recurse`: Whether to recurse into subdirectories.
- `terraform_state_migrate_aws_cli_path`: Path to the `aws` CLI binary.

Example Playbook
----------------
```yaml
- hosts: localhost
  tasks:
    - name: Migrate tfstate to MinIO
      ansible.builtin.include_role:
        name: lit.foundational.terraform_state_migrate
      vars:
        terraform_state_migrate_local_root: /srv/vault/bootstrap
        terraform_state_migrate_s3_endpoint: https://minio.example.com
        terraform_state_migrate_s3_bucket: tfstate
        terraform_state_migrate_s3_access_key: "{{ minio_access_key }}"
        terraform_state_migrate_s3_secret_key: "{{ minio_secret_key }}"
        terraform_state_migrate_s3_key_prefix: vault
```
