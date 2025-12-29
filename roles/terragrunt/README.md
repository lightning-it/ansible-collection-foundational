# terragrunt

Role to execute terraform via dynamic terragrunt.hcl file

## Requirements

No.

## Role Variables

See defaults/main.yml

## Dependencies

No.

## Example Playbook
```
- name: "Execute Terragrunt"
  hosts: localhost
  gather_facts: false
  vars:
    terragrunt_template: custom.hcl.j2
  roles:
    - role: terragrunt
  tags:
    - terragrunt
```

## License

BSD

## Author Information

Dirk Egert
