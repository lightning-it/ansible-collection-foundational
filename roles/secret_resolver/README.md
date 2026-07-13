# lit.foundational.secret_resolver

Resolve explicitly requested secrets on the Ansible controller into one
provider-independent dictionary.

This role is an orchestration and normalization layer. It is **not** a secret
manager and does not replace HashiCorp Vault, HCP Vault, 1Password, Ansible
Vault, AAP credentials, CI credentials, or another external trust source.
Application and infrastructure roles should consume ordinary variables derived
from the normalized result and remain unaware of the selected backend.

~~~text
Inventory or playbook policy
            |
            v
lit.foundational.secret_resolver
            |
            +-- secret_resolver_result (secret values)
            |
            +-- secret_resolver_metadata (non-secret audit state)
            |
            v
Provider-independent application roles
~~~

HashiCorp Vault or HCP Vault is the preferred operational backend when
available. Ansible Vault is suitable for bootstrap and fully offline
environments. 1Password is particularly useful for developer workstations,
human bootstrap flows, Ansible Vault password retrieval, emergency recovery
material, and short-lived local execution.

Fallback is disabled by default. A Vault outage should normally fail closed
instead of silently downgrading to another source.

The existing lit.foundational.secret_backend and
lit.foundational.secret_kv interfaces remain unchanged. This role introduces a
separate normalized request/result contract, with no implicit compatibility
aliases. Consumers can adopt it incrementally without refactoring unrelated
application roles.

## Execution model

The role delegates validation, retrieval, generation, persistence, and result
publication to localhost with become disabled and run_once enabled. Provider
clients and Python dependencies belong on the Ansible controller or execution
environment, not on managed hosts. The role does not install dependencies or
CLIs.

The supported multi-host execution model is the linear strategy with one
active batch. Ansible applies run_once once per serial batch, and the free
strategy does not provide a deterministic single-host boundary. For serial or
free application plays, resolve secrets in a dedicated hosts: localhost,
strategy: linear play, then reference
hostvars['localhost'].secret_resolver_result from later plays in the same
playbook run.

All request policy and provider inputs must be controller-, group-, or
play-scoped and identical for every host in that active batch. run_once uses
the first host's variable context and broadcasts its result; host-specific
runtime or already-decrypted variables would therefore resolve only the first
host's value and expose it to the other hosts. Use separate controller plays
or separate role invocations when secrets are intentionally host-specific.

Use the collection FQCN:

~~~yaml
- role: lit.foundational.secret_resolver
~~~

The role publishes host facts with cacheable set to false:

- secret_resolver_result contains the resolved values.
- secret_resolver_metadata contains non-sensitive resolution state.

Both public outputs are cleared before a transaction, so a failed invocation
that reaches tasks/main.yml cannot leave an earlier successful result looking
current. Ansible's automatic role argument validation runs before role tasks;
if that schema validation itself fails, Ansible cannot first clear facts from a
prior invocation. An always block overwrites role-private secret-bearing state
after success or failure. The published result intentionally remains available
to consumers.

The values still exist in controller memory and in the consuming play. See
[Security considerations](#security-considerations) before passing either
dictionary to another role.

## Supported providers

| Provider | Read | Generate | Write back | Migration target | Notes |
|---|---:|---:|---:|---:|---|
| hashicorp_vault | Yes | No | KV v2 | KV v2 | HashiCorp Vault and HCP Vault-compatible endpoints |
| ansible_vault | Yes | No | No | No | Reads an already-decrypted Ansible variable |
| onepassword | Yes | No | No | No | Uses the controller-side 1Password CLI and lookup |
| environment | Yes | No | No | No | Reads the controller process environment |
| runtime | Yes | No | No | No | Reads an exact Ansible variable name |
| generated | No | Yes | Via HashiCorp Vault | No | Opt-in per request |

Migration sources may be Ansible Vault, 1Password, environment, or runtime
variables. The implemented persistent target is HashiCorp Vault KV version 2.
Migration never deletes or rotates the source.

## Requirements

| Component | Requirement | Used for |
|---|---|---|
| ansible-core | 2.16 or newer | Role argument validation and execution |
| community.general | 11.4.9 or newer, before 12.0.0 | Random generation and 1Password lookup |
| community.hashi_vault | 6.2.1 or newer, before 7.0.0 | Vault KV v2 reads and writes |
| hvac | Installed for the controller Python interpreter | Vault reads and writes |
| 1Password CLI | Authenticated op 2.x executable on the controller PATH | 1Password requests only |

The Ansible collection dependencies are declared in the collection galaxy.yml.
The separate hvac Python package must be present in the Python interpreter
Ansible selects for delegated localhost modules. The role checks that exact
module interpreter before Vault access and returns dependency_missing without
exposing provider data when it is absent.

For 1Password, op 2.x must be available on the controller PATH. The role checks
both op --version and op whoami before querying an item. Supply the
authentication context through the controller environment or execution
environment. A missing or unsupported CLI is dependency_missing. The CLI is
never required on managed hosts.

HashiCorp Vault support is for KV version 2. The public authentication choices
are token, AppRole, and JWT. The KV modules used by this role do not expose
Kubernetes authentication through this role's argument interface. For a
Kubernetes or other workload-identity flow, exchange the workload identity
outside the role and inject a short-lived Vault token, or use an equivalent
pre-authenticated execution-environment bridge.

## Variables

The public interface is fully specified in meta/argument_specs.yml. Static
role-owned defaults are documented in defaults/main.yml; the public
secret_resolver_* inputs intentionally remain caller supplied.

### Global variables

| Variable | Type | Default | Description |
|---|---|---|---|
| secret_resolver_provider | string | runtime | Primary provider when no provider order is set |
| secret_resolver_provider_order | list of strings | empty list | Explicit global provider chain |
| secret_resolver_allow_fallback | boolean | false | Permit eligible movement through a provider chain |
| secret_resolver_fallback_on | list of strings | secret_not_found, secret_key_missing | Categories eligible for fallback |
| secret_resolver_phase | string | operational | Lifecycle phase: bootstrap or operational |
| secret_resolver_requests | list of dictionaries | empty list | Normalized requests to resolve |

When provider_order is empty, the effective chain contains only provider.
Provider names are:

- hashicorp_vault
- ansible_vault
- onepassword
- environment
- runtime
- generated

### Global Vault variables

| Variable | Type | Default | Description |
|---|---|---|---|
| secret_resolver_vault_addr | string | VAULT_ADDR | HashiCorp Vault or HCP Vault address; required for Vault operations |
| secret_resolver_vault_namespace | string | VAULT_NAMESPACE | Optional Vault Enterprise or HCP Vault namespace |
| secret_resolver_vault_mount_point | string | secret | Default KV version 2 engine mount |
| secret_resolver_vault_auth_method | string | token | token, approle, or jwt |
| secret_resolver_vault_auth_mount_point | string | unset | Optional non-default auth-method mount |
| secret_resolver_vault_validate_certs | boolean | true | Validate Vault TLS certificates |
| secret_resolver_vault_ca_cert | string | unset | Controller-side CA certificate path |
| secret_resolver_vault_timeout | integer | unset | Connection timeout in seconds; at least 1 |
| secret_resolver_vault_retries | integer | unset | Non-negative connection retry count |
| secret_resolver_vault_token_validate | boolean | true | Validate a token with lookup-self |
| secret_resolver_vault_token | string | unset | Securely injected Vault token |
| secret_resolver_vault_role_id | string | unset | Securely injected AppRole role ID or JWT role identifier |
| secret_resolver_vault_secret_id | string | unset | Securely injected AppRole Secret ID |
| secret_resolver_vault_jwt | string | unset | Securely injected JWT assertion |

Authentication inputs map as follows:

| Method | Inputs |
|---|---|
| token | secret_resolver_vault_token or provider-supported environment injection |
| approle | secret_resolver_vault_role_id and secret_resolver_vault_secret_id |
| jwt | secret_resolver_vault_role_id and secret_resolver_vault_jwt |

secret_resolver_vault_auth_mount_point selects the authentication backend
mount. secret_resolver_vault_mount_point selects the KV v2 secrets engine;
they are independent settings.

Token, Secret ID, and JWT variables are marked no_log in the argument
specification and have no credential defaults. Prefer provider-supported
environment injection, an AAP credential, a CI credential, or workload
identity. Bootstrap authentication still must originate in an external trust
source.

Token lookup-self validation improves the distinction between an invalid token
and authorization failure at a requested secret path. A deliberately
restricted token that cannot call lookup-self may set
secret_resolver_vault_token_validate to false, with reduced diagnostic
precision.

## Request schema

Each item in secret_resolver_requests describes one output key and every
permitted source or persistence policy for it.

### Request-level fields

| Field | Type | Default | Description |
|---|---|---|---|
| name | string | required | Safe dictionary key published in the result |
| required | boolean | true | Fail when ordinary absence remains unresolved |
| description | string | unset | Non-secret purpose |
| sensitive | boolean | true | Metadata marker; values remain protected even when false |
| tags | list of strings | empty list | Non-secret request classification |
| provider_order | list of strings | global policy | Request-specific ordered chain; ignored during migration |
| allow_fallback | boolean | global policy | Request-specific fallback override; ignored during migration |
| fallback_on | list of strings | global policy | Request-specific eligible categories; ignored during migration |
| default | any | unset | Value used only after ordinary absence |
| validation | dictionary | unset | Value constraints |
| hashicorp_vault | dictionary | unset | Vault KV v2 read location |
| ansible_vault | dictionary | unset | Already-decrypted variable location |
| onepassword | dictionary | unset | 1Password item field location |
| environment | dictionary | unset | Controller environment location |
| runtime | dictionary | unset | Runtime Ansible variable location |
| generation | dictionary | unset | Opt-in generation policy |
| write_back | dictionary | unset | Generated-value persistence policy |
| migration | dictionary | unset | Explicit source-to-target migration policy |

Names and runtime or Ansible Vault variable references must match
`^[A-Za-z_][A-Za-z0-9_]*$`. Environment names use the same safe identifier
pattern. Description and tags are accepted classification fields but are not
copied into the output metadata.

### Validation fields

| Field | Type | Default | Description |
|---|---|---|---|
| allow_empty | boolean | false | Permit a defined empty value |
| min_length | integer | unset | Minimum string-representation length |
| max_length | integer | unset | Maximum string-representation length |
| pattern | string | unset | Regular expression that must match the complete value |

Validation applies equally to retrieved, generated, and default values. Null is
never accepted. An empty string, mapping, or sequence is different from an
undefined source and is valid only when allow_empty is true.

### Provider location fields

| Block | Fields |
|---|---|
| hashicorp_vault | path (required), key (required), mount_point (optional) |
| ansible_vault | variable (required) |
| onepassword | item (required), field (required), vault, account, section |
| environment | variable (required) |
| runtime | variable (required) |

Vault paths are relative to the KV v2 engine mount. Do not include data/ or
metadata/ prefixes. Empty segments, parent traversal, and unsafe keys are
rejected. A request-specific mount_point overrides the global KV engine mount.

The Ansible Vault provider does not decrypt a file or evaluate an expression.
It resolves the exact name of an already-loaded variable. The runtime provider
uses the same exact-name rule.

The 1Password provider accepts an item name or ID and a field ID or label.
Optional vault, account, and section selectors disambiguate the lookup. Field
ID and label matching is case-insensitive. Item, field, and every supplied
optional selector must be non-empty.

### Generation fields

| Field | Type | Default | Description |
|---|---|---|---|
| enabled | boolean | false | Permit generation after configured reads report absence |
| type | string | password | password, alphanumeric, hex, or uuid |
| length | integer | 32 | Output length; UUID output is always 36 characters |
| lower | boolean | true | Permit lowercase in password mode |
| upper | boolean | true | Permit uppercase in password mode |
| numbers | boolean | true | Permit digits in password mode |
| special | boolean | true | Permit special characters in password mode |
| min_lower | integer | 0 | Minimum lowercase characters |
| min_upper | integer | 0 | Minimum uppercase characters |
| min_numeric | integer | 0 | Minimum digits |
| min_special | integer | 0 | Minimum special characters |
| special_characters | string | unset | Allowed special-character set for password mode |
| characters | string | unset | Complete character set override |
| persistence_required | boolean | false | Require successful enabled write-back |

Generation uses community.general.random_string on the controller.
Alphanumeric mode uses lowercase, uppercase, and digits; hex uses lowercase
hexadecimal characters; UUID produces a standard 36-character representation.

The length must be positive, minimum character counts must be non-negative and
fit within the length, and a custom characters set must contain at least two
distinct characters. characters cannot override hex or UUID and cannot be
combined with class-specific minimums. Hex and UUID cannot use minimum
character counts. Special-character constraints apply only to password mode.
Password mode must enable at least one character class unless characters
supplies the complete set. A positive class minimum is invalid when the same
class is disabled. An explicitly supplied special_characters set cannot be
empty or accompany special: false.

### Write-back fields

| Field | Type | Default | Description |
|---|---|---|---|
| enabled | boolean | false | Persist a generated value |
| provider | string | hashicorp_vault | Persistent provider; only hashicorp_vault is supported |
| overwrite | boolean | false | Replace a different existing target value |
| hashicorp_vault | dictionary | request read location | Target path, key, and optional mount_point |

When present, write_back.hashicorp_vault requires path and key. Generated
write-back is accepted only when hashicorp_vault is the first read provider and
the write target is exactly the same mount, path, and key as the read location.
This guarantees that a later run retrieves the persisted value before it can
generate a replacement.

The role reads the complete existing KV v2 document, preserves its other keys,
and uses check-and-set when updating the requested key. A different existing
value fails when overwrite is false. An identical value is already_present and
does not write. Check mode reports would_write; it fails if
persistence_required cannot be satisfied.

### Migration fields

| Field | Type | Default | Description |
|---|---|---|---|
| enabled | boolean | false | Enable explicit migration |
| source_provider | string | unset | Provider that must supply the value |
| target_provider | string | unset | Must be hashicorp_vault |
| overwrite | boolean | false | Replace a different target key |
| hashicorp_vault | dictionary | request Vault location | Target path, key, and optional mount_point |

Migration requires the bootstrap phase, distinct source and target providers,
a configured source block, and generation disabled. Write-back and migration
are mutually exclusive. The source provider alone is resolved during a
migration; the normal provider chain and fallback policy are not used.

## Dependencies

The role has no Ansible role dependencies. Collection dependencies are owned by
galaxy.yml: community.general supplies secure generation and the 1Password
lookup, while community.hashi_vault supplies KV version 2 modules. Vault access
also requires hvac in the delegated-controller Python interpreter; 1Password
access requires an authenticated op 2.x CLI. The role validates but never
installs these controller dependencies.

## Resolution order and fallback

For a normal request, the role:

1. Builds the request-specific provider order, or inherits the global order.
2. Attempts the first provider.
3. Continues only when fallback is enabled and the failure category is listed
   in fallback_on.
4. If generation is enabled and not already in the chain, appends generated
   after the retrieval providers. Generation is attempted only after
   secret_not_found or secret_key_missing and does not require fallback to be
   enabled.
5. Applies an explicit default only after secret_not_found or
   secret_key_missing.
6. Validates the selected value.
7. Performs enabled write-back or migration.
8. Adds the secret and non-sensitive metadata to the output dictionaries.

The default fallback categories are only:

- secret_not_found
- secret_key_missing

The complete category vocabulary eligible for explicit provider fallback is:

- provider_unavailable
- authentication_failed
- authorization_failed
- secret_not_found
- secret_key_missing
- dependency_missing
- invalid_response
- tls_failed
- validation_failed

Do not broaden fallback_on casually. In particular, authentication failure,
authorization failure, malformed provider data, TLS failure, and Vault
unavailability should normally fail. Adding one of those categories is an
explicit decision to trust a lower-priority source under that failure mode.
Setting a provider order alone never enables fallback.
invalid_configuration is rejected before provider resolution, and
write_back_failed or migration_failed occurs after it; those terminal
categories can never trigger fallback.

An optional request that remains absent is omitted from
secret_resolver_result and receives unresolved metadata. Non-absence
errors fail closed even for optional requests. A required unresolved absence
fails the role.

## Configuration validation

The role validates policy before it reads any requested secret. It rejects:

- unsupported or duplicate providers in an order;
- fallback enabled without at least two explicitly ordered providers;
- unsupported fallback categories;
- duplicate or unsafe normalized request names;
- a provider in the effective order without its matching request block;
- unsafe runtime, Ansible Vault, or environment variable names;
- empty required or optional 1Password selectors;
- an empty Vault address, unsafe mount, traversal, repeated path separators,
  data/ or metadata/ prefixes, and unsafe Vault keys;
- negative or inverted value length constraints and invalid regular
  expressions;
- a default combined with enabled generation;
- invalid generation lengths, character sets, or minimum character counts;
- write-back without generation;
- persistence_required without write-back;
- write-back that does not read HashiCorp Vault first at the identical target;
- simultaneous write-back and migration; and
- migration outside bootstrap, with a default, with the same source and target,
  with an unsupported or unconfigured source, without a HashiCorp Vault target,
  or with generation.

Argument-spec validation also rejects missing required nested fields and
incorrect scalar, list, or dictionary types before provider-specific tasks
run.

## Outputs

Given a resolved request named postgresql_admin_password:

~~~yaml
secret_resolver_result:
  postgresql_admin_password: resolved-value
~~~

Do not print this dictionary. The example value above is illustrative only.

Metadata is separate and contains no secret values or authentication material:

~~~yaml
secret_resolver_metadata:
  postgresql_admin_password:
    resolved: true
    provider: hashicorp_vault
    generated: false
    written_back: false
    migrated: false
    persistence_state: not_requested
    fallback_used: false
    fallback_attempted: false
    attempted_providers:
      - hashicorp_vault
    attempt_failures: []
    failure_category: null
    required: true
    sensitive: true
~~~

Every metadata entry has exactly these fields:

| Field | Meaning |
|---|---|
| resolved | Whether a value was selected |
| provider | Selected provider, default, or null |
| generated | Whether the selected value was generated |
| written_back | Whether this run changed the generated-value target |
| migrated | Whether this run changed the migration target |
| persistence_state | not_requested, already_present, would_write, or written |
| fallback_used | Whether a later non-generated provider supplied the value |
| fallback_attempted | Whether a later non-generated provider was attempted |
| attempted_providers | Ordered, non-secret provider audit list |
| attempt_failures | Ordered failed-attempt provider/category records; never provider text or values |
| failure_category | Null when resolved, otherwise the ordinary absence category |
| required | Effective request requirement |
| sensitive | Effective sensitivity marker |

written_back and migrated describe an actual backend change, not merely an
enabled policy. An idempotent repeat can therefore report false with
persistence_state set to already_present.
attempt_failures makes an explicitly enabled downgrade auditable without
retaining exception text or secret material.

## Example Playbook

All examples use the valid collection FQCN
lit.foundational.secret_resolver. Authentication values are deliberately
absent and must be injected securely.

### External HashiCorp Vault or HCP Vault

This example reads a KV v2 field. VAULT_TOKEN or another matching
provider-supported authentication input is supplied by the execution
environment.

~~~yaml
---
- name: Resolve operational secrets
  hosts: application_servers
  gather_facts: false
  roles:
    - role: lit.foundational.secret_resolver
      vars:
        secret_resolver_provider: hashicorp_vault
        secret_resolver_vault_addr: https://vault.example.invalid
        secret_resolver_vault_namespace: admin/platform
        secret_resolver_vault_validate_certs: true
        secret_resolver_requests:
          - name: postgresql_admin_password
            required: true
            hashicorp_vault:
              path: applications/postgresql
              key: admin_password
              mount_point: secret
~~~

For HCP Vault, set the HCP endpoint and namespace appropriate to the cluster.
Do not hardcode a token, AppRole Secret ID, or JWT in the playbook.

### Ansible Vault-only environment

The encrypted file is decrypted by Ansible before the role runs:

~~~yaml
---
- name: Resolve an offline Ansible Vault secret
  hosts: application_servers
  gather_facts: false
  vars_files:
    - vars/production.vault.yml
  roles:
    - role: lit.foundational.secret_resolver
      vars:
        secret_resolver_provider: ansible_vault
        secret_resolver_requests:
          - name: postgresql_admin_password
            required: true
            ansible_vault:
              variable: vault_postgresql_admin_password
~~~

Use the normal Ansible Vault ID workflow, for example:

~~~console
ansible-playbook deploy.yml --vault-id production@prompt
~~~

The role neither knows the Vault ID nor decrypts the file itself. Never store a
Vault password in role defaults or source control.

### 1Password developer workflow

Authenticate op on the controller before Ansible starts, or inject an
appropriate service-account context into the execution environment:

~~~yaml
---
- name: Resolve a developer bootstrap secret
  hosts: developer_target
  gather_facts: false
  roles:
    - role: lit.foundational.secret_resolver
      vars:
        secret_resolver_provider: onepassword
        secret_resolver_requests:
          - name: postgresql_admin_password
            required: true
            onepassword:
              item: PostgreSQL
              field: admin_password
              vault: Infrastructure
              account: account-id-from-controller-config
~~~

The lookup and CLI checks run on the controller. No 1Password CLI is installed
or executed on developer_target.

### Environment-variable injection for CI

Configure POSTGRESQL_ADMIN_PASSWORD as a protected and masked environment
variable in the CI job, then execute Ansible without copying its value into
command-line arguments:

~~~yaml
---
- name: Resolve a CI-injected secret
  hosts: application_servers
  gather_facts: false
  roles:
    - role: lit.foundational.secret_resolver
      vars:
        secret_resolver_provider: environment
        secret_resolver_requests:
          - name: postgresql_admin_password
            required: true
            environment:
              variable: POSTGRESQL_ADMIN_PASSWORD
~~~

~~~console
export POSTGRESQL_ADMIN_PASSWORD
ansible-playbook deploy.yml
~~~

The export line assumes the CI runner has already injected the protected
value. Undefined and defined-but-empty values are distinct; an empty value
fails validation unless allow_empty is explicitly true.

### Runtime-variable injection for AAP or Semaphore

Configure the named input through an AAP credential, protected survey input,
Semaphore variable group, or another secure runtime mechanism:

~~~yaml
---
- name: Resolve an automation-controller input
  hosts: application_servers
  gather_facts: false
  roles:
    - role: lit.foundational.secret_resolver
      vars:
        secret_resolver_provider: runtime
        secret_resolver_requests:
          - name: postgresql_admin_password
            required: true
            runtime:
              variable: postgresql_admin_password_input
~~~

Inject postgresql_admin_password_input at launch. Avoid placing secret values
directly in a shell command or job template source.

### Optional request and default

An unresolved optional request is omitted:

~~~yaml
secret_resolver_requests:
  - name: optional_api_token
    required: false
    runtime:
      variable: optional_api_token_input
~~~

An explicit default is used only for an ordinary absence and is validated like
any other value:

~~~yaml
secret_resolver_requests:
  - name: bootstrap_label
    required: false
    runtime:
      variable: bootstrap_label_input
    default: offline-bootstrap
    validation:
      min_length: 3
      max_length: 64
~~~

Do not combine default with enabled generation.

### Explicit fallback

This policy falls back from Vault to an already-decrypted Ansible Vault
variable only when the Vault path or key is absent:

~~~yaml
secret_resolver_provider_order:
  - hashicorp_vault
  - ansible_vault
secret_resolver_allow_fallback: true
secret_resolver_fallback_on:
  - secret_not_found
  - secret_key_missing
secret_resolver_vault_addr: https://vault.example.invalid
secret_resolver_requests:
  - name: postgresql_admin_password
    required: true
    hashicorp_vault:
      path: applications/postgresql
      key: admin_password
      mount_point: secret
    ansible_vault:
      variable: vault_postgresql_admin_password
~~~

A Vault outage, TLS error, authentication failure, or authorization failure
still fails this example. This protects operators from silently using stale
bootstrap material during an operational incident.

### Generation and idempotent Vault write-back

The first run reads Vault. If the path or key is absent, it generates a value
and writes it to the same location. Later runs retrieve that value before
generation:

~~~yaml
---
- name: Create or retrieve an application password
  hosts: application_servers
  gather_facts: false
  roles:
    - role: lit.foundational.secret_resolver
      vars:
        secret_resolver_provider: hashicorp_vault
        secret_resolver_vault_addr: https://vault.example.invalid
        secret_resolver_requests:
          - name: postgresql_admin_password
            required: true
            hashicorp_vault:
              path: applications/postgresql
              key: admin_password
              mount_point: secret
            generation:
              enabled: true
              type: password
              length: 40
              min_lower: 1
              min_upper: 1
              min_numeric: 1
              min_special: 1
              persistence_required: true
            write_back:
              enabled: true
              provider: hashicorp_vault
              overwrite: false
~~~

Write permission and secure Vault authentication are required. The role
preserves unrelated keys in the KV document and refuses to replace a different
existing value unless overwrite is true.

Generation without write-back is ephemeral and can return a different value on
every run:

~~~yaml
secret_resolver_provider: generated
secret_resolver_requests:
  - name: temporary_session_value
    generation:
      enabled: true
      type: hex
      length: 32
~~~

### Controlled Ansible Vault to HashiCorp Vault migration

Migration is bootstrap-only, copies one explicitly named source, and leaves the
source untouched:

~~~yaml
---
- name: Migrate a bootstrap secret
  hosts: application_servers
  gather_facts: false
  vars_files:
    - vars/bootstrap.vault.yml
  roles:
    - role: lit.foundational.secret_resolver
      vars:
        secret_resolver_phase: bootstrap
        secret_resolver_vault_addr: https://vault.example.invalid
        secret_resolver_requests:
          - name: postgresql_admin_password
            required: true
            ansible_vault:
              variable: vault_postgresql_admin_password
            migration:
              enabled: true
              source_provider: ansible_vault
              target_provider: hashicorp_vault
              overwrite: false
              hashicorp_vault:
                path: applications/postgresql
                key: admin_password
                mount_point: secret
~~~

The target is read first and updated with KV v2 check-and-set semantics. An
identical target is already_present. A different target fails unless overwrite
is true. Source deletion, source retirement, and rotation are separate
operational actions.

### Separate local Vault lifecycle plays

Do not try to resolve operational values from a local Vault before it is
installed, initialized, unsealed, reachable, and authenticated. Keep the
lifecycle boundaries visible:

~~~yaml
# bootstrap_vault.yml
---
- name: Resolve bootstrap material from an external trust source
  hosts: localhost
  connection: local
  gather_facts: false
  strategy: linear
  vars_files:
    - vars/vault-bootstrap.vault.yml
  roles:
    - role: lit.foundational.secret_resolver
      vars:
        secret_resolver_phase: bootstrap
        secret_resolver_provider: ansible_vault
        secret_resolver_requests:
          - name: vault_bootstrap_input
            ansible_vault:
              variable: vault_bootstrap_input_encrypted
  tasks:
    - name: Bootstrap the local Vault deployment
      ansible.builtin.include_role:
        name: organization.platform.vault_bootstrap
      vars:
        platform_vault_bootstrap_input: >-
          {{ secret_resolver_result.vault_bootstrap_input }}
~~~

~~~yaml
# configure_vault.yml
---
- name: Verify local Vault readiness and configure operational access
  hosts: localhost
  connection: local
  gather_facts: false
  strategy: linear
  roles:
    # Replace this project-owned role with the Vault deployment role selected
    # by the operator. It verifies readiness and establishes the operational
    # authentication method without reusing an implicit provider transition.
    - role: organization.platform.vault_configuration
~~~

~~~yaml
# deploy_platform.yml
---
- name: Resolve from the ready operational Vault
  hosts: localhost
  connection: local
  gather_facts: false
  strategy: linear
  roles:
    - role: lit.foundational.secret_resolver
      vars:
        secret_resolver_phase: operational
        secret_resolver_provider: hashicorp_vault
        secret_resolver_vault_addr: https://vault.service.consul:8200
        secret_resolver_requests:
          - name: postgresql_admin_password
            hashicorp_vault:
              path: applications/postgresql
              key: admin_password

- name: Deploy the platform with normalized inputs
  hosts: application_servers
  gather_facts: false
  vars:
    postgresql_admin_password: >-
      {{ hostvars['localhost'].secret_resolver_result.postgresql_admin_password }}
  roles:
    - role: lit.applications.postgresql
~~~

The organization.platform roles are intentionally deployment-specific
and are not provided by this collection. Run the three playbooks separately.
Within deploy_platform.yml, the dedicated resolver play and the application
play remain part of the same Ansible process, so the non-cacheable localhost
fact is available through hostvars. Do not change the provider opaquely halfway
through one task sequence.

### Integration with an application role

Pass only the normalized variable to the application role:

~~~yaml
- name: Deploy PostgreSQL
  ansible.builtin.include_role:
    name: lit.applications.postgresql
  vars:
    postgresql_admin_password: >-
      {{ secret_resolver_result.postgresql_admin_password }}
~~~

The PostgreSQL role does not need community.hashi_vault, a 1Password lookup, or
provider-specific inventory.

For serial or free application execution, use the two-play localhost pattern
shown in deploy_platform.yml instead of invoking the resolver once per
application batch. Non-cacheable resolver facts do not carry across separate
ansible-playbook processes.

## Generation, persistence, and migration lifecycle

The normal generated-secret sequence is:

~~~text
Read authoritative backend
        |
        +-- value exists --> validate and return it
        |
        +-- ordinary absence
                 |
                 +-- generation disabled --> default, omit optional, or fail
                 |
                 +-- generation enabled --> generate
                                              |
                                              +-- write-back enabled --> persist
                                              |
                                              +-- no write-back --> ephemeral
~~~

Persistence-required generation fails when write-back is disabled, fails in
check mode when a write would be needed, and fails if the backend cannot
confirm persistence. Read-only provider access reports no change. Generation
reports a change, and backend writes report changes only when state is
modified.

Migration is deliberately different from fallback and write-back:

~~~text
Explicit bootstrap source --> resolve and validate --> verify Vault target
                                                     |
                                                     +-- same --> no write
                                                     +-- absent --> CAS write
                                                     +-- different --> fail unless overwrite=true
~~~

No migration operation deletes, retires, or rotates its source.

## Error categories and troubleshooting

Resolution-time failures identify the normalized name, attempted provider,
category, fallback state, required state, and a corrective action without
including the secret. Global and per-request policy validation fails before a
provider attempt, so those messages identify the invalid scope and category
instead of inventing provider or fallback state. Ansible's automatic argument
schema errors use ansible-core's own validation format.

| Category | Typical cause | Corrective action |
|---|---|---|
| provider_unavailable | Route, timeout, or service failure | Check controller connectivity, service health, address, and timeout |
| authentication_failed | Missing or rejected auth context | Correct the injected token, AppRole, JWT, or 1Password session |
| authorization_failed | Provider policy denied access | Grant the controller identity access to the exact location |
| secret_not_found | Item or Vault path absent | Create it, configure a default, or enable generation |
| secret_key_missing | Document exists but field is absent | Correct or add the requested key or field |
| invalid_configuration | Contradictory or unsafe policy | Correct provider, path, order, generation, or migration settings |
| dependency_missing | hvac or op 2.x is unavailable | Install it in the controller or execution environment |
| invalid_response | Provider returned an unexpected shape or unclassified error | Check provider compatibility and item shape |
| tls_failed | CA or certificate verification failed | Correct trust configuration; do not routinely disable validation |
| validation_failed | Value violates empty, length, or pattern policy | Correct the source value or constraint |
| write_back_failed | Target verification, overwrite, CAS, or write failed | Check path, policy, concurrent updates, and write permission |
| migration_failed | Migration target or write failed | Check bootstrap policy, target state, and permission |

Useful checks:

- Confirm the Python interpreter selected for delegated localhost modules can
  import hvac.
- Confirm op --version and op whoami succeed in the same controller
  environment used by Ansible.
- Confirm VAULT_ADDR or secret_resolver_vault_addr is set.
- Confirm the Vault path is relative to the engine mount and omits data/.
- Confirm the token or role has both read permission and, for persistence,
  write permission.
- Confirm fallback is enabled only when the provider chain has at least two
  distinct entries.
- Confirm generated write-back reads and writes the identical Vault location.
- Confirm migration runs only in bootstrap phase.

## Security considerations

- no_log suppresses normal task and failure output; it does not remove secret
  values from controller memory.
- The role overwrites its private secret-bearing facts in an always block, but
  this is defense in depth rather than a memory-erasure guarantee.
- The result is a non-cacheable host fact, but downstream debug tasks, callback
  plugins, custom logging, or cached derived facts can still disclose it.
- Never debug or serialize secret_resolver_result.
- Never embed tokens, Secret IDs, JWTs, Vault passwords, or 1Password session
  material in role defaults, examples, task names, or command-line arguments.
- Keep TLS validation enabled. Use secret_resolver_vault_ca_cert for a
  private CA.
- Treat the entire result dictionary as sensitive even if a request sets
  sensitive to false. That setting is metadata, not permission to log.
- Ensure AAP and CI execution environments prevent unrelated jobs and users
  from reading injected credentials or process environments.
- Generated secrets are stable only after authoritative persistence. Without
  write-back they are intentionally ephemeral.
- Fallback can select older or less authoritative data. Keep it disabled unless
  the downgrade policy has been reviewed.
- Bootstrap credentials must still come from an external trust source.

## Testing

The lightweight Molecule scenario exercises controller-local resolution,
validation, fallback, defaults, generation, metadata safety, failure cases, and
idempotence without requiring production provider accounts:

~~~console
molecule test -s secret-resolver-basic
~~~

The real Vault integration scenario uses a disposable Vault service and proves
KV v2 retrieval, generation, write-back, migration, and repeat-run behavior:

~~~console
molecule test -s secret-resolver-vault-integration_heavy
~~~

It pins community.hashi_vault 6.2.1 to exercise the declared compatibility
floor. It requires the scenario's container runtime prerequisites and is
separate from mocked or unit-like provider checks. Public CI does not require a
real HCP Vault tenant or production 1Password account.

Useful affected-file and collection checks include:

~~~console
yamllint roles/secret_resolver changelogs/fragments/secret-resolver.yml
ansible-lint roles/secret_resolver
ansible-galaxy collection build
~~~

Review callback output when changing secret-handling tasks and use only
unmistakably synthetic test values.

## Compatibility matrix

| Environment | Status |
|---|---|
| ansible-core 2.16 and newer | Supported by role metadata |
| AAP execution environments | Supported when controller dependencies and credentials are present |
| Local Ansible controller | Supported when provider dependencies are present |
| CI/CD runner | Supported with protected runtime or environment injection |
| Offline execution | Supported with Ansible Vault, runtime, environment, or ephemeral generation |
| HashiCorp Vault / HCP Vault KV v2 | Read and persistent write target |
| 1Password | Read-only through authenticated controller CLI |
| Managed hosts | Provider clients are not required |

## License

MIT

## Author

Lightning IT
