# OpenSSF Readiness

This repository follows the Lightning IT shared OpenSSF readiness model generated from `lightning-it/shared-assets-lit`.

## Governing Decisions And Standards

- [Repository Topology and Shared Engineering Assets](https://lit.atlassian.net/wiki/spaces/LIT/pages/2878636297)
- [Branching, Review and Release Governance](https://lit.atlassian.net/wiki/spaces/LIT/pages/2878603438)
- [Mandatory CI Quality and Artifact Assurance](https://lit.atlassian.net/wiki/spaces/LIT/pages/2878636340)
- [Distributed Test Ownership and Central Heavy Execution](https://lit.atlassian.net/wiki/spaces/LIT/pages/2886566105)
- [Repository and Secure SDLC Standard](https://lit.atlassian.net/wiki/spaces/LIT/pages/2887778335)
- [OpenSSF and Software Supply Chain Assurance](https://lit.atlassian.net/wiki/spaces/LIT/pages/2887024876)

## Repository

- Repository: `ansible-collection-foundational`
- Visibility: `public`
- Type: `ansible_collection`
- Release type: `ansible_galaxy`
- Artifact type: `ansible_collection_tarball`

## Scorecard

Enabled through `.github/workflows/openssf-scorecard.yml` with scheduled, manual, and `branch_protection_rule` triggers. The workflow executes a digest-pinned Scorecard container, retains SARIF as an artifact of the GitHub Actions workflow run, and uploads SARIF to GitHub code scanning where the repository supports it. Repository-run results are not published to the OpenSSF API because its workflow verifier does not currently accept the immutable container invocation.

The Scorecard badge is included in `README.md` only for public repositories where the workflow is synced. It can reflect OpenSSF's independent scan rather than a repository-published result.

## Best Practices Badge

Required but not enrolled. Enroll manually at OpenSSF Best Practices, complete the questionnaire until the project reaches the configured target level, then record the numeric project ID as `openssf_best_practices.project_id` in the central `release-model/repositories.yml` inventory in `lightning-it/shared-assets-lit`.

Do not add a passing OpenSSF Best Practices badge until the repository is actually enrolled and passing. Badges must be generated from the central `release-model/repositories.yml` inventory in `lightning-it/shared-assets-lit`; hand-written badges are rejected by the release-model audit.

## Security Policy

`SECURITY.md` describes supported versions, vulnerability reporting, coordinated disclosure, supported artifact scope, and the distinction between public repository content and private customer or infrastructure data.

## Branch Protection And Release Integrity

- `main` is the protected release branch.
- `develop` is the integration branch for normal work, Renovate, and shared-assets-lit PRs.
- Every pull request must have a completed GitHub Copilot review for its current head revision.
- `develop` to `main` promotion PRs are manual release gates and must never auto-merge.
- Integration and backmerge PRs may auto-merge only after required checks pass, all review conversations are resolved, and there are no conflicts.
- Releases and publishing happen only from trusted `main` workflows after validation.
- Release evidence is generated for repositories with release artifacts.

## Dependency Automation

Dependency automation must target `develop` and must not bypass required checks. Coverage should include GitHub Actions, language dependencies, Ansible content, container base images, pre-commit hooks, and documentation tooling where applicable.

## Security Scanning

ansible-lint, yamllint, changelog checks, collection build/smoke validation, and CodeQL where enabled.

## Exceptions

Repository-specific exceptions must be documented in this file or in `.lit/repository.yml`. Exceptions must not expose secrets, private infrastructure details, customer data, or credential-bearing examples.

The current Galaxy release path records and remotely verifies the immutable collection tarball SHA-256, but does not yet attach a CycloneDX SBOM, signed checksum bundle, or GitHub provenance attestation. Migration target: the verified `ansible-collection-supplementary` release-evidence model. Exception owner: `@lightning-it/ent:release`; compensating controls: protected exact-SHA release flow, candidate build/install tests, Galaxy post-publish digest verification, and immutable GitHub Release assets; review/expiry: `2026-10-31`.
