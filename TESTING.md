# Testing

This repository uses the Lightning IT shared test model.

## Test Profiles

- `pre-commit`
- `lint`
- `light`
- `molecule-light`
- `release-validation`

## Supported Matrix

Operating systems and runners:

- `ubuntu-latest`

Products and runtimes:

- `ansible-core`
- `molecule`

## When Tests Run

- Normal pull requests run pre-commit, linting, syntax checks, and light tests relevant to changed files.
- Renovate and verified shared-assets or repository-quality synchronization pull requests target `develop` and may auto-merge only after required checks pass.
- `develop` to `main` promotion pull requests run the strongest validation profile for this repository.
- Trusted `main` release workflows build and publish artifacts only after validation succeeds.

## Local Commands

Run pre-commit locally:

```bash
pre-commit run --all-files
```

Run repository-specific light checks from the checked-out repository:

```bash
bash scripts/wunder-devtools-ee.sh true
```

Heavy Incus tests require an Ubuntu host or runner with Incus available, suitable images, and repository-specific scenario configuration. Heavy tests must use sanitized inputs and must not rely on private inventory values.

## Heavy execution ownership

Heavy scenarios and their component assertions remain in this repository.
Their protected execution is owned exclusively by the commit-pinned reusable
workflow in `lightning-it/modulix-validation`, in accordance with the accepted
[Modulix test execution ownership ADR](https://wiki.cloud.l-it.io/wiki/spaces/LIT/pages/2886566105).
The workflow pin must resolve to protected long-lived branch history so it
remains available after rollout branches are deleted.

The required central matrix contains every routed Heavy scenario: Incus
floating-IP, disposable Vault integration, read-only Hetzner Robot audit, and
disposable Hetzner Cloud infrastructure. Each writes a post-assertion success
marker; a missing protected credential, skipped scenario, or incomplete
verification therefore cannot pass. The exact candidate archive and source SHA
are recorded in normalized evidence.

## Interpreting GitHub Actions

The GitHub Actions matrix is the primary dashboard. Job names should expose the repository class, OS/runtime, and profile, for example `ansible / rhel9 / molecule-heavy-incus` or `container / ubuntu / build-smoke`.

Release evidence is generated during trusted release workflows and attached to or linked from GitHub Releases where the repository publishes release artifacts.
