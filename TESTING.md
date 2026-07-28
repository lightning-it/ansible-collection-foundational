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

The required central matrix currently contains the executable Incus floating-IP
scenario and the disposable local Vault integration scenario. Each must write a
post-assertion success marker; a skipped or incomplete scenario therefore
cannot pass. The exact candidate archive and source SHA are recorded in
normalized evidence.

The `hetzner-robot-live_heavy` and `hetzner_cloud_live_heavy` scenarios remain
versioned here but are not release-required until the protected environment has
the documented narrowly scoped Hetzner credentials. They are never executed by
a collection-owned workflow and must not be represented as passing through a
skip.

## Interpreting GitHub Actions

The GitHub Actions matrix is the primary dashboard. Job names should expose the repository class, OS/runtime, and profile, for example `ansible / rhel9 / molecule-heavy-incus` or `container / ubuntu / build-smoke`.

Release evidence is generated during trusted release workflows and attached to or linked from GitHub Releases where the repository publishes release artifacts.
