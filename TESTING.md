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

- Normal pull requests run the declared test profiles relevant to changed files.
- Renovate and verified shared-assets or repository-quality synchronization pull requests target `develop` and may auto-merge only after required checks pass.
- `develop` to `main` promotion pull requests run the strongest validation profile for this repository.
- Trusted `main` release workflows build and publish artifacts only after validation succeeds.

## Local Commands

Run the managed repository-policy checks:

```bash
python3 scripts/lit-repository-quality.py
```

Run the declared pre-commit profile:

```bash
pre-commit run --all-files
```

Run the collection's deterministic light checks:

```bash
bash scripts/wunder-devtools-ee.sh true
```

Heavy Incus execution is not required for this repository. Do not report an Incus run as part of its acceptance evidence.

## Interpreting GitHub Actions

The GitHub Actions matrix is the primary dashboard. Job names should expose the repository class, OS/runtime where applicable, and profile, for example `ansible / rhel9 / molecule-heavy-incus`.

Release evidence is generated during trusted release workflows and attached to or linked from GitHub Releases where the repository publishes release artifacts.
