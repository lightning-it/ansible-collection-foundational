# GitHub Copilot review instructions

- Review every change for correctness, security, least privilege, and failure behavior.
- When present, apply all repository-specific guidance in `AGENTS.md` and path-scoped instruction files.
- Treat malformed external input as an error rather than silently coercing it.
- Check that credentials are scoped to the smallest required job.
- Require new or modified third-party GitHub Actions dependencies to use immutable commit SHAs.
- Explain each finding's impact and propose a concrete fix.
- Prefer a regression test for bugs and security issues.
- Treat `AGENTS.md` as the canonical repository contract. A managed
  `AGENTS_SHA256` marker below binds these instructions to the reviewed
  `AGENTS.md`; instruction drift is a blocking finding.

<!-- Managed contract: Codex and Copilot must apply AGENTS.md. -->
<!-- AGENTS_SHA256: baeec69bcdf95fc29e42e2b6c94a3bc358cb4b39afb2b02ccd9c7e8aeb30f081 -->
