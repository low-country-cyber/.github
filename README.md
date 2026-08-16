# LCCS GitHub Governance

Organization-wide contribution guidance, security reporting policy,
pull-request defaults, and reusable read-only validation workflows.

This repository is intentionally public so GitHub can apply its default
community-health files across repositories owned by `low-country-cyber`.

## Pull request governance audit

The audit-only PR governance tool inventories open organization pull requests
and produces a plain-English green/yellow/red report. Green is only a candidate
for owner approval; the tool has no merge or other GitHub mutation capability.

See [`docs/pr-governance-audit.md`](docs/pr-governance-audit.md) for the local
administrator command, scheduled public-visible workflow, policy boundaries,
tests, and the separate approval gate required before any future write mode.
