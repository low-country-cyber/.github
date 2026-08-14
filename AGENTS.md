# AGENTS.md - LCCS GitHub Governance

## Purpose

This public repository owns organization-wide contribution guidance, security
reporting guidance, pull-request defaults, and reusable read-only GitHub
Actions workflows.

## Boundaries

- Keep all content vendor-neutral and safe for public disclosure.
- Never include customer names, evidence, credentials, private repository
  inventories, internal URLs, raw logs, or runtime configuration.
- Reusable workflows must use read-only permissions and must not accept or
  inherit secrets.
- Do not add deployment, release, cloud, infrastructure, customer-system, or
  notification mutations.

## Validation

Run:

```bash
python3 tools/validate_repo.py
git diff --check
```

## Delivery

Use signed commits, feature branches, and draft pull requests. Never merge
without explicit owner approval.
