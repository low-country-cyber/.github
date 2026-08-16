# Pull Request Governance Audit

This tool gives LCCS a company-wide, plain-English view of open GitHub pull
requests without changing GitHub state. It is deliberately audit-only.

## What the colors mean

- **Green**: a low-risk dependency-only candidate with passing checks. It still
  needs owner approval and is not merged automatically.
- **Yellow**: human review is required. Drafts, missing or pending checks,
  workflow changes, infrastructure changes, governance work, recovery
  checkpoints, security hardening, major dependency upgrades, and general code
  changes stay yellow.
- **Red**: blocked. A merge conflict, a blocked merge state, a failed check, or
  an inspection failure must be resolved first.

The policy is stored in `.github/pr-governance-policy.json`. The policy mode is
`audit-only`, and every mutation capability must remain explicitly `false`.
Repository validation fails if this boundary is changed.

## Run the complete administrator audit

Use an authenticated LCCS GitHub CLI session. The command reads only the
repositories visible to that identity and writes reports beneath the ignored
`.local/` directory.

```bash
mkdir -p .local/pr-audit
python3 tools/pr_governance_audit.py \
  --owner low-country-cyber \
  --output .local/pr-audit/report.md \
  --json-output .local/pr-audit/report.json
```

The command fails closed if GitHub cannot be inspected or if the open-PR result
reaches its configured limit. It never invokes a merge, label, comment,
ready-for-review, branch-update, deployment, or notification operation.

## Scheduled public-visible audit

`.github/workflows/pr-governance-audit.yml` runs on weekdays and can also be
started manually. It uses only the repository's read-only GitHub workflow token
and publishes a Markdown job summary. It does not receive an organization
secret and cannot see private repositories that are outside that token's
visibility.

For that reason, the scheduled summary must not be treated as proof that every
private LCCS repository was inspected. Use the administrator command for the
complete visibility available to the authenticated company account.

## Test without GitHub

The fixture is synthetic and contains no LCCS or customer inventory.

```bash
python3 -m unittest discover -s tests -v
python3 tools/pr_governance_audit.py \
  --owner example \
  --input-json tests/fixtures/open-prs.json \
  --scope-label "synthetic fixture" \
  --output .local/pr-audit/fixture-report.md \
  --json-output .local/pr-audit/fixture-report.json
```

## Future activation gate

Automatic writes are intentionally out of scope for this version. A future
merge service requires a separate private design using a least-privilege GitHub
App, repository rulesets, required checks, protected branches, an explicit
allowlist, rollback instructions, audit logging, and fresh LCCS owner approval.
