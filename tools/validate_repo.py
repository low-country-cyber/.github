#!/usr/bin/env python3
"""Validate the public LCCS organization-governance repository."""

from __future__ import annotations

from pathlib import Path
import json
import re
import sys

import yaml


ROOT = Path(__file__).resolve().parents[1]
REQUIRED = {
    "AGENTS.md",
    "CONTRIBUTING.md",
    "PULL_REQUEST_TEMPLATE.md",
    "SECURITY.md",
    "SUPPORT.md",
    ".github/CODEOWNERS",
    ".github/dependabot.yml",
    ".github/pr-governance-policy.json",
    ".github/workflows/gitleaks.yml",
    ".github/workflows/pr-governance-audit.yml",
    ".github/workflows/secret-scan.yml",
    ".github/workflows/validate.yml",
    "docs/pr-governance-audit.md",
    "tests/fixtures/open-prs.json",
    "tests/test_pr_governance_audit.py",
    "tools/pr_governance_audit.py",
}
FORBIDDEN_SUFFIXES = {
    ".env",
    ".key",
    ".log",
    ".pem",
    ".pfx",
    ".p12",
    ".tfplan",
    ".tfstate",
}
FORBIDDEN_MARKERS = (
    "-----BEGIN PRIVATE KEY-----",
    "github_pat_",
    "ghp_",
    "xoxb-",
)
ACTION_USE = re.compile(r"^\s*uses:\s+[^\s@]+@([^\s#]+)", re.MULTILINE)
IMMUTABLE_ACTION_REF = re.compile(r"^[0-9a-f]{40}$")
IMMUTABLE_IMAGE_REF = re.compile(r"ghcr\.io/gitleaks/gitleaks@sha256:[0-9a-f]{64}")


def main() -> int:
    issues: list[str] = []
    for relative in sorted(REQUIRED):
        if not (ROOT / relative).is_file():
            issues.append(f"missing required file: {relative}")

    for path in ROOT.rglob("*"):
        if not path.is_file() or ".git" in path.parts or "__pycache__" in path.parts:
            continue
        if path.resolve() == Path(__file__).resolve():
            continue
        relative = path.relative_to(ROOT).as_posix()
        if path.suffix.lower() in FORBIDDEN_SUFFIXES:
            issues.append(f"forbidden public file type: {relative}")
        text = path.read_text(encoding="utf-8", errors="ignore")
        if any(marker in text for marker in FORBIDDEN_MARKERS):
            issues.append(f"possible sensitive marker: {relative}")
        if path.suffix.lower() in {".yaml", ".yml"}:
            try:
                yaml.safe_load(text)
            except yaml.YAMLError as exc:
                issues.append(f"invalid YAML: {relative}: {exc}")

    for workflow in sorted((ROOT / ".github/workflows").glob("*.yml")):
        text = workflow.read_text(encoding="utf-8")
        relative = workflow.relative_to(ROOT).as_posix()
        for action_ref in ACTION_USE.findall(text):
            if not IMMUTABLE_ACTION_REF.fullmatch(action_ref):
                issues.append(f"mutable third-party action reference: {relative}: @{action_ref}")

    gitleaks_workflow = (ROOT / ".github/workflows/gitleaks.yml").read_text(encoding="utf-8")
    if not IMMUTABLE_IMAGE_REF.search(gitleaks_workflow):
        issues.append("Gitleaks image must be pinned by sha256 digest")
    if gitleaks_workflow.count("docker run --rm --network none") != 2:
        issues.append("both Gitleaks container runs must disable networking")

    secret_scan_workflow = (ROOT / ".github/workflows/secret-scan.yml").read_text(encoding="utf-8")
    if "push:\n    branches: [main]" not in secret_scan_workflow:
        issues.append("secret-scan push trigger must be limited to main")

    policy_path = ROOT / ".github/pr-governance-policy.json"
    try:
        policy = json.loads(policy_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        issues.append(f"invalid PR governance policy JSON: {exc}")
    else:
        if policy.get("mode") != "audit-only":
            issues.append("PR governance policy must remain audit-only")
        mutations = policy.get("mutations", {})
        if not mutations or any(bool(value) for value in mutations.values()):
            issues.append("all PR governance mutation capabilities must remain disabled")

    audit_workflow = (ROOT / ".github/workflows/pr-governance-audit.yml").read_text(
        encoding="utf-8"
    )
    if "pull_request:" in audit_workflow or "push:" in audit_workflow:
        issues.append("organization PR audit must not run untrusted pull-request or push code")
    if "workflow_dispatch:" not in audit_workflow or "schedule:" not in audit_workflow:
        issues.append("organization PR audit must support manual and scheduled audit-only runs")
    if re.search(r"^\s{2,}[a-z_-]+:\s+write\s*$", audit_workflow, re.MULTILINE):
        issues.append("organization PR audit permissions must remain read-only")
    if "secrets." in audit_workflow:
        issues.append("organization PR audit must not accept or inherit repository secrets")
    forbidden_audit_commands = (
        "gh pr merge",
        "gh pr ready",
        "gh pr edit",
        "gh pr comment",
        "gh api --method post",
        "gh api --method patch",
        "gh api --method delete",
    )
    audit_tool = (ROOT / "tools/pr_governance_audit.py").read_text(encoding="utf-8").lower()
    for command in forbidden_audit_commands:
        if command in audit_tool or command in audit_workflow.lower():
            issues.append(f"organization PR audit contains forbidden mutation command: {command}")

    if issues:
        print("FAIL: organization governance validation")
        for issue in issues:
            print(f"- {issue}")
        return 1
    print("PASS: organization governance validation")
    return 0


if __name__ == "__main__":
    sys.exit(main())
