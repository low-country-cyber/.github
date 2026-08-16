#!/usr/bin/env python3
"""Validate the public LCCS organization-governance repository."""

from __future__ import annotations

from pathlib import Path
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
    ".github/workflows/gitleaks.yml",
    ".github/workflows/secret-scan.yml",
    ".github/workflows/validate.yml",
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

    if issues:
        print("FAIL: organization governance validation")
        for issue in issues:
            print(f"- {issue}")
        return 1
    print("PASS: organization governance validation")
    return 0


if __name__ == "__main__":
    sys.exit(main())
