#!/usr/bin/env python3
"""Generate a read-only, plain-English audit of organization pull requests."""

from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import fnmatch
import json
from pathlib import Path
import re
import subprocess
import sys
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_POLICY = ROOT / ".github" / "pr-governance-policy.json"
FAILURE_STATES = {
    "ACTION_REQUIRED",
    "CANCELLED",
    "ERROR",
    "FAILURE",
    "STALE",
    "STARTUP_FAILURE",
    "TIMED_OUT",
}
PENDING_STATES = {"EXPECTED", "IN_PROGRESS", "PENDING", "QUEUED", "REQUESTED", "WAITING"}
SUCCESS_STATES = {"COMPLETED", "NEUTRAL", "SKIPPED", "SUCCESS"}
BLOCKED_MERGE_STATES = {"BLOCKED", "DIRTY"}


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def load_policy(path: Path) -> dict[str, Any]:
    policy = load_json(path)
    if policy.get("mode") != "audit-only":
        raise ValueError("policy mode must be audit-only")
    mutations = policy.get("mutations", {})
    if not mutations or any(bool(value) for value in mutations.values()):
        raise ValueError("all policy mutations must be explicitly disabled")
    return policy


def run_gh(arguments: list[str]) -> Any:
    result = subprocess.run(
        ["gh", *arguments],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(f"GitHub CLI inspection failed with exit code {result.returncode}")
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError("GitHub CLI returned invalid JSON") from exc


def fetch_open_prs(owner: str, limit: int) -> list[dict[str, Any]]:
    summaries = run_gh(
        [
            "search",
            "prs",
            "--owner",
            owner,
            "--state",
            "open",
            "--limit",
            str(limit),
            "--json",
            "repository,number,title,isDraft,author,updatedAt,url",
        ]
    )
    if len(summaries) >= limit:
        raise RuntimeError(
            f"open PR result reached the limit of {limit}; refusing to produce a partial audit"
        )

    records: list[dict[str, Any]] = []
    for summary in summaries:
        repository = summary["repository"]["nameWithOwner"]
        number = int(summary["number"])
        record = dict(summary)
        record["repository"] = repository
        try:
            detail = run_gh(
                [
                    "pr",
                    "view",
                    str(number),
                    "--repo",
                    repository,
                    "--json",
                    "baseRefName,headRefName,mergeable,mergeStateStatus,reviewDecision,statusCheckRollup,files",
                ]
            )
            record.update(detail)
        except RuntimeError:
            record["inspection_error"] = True
        records.append(record)
    return records


def author_login(record: dict[str, Any]) -> str:
    author = record.get("author") or {}
    return str(author.get("login", "unknown"))


def category_for(record: dict[str, Any], policy: dict[str, Any]) -> str:
    title = str(record.get("title", "")).strip()
    lowered = title.lower()
    if author_login(record) in policy["trusted_dependency_authors"]:
        return "dependency update"
    if lowered == "add repository github governance baseline":
        return "governance baseline"
    if lowered.startswith("recovery checkpoint:"):
        return "recovery checkpoint"
    if "harden" in lowered or "hardening" in lowered:
        return "security hardening"
    if "cross-repository audit" in lowered:
        return "cross-repository audit"
    return "general change"


def changed_paths(record: dict[str, Any]) -> list[str]:
    paths: list[str] = []
    for item in record.get("files") or []:
        if isinstance(item, dict) and item.get("path"):
            paths.append(str(item["path"]))
        elif isinstance(item, str):
            paths.append(item)
    return paths


def matches_any(path: str, patterns: list[str]) -> bool:
    for pattern in patterns:
        if fnmatch.fnmatch(path, pattern):
            return True
        if pattern.startswith("**/") and fnmatch.fnmatch(path, pattern[3:]):
            return True
    return False


def dependency_is_major(title: str) -> bool:
    match = re.search(r"\bfrom\s+v?(\d+)(?:\.\d+)*\s+to\s+v?(\d+)(?:\.\d+)*\b", title, re.I)
    return bool(match and int(match.group(2)) > int(match.group(1)))


def summarize_checks(record: dict[str, Any]) -> tuple[str, str]:
    checks = record.get("statusCheckRollup") or []
    if not checks:
        return "missing", "no automated checks are reported"

    outcomes: list[str] = []
    for check in checks:
        if not isinstance(check, dict):
            outcomes.append("unknown")
            continue
        conclusion = str(check.get("conclusion") or "").upper()
        state = str(check.get("state") or "").upper()
        status = str(check.get("status") or "").upper()
        if conclusion in FAILURE_STATES or state in FAILURE_STATES:
            outcomes.append("failing")
        elif conclusion in PENDING_STATES or state in PENDING_STATES or status in PENDING_STATES:
            outcomes.append("pending")
        elif conclusion in SUCCESS_STATES or state in SUCCESS_STATES:
            outcomes.append("passing")
        else:
            outcomes.append("unknown")

    if "failing" in outcomes:
        return "failing", "one or more automated checks are failing"
    if "pending" in outcomes:
        return "pending", "automated checks are still running or waiting"
    if outcomes and all(outcome == "passing" for outcome in outcomes):
        return "passing", "all reported automated checks passed"
    return "unknown", "automated check results could not be interpreted safely"


def assess(record: dict[str, Any], policy: dict[str, Any]) -> dict[str, Any]:
    category = category_for(record, policy)
    paths = changed_paths(record)
    check_state, check_reason = summarize_checks(record)
    blockers: list[str] = []
    reviews: list[str] = []

    if record.get("inspection_error"):
        blockers.append("GitHub details could not be inspected")
    if record.get("mergeable") == "CONFLICTING" or record.get("mergeStateStatus") in BLOCKED_MERGE_STATES:
        blockers.append("the PR is currently blocked or has merge conflicts")
    if check_state == "failing":
        blockers.append(check_reason)
    elif check_state != "passing":
        reviews.append(check_reason)
    if bool(record.get("isDraft")):
        reviews.append("the PR is still a draft")
    if record.get("mergeable") not in {"MERGEABLE"}:
        reviews.append("GitHub has not confirmed that the PR is mergeable")

    sensitive = sorted(path for path in paths if matches_any(path, policy["sensitive_paths"]))
    if sensitive:
        reviews.append("sensitive workflow, infrastructure, deployment, or ownership files changed")
    if category in policy["manual_review_categories"]:
        reviews.append(f"{category} changes always require human review")
    if category == "dependency update" and dependency_is_major(str(record.get("title", ""))):
        reviews.append("the dependency update crosses a major version")

    low_risk_dependency = bool(paths) and all(
        matches_any(path, policy["low_risk_dependency_paths"]) for path in paths
    )
    eligible_candidate = (
        category == "dependency update"
        and low_risk_dependency
        and not blockers
        and not reviews
        and check_state == "passing"
    )

    if blockers:
        color = "red"
        recommendation = "blocked"
        reasons = blockers + reviews
    elif eligible_candidate:
        color = "green"
        recommendation = "candidate for owner approval"
        reasons = ["low-risk dependency-only change with passing checks"]
    else:
        color = "yellow"
        recommendation = "human review required"
        reasons = reviews or ["this change is outside the narrow low-risk dependency policy"]

    return {
        "repository": record.get("repository", "unknown"),
        "number": record.get("number"),
        "title": record.get("title", "Untitled PR"),
        "url": record.get("url", ""),
        "author": author_login(record),
        "category": category,
        "color": color,
        "recommendation": recommendation,
        "reasons": reasons,
        "draft": bool(record.get("isDraft")),
        "check_state": check_state,
        "mergeable": record.get("mergeable", "UNKNOWN"),
        "sensitive_paths": sensitive,
    }


def escape_cell(value: object) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def render_markdown(owner: str, scope: str, assessments: list[dict[str, Any]]) -> str:
    counts = Counter(item["color"] for item in assessments)
    categories = Counter(item["category"] for item in assessments)
    generated = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    lines = [
        "# LCCS Pull Request Governance Audit",
        "",
        "> Audit-only: this report made no GitHub changes and cannot merge pull requests.",
        "",
        f"- Organization: `{owner}`",
        f"- Scope: {scope}",
        f"- Generated: `{generated}`",
        f"- Open PRs inspected: **{len(assessments)}**",
        f"- Green candidates: **{counts['green']}**",
        f"- Yellow review required: **{counts['yellow']}**",
        f"- Red blocked: **{counts['red']}**",
        "",
        "Green means candidate for owner approval, not automatically approved or merged.",
        "",
        "## Results",
        "",
        "| Status | Repository / PR | Category | Checks | Recommendation | Reason |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    icons = {"green": "GREEN", "yellow": "YELLOW", "red": "RED"}
    for item in sorted(assessments, key=lambda value: (value["color"], value["repository"], value["number"] or 0)):
        link = f"[{item['repository']}#{item['number']}]({item['url']})"
        reason = "; ".join(item["reasons"])
        lines.append(
            "| "
            + " | ".join(
                escape_cell(value)
                for value in (
                    icons[item["color"]],
                    link,
                    item["category"],
                    item["check_state"],
                    item["recommendation"],
                    reason,
                )
            )
            + " |"
        )
    lines.extend(["", "## Category totals", ""])
    for category, count in sorted(categories.items()):
        lines.append(f"- {category}: {count}")
    lines.extend(
        [
            "",
            "## Safety boundary",
            "",
            "This audit has no merge, label, comment, branch-update, or ready-for-review capability. ",
            "Any future write mode requires a separate private design, least-privilege GitHub App review, ",
            "repository rulesets, passing required checks, and explicit LCCS owner approval.",
            "",
        ]
    )
    return "\n".join(lines)


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--owner", default="low-country-cyber")
    parser.add_argument("--policy", type=Path, default=DEFAULT_POLICY)
    parser.add_argument("--input-json", type=Path, help="Use fixture data instead of GitHub")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--json-output", type=Path)
    parser.add_argument("--limit", type=int, default=100)
    parser.add_argument(
        "--scope-label",
        default="repositories visible to the current authenticated GitHub identity",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    try:
        policy = load_policy(args.policy.resolve())
        if args.input_json:
            payload = load_json(args.input_json.resolve())
            records = payload["prs"] if isinstance(payload, dict) else payload
        else:
            records = fetch_open_prs(args.owner, args.limit)
        assessments = [assess(record, policy) for record in records]
        markdown = render_markdown(args.owner, args.scope_label, assessments)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(markdown, encoding="utf-8")
        if args.json_output:
            args.json_output.parent.mkdir(parents=True, exist_ok=True)
            args.json_output.write_text(
                json.dumps(
                    {
                        "mode": "audit-only",
                        "owner": args.owner,
                        "scope": args.scope_label,
                        "results": assessments,
                    },
                    indent=2,
                    sort_keys=True,
                )
                + "\n",
                encoding="utf-8",
            )
    except (OSError, ValueError, RuntimeError, json.JSONDecodeError) as exc:
        print(f"PR governance audit failed safely: {exc}", file=sys.stderr)
        return 2

    counts = Counter(item["color"] for item in assessments)
    print(
        f"Audit complete: {len(assessments)} open PRs; "
        f"green={counts['green']} yellow={counts['yellow']} red={counts['red']}; no changes made"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
