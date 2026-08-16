from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
sys.path.insert(0, str(TOOLS))

import pr_governance_audit as audit  # noqa: E402


class GovernanceAuditTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.policy = audit.load_policy(ROOT / ".github" / "pr-governance-policy.json")
        cls.fixture = json.loads(
            (ROOT / "tests" / "fixtures" / "open-prs.json").read_text(encoding="utf-8")
        )["prs"]

    def test_low_risk_dependency_with_checks_is_green(self) -> None:
        result = audit.assess(self.fixture[0], self.policy)
        self.assertEqual(result["color"], "green")
        self.assertEqual(result["recommendation"], "candidate for owner approval")

    def test_draft_governance_change_requires_review(self) -> None:
        result = audit.assess(self.fixture[1], self.policy)
        self.assertEqual(result["color"], "yellow")
        self.assertIn("the PR is still a draft", result["reasons"])

    def test_sensitive_workflow_change_never_becomes_green(self) -> None:
        result = audit.assess(self.fixture[2], self.policy)
        self.assertEqual(result["color"], "yellow")
        self.assertTrue(result["sensitive_paths"])

    def test_failing_check_is_red(self) -> None:
        result = audit.assess(self.fixture[3], self.policy)
        self.assertEqual(result["color"], "red")

    def test_missing_checks_and_unknown_mergeability_require_review(self) -> None:
        result = audit.assess(self.fixture[4], self.policy)
        self.assertEqual(result["color"], "yellow")
        self.assertIn("no automated checks are reported", result["reasons"])

    def test_major_dependency_upgrade_requires_review(self) -> None:
        record = dict(self.fixture[0])
        record["title"] = "chore(deps): bump package from 5 to 7"
        result = audit.assess(record, self.policy)
        self.assertEqual(result["color"], "yellow")
        self.assertIn("the dependency update crosses a major version", result["reasons"])

    def test_completed_check_without_conclusion_is_not_passing(self) -> None:
        record = dict(self.fixture[0])
        record["statusCheckRollup"] = [{"status": "COMPLETED", "conclusion": ""}]
        result = audit.assess(record, self.policy)
        self.assertEqual(result["color"], "yellow")
        self.assertEqual(result["check_state"], "unknown")

    def test_policy_rejects_enabled_mutation(self) -> None:
        policy = json.loads(json.dumps(self.policy))
        policy["mutations"]["merge"] = True
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "unsafe.json"
            path.write_text(json.dumps(policy), encoding="utf-8")
            with self.assertRaises(ValueError):
                audit.load_policy(path)

    def test_fixture_cli_generates_markdown_and_json_without_github(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            markdown = Path(temp_dir) / "audit.md"
            structured = Path(temp_dir) / "audit.json"
            result = subprocess.run(
                [
                    sys.executable,
                    str(TOOLS / "pr_governance_audit.py"),
                    "--owner",
                    "example",
                    "--input-json",
                    str(ROOT / "tests" / "fixtures" / "open-prs.json"),
                    "--output",
                    str(markdown),
                    "--json-output",
                    str(structured),
                    "--scope-label",
                    "synthetic fixture",
                ],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("no changes made", result.stdout)
            report = markdown.read_text(encoding="utf-8")
            self.assertIn("Audit-only", report)
            self.assertIn("Green candidates: **1**", report)
            payload = json.loads(structured.read_text(encoding="utf-8"))
            self.assertEqual(payload["mode"], "audit-only")
            self.assertEqual(len(payload["results"]), 5)


if __name__ == "__main__":
    unittest.main()
