"""Unit tests for scripts/prowler_compare.py, using the synthetic fixtures."""

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import prowler_compare as pc  # noqa: E402

FIXTURES = ROOT / "tests" / "fixtures"


class CompareTest(unittest.TestCase):
    def setUp(self):
        self.before = pc.load(FIXTURES / "prowler-before.csv")
        self.after = pc.load(FIXTURES / "prowler-after.csv")

    def test_muted_findings_are_ignored(self):
        self.assertEqual(len(self.before), 6)
        self.assertNotIn("ec2_instance_imdsv2_enabled", {r["CHECK_ID"] for r in self.before})

    def test_pass_rate(self):
        self.assertEqual(pc.pass_rate(self.before), "17%")
        self.assertEqual(pc.pass_rate(self.after), "86%")

    def test_report_sections(self):
        report = pc.compare(self.before, self.after)
        self.assertIn("| Failed checks | 5 | 1 |", report)
        self.assertIn("| Critical | 2 | 0 |", report)
        self.assertIn("## Fixed (5)", report)
        self.assertIn("## New since baseline (1)", report)
        self.assertIn("`iam_user_mfa_enabled_console_access`", report)
        self.assertIn("## Remaining critical and high (1)", report)

    def test_rejects_non_prowler_csv(self):
        bad = FIXTURES / "credential-report.csv"
        with self.assertRaises(SystemExit):
            pc.load(bad)


if __name__ == "__main__":
    unittest.main()
