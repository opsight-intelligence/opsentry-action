"""
Tests for scripts/summarize.py: severity totals across reports, the fail-on threshold and the summary text.

Reports are small dicts shaped like the scanners' JSON output, so no file or environment is touched.
The threshold cases cover every level, the 'none' level and an unknown value.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))
from summarize import FailOnError, Totals, count_findings, fails_threshold, render_summary  # noqa: E402

SECURITY = {"critical_count": 1, "high_count": 2, "medium_count": 0, "low_count": 3}
CODE_HEALTH = {"high_count": 1, "medium_count": 4, "low_count": 0}
GOVERNANCE = {"critical_count": 0, "high_count": 0, "medium_count": 1, "low_count": 0}


class CountFindingsTest(unittest.TestCase):
    def test_sums_every_report(self) -> None:
        totals = count_findings([SECURITY, CODE_HEALTH, GOVERNANCE])
        self.assertEqual(totals, Totals(critical=1, high=3, medium=5, low=3))
        self.assertEqual(totals.findings, 12)

    def test_missing_or_bad_counts_are_zero(self) -> None:
        self.assertEqual(count_findings([{}, {"high_count": "two"}]).findings, 0)

    def test_no_reports(self) -> None:
        self.assertEqual(count_findings([]).findings, 0)


class FailsThresholdTest(unittest.TestCase):
    ONLY_MEDIUM = Totals(critical=0, high=0, medium=2, low=0)

    def test_levels_at_or_above(self) -> None:
        self.assertFalse(fails_threshold(self.ONLY_MEDIUM, "critical"))
        self.assertFalse(fails_threshold(self.ONLY_MEDIUM, "high"))
        self.assertTrue(fails_threshold(self.ONLY_MEDIUM, "medium"))
        self.assertTrue(fails_threshold(self.ONLY_MEDIUM, "low"))

    def test_none_never_fails(self) -> None:
        self.assertFalse(fails_threshold(Totals(critical=5, high=0, medium=0, low=0), "none"))

    def test_case_and_spaces_are_ignored(self) -> None:
        self.assertTrue(fails_threshold(self.ONLY_MEDIUM, " Medium "))

    def test_unknown_level_is_an_error(self) -> None:
        with self.assertRaises(FailOnError):
            fails_threshold(self.ONLY_MEDIUM, "severe")


class RenderSummaryTest(unittest.TestCase):
    def test_states_result_and_missing_scans(self) -> None:
        text = render_summary(Totals(1, 0, 0, 0), "high", True, ["code-health-report.json"])
        self.assertIn("| Critical | 1 |", text)
        self.assertIn("Result: **fail**", text)
        self.assertIn("`code-health-report.json`", text)


if __name__ == "__main__":
    unittest.main()
