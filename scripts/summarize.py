"""
Combine the OpSentry scan reports into one result, set the action's outputs and apply the fail-on threshold.

The pure part (count_findings, fails_threshold, render_summary) adds up severity counts across the JSON reports
and decides whether the run fails; main() is the thin adapter that reads report files and environment variables
and writes GITHUB_OUTPUT, GITHUB_STEP_SUMMARY and the exit code. A scan that was expected to run but left no report
is reported as a scan error and fails the run, so a crashed scanner can never look like a clean pass.
"""

from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Sequence

SEVERITIES: Sequence[str] = ("critical", "high", "medium", "low")
NO_THRESHOLD: str = "none"
EXIT_PASS: int = 0
EXIT_THRESHOLD: int = 1
EXIT_SCAN_ERROR: int = 2
REPORT_SEPARATOR: str = ","
DEFAULT_FAIL_ON: str = "high"

#: Comma-separated report paths of the scans that ran; empty when none ran.
EXPECTED_REPORTS: str = os.environ.get("EXPECTED_REPORTS", "")
#: The fail-on input; defaults to the action's own default.
FAIL_ON: str = os.environ.get("FAIL_ON", DEFAULT_FAIL_ON)
#: Directory holding the reports, published as the report-path output.
REPORT_DIR: str = os.environ.get("REPORT_DIR", "")
#: Files GitHub Actions reads outputs and the job summary from; empty outside Actions.
GITHUB_OUTPUT_PATH: str = os.environ.get("GITHUB_OUTPUT", "")
GITHUB_STEP_SUMMARY_PATH: str = os.environ.get("GITHUB_STEP_SUMMARY", "")


class FailOnError(ValueError):
    """The fail-on input names no known severity."""


@dataclass(frozen=True)
class Totals:
    """Finding counts summed across every report that was read."""

    critical: int
    high: int
    medium: int
    low: int

    @property
    def findings(self) -> int:
        """All findings at any severity."""
        return self.critical + self.high + self.medium + self.low


def count_findings(reports: List[Dict[str, object]]) -> Totals:
    """Sum the per-severity counts of every report; a missing count is zero."""
    sums = {severity: 0 for severity in SEVERITIES}
    for report in reports:
        for severity in SEVERITIES:
            value = report.get(f"{severity}_count", 0)
            sums[severity] += value if isinstance(value, int) else 0
    return Totals(**sums)


def fails_threshold(totals: Totals, fail_on: str) -> bool:
    """True when any finding is at or above the fail-on severity; 'none' never fails."""
    level = fail_on.strip().lower()
    if level == NO_THRESHOLD:
        return False
    if level not in SEVERITIES:
        raise FailOnError(f"fail-on must be one of {', '.join(SEVERITIES)} or {NO_THRESHOLD}, got '{fail_on}'")
    at_or_above = SEVERITIES[: SEVERITIES.index(level) + 1]
    return any(getattr(totals, severity) > 0 for severity in at_or_above)


def render_summary(totals: Totals, fail_on: str, failed: bool, missing: List[str]) -> str:
    """Markdown for the job summary page."""
    lines = ["## OpSentry scan", "", "| Severity | Findings |", "|---|---|"]
    lines += [f"| {severity.capitalize()} | {getattr(totals, severity)} |" for severity in SEVERITIES]
    lines += ["", f"Threshold: `{fail_on}`. Result: **{'fail' if failed else 'pass'}**."]
    if missing:
        lines += ["", "Scans that left no report (scan error): " + ", ".join(f"`{m}`" for m in missing)]
    return "\n".join(lines) + "\n"


def _append(target: str, text: str) -> None:
    """Append text to a GitHub Actions file, when the path is set."""
    if target:
        with open(target, "a", encoding="utf-8") as handle:
            handle.write(text)


def main() -> int:
    """Read the reports, write outputs and summary, and return the exit code."""
    expected = [p for p in EXPECTED_REPORTS.split(REPORT_SEPARATOR) if p]
    fail_on = FAIL_ON
    present = [p for p in expected if Path(p).is_file()]
    missing = [Path(p).name for p in expected if p not in present]
    reports = [json.loads(Path(p).read_text(encoding="utf-8")) for p in present]
    totals = count_findings(reports)
    try:
        failed = fails_threshold(totals, fail_on)
    except FailOnError as error:
        print(f"::error::{error}")
        return EXIT_SCAN_ERROR
    _append(GITHUB_OUTPUT_PATH, f"findings-count={totals.findings}\ncritical-count={totals.critical}\n"
                             f"high-count={totals.high}\nreport-path={REPORT_DIR}\n")
    _append(GITHUB_STEP_SUMMARY_PATH, render_summary(totals, fail_on, failed, missing))
    print(f"OpSentry: {totals.findings} findings (critical {totals.critical}, high {totals.high}), fail-on {fail_on}")
    if missing:
        print(f"::error::Scan error: no report from {', '.join(missing)}")
        return EXIT_SCAN_ERROR
    return EXIT_THRESHOLD if failed else EXIT_PASS


if __name__ == "__main__":
    sys.exit(main())
