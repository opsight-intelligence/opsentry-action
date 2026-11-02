"""
PR Comment Reporter for Security Audit and Code Health.
Reads a JSON scan report and posts a formatted comment on the PR using GitHub API.
Updates existing comment if one already exists (avoids duplicates).
"""

import json
import os
import sys
import urllib.request
import urllib.error


DEFAULT_COMMENT_MARKER = "<!-- security-audit-bot -->"

SEVERITY_ICONS = {
    "critical": "[CRITICAL]",
    "high": "[HIGH]",
    "medium": "[MEDIUM]",
    "low": "[LOW]",
}


def load_report(report_path: str) -> dict:
    """Load the JSON scan report."""
    with open(report_path, "r") as f:
        return json.load(f)


def detect_report_type(report: dict) -> str:
    """Detect whether this is a security, health, or governance report."""
    if "guardrails_present" in report:
        return "governance"
    if "health_score" in report:
        return "health"
    return "security"


def format_security_comment(report: dict, marker: str) -> str:
    """Format a security audit report as a GitHub PR markdown comment."""
    lines = [marker]

    if report["blocks_merge"]:
        lines.append("## Security Audit -- FAILED")
        lines.append("")
        lines.append("Critical or high severity issues found. **This PR cannot be merged until these are resolved.**")
    elif report["total_findings"] > 0:
        lines.append("## Security Audit -- Warnings")
        lines.append("")
        lines.append("Non-blocking issues found. Please review before merging.")
    else:
        lines.append("## Security Audit -- PASSED")
        lines.append("")
        lines.append(f"Scanned {report['files_scanned']} files. No security issues found.")
        return "\n".join(lines)

    lines.append("")
    lines.append(f"**Files scanned:** {report['files_scanned']}")
    lines.append(f"**Total findings:** {report['total_findings']}")
    lines.append("| Severity | Count |")
    lines.append("|----------|-------|")
    lines.append(f"| {SEVERITY_ICONS['critical']} Critical | {report['critical_count']} |")
    lines.append(f"| {SEVERITY_ICONS['high']} High | {report['high_count']} |")
    lines.append(f"| {SEVERITY_ICONS['medium']} Medium | {report['medium_count']} |")
    lines.append(f"| {SEVERITY_ICONS['low']} Low | {report['low_count']} |")

    if report.get("llm_calls_made", 0) > 0:
        lines.append("")
        lines.append(f"**LLM calls made:** {report['llm_calls_made']}")

    _append_findings(lines, report)

    lines.append("---")
    lines.append("*Posted by Security Audit Agent*")
    return "\n".join(lines)


def format_health_comment(report: dict, marker: str) -> str:
    """Format a code health report as a GitHub PR markdown comment."""
    lines = [marker]

    if report["blocks_merge"]:
        lines.append("## Code Health -- FAILED")
        lines.append("")
        lines.append("High severity code health issues found. **This PR cannot be merged until these are resolved.**")
    elif report["total_findings"] > 0:
        lines.append("## Code Health -- Warnings")
        lines.append("")
        lines.append("Non-blocking issues found. Please review before merging.")
    else:
        lines.append("## Code Health -- PASSED")
        lines.append("")
        lines.append(f"Scanned {report['files_scanned']} files. No code health issues found.")
        return "\n".join(lines)

    lines.append("")
    lines.append(f"**Health Score:** {report.get('health_score', 'N/A')}")
    lines.append(f"**Files scanned:** {report['files_scanned']}")
    lines.append(f"**Total findings:** {report['total_findings']}")
    lines.append("| Severity | Count |")
    lines.append("|----------|-------|")
    lines.append(f"| {SEVERITY_ICONS['high']} High | {report['high_count']} |")
    lines.append(f"| {SEVERITY_ICONS['medium']} Medium | {report['medium_count']} |")
    lines.append(f"| {SEVERITY_ICONS['low']} Low | {report['low_count']} |")

    if report.get("llm_calls_made", 0) > 0:
        lines.append("")
        lines.append(f"**LLM calls made:** {report['llm_calls_made']}")

    _append_findings(lines, report)

    lines.append("---")
    lines.append("*Posted by Code Health Agent*")
    return "\n".join(lines)


def _format_finding(lines: list, finding: dict) -> None:
    """Append a single formatted finding to comment lines."""
    fix_tag = " [auto-fixable]" if finding.get("auto_fixable") else ""
    lines.append(f"**{finding['rule_name']}**{fix_tag}")
    lines.append(f"- File: `{finding['file_path']}` (line {finding['line_number']})")
    if finding.get("code_snippet"):
        lines.append(f"- Code: `{finding['code_snippet']}`")
    lines.append(f"- {finding['description']}")
    lines.append(f"- Fix: {finding['remediation']}")
    lines.append("")


def _append_findings(lines: list, report: dict) -> None:
    """Append auto-fixable count and grouped findings to comment lines."""
    if report.get("auto_fixable_count", 0) > 0:
        lines.append("")
        lines.append(f"**Auto-fixable issues:** {report['auto_fixable_count']}")

    if report.get("suppressed_count", 0) > 0:
        lines.append(f"**Suppressed (confirmed false positives):** {report['suppressed_count']}")

    all_findings = report.get("findings", [])
    deterministic = [f for f in all_findings if f.get("source") != "llm"]
    llm_findings = [f for f in all_findings if f.get("source") == "llm"]

    findings_by_severity = {}
    for finding in deterministic:
        sev = finding["severity"]
        if sev not in findings_by_severity:
            findings_by_severity[sev] = []
        findings_by_severity[sev].append(finding)

    severity_order = ["critical", "high", "medium", "low"]
    for sev in severity_order:
        if sev not in findings_by_severity:
            continue

        icon = SEVERITY_ICONS.get(sev, "")
        lines.append("")
        lines.append(f"### {icon} {sev.upper()}")
        lines.append("")

        for finding in findings_by_severity[sev]:
            _format_finding(lines, finding)

    if llm_findings:
        lines.append("")
        lines.append("### AI Advisory (LLM-detected)")
        lines.append("")
        lines.append(
            "*These findings are AI-generated and advisory only. "
            "They may contain false positives. Verify before acting.*"
        )
        lines.append("")
        for finding in llm_findings:
            confidence = finding.get("confidence", "medium")
            confidence_label = f" [confidence: {confidence}]"
            lines.append(f"**{finding['rule_name']}**{confidence_label}")
            lines.append(f"- File: `{finding['file_path']}` (line {finding['line_number']})")
            lines.append(f"- {finding['description']}")
            lines.append(f"- Fix: {finding['remediation']}")
            lines.append("")


def format_governance_comment(report: dict, marker: str) -> str:
    """Format a governance check report as a GitHub PR markdown comment."""
    lines = [marker]

    if report["blocks_merge"]:
        lines.append("## Governance Check -- FAILED")
        lines.append("")
        lines.append("Governance violations found. **This PR cannot be merged until these are resolved.**")
    elif report["total_findings"] > 0:
        lines.append("## Governance Check -- Warnings")
        lines.append("")
        lines.append("Non-blocking governance issues found. Please review.")
    else:
        lines.append("## Governance Check -- PASSED")
        lines.append("")
        lines.append(f"Scanned {report['files_scanned']} files. All guardrails present and compliant.")
        return "\n".join(lines)

    guardrails_status = "Present" if report.get("guardrails_present") else "Missing/Incomplete"
    lines.append("")
    lines.append(f"**Guardrails status:** {guardrails_status}")
    lines.append(f"**Files scanned:** {report['files_scanned']}")
    lines.append(f"**Total findings:** {report['total_findings']}")
    lines.append("| Severity | Count |")
    lines.append("|----------|-------|")
    lines.append(f"| {SEVERITY_ICONS['critical']} Critical | {report['critical_count']} |")
    lines.append(f"| {SEVERITY_ICONS['high']} High | {report['high_count']} |")
    lines.append(f"| {SEVERITY_ICONS['medium']} Medium | {report['medium_count']} |")
    lines.append(f"| {SEVERITY_ICONS['low']} Low | {report['low_count']} |")

    _append_findings(lines, report)

    lines.append("---")
    lines.append("*Posted by Governance Check Agent*")
    return "\n".join(lines)


def format_comment(report: dict, marker: str) -> str:
    """Format any report type as a GitHub PR markdown comment."""
    report_type = detect_report_type(report)
    if report_type == "governance":
        return format_governance_comment(report, marker)
    if report_type == "health":
        return format_health_comment(report, marker)
    return format_security_comment(report, marker)


def github_api_request(url: str, method: str, data: dict = None, token: str = None) -> dict:
    """Make a request to the GitHub API."""
    headers = {
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": "security-audit-bot",
    }
    if token:
        headers["Authorization"] = f"token {token}"

    body = json.dumps(data).encode("utf-8") if data else None
    req = urllib.request.Request(url, data=body, headers=headers, method=method)

    try:
        with urllib.request.urlopen(req) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        error_body = e.read().decode("utf-8")
        print(f"GitHub API error {e.code}: {error_body}", file=sys.stderr)
        raise


def find_existing_comment(repo: str, pr_number: str, token: str, marker: str) -> int | None:
    """Find an existing comment with the given marker on the PR."""
    url = f"https://api.github.com/repos/{repo}/issues/{pr_number}/comments"
    comments = github_api_request(url, "GET", token=token)

    for comment in comments:
        if marker in comment.get("body", ""):
            return comment["id"]
    return None


def post_or_update_comment(repo: str, pr_number: str, body: str, token: str, marker: str) -> None:
    """Post a new comment or update an existing one."""
    existing_id = find_existing_comment(repo, pr_number, token, marker)

    if existing_id:
        url = f"https://api.github.com/repos/{repo}/issues/comments/{existing_id}"
        github_api_request(url, "PATCH", data={"body": body}, token=token)
        print(f"Updated existing comment {existing_id}")
    else:
        url = f"https://api.github.com/repos/{repo}/issues/{pr_number}/comments"
        result = github_api_request(url, "POST", data={"body": body}, token=token)
        print(f"Posted new comment {result.get('id')}")


def main():
    """Entry point for the PR comment reporter."""
    report_path = os.environ.get("REPORT_OUTPUT", "security-report.json")
    repo = os.environ.get("GITHUB_REPOSITORY", "")
    pr_number = os.environ.get("PR_NUMBER", "")
    token = os.environ.get("GITHUB_TOKEN", "")
    marker = os.environ.get("COMMENT_MARKER", DEFAULT_COMMENT_MARKER)

    report = load_report(report_path)

    if not all([repo, pr_number, token]):
        print("Missing required environment variables: GITHUB_REPOSITORY, PR_NUMBER, GITHUB_TOKEN")
        print("Printing report to stdout instead.\n")
        print(format_comment(report, marker))
        return

    comment_body = format_comment(report, marker)
    post_or_update_comment(repo, pr_number, comment_body, token, marker)


if __name__ == "__main__":
    main()
