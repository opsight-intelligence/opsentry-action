"""
Governance Check Scanner for CI/CD Pipeline.
Verifies guardrail files are present and unmodified, scans for policy violations.
Outputs a structured JSON report compatible with report_to_pr.py.
"""

import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass, field, asdict
from enum import Enum
from pathlib import Path
from typing import Optional

from config_loader import get_config, get_value, get_pattern_pairs

_CFG = get_config()


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class Finding:
    rule_id: str
    rule_name: str
    severity: str
    file_path: str
    line_number: int
    code_snippet: str
    description: str
    remediation: str
    auto_fixable: bool = False
    auto_fix_type: Optional[str] = None


@dataclass
class GovernanceReport:
    files_scanned: int = 0
    total_findings: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    findings: list = field(default_factory=list)
    auto_fixable_count: int = 0
    blocks_merge: bool = False
    guardrails_present: bool = False
    guardrails_intact: bool = False


GUARDRAILS_MARKER_START = "<!-- GUARDRAILS START"
GUARDRAILS_MARKER_END = "<!-- GUARDRAILS END -->"

REQUIRED_CLAUDE_MD_SECTIONS = get_value(_CFG, "governance", "required_claude_md_sections", default=[
    "Sensitive File Access", "Client Confidential Data", "Credentials and Connection Strings",
    "SQL Safety", "Dangerous", "Frontend Security", "Git Operations", "Destructive Commands",
    "Database Safety", "Network Requests", "Code Quality", "Data Exfiltration", "Package",
    "Scope", "Environment Isolation", "Resource Limits", "Compliance", "When in Doubt",
])

REQUIRED_DENY_RULES = get_value(_CFG, "governance", "required_deny_rules", default=[
    "Read(**/.env)", "Read(**/.env.*)", "Read(**/credentials.json)", "Read(**/*secret*)",
    "Bash(rm -rf *)", "Bash(sudo *)", "Bash(git *)", "Bash(chmod 777 *)",
])

REQUIRED_HOOKS = get_value(_CFG, "governance", "required_hooks", default=[
    "block-sensitive-files.sh", "block-dangerous-commands.sh", "block-git-commands.sh",
    "block-data-exfiltration.sh", "block-package-install.sh", "block-scope-escape.sh",
    "block-environment-escape.sh", "block-pii-leakage.sh",
])

GITIGNORE_REQUIRED = get_value(_CFG, "governance", "gitignore_required", default=[
    ".env", "credentials.json", "*.pem", "*.key", "secrets/",
])

ENV_FILE_PATTERNS = get_value(_CFG, "governance", "env_file_patterns", default=[
    r"^\.env$", r"^\.env\..*$", r"^\.env\.local$", r"^\.env\.production$", r"^\.env\.staging$",
])

_BUILTIN_CLIENT_DATA = [
    (r"[a-zA-Z0-9._%+-]+@(?!example\.com|test\.com|noreply)[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", "Possible real email address"),
    (r"(?:CONFIDENTIAL|INTERNAL[- ]ONLY|DO NOT DISTRIBUTE)", "Confidentiality marker in code"),
]
CLIENT_DATA_PATTERNS = get_pattern_pairs(_CFG, "governance", "client_data_patterns", default=_BUILTIN_CLIENT_DATA)

CLIENT_DATA_SKIP_WORDS = get_value(_CFG, "governance", "client_data_skip_words", default=[
    "example", "test", "mock", "sample", "placeholder", "todo", "fixme", "xxx", "your-",
])

SKIP_DIRS = set(get_value(_CFG, "skip_dirs", default=[
    "node_modules", ".git", "__pycache__", ".venv", "venv",
    "env", "dist", "build", ".next", ".nuxt",
    "vendor", "target", ".tox", ".mypy_cache", ".pytest_cache",
]))

SCAN_EXTENSIONS = set(get_value(_CFG, "scan_extensions", default=[
    ".py", ".js", ".ts", ".jsx", ".tsx",
    ".java", ".go", ".rb", ".php",
    ".c", ".h", ".cpp", ".hpp", ".cc", ".cxx",
    ".yml", ".yaml", ".toml", ".json", ".cfg", ".ini", ".conf",
    ".sh", ".bash", ".sql", ".md",
]))


def get_pr_changed_files(base_branch: str = "main") -> list[str]:
    """Get files changed in the current PR."""
    try:
        result = subprocess.run(
            ["git", "diff", "--name-only", "--diff-filter=ACMR", base_branch],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode == 0 and result.stdout.strip():
            return [f.strip() for f in result.stdout.strip().split("\n") if f.strip()]
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass
    return []


def check_claude_md(root_dir: str) -> list[Finding]:
    """Check if CLAUDE.md exists and contains guardrails sections."""
    findings = []
    claude_md_path = os.path.join(root_dir, "CLAUDE.md")

    if not os.path.exists(claude_md_path):
        findings.append(Finding(
            rule_id="GOV-001",
            rule_name="CLAUDE.md missing",
            severity=Severity.CRITICAL,
            file_path="CLAUDE.md",
            line_number=0,
            code_snippet="",
            description="CLAUDE.md file does not exist at the project root. AI guardrails are not active.",
            remediation="Run ./ai-guardrails/install.sh to install guardrails, or copy CLAUDE.md from the ai-guardrails repo.",
            auto_fixable=True,
            auto_fix_type="restore_claude_md",
        ))
        return findings

    with open(claude_md_path, "r", errors="ignore") as f:
        content = f.read()

    if GUARDRAILS_MARKER_START not in content:
        findings.append(Finding(
            rule_id="GOV-001a",
            rule_name="CLAUDE.md missing guardrails markers",
            severity=Severity.HIGH,
            file_path="CLAUDE.md",
            line_number=1,
            code_snippet="Missing: <!-- GUARDRAILS START ... -->",
            description="CLAUDE.md exists but does not contain guardrails markers. Guardrails may not be installed.",
            remediation="Run ./ai-guardrails/install.sh to merge guardrails into the existing CLAUDE.md.",
            auto_fixable=True,
            auto_fix_type="restore_claude_md",
        ))
        return findings

    missing_sections = []
    for section in REQUIRED_CLAUDE_MD_SECTIONS:
        if section.lower() not in content.lower():
            missing_sections.append(section)

    if missing_sections:
        findings.append(Finding(
            rule_id="GOV-001b",
            rule_name="CLAUDE.md missing sections",
            severity=Severity.HIGH,
            file_path="CLAUDE.md",
            line_number=1,
            code_snippet=f"Missing: {', '.join(missing_sections[:5])}{'...' if len(missing_sections) > 5 else ''}",
            description=f"CLAUDE.md is missing {len(missing_sections)} required guardrail section(s): {', '.join(missing_sections)}",
            remediation="Run ./ai-guardrails/install.sh to restore the complete guardrails section.",
            auto_fixable=True,
            auto_fix_type="restore_claude_md",
        ))

    return findings


def check_settings_json(root_dir: str) -> list[Finding]:
    """Check if .claude/settings.json exists with required deny rules."""
    findings = []
    settings_path = os.path.join(root_dir, ".claude", "settings.json")

    if not os.path.exists(settings_path):
        findings.append(Finding(
            rule_id="GOV-002",
            rule_name="settings.json missing",
            severity=Severity.CRITICAL,
            file_path=".claude/settings.json",
            line_number=0,
            code_snippet="",
            description=".claude/settings.json does not exist. Permission deny rules are not active.",
            remediation="Run ./ai-guardrails/install.sh to install settings.json.",
            auto_fixable=True,
            auto_fix_type="restore_settings",
        ))
        return findings

    try:
        with open(settings_path, "r") as f:
            settings = json.load(f)
    except (json.JSONDecodeError, OSError):
        findings.append(Finding(
            rule_id="GOV-002a",
            rule_name="settings.json invalid",
            severity=Severity.CRITICAL,
            file_path=".claude/settings.json",
            line_number=1,
            code_snippet="Invalid JSON",
            description=".claude/settings.json exists but contains invalid JSON.",
            remediation="Run ./ai-guardrails/install.sh to restore settings.json.",
            auto_fixable=True,
            auto_fix_type="restore_settings",
        ))
        return findings

    deny_rules = settings.get("permissions", {}).get("deny", [])
    missing_rules = [r for r in REQUIRED_DENY_RULES if r not in deny_rules]

    if missing_rules:
        findings.append(Finding(
            rule_id="GOV-002b",
            rule_name="settings.json missing deny rules",
            severity=Severity.HIGH,
            file_path=".claude/settings.json",
            line_number=1,
            code_snippet=f"Missing: {', '.join(missing_rules[:4])}{'...' if len(missing_rules) > 4 else ''}",
            description=f"settings.json is missing {len(missing_rules)} required deny rule(s).",
            remediation="Run ./ai-guardrails/install.sh to merge missing deny rules.",
            auto_fixable=True,
            auto_fix_type="restore_settings",
        ))

    return findings


def check_hook_scripts(root_dir: str) -> list[Finding]:
    """Check if hook scripts exist in .claude/hooks/."""
    findings = []
    hooks_dir = os.path.join(root_dir, ".claude", "hooks")

    if not os.path.isdir(hooks_dir):
        findings.append(Finding(
            rule_id="GOV-003",
            rule_name="Hook scripts directory missing",
            severity=Severity.CRITICAL,
            file_path=".claude/hooks/",
            line_number=0,
            code_snippet="",
            description=".claude/hooks/ directory does not exist. Hook-based enforcement is not active.",
            remediation="Run ./ai-guardrails/install.sh to install hook scripts.",
            auto_fixable=True,
            auto_fix_type="restore_hooks",
        ))
        return findings

    missing_hooks = []
    for hook in REQUIRED_HOOKS:
        hook_path = os.path.join(hooks_dir, hook)
        if not os.path.exists(hook_path):
            missing_hooks.append(hook)

    if missing_hooks:
        findings.append(Finding(
            rule_id="GOV-003a",
            rule_name="Hook scripts missing",
            severity=Severity.HIGH,
            file_path=".claude/hooks/",
            line_number=0,
            code_snippet=f"Missing: {', '.join(missing_hooks[:4])}{'...' if len(missing_hooks) > 4 else ''}",
            description=f"{len(missing_hooks)} required hook script(s) missing from .claude/hooks/.",
            remediation="Run ./ai-guardrails/install.sh to install missing hook scripts.",
            auto_fixable=True,
            auto_fix_type="restore_hooks",
        ))

    return findings


def check_pr_modifies_guardrails(changed_files: list[str]) -> list[Finding]:
    """Check if the PR modifies any guardrail files."""
    findings = []
    guardrail_patterns = [
        r"^\.claude/",
        r"^CLAUDE\.md$",
    ]

    modified_guardrails = []
    for filepath in changed_files:
        for pattern in guardrail_patterns:
            if re.search(pattern, filepath):
                modified_guardrails.append(filepath)
                break

    if modified_guardrails:
        findings.append(Finding(
            rule_id="GOV-004",
            rule_name="PR modifies guardrail files",
            severity=Severity.CRITICAL,
            file_path=modified_guardrails[0],
            line_number=0,
            code_snippet=f"Modified: {', '.join(modified_guardrails)}",
            description=f"This PR modifies {len(modified_guardrails)} guardrail file(s). Guardrail files are centrally managed and should not be modified per-repo.",
            remediation="Revert changes to guardrail files. If changes are intentional, get approval from the AI team.",
        ))

    return findings


def check_env_files(root_dir: str) -> list[Finding]:
    """Scan entire repo for .env files that should not be committed."""
    findings = []

    for dirpath, dirnames, filenames in os.walk(root_dir):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for filename in filenames:
            for pattern in ENV_FILE_PATTERNS:
                if re.match(pattern, filename):
                    rel_path = os.path.relpath(os.path.join(dirpath, filename), root_dir)
                    findings.append(Finding(
                        rule_id="GOV-005",
                        rule_name="Environment file in repository",
                        severity=Severity.CRITICAL,
                        file_path=rel_path,
                        line_number=0,
                        code_snippet=f"File: {filename}",
                        description=f"Environment file '{rel_path}' should not be in the repository. It may contain secrets.",
                        remediation="Remove this file from version control and add it to .gitignore.",
                        auto_fixable=True,
                        auto_fix_type="add_to_gitignore",
                    ))
                    break

    return findings


def check_gitignore(root_dir: str) -> list[Finding]:
    """Check if .gitignore has required entries."""
    findings = []
    gitignore_path = os.path.join(root_dir, ".gitignore")

    if not os.path.exists(gitignore_path):
        findings.append(Finding(
            rule_id="GOV-006",
            rule_name="Missing .gitignore",
            severity=Severity.MEDIUM,
            file_path=".gitignore",
            line_number=0,
            code_snippet="",
            description=".gitignore file does not exist. Sensitive files may be committed accidentally.",
            remediation="Create a .gitignore with entries for .env, credentials.json, *.pem, *.key, secrets/",
            auto_fixable=True,
            auto_fix_type="create_gitignore",
        ))
        return findings

    with open(gitignore_path, "r", errors="ignore") as f:
        content = f.read()

    missing = [entry for entry in GITIGNORE_REQUIRED if entry not in content]
    if missing:
        findings.append(Finding(
            rule_id="GOV-006a",
            rule_name="Missing .gitignore entries",
            severity=Severity.MEDIUM,
            file_path=".gitignore",
            line_number=0,
            code_snippet=f"Missing: {', '.join(missing)}",
            description=f".gitignore is missing entries for: {', '.join(missing)}",
            remediation=f"Add the following to .gitignore: {', '.join(missing)}",
            auto_fixable=True,
            auto_fix_type="update_gitignore",
        ))

    return findings


def check_client_data_patterns(root_dir: str) -> list[Finding]:
    """Scan code for patterns that look like real client data."""
    findings = []

    for dirpath, dirnames, filenames in os.walk(root_dir):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for filename in filenames:
            filepath = os.path.join(dirpath, filename)
            if Path(filepath).suffix not in SCAN_EXTENSIONS:
                continue

            try:
                with open(filepath, "r", errors="ignore") as f:
                    lines = f.readlines()
            except (OSError, IOError):
                continue

            for line_num, line in enumerate(lines, 1):
                for pattern, name in CLIENT_DATA_PATTERNS:
                    if re.search(pattern, line, re.IGNORECASE):
                        if any(skip in line.lower() for skip in CLIENT_DATA_SKIP_WORDS):
                            continue
                        rel_path = os.path.relpath(filepath, root_dir)
                        findings.append(Finding(
                            rule_id="GOV-007",
                            rule_name=f"Possible client data: {name}",
                            severity=Severity.MEDIUM,
                            file_path=rel_path,
                            line_number=line_num,
                            code_snippet=line.strip()[:120],
                            description=f"{name} detected. Real client data should never appear in code.",
                            remediation="Replace with anonymised test data or remove. Flag for human review if unsure.",
                        ))

    return findings


def run_scan(root_dir: str = ".", base_branch: str = "main") -> GovernanceReport:
    """Run the full governance check and return a report."""
    report = GovernanceReport()
    all_findings = []

    changed_files = get_pr_changed_files(base_branch)

    # Guardrail file checks
    claude_findings = check_claude_md(root_dir)
    settings_findings = check_settings_json(root_dir)
    hooks_findings = check_hook_scripts(root_dir)
    all_findings.extend(claude_findings)
    all_findings.extend(settings_findings)
    all_findings.extend(hooks_findings)

    report.guardrails_present = (
        len(claude_findings) == 0
        and len(settings_findings) == 0
        and len(hooks_findings) == 0
    )

    # PR modification check
    all_findings.extend(check_pr_modifies_guardrails(changed_files))

    # Repo-wide checks
    all_findings.extend(check_env_files(root_dir))
    all_findings.extend(check_gitignore(root_dir))
    all_findings.extend(check_client_data_patterns(root_dir))

    # Count files scanned
    for dirpath, dirnames, filenames in os.walk(root_dir):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for filename in filenames:
            if Path(os.path.join(dirpath, filename)).suffix in SCAN_EXTENSIONS:
                report.files_scanned += 1

    for f in all_findings:
        if f.severity == Severity.CRITICAL:
            report.critical_count += 1
        elif f.severity == Severity.HIGH:
            report.high_count += 1
        elif f.severity == Severity.MEDIUM:
            report.medium_count += 1
        elif f.severity == Severity.LOW:
            report.low_count += 1
        if f.auto_fixable:
            report.auto_fixable_count += 1

    report.total_findings = len(all_findings)
    report.findings = [asdict(f) for f in all_findings]
    report.blocks_merge = report.critical_count > 0 or report.high_count > 0
    report.guardrails_intact = report.guardrails_present and not report.blocks_merge

    return report


def main():
    """Entry point for the governance check scanner."""
    root_dir = os.environ.get("SCAN_ROOT", ".")
    base_branch = os.environ.get("BASE_BRANCH", "main")
    output_file = os.environ.get("GOVERNANCE_REPORT_OUTPUT", "governance-report.json")

    print(f"Running governance check on: {root_dir}")
    report = run_scan(root_dir, base_branch)

    with open(output_file, "w") as f:
        json.dump(asdict(report), f, indent=2)

    print(f"\nGovernance check complete: {report.files_scanned} files scanned")
    print(f"  Guardrails present: {'Yes' if report.guardrails_present else 'No'}")
    print(f"  Critical: {report.critical_count}")
    print(f"  High:     {report.high_count}")
    print(f"  Medium:   {report.medium_count}")
    print(f"  Low:      {report.low_count}")
    print(f"  Auto-fixable: {report.auto_fixable_count}")
    print(f"\nReport saved to: {output_file}")

    if report.blocks_merge:
        print("\nRESULT: FAIL -- Governance violations found. PR should not be merged.")
        sys.exit(1)
    else:
        print("\nRESULT: PASS -- Governance check passed.")
        sys.exit(0)


if __name__ == "__main__":
    main()
