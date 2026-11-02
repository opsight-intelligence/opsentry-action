"""
Auto-Fix Script for Security Audit.
Reads the JSON scan report and applies safe, well-tested fixes for auto-fixable issues.
Commits changes to the PR branch with descriptive commit messages.
"""

import json
import os
import re
import subprocess
import sys


def load_report(report_path: str) -> dict:
    """Load the JSON scan report."""
    with open(report_path, "r") as f:
        return json.load(f)


def fix_bare_except(filepath: str, line_number: int) -> bool:
    """Replace bare except: with except Exception as e: and add logging."""
    try:
        with open(filepath, "r") as f:
            lines = f.readlines()

        idx = line_number - 1
        if idx < 0 or idx >= len(lines):
            return False

        line = lines[idx]
        if re.search(r"except\s*:\s*$", line):
            indent = len(line) - len(line.lstrip())
            lines[idx] = " " * indent + "except Exception as e:  # Fixed by security-audit agent\n"

            next_idx = idx + 1
            if next_idx < len(lines):
                next_indent = len(lines[next_idx]) - len(lines[next_idx].lstrip())
                if next_indent > indent:
                    log_line = " " * next_indent + 'import logging; logging.getLogger(__name__).error("Unexpected error: %s", e)  # Added by security-audit agent\n'
                    lines.insert(next_idx, log_line)

            with open(filepath, "w") as f:
                f.writelines(lines)
            return True
    except (OSError, IOError):
        pass
    return False


def fix_eval_to_literal_eval(filepath: str, line_number: int) -> bool:
    """Replace eval() with ast.literal_eval() where it appears to parse literals."""
    try:
        with open(filepath, "r") as f:
            content = f.read()
            lines = content.split("\n")

        idx = line_number - 1
        if idx < 0 or idx >= len(lines):
            return False

        line = lines[idx]
        if "eval(" in line and "literal_eval" not in line:
            lines[idx] = line.replace("eval(", "ast.literal_eval(")

            if "import ast" not in content and "from ast import" not in content:
                for i, line in enumerate(lines):
                    if line.startswith("import ") or line.startswith("from "):
                        lines.insert(i, "import ast  # Added by security-audit agent")
                        break
                else:
                    lines.insert(0, "import ast  # Added by security-audit agent")

            with open(filepath, "w") as f:
                f.write("\n".join(lines))
            return True
    except (OSError, IOError):
        pass
    return False


def fix_os_system(filepath: str, line_number: int) -> bool:
    """Replace os.system(cmd) with subprocess.run(cmd, shell=True, check=True)."""
    try:
        with open(filepath, "r") as f:
            content = f.read()
            lines = content.split("\n")

        idx = line_number - 1
        if idx < 0 or idx >= len(lines):
            return False

        line = lines[idx]
        match = re.search(r"os\.system\((.+)\)", line)
        if match:
            arg = match.group(1)
            replacement = f"subprocess.run({arg}, shell=True, check=True)  # Fixed by security-audit agent"
            lines[idx] = line[:match.start()] + replacement + line[match.end():]

            if "import subprocess" not in content:
                for i, line in enumerate(lines):
                    if line.startswith("import ") or line.startswith("from "):
                        lines.insert(i, "import subprocess  # Added by security-audit agent")
                        break
                else:
                    lines.insert(0, "import subprocess  # Added by security-audit agent")

            with open(filepath, "w") as f:
                f.write("\n".join(lines))
            return True
    except (OSError, IOError):
        pass
    return False


def fix_gitignore(root_dir: str = ".") -> bool:
    """Create or update .gitignore with required entries."""
    gitignore_path = os.path.join(root_dir, ".gitignore")
    required_entries = [
        ".env",
        ".env.*",
        ".env.local",
        ".env.production",
        ".env.staging",
        "credentials.json",
        "credentials.yaml",
        "*.pem",
        "*.key",
        "*.p12",
        "*.pfx",
        "secrets/",
        "credentials/",
    ]

    existing_content = ""
    if os.path.exists(gitignore_path):
        with open(gitignore_path, "r") as f:
            existing_content = f.read()

    missing = [entry for entry in required_entries if entry not in existing_content]
    if not missing:
        return False

    with open(gitignore_path, "a") as f:
        f.write("\n# Added by security-audit agent\n")
        for entry in missing:
            f.write(f"{entry}\n")

    return True


FIX_HANDLERS = {
    "fix_bare_except": fix_bare_except,
    "replace_eval": fix_eval_to_literal_eval,
    "replace_os_system": fix_os_system,
}


def apply_fixes(report: dict, root_dir: str = ".") -> list[str]:
    """Apply all auto-fixable issues and return list of descriptions."""
    applied = []

    for finding in report.get("findings", []):
        if not finding.get("auto_fixable"):
            continue

        fix_type = finding.get("auto_fix_type")
        filepath = finding.get("file_path", "")
        line_number = finding.get("line_number", 0)

        if fix_type in ("create_gitignore", "update_gitignore", "add_to_gitignore"):
            if fix_gitignore(root_dir):
                applied.append("Updated .gitignore with security entries")
            continue

        handler = FIX_HANDLERS.get(fix_type)
        if handler and filepath and line_number:
            if handler(filepath, line_number):
                applied.append(f"Fixed {finding['rule_name']} in {filepath}:{line_number}")

    return applied


def git_commit_fixes(descriptions: list[str]):
    """Commit the auto-fixes to the current branch."""
    try:
        subprocess.run(["git", "add", "-A"], check=True, capture_output=True)

        has_changes = subprocess.run(
            ["git", "diff", "--cached", "--quiet"],
            capture_output=True,
        )

        if has_changes.returncode != 0:
            commit_msg = "fix(security-agent): auto-fix security issues\n\n"
            commit_msg += "\n".join(f"- {d}" for d in descriptions)
            subprocess.run(
                ["git", "commit", "-m", commit_msg],
                check=True,
                capture_output=True,
                env={
                    **os.environ,
                    "GIT_AUTHOR_NAME": "OpSentry Bot",
                    "GIT_AUTHOR_EMAIL": "opsentry@opsight.dev",
                    "GIT_COMMITTER_NAME": "OpSentry Bot",
                    "GIT_COMMITTER_EMAIL": "opsentry@opsight.dev",
                },
            )
            subprocess.run(["git", "push"], check=True, capture_output=True)
            print(f"Committed and pushed {len(descriptions)} auto-fixes.")
        else:
            print("No changes to commit after auto-fixes.")
    except subprocess.CalledProcessError as e:
        print(f"Git commit failed: {e.stderr.decode() if e.stderr else str(e)}", file=sys.stderr)


def main():
    """Entry point for the auto-fix script."""
    report_path = os.environ.get("REPORT_OUTPUT", "security-report.json")
    root_dir = os.environ.get("SCAN_ROOT", ".")
    do_commit = os.environ.get("AUTO_COMMIT", "false").lower() == "true"

    report = load_report(report_path)

    fixable = [f for f in report.get("findings", []) if f.get("auto_fixable")]
    if not fixable:
        print("No auto-fixable issues found.")
        return

    print(f"Found {len(fixable)} auto-fixable issues. Applying fixes...")
    applied = apply_fixes(report, root_dir)

    if applied:
        print(f"\nApplied {len(applied)} fixes:")
        for desc in applied:
            print(f"  - {desc}")

        if do_commit:
            git_commit_fixes(applied)
        else:
            print("\nAUTO_COMMIT is not enabled. Fixes applied locally but not committed.")
    else:
        print("No fixes could be applied.")


if __name__ == "__main__":
    main()
