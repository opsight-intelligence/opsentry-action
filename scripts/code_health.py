"""
Code Health Scanner for CI/CD Pipeline.
Scans source files for code quality issues using regex and optional LLM analysis.
Outputs a structured JSON report of findings grouped by severity.
"""

import json
import os
import re
import sys
import ast
from dataclasses import dataclass, field, asdict
from enum import Enum
from pathlib import Path
from typing import Optional

from config_loader import get_config, get_value, is_false_positive

_CFG = get_config()


class Severity(str, Enum):
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
    auto_fix_content: Optional[str] = None


@dataclass
class CodeHealthReport:
    files_scanned: int = 0
    total_findings: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    findings: list = field(default_factory=list)
    auto_fixable_count: int = 0
    blocks_merge: bool = False
    health_score: str = "A"
    llm_calls_made: int = 0
    llm_tokens_used: int = 0
    suppressed_count: int = 0
    scan_duration_seconds: float = 0.0


MAX_FILE_LINES = get_value(_CFG, "code_health", "max_file_lines", default=500)
MAX_FUNCTION_LINES = get_value(_CFG, "code_health", "max_function_lines", default=50)
DEAD_CODE_THRESHOLD = get_value(_CFG, "code_health", "dead_code_threshold", default=3)

SCAN_EXTENSIONS = set(get_value(_CFG, "scan_extensions", default=[
    ".py", ".js", ".ts", ".jsx", ".tsx",
    ".java",
    ".c", ".h", ".cpp", ".hpp", ".cc", ".cxx",
]))

SKIP_DIRS = set(get_value(_CFG, "skip_dirs", default=[
    "node_modules", ".git", "__pycache__", ".venv", "venv",
    "env", "dist", "build", ".next", ".nuxt",
    "vendor", "target", ".tox", ".mypy_cache", ".pytest_cache",
    "migrations", "alembic",
]))

IO_IMPORT_PATTERNS = get_value(_CFG, "code_health", "io_import_patterns", default=[
    r"(?:from\s+|import\s+)(?:snowflake|mysql|psycopg2|sqlalchemy|pymongo)",
    r"(?:from\s+|import\s+)(?:requests|httpx|aiohttp|urllib)",
    r"(?:from\s+|import\s+)(?:boto3|botocore)",
    r"(?:from\s+|import\s+)(?:fastapi|flask|django)",
])

MAGIC_NUMBER_PATTERN = r"(?<!=\s)(?<!\w)(?<!\.)\b(\d+)\b(?!\s*[=:])"
MAGIC_NUMBER_ALLOWED = set(get_value(_CFG, "code_health", "magic_number_allowed", default=[0, 1, -1, 2, 10, 100, 1000, 60, 24, 365, 200, 201, 400, 401, 403, 404, 500]))


def get_changed_files(base_branch: str = "main") -> list[str]:
    """Get list of files changed compared to base branch."""
    try:
        import subprocess
        result = subprocess.run(
            ["git", "diff", "--name-only", "--diff-filter=ACMR", base_branch],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode == 0 and result.stdout.strip():
            return [f.strip() for f in result.stdout.strip().split("\n") if f.strip()]
    except (Exception,):
        pass
    return []


def get_all_files(root_dir: str = ".") -> list[str]:
    """Get all scannable files."""
    files = []
    for dirpath, dirnames, filenames in os.walk(root_dir):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for filename in filenames:
            filepath = os.path.join(dirpath, filename)
            if Path(filepath).suffix in SCAN_EXTENSIONS:
                files.append(filepath)
    return files


def check_file_length(filepath: str, lines: list[str]) -> list[Finding]:
    """Check if file exceeds MAX_FILE_LINES."""
    findings = []
    if len(lines) > MAX_FILE_LINES:
        findings.append(Finding(
            rule_id="CH-001",
            rule_name="500-Line Shield violated",
            severity=Severity.HIGH,
            file_path=filepath,
            line_number=1,
            code_snippet=f"File has {len(lines)} lines (limit: {MAX_FILE_LINES})",
            description=f"File exceeds {MAX_FILE_LINES} lines ({len(lines)} lines). Large files are harder to review, test, and maintain.",
            remediation="Split this file into smaller modules based on responsibility. Extract related functions/classes into separate files.",
        ))
    return findings


def check_python_functions(filepath: str, content: str, lines: list[str]) -> list[Finding]:
    """Check Python function sizes and missing docstrings using AST."""
    findings = []
    try:
        tree = ast.parse(content)
    except SyntaxError:
        return findings

    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            func_lines = (node.end_lineno or node.lineno) - node.lineno + 1
            if func_lines > MAX_FUNCTION_LINES:
                findings.append(Finding(
                    rule_id="CH-003",
                    rule_name="Function size limit exceeded",
                    severity=Severity.MEDIUM,
                    file_path=filepath,
                    line_number=node.lineno,
                    code_snippet=f"def {node.name}() — {func_lines} lines (limit: {MAX_FUNCTION_LINES})",
                    description=f"Function '{node.name}' is {func_lines} lines long. Large functions are hard to understand and test.",
                    remediation=f"Extract parts of '{node.name}' into smaller helper functions.",
                ))

            if not ast.get_docstring(node):
                is_public = not node.name.startswith("_")
                if is_public:
                    findings.append(Finding(
                        rule_id="CH-004a",
                        rule_name="Missing function docstring",
                        severity=Severity.MEDIUM,
                        file_path=filepath,
                        line_number=node.lineno,
                        code_snippet=f"def {node.name}()",
                        description=f"Public function '{node.name}' has no docstring.",
                        remediation=f"Add a docstring describing what '{node.name}' does, its parameters, and return value.",
                        auto_fixable=True,
                        auto_fix_type="add_function_docstring",
                    ))

            for arg in node.args.args:
                if arg.arg != "self" and arg.arg != "cls" and not arg.annotation:
                    is_public = not node.name.startswith("_")
                    if is_public:
                        findings.append(Finding(
                            rule_id="CH-008",
                            rule_name="Missing type hint",
                            severity=Severity.LOW,
                            file_path=filepath,
                            line_number=node.lineno,
                            code_snippet=f"def {node.name}(..., {arg.arg}, ...)",
                            description=f"Parameter '{arg.arg}' in function '{node.name}' has no type hint.",
                            remediation=f"Add a type annotation: {arg.arg}: <type>",
                        ))
                        break

            if not node.returns:
                is_public = not node.name.startswith("_")
                if is_public and node.name != "__init__":
                    findings.append(Finding(
                        rule_id="CH-008b",
                        rule_name="Missing return type hint",
                        severity=Severity.LOW,
                        file_path=filepath,
                        line_number=node.lineno,
                        code_snippet=f"def {node.name}(...)",
                        description=f"Function '{node.name}' has no return type annotation.",
                        remediation=f"Add a return type: def {node.name}(...) -> <type>:",
                    ))

        if isinstance(node, ast.ClassDef):
            if not ast.get_docstring(node):
                is_public = not node.name.startswith("_")
                if is_public:
                    findings.append(Finding(
                        rule_id="CH-004b",
                        rule_name="Missing class docstring",
                        severity=Severity.MEDIUM,
                        file_path=filepath,
                        line_number=node.lineno,
                        code_snippet=f"class {node.name}",
                        description=f"Public class '{node.name}' has no docstring.",
                        remediation=f"Add a docstring describing the purpose of '{node.name}'.",
                        auto_fixable=True,
                        auto_fix_type="add_class_docstring",
                    ))

    return findings


def check_module_docstring(filepath: str, content: str) -> list[Finding]:
    """Check if Python file has a module-level docstring."""
    findings = []
    if not filepath.endswith(".py"):
        return findings

    try:
        tree = ast.parse(content)
        if not ast.get_docstring(tree):
            findings.append(Finding(
                rule_id="CH-004",
                rule_name="Missing module docstring",
                severity=Severity.MEDIUM,
                file_path=filepath,
                line_number=1,
                code_snippet=f"File: {os.path.basename(filepath)}",
                description="File is missing a module-level docstring. Every file should start with a 3-sentence summary.",
                remediation="Add a module docstring at the top of the file describing its purpose.",
                auto_fixable=True,
                auto_fix_type="add_module_docstring",
            ))
    except SyntaxError:
        pass

    return findings


def check_dead_code(filepath: str, lines: list[str]) -> list[Finding]:
    """Check for blocks of commented-out code."""
    findings = []
    consecutive_comments = 0
    block_start = 0

    code_comment_pattern = re.compile(
        r"^\s*#\s*(?:def |class |if |for |while |return |import |from |try:|except|raise |"
        r"with |print\(|self\.|[a-zA-Z_]\w*\s*[=(]|[a-zA-Z_]\w*\.[a-zA-Z_])"
    )

    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if code_comment_pattern.match(stripped):
            if consecutive_comments == 0:
                block_start = i
            consecutive_comments += 1
        else:
            if consecutive_comments >= DEAD_CODE_THRESHOLD:
                findings.append(Finding(
                    rule_id="CH-005",
                    rule_name="Dead code (commented out)",
                    severity=Severity.MEDIUM,
                    file_path=filepath,
                    line_number=block_start,
                    code_snippet=f"{consecutive_comments} consecutive lines of commented-out code (lines {block_start}-{block_start + consecutive_comments - 1})",
                    description=f"Block of {consecutive_comments} commented-out code lines. Dead code clutters the codebase and confuses readers.",
                    remediation="Remove commented-out code. Use version control to recover old code if needed.",
                    auto_fixable=True,
                    auto_fix_type="remove_dead_code",
                ))
            consecutive_comments = 0

    if consecutive_comments >= DEAD_CODE_THRESHOLD:
        findings.append(Finding(
            rule_id="CH-005",
            rule_name="Dead code (commented out)",
            severity=Severity.MEDIUM,
            file_path=filepath,
            line_number=block_start,
            code_snippet=f"{consecutive_comments} consecutive lines of commented-out code",
            description=f"Block of {consecutive_comments} commented-out code lines at end of file.",
            remediation="Remove commented-out code. Use version control to recover old code if needed.",
            auto_fixable=True,
            auto_fix_type="remove_dead_code",
        ))

    return findings


def check_bare_except(filepath: str, lines: list[str]) -> list[Finding]:
    """Check for bare except clauses."""
    findings = []
    for i, line in enumerate(lines, 1):
        if re.search(r"except\s*:\s*$", line):
            findings.append(Finding(
                rule_id="CH-006",
                rule_name="Bare except clause",
                severity=Severity.MEDIUM,
                file_path=filepath,
                line_number=i,
                code_snippet=line.strip()[:120],
                description="Bare except: catches all exceptions. Use specific exception types.",
                remediation="Replace with: except SpecificException as e:",
                auto_fixable=True,
                auto_fix_type="fix_bare_except",
            ))
    return findings


def check_io_separation(filepath: str, lines: list[str]) -> list[Finding]:
    """Check if I/O imports exist in files that look like pure logic modules."""
    findings = []
    filename = os.path.basename(filepath)

    io_indicators = ["utils", "helpers", "calculator", "parser", "validator", "formatter", "converter", "processor"]
    is_likely_pure = any(ind in filename.lower() for ind in io_indicators)

    if not is_likely_pure:
        return findings

    for i, line in enumerate(lines, 1):
        for pattern in IO_IMPORT_PATTERNS:
            if re.search(pattern, line):
                findings.append(Finding(
                    rule_id="CH-010",
                    rule_name="I/O import in pure logic module",
                    severity=Severity.LOW,
                    file_path=filepath,
                    line_number=i,
                    code_snippet=line.strip()[:120],
                    description=f"File '{filename}' appears to be a pure logic module but imports I/O libraries.",
                    remediation="Move I/O operations to a separate module. Pass data into this module as function arguments.",
                ))
                break

    return findings


def check_missing_tests(filepath: str, root_dir: str = ".") -> list[Finding]:
    """Check if a Python module has a corresponding test file."""
    findings = []
    if not filepath.endswith(".py"):
        return findings

    filename = os.path.basename(filepath)
    if filename.startswith("test_") or filename.endswith("_test.py") or filename == "__init__.py":
        return findings
    if any(skip in filepath for skip in ["test", "migration", "alembic", "config"]):
        return findings

    stem = Path(filepath).stem
    test_patterns = [
        f"test_{stem}.py",
        f"{stem}_test.py",
        f"test_{stem}.ts",
        f"{stem}.test.ts",
        f"{stem}.spec.ts",
    ]

    found_test = False
    for dirpath, _, filenames in os.walk(root_dir):
        for fn in filenames:
            if fn in test_patterns:
                found_test = True
                break
        if found_test:
            break

    if not found_test:
        findings.append(Finding(
            rule_id="CH-002",
            rule_name="Missing test file",
            severity=Severity.HIGH,
            file_path=filepath,
            line_number=1,
            code_snippet=f"No test file found for {filename}",
            description=f"Module '{filename}' has no corresponding test file.",
            remediation=f"Create a test file: test_{stem}.py with tests for the public functions in this module.",
        ))

    return findings


def check_java_functions(filepath: str, lines: list[str]) -> list[Finding]:
    """Check Java method sizes and missing Javadoc using brace counting."""
    findings = []
    if not filepath.endswith(".java"):
        return findings

    method_pattern = re.compile(
        r"^\s*(?:public|private|protected|static|\s)*\s+"
        r"(?:void|int|long|float|double|boolean|char|byte|short|String|List|Map|Set|Optional|\w+(?:<[^>]+>)?)\s+"
        r"(\w+)\s*\("
    )

    i = 0
    while i < len(lines):
        match = method_pattern.match(lines[i])
        if match:
            method_name = match.group(1)
            method_start = i + 1
            brace_count = 0
            found_open = False
            j = i
            while j < len(lines):
                brace_count += lines[j].count("{") - lines[j].count("}")
                if "{" in lines[j]:
                    found_open = True
                if found_open and brace_count <= 0:
                    method_lines = j - i + 1
                    if method_lines > MAX_FUNCTION_LINES:
                        findings.append(Finding(
                            rule_id="CH-003",
                            rule_name="Function size limit exceeded",
                            severity=Severity.MEDIUM,
                            file_path=filepath,
                            line_number=method_start,
                            code_snippet=f"{method_name}() -- {method_lines} lines (limit: {MAX_FUNCTION_LINES})",
                            description=f"Java method '{method_name}' is {method_lines} lines long.",
                            remediation=f"Extract parts of '{method_name}' into smaller helper methods.",
                        ))
                    break
                j += 1
        i += 1

    # Check for missing Javadoc on public methods
    for i, line in enumerate(lines):
        if re.match(r"\s*public\s+", line) and "class " not in line:
            has_javadoc = False
            j = i - 1
            while j >= 0 and lines[j].strip() == "":
                j -= 1
            if j >= 0 and (lines[j].strip().endswith("*/") or lines[j].strip().startswith("*")):
                has_javadoc = True
            if not has_javadoc:
                method_match = re.search(r"(\w+)\s*\(", line)
                name = method_match.group(1) if method_match else "unknown"
                findings.append(Finding(
                    rule_id="CH-004a",
                    rule_name="Missing Javadoc",
                    severity=Severity.MEDIUM,
                    file_path=filepath,
                    line_number=i + 1,
                    code_snippet=line.strip()[:120],
                    description=f"Public method '{name}' has no Javadoc comment.",
                    remediation=f"Add a Javadoc comment above '{name}' describing its purpose.",
                ))

    return findings


def check_c_functions(filepath: str, lines: list[str]) -> list[Finding]:
    """Check C/C++ function sizes using brace counting."""
    findings = []
    suffix = Path(filepath).suffix
    if suffix not in {".c", ".h", ".cpp", ".hpp", ".cc", ".cxx"}:
        return findings

    func_pattern = re.compile(
        r"^(?!.*(?:if|else|for|while|switch|return|typedef|struct|enum|union|#))"
        r"\s*(?:static\s+|inline\s+|extern\s+|const\s+)*"
        r"(?:void|int|long|float|double|char|unsigned|signed|bool|size_t|ssize_t|\w+[\s*]+)"
        r"(\w+)\s*\([^;]*$"
    )

    i = 0
    while i < len(lines):
        match = func_pattern.match(lines[i])
        if match and "{" in lines[i] or (match and i + 1 < len(lines) and "{" in lines[i + 1]):
            func_name = match.group(1)
            func_start = i + 1
            brace_count = 0
            found_open = False
            j = i
            while j < len(lines):
                brace_count += lines[j].count("{") - lines[j].count("}")
                if "{" in lines[j]:
                    found_open = True
                if found_open and brace_count <= 0:
                    func_lines = j - i + 1
                    if func_lines > MAX_FUNCTION_LINES:
                        findings.append(Finding(
                            rule_id="CH-003",
                            rule_name="Function size limit exceeded",
                            severity=Severity.MEDIUM,
                            file_path=filepath,
                            line_number=func_start,
                            code_snippet=f"{func_name}() -- {func_lines} lines (limit: {MAX_FUNCTION_LINES})",
                            description=f"C/C++ function '{func_name}' is {func_lines} lines long.",
                            remediation=f"Extract parts of '{func_name}' into smaller helper functions.",
                        ))
                    break
                j += 1
        i += 1

    # Check for missing header comment on functions
    for i, line in enumerate(lines):
        match = func_pattern.match(line)
        if match:
            has_comment = False
            j = i - 1
            while j >= 0 and lines[j].strip() == "":
                j -= 1
            if j >= 0 and (lines[j].strip().endswith("*/") or lines[j].strip().startswith("//")):
                has_comment = True
            if not has_comment:
                func_name = match.group(1)
                findings.append(Finding(
                    rule_id="CH-004a",
                    rule_name="Missing function comment",
                    severity=Severity.MEDIUM,
                    file_path=filepath,
                    line_number=i + 1,
                    code_snippet=line.strip()[:120],
                    description=f"Function '{func_name}' has no preceding comment.",
                    remediation=f"Add a comment above '{func_name}' describing its purpose.",
                ))

    return findings


def check_missing_file_header(filepath: str, lines: list[str]) -> list[Finding]:
    """Check if Java/C files have a file-level comment or header."""
    findings = []
    suffix = Path(filepath).suffix
    if suffix not in {".java", ".c", ".h", ".cpp", ".hpp", ".cc", ".cxx"}:
        return findings

    if not lines:
        return findings

    first_non_empty = 0
    for i, line in enumerate(lines):
        if line.strip():
            first_non_empty = i
            break

    first_line = lines[first_non_empty].strip()
    if not (first_line.startswith("/*") or first_line.startswith("//") or first_line.startswith("/**")):
        findings.append(Finding(
            rule_id="CH-004",
            rule_name="Missing file header comment",
            severity=Severity.MEDIUM,
            file_path=filepath,
            line_number=1,
            code_snippet=f"File: {os.path.basename(filepath)}",
            description="File is missing a header comment describing its purpose.",
            remediation="Add a comment at the top of the file describing what it does.",
        ))

    return findings


def generate_docstring_with_llm(code: str, kind: str = "module") -> Optional[str]:
    """Use the configured LLM to generate a docstring for the given code."""
    try:
        from llm_client import get_client
        client = get_client()

        if kind == "module":
            prompt = (
                "Generate a Python module docstring (3 sentences maximum) for the following code. "
                "Return ONLY the docstring content, no quotes, no code fences.\n\n"
                f"```python\n{code[:3000]}\n```"
            )
        elif kind == "function":
            prompt = (
                "Generate a one-line Python docstring for the following function. "
                "Return ONLY the docstring content, no quotes, no code fences.\n\n"
                f"```python\n{code[:1500]}\n```"
            )
        elif kind == "class":
            prompt = (
                "Generate a one-line Python docstring for the following class. "
                "Return ONLY the docstring content, no quotes, no code fences.\n\n"
                f"```python\n{code[:2000]}\n```"
            )
        else:
            return None

        response = client.complete(
            prompt=prompt,
            system="You are a concise technical writer. Return only the docstring text, nothing else.",
            max_tokens=200,
            temperature=0.0,
        )
        return response.text.strip().strip('"').strip("'")

    except Exception as e:
        print(f"LLM docstring generation failed: {e}", file=sys.stderr)
        return None


def scan_file(filepath: str, root_dir: str = ".", use_llm: bool = False) -> tuple[list[Finding], int]:
    """Scan a single file for code health issues. Returns (findings, llm_calls)."""
    findings = []
    llm_calls = 0

    try:
        with open(filepath, "r", errors="ignore") as f:
            content = f.read()
            lines = content.split("\n")
    except (OSError, IOError):
        return findings, llm_calls

    findings.extend(check_file_length(filepath, lines))
    findings.extend(check_dead_code(filepath, lines))
    findings.extend(check_bare_except(filepath, lines))
    findings.extend(check_io_separation(filepath, lines))

    if filepath.endswith(".py"):
        findings.extend(check_module_docstring(filepath, content))
        findings.extend(check_python_functions(filepath, content, lines))
        findings.extend(check_missing_tests(filepath, root_dir))

    if filepath.endswith(".java"):
        findings.extend(check_java_functions(filepath, lines))
        findings.extend(check_missing_file_header(filepath, lines))
        findings.extend(check_missing_tests(filepath, root_dir))

    suffix = Path(filepath).suffix
    if suffix in {".c", ".h", ".cpp", ".hpp", ".cc", ".cxx"}:
        findings.extend(check_c_functions(filepath, lines))
        findings.extend(check_missing_file_header(filepath, lines))

    if use_llm:
        for finding in findings:
            if finding.auto_fix_type in ("add_module_docstring", "add_function_docstring", "add_class_docstring"):
                docstring = generate_docstring_with_llm(content, finding.auto_fix_type.replace("add_", "").replace("_docstring", ""))
                if docstring:
                    finding.auto_fix_content = docstring
                    llm_calls += 1

    return findings, llm_calls


def calculate_health_score(report: CodeHealthReport) -> str:
    """Calculate a letter grade based on finding density."""
    if report.files_scanned == 0:
        return "A"
    density = report.total_findings / report.files_scanned
    if density == 0:
        return "A"
    elif density < 0.5:
        return "B"
    elif density < 1.0:
        return "C"
    elif density < 2.0:
        return "D"
    else:
        return "F"


def run_scan(
    files: list[str],
    root_dir: str = ".",
    use_llm: bool = False,
    base_branch: str = "main",
) -> CodeHealthReport:
    """Run the full code health scan."""
    report = CodeHealthReport()

    for filepath in files:
        report.files_scanned += 1
        file_findings, llm_calls = scan_file(filepath, root_dir, use_llm)
        report.llm_calls_made += llm_calls

        active_findings = []
        for f in file_findings:
            if is_false_positive(_CFG, f.rule_id, f.file_path):
                report.suppressed_count += 1
                continue
            active_findings.append(f)

        for f in active_findings:
            if f.severity == Severity.HIGH:
                report.high_count += 1
            elif f.severity == Severity.MEDIUM:
                report.medium_count += 1
            elif f.severity == Severity.LOW:
                report.low_count += 1
            if f.auto_fixable:
                report.auto_fixable_count += 1

        report.findings.extend([asdict(f) for f in active_findings])

    report.total_findings = len(report.findings)
    report.blocks_merge = report.high_count > 0
    report.health_score = calculate_health_score(report)

    if use_llm:
        from llm_enrichment import enrich_findings, get_diff_content
        llm_tier = os.environ.get("LLM_TIER", "fast").lower()
        diff = get_diff_content(base_branch)
        result = enrich_findings(
            diff=diff,
            existing_rules=_CFG,
            existing_findings=report.findings,
            scanner_type="health",
            llm_tier=llm_tier,
        )
        for finding in result.findings:
            sev = finding.get("severity", "medium")
            if sev == Severity.HIGH:
                report.high_count += 1
            elif sev == Severity.MEDIUM:
                report.medium_count += 1
            elif sev == Severity.LOW:
                report.low_count += 1
        report.findings.extend(result.findings)
        report.total_findings += len(result.findings)
        report.blocks_merge = report.high_count > 0
        report.llm_calls_made += 1 if result.findings or result.input_tokens > 0 else 0
        report.llm_tokens_used += result.input_tokens + result.output_tokens

    return report


def main():
    """Entry point for the code health scanner."""
    root_dir = os.environ.get("SCAN_ROOT", ".")
    base_branch = os.environ.get("BASE_BRANCH", "main")
    output_file = os.environ.get("CODE_HEALTH_REPORT_OUTPUT", "code-health-report.json")
    scan_mode = os.environ.get("SCAN_MODE", "changed")
    use_llm = os.environ.get("USE_LLM", "false").lower() == "true"

    if scan_mode == "changed":
        files = get_changed_files(base_branch)
        if not files:
            print("No changed files found, falling back to full scan.")
            files = get_all_files(root_dir)
    else:
        files = get_all_files(root_dir)

    scannable = [f for f in files if Path(f).suffix in SCAN_EXTENSIONS and os.path.isfile(f)]

    if use_llm:
        from llm_enrichment import determine_llm_tier
        effective_tier = determine_llm_tier(scannable)
        if effective_tier == "deep":
            print("High-risk files detected, escalating to LLM_TIER=deep")
        os.environ["LLM_TIER"] = effective_tier

    import time
    start_time = time.monotonic()

    print(f"Scanning {len(scannable)} files (LLM: {'enabled' if use_llm else 'disabled'})...")
    report = run_scan(scannable, root_dir, use_llm, base_branch)

    report.scan_duration_seconds = round(time.monotonic() - start_time, 2)

    with open(output_file, "w") as f:
        json.dump(asdict(report), f, indent=2)

    print(f"\nScan complete: {report.files_scanned} files scanned in {report.scan_duration_seconds}s")
    print(f"  Health Score: {report.health_score}")
    print(f"  High:   {report.high_count}")
    print(f"  Medium: {report.medium_count}")
    print(f"  Low:    {report.low_count}")
    print(f"  Auto-fixable: {report.auto_fixable_count}")
    if use_llm:
        print(f"  LLM calls: {report.llm_calls_made}")
    print(f"\nReport saved to: {output_file}")

    if report.blocks_merge:
        print("\nRESULT: FAIL — High severity code health issues found.")
        sys.exit(1)
    else:
        print(f"\nRESULT: PASS — Health score: {report.health_score}")
        sys.exit(0)


if __name__ == "__main__":
    main()
