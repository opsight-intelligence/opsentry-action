"""
Security Audit Scanner for CI/CD Pipeline.
Scans source files for security vulnerabilities using regex pattern matching.
Outputs a structured JSON report of findings grouped by severity.
"""

import json
import os
import re
import sys
from dataclasses import dataclass, field, asdict
from enum import Enum
from pathlib import Path
from typing import Optional

from config_loader import (
    get_config, get_value, get_pattern_pairs, get_dangerous_patterns,
    is_rule_enabled, get_rule_severity, get_custom_rules, is_false_positive,
)

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
class ScanReport:
    files_scanned: int = 0
    total_findings: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    findings: list = field(default_factory=list)
    auto_fixable_count: int = 0
    blocks_merge: bool = False
    llm_calls_made: int = 0
    llm_tokens_used: int = 0
    suppressed_count: int = 0
    scan_duration_seconds: float = 0.0


# === PATTERN DEFINITIONS (overridable via config/default.json) ===

_BUILTIN_SECRET_PATTERNS = [
    (r'''(?:password|passwd|pwd)\s*=\s*["\'][^"\']{4,}["\']''', "Hardcoded password"),
    (r'''(?:api_key|apikey|api_secret)\s*=\s*["\'][^"\']{4,}["\']''', "Hardcoded API key"),
    (r'''(?:token|auth_token|access_token|secret_token)\s*=\s*["\'][^"\']{4,}["\']''', "Hardcoded token"),
    (r'''(?:secret|secret_key)\s*=\s*["\'][^"\']{4,}["\']''', "Hardcoded secret"),
    (r'''(?:aws_access_key_id|aws_secret_access_key)\s*=\s*["\'][^"\']{4,}["\']''', "Hardcoded AWS credential"),
    (r'''AKIA[0-9A-Z]{16}''', "AWS Access Key ID"),
    (r'''(?:sk-[a-zA-Z0-9]{20,})''', "OpenAI/Anthropic API key pattern"),
    (r'''(?:ghp_[a-zA-Z0-9]{36})''', "GitHub Personal Access Token"),
    (r'''(?:xox[bpas]-[a-zA-Z0-9-]{10,})''', "Slack token"),
]
SECRET_PATTERNS = get_pattern_pairs(_CFG, "security", "secret_patterns", default=_BUILTIN_SECRET_PATTERNS)

_BUILTIN_SECRET_SKIP_WORDS = [
    "example", "placeholder", "your-", "xxx", "changeme",
    "todo", "fixme", "<", "...", "test_", "mock_",
    "os.environ", "os.getenv", "environ.get",
]
SECRET_SKIP_WORDS = get_value(_CFG, "security", "secret_skip_words", default=_BUILTIN_SECRET_SKIP_WORDS)

_BUILTIN_SQL_INJECTION_PATTERNS = [
    (r'''f["\'](?:SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC)\s.*\{.*\}''', "f-string SQL query"),
    (r'''["\'](?:SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC)\s.*["\']\s*\+\s*''', "String concatenation in SQL"),
    (r'''["\'](?:SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC)\s.*["\']\s*%\s*''', "% formatting in SQL"),
    (r'''\.format\(.*\).*(?:SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC)''', ".format() in SQL"),
    (r'''(?:SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC)\s.*["\']\s*\+\s*(?:request|user_input|params|args|kwargs)''', "User input in SQL concatenation"),
]
SQL_INJECTION_PATTERNS = get_pattern_pairs(_CFG, "security", "sql_injection_patterns", default=_BUILTIN_SQL_INJECTION_PATTERNS)

_BUILTIN_DANGEROUS_PYTHON = [
    (r'''\beval\s*\(''', "eval()", "eval() executes arbitrary code. Use ast.literal_eval() for literals or json.loads() for JSON.", True, "replace_eval"),
    (r'''\bexec\s*\(''', "exec()", "exec() executes arbitrary statements. There is almost never a valid use case.", False, None),
    (r'''pickle\.loads?\s*\(''', "pickle.load/loads", "Pickle can execute arbitrary code during deserialization. Use json for untrusted data.", False, None),
    (r'''os\.system\s*\(''', "os.system()", "os.system() is vulnerable to shell injection. Use subprocess.run() with a list.", True, "replace_os_system"),
    (r'''subprocess\.(?:run|call|Popen)\s*\([^)]*shell\s*=\s*True''', "subprocess shell=True", "shell=True with variable input allows shell injection. Use a list of arguments instead.", False, None),
    (r'''__import__\s*\((?!.*["\'][a-z_]+["\'])''', "__import__() with variable", "Dynamic imports can load arbitrary modules. Use importlib with validated input.", False, None),
]
DANGEROUS_PYTHON_PATTERNS = get_dangerous_patterns(_CFG, "security", "dangerous_python_patterns", default=_BUILTIN_DANGEROUS_PYTHON)

_BUILTIN_DANGEROUS_JAVA = [
    (r'''Runtime\.getRuntime\(\)\.exec\s*\(''', "Runtime.exec()", "Runtime.exec() is vulnerable to command injection. Use ProcessBuilder with argument list.", False, None),
    (r'''Statement\s.*\.execute(?:Query|Update)?\s*\(\s*["\'].*["\']\s*\+''', "Statement with concatenation", "SQL via Statement with concatenation is vulnerable to injection. Use PreparedStatement.", False, None),
    (r'''new\s+ObjectInputStream\s*\(''', "ObjectInputStream deserialization", "Java deserialization can execute arbitrary code. Validate input or use JSON/protobuf.", False, None),
    (r'''\.createStatement\s*\(\s*\)''', "Statement without PreparedStatement", "createStatement() is prone to SQL injection. Use connection.prepareStatement() instead.", False, None),
    (r'''ScriptEngine.*\.eval\s*\(''', "ScriptEngine.eval()", "ScriptEngine.eval() executes arbitrary code. Avoid evaluating untrusted input.", False, None),
    (r'''XMLInputFactory.*\.createXMLStreamReader''', "XML parsing without XXE protection", "XML parsing without disabling external entities allows XXE attacks. Disable DTD and external entities.", False, None),
]
DANGEROUS_JAVA_PATTERNS = get_dangerous_patterns(_CFG, "security", "dangerous_java_patterns", default=_BUILTIN_DANGEROUS_JAVA)

_BUILTIN_DANGEROUS_C = [
    (r'''\bgets\s*\(''', "gets()", "gets() has no bounds checking and always causes buffer overflow. Use fgets() instead.", False, None),
    (r'''\bsprintf\s*\(''', "sprintf()", "sprintf() has no bounds checking. Use snprintf() to prevent buffer overflow.", False, None),
    (r'''\bstrcpy\s*\(''', "strcpy()", "strcpy() has no bounds checking. Use strncpy() or strlcpy() instead.", False, None),
    (r'''\bstrcat\s*\(''', "strcat()", "strcat() has no bounds checking. Use strncat() or strlcat() instead.", False, None),
    (r'''printf\s*\(\s*[a-zA-Z_]\w*\s*\)''', "printf() format string", "printf() with a variable as format string allows format string attacks. Use printf(\"%s\", var) instead.", False, None),
    (r'''\bscanf\s*\(\s*["\']%s["\']''', "scanf(%s)", "scanf(%s) has no bounds checking. Use scanf(%Ns) with a width limit.", False, None),
    (r'''\bsystem\s*\(''', "system()", "system() is vulnerable to shell injection. Use execve() or posix_spawn() with argument arrays.", False, None),
    (r'''\bmalloc\s*\([^)]*\)\s*;(?!.*(?:if|assert|check))''', "malloc without null check", "malloc() can return NULL. Always check the return value before use.", False, None),
]
DANGEROUS_C_PATTERNS = get_dangerous_patterns(_CFG, "security", "dangerous_c_patterns", default=_BUILTIN_DANGEROUS_C)

_BUILTIN_SQL_JAVA = [
    (r'''["\'](?:SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER)\s.*["\']\s*\+\s*(?:request|param|input|user|arg)''', "Java SQL concatenation with user input"),
    (r'''String\s+\w*(?:sql|query|stmt)\w*\s*=\s*["\'](?:SELECT|INSERT|UPDATE|DELETE).*["\']\s*\+''', "Java SQL string concatenation"),
]
SQL_INJECTION_JAVA_PATTERNS = get_pattern_pairs(_CFG, "security", "sql_injection_java_patterns", default=_BUILTIN_SQL_JAVA)

_BUILTIN_XSS = [
    (r'''\.innerHTML\s*=\s*(?!.*(?:DOMPurify|sanitize|escape))''', "innerHTML assignment without sanitization"),
    (r'''dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:(?!.*(?:DOMPurify|sanitize))''', "dangerouslySetInnerHTML without DOMPurify"),
    (r'''document\.write\s*\((?!.*(?:escape|sanitize))''', "document.write() with potentially unsafe input"),
]
XSS_PATTERNS = get_pattern_pairs(_CFG, "security", "xss_patterns", default=_BUILTIN_XSS)

_BUILTIN_CONN_STR = [
    (r'''(?:snowflake|mysql|postgresql|postgres|mssql):\/\/[^:]+:[^@]+@''', "Connection string with embedded credentials"),
    (r'''(?:jdbc|odbc):.*(?:password|pwd)=[^;]+''', "JDBC/ODBC connection with password"),
    (r'''(?:Server|Host)=.*(?:Password|Pwd)=''', "Connection string with password parameter"),
]
CONNECTION_STRING_PATTERNS = get_pattern_pairs(_CFG, "security", "connection_string_patterns", default=_BUILTIN_CONN_STR)

_BUILTIN_CRED_FILES = [
    r'''\.env$''',
    r'''\.env\..*$''',
    r'''\.env\.local$''',
    r'''\.env\.production$''',
    r'''\.env\.staging$''',
    r'''credentials\.json$''',
    r'''credentials\.yaml$''',
    r'''credentials\.toml$''',
    r'''\.pem$''',
    r'''\.key$''',
    r'''\.p12$''',
    r'''\.pfx$''',
    r'''\.keystore$''',
    r'''\.jks$''',
]
CREDENTIAL_FILE_PATTERNS = get_value(_CFG, "security", "credential_file_patterns", default=_BUILTIN_CRED_FILES)

BARE_EXCEPT_PATTERN = r'''except\s*:\s*$'''
UNSAFE_YAML_PATTERN = r'''yaml\.load\s*\([^)]*\)(?!.*(?:SafeLoader|CSafeLoader))'''

_BUILTIN_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx",
    ".java", ".go", ".rb", ".php",
    ".c", ".h", ".cpp", ".hpp", ".cc", ".cxx",
    ".yml", ".yaml", ".toml", ".json", ".cfg", ".ini", ".conf",
    ".sh", ".bash",
    ".sql",
    ".md", ".txt",
}
SCAN_EXTENSIONS = set(get_value(_CFG, "scan_extensions", default=list(_BUILTIN_EXTENSIONS)))

_BUILTIN_SKIP = {
    "node_modules", ".git", "__pycache__", ".venv", "venv",
    "env", ".env", "dist", "build", ".next", ".nuxt",
    "vendor", "target", ".tox", ".mypy_cache", ".pytest_cache",
}
SKIP_DIRS = set(get_value(_CFG, "skip_dirs", default=list(_BUILTIN_SKIP)))


def get_changed_files(base_branch: str = "main") -> list[str]:
    """Get list of files changed compared to base branch using git diff."""
    try:
        import subprocess
        result = subprocess.run(
            ["git", "diff", "--name-only", "--diff-filter=ACMR", base_branch],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode == 0 and result.stdout.strip():
            return [f.strip() for f in result.stdout.strip().split("\n") if f.strip()]
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass
    return []


def get_all_files(root_dir: str = ".") -> list[str]:
    """Get all scannable files in the project."""
    files = []
    for dirpath, dirnames, filenames in os.walk(root_dir):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for filename in filenames:
            filepath = os.path.join(dirpath, filename)
            if Path(filepath).suffix in SCAN_EXTENSIONS:
                files.append(filepath)
    return files


def is_credential_file(filepath: str) -> bool:
    """Check if a file matches credential file patterns."""
    filename = os.path.basename(filepath)
    for pattern in CREDENTIAL_FILE_PATTERNS:
        if re.search(pattern, filename, re.IGNORECASE):
            return True
    return False


def check_gitignore(root_dir: str = ".") -> list[Finding]:
    """Check if .gitignore has required entries."""
    findings = []
    gitignore_path = os.path.join(root_dir, ".gitignore")
    required_entries = [".env", "credentials.json", "*.pem", "*.key", "secrets/"]

    if not os.path.exists(gitignore_path):
        findings.append(Finding(
            rule_id="SEC-009",
            rule_name="Missing .gitignore",
            severity=Severity.MEDIUM,
            file_path=".gitignore",
            line_number=0,
            code_snippet="",
            description=".gitignore file does not exist. Sensitive files may be committed accidentally.",
            remediation="Create a .gitignore file with entries for .env, credentials.json, *.pem, *.key, secrets/",
            auto_fixable=True,
            auto_fix_type="create_gitignore",
        ))
        return findings

    with open(gitignore_path, "r", errors="ignore") as f:
        content = f.read()

    missing = [entry for entry in required_entries if entry not in content]
    if missing:
        findings.append(Finding(
            rule_id="SEC-009",
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


def _sev(config_key_parts: tuple, fallback: str) -> str:
    """Get severity from config or fall back to hardcoded default."""
    return get_rule_severity(_CFG, *config_key_parts, default=fallback)


def _enabled(config_key_parts: tuple) -> bool:
    """Check if a rule group is enabled in config."""
    return is_rule_enabled(_CFG, *config_key_parts)


def scan_file(filepath: str) -> list[Finding]:
    """Scan a single file for security vulnerabilities."""
    findings = []

    if is_credential_file(filepath):
        findings.append(Finding(
            rule_id="SEC-005",
            rule_name="Credential file in repository",
            severity=Severity.CRITICAL,
            file_path=filepath,
            line_number=0,
            code_snippet=f"File: {os.path.basename(filepath)}",
            description=f"Credential file '{os.path.basename(filepath)}' should not be in the repository.",
            remediation="Remove this file from version control and add it to .gitignore.",
            auto_fixable=True,
            auto_fix_type="add_to_gitignore",
        ))

    try:
        with open(filepath, "r", errors="ignore") as f:
            lines = f.readlines()
    except (OSError, IOError):
        return findings

    for line_num, line in enumerate(lines, 1):
        stripped = line.strip()

        if stripped.startswith("#") or stripped.startswith("//") or stripped.startswith("*"):
            if not any(re.search(p, stripped, re.IGNORECASE) for p, _ in SECRET_PATTERNS):
                continue

        if _enabled(("security", "secret_patterns")):
            sev = _sev(("security", "secret_patterns"), "critical")
            for pattern, name in SECRET_PATTERNS:
                if re.search(pattern, line, re.IGNORECASE):
                    if any(skip in line.lower() for skip in SECRET_SKIP_WORDS):
                        continue
                    findings.append(Finding(
                        rule_id="SEC-001",
                        rule_name=f"Hardcoded secret: {name}",
                        severity=sev,
                        file_path=filepath,
                        line_number=line_num,
                        code_snippet=stripped[:120],
                        description=f"{name} detected. Credentials must never be hardcoded.",
                        remediation="Use environment variables or a secrets manager instead.",
                    ))

        if _enabled(("security", "sql_injection_patterns")):
            sev = _sev(("security", "sql_injection_patterns"), "critical")
            for pattern, name in SQL_INJECTION_PATTERNS:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(Finding(
                        rule_id="SEC-002",
                        rule_name=f"SQL injection risk: {name}",
                        severity=sev,
                        file_path=filepath,
                        line_number=line_num,
                        code_snippet=stripped[:120],
                        description=f"{name}. SQL queries built with string interpolation are vulnerable to injection.",
                        remediation="Use parameterized queries: cursor.execute('SELECT ... WHERE id = %s', (value,))",
                    ))

        if _enabled(("security", "dangerous_python_patterns")):
            sev = _sev(("security", "dangerous_python_patterns"), "high")
            for item in DANGEROUS_PYTHON_PATTERNS:
                pattern, name, desc, fixable, fix_type = item
                if re.search(pattern, line):
                    findings.append(Finding(
                        rule_id="SEC-003",
                        rule_name=f"Dangerous pattern: {name}",
                        severity=sev,
                        file_path=filepath,
                        line_number=line_num,
                        code_snippet=stripped[:120],
                        description=desc,
                        remediation=desc.split(". ", 1)[-1] if ". " in desc else desc,
                        auto_fixable=fixable,
                        auto_fix_type=fix_type,
                    ))

        if _enabled(("security", "xss_patterns")):
            sev = _sev(("security", "xss_patterns"), "high")
            for pattern, name in XSS_PATTERNS:
                if re.search(pattern, line):
                    findings.append(Finding(
                        rule_id="SEC-004",
                        rule_name=f"XSS risk: {name}",
                        severity=sev,
                        file_path=filepath,
                        line_number=line_num,
                        code_snippet=stripped[:120],
                        description=f"{name}. Unsanitised user input in HTML can execute malicious scripts.",
                        remediation="Use textContent instead of innerHTML, or sanitise with DOMPurify.",
                    ))

        if _enabled(("security", "dangerous_java_patterns")):
            sev = _sev(("security", "dangerous_java_patterns"), "high")
            for item in DANGEROUS_JAVA_PATTERNS:
                pattern, name, desc, fixable, fix_type = item
                if re.search(pattern, line):
                    findings.append(Finding(
                        rule_id="SEC-010",
                        rule_name=f"Dangerous Java pattern: {name}",
                        severity=sev,
                        file_path=filepath,
                        line_number=line_num,
                        code_snippet=stripped[:120],
                        description=desc,
                        remediation=desc.split(". ", 1)[-1] if ". " in desc else desc,
                        auto_fixable=fixable,
                        auto_fix_type=fix_type,
                    ))

        if _enabled(("security", "dangerous_c_patterns")):
            sev = _sev(("security", "dangerous_c_patterns"), "high")
            for item in DANGEROUS_C_PATTERNS:
                pattern, name, desc, fixable, fix_type = item
                if re.search(pattern, line):
                    findings.append(Finding(
                        rule_id="SEC-011",
                        rule_name=f"Dangerous C/C++ pattern: {name}",
                        severity=sev,
                        file_path=filepath,
                        line_number=line_num,
                        code_snippet=stripped[:120],
                        description=desc,
                        remediation=desc.split(". ", 1)[-1] if ". " in desc else desc,
                        auto_fixable=fixable,
                        auto_fix_type=fix_type,
                    ))

        if _enabled(("security", "sql_injection_java_patterns")):
            sev = _sev(("security", "sql_injection_java_patterns"), "critical")
            for pattern, name in SQL_INJECTION_JAVA_PATTERNS:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(Finding(
                        rule_id="SEC-002",
                        rule_name=f"SQL injection risk: {name}",
                        severity=sev,
                        file_path=filepath,
                        line_number=line_num,
                        code_snippet=stripped[:120],
                        description=f"{name}. Use PreparedStatement with parameterized queries.",
                        remediation="Use PreparedStatement: conn.prepareStatement(\"SELECT ... WHERE id = ?\") and setString()/setInt().",
                    ))

        if _enabled(("security", "connection_string_patterns")):
            sev = _sev(("security", "connection_string_patterns"), "critical")
            for pattern, name in CONNECTION_STRING_PATTERNS:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(Finding(
                        rule_id="SEC-006",
                        rule_name=f"Exposed connection string: {name}",
                        severity=sev,
                        file_path=filepath,
                        line_number=line_num,
                        code_snippet=stripped[:80] + "...[REDACTED]",
                        description="Connection string with embedded credentials found.",
                        remediation="Store connection credentials in environment variables or secrets manager.",
                    ))

        if _enabled(("security", "bare_except")):
            sev = _sev(("security", "bare_except"), "medium")
            if re.search(BARE_EXCEPT_PATTERN, line):
                findings.append(Finding(
                    rule_id="SEC-007",
                    rule_name="Bare except clause",
                    severity=sev,
                    file_path=filepath,
                    line_number=line_num,
                    code_snippet=stripped[:120],
                    description="Bare except: catches all exceptions including SystemExit and KeyboardInterrupt.",
                    remediation="Catch specific exceptions: except ValueError as e:",
                    auto_fixable=True,
                    auto_fix_type="fix_bare_except",
                ))

        if _enabled(("security", "unsafe_yaml")):
            sev = _sev(("security", "unsafe_yaml"), "medium")
            if re.search(UNSAFE_YAML_PATTERN, line):
                findings.append(Finding(
                    rule_id="SEC-008",
                    rule_name="Unsafe YAML loading",
                    severity=sev,
                    file_path=filepath,
                    line_number=line_num,
                    code_snippet=stripped[:120],
                    description="yaml.load() without SafeLoader can execute arbitrary Python code.",
                    remediation="Use yaml.safe_load() or yaml.load(data, Loader=yaml.SafeLoader)",
                ))

        # Custom rules from config
        for rule in get_custom_rules(_CFG, scanner="security"):
            if re.search(rule["pattern"], line, re.IGNORECASE):
                findings.append(Finding(
                    rule_id=rule["rule_id"],
                    rule_name=rule["rule_name"],
                    severity=rule.get("severity", "medium"),
                    file_path=filepath,
                    line_number=line_num,
                    code_snippet=stripped[:120],
                    description=rule.get("description", ""),
                    remediation=rule.get("remediation", ""),
                    auto_fixable=rule.get("auto_fixable", False),
                ))

    return findings


def run_scan(
    files: list[str],
    root_dir: str = ".",
    use_llm: bool = False,
    base_branch: str = "main",
) -> ScanReport:
    """Run the full security scan and return a report."""
    report = ScanReport()
    all_findings = []

    all_findings.extend(check_gitignore(root_dir))

    for filepath in files:
        report.files_scanned += 1
        file_findings = scan_file(filepath)
        all_findings.extend(file_findings)

    # Cross-file AST composition analysis (SEC-012).
    # Closes the Attack 4 (salami) residual from red-team-log.md by flagging
    # file-read + network + sensitive-path compositions that span imports.
    if _enabled(("security", "composition")):
        comp_sev = _sev(("security", "composition"), "high")
        skip_tests = get_value(_CFG, "security", "composition", "skip_test_files", default=True)
        python_files = [f for f in files if f.endswith(".py")]
        try:
            from composition_audit import scan_composition
            comp_findings = scan_composition(
                python_files,
                root_dir=root_dir,
                severity=comp_sev,
                skip_test_files=bool(skip_tests),
            )
            for raw in comp_findings:
                all_findings.append(Finding(**raw))
        except Exception as comp_err:  # pragma: no cover - defensive
            print(f"WARNING: composition analysis failed: {comp_err}", file=sys.stderr)

    # Network exposure scan (SEC-013).
    # Catches services bound to 0.0.0.0 on dangerous database/admin ports —
    # the canonical "dev config shipped to prod with Redis on the LAN" foot-gun.
    if _enabled(("security", "network_exposure")):
        net_sev = _sev(("security", "network_exposure"), "high")
        try:
            from network_exposure_audit import scan_network_exposure
            net_findings = scan_network_exposure(files, severity=net_sev)
            for raw in net_findings:
                all_findings.append(Finding(**raw))
        except Exception as net_err:  # pragma: no cover - defensive
            print(f"WARNING: network exposure analysis failed: {net_err}", file=sys.stderr)

    active_findings = []
    for f in all_findings:
        if is_false_positive(_CFG, f.rule_id, f.file_path):
            report.suppressed_count += 1
        else:
            active_findings.append(f)
    all_findings = active_findings

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

    if use_llm:
        from llm_enrichment import enrich_findings, get_diff_content
        llm_tier = os.environ.get("LLM_TIER", "fast").lower()
        diff = get_diff_content(base_branch)
        result = enrich_findings(
            diff=diff,
            existing_rules=_CFG,
            existing_findings=all_findings,
            scanner_type="security",
            llm_tier=llm_tier,
        )
        for finding in result.findings:
            sev = finding.get("severity", "medium")
            if sev == Severity.CRITICAL:
                report.critical_count += 1
            elif sev == Severity.HIGH:
                report.high_count += 1
            elif sev == Severity.MEDIUM:
                report.medium_count += 1
            elif sev == Severity.LOW:
                report.low_count += 1
        report.findings.extend(result.findings)
        report.total_findings += len(result.findings)
        report.blocks_merge = report.critical_count > 0 or report.high_count > 0
        report.llm_calls_made = 1 if result.findings or result.input_tokens > 0 else 0
        report.llm_tokens_used = result.input_tokens + result.output_tokens

    return report


def main():
    """Entry point for the security audit scanner."""
    root_dir = os.environ.get("SCAN_ROOT", ".")
    base_branch = os.environ.get("BASE_BRANCH", "main")
    output_file = os.environ.get("REPORT_OUTPUT", "security-report.json")
    scan_mode = os.environ.get("SCAN_MODE", "changed")
    use_llm = os.environ.get("USE_LLM", "false").lower() == "true"

    if scan_mode == "changed":
        files = get_changed_files(base_branch)
        if not files:
            print("No changed files found, falling back to full scan.")
            files = get_all_files(root_dir)
    else:
        files = get_all_files(root_dir)

    scannable_files = [f for f in files if Path(f).suffix in SCAN_EXTENSIONS and os.path.isfile(f)]

    if use_llm:
        from llm_enrichment import determine_llm_tier
        effective_tier = determine_llm_tier(scannable_files)
        if effective_tier == "deep":
            print("High-risk files detected, escalating to LLM_TIER=deep")
        os.environ["LLM_TIER"] = effective_tier

    import time
    start_time = time.monotonic()

    print(f"Scanning {len(scannable_files)} files (LLM: {'enabled' if use_llm else 'disabled'})...")
    report = run_scan(scannable_files, root_dir, use_llm=use_llm, base_branch=base_branch)

    report.scan_duration_seconds = round(time.monotonic() - start_time, 2)

    with open(output_file, "w") as f:
        json.dump(asdict(report), f, indent=2)

    print(f"\nScan complete: {report.files_scanned} files scanned in {report.scan_duration_seconds}s")
    print(f"  Critical: {report.critical_count}")
    print(f"  High:     {report.high_count}")
    print(f"  Medium:   {report.medium_count}")
    print(f"  Low:      {report.low_count}")
    print(f"  Auto-fixable: {report.auto_fixable_count}")
    if use_llm:
        print(f"  LLM calls: {report.llm_calls_made}")
        print(f"  LLM tokens: {report.llm_tokens_used}")
    print(f"\nReport saved to: {output_file}")

    if report.blocks_merge:
        print("\nRESULT: FAIL -- Critical or High severity issues found. PR should not be merged.")
        sys.exit(1)
    else:
        print("\nRESULT: PASS -- No blocking issues found.")
        sys.exit(0)


if __name__ == "__main__":
    main()
