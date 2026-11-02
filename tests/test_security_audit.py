"""
Tests for the Security Audit Scanner.
Verifies that each pattern category correctly identifies vulnerabilities
and does not flag safe code (false positives).
"""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))
from security_audit import scan_file, check_gitignore, is_credential_file


class TestHardcodedSecrets(unittest.TestCase):
    """Test detection of hardcoded secrets."""

    def _scan_code(self, code: str, ext: str = ".py") -> list:
        with tempfile.NamedTemporaryFile(mode="w", suffix=ext, delete=False) as f:
            f.write(code)
            f.flush()
            findings = scan_file(f.name)
        os.unlink(f.name)
        return [f for f in findings if f.rule_id == "SEC-001"]

    def test_hardcoded_password(self):
        findings = self._scan_code('password = "SuperSecret123"')
        self.assertTrue(len(findings) > 0, "Should detect hardcoded password")

    def test_hardcoded_api_key(self):
        findings = self._scan_code('api_key = "sk-1234567890abcdef"')
        self.assertTrue(len(findings) > 0, "Should detect hardcoded API key")

    def test_hardcoded_token(self):
        findings = self._scan_code('token = "ghp_abcdefghijklmnopqrstuvwxyz1234567890"')
        self.assertTrue(len(findings) > 0, "Should detect hardcoded token")

    def test_aws_key(self):
        findings = self._scan_code('key = "AKIAIOSFODNN7REALKEY"')
        self.assertTrue(len(findings) > 0, "Should detect AWS access key")

    def test_env_var_not_flagged(self):
        findings = self._scan_code('password = os.environ.get("DB_PASSWORD")')
        self.assertEqual(len(findings), 0, "Should not flag environment variable usage")

    def test_placeholder_not_flagged(self):
        findings = self._scan_code('api_key = "your-api-key-here"')
        self.assertEqual(len(findings), 0, "Should not flag placeholder values")

    def test_example_not_flagged(self):
        findings = self._scan_code('password = "example_password"')
        self.assertEqual(len(findings), 0, "Should not flag example values")


class TestSQLInjection(unittest.TestCase):
    """Test detection of SQL injection vulnerabilities."""

    def _scan_code(self, code: str) -> list:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()
            findings = scan_file(f.name)
        os.unlink(f.name)
        return [f for f in findings if f.rule_id == "SEC-002"]

    def test_fstring_sql(self):
        findings = self._scan_code('query = f"SELECT * FROM users WHERE id = {user_id}"')
        self.assertTrue(len(findings) > 0, "Should detect f-string SQL")

    def test_concat_sql(self):
        findings = self._scan_code('query = "SELECT * FROM users WHERE id = " + user_id')
        self.assertTrue(len(findings) > 0, "Should detect concatenated SQL")

    def test_format_sql(self):
        findings = self._scan_code('query = "SELECT * FROM users WHERE id = %s" % user_id')
        self.assertTrue(len(findings) > 0, "Should detect % formatted SQL")

    def test_parameterized_not_flagged(self):
        findings = self._scan_code('cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))')
        self.assertEqual(len(findings), 0, "Should not flag parameterized queries")


class TestDangerousPython(unittest.TestCase):
    """Test detection of dangerous Python patterns."""

    def _scan_code(self, code: str) -> list:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()
            findings = scan_file(f.name)
        os.unlink(f.name)
        return [f for f in findings if f.rule_id == "SEC-003"]

    def test_eval(self):
        findings = self._scan_code('result = eval(user_input)')
        self.assertTrue(len(findings) > 0, "Should detect eval()")

    def test_exec(self):
        findings = self._scan_code('exec(code_string)')
        self.assertTrue(len(findings) > 0, "Should detect exec()")

    def test_os_system(self):
        findings = self._scan_code('os.system(command)')
        self.assertTrue(len(findings) > 0, "Should detect os.system()")

    def test_pickle_loads(self):
        findings = self._scan_code('data = pickle.loads(raw_bytes)')
        self.assertTrue(len(findings) > 0, "Should detect pickle.loads()")

    def test_subprocess_shell_true(self):
        findings = self._scan_code('subprocess.run(cmd, shell=True)')
        self.assertTrue(len(findings) > 0, "Should detect subprocess with shell=True")

    def test_literal_eval_not_flagged(self):
        findings = self._scan_code('result = ast.literal_eval(data)')
        self.assertEqual(len(findings), 0, "Should not flag ast.literal_eval()")


class TestXSS(unittest.TestCase):
    """Test detection of XSS vulnerabilities."""

    def _scan_code(self, code: str) -> list:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".js", delete=False) as f:
            f.write(code)
            f.flush()
            findings = scan_file(f.name)
        os.unlink(f.name)
        return [f for f in findings if f.rule_id == "SEC-004"]

    def test_innerhtml(self):
        findings = self._scan_code('element.innerHTML = userInput;')
        self.assertTrue(len(findings) > 0, "Should detect innerHTML assignment")

    def test_innerhtml_with_sanitize_not_flagged(self):
        findings = self._scan_code('element.innerHTML = DOMPurify.sanitize(userInput);')
        self.assertEqual(len(findings), 0, "Should not flag sanitized innerHTML")


class TestConnectionStrings(unittest.TestCase):
    """Test detection of exposed connection strings."""

    def _scan_code(self, code: str) -> list:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()
            findings = scan_file(f.name)
        os.unlink(f.name)
        return [f for f in findings if f.rule_id == "SEC-006"]

    def test_snowflake_connection(self):
        findings = self._scan_code('conn = "snowflake://user:password123@account"')
        self.assertTrue(len(findings) > 0, "Should detect Snowflake connection string")

    def test_mysql_connection(self):
        findings = self._scan_code('conn = "mysql://admin:secret@localhost/db"')
        self.assertTrue(len(findings) > 0, "Should detect MySQL connection string")


class TestCredentialFiles(unittest.TestCase):
    """Test detection of credential file patterns."""

    def test_env_file(self):
        self.assertTrue(is_credential_file(".env"))

    def test_env_production(self):
        self.assertTrue(is_credential_file(".env.production"))

    def test_credentials_json(self):
        self.assertTrue(is_credential_file("credentials.json"))

    def test_pem_file(self):
        self.assertTrue(is_credential_file("server.pem"))

    def test_key_file(self):
        self.assertTrue(is_credential_file("private.key"))

    def test_normal_py_not_flagged(self):
        self.assertFalse(is_credential_file("app.py"))

    def test_normal_json_not_flagged(self):
        self.assertFalse(is_credential_file("package.json"))


class TestBareExcept(unittest.TestCase):
    """Test detection of bare except clauses."""

    def _scan_code(self, code: str) -> list:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(code)
            f.flush()
            findings = scan_file(f.name)
        os.unlink(f.name)
        return [f for f in findings if f.rule_id == "SEC-007"]

    def test_bare_except(self):
        code = "try:\n    x = 1\nexcept:\n    pass"
        findings = self._scan_code(code)
        self.assertTrue(len(findings) > 0, "Should detect bare except")

    def test_specific_except_not_flagged(self):
        code = "try:\n    x = 1\nexcept ValueError as e:\n    pass"
        findings = self._scan_code(code)
        self.assertEqual(len(findings), 0, "Should not flag specific except")


class TestGitignore(unittest.TestCase):
    """Test .gitignore validation."""

    def test_missing_gitignore(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            findings = check_gitignore(tmpdir)
            self.assertTrue(len(findings) > 0, "Should flag missing .gitignore")

    def test_complete_gitignore(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            gitignore_path = os.path.join(tmpdir, ".gitignore")
            with open(gitignore_path, "w") as f:
                f.write(".env\ncredentials.json\n*.pem\n*.key\nsecrets/\n")
            findings = check_gitignore(tmpdir)
            self.assertEqual(len(findings), 0, "Should not flag complete .gitignore")


class TestDangerousJava(unittest.TestCase):
    """Test detection of dangerous Java patterns."""

    def _scan_code(self, code: str) -> list:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".java", delete=False) as f:
            f.write(code)
            f.flush()
            findings = scan_file(f.name)
        os.unlink(f.name)
        return [f for f in findings if f.rule_id == "SEC-010"]

    def test_runtime_exec(self):
        findings = self._scan_code('Runtime.getRuntime().exec(command);')
        self.assertTrue(len(findings) > 0, "Should detect Runtime.exec()")

    def test_object_input_stream(self):
        findings = self._scan_code('ObjectInputStream ois = new ObjectInputStream(input);')
        self.assertTrue(len(findings) > 0, "Should detect ObjectInputStream")

    def test_create_statement(self):
        findings = self._scan_code('Statement stmt = conn.createStatement();')
        self.assertTrue(len(findings) > 0, "Should detect createStatement()")

    def test_prepared_statement_not_flagged(self):
        findings = self._scan_code('PreparedStatement ps = conn.prepareStatement("SELECT * FROM t WHERE id = ?");')
        self.assertEqual(len(findings), 0, "Should not flag PreparedStatement")


class TestDangerousC(unittest.TestCase):
    """Test detection of dangerous C/C++ patterns."""

    def _scan_code(self, code: str, ext: str = ".c") -> list:
        with tempfile.NamedTemporaryFile(mode="w", suffix=ext, delete=False) as f:
            f.write(code)
            f.flush()
            findings = scan_file(f.name)
        os.unlink(f.name)
        return [f for f in findings if f.rule_id == "SEC-011"]

    def test_gets(self):
        findings = self._scan_code('gets(buffer);')
        self.assertTrue(len(findings) > 0, "Should detect gets()")

    def test_sprintf(self):
        findings = self._scan_code('sprintf(buf, "%s", input);')
        self.assertTrue(len(findings) > 0, "Should detect sprintf()")

    def test_strcpy(self):
        findings = self._scan_code('strcpy(dest, src);')
        self.assertTrue(len(findings) > 0, "Should detect strcpy()")

    def test_system(self):
        findings = self._scan_code('system(command);')
        self.assertTrue(len(findings) > 0, "Should detect system()")

    def test_snprintf_not_flagged(self):
        findings = self._scan_code('snprintf(buf, sizeof(buf), "%s", input);')
        self.assertEqual(len(findings), 0, "Should not flag snprintf()")

    def test_fgets_not_flagged(self):
        findings = self._scan_code('fgets(buffer, sizeof(buffer), stdin);')
        self.assertEqual(len(findings), 0, "Should not flag fgets()")


if __name__ == "__main__":
    unittest.main()
