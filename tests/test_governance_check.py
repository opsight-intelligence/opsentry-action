"""
Tests for the Governance Check Scanner.
Verifies guardrail file detection, policy violation scanning,
and correct handling of present/missing/modified guardrail states.
"""

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))
from governance_check import (
    check_claude_md,
    check_settings_json,
    check_hook_scripts,
    check_pr_modifies_guardrails,
    check_env_files,
    check_gitignore,
    check_client_data_patterns,
    GUARDRAILS_MARKER_START,
    GUARDRAILS_MARKER_END,
    REQUIRED_CLAUDE_MD_SECTIONS,
    REQUIRED_DENY_RULES,
    REQUIRED_HOOKS,
)


class TestClaudeMd(unittest.TestCase):
    """Test CLAUDE.md guardrails detection."""

    def test_missing_claude_md(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            findings = check_claude_md(tmpdir)
            self.assertTrue(len(findings) > 0)
            self.assertEqual(findings[0].rule_id, "GOV-001")
            self.assertEqual(findings[0].severity, "critical")

    def test_claude_md_without_markers(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            with open(os.path.join(tmpdir, "CLAUDE.md"), "w") as f:
                f.write("# My Project\nSome custom content.")
            findings = check_claude_md(tmpdir)
            self.assertTrue(len(findings) > 0)
            self.assertEqual(findings[0].rule_id, "GOV-001a")

    def test_claude_md_with_all_sections(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            content = GUARDRAILS_MARKER_START + "\n"
            for section in REQUIRED_CLAUDE_MD_SECTIONS:
                content += f"## {section}\nSome rules here.\n"
            content += GUARDRAILS_MARKER_END + "\n"
            with open(os.path.join(tmpdir, "CLAUDE.md"), "w") as f:
                f.write(content)
            findings = check_claude_md(tmpdir)
            self.assertEqual(len(findings), 0, "Should pass with all sections present")

    def test_claude_md_missing_sections(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            content = GUARDRAILS_MARKER_START + "\n"
            content += "## Sensitive File Access\nSome rules.\n"
            content += GUARDRAILS_MARKER_END + "\n"
            with open(os.path.join(tmpdir, "CLAUDE.md"), "w") as f:
                f.write(content)
            findings = check_claude_md(tmpdir)
            self.assertTrue(len(findings) > 0)
            self.assertEqual(findings[0].rule_id, "GOV-001b")


class TestSettingsJson(unittest.TestCase):
    """Test settings.json deny rules detection."""

    def test_missing_settings(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            findings = check_settings_json(tmpdir)
            self.assertTrue(len(findings) > 0)
            self.assertEqual(findings[0].rule_id, "GOV-002")

    def test_invalid_json(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            claude_dir = os.path.join(tmpdir, ".claude")
            os.makedirs(claude_dir)
            with open(os.path.join(claude_dir, "settings.json"), "w") as f:
                f.write("not json {{{")
            findings = check_settings_json(tmpdir)
            self.assertTrue(len(findings) > 0)
            self.assertEqual(findings[0].rule_id, "GOV-002a")

    def test_complete_settings(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            claude_dir = os.path.join(tmpdir, ".claude")
            os.makedirs(claude_dir)
            settings = {"permissions": {"deny": list(REQUIRED_DENY_RULES)}}
            with open(os.path.join(claude_dir, "settings.json"), "w") as f:
                json.dump(settings, f)
            findings = check_settings_json(tmpdir)
            self.assertEqual(len(findings), 0, "Should pass with all deny rules")

    def test_missing_deny_rules(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            claude_dir = os.path.join(tmpdir, ".claude")
            os.makedirs(claude_dir)
            settings = {"permissions": {"deny": ["Read(**/.env)"]}}
            with open(os.path.join(claude_dir, "settings.json"), "w") as f:
                json.dump(settings, f)
            findings = check_settings_json(tmpdir)
            self.assertTrue(len(findings) > 0)
            self.assertEqual(findings[0].rule_id, "GOV-002b")


class TestHookScripts(unittest.TestCase):
    """Test hook script presence detection."""

    def test_missing_hooks_dir(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            findings = check_hook_scripts(tmpdir)
            self.assertTrue(len(findings) > 0)
            self.assertEqual(findings[0].rule_id, "GOV-003")

    def test_all_hooks_present(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            hooks_dir = os.path.join(tmpdir, ".claude", "hooks")
            os.makedirs(hooks_dir)
            for hook in REQUIRED_HOOKS:
                with open(os.path.join(hooks_dir, hook), "w") as f:
                    f.write("#!/bin/bash\n")
            findings = check_hook_scripts(tmpdir)
            self.assertEqual(len(findings), 0, "Should pass with all hooks present")

    def test_missing_some_hooks(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            hooks_dir = os.path.join(tmpdir, ".claude", "hooks")
            os.makedirs(hooks_dir)
            with open(os.path.join(hooks_dir, "block-sensitive-files.sh"), "w") as f:
                f.write("#!/bin/bash\n")
            findings = check_hook_scripts(tmpdir)
            self.assertTrue(len(findings) > 0)
            self.assertEqual(findings[0].rule_id, "GOV-003a")


class TestPrModifiesGuardrails(unittest.TestCase):
    """Test detection of guardrail file modifications in PR."""

    def test_pr_modifies_claude_md(self):
        findings = check_pr_modifies_guardrails(["CLAUDE.md", "src/app.py"])
        self.assertTrue(len(findings) > 0)
        self.assertEqual(findings[0].rule_id, "GOV-004")

    def test_pr_modifies_claude_dir(self):
        findings = check_pr_modifies_guardrails([".claude/settings.json"])
        self.assertTrue(len(findings) > 0)
        self.assertEqual(findings[0].rule_id, "GOV-004")

    def test_pr_normal_files_not_flagged(self):
        findings = check_pr_modifies_guardrails(["src/app.py", "tests/test_app.py"])
        self.assertEqual(len(findings), 0, "Should not flag normal file changes")

    def test_pr_empty_changes(self):
        findings = check_pr_modifies_guardrails([])
        self.assertEqual(len(findings), 0)


class TestEnvFiles(unittest.TestCase):
    """Test .env file detection in repository."""

    def test_env_file_found(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            with open(os.path.join(tmpdir, ".env"), "w") as f:
                f.write("SECRET=value\n")
            findings = check_env_files(tmpdir)
            self.assertTrue(len(findings) > 0)
            self.assertEqual(findings[0].rule_id, "GOV-005")

    def test_env_production_found(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            with open(os.path.join(tmpdir, ".env.production"), "w") as f:
                f.write("SECRET=value\n")
            findings = check_env_files(tmpdir)
            self.assertTrue(len(findings) > 0)

    def test_no_env_files(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            with open(os.path.join(tmpdir, "app.py"), "w") as f:
                f.write("print('hello')\n")
            findings = check_env_files(tmpdir)
            self.assertEqual(len(findings), 0, "Should not flag non-env files")


class TestGitignore(unittest.TestCase):
    """Test .gitignore validation."""

    def test_missing_gitignore(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            findings = check_gitignore(tmpdir)
            self.assertTrue(len(findings) > 0)
            self.assertEqual(findings[0].rule_id, "GOV-006")

    def test_complete_gitignore(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            with open(os.path.join(tmpdir, ".gitignore"), "w") as f:
                f.write(".env\ncredentials.json\n*.pem\n*.key\nsecrets/\n")
            findings = check_gitignore(tmpdir)
            self.assertEqual(len(findings), 0)

    def test_incomplete_gitignore(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            with open(os.path.join(tmpdir, ".gitignore"), "w") as f:
                f.write(".env\n")
            findings = check_gitignore(tmpdir)
            self.assertTrue(len(findings) > 0)
            self.assertEqual(findings[0].rule_id, "GOV-006a")


class TestClientDataPatterns(unittest.TestCase):
    """Test client data pattern detection."""

    def _scan_code(self, code: str, filename: str = "app.py") -> list:
        with tempfile.TemporaryDirectory() as tmpdir:
            filepath = os.path.join(tmpdir, filename)
            with open(filepath, "w") as f:
                f.write(code)
            findings = check_client_data_patterns(tmpdir)
        return [f for f in findings if f.rule_id == "GOV-007"]

    def test_real_email_detected(self):
        findings = self._scan_code('contact = "john.doe@acme-corp.com"')
        self.assertTrue(len(findings) > 0, "Should detect real email address")

    def test_confidentiality_marker_detected(self):
        findings = self._scan_code('# CONFIDENTIAL - do not share')
        self.assertTrue(len(findings) > 0, "Should detect confidentiality marker")

    def test_example_email_not_flagged(self):
        findings = self._scan_code('contact = "user@example.com"')
        self.assertEqual(len(findings), 0, "Should not flag example.com emails")

    def test_test_data_not_flagged(self):
        findings = self._scan_code('test_email = "test@example.com"')
        self.assertEqual(len(findings), 0, "Should not flag test data")

    def test_normal_code_not_flagged(self):
        findings = self._scan_code('x = 42\nprint("hello world")\n')
        self.assertEqual(len(findings), 0, "Should not flag normal code")


if __name__ == "__main__":
    unittest.main()
