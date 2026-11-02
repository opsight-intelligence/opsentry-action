"""
Configuration loader for CI Agent scanners.
Loads pattern definitions, thresholds, and rules from a JSON config file.
Falls back to built-in defaults if no config file is found.
"""

import json
import os
from pathlib import Path
from typing import Any


CONFIG_ENV_VAR = "CI_AGENT_CONFIG"
DEFAULT_CONFIG_FILENAME = "default.json"


def _find_config_path() -> str | None:
    """Locate the config file by checking env var, then standard locations."""
    env_path = os.environ.get(CONFIG_ENV_VAR)
    if env_path and os.path.isfile(env_path):
        return env_path

    script_dir = Path(__file__).parent
    candidates = [
        script_dir.parent / "config" / DEFAULT_CONFIG_FILENAME,
        script_dir / "config" / DEFAULT_CONFIG_FILENAME,
        Path.cwd() / "config" / DEFAULT_CONFIG_FILENAME,
        Path.cwd() / DEFAULT_CONFIG_FILENAME,
    ]

    for candidate in candidates:
        if candidate.is_file():
            return str(candidate)

    return None


def load_config() -> dict:
    """Load configuration from JSON file. Returns empty dict if not found."""
    config_path = _find_config_path()
    if config_path is None:
        return {}

    try:
        with open(config_path, "r") as f:
            config = json.load(f)
        print(f"Config loaded from: {config_path}")
        return config
    except (json.JSONDecodeError, OSError) as e:
        print(f"Warning: Could not load config from {config_path}: {e}")
        return {}


def get_value(config: dict, *keys: str, default: Any = None) -> Any:
    """Get a nested value from config dict. Returns default if not found."""
    current = config
    for key in keys:
        if isinstance(current, dict) and key in current:
            current = current[key]
        else:
            return default
    return current


def is_rule_enabled(config: dict, *keys: str) -> bool:
    """Check if a rule group is enabled. Defaults to True if not specified."""
    group = get_value(config, *keys)
    if isinstance(group, dict):
        return group.get("enabled", True)
    return True


def get_rule_severity(config: dict, *keys: str, default: str = "high") -> str:
    """Get the severity level for a rule group. Returns default if not specified."""
    group = get_value(config, *keys)
    if isinstance(group, dict):
        return group.get("severity", default)
    return default


def get_pattern_pairs(config: dict, *keys: str, default: list = None) -> list[tuple[str, str]]:
    """Load pattern/name pairs from config. Handles both old and new format."""
    group = get_value(config, *keys, default=None)
    if group is None:
        return default or []

    items = group
    if isinstance(group, dict):
        if not group.get("enabled", True):
            return []
        items = group.get("patterns", [])

    if not items:
        return default or []
    return [(item["pattern"], item["name"]) for item in items if isinstance(item, dict)]


def get_dangerous_patterns(config: dict, *keys: str, default: list = None) -> list[tuple]:
    """Load dangerous pattern tuples (pattern, name, desc, fixable, fix_type) from config."""
    group = get_value(config, *keys, default=None)
    if group is None:
        return default or []

    items = group
    if isinstance(group, dict):
        if not group.get("enabled", True):
            return []
        items = group.get("patterns", [])

    if not items:
        return default or []
    result = []
    for item in items:
        if isinstance(item, dict):
            result.append((
                item["pattern"],
                item["name"],
                item.get("description", ""),
                item.get("auto_fixable", False),
                item.get("fix_type"),
            ))
    return result


def get_custom_rules(config: dict, scanner: str = None) -> list[dict]:
    """Get custom rules from config, optionally filtered by scanner type."""
    rules = get_value(config, "custom_rules", default=[])
    result = []
    for item in rules:
        if isinstance(item, dict) and "rule_id" in item:
            if not item.get("enabled", True):
                continue
            if scanner and item.get("scanner") != scanner:
                continue
            result.append(item)
    return result


def get_false_positive_overrides(config: dict) -> list[dict]:
    """Load confirmed false positive overrides from config."""
    fp_section = get_value(config, "false_positive_overrides", default={})
    overrides = fp_section.get("overrides", [])
    return [o for o in overrides if isinstance(o, dict) and not o.get("_example")]


def is_false_positive(config: dict, rule_id: str, file_path: str) -> bool:
    """Check if a finding matches a confirmed false positive override."""
    for override in get_false_positive_overrides(config):
        if override.get("rule_id") == rule_id:
            pattern = override.get("file_pattern", "")
            if not pattern or pattern in file_path:
                return True
    return False


_config_cache = None


def get_config() -> dict:
    """Get cached config. Loads once on first call."""
    global _config_cache
    if _config_cache is None:
        _config_cache = load_config()
    return _config_cache


def reset_cache() -> None:
    """Reset config cache. Useful for testing."""
    global _config_cache
    _config_cache = None
