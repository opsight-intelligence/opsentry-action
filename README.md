# OpSentry GitHub Action

Scan PRs for security vulnerabilities, code quality issues, and guardrail compliance.

## Quick Start

Add to `.github/workflows/opsentry.yml`:

```yaml
name: OpSentry
on:
  pull_request:
    branches: [main]

permissions:
  contents: write
  pull-requests: write

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: opsight-intelligence/opsentry-action@v1
```

That's it. Every PR gets scanned for secrets, SQL injection, dangerous patterns, code quality, and guardrail compliance.

## Inputs

| Input | Default | Description |
|-------|---------|-------------|
| `scan-type` | `all` | `security`, `code-health`, `governance`, or `all` |
| `scan-mode` | `changed` | `changed` (PR files only) or `full` (all files) |
| `fail-on` | `high` | Fail on: `critical`, `high`, `medium`, `low`, `none` |
| `auto-fix` | `true` | Auto-fix safe issues and commit to PR branch |
| `post-comment` | `true` | Post results as a PR comment |
| `llm-provider` | `none` | LLM for docstring generation: `bedrock`, `anthropic`, `openai`, `local`, `none` |

## Examples

### Security scan only

```yaml
- uses: opsight-intelligence/opsentry-action@v1
  with:
    scan-type: security
    fail-on: critical
```

### Full scan with LLM docstrings

```yaml
- uses: opsight-intelligence/opsentry-action@v1
  with:
    llm-provider: anthropic
  env:
    ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
```
