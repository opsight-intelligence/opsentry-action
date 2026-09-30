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
| `config-path` | `''` | Path to a `guardrails.yaml` config file |
| `scan-mode` | `changed` | `changed` (PR files only) or `full` (all files) |
| `fail-on` | `high` | **Not implemented yet** -- accepted but ignored; see below |
| `auto-fix` | `true` | Auto-fix safe issues and commit to PR branch |
| `post-comment` | `true` | Post results as a PR comment |
| `llm-provider` | `none` | LLM for docstring generation: `bedrock`, `anthropic`, `openai`, `local`, `none` |

### Known limitations

- **`fail-on` is not implemented yet.** The input is accepted but no step reads it, so
  the action does not fail the check based on finding severity. Do not rely on it as a
  merge gate.
- **Outputs are not populated yet.** `action.yml` declares `findings-count`,
  `critical-count`, `high-count` and `report-path`, but none of them is set, so they are
  always empty. Do not reference them from later steps.

## Outputs

| Output | Status |
|--------|--------|
| `findings-count` | Declared, not populated |
| `critical-count` | Declared, not populated |
| `high-count` | Declared, not populated |
| `report-path` | Declared, not populated |

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
    scan-mode: full
    llm-provider: anthropic
  env:
    ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
```

### LLM provider credentials

The action does not take API keys as inputs. Pass whatever credentials your chosen
`llm-provider` needs as `env:` on the step, sourced from repository secrets -- for
example `ANTHROPIC_API_KEY` for `anthropic`, the provider's standard API-key variable
for `openai`, or AWS credentials (for example via `aws-actions/configure-aws-credentials`)
for `bedrock`. `local` and `none` need no credentials. Never put a key in the workflow
file itself.

## Versioning

This action follows [Semantic Versioning](https://semver.org/). Each release is tagged
`vX.Y.Z`, and the floating `v1` tag always points at the newest `v1.x.y` release.

- Pin to `@v1` to receive backwards-compatible updates automatically
- Pin to `@v1.0.1` to lock to an exact release

See [CHANGELOG.md](CHANGELOG.md) for the release history.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for the branching model, versioning rules, and
what every change is expected to include.
