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
| `config-path` | `''` | Path to a scanner config JSON in the repo being scanned, same shape as [`config/default.json`](config/default.json); empty uses the defaults |
| `scan-mode` | `changed` | `changed` (PR files only) or `full` (all files) |
| `fail-on` | `high` | Fail the check when any finding is at or above `critical`, `high`, `medium` or `low`; `none` never fails |
| `auto-fix` | `true` | Auto-fix safe issues and commit to PR branch |
| `post-comment` | `true` | Post results as a PR comment |
| `llm-provider` | `none` | LLM for docstring generation: `bedrock`, `anthropic`, `openai`, `local`, `none` |

## How it works

The scanners ship inside this action (`scripts/`), so nothing else is checked out and no token beyond the default
`GITHUB_TOKEN` is needed. Each selected scan writes a JSON report to the runner's temporary directory, never into
your repository, so auto-fix commits contain only the fixes. In `changed` mode the action fetches the pull
request's base branch and scans only the files that differ from it; outside a pull request, or if the base branch
cannot be fetched, it scans every file. A last step adds up the reports, writes a summary to the job page, sets the
outputs and applies `fail-on`. A scanner that crashes without writing its report fails the check as a scan error,
so a broken run never passes as clean.

### Permissions

`auto-fix: true` commits to the pull request branch and needs `contents: write`; `post-comment: true` needs
`pull-requests: write`. Pull requests from forks cannot be pushed to, so auto-fix logs a warning there and the scan
still runs. Set `auto-fix: 'false'` for a read-only check.

## Outputs

| Output | Contents |
|--------|----------|
| `findings-count` | Total findings across the scans that ran |
| `critical-count` | Critical findings |
| `high-count` | High findings |
| `report-path` | Directory holding `security-report.json`, `code-health-report.json` and `governance-report.json` |

```yaml
- uses: opsight-intelligence/opsentry-action@v1
  id: opsentry
  with:
    fail-on: none
- run: echo "OpSentry found ${{ steps.opsentry.outputs.findings-count }} issues"
- uses: actions/upload-artifact@v4
  with:
    name: opsentry-reports
    path: ${{ steps.opsentry.outputs.report-path }}
```

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

## Licence

Apache License 2.0, the same as [OpSentry](https://github.com/opsight-intelligence/opsentry). See [LICENSE](LICENSE).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for the branching model, versioning rules, and
what every change is expected to include.
