# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed
- The action works for any repository. It used to check out `opsight-intelligence/opsentry` and run
  `.opsentry/ai-ci-agents/scripts/*.py`, a directory that repository has never contained, so every scan step
  failed. The scanners now ship inside the action under `scripts/`, with their defaults in `config/default.json`.
- `fail-on` is applied: a final step adds up the reports and fails the check when any finding is at or above the
  chosen severity; `none` never fails. A scanner that crashes without writing its report fails the check as a
  scan error instead of passing.
- The declared outputs `findings-count`, `critical-count`, `high-count` and `report-path` are set.
- Reports go to the runner's temporary directory instead of the repository, so auto-fix no longer commits them.
- `scan-mode: changed` fetches the pull request's base branch first, so it scans the PR's files instead of
  silently falling back to every file.
- `config-path` is passed to the scanners; a path that does not exist fails the run with a clear error.

### Added
- `scripts/summarize.py` with unit tests, the scanners' own tests, a CI workflow that runs them and runs the
  action against this repository (outputs, reports, a strict `fail-on`), and a job summary table.
- `LICENSE`: Apache License 2.0, the same as OpSentry.

### Changed
- `config-path` now names a scanner config JSON (the shape of `config/default.json`), not `guardrails.yaml`.
- Python 3.12 on the runner (was 3.11).

## [1.0.1] - 2026-09-30

### Added
- `VERSION` file, `CHANGELOG.md`, and `CONTRIBUTING.md` establishing the Git Flow,
  semantic versioning, changelog, and documentation policy for this repository.
- `develop` integration branch. Feature work now branches from `develop` and reaches
  `main` through a `release/*` branch.

### Changed
- Release tagging is now two-tier: an immutable `vX.Y.Z` tag per release plus the
  floating `v1` major tag that workflow consumers pin to.
- README now documents the `config-path` input and adds an Outputs table.
- README states plainly that `fail-on` is not implemented yet and that the declared
  outputs are never populated, so nobody relies on either as a merge gate or in a
  later step.
- The "Full scan with LLM docstrings" example now actually sets `scan-mode: full`,
  and README explains how to pass provider credentials through `env:` from secrets.

## [1.0.0] - 2026-06-11

### Added
- Initial release of the OpSentry composite GitHub Action.
- Three scan types selectable via `scan-type`: `security`, `code-health`, `governance`,
  or `all`.
- `scan-mode` input to scan only PR-changed files (`changed`) or the whole tree (`full`).
- `fail-on` severity threshold input (`critical`, `high`, `medium`, `low`, `none`).
- `auto-fix` input that applies safe fixes and commits them to the PR branch.
- `post-comment` input that publishes scan results as a PR comment.
- `llm-provider` input for docstring generation (`bedrock`, `anthropic`, `openai`,
  `local`, `none`).
- Outputs: `findings-count`, `critical-count`, `high-count`, `report-path`.

[Unreleased]: https://github.com/opsight-intelligence/opsentry-action/compare/v1.0.1...HEAD
[1.0.1]: https://github.com/opsight-intelligence/opsentry-action/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/opsight-intelligence/opsentry-action/releases/tag/v1.0.0
