# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
