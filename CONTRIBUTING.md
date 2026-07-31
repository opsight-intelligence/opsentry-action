# Contributing

## Branching model (Git Flow)

| Branch | Role |
|--------|------|
| `main` | Production. Only ever updated by merging `release/*` or `hotfix/*`. |
| `develop` | Integration branch. Default branch for PRs. |
| `feature/<name>` | Branched from `develop`, merged back into `develop`. |
| `bugfix/<name>` | Non-urgent fixes. Branched from `develop`. |
| `release/<version>` | Cut from `develop`, merged into `main` **and** back into `develop`. |
| `hotfix/<version>` | Cut from `main` for urgent fixes, merged into `main` **and** `develop`. |

Never commit directly to `main` or `develop` — always open a PR.

## Versioning

Semantic Versioning (`MAJOR.MINOR.PATCH`), tracked in the `VERSION` file at the repo root.

- **MAJOR** — breaking changes to action inputs, outputs, or behavior
- **MINOR** — new inputs, outputs, or backwards-compatible capabilities
- **PATCH** — bug fixes, documentation, internal refactors

Every commit bumps `VERSION` and stages it alongside the change.

### Tags

This repository uses two-tier tagging, as is conventional for GitHub Actions:

- `vX.Y.Z` — immutable tag created for every release that lands on `main`
- `v1` — floating major tag, moved forward to the newest `v1.x.y` release

Consumers pin to `@v1`. Never move a `vX.Y.Z` tag once published.

## Required with every change

A change is not complete until all four land in the same commit:

1. **Code** — the change itself
2. **`VERSION`** — bumped per SemVer
3. **`CHANGELOG.md`** — entry added under `## [Unreleased]`, in the appropriate
   `### Added` / `### Changed` / `### Deprecated` / `### Removed` / `### Fixed` /
   `### Security` subsection
4. **Docs** — `README.md` input/output tables and examples updated for any change to
   `action.yml`; migration notes written for anything breaking

If a change genuinely affects no documentation, say so in the PR rather than skipping silently.

## Commit messages

Conventional Commits, with the resulting version in brackets:

```
type(scope): subject [vX.Y.Z]
```

`type` is one of `feat`, `fix`, `docs`, `style`, `refactor`, `perf`, `test`, `chore`,
`build`, `ci`. Subject is imperative and under 72 characters. Use the body to explain
why, not what.

Examples:

- `feat(inputs): add severity-threshold input [v1.1.0]`
- `fix(scan): handle empty PR diff [v1.0.1]`

## Releasing

1. Cut `release/<version>` from `develop`
2. Roll `## [Unreleased]` into a `## [<version>] - <YYYY-MM-DD>` section
3. Open a PR into `main`, merge, then tag `v<version>` and move the `v1` tag
4. Merge `main` back into `develop`
5. Delete the release branch locally and on the remote, and close any PRs the release
   supersedes
