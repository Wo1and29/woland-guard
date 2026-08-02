# Contributing to Woland Guard

Woland Guard is a defensive Linux server monitoring MVP. This document describes how the
project is actually built and reviewed today, not an aspirational process.

## Project layout

`uv` workspace with three packages plus test/ops tooling:

```
apps/agent/            Linux agent (journald -> SQLite spool -> HTTPS delivery)
apps/control-plane/    FastAPI API, detection engine, outbox worker, Dashboard
packages/contracts/    Shared Pydantic event contract (woland-guard-contracts)
detection-rules/       Versioned YAML detection rules
migrations/            Alembic migrations
scripts/demo_e2e/      Synthetic demo generator and 8B release-verification tooling
tests/unit/            No external services required
tests/integration/     Real PostgreSQL, run through Docker Compose
tests/e2e/             Full Compose/Docker/browser release gates, explicitly opt-in
tests/browser/         Playwright/Chromium Dashboard verification
docs/adr/              One ADR per implemented stage
```

## Setting up

```bash
uv sync --all-packages
uv run pytest
```

This runs unit tests only; PostgreSQL integration tests and Docker/browser/e2e tests skip
themselves automatically without the Compose environment (see below).

## Before opening a change

```bash
uv run ruff check .
uv run ruff format --check .
uv run mypy
uv run pytest
```

All four must pass. `mypy` runs in `strict` mode across `apps/agent/src`,
`apps/control-plane/src`, `packages/contracts/src`, `scripts` and `tests` — there is no
per-file opt-out beyond `tests/**` being exempt from Ruff's `S101` (assert) rule.

For changes touching the database, backend business logic, ingestion, Telegram delivery or the
Dashboard, also run the PostgreSQL integration suite:

```bash
docker compose up -d --wait postgres control-plane
docker compose exec control-plane alembic upgrade head
docker compose exec control-plane alembic check
docker compose --profile test run --rm integration-tests
docker compose down -v
```

`alembic check` catches drift between the SQLAlchemy models and the migration history — run it
whenever you add or edit a model.

For changes touching `scripts/demo_e2e`, `tests/e2e` or `tests/browser`, also run the relevant
opt-in suite locally before proposing the change (these are release gates, not routine CI
checks — see [docs/demo.md](docs/demo.md)):

```bash
WG_RUN_DEMO_E2E=1 uv run pytest tests/e2e -k "not tracked_only"
```

The tracked-only clean-install gate (`WG_RUN_CLEAN_INSTALL=1`) additionally requires a clean
`git status` and a committed candidate, since it extracts `git archive HEAD` — it is meant to run
against a commit you already intend to keep, not mid-edit.

## Architecture Decision Records

Every implemented stage has a corresponding `docs/adr/NNNN-slug.md`. An ADR here is not a
proposal — it is written once the stage is actually implemented and reviewed, and records:

- the context that forced the decision;
- the concrete decisions made, numbered;
- explicit "Ограничения"/"Последствия" — what the stage does *not* guarantee.

If your change meaningfully alters a documented decision (not just its implementation detail),
add a new ADR rather than editing history. Small clarifications to an already-accurate ADR are
fine to edit in place.

## Detection rules

Rules live in `detection-rules/*.yaml`, one `rule_key` per file, validated against a closed
Pydantic schema (`schema_version: 1`, exactly one of `single` / `threshold` / `distinct_count`
/ `sequence` / `first_seen`, no expression evaluation). See
[docs/detection-rules.md](docs/detection-rules.md) for the schema and current rule set. After
adding or editing a rule:

```bash
docker compose exec control-plane woland-guard-admin validate-rules --rules-dir /workspace/detection-rules
docker compose exec control-plane woland-guard-admin sync-rules --rules-dir /workspace/detection-rules
```

Add a test event batch and an integration test asserting the expected incident, following the
pattern in `tests/integration/test_detection_engine.py`.

## Commit style

Single-line, imperative, [Conventional Commits](https://www.conventionalcommits.org/)-style
subjects — `feat: add X`, `fix: correct Y`, `test: add Z`, `ci: ...`, `chore: ...`. No commit
body is used in this repository's history; keep the summary in the PR description instead if it
needs more context than the subject line carries.

## What not to do

- No hardcoded secrets, tokens or real credentials anywhere in the tree — configuration only
  through environment variables, and `.env.example` never carries real values.
- No real server logs, hostnames, IP addresses or personal data — synthetic data only, see
  `detection-rules` test fixtures and `scripts/demo_e2e` for the existing pattern.
- No bare `except:`/silently swallowed errors, no `shell=True`, no string-concatenated SQL —
  Ruff's `S` (bandit) rules and the existing code already enforce this; match it.
- Do not weaken a documented safety property (dry-run-by-default blocking, allowlist protection,
  audit logging, `TRUNCATE`/`UPDATE`/`DELETE` triggers on history/audit tables) without updating
  the corresponding ADR and [docs/threat-model.md](docs/threat-model.md) in the same change.

## Reporting security issues

Do not open a public issue for a suspected vulnerability — see [SECURITY.md](SECURITY.md).
