**What changed and why**

**Testing**

- [ ] `uv run ruff check .` / `uv run ruff format --check .`
- [ ] `uv run mypy`
- [ ] `uv run pytest`
- [ ] Integration tests against real PostgreSQL (`docker compose --profile test run --rm integration-tests`), if the change touches the control plane or database
- [ ] A new/updated ADR, if this changes a trust boundary or architectural decision

No real credentials, hostnames, IPs, or log data in the diff or in test fixtures.
