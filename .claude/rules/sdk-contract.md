---
title: LiteSOC Python SDK Contract
scope: litesoc-python
applies_to:
  - "src/litesoc/**"
  - "pyproject.toml"
  - "CHANGELOG.md"
  - "tests/**"
---

# SDK Contract Rule (Python)

- **Transport & auth:** API base `https://api.litesoc.io`, authenticate with the `X-API-Key` header.
- **Parity:** Keep the method surface and behavior at 100% parity with `litesoc-node` and `litesoc-php`. Any change opens parity tasks for both.
- **No server logic:** Never embed server-only concerns — `severity`, `timestamp`, quota, retention, and redaction are server-side.
- **Naming:** public API is **snake_case**.
- **Contract source of truth:** Confirm shapes against `lsoc_app` and update `litesoc-docs` on any contract change.
- **Quality gates:** mypy **strict** clean, ruff clean, and pytest at **100% coverage** (`--cov-fail-under=100`) before commit/PR.
- **Versioning:** Reconcile version drift across `pyproject.toml`, `__init__.__version__`, and `CHANGELOG.md` before release. (Known drift: `2.5.1` / `2.2.0` / `2.5.0`.)
- **Testing:** Mock HTTP with `responses`; never use real API keys or PII (use `lsoc_live_mockkey`, `test@example.com`).
- **Publishing** is gated by the root `release-check` skill and `publish.yml` — do not release ad hoc.
