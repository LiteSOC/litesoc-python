# CLAUDE.md — litesoc-python

> Complements the workspace root [`../CLAUDE.md`](../CLAUDE.md). The root defines shared agents (`integration-reviewer`, `backend`, `security`, `test-runner`, `bug-investigator`, …), rules, and skills — this file does **not** redefine them. Read the root first for cross-repo standards.

## Purpose
Official LiteSOC **Python SDK** (PyPI package `litesoc`). Typed client over the LiteSOC HTTP API for ingestion (`POST /collect`) and management (`/alerts`, `/events`). It must stay at **100% behavioral parity** with `litesoc-node` and `litesoc-php` and in sync with the `lsoc_app` API contract and `litesoc-docs`.

## Technology stack
- **Language:** Python **>=3.9** (tested 3.9–3.13). Ships `py.typed`.
- **Layout:** src-layout; build backend **setuptools>=70** (`build_meta`).
- **Runtime dep:** `requests>=2.32`.
- **Test:** pytest `>=8` (+ `pytest-asyncio`, `responses`).
- **Types:** mypy `>=1.13` (strict).
- **Lint/format:** ruff `>=0.8`.

## Key directories
- `src/litesoc/` — `__init__.py`, `client.py`, `types.py`.
- `tests/` — pytest suite.

## Commands
No scripts table / Makefile / tox — commands mirror CI:
| Task | Command |
| --- | --- |
| Lint | `ruff check src/ tests/` |
| Typecheck | `mypy src/ --ignore-missing-imports` |
| Test + coverage | `pytest tests/ -v --cov=src/litesoc --cov-report=term-missing --cov-fail-under=100` |

Coverage is **fail-under 100** — every path must be tested.

## Architecture & boundaries
- Public entry: `class LiteSOC`.
- **Methods:** `track`, `track_batch`, `flush`, `get_queue_size`, `clear_queue`, `shutdown`, `get_alerts`, `get_alert`, `resolve_alert`, `mark_alert_safe`, `get_events`, `get_event`, `get_plan_info`, `has_plan_info`, plus `track_*` convenience helpers.
- **Exported models:** `SecurityEvents`, `Actor`, `Alert`, `Event`, `Forensics`, `Location`, `NetworkForensics`, `TrackOptions`, `LiteSOCConfig`.
- **Error classes:** `LiteSOCError`, `LiteSOCAuthError`, `RateLimitError`, `NotFoundError`, `PlanRestrictedError`, `ValidationError`.
- **Naming:** public API is **snake_case**.
- **Client boundary:** transport + typing only. Server assigns `severity` and `timestamp`; quota, retention, and redaction are **server concerns**. Batches cap at **100 events**.

## External dependencies
- HTTP API base `https://api.litesoc.io`, authenticated with the `X-API-Key` header.
- Response headers surfaced to callers: `X-LiteSOC-Plan`, `X-LiteSOC-Retention`, `X-LiteSOC-Cutoff`.

## Environment variables
None read in `src/`. All configuration flows through `LiteSOCConfig` (constructor options). Do not add hidden `os.environ` reads.

## Security-sensitive code paths
- API-key handling / `X-API-Key` header construction and version metadata in `client.py`.
- Error mapping (auth vs. rate-limit vs. plan-restricted) — must not leak key material.
- Tests mock HTTP via `responses`; use mock credentials only (e.g. `lsoc_live_mockkey`), never real keys or PII.

## Database / migration responsibility
None. SDKs own no schema or migrations.

## Deployment / registry target
- **PyPI** package `litesoc`. `pyproject` version **2.5.1**.
- ⚠️ **Version drift:** `__init__.__version__` is **2.2.0** and `CHANGELOG.md` top is **2.5.0** vs `pyproject` **2.5.1**. Reconcile all three before release (`release-check`).
- CI: `ci.yml` (ruff, mypy, test matrix 3.9–3.13 with coverage fail-under 100, cross-OS) and `publish.yml` (`python -m build` + `pypa/gh-action-pypi-publish`).

## Cross-repository consumers & dependencies
- Parity peers: **litesoc-node**, **litesoc-php**. Contract source of truth: **lsoc_app** + **litesoc-docs**.

## Repo-specific rules & skills
- Rule: [`.claude/rules/sdk-contract.md`](.claude/rules/sdk-contract.md) — parity, versioning, and testing constraints.
- Cross-repo/integration/testing/security concerns follow the **root** rules and agents.
