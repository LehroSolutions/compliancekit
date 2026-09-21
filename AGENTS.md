# AGENTS.md — ComplianceKit

Operating contract for AI coding agents, with human-in-the-loop checkpoints.
Humans: this file doubles as the fastest way to work on ComplianceKit.

## Identity

ComplianceKit is a POPIA-focused PII scanner and compliance toolkit for South
African data patterns. The runtime is **Python 3.11+** (setuptools project in
`compliancekit/`, tests in `tests/`). The `package.json` at the root is a
**tooling stub only** — do not add JS runtime code to it.
License: Apache-2.0.

## Command Reference

| Task | Command |
|---|---|
| Install (editable, with dev tools) | `pip install -e ".[dev]"` |
| Run tests | `python -m pytest -q` |
| Lint (Python) | `python -m ruff check .` |
| CLI | `compliancekit --help` |
| Docs (build/check) | `bun run docs:build` / `bun run docs:check` |
| **Full verify (run before declaring done)** | `python -m pytest -q && python -m ruff check .` |

## Verify Contract

Verify = pytest + ruff, run inside the project venv (`.venv/`). Must pass
before you report success. If ruff is not installed, run
`pip install -e ".[dev]"` first — do not skip lint silently.

## Codebase Map

- `compliancekit/` — Python package: detection core, CLI (`cli.py`), server
- `tests/` — pytest suite (`test_pii.py`, `test_popia.py`, `test_version.py`, …)
- `webapp/` — auxiliary HTTP server/ops surface (hardened, see CHANGELOG)
- `convex/` — Convex backend used by the webapp
- `scripts/docs.mjs` — documentation pipeline

## Conventions

- Zero runtime dependencies — detection is pure Python. Do not add runtime
  deps without explicit human approval; dev deps go in `[project.optional-dependencies].dev`.
- New PII patterns require: detector + unit test + a POPIA reference comment.
- Regexes must be anchored and tested against false positives (SA ID numbers,
  phone numbers, bank accounts have overlapping formats).

## Human-in-the-Loop Checkpoints

Ask the human before:
- Adding any runtime dependency (this is a deliberate zero-dep library).
- Changing detection behavior in ways that could alter scan verdicts.
- Modifying the webapp HTTP server (it has been red-team hardened).

## Danger Zones

- Never commit real PII, sample customer data, or `.env` files.
- Never commit `.venv/`, `__pycache__/`, or `.pytest_cache/` (gitignored).
- Never relax ruff/pytest to make verify pass — fix the code.
