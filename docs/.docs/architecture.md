# ComplianceKit Architecture

  ## Intent
  POPIA-focused PII scanning core and operator console for South African data patterns.

  ## Runtime shape
  - Domain: **Privacy / POPIA compliance**
  - Primary stack: Python 3.11+, stdlib HTTP server, SQLite optional state, vanilla webapp
  - Key entrypoints:
- `compliancekit/pii.py`
- `compliancekit/popia.py`
- `webapp/server.py`
- `webapp/index.html`

  ## Boundaries
  - Validate inputs at trust boundaries.
  - Keep authorization explicit near data access.
  - Prefer recoverable errors over silent failure.
  - Keep side effects isolated and observable.

  ## Related
  - [Design System](./design-system.md)
  - [Security](./security.md)
  - [ADR-0001](./adr-0001-docs-system.md)
  - [Roadmap](./roadmap.md)
