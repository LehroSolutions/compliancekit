# Changelog

All notable changes to this project are documented in this file.

## [1.0.0] - 2026-03-02

### Added
- Production release documentation and gating:
  - `RELEASE_CHECKLIST.md`
  - CI unit-test execution in `.github/workflows/ci.yml`
  - New unit tests for PII detection, POPIA summary behavior, and production runtime config guards
- Runtime environment controls in `webapp/server.py`:
  - `APP_ENV`, `APP_HOST`, `APP_PORT`, `ACCESS_TTL_MIN`, `REFRESH_TTL_DAYS`, `MAX_BODY_BYTES`
  - Production startup validation to reject insecure default credentials
- Response hardening:
  - `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Cache-Control` headers
  - Robust malformed JSON and request-size handling with explicit 4xx responses
- API summary normalization to expose both snake_case and camelCase fields for compatibility.

### Changed
- Package version bumped from `0.1.0` to `1.0.0`.
- Frontend (`webapp/index.html`) hardened to:
  - Escape dynamic content before HTML injection
  - Handle auth expiry and clear stale sessions
  - Remove fabricated AI remediation fallback output
  - Align rendering with normalized API summary fields
- SQLite connection opened with cross-thread access plus write locking to prevent runtime thread errors.
- SA phone regex updated to properly detect `+27...` numbers.

### Fixed
- Frontend/backend summary key mismatch (`risk_level` vs `riskLevel`, etc.).
- False negative for valid South African `+27` phone number detection.
