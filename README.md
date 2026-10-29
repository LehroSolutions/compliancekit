<p align="center">

Deployment, release checks, persistence, backup, and rollback: [OPERATIONS.md](OPERATIONS.md).
  <h1 align="center">ComplianceKit</h1>
  <p align="center">
    <strong>POPIA-focused PII scanner and compliance toolkit for South African data patterns.</strong>
    <br />
    Built and maintained by <a href="https://github.com/LehroSolutions">LehroSolutions</a>
  </p>
  <p align="center">
    <a href="https://github.com/LehroSolutions/compliancekit/actions"><img src="https://img.shields.io/github/actions/workflow/status/LehroSolutions/compliancekit/ci.yml?label=CI&style=flat-square" alt="CI" /></a>
    <img src="https://img.shields.io/badge/python-3.11%2B-blue?style=flat-square" alt="Python 3.11+" />
    <img src="https://img.shields.io/badge/license-Apache--2.0-green?style=flat-square" alt="License" />
    <img src="https://img.shields.io/badge/version-1.0.0-orange?style=flat-square" alt="Version" />
  </p>
</p>

---

## What is ComplianceKit?

**ComplianceKit** is an open-source compliance toolkit purpose-built for the [Protection of Personal Information Act (POPIA)](https://popia.co.za/) — South Africa's primary data protection law. It detects personally identifiable information (PII) in free-form text, maps each finding to the applicable POPIA condition, scores risk exposure, and generates actionable remediation recommendations.

The tool is designed for **Information Officers, Data Protection Officers, compliance teams, and developers** who need to audit documents, databases, or user-submitted text for PII exposure. ComplianceKit runs entirely locally — no data leaves your machine unless you explicitly configure it to.

ComplianceKit ships as three things:

1. **A Python library** — import `detect_pii` and `build_compliance_summary` directly into your own code.
2. **A CLI scanner** — pipe files or stdin through `compliancekit` for instant terminal-based PII auditing.
3. **A self-hosted web application** — a full dashboard with PII scanning, risk visualization, scan history, remediation tracking, policy management, report generation, and role-based authentication.

---

## Key Features

| Capability                      | Description                                                                                               |
| ------------------------------- | --------------------------------------------------------------------------------------------------------- |
| **SA ID Number Detection**      | 13-digit South African ID numbers validated with Luhn checksum                                            |
| **Phone Number Detection**      | Local (`0XX`) and international (`+27`) formats                                                           |
| **Company Registration**        | `YYYY/NNNNNN/NN` format matching                                                                          |
| **Email Detection**             | Standard email pattern matching                                                                           |
| **Passport Numbers**            | South African passport format (`A` + 8 digits)                                                            |
| **Bank Account Numbers**        | 8–11 digit numbers with context-aware detection (requires keywords: _bank_, _account_, _iban_, _branch_)  |
| **Tax Reference Numbers**       | 10-digit numbers with context-aware detection (requires keywords: _tax_, _sars_, _tin_)                   |
| **POPIA Condition Mapping**     | Each finding is mapped to the relevant POPIA condition (Processing Limitation, Security Safeguards, etc.) |
| **Risk Scoring**                | Automatic risk classification: `high` (≥15 findings), `medium` (≥6), `low` (<6)                           |
| **Remediation Recommendations** | Actionable steps per POPIA condition (encryption, consent, retention policies)                            |
| **Value Masking**               | All PII values are masked in output — raw PII is never persisted                                          |
| **Web Dashboard**               | Scan text, view color-coded results, track scan history, manage remediations                              |
| **Role-Based Auth**             | Bearer token authentication with admin/operator/viewer roles and scope enforcement                        |
| **Audit Trail**                 | Login, logout, and token refresh events are recorded                                                      |
| **SQLite or explicit JSON**      | Persistent storage with explicit backend selection and startup refusal on corruption                           |
| **Docker Ready**                | Single-command deployment with the included `Dockerfile`                                                  |
| **Zero Dependencies**           | Core library uses Python stdlib only — no external packages required                                      |

---

## Quick Start

### Install (CLI)

```bash
# Clone the repository
git clone https://github.com/LehroSolutions/compliancekit.git
cd compliancekit

# Install in development mode
python -m pip install -e .

# Scan a file
compliancekit --file document.txt

# Scan from stdin
echo "ID number: 9001015009087" | compliancekit --json

# Summary only (no individual findings)
compliancekit --file document.txt --summary-only
```

CLI input is bounded to 1,000,000 characters. Oversized input, unreadable files,
and invalid UTF-8 return exit code 2 with a concise error; successful scans return
0. Detailed CLI output masks matched values and never prints the original text.

### Run the Web Application

```bash
# Copy and configure environment
cp .env.example .env
# Edit .env with your credentials (required for production)

# Start the server
python webapp/server.py

# Open in browser
# http://127.0.0.1:5101
```

### Run with Docker

```bash
docker build -t compliancekit .
docker run -p 5101:5101 \
  -e APP_ENV=production \
  -e APP_PASS=your-secure-password \
  -e AUTH_SALT=your-unique-salt \
  compliancekit
```

---

## Architecture

```
compliancekit/
├── compliancekit/              # Core Python library
│   ├── __init__.py             # Public API exports (detect_pii, build_compliance_summary)
│   ├── pii.py                  # Regex-based PII detection engine with Luhn validation
│   ├── popia.py                # POPIA condition mapping and risk scoring
│   └── cli.py                  # CLI entrypoint (compliancekit command)
├── webapp/
│   ├── server.py               # HTTP API server (threaded) with auth, RBAC, and persistence
│   └── index.html              # Single-page dashboard UI ("POPIA Radar")
├── tests/
│   ├── test_pii.py             # PII detection pattern tests
│   ├── test_popia.py           # POPIA summary behavior tests
│   ├── test_server_runtime_config.py  # Production config guard tests
│   ├── test_server_webapp.py  # Auth, scopes, body limits, regex guard, retention tests
│   └── test_version.py         # Version consistency test
├── convex/                     # UNUSED Convex mirror — the webapp does NOT use it; all 7
│   │                            # functions are unauthenticated. Retained for reference only.
│   ├── schema.ts               # Database tables: scans, findings, remediations, auditLog
│   ├── queries.ts              # Reactive read functions
│   └── mutations.ts            # Transactional write functions
├── .docs/                      # Superseded duplicate documentation tree (see .docs/README.md)
├── .github/workflows/ci.yml    # GitHub Actions CI pipeline
├── Dockerfile                  # Container deployment
├── .env.example                # Environment variable template
├── pyproject.toml              # Python package configuration
├── CHANGELOG.md                # Release history
└── RELEASE_CHECKLIST.md        # Pre-release quality gate
```

**Data flow:** Text input → `detect_pii()` → PII findings → `build_compliance_summary()` → risk-scored report with POPIA conditions and remediation steps. All PII values are masked before storage.

---

## Webapp API Reference

The webapp (`webapp/server.py`) speaks JSON over HTTP on `APP_HOST:APP_PORT` (default
`127.0.0.1:5101`). It has no TLS, no CORS, and no CSRF protection — terminate TLS and put it
behind a reverse proxy before exposing it beyond localhost.

### Unauthenticated endpoints

| Method | Path          | Description                                |
| ------ | ------------- | ------------------------------------------ |
| `GET`  | `/`           | Serves the web dashboard                   |
| `GET`  | `/api/health` | Liveness check                            |
| `GET`  | `/api/ready`  | Readiness check (reports storage backend)  |
| `POST` | `/api/auth/login` | Exchange credentials for tokens (body: `{ "username", "password" }`) |
| `POST` | `/api/auth/refresh` | Exchange a refresh token (body: `{ "refreshToken" }`) |

Everything else requires `Authorization: Bearer <accessToken>`. The token comparison is
constant-time; the token is valid for `ACCESS_TTL_MIN` minutes.

### Authenticated endpoints

| Method  | Path                       | Scope | Description                                        |
| ------- | -------------------------- | ----- | -------------------------------------------------- |
| `POST`  | `/api/scan`                | write | Scan text for PII (body: `{ "text": "..." }`)       |
| `POST`  | `/api/auth/logout`         | read  | Revoke the caller's tokens (body: `{ "refreshToken" }`) |
| `GET`   | `/api/v2/scans`            | read  | List retained scans                                |
| `POST`  | `/api/v2/scans`            | write | Create a scan, returns `{ id, summary }`            |
| `GET`   | `/api/v2/remediations`     | read  | List remediations                                  |
| `POST`  | `/api/v2/remediations`     | write | Create remediation item                            |
| `PATCH` | `/api/v2/remediations/:id` | write | Update remediation status/owner                    |
| `GET`   | `/api/v2/policies`         | read  | List policy profiles                               |
| `POST`  | `/api/v2/policies`         | write | Create policy profile                              |
| `GET`   | `/api/v2/custom-rules`     | read  | List custom detection rules                        |
| `POST`  | `/api/v2/custom-rules`     | write | Create a custom rule                               |
| `GET`   | `/api/v2/report-jobs`      | read  | List report jobs                                   |
| `POST`  | `/api/v2/report-jobs`      | write | Queue a report job                                 |
| `GET`   | `/api/v2/analytics`        | read  | Aggregate counts by PII type and risk level        |
| `POST`  | `/api/ai/remediate`        | read  | Generate a POPIA remediation action plan (body: `{ "findings": [...] }`, max `MAX_REMEDIATE_FINDINGS` entries) |

### Roles & scopes

| Role       | Scopes                   |
| ---------- | ------------------------ |
| `admin`    | `read`, `write`, `admin` |
| `operator` | `read`, `write`          |
| `viewer`   | `read`                   |

### Example flow

```bash
# 1. Log in and keep the access token
TOKEN=$(curl -s -X POST http://127.0.0.1:5101/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"..."}' | python -c 'import json,sys; print(json.load(sys.stdin)["accessToken"])')

# 2. Scan text
curl -s -X POST http://127.0.0.1:5101/api/v2/scans \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"text":"ID number: 9001015009087"}'

# 3. Add a custom rule (patterns are length-capped and screened for backtracking shapes)
curl -s -X POST http://127.0.0.1:5101/api/v2/custom-rules \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"name":"Employee ref","label":"EMP_REF","pattern":"EMP-[0-9]{4}"}'

# 4. Read the audit trail and log out
curl -s -X POST http://127.0.0.1:5101/api/auth/logout \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' -d '{}'
```

A missing or invalid token returns `401`; an insufficient scope also returns `401` with
`{"error": "Insufficient scope."}`. Repeated failed logins from one IP return `429` after
`8` attempts in `15` minutes.

### Custom rule limits

Custom patterns are operator-supplied and run against every scan, so they are screened before
they are ever compiled: `200` characters max, at most `8` quantifiers, no counted repeat above
`64`, no quantifier on a group that itself contains a quantifier or an alternation, and no two
adjacent quantified atoms whose character ranges overlap. Up to `100` rules may be stored and
at most `25` are executed per scan. A rejected pattern returns `400`.

---

## Retention, Storage & Deletion

ComplianceKit stores only **masked** PII — `90********87` — so a retained scan does not contain
the value it detected. Retained collections are trimmed on every write to fixed ceilings, so
state cannot grow without bound:

| Collection | Retained | Rationale |
| ---------- | -------- | --------- |
| Scans | 500 | Operating history window |
| Remediations | 500 | Compliance work items |
| Policy profiles | 100 | Deployment configuration, not a ledger |
| Report jobs | 200 | Render queue high-water mark |
| Custom rules | 100 | Matches the write-time ceiling |
| Auth audit log | 1000 | Login/logout/refresh events; horizon well beyond the refresh TTL |

State uses SQLite by default. Set `APP_DB_FILE` to a persistent path or explicitly select
`APP_STORAGE=json` with `APP_DATA_FILE`. Errors stop startup without switching stores.
Findings are masked, but masking is not anonymization. Protect retained history and backups.
There is no per-record deletion endpoint; a full-store deletion also removes accounts and sessions.
Follow [OPERATIONS.md](OPERATIONS.md) for backup and recovery before planned data erasure.

---

## Configuration

All configuration is via environment variables. See [`.env.example`](.env.example) for a template.

| Variable                | Default                 | Description                                                                 |
| ----------------------- | ----------------------- | --------------------------------------------------------------------------- |
| `APP_ENV`               | `development`           | Only `development`/`dev` relax the credential checks below; **any other value fails closed** |
| `APP_HOST`              | `127.0.0.1`             | Server bind address                                                         |
| `APP_PORT`              | `5101`                  | Server port                                                                 |
| `APP_USER`              | `admin`                 | Default username                                                            |
| `APP_PASS`              | `admin123`              | Default password (**refused outside development**)                           |
| `APP_ROLE`              | `admin`                 | Default user role (`admin` / `operator` / `viewer`)                         |
| `AUTH_SALT`             | `compliancekit-salt`    | Password hashing salt (**refused outside development**)                      |
| `ACCESS_TTL_MIN`        | `15`                    | Access token lifetime in minutes                                            |
| `REFRESH_TTL_DAYS`      | `7`                     | Refresh token lifetime in days                                              |
| `MAX_BODY_BYTES`        | `1048576`               | Maximum request body size (1 MB)                                            |
| `MAX_SCAN_TEXT_CHARS`   | `200000`                | Maximum characters per scan; also the bound custom rules run against        |
| `MAX_REMEDIATE_FINDINGS`| `200`                   | Maximum findings accepted by `POST /api/ai/remediate`                       |

> **Fail-closed startup:** the server refuses to boot unless `APP_ENV` is `development`/`dev`
> **and** `APP_PASS` and `AUTH_SALT` are both real values. Empty strings and the shipped
> placeholders (`admin123`, `compliancekit-salt`, `changeme`, `change-me-before-production`,
> `password`) are all rejected. This means `APP_ENV=staging`, `APP_ENV=Production` and typos
> fail closed rather than silently starting with default credentials — and copying
> `.env.example` unchanged is *not* a way to satisfy the check.

---

## Testing

```bash
# Run the full test suite
python -m pytest -q

# Lint
python -m ruff check .
```

CI runs automatically on push and pull requests via GitHub Actions (`.github/workflows/ci.yml`).

---

## Security Headers

All API and HTML responses include:

- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `Referrer-Policy: no-referrer`
- `Cache-Control: no-store`
- `Permissions-Policy: camera=(), microphone=(), geolocation=()`
- `Content-Security-Policy` — the dashboard's one inline `<script>` is authorised by a
  per-response nonce, so `script-src` does not need `'unsafe-inline'`.

---

## Changelog

See [`CHANGELOG.md`](CHANGELOG.md) for the full release history.

---

## Contributing

ComplianceKit is an open-source project by **Lehro Solutions**. Contributions are welcome — please open an issue or submit a pull request.

Before submitting changes, please:

1. Run `python -m pytest -q` and `python -m ruff check .`.
2. Review the [`RELEASE_CHECKLIST.md`](RELEASE_CHECKLIST.md) for quality gates.
3. Follow existing code conventions (stdlib only, no external dependencies in core).

---

## License

Copyright © 2026 Lehro Solutions. Licensed under the [Apache License 2.0](LICENSE). See [NOTICE](NOTICE).

## Documentation

Canonical docs hub: [`docs/.docs/index.md`](docs/.docs/index.md)

## Package manager

ComplianceKit is Python-native. **Bun is not used here.** Prefer `python -m venv .venv` and install via `pyproject.toml`.

See `docs/.docs/adr-0003-package-manager-bun.md`.

<!-- docs-system:start -->

## Documentation

The current public documentation is available in [`docs/index.html`](docs/index.html). Start with [`docs/current/start-here.md`](docs/current/start-here.md) for scope, current changes, workflows, architecture, security, quality, and contribution guidance.

### Latest public changes

- Bulk local file processing
- Custom rules editor
- Remediation queue and analytics
- Policy profiles and report jobs

Documentation is maintained as canonical Markdown plus generated HTML and JSON counterparts. Run `bun run docs:build` after changing `docs/current/*.md` and `bun run docs:check` before a public release. `docs:build` currently exits non-zero on purpose: no generator is vendored, so refreshing `sourceChecksum` requires the upstream docs packaging pipeline.
<!-- docs-system:end -->

<!-- bun-toolchain:start -->

## Bun and CI

This repository uses **Bun 1.3.14** to run the docs tooling, and targets **Node 24+** for
JavaScript tooling and CI. The runtime itself is Python — `package.json` is a tooling stub
with no JS runtime dependencies.

```bash
bun install
bun run docs:check
```

There is no `bun run build` or `bun run test`; use `python -m pytest -q` and
`python -m ruff check .`. Do not use `npm ci`; Bun is the canonical install path for the
tooling scripts.
<!-- bun-toolchain:end -->
