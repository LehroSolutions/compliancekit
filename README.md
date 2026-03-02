<p align="center">
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

| Capability | Description |
|---|---|
| **SA ID Number Detection** | 13-digit South African ID numbers validated with Luhn checksum |
| **Phone Number Detection** | Local (`0XX`) and international (`+27`) formats |
| **Company Registration** | `YYYY/NNNNNN/NN` format matching |
| **Email Detection** | Standard email pattern matching |
| **Passport Numbers** | South African passport format (`A` + 8 digits) |
| **Bank Account Numbers** | 8–11 digit numbers with context-aware detection (requires keywords: *bank*, *account*, *iban*, *branch*) |
| **Tax Reference Numbers** | 10-digit numbers with context-aware detection (requires keywords: *tax*, *sars*, *tin*) |
| **POPIA Condition Mapping** | Each finding is mapped to the relevant POPIA condition (Processing Limitation, Security Safeguards, etc.) |
| **Risk Scoring** | Automatic risk classification: `high` (≥15 findings), `medium` (≥6), `low` (<6) |
| **Remediation Recommendations** | Actionable steps per POPIA condition (encryption, consent, retention policies) |
| **Value Masking** | All PII values are masked in output — raw PII is never persisted |
| **Web Dashboard** | Scan text, view color-coded results, track scan history, manage remediations |
| **Role-Based Auth** | Bearer token authentication with admin/operator/viewer roles and scope enforcement |
| **Audit Trail** | Login, logout, and token refresh events are recorded |
| **SQLite + JSON Fallback** | Persistent storage with automatic SQLite, falling back to JSON when unavailable |
| **Docker Ready** | Single-command deployment with the included `Dockerfile` |
| **Zero Dependencies** | Core library uses Python stdlib only — no external packages required |

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
│   ├── server.py               # HTTP API server with auth, RBAC, and persistence
│   └── index.html              # Single-page dashboard UI ("POPIA Radar")
├── tests/
│   ├── test_pii.py             # PII detection pattern tests
│   ├── test_popia.py           # POPIA summary behavior tests
│   ├── test_server_runtime_config.py  # Production config guard tests
│   └── test_version.py         # Version consistency test
├── convex/                     # Convex backend schema (optional cloud integration)
│   ├── schema.ts               # Database tables: scans, findings, remediations, auditLog
│   ├── queries.ts              # Reactive read functions
│   └── mutations.ts            # Transactional write functions
├── .docs/                      # Internal project documentation
├── .github/workflows/ci.yml    # GitHub Actions CI pipeline
├── Dockerfile                  # Container deployment
├── .env.example                # Environment variable template
├── pyproject.toml              # Python package configuration
├── CHANGELOG.md                # Release history
└── RELEASE_CHECKLIST.md        # Pre-release quality gate
```

**Data flow:** Text input → `detect_pii()` → PII findings → `build_compliance_summary()` → risk-scored report with POPIA conditions and remediation steps. All PII values are masked before storage.

---

## API Reference

### Public Endpoints (No Auth)

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/` | Serves the web dashboard |
| `GET` | `/api/health` | Health check |
| `GET` | `/api/ready` | Readiness check (reports storage backend) |
| `POST` | `/api/scan` | Scan text for PII (body: `{ "text": "..." }`) |

### Authentication

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/auth/login` | Login → access + refresh tokens (body: `{ "username", "password" }`) |
| `POST` | `/api/auth/refresh` | Refresh access token (body: `{ "refreshToken" }`) |
| `POST` | `/api/auth/logout` | Revoke tokens |

### Authenticated Endpoints (Bearer Token)

| Method | Path | Scope | Description |
|--------|------|-------|-------------|
| `GET` | `/api/v2/scans` | read | List all scans |
| `POST` | `/api/v2/scans` | write | Create authenticated scan |
| `GET` | `/api/v2/remediations` | read | List remediations |
| `POST` | `/api/v2/remediations` | write | Create remediation item |
| `PATCH` | `/api/v2/remediations/:id` | write | Update remediation status/owner |
| `GET` | `/api/v2/policies` | read | List policy profiles |
| `POST` | `/api/v2/policies` | write | Create policy profile |
| `GET` | `/api/v2/report-jobs` | read | List report jobs |
| `POST` | `/api/v2/report-jobs` | write | Queue a report job |
| `POST` | `/api/ai/remediate` | — | Generate POPIA remediation action plan |

### Roles & Scopes

| Role | Scopes |
|------|--------|
| `admin` | `read`, `write`, `admin` |
| `operator` | `read`, `write` |
| `viewer` | `read` |

---

## Configuration

All configuration is via environment variables. See [`.env.example`](.env.example) for a template.

| Variable | Default | Description |
|----------|---------|-------------|
| `APP_ENV` | `development` | Set to `production` to enforce secure defaults |
| `APP_HOST` | `127.0.0.1` | Server bind address |
| `APP_PORT` | `5101` | Server port |
| `APP_USER` | `admin` | Default username |
| `APP_PASS` | `change-me-before-production` | Default password (**blocked in production if unchanged**) |
| `APP_ROLE` | `admin` | Default user role (`admin` / `operator` / `viewer`) |
| `AUTH_SALT` | `change-me-before-production` | Password hashing salt (**blocked in production if unchanged**) |
| `ACCESS_TTL_MIN` | `15` | Access token lifetime in minutes |
| `REFRESH_TTL_DAYS` | `7` | Refresh token lifetime in days |
| `MAX_BODY_BYTES` | `1048576` | Maximum request body size (1 MB) |

> **Production hardening:** When `APP_ENV=production`, the server will refuse to start if `APP_PASS` or `AUTH_SALT` still have their insecure defaults.

---

## Testing

```bash
# Run the full test suite
python -m unittest discover -s tests -p "test_*.py" -v

# Static compile check
python -m py_compile webapp/server.py compliancekit/cli.py compliancekit/pii.py compliancekit/popia.py
```

CI runs automatically on push and pull requests via GitHub Actions (`.github/workflows/ci.yml`).

---

## Security Headers

All API and HTML responses include:

- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `Referrer-Policy: no-referrer`
- `Cache-Control: no-store`

---

## Changelog

See [`CHANGELOG.md`](CHANGELOG.md) for the full release history.

---

## Contributing

ComplianceKit is an open-source project by **Lehro Solutions**. Contributions are welcome — please open an issue or submit a pull request.

Before submitting changes, please:
1. Run the full test suite (`python -m unittest discover -s tests -p "test_*.py" -v`).
2. Review the [`RELEASE_CHECKLIST.md`](RELEASE_CHECKLIST.md) for quality gates.
3. Follow existing code conventions (stdlib only, no external dependencies in core).

---

## License

Copyright © 2026 Lehro Solutions. Licensed under the [Apache License 2.0](LICENSE).
