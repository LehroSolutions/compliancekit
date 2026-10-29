# ComplianceKit — Copilot Skill

---
name: compliancekit-dev
description: Build and extend ComplianceKit — a POPIA compliance scanner that detects PII in text, maps findings to POPIA conditions, generates risk-scored compliance summaries, and manages audit records.
---

## Tool Purpose

ComplianceKit scans free-form text for South African PII (ID numbers with Luhn validation, phone numbers, company registrations, emails, passports, bank account numbers, tax reference numbers), maps each finding to applicable POPIA conditions, and produces risk-scored compliance summaries.

## Use This Skill For

- Detecting PII in documents or free-form text.
- Generating POPIA compliance reports with risk levels.
- Validating South African ID numbers (Luhn checksum).
- Mapping PII findings to POPIA conditions/obligations.

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Runtime | Python 3.11+ (stdlib only) |
| Server | `http.server` |
| Storage | SQLite (`sqlite3`) or explicitly selected JSON-file storage |
| Auth | SHA-256 + hmac bearer tokens |
| Port | 5101 |

## Project Structure

```
compliancekit/
├── compliancekit/
│   ├── pii.py              # detect_pii() — regex-based detection
│   ├── popia.py            # build_compliance_summary() — POPIA mapping
│   └── cli.py              # CLI entrypoint
├── webapp/
│   ├── server.py           # API server, Auth, & Persistence
│   └── index.html          # Cyan "POPIA Radar" Dashboard UI
├── tests/                  # Full unit test suite
├── convex/                 # Optional cloud integration
├── Dockerfile              # Container deployment
└── pyproject.toml          # Package configuration
```

## Core Library

### `detect_pii(text)` → list[PIIFinding]
Scans text with regex patterns. Returns `PIIFinding` objects (label, value, start, end, confidence, context).

| PII Type | Pattern | Validation |
|----------|---------|-----------|
| `sa_id_number` | 13 digits | Luhn checksum required |
| `sa_phone` | Local/Intl | Format match |
| `sa_company_registration` | YYYY/NNNNNN/NN | Format match |
| `email` | Standard | Regex |
| `passport_number` | A + 8 digits | Format match |
| `bank_account` | 8-11 digits | Context-aware (keywords required) |
| `tax_number` | 10 digits | Context-aware (keywords required) |

### `build_compliance_summary(findings)` → dict
Maps findings to POPIA conditions.
**Risk Thresholds:**
- `high`: ≥ 15 findings
- `medium`: ≥ 6 findings
- `low`: < 6 findings

## API Endpoints

| Method | Path | Auth |
|--------|------|------|
| GET | `/api/health` | — |
| GET | `/api/ready` | — |
| POST | `/api/scan` | — |
| POST | `/api/auth/login` | — |
| POST | `/api/auth/refresh` | — |
| POST | `/api/v2/scans` | read/write |
| GET | `/api/v2/remediations` | read |
| POST | `/api/v2/remediations` | write |
| PATCH | `/api/v2/remediations/:id` | write |
| POST | `/api/ai/remediate` | — |

## Commands

```bash
python -m pip install -e .
compliancekit --file sample.txt
python webapp/server.py
python -m unittest discover -s tests
```

## Security Rules
- NEVER persist raw PII.
- ALWAYS validate SA ID using Luhn checksum.
- Bank/Tax detection REQUIRES keyword presence (bank, tax, sars, tin, etc.).
- BLOCK default `APP_PASS` in production mode.
