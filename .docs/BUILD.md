# ComplianceKit - Build Guide

## Purpose
ComplianceKit is a POPIA-focused toolkit for South African PII discovery, risk classification, and compliance reporting. It provides a core Python library, a CLI tool, and a self-hosted web application.

## Project Scope
- **Core Library**: Regex/rule-based PII detection engine with Luhn validation for South African IDs.
- **Compliance Engine**: Mapping findings to POPIA conditions and generating risk summaries.
- **CLI Tool**: Command-line interface for scanning files or stdin.
- **Web Application**: HTTP server with authentication, RBAC, scan history, and a cyan "POPIA Radar" dashboard.
- **Persistent Storage**: SQLite database with JSON-file fallback.
- **Docker Integration**: Containerized deployment support.

## Project Structure
- `compliancekit/pii.py`: PII detection primitives and regex patterns.
- `compliancekit/popia.py`: POPIA condition mapping and risk scoring logic.
- `compliancekit/cli.py`: CLI entrypoint and output masking.
- `webapp/server.py`: HTTP API server, authentication, and persistence logic.
- `webapp/index.html`: Dashboard UI.
- `tests/`: Unit tests for detection, compliance logic, and server configuration.
- `Dockerfile`: Container build instructions.
- `pyproject.toml`: Package metadata and dependencies.

## Local Development
1. **Environment Setup**:
   ```bash
   python -m venv venv
   source venv/bin/activate  # or venv\Scripts\activate on Windows
   pip install -e .
   ```
2. **Running Tests**:
   ```bash
   python -m unittest discover -s tests -p "test_*.py" -v
   ```
3. **Running Webapp**:
   ```bash
   cp .env.example .env
   # Update .env as needed
   python webapp/server.py
   ```

## Quality Gates
- **SA ID Validation**: All ID numbers must pass Luhn checksum validation.
- **Contextual Detection**: Bank and Tax numbers require keyword context to reduce false positives.
- **Data Minimization**: No raw PII is stored; only masked or redacted values are persisted.
- **Production Guardrails**: The server rejects insecure default credentials when `APP_ENV=production`.
- **CI/CD**: All pushes must pass the GitHub Actions pipeline (`ci.yml`).
