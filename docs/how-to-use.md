# How to Use ComplianceKit

ComplianceKit detects South African PII patterns and maps findings to POPIA conditions.

## 1) Install

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .
```

## 2) CLI scan

```bash
compliancekit --file document.txt
echo "ID 9001015009087" | compliancekit --json
```

## 3) Web dashboard

```bash
python webapp/server.py
```

Then open the local URL printed by the server.

### Operator flow
1. Authenticate with configured credentials (see `.env.example`)
2. Paste text or bulk-upload local files
3. Review masked findings and risk summary
4. Export CSV / queue remediations / manage custom rules

## 4) Production notes
- Set strong `APP_PASS` and `AUTH_SALT`
- Prefer reverse-proxy TLS
- Keep scan data local

## Related
- [INSTALL.md](../../INSTALL.md)
- [Security](./security.md)
- [Architecture](./architecture.md)
