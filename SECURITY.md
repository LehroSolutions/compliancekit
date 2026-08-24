# Security Policy

## Supported versions
Security fixes target the latest mainline release of **ComplianceKit**.

## Reporting a vulnerability
Report privately via GitHub Private Vulnerability Reporting (when enabled) or email maintainers.

Include version/commit, reproduction steps, and impact.
Do **not** open public issues for undisclosed vulnerabilities.

## Production expectations
- Never commit `.env`, keys, tokens, or live databases
- Use strong secrets in production
- Keep dependencies updated
- Prefer least-privilege credentials
