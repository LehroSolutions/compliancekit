# ComplianceKit Security

## Current controls
- PBKDF2 password verifiers with legacy migration path
- Login throttling + session-only browser tokens
- CSP/security headers; masked PII in UI
- Custom regex rules reject high-risk constructs

## Logging convention
Security issues noticed during failed builds or breaking errors should be recorded under this docs system as dated markdown notes and linked from this page.

## Related logs
- Prefer `SECURITY_ISSUES_YYYY-MM-DD.md` siblings in this folder when incidents occur
- Keep secrets out of documentation samples

## Related
- [Architecture](./architecture.md)
- [License](./license.md)
- [ADR-0002](./adr-0002-apache-2-0.md)
