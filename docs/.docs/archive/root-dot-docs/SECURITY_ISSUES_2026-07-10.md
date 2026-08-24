# Security issues noticed — 2026-07-10 continuation

## Findings

- Fast SHA-256 password hashing was insufficient for production verifiers (patched earlier to PBKDF2).
- Browser tokens previously lived in localStorage (patched to sessionStorage).
- Custom regex editor could become a ReDoS vector if unrestricted.

## Patches

- PBKDF2-HMAC-SHA256 with 310k iterations + legacy verify path.
- Login attempt throttling per client IP.
- CSP / Permissions-Policy headers.
- Custom rule patterns length-limited and reject high-risk constructs.

## Residual risk

- In-memory login throttle resets on process restart.
