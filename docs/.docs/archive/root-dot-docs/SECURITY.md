# ComplianceKit - Security Guide

## Security Model
ComplianceKit prioritizes data minimization and local control of sensitive PII.

### 1. Data Minimization
- **Masking**: PII values are masked by default (e.g., `90********087`) before being returned by the API or stored in any database.
- **In-Memory Processing**: The core library performs scanning in memory. Raw PII is never written to disk by ComplianceKit itself.

### 2. Authentication & Authorization
- **Bearer Tokens**: Authenticated routes require a JWS-style Bearer token.
- **SHA-256 Hashing**: Passwords are saved as SHA-256 hashes salted with `AUTH_SALT`.
- **RBAC**: Access is governed by roles:
  - `admin`: Full access (read, write, admin).
  - `operator`: Can scan and manage remediations (read, write).
  - `viewer`: Read-only access to dashboard and scans (read).

### 3. Response Hardening
The web server implements baseline security headers for all responses:
- `X-Content-Type-Options: nosniff`: Prevents MIME-sniffing.
- `X-Frame-Options: DENY`: Prevents clickjacking.
- `Referrer-Policy: no-referrer`: Protects navigation context.
- `Cache-Control: no-store`: Ensures sensitive findings aren't cached by browsers.

### 4. Production Controls
The application enforces a "Secure by Default" posture in production environments:
- **Default Rejection**: Startup fails if insecure default credentials (`APP_PASS`) or salts (`AUTH_SALT`) are detected when `APP_ENV=production`.
- **Payload Limits**: `MAX_BODY_BYTES` guards against large text submission attacks.

### 5. POPIA Alignment
- **Condition 7 (Security Safeguards)**: Enforced via masking, RBAC, and local-first deployment.
- **Condition 3 (Processing Limitation)**: Supported by identifying and flagging unnecessary PII categories for remediation.

## Threat Model & Mitigations
- **Leakage of Raw PII**: Mitigated by masking and no raw persistence.
- **Brute Force**: Mitigated by slow HMAC-based password verification and token short-TTL.
- **Data Integrity**: SQLite transactions and CI test suites ensure deterministic scan outputs.
