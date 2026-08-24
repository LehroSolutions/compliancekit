# ComplianceKit - Production Guide

## Deployment Model
ComplianceKit is designed as a local-first or self-hosted compliance tool. It can be deployed as:
- **CLI Tool**: For ad-hoc scanning in local environments or build pipelines.
- **Self-Hosted Service**: Using the included `webapp/server.py` or the provided `Dockerfile`.

## Configuration (Environment Variables)
Production behavior is controlled via environment variables.

| Variable | Default | Description |
|----------|---------|-------------|
| `APP_ENV` | `development` | Setting to `production` enables security enforcement. |
| `APP_USER` | `admin` | Default admin username. |
| `APP_PASS` | `admin123` | Default password (**Must be changed for production**). |
| `AUTH_SALT` | `compliancekit-salt` | Password hashing salt (**Must be changed for production**). |
| `MAX_BODY_BYTES` | `1048576` | (1MB) Maximum request payload size to prevent DOS. |
| `ACCESS_TTL_MIN` | `15` | Access token expiration time. |
| `REFRESH_TTL_DAYS` | `7` | Refresh token expiration time. |

## Runtime Backend
- **SQLite**: The server attempts to use `webapp/data.sqlite` for persistence.
- **JSON Fallback**: If SQLite is unavailable, it falls back to `webapp/data.json`.
- **Monitoring**: Use the `/api/ready` endpoint to check the active storage backend.

## Production Hardening
When `APP_ENV=production`:
1. The server **fails to start** if `APP_PASS` or `AUTH_SALT` remain at their default values.
2. All API responses include strict security headers (`X-Frame-Options`, `X-Content-Type-Options`, etc.).
3. Request size limits are strictly enforced.

## Docker Deployment
```bash
docker build -t compliancekit .
docker run -p 5101:5101 \
  -e APP_ENV=production \
  -e APP_PASS="YOUR_SECURE_PASSWORD" \
  -e AUTH_SALT="YOUR_SECURE_SALT" \
  compliancekit
```

## Maintenance
- **Data Retention**: Periodically clear `webapp/data.sqlite` or rotate the file if needed.
- **Rule Updates**: Monitor `compliancekit/pii.py` for pattern updates to SA legal requirements.
