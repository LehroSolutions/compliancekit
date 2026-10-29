# Operations and recovery

This release runs locally without external AI services or cloud credentials. The web service is a single-process deployment with a durable local store. Put it behind a maintained HTTPS reverse proxy with request and connection limits before exposing it publicly. Multiple processes must not share this snapshot store.

## Configure and start

- Use a supported runtime and install the project as described in README.
- Set `APP_ENV=production`, `APP_USER`, `APP_PASS`, `AUTH_SALT`, and `APP_ROLE` in the service manager's environment. Generate independent random values for the password and salt; copied template placeholders are refused.
- A local `.env` file is documentation only; the Python server does not load it automatically.
- Set `APP_DB_FILE` to a persistent, restricted directory outside the source checkout. The default storage mode is `APP_STORAGE=sqlite`. Set `APP_STORAGE=json` only when deliberately selecting the JSON backend and set `APP_DATA_FILE`.
- SQLite errors, unreadable JSON, and invalid stored state stop startup. The server never silently switches stores. A new SQLite store can import an existing valid JSON file; an existing SQLite store takes precedence.
- Run `python -m webapp.server` from the checkout. Bind the host to loopback behind a local proxy; containers explicitly bind to all interfaces.
- `APP_USER`, `APP_PASS`, and `APP_ROLE` seed a new store. Changing them does not replace accounts in an existing store. Plan credential rotation explicitly; retain `AUTH_SALT` while migrating legacy hashes.

## Release checks

Run `python -m pytest -q` and `python -m ruff check .`. Tests isolate imports and subprocesses from existing webapp data. Production tests exercise homepage, invalid login and JSON, access control, create/read, restart, refresh/logout, corrupt stores, invalid state shape, and write-failure recovery with temporary data.

Build a wheel with `python -m pip wheel . --no-deps --wheel-dir dist`, install it into a clean environment, and smoke-test the CLI. The wheel contains the core/CLI; the optional webapp runs from the source checkout or container.

`python scripts/verify-wheel.py` automates the wheel build, clean temporary
installation, masked CLI scan and missing-file failure check. CI runs it for each
supported Python version. No developer data or credentials are used.

Build the container with `docker build -t compliancekit:local .`. Supply real environment values through a protected environment file or service secret manager and mount a named volume at `/data`. Do not bake secrets into the image. The image runs as an unprivileged user and probes `/api/ready`. Test the actual image, reverse proxy/TLS, service supervisor restart, disk-full alerting, and restore procedure on the deployment host before release.

## Monitor and recover

- `GET /api/health` checks process responsiveness; `GET /api/ready` reports the selected initialized backend. A successful probe is not a disk-space or backup guarantee.
- Alert on 5xx errors, repeated login failures, disk pressure, and startup failures. Request bodies/passwords/tokens must not be added to logs.
- Each successful mutation is committed before success is returned. JSON uses a sibling temporary file, flush, and atomic replacement; SQLite uses transactions. Failed mutations restore the in-memory snapshot so a rejected operation does not appear in subsequent reads.
- Stop the service before copying its SQLite database or JSON store. Retain the previous application version, configuration, and a timestamped encrypted/restricted backup together. Do not delete state files as routine maintenance.
- Validate SQLite backups with `PRAGMA integrity_check`; then launch a separate instance using the backup and temporary ports, authenticate, and verify representative records. Backups contain password hashes and live session tokens and require access controls.
- On corruption or permission failure, stop the service, preserve the failed store for diagnosis, correct permissions or restore the verified backup to the same configured path, and start the same version. Confirm readiness and the record count before admitting traffic. Do not select JSON merely to bypass a failed SQLite store.
- To roll back application code, stop the service and restore the previous code/configuration first. Restore its matching backup if a future release changes the state schema. Existing credentials and sessions must be reviewed after any incident.

## Product boundaries

Scan findings are masked before persistence; scanning is a heuristic aid and does not certify POPIA compliance. Custom regex rules remain a restricted, bounded language rather than an arbitrary regex execution service. Each token collection retains at most 100 sessions; older entries are evicted. The Convex directory is not used by this local web service.
