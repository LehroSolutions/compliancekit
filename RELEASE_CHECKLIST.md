# Release Checklist

Use this checklist before tagging or publishing a release.

## 1. Versioning
- [ ] Confirm target version in `pyproject.toml`.
- [ ] Confirm `compliancekit/__init__.py` `__version__` matches.
- [ ] Add release entry to `CHANGELOG.md` with the current date.

## 2. Security and Configuration
- [ ] Confirm `.env.example` does not contain production secrets.
- [ ] Verify production defaults are blocked:
  - [ ] `APP_ENV=production` fails startup if `APP_PASS` is default
  - [ ] `APP_ENV=production` fails startup if `AUTH_SALT` is default
- [ ] Verify request body limit (`MAX_BODY_BYTES`) is set appropriately for deployment.

## 3. Quality Gates
- [ ] Run static compile check:
  - `python -m py_compile webapp/server.py compliancekit/cli.py compliancekit/pii.py compliancekit/popia.py`
- [ ] Run test suite:
  - `python -m unittest discover -s tests -p "test_*.py" -v`
- [ ] Manually smoke test API:
  - [ ] `POST /api/scan` success path
  - [ ] malformed JSON returns 400
  - [ ] auth-required v2 endpoints reject invalid tokens with 401

## 4. Packaging
- [ ] Build source/wheel artifacts:
  - `python -m pip install --upgrade build`
  - `python -m build`
- [ ] Verify install in a clean virtual environment:
  - `python -m pip install dist/<artifact>.whl`
  - `compliancekit --help`

## 5. Documentation and Ops
- [ ] README reflects current auth/environment behavior.
- [ ] Changelog includes all user-facing and security-significant changes.
- [ ] `.gitignore` excludes local runtime artifacts (`.env`, sqlite/db files, caches).

## 6. Release
- [ ] Tag the release (`vX.Y.Z`).
- [ ] Publish GitHub release notes from `CHANGELOG.md`.
- [ ] Publish package/artifacts to the intended distribution channel.
