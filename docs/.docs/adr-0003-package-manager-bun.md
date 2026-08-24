# ADR-0003: Package manager selection (Bun vs alternatives)

## Status
Accepted — Python remains primary

## Context
The constellation mixes Next.js/Vite/Node CLIs with pure Python services. Bun is excellent for JS/TS install + runtime ergonomics, but it is not a Python package manager.

## Decision
ComplianceKit is primarily Python. **Bun is not ideal** as the primary toolchain. Keep Python packaging (`pyproject.toml` / venv / uv / pip).

### Recommendation
Do not convert this repository to Bun.

## Bun ideal when
- Dependencies are npm packages
- Scripts are Node/TypeScript CLIs or Vite/Next apps
- Fast local install and `bunx` DX matter

## Bun not ideal when
- Runtime is CPython/FastAPI/pytest
- Native Python packaging/metadata is required
- Tooling assumes pip/uv lock semantics exclusively

## Consequences
- JS/TS packages declare `packageManager: bun@...` and ship `bunfig.toml`
- npm lockfiles are archived as legacy artifacts
- Contributors generate `bun.lock` with `bun install` on a network machine
- Python packages keep their existing tooling

## Related
- [How to Use](./how-to-use.md)
- [Architecture](./architecture.md)
- [Index](./index.md)
