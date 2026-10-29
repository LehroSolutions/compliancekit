# Archive — non-authoritative

Everything under this directory is **historical evidence only**. Nothing here is a source of
truth, and nothing here is validated by `bun run docs:check`.

| Path | Origin |
| --- | --- |
| `BUILD.md`, `PRODUCTION.md`, `SKILL.md`, `SECURITY_ISSUES_*.md`, `UPGRADE_COMPLETION_*.md` | Snapshots of material superseded by [`docs/.docs/`](../index.md) |
| `root-dot-docs/` | Snapshot of the old root `.docs/` tree after its move into `docs/.docs/` |

## Current sources of truth

- Public, current guidance: [`docs/current/*.md`](../current/start-here.md), with generated
  HTML/JSON counterparts validated by `bun run docs:check`.
- Internal project documentation hub: [`docs/.docs/index.md`](../index.md).
- Decisions: [`adr-0001`](../adr-0001-docs-system.md), [`adr-0002`](../adr-0002-apache-2-0.md),
  [`adr-0003`](../adr-0003-package-manager-bun.md), and
  [`adr-0004`](../current/adr-0004-documentation-contract.md).

If a file here disagrees with a current source, the current source wins. Do not edit archive
files expecting them to propagate.