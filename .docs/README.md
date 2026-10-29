# Superseded duplicates — not the canonical hub

Canonical ultra-linked documentation lives in [`docs/.docs/index.md`](../docs/.docs/index.md).
Current public guidance lives in [`docs/current/`](../docs/current/start-here.md).

This root `.docs/` tree was moved into `docs/.docs/`, but the original files were left behind.
They are **retained duplicates, not sources of truth**. Deletion was not authorised, so the
mapping below records which copy governs:

| File here | Authoritative copy | State |
| --- | --- | --- |
| `BUILD.md` | [`docs/.docs/BUILD.md`](../docs/.docs/BUILD.md) | Reconciled — byte-identical to the canonical copy |
| `PRODUCTION.md` | [`docs/.docs/PRODUCTION.md`](../docs/.docs/PRODUCTION.md) | Reconciled — byte-identical to the canonical copy |
| `SKILL.md` | [`docs/.docs/SKILL.md`](../docs/.docs/SKILL.md) | Reconciled — byte-identical to the canonical copy |
| `SECURITY.md` | [`docs/.docs/security.md`](../docs/.docs/security.md) | **Divergent content** — this is the older, longer security guide; needs a human decision on what to keep |
| `FRONTEND_NEXT_STEPS.md` | [`docs/.docs/FRONTEND_NEXT_STEPS.md`](../docs/.docs/FRONTEND_NEXT_STEPS.md) | **Divergent content** — this copy is the newer roadmap; needs a human decision on what to keep |

Until those two divergences are resolved, treat the canonical paths in the middle column as
correct and this tree as background. Earlier copies of this material were archived under
[`docs/.docs/archive/root-dot-docs/`](../docs/.docs/archive/root-dot-docs/README.md).