# ADR-0001: Ultra-linked documentation system

## Status
Accepted — 2026-07-10

> **Superseded in scope by [ADR-0004](../current/adr-0004-documentation-contract.md).**
> This ADR describes the `docs/.docs` Markdown + HTML + JSON twin hub. Current public
> guidance moved to `docs/current/*.md` under ADR-0004's counterpart contract. Retained for
> history; do not treat it as the current documentation contract.

## Context
Operator and agent workflows need durable, discoverable product knowledge that survives chat resets.

## Decision
Maintain a `docs/.docs` hub where every core page exists as **Markdown + HTML + JSON** twins with reciprocal links.

## Consequences
- Slightly higher doc maintenance cost
- Much better agent/human navigability
- HTML provides offline browsing without a static site pipeline

## Related
- [Index](./index.md)
- [Skills](./skills.md)
