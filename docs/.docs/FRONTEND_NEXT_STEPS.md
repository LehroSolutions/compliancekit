# ComplianceKit Frontend Roadmap

ComplianceKit features a cyan/navy "POPIA Radar" dashboard for interactive auditing.

## Current Capabilities
- [x] **PII Detector**: Free-form text input with instant scanning.
- [x] **Risk Results**: Table view of detected PII (masked) with confidence scores.
- [x] **Compliance Summary**: POPIA condition breakdown and risk level.
- [x] **Scan History**: Persistent storage/retrieval with filtering.
- [x] **Remediation Queue**: Create and list remediation tasks.
- [x] **Auth Management**: Login, logout, throttling, session-only tokens.
- [x] **Bulk Processing**: Multi-file local scans.
- [x] **Export Engine**: CSV export of masked findings.
- [x] **Interactive Analytics**: Findings-by-type bars and risk mix.
- [x] **Custom Rules Editor**: Operator-defined safe regex labels.

## Implementation Standards
- Maintain the cyan-on-black industrial aesthetic.
- High contrast + keyboard focus for interactive panels.
- Never render raw PII values in the DOM.
