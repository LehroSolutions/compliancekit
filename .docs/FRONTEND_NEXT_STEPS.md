# ComplianceKit Frontend Roadmap

ComplianceKit features a cyan/navy "POPIA Radar" dashboard for interactive auditing.

## Current Capabilities (V1)
- [x] **PII Detector**: Free-form text input with instant scanning.
- [x] **Risk Results**: Table view of detected PII (masked) with confidence scores.
- [x] **Compliance Summary**: POPIA condition breakdown and risk level (`high`/`medium`/`low`).
- [x] **Scan History**: Persistent storage and retrieval of previous scan results.
- [x] **Remediation Queue**: List-view for status tracking of compliance tasks.
- [x] **Auth Management**: Login, logout, and token expiration handling.

## Planned Improvements (Next Steps)
1. **Interactive Analytics**: Dashboard charts for PII distribution by condition and document type.
2. **Export Engine**: Generate PDF/CSV compliance reports for external audits.
3. **Advanced Filtering**: Search and filter scan history by risk level, date range, or specific PII categories.
4. **Remediation Workflow**: Detailed remediation view with assignment and evidence upload support.
5. **Bulk Processing**: Upload multiple files simultaneously from the UI.
6. **Custom Rules Editor**: Allow users to define project-specific regex patterns from the settings panel.

## Implementation Standards
- **Cytron Design Language**: Maintain the cyan-on-black industrial aesthetic.
- **Accessibility**: Ensure high contrast and keyboard navigation for all interactive panels.
- **Privacy First**: Zero rendering of raw PII values in DOM/UI components.
