        # Audit & Improvements — 2026-07-10

        Product: **ComplianceKit**

        ## Audit findings addressed
        - Operators may run bun install expecting JS package; product is Python-native

        ## Improvements applied
        - Added INSTALL.md with Python venv/pip path
- Added private tooling package.json stub so bun install no longer hard-fails; postinstall explains Python path

        ## Install verification
        - JS/TS packages: run `bun install` from the directory containing `package.json` (repo root for workspace packages).
        - Python packages: use venv + pip (`INSTALL.md`).

        ## Related
        - [How to Use](./how-to-use.md)
        - [Security](./security.md)
        - [ADR-0003 Package Manager](./adr-0003-package-manager-bun.md)
