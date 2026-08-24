# Install

ComplianceKit is **Python-native**. Do **not** expect `bun install` to manage its runtime deps.

```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -e .
# or: pip install -r requirements.txt  (if present)
python -m compliancekit --help
python webapp/server.py
```

If you ran `bun install` here and saw “could not find a package.json”, that is expected unless a local tooling package.json is added for docs/scripts only.
