# Install

ComplianceKit is **Python-native**. Do **not** expect `bun install` to manage its runtime deps.

```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -e .
python -m compliancekit --help
python webapp/server.py
```

There is no `requirements.txt`; dependencies are declared in `pyproject.toml` and the
runtime has none. For the test and lint extras use `pip install -e ".[dev]"`.

If you ran `bun install` here and saw “could not find a package.json”, that is expected unless a local tooling package.json is added for docs/scripts only.
