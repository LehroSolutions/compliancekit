"""Always isolate webapp imports from a developer's real account and scan history."""
from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

_DIRECTORY = tempfile.TemporaryDirectory(prefix="compliancekit-pytest-")
os.environ.update({
    "APP_ENV": "development",
    "APP_STORAGE": "sqlite",
    "APP_DB_FILE": str(Path(_DIRECTORY.name) / "state.sqlite"),
    "APP_DATA_FILE": str(Path(_DIRECTORY.name) / "state.json"),
})


def pytest_unconfigure() -> None:
    module = sys.modules.get("webapp.server")
    if module is not None and module.DB_CONN is not None:
        module.DB_CONN.close()
    _DIRECTORY.cleanup()
