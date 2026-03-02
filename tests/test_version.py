from __future__ import annotations

import pathlib
import tomllib
import unittest

from compliancekit import __version__


class VersionTests(unittest.TestCase):
    def test_package_version_matches_pyproject(self) -> None:
        pyproject_path = pathlib.Path(__file__).resolve().parents[1] / "pyproject.toml"
        data = tomllib.loads(pyproject_path.read_text(encoding="utf-8"))
        project_version = data["project"]["version"]
        self.assertEqual(__version__, project_version)


if __name__ == "__main__":
    unittest.main()
