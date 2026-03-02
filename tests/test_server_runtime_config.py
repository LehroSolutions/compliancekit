from __future__ import annotations

import os
import subprocess
import sys
import unittest


class ServerRuntimeConfigTests(unittest.TestCase):
    def test_production_rejects_default_credentials(self) -> None:
        env = os.environ.copy()
        env["APP_ENV"] = "production"
        env.pop("APP_PASS", None)
        env.pop("AUTH_SALT", None)
        proc = subprocess.run(
            [sys.executable, "-c", "import webapp.server"],
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("APP_PASS uses an insecure default in production", proc.stderr)


if __name__ == "__main__":
    unittest.main()
