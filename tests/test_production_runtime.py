from __future__ import annotations

import contextlib
import http.client
import json
import os
import secrets
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PORT = 3410
WRITE_ROUTE = "/api/scan"
READ_ROUTE = "/api/v2/scans"
COLLECTION = "scans"


class ProductionRuntimeTests(unittest.TestCase):
    def test_custom_rule_ending_with_a_group_is_validated_without_crashing(self) -> None:
        from webapp import server

        self.assertIsNotNone(server.compile_custom_rule("(EMP)"))


    def test_failed_write_does_not_publish_or_retain_a_phantom_record(self) -> None:
        self.env["APP_STORAGE"] = "json"
        self.start()
        session = self.request(
            "POST", "/api/auth/login",
            {"username": "runtime-admin", "password": self.password},
        )[1]
        token = session["accessToken"]
        state_file = self.data / "state.json"
        backup = self.data / "state.saved"
        state_file.rename(backup)
        state_file.mkdir()
        code, _, _ = self.request("POST", WRITE_ROUTE, {"text": "hello please"}, token)
        self.assertEqual(code, http.client.INTERNAL_SERVER_ERROR)
        self.assertEqual(self.request("GET", READ_ROUTE, token=token)[1][COLLECTION], [])
        state_file.rmdir()
        backup.rename(state_file)
        code, _, _ = self.request("POST", WRITE_ROUTE, {"text": "hello please"}, token)
        self.assertIn(code, (http.client.OK, http.client.CREATED))
        self.assertEqual(len(self.request("GET", READ_ROUTE, token=token)[1][COLLECTION]), 1)

    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory(prefix="compliancekit-runtime-")
        self.addCleanup(self.directory.cleanup)
        self.data = Path(self.directory.name)
        self.password = secrets.token_urlsafe(24)
        self.env = {
            **os.environ,
            "APP_ENV": "production",
            "APP_USER": "runtime-admin",
            "APP_PASS": self.password,
            "AUTH_SALT": secrets.token_urlsafe(32),
            "APP_ROLE": "admin",
            "APP_STORAGE": "sqlite",
            "APP_DATA_FILE": str(self.data / "state.json"),
            "APP_DB_FILE": str(self.data / "state.sqlite"),
            "HOST": "127.0.0.1",
            "APP_HOST": "127.0.0.1",
            "PORT": str(PORT),
            "APP_PORT": str(PORT),
        }
        self.process = None
        self.log = (self.data / "server.log").open("w+", encoding="utf-8")
        self.addCleanup(self.log.close)
        self.addCleanup(self.stop)

    def stop(self) -> None:
        if self.process is not None:
            self.process.terminate()
            self.process.wait(timeout=10)
            self.process = None

    def start(self) -> None:
        self.process = subprocess.Popen(
            [sys._base_executable, "-m", "webapp.server"],
            cwd=ROOT, env=self.env, stdout=self.log, stderr=self.log,
        )
        deadline = time.monotonic() + 45
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                self.log.seek(0)
                self.fail(self.log.read())
            try:
                code, _, _ = self.request("GET", "/api/ready")
                if code == http.client.OK:
                    return
            except OSError:
                pass
            time.sleep(0.05)
        self.fail("Server readiness timeout")

    def request(self, method, route, body=None, token=None, extra_headers=None):
        headers = {"Content-Type": "application/json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        headers.update(extra_headers or {})
        encoded = body if isinstance(body, str) else json.dumps(body) if body is not None else None
        connection = http.client.HTTPConnection("127.0.0.1", PORT, timeout=10)
        try:
            connection.request(method, route, body=encoded, headers=headers)
            response = connection.getresponse()
            raw = response.read().decode("utf-8")
            data = json.loads(raw) if "application/json" in response.getheader("Content-Type", "") else raw
            return response.status, data, dict(response.getheaders())
        finally:
            connection.close()

    def rejected_import(self, env=None):
        return subprocess.run(
            [sys._base_executable, "-c", "import webapp.server"],
            cwd=ROOT, env=env or self.env, capture_output=True, text=True,
            check=False, timeout=30,
        )

    def test_primary_journey_and_restart(self) -> None:
        self.start()
        self.assertEqual(self.request("GET", "/")[0], http.client.OK)
        self.assertEqual(self.request("GET", READ_ROUTE)[0], http.client.UNAUTHORIZED)
        self.assertEqual(
            self.request("POST", "/api/auth/login", {"username": "runtime-admin", "password": "wrong"})[0],
            http.client.UNAUTHORIZED,
        )
        self.assertEqual(self.request("POST", "/api/auth/login", "{")[0], http.client.BAD_REQUEST)
        self.assertEqual(
            self.request("POST", "/api/auth/login", "{}", extra_headers={"Content-Length": "-1"})[0],
            http.client.BAD_REQUEST,
        )
        code, session, headers = self.request(
            "POST", "/api/auth/login", {"username": "runtime-admin", "password": self.password},
        )
        self.assertEqual(code, http.client.OK)
        self.assertEqual(headers.get("Cache-Control"), "no-store")
        token = session["accessToken"]
        code, result, _ = self.request(
            "POST", WRITE_ROUTE, {"text": "Contact synthetic@example.test"}, token,
        )
        self.assertIn(code, (http.client.OK, http.client.CREATED))
        self.assertIsInstance(result, dict)
        self.assertEqual(len(self.request("GET", READ_ROUTE, token=token)[1][COLLECTION]), 1)
        self.stop()
        self.start()
        self.assertEqual(len(self.request("GET", READ_ROUTE, token=token)[1][COLLECTION]), 1)
        refreshed = self.request(
            "POST", "/api/auth/refresh", {"refreshToken": session["refreshToken"]},
        )
        self.assertEqual(refreshed[0], http.client.OK)
        self.assertEqual(
            self.request("POST", "/api/auth/logout", {"refreshToken": session["refreshToken"]}, token)[0],
            http.client.OK,
        )
        self.assertEqual(self.request("GET", READ_ROUTE, token=token)[0], http.client.UNAUTHORIZED)
        self.assertEqual(
            self.request("POST", "/api/auth/refresh", {"refreshToken": session["refreshToken"]})[0],
            http.client.UNAUTHORIZED,
        )

    def test_startup_rejects_placeholder_before_creating_state(self) -> None:
        for environment in ("production", "staging", "prodution"):
            with self.subTest(environment=environment):
                result = self.rejected_import({
                    **self.env, "APP_ENV": environment, "APP_PASS": "change-me-before-production",
                })
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse((self.data / "state.sqlite").exists())

    def test_corrupt_database_is_preserved_and_refused(self) -> None:
        database = self.data / "state.sqlite"
        database.write_bytes(b"not a sqlite database")
        result = self.rejected_import()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(database.read_bytes(), b"not a sqlite database")
        self.assertFalse((self.data / "state.json").exists())

    def test_invalid_sqlite_payload_is_preserved(self) -> None:
        database = self.data / "state.sqlite"
        with contextlib.closing(sqlite3.connect(database)) as connection:
            connection.execute(
                "CREATE TABLE state_store (id INTEGER PRIMARY KEY, payload TEXT, updated_at TEXT)",
            )
            connection.execute("INSERT INTO state_store VALUES (1, '{}', 'now')")
            connection.commit()
        result = self.rejected_import()
        self.assertNotEqual(result.returncode, 0)
        with contextlib.closing(sqlite3.connect(database)) as connection:
            self.assertEqual(connection.execute("SELECT payload FROM state_store").fetchone()[0], "{}")

    def test_corrupt_json_is_preserved_and_refused(self) -> None:
        state = self.data / "state.json"
        state.write_text("{truncated", encoding="utf-8")
        result = self.rejected_import({**self.env, "APP_STORAGE": "json"})
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(state.read_text(encoding="utf-8"), "{truncated")
        self.assertFalse((self.data / "state.sqlite").exists())

    def test_sqlite_takes_precedence_over_stale_json(self) -> None:
        result = self.rejected_import()
        self.assertEqual(result.returncode, 0, result.stderr)
        (self.data / "state.json").write_text("{old corrupt migration source", encoding="utf-8")
        result = self.rejected_import()
        self.assertEqual(result.returncode, 0, result.stderr)
