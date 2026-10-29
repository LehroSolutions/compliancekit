from __future__ import annotations

import io
import json
import re
import secrets
import time
import unittest
from datetime import timedelta
from email.message import Message
from typing import Any
from unittest import mock

from webapp import server


def _token(user_id: str, role: str, token: str) -> dict[str, Any]:
    return {
        "id": secrets.token_hex(8),
        "token": token,
        "userId": user_id,
        "role": role,
        "scopes": list(server.ROLE_SCOPES[role]),
        "createdAt": server.now_iso(),
        "expiresAt": (server.utc_now() + timedelta(hours=1)).isoformat(),
    }


def _fresh_state() -> dict[str, Any]:
    return {
        "users": [{"id": "u-admin", "username": "admin", "passwordHash": "pbkdf2_sha256$1$2", "role": "admin"}],
        "auth": {"accessTokens": [], "refreshTokens": [], "audit": []},
        "scans": [],
        "remediations": [],
        "policyProfiles": [{"id": "profile-default"}],
        "reportJobs": [],
        "customRules": [],
    }


class _RecordingHandler(server.Handler):
    """Handler wired to in-memory streams so handlers can be driven without a socket."""

    def __init__(self, method: str, path: str, body: bytes = b"", headers: dict[str, str] | None = None):
        self.command = method
        self.path = path
        self.rfile = io.BytesIO(body)
        self.wfile = io.BytesIO()
        self.client_address = ("127.0.0.1", 40000)
        base = {"Content-Length": str(len(body))}
        base.update(headers or {})
        self.headers = Message()
        for key, value in base.items():
            self.headers[key] = value
        self._status = 0
        self._sent_headers: list[tuple[str, str]] = []

    def send_response(self, code: int, message: str | None = None) -> None:
        self._status = code

    def send_header(self, key: str, value: str) -> None:
        self._sent_headers.append((key, value))

    def end_headers(self) -> None:
        return

    def call(self) -> tuple[int, Any]:
        getattr(self, f"do_{self.command}")()
        raw = self.wfile.getvalue()
        if (self.header("Content-Type") or "").startswith("application/json"):
            return self._status, (json.loads(raw) if raw else None)
        return self._status, raw.decode("utf-8")

    def header(self, name: str) -> str | None:
        return next((value for key, value in self._sent_headers if key.lower() == name.lower()), None)


class CustomRegexGuardTests(unittest.TestCase):
    def test_catastrophic_patterns_are_rejected(self) -> None:
        hostile = {
            "a{1000}a{1000}a{1000}a{1000}a{1000}a{1000}a{1000}a{1000}b": "counted repeat",
            "(a+)+": "already contains a quantifier",
            "(a*)*": "already contains a quantifier",
            "(a|a)*": "contains an alternation",
            "(abc){1000}": "counted repeat",
            "a*a*": "same character",
            r"[ab]*[bc]*": "same character",
            r"\d{10}\d{10}": "same character",
            "a" * 300: "characters",
        }
        for pattern, expected in hostile.items():
            with self.subTest(pattern=pattern[:40]):
                reason = server.unsafe_regex_reason(pattern)
                self.assertIsNotNone(reason, f"hostile pattern accepted: {pattern[:60]}")
                self.assertIn(expected, reason.lower())
                self.assertIsNone(server.compile_custom_rule(pattern))

    def test_legitimate_rules_still_compile_and_match(self) -> None:
        cases = {
            r"^\d{3}-\d{3}-\d{4}$": "011-123-4567",
            r"EMP-[0-9]{4}": "EMP-0042",
            r"[A-Z]{2}\d{6}": "ZA004213",
            r"case-[0-9]{4}": "case-9134",
            r"\d{8}[/-]\d{2}": "12345678-91",
        }
        for pattern, text in cases.items():
            with self.subTest(pattern=pattern):
                self.assertIsNone(server.unsafe_regex_reason(pattern))
                compiled = server.compile_custom_rule(pattern)
                self.assertIsNotNone(compiled)
                self.assertIsNotNone(compiled.search(text))

    def test_hostile_rule_cannot_slow_a_scan_down(self) -> None:
        """The guard must reject, not merely make slow: this runs on the untrusted path."""
        rules = [
            {"id": "r1", "enabled": True, "label": "A", "pattern": "a{1000}a{1000}a{1000}a{1000}a{1000}a{1000}aaab"},
            {"id": "r2", "enabled": True, "label": "B", "pattern": "(a+)+"},
            {"id": "r3", "enabled": True, "label": "C", "pattern": r"\d{10}\d{10}"},
        ]
        started = time.monotonic()
        findings = server.apply_custom_rules("a" * 100_000, rules)
        elapsed = time.monotonic() - started
        self.assertEqual(findings, [])
        self.assertLess(elapsed, 2.0, "catastrophic rules were executed instead of rejected")

    def test_legitimate_rules_still_produce_findings(self) -> None:
        rules = [{"id": "r1", "enabled": True, "label": "EMP", "pattern": r"EMP-[0-9]{4}"}]
        findings = server.apply_custom_rules("see EMP-0042 and EMP-9134", rules)
        self.assertEqual([f["label"] for f in findings], ["EMP", "EMP"])
        self.assertEqual(findings[0]["value_masked"], "EM****42")

    def test_rules_are_cached_not_recompiled_per_scan(self) -> None:
        pattern = r"EMP-[0-9]{4}"
        server.COMPILED_RULE_CACHE.clear()
        first = server.compile_custom_rule(pattern)
        second = server.compile_custom_rule(pattern)
        self.assertIs(first, second, "compiled rule was not served from the cache")

    def test_only_enabled_rules_and_bounded_text_are_scanned(self) -> None:
        rules = [
            {"id": "r1", "enabled": False, "label": "OFF", "pattern": r"EMP-[0-9]{4}"},
            {"id": "r2", "enabled": True, "label": "ON", "pattern": r"EMP-[0-9]{4}"},
        ]
        self.assertEqual([f["label"] for f in server.apply_custom_rules("EMP-0042", rules)], ["ON"])

    def test_findings_per_scan_are_capped(self) -> None:
        rules = [{"id": "r1", "enabled": True, "label": "E", "pattern": r"[0-9]"}]
        findings = server.apply_custom_rules("0123456789" * 20, rules)
        self.assertEqual(len(findings), server.MAX_CUSTOM_RULE_FINDINGS)

    def test_rules_executed_per_scan_is_capped(self) -> None:
        rules = [
            {"id": f"r{i}", "enabled": True, "label": "L", "pattern": r"EMP-[0-9]{4}"}
            for i in range(server.MAX_RULES_PER_SCAN + 10)
        ]
        with mock.patch.object(server, "compile_custom_rule", wraps=server.compile_custom_rule) as spy:
            server.apply_custom_rules("EMP-0042", rules)
        self.assertEqual(spy.call_count, server.MAX_RULES_PER_SCAN)


class RetentionCapTests(unittest.TestCase):
    def test_every_retained_collection_is_capped(self) -> None:
        state = _fresh_state()
        for key in ("scans", "remediations", "policyProfiles", "reportJobs", "customRules"):
            state[key] = [{"id": f"{key}-{i}"} for i in range(server.RETENTION_CAPS[key] + 25)]
        state["auth"]["audit"] = [{"id": f"a-{i}"} for i in range(server.RETENTION_CAPS["audit"] + 25)]

        server.prune_state(state)

        for key, cap in server.RETENTION_CAPS.items():
            collection = state["auth"]["audit"] if key == "audit" else state[key]
            with self.subTest(collection=key):
                self.assertEqual(len(collection), cap)

    def test_newest_records_are_the_ones_kept(self) -> None:
        state = _fresh_state()
        state["remediations"] = [{"id": f"r{i}"} for i in range(server.RETENTION_CAPS["remediations"] + 5)]
        server.prune_state(state)
        self.assertEqual(state["remediations"][0]["id"], "r0")
        self.assertEqual(state["remediations"][-1]["id"], f"r{server.RETENTION_CAPS['remediations'] - 1}")

    def test_save_state_applies_retention(self) -> None:
        state = _fresh_state()
        state["reportJobs"] = [{"id": f"j{i}"} for i in range(server.RETENTION_CAPS["reportJobs"] + 10)]
        with mock.patch.object(server, "DB_CONN", None), mock.patch.object(
            server, "write_json_atomic"
        ):
            server.save_state(state)
        self.assertEqual(len(state["reportJobs"]), server.RETENTION_CAPS["reportJobs"])


class AuthorizationTests(unittest.TestCase):
    def _post(self, path: str, body: dict[str, Any], token: str | None = None):
        handler = _RecordingHandler(
            "POST", path, json.dumps(body).encode("utf-8"), {"Authorization": f"Bearer {token}"} if token else {}
        )
        with mock.patch.object(server, "STATE", _fresh_state()), mock.patch.object(
            server, "save_state", lambda state: None
        ):
            return handler.call()

    def _authorized_state(self) -> dict[str, Any]:
        state = _fresh_state()
        state["auth"]["accessTokens"] = [_token("u-admin", "admin", "valid-token")]
        return state

    def test_logout_requires_authorization(self) -> None:
        status, _ = self._post("/api/auth/logout", {"username": "admin"})
        self.assertEqual(status, 401)

    def test_remediate_requires_authorization(self) -> None:
        status, _ = self._post("/api/ai/remediate", {"findings": [{"pii_type": "SA_ID"}]})
        self.assertEqual(status, 401)

    def test_scan_requires_authorization(self) -> None:
        status, _ = self._post("/api/scan", {"text": "ID 9001015009087"})
        self.assertEqual(status, 401)

    def test_logout_derives_username_from_session_not_payload(self) -> None:
        state = self._authorized_state()
        handler = _RecordingHandler(
            "POST",
            "/api/auth/logout",
            json.dumps({"username": "forged-admin", "refreshToken": "nope"}).encode("utf-8"),
            {"Authorization": "Bearer valid-token"},
        )
        with mock.patch.object(server, "STATE", state), mock.patch.object(
            server, "save_state", lambda s: None
        ):
            status, payload = handler.call()
        self.assertEqual(status, 200)
        self.assertEqual(payload, {"loggedOut": True})
        self.assertEqual(state["auth"]["audit"][0]["username"], "admin")
        self.assertEqual(state["auth"]["audit"][0]["event"], "logout")
        self.assertEqual(state["auth"]["accessTokens"], [])

    def test_logout_will_not_revoke_another_users_refresh_token(self) -> None:
        state = self._authorized_state()
        state["users"].append({"id": "u-other", "username": "other", "passwordHash": "x", "role": "viewer"})
        state["auth"]["refreshTokens"] = [_token("u-other", "viewer", "victim-refresh")]
        handler = _RecordingHandler(
            "POST",
            "/api/auth/logout",
            json.dumps({"refreshToken": "victim-refresh"}).encode("utf-8"),
            {"Authorization": "Bearer valid-token"},
        )
        with mock.patch.object(server, "STATE", state), mock.patch.object(
            server, "save_state", lambda s: None
        ):
            status, _ = handler.call()
        self.assertEqual(status, 200)
        self.assertEqual(len(state["auth"]["refreshTokens"]), 1, "another user's refresh token was revoked")

    def test_remediate_caps_findings(self) -> None:
        state = self._authorized_state()
        handler = _RecordingHandler(
            "POST",
            "/api/ai/remediate",
            json.dumps({"findings": [{"pii_type": "SA_ID"}] * (server.MAX_REMEDIATE_FINDINGS + 50)}).encode(
                "utf-8"
            ),
            {"Authorization": "Bearer valid-token"},
        )
        with mock.patch.object(server, "STATE", state), mock.patch.object(
            server, "save_state", lambda s: None
        ):
            status, payload = handler.call()
        self.assertEqual(status, 200)
        self.assertEqual(len(payload["actionPlan"]), server.MAX_REMEDIATE_FINDINGS)

    def test_custom_rule_store_is_capped(self) -> None:
        state = self._authorized_state()
        state["customRules"] = [{"id": f"rule-{i}", "pattern": r"EMP-[0-9]{4}"} for i in range(server.MAX_CUSTOM_RULES)]
        body = {"name": "n", "label": "l", "pattern": r"EMP-[0-9]{4}"}
        handler = _RecordingHandler(
            "POST", "/api/v2/custom-rules", json.dumps(body).encode("utf-8"),
            {"Authorization": "Bearer valid-token"},
        )
        with mock.patch.object(server, "STATE", state), mock.patch.object(
            server, "save_state", lambda s: None
        ):
            status, payload = handler.call()
        self.assertEqual(status, 400)
        self.assertIn("Custom rule limit reached", payload["error"])
        self.assertEqual(len(state["customRules"]), server.MAX_CUSTOM_RULES)

    def test_body_over_limit_is_rejected(self) -> None:
        handler = _RecordingHandler("POST", "/api/auth/login", b"{}", {"Content-Length": str(server.MAX_BODY_BYTES + 1)})
        with mock.patch.object(server, "STATE", _fresh_state()):
            status, payload = handler.call()
        self.assertEqual(status, 413)
        self.assertIn("too large", payload["error"])


class TokenComparisonTests(unittest.TestCase):
    def test_authorize_compares_tokens_in_constant_time(self) -> None:
        state = _fresh_state()
        state["auth"]["accessTokens"] = [_token("u-admin", "admin", "valid-token")]
        handler = _RecordingHandler("GET", "/api/v2/scans", b"", {"Authorization": "Bearer valid-token"})
        with mock.patch.object(server, "STATE", state), mock.patch.object(
            server, "secure_equals", wraps=server.secure_equals
        ) as spy:
            allowed, _, _ = handler._authorize("read")
        self.assertTrue(allowed)
        self.assertTrue(spy.called, "token was not compared with hmac.compare_digest")

    def test_authorize_rejects_a_near_miss_token(self) -> None:
        state = _fresh_state()
        state["auth"]["accessTokens"] = [_token("u-admin", "viewer", "valid-token")]
        handler = _RecordingHandler("GET", "/api/v2/scans", b"", {"Authorization": "Bearer valid-tokeN"})
        with mock.patch.object(server, "STATE", state):
            allowed, _, _ = handler._authorize("read")
        self.assertFalse(allowed)

    def test_viewer_scope_is_enforced(self) -> None:
        state = _fresh_state()
        state["auth"]["accessTokens"] = [_token("u-admin", "viewer", "valid-token")]
        handler = _RecordingHandler("POST", "/api/scan", b"{}", {"Authorization": "Bearer valid-token"})
        with mock.patch.object(server, "STATE", state), mock.patch.object(
            server, "save_state", lambda s: None
        ):
            status, _ = handler.call()
        self.assertEqual(status, 401)


class RuntimeConfigTests(unittest.TestCase):
    def test_non_development_values_fail_closed(self) -> None:
        for value in ("production", "PRODUCTION", "Production", "staging", "prodution", "prod", "qa"):
            with self.subTest(app_env=value):
                self.assertNotIn(value, server.DEVELOPMENT_ENVS)

    def test_development_values_still_relaxed(self) -> None:
        self.assertIn("development", server.DEVELOPMENT_ENVS)
        self.assertIn("dev", server.DEVELOPMENT_ENVS)

    def test_shipped_placeholders_are_treated_as_insecure(self) -> None:
        self.assertIn("change-me-before-production", server.INSECURE_PASS_VALUES)
        self.assertIn("change-me-before-production", server.INSECURE_SALT_VALUES)
        self.assertIn("", server.INSECURE_PASS_VALUES)


class ServerThreadingTests(unittest.TestCase):
    def test_server_class_is_threading(self) -> None:
        import http.server

        self.assertTrue(issubclass(http.server.ThreadingHTTPServer, http.server.HTTPServer))

    def test_dashboard_csp_authorises_inline_script_by_nonce_only(self) -> None:
        handler = _RecordingHandler("GET", "/")
        status, _ = handler.call()
        self.assertEqual(status, 200)
        csp = handler.header("Content-Security-Policy")
        self.assertIsNotNone(csp)
        self.assertNotIn("script-src 'self' 'unsafe-inline'", csp)
        self.assertRegex(csp or "", r"script-src 'self' 'nonce-[A-Za-z0-9_-]+'")

    def test_dashboard_inline_script_carries_the_nonce_from_the_header(self) -> None:
        handler = _RecordingHandler("GET", "/")
        handler.call()
        csp = handler.header("Content-Security-Policy") or ""
        nonce = re.search(r"'nonce-([A-Za-z0-9_-]+)'", csp)
        self.assertIsNotNone(nonce)
        body = handler.wfile.getvalue().decode("utf-8")
        self.assertIn(f'<script nonce="{nonce.group(1)}">', body)

    def test_each_dashboard_response_uses_a_fresh_nonce(self) -> None:
        nonces = set()
        for _ in range(2):
            handler = _RecordingHandler("GET", "/")
            handler.call()
            nonces.add(re.search(r"'nonce-([A-Za-z0-9_-]+)'", handler.header("Content-Security-Policy") or "").group(1))
        self.assertEqual(len(nonces), 2)

    def test_api_responses_get_a_csp_without_unsafe_inline(self) -> None:
        handler = _RecordingHandler("GET", "/api/health")
        handler.call()
        csp = handler.header("Content-Security-Policy") or ""
        self.assertIn("script-src 'self';", csp)


if __name__ == "__main__":
    unittest.main()
