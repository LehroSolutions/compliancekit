from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import re
import time
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from threading import Lock
from typing import Any
from urllib.parse import urlparse

from compliancekit.pii import detect_pii
from compliancekit.popia import build_compliance_summary


def _env_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


APP = "compliancekit"
INDEX = Path(__file__).with_name("index.html")
STATE_FILE = Path(__file__).with_name("data.json")
DB_FILE = Path(__file__).with_name("data.sqlite")
APP_ENV = os.getenv("APP_ENV", "development").strip().lower()
DEFAULT_AUTH_SALT = "compliancekit-salt"
DEFAULT_APP_PASS = "admin123"
HOST = os.getenv("APP_HOST", "127.0.0.1")
PORT = _env_int("APP_PORT", 5101)
AUTH_SALT = os.getenv("AUTH_SALT", DEFAULT_AUTH_SALT)
APP_USER = os.getenv("APP_USER", "admin")
APP_PASS = os.getenv("APP_PASS", DEFAULT_APP_PASS)
APP_ROLE = os.getenv("APP_ROLE", "admin")
ACCESS_TTL_MIN = _env_int("ACCESS_TTL_MIN", 15)
REFRESH_TTL_DAYS = _env_int("REFRESH_TTL_DAYS", 7)
MAX_BODY_BYTES = _env_int("MAX_BODY_BYTES", 1024 * 1024)
ROLE_SCOPES = {
    "admin": ["read", "write", "admin"],
    "operator": ["read", "write"],
    "viewer": ["read"],
}
POPIA_CONDITION_MAP = {
    "SA_ID": {
        "conditions": ["Condition 3 - Processing Limitation", "Condition 7 - Security Safeguards"],
        "deadline_days": 30,
    },
    "PASSPORT": {
        "conditions": ["Condition 3 - Processing Limitation", "Condition 7 - Security Safeguards"],
        "deadline_days": 30,
    },
    "EMAIL": {
        "conditions": ["Condition 4 - Further Processing Limitation", "Condition 8 - Data Subject Participation"],
        "deadline_days": 14,
    },
    "PHONE": {
        "conditions": ["Condition 4 - Further Processing Limitation", "Condition 8 - Data Subject Participation"],
        "deadline_days": 14,
    },
    "CREDIT_CARD": {
        "conditions": ["Condition 7 - Security Safeguards", "Condition 3 - Processing Limitation"],
        "deadline_days": 7,
    },
    "BANK_ACCOUNT": {
        "conditions": ["Condition 7 - Security Safeguards", "Condition 3 - Processing Limitation"],
        "deadline_days": 7,
    },
}
STORAGE_BACKEND = "json-file"
DB_CONN: sqlite3.Connection | None = None
DB_LOCK = Lock()
LOGIN_ATTEMPTS: dict[str, list[float]] = {}
LOGIN_WINDOW_SECONDS = 15 * 60
LOGIN_MAX_ATTEMPTS = 8


class RequestError(Exception):
    def __init__(self, code: int, message: str):
        self.code = code
        self.message = message
        super().__init__(message)


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def now_iso() -> str:
    return utc_now().isoformat()


def hash_password(password: str) -> str:
    derived = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), AUTH_SALT.encode("utf-8"), 310_000)
    return f"pbkdf2_sha256$310000${derived.hex()}"


def verify_password(password: str, stored: str) -> bool:
    if stored.startswith("pbkdf2_sha256$"):
        return secure_equals(stored, hash_password(password))
    legacy = hashlib.sha256(f"{AUTH_SALT}:{password}".encode("utf-8")).hexdigest()
    return secure_equals(stored, legacy)


def secure_equals(left: str, right: str) -> bool:
    return hmac.compare_digest(left.encode("utf-8"), right.encode("utf-8"))


def mask_value(value: str) -> str:
    if len(value) <= 4:
        return "*" * len(value)
    return f"{value[:2]}{'*' * (len(value) - 4)}{value[-2:]}"


def validate_required(payload: dict[str, Any], required: list[str]) -> list[str]:
    return [key for key in required if payload.get(key) in (None, "")]


def parse_iso(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def is_expired(value: str) -> bool:
    return parse_iso(value) <= utc_now()


def log_event(level: str, message: str, request_id: str, **meta: Any) -> None:
    print(json.dumps({"timestamp": now_iso(), "level": level, "app": APP, "requestId": request_id, "message": message, **meta}))


def validate_runtime_config() -> None:
    if APP_ROLE not in ROLE_SCOPES:
        raise RuntimeError(f"Unsupported APP_ROLE '{APP_ROLE}'. Expected one of: {', '.join(ROLE_SCOPES)}")
    if ACCESS_TTL_MIN <= 0:
        raise RuntimeError("ACCESS_TTL_MIN must be greater than 0.")
    if REFRESH_TTL_DAYS <= 0:
        raise RuntimeError("REFRESH_TTL_DAYS must be greater than 0.")
    if MAX_BODY_BYTES <= 0:
        raise RuntimeError("MAX_BODY_BYTES must be greater than 0.")
    if APP_ENV in {"prod", "production"}:
        if APP_PASS == DEFAULT_APP_PASS:
            raise RuntimeError("APP_PASS uses an insecure default in production.")
        if AUTH_SALT == DEFAULT_AUTH_SALT:
            raise RuntimeError("AUTH_SALT uses an insecure default in production.")


def default_state() -> dict[str, Any]:
    return {
        "users": [{"id": "u-admin", "username": APP_USER, "passwordHash": hash_password(APP_PASS), "role": APP_ROLE}],
        "auth": {"accessTokens": [], "refreshTokens": [], "audit": []},
        "scans": [],
        "remediations": [],
        "policyProfiles": [
            {
                "id": "profile-default",
                "name": "Default POPIA Profile",
                "rulesetVersion": "2026.1",
                "strictness": "balanced",
            }
        ],
        "reportJobs": [],
        "customRules": [],
    }


def load_json_state() -> dict[str, Any]:
    if STATE_FILE.exists():
        return json.loads(STATE_FILE.read_text(encoding="utf-8"))
    return default_state()


def save_state(state: dict[str, Any]) -> None:
    if DB_CONN is not None:
        with DB_LOCK:
            DB_CONN.execute(
                "INSERT INTO state_store (id, payload, updated_at) VALUES (1, ?, ?) "
                "ON CONFLICT(id) DO UPDATE SET payload=excluded.payload, updated_at=excluded.updated_at",
                (json.dumps(state), now_iso()),
            )
            DB_CONN.commit()
        return
    STATE_FILE.write_text(json.dumps(state, indent=2), encoding="utf-8")


def init_state() -> dict[str, Any]:
    global DB_CONN, STORAGE_BACKEND
    fallback_state = load_json_state()
    try:
        conn = sqlite3.connect(DB_FILE, check_same_thread=False)
        conn.execute(
            "CREATE TABLE IF NOT EXISTS state_store (id INTEGER PRIMARY KEY CHECK (id = 1), payload TEXT NOT NULL, updated_at TEXT NOT NULL)"
        )
        row = conn.execute("SELECT payload FROM state_store WHERE id = 1").fetchone()
        DB_CONN = conn
        STORAGE_BACKEND = "sqlite"
        if row and row[0]:
            return json.loads(row[0])
        conn.execute(
            "INSERT INTO state_store (id, payload, updated_at) VALUES (1, ?, ?) "
            "ON CONFLICT(id) DO UPDATE SET payload=excluded.payload, updated_at=excluded.updated_at",
            (json.dumps(fallback_state), now_iso()),
        )
        conn.commit()
        return fallback_state
    except Exception:
        try:
            conn.close()  # type: ignore[name-defined]
        except Exception:
            pass
        DB_CONN = None
        STORAGE_BACKEND = "json-file"
        return fallback_state


def to_api_summary(summary: dict[str, Any]) -> dict[str, Any]:
    normalized = dict(summary)
    total_findings = int(summary.get("total_findings", summary.get("totalFindings", 0)))
    risk_level = str(summary.get("risk_level", summary.get("riskLevel", "low")))
    findings_by_type = summary.get("findings_by_type", summary.get("findingsByType", {}))
    findings_by_popia_condition = summary.get("findings_by_popia_condition", summary.get("findingsByPopiaCondition", {}))
    remediation_recommendations = summary.get("remediation_recommendations", summary.get("remediationRecommendations", []))

    normalized["total_findings"] = total_findings
    normalized["risk_level"] = risk_level
    normalized["findings_by_type"] = findings_by_type
    normalized["findings_by_popia_condition"] = findings_by_popia_condition
    normalized["remediation_recommendations"] = remediation_recommendations

    normalized["totalFindings"] = total_findings
    normalized["riskLevel"] = risk_level
    normalized["findingsByType"] = findings_by_type
    normalized["findingsByPopiaCondition"] = findings_by_popia_condition
    normalized["remediationRecommendations"] = remediation_recommendations
    normalized["sensitiveCategories"] = len(findings_by_type) if isinstance(findings_by_type, dict) else 0
    normalized["popiaExposureScore"] = total_findings
    return normalized


def normalize_scan(scan: dict[str, Any]) -> dict[str, Any]:
    item = dict(scan)
    summary = item.get("summary")
    item["summary"] = to_api_summary(summary if isinstance(summary, dict) else {})
    return item


validate_runtime_config()
STATE = init_state()



def apply_custom_rules(text: str, rules: list[dict[str, Any]]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for rule in rules:
        if not rule.get("enabled", True):
            continue
        pattern = str(rule.get("pattern") or "")
        label = str(rule.get("label") or rule.get("name") or "CUSTOM")
        try:
            compiled = re.compile(pattern)
        except re.error:
            continue
        for match in compiled.finditer(text[:200_000]):
            value = match.group(0)
            masked = value[:2] + ("*" * max(len(value) - 4, 0)) + value[-2:] if len(value) > 4 else "****"
            findings.append(
                {
                    "label": label,
                    "pii_type": label,
                    "value_masked": masked,
                    "confidence": 0.72,
                    "source": "custom-rule",
                    "ruleId": rule.get("id"),
                }
            )
            if len(findings) >= 50:
                return findings
    return findings


class Handler(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args: Any) -> None:
        return

    def _request_id(self) -> str:
        return self.headers.get("x-request-id") or secrets.token_hex(8)

    def _path(self) -> str:
        return urlparse(self.path).path

    def _request_context(self, method: str) -> tuple[str, str]:
        request_id = self._request_id()
        path = self._path()
        log_event("info", "request", request_id, method=method, path=path)
        return request_id, path

    def _send_common_headers(self, content_type: str) -> None:
        self.send_header("Content-Type", content_type)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")

    def _read_json(self) -> dict[str, Any]:
        length_raw = self.headers.get("Content-Length", "0")
        try:
            length = int(length_raw)
        except ValueError as exc:
            raise RequestError(400, "Invalid Content-Length header.") from exc
        if length < 0:
            raise RequestError(400, "Invalid Content-Length header.")
        if length > MAX_BODY_BYTES:
            raise RequestError(413, f"Request body too large. Max allowed is {MAX_BODY_BYTES} bytes.")
        if length == 0:
            return {}
        raw = self.rfile.read(length)
        try:
            decoded = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise RequestError(400, "Request body must be valid UTF-8.") from exc
        if not decoded.strip():
            return {}
        try:
            payload = json.loads(decoded)
        except json.JSONDecodeError as exc:
            raise RequestError(400, "Malformed JSON payload.") from exc
        if not isinstance(payload, dict):
            raise RequestError(400, "JSON payload must be an object.")
        return payload

    def _send_json(self, code: int, payload: dict[str, Any]) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(code)
        self._send_common_headers("application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _handle_exception(self, exc: Exception, request_id: str, method: str, path: str) -> None:
        if isinstance(exc, RequestError):
            self._send_json(exc.code, {"error": exc.message})
            return
        log_event("error", "request_failed", request_id, method=method, path=path, error=str(exc))
        self._send_json(500, {"error": "Internal server error."})

    def _bearer(self) -> str:
        header = self.headers.get("Authorization", "")
        if not header.startswith("Bearer "):
            return ""
        return header[7:]

    def _cleanup_tokens(self) -> None:
        STATE["auth"]["accessTokens"] = [t for t in STATE["auth"]["accessTokens"] if not is_expired(t["expiresAt"])]
        STATE["auth"]["refreshTokens"] = [t for t in STATE["auth"]["refreshTokens"] if not is_expired(t["expiresAt"])]

    def _issue_token(self, user: dict[str, Any], kind: str) -> dict[str, Any]:
        ttl = timedelta(minutes=ACCESS_TTL_MIN) if kind == "access" else timedelta(days=REFRESH_TTL_DAYS)
        token = {
            "id": secrets.token_hex(8),
            "token": secrets.token_urlsafe(32),
            "userId": user["id"],
            "role": user["role"],
            "scopes": ROLE_SCOPES.get(user["role"], ROLE_SCOPES["viewer"]),
            "createdAt": now_iso(),
            "expiresAt": (utc_now() + ttl).isoformat(),
        }
        if kind == "access":
            STATE["auth"]["accessTokens"].append(token)
        else:
            STATE["auth"]["refreshTokens"].append(token)
        return token

    def _authorize(self, scope: str) -> tuple[bool, dict[str, Any] | None, str | None]:
        self._cleanup_tokens()
        token = self._bearer()
        match = next((item for item in STATE["auth"]["accessTokens"] if item["token"] == token), None)
        if not match:
            return False, None, "Missing or invalid token."
        if scope not in match["scopes"]:
            return False, None, "Insufficient scope."
        return True, match, None

    def _record_auth_audit(self, event: str, username: str, success: bool) -> None:
        STATE["auth"]["audit"].insert(
            0,
            {
                "id": secrets.token_hex(8),
                "at": now_iso(),
                "event": event,
                "username": username,
                "success": success,
                "ip": self.client_address[0] if self.client_address else "unknown",
            },
        )

    def _create_scan(self, text: str) -> dict[str, Any]:
        findings = detect_pii(text)
        summary = to_api_summary(build_compliance_summary(findings))
        masked = [{"label": finding.label, "value_masked": mask_value(finding.value), "confidence": finding.confidence} for finding in findings]
        custom_findings = apply_custom_rules(text, STATE.get("customRules", []))
        if custom_findings:
            masked = list(masked) + custom_findings
            # keep summary counts roughly aligned for operator visibility
            try:
                summary["totalFindings"] = int(summary.get("totalFindings") or summary.get("total_findings") or 0) + len(custom_findings)
            except Exception:
                pass
        scan = {
            "id": f"scan-{secrets.token_hex(4)}",
            "createdAt": now_iso(),
            "summary": summary,
            "findings": masked,
        }
        STATE["scans"].insert(0, scan)
        save_state(STATE)
        return {"summary": summary, "findings": masked}

    def do_GET(self) -> None:
        request_id, path = self._request_context("GET")
        try:
            if path == "/":
                html = INDEX.read_text(encoding="utf-8").encode("utf-8")
                self.send_response(200)
                self._send_common_headers("text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(html)))
                self.end_headers()
                self.wfile.write(html)
                return

            if path == "/api/health":
                self._send_json(200, {"app": APP, "status": "ok", "time": now_iso()})
                return

            if path == "/api/ready":
                self._send_json(200, {"ready": True, "storage": STORAGE_BACKEND})
                return

            if path == "/api/v2/scans":
                allowed, _, reason = self._authorize("read")
                if not allowed:
                    self._send_json(401, {"error": reason})
                    return
                self._send_json(200, {"scans": [normalize_scan(scan) for scan in STATE["scans"]]})
                return

            if path == "/api/v2/remediations":
                allowed, _, reason = self._authorize("read")
                if not allowed:
                    self._send_json(401, {"error": reason})
                    return
                self._send_json(200, {"remediations": STATE["remediations"]})
                return

            if path == "/api/v2/policies":
                allowed, _, reason = self._authorize("read")
                if not allowed:
                    self._send_json(401, {"error": reason})
                    return
                self._send_json(200, {"policyProfiles": STATE["policyProfiles"]})
                return

            if path == "/api/v2/custom-rules":
                allowed, _, reason = self._authorize("read")
                if not allowed:
                    self._send_json(401, {"error": reason})
                    return
                self._send_json(200, {"rules": STATE.get("customRules", [])})
                return

            if path == "/api/v2/analytics":
                allowed, _, reason = self._authorize("read")
                if not allowed:
                    self._send_json(401, {"error": reason})
                    return
                scans = STATE.get("scans", [])
                by_type: dict[str, int] = {}
                by_risk: dict[str, int] = {}
                for scan in scans:
                    summary = scan.get("summary") or {}
                    risk = str(summary.get("riskLevel") or summary.get("risk_level") or "low").lower()
                    by_risk[risk] = by_risk.get(risk, 0) + 1
                    findings = scan.get("findings") or []
                    for finding in findings:
                        label = str(finding.get("label") or finding.get("pii_type") or "UNKNOWN").upper()
                        by_type[label] = by_type.get(label, 0) + 1
                self._send_json(
                    200,
                    {
                        "scanCount": len(scans),
                        "remediationCount": len(STATE.get("remediations", [])),
                        "customRuleCount": len(STATE.get("customRules", [])),
                        "findingsByType": by_type,
                        "scansByRisk": by_risk,
                    },
                )
                return

            if path == "/api/v2/report-jobs":
                allowed, _, reason = self._authorize("read")
                if not allowed:
                    self._send_json(401, {"error": reason})
                    return
                self._send_json(200, {"reportJobs": STATE["reportJobs"]})
                return

            self._send_json(404, {"error": "Not found"})
        except Exception as exc:
            self._handle_exception(exc, request_id, "GET", path)

    def do_POST(self) -> None:
        request_id, path = self._request_context("POST")
        try:
            if path == "/api/auth/login":
                payload = self._read_json()
                client_ip = self.client_address[0] if self.client_address else "unknown"
                now = time.monotonic()
                attempts = [stamp for stamp in LOGIN_ATTEMPTS.get(client_ip, []) if now - stamp < LOGIN_WINDOW_SECONDS]
                if len(attempts) >= LOGIN_MAX_ATTEMPTS:
                    self._send_json(429, {"error": "Too many login attempts. Try again later."})
                    return
                missing = validate_required(payload, ["username", "password"])
                if missing:
                    self._send_json(400, {"error": f"Missing fields: {', '.join(missing)}"})
                    return
                user = next((item for item in STATE["users"] if item["username"] == payload["username"]), None)
                success = bool(user and verify_password(str(payload["password"]), user["passwordHash"]))
                self._record_auth_audit("login", payload["username"], success)
                if not success:
                    attempts.append(now)
                    LOGIN_ATTEMPTS[client_ip] = attempts
                    save_state(STATE)
                    self._send_json(401, {"error": "Invalid username or password."})
                    return
                LOGIN_ATTEMPTS.pop(client_ip, None)
                if user and not user["passwordHash"].startswith("pbkdf2_sha256$"):
                    user["passwordHash"] = hash_password(str(payload["password"]))
                access = self._issue_token(user, "access")
                refresh = self._issue_token(user, "refresh")
                save_state(STATE)
                self._send_json(
                    200,
                    {
                        "token": access["token"],
                        "accessToken": access["token"],
                        "refreshToken": refresh["token"],
                        "expiresAt": access["expiresAt"],
                        "role": access["role"],
                        "scopes": access["scopes"],
                    },
                )
                return

            if path == "/api/auth/refresh":
                payload = self._read_json()
                missing = validate_required(payload, ["refreshToken"])
                if missing:
                    self._send_json(400, {"error": "refreshToken is required."})
                    return
                self._cleanup_tokens()
                refresh = next((item for item in STATE["auth"]["refreshTokens"] if item["token"] == payload["refreshToken"]), None)
                if not refresh:
                    self._send_json(401, {"error": "Refresh token is invalid or expired."})
                    return
                user = next((item for item in STATE["users"] if item["id"] == refresh["userId"]), None)
                if not user:
                    STATE["auth"]["refreshTokens"] = [item for item in STATE["auth"]["refreshTokens"] if item["id"] != refresh["id"]]
                    save_state(STATE)
                    self._send_json(401, {"error": "Refresh token is invalid."})
                    return
                access = self._issue_token(user, "access")
                self._record_auth_audit("refresh", user["username"], True)
                save_state(STATE)
                self._send_json(
                    200,
                    {
                        "token": access["token"],
                        "accessToken": access["token"],
                        "expiresAt": access["expiresAt"],
                        "scopes": access["scopes"],
                    },
                )
                return

            if path == "/api/auth/logout":
                payload = self._read_json()
                token = self._bearer()
                STATE["auth"]["accessTokens"] = [item for item in STATE["auth"]["accessTokens"] if item["token"] != token]
                refresh_token = payload.get("refreshToken")
                if refresh_token:
                    STATE["auth"]["refreshTokens"] = [item for item in STATE["auth"]["refreshTokens"] if item["token"] != refresh_token]
                self._record_auth_audit("logout", payload.get("username", "unknown"), True)
                save_state(STATE)
                self._send_json(200, {"loggedOut": True})
                return

            if path == "/api/scan":
                payload = self._read_json()
                text = str(payload.get("text", ""))
                self._send_json(200, self._create_scan(text))
                return

            if path == "/api/v2/scans":
                allowed, _, reason = self._authorize("write")
                if not allowed:
                    self._send_json(401, {"error": reason})
                    return
                payload = self._read_json()
                text = str(payload.get("text", ""))
                result = self._create_scan(text)
                self._send_json(201, {"id": STATE["scans"][0]["id"], "summary": result["summary"]})
                return

            if path == "/api/v2/remediations":
                allowed, _, reason = self._authorize("write")
                if not allowed:
                    self._send_json(401, {"error": reason})
                    return
                payload = self._read_json()
                missing = validate_required(payload, ["title", "condition", "owner"])
                if missing:
                    self._send_json(400, {"error": f"Missing fields: {', '.join(missing)}"})
                    return
                item = {
                    "id": f"rem-{secrets.token_hex(4)}",
                    "createdAt": now_iso(),
                    "title": payload["title"],
                    "condition": payload["condition"],
                    "owner": payload["owner"],
                    "status": payload.get("status", "open"),
                    "priority": payload.get("priority", "medium"),
                }
                STATE["remediations"].insert(0, item)
                save_state(STATE)
                self._send_json(201, item)
                return

            if path == "/api/v2/policies":
                allowed, _, reason = self._authorize("write")
                if not allowed:
                    self._send_json(401, {"error": reason})
                    return
                payload = self._read_json()
                missing = validate_required(payload, ["name", "rulesetVersion"])
                if missing:
                    self._send_json(400, {"error": f"Missing fields: {', '.join(missing)}"})
                    return
                item = {
                    "id": f"policy-{secrets.token_hex(4)}",
                    "createdAt": now_iso(),
                    "name": payload["name"],
                    "rulesetVersion": payload["rulesetVersion"],
                    "strictness": payload.get("strictness", "balanced"),
                }
                STATE["policyProfiles"].insert(0, item)
                save_state(STATE)
                self._send_json(201, item)
                return

            if path == "/api/v2/custom-rules":
                allowed, _, reason = self._authorize("write")
                if not allowed:
                    self._send_json(401, {"error": reason})
                    return
                payload = self._read_json()
                missing = validate_required(payload, ["name", "pattern", "label"])
                if missing:
                    self._send_json(400, {"error": f"Missing fields: {', '.join(missing)}"})
                    return
                name = str(payload["name"])[:80]
                label = str(payload["label"])[:80]
                pattern = str(payload["pattern"])[:200]
                if len(pattern) < 3:
                    self._send_json(400, {"error": "Pattern too short."})
                    return
                if any(token in pattern for token in ["(?", "*+", "++", "{", "\1"]):
                    self._send_json(400, {"error": "Pattern uses disallowed constructs."})
                    return
                try:
                    re.compile(pattern)
                except re.error as exc:
                    self._send_json(400, {"error": f"Invalid regex: {exc}"})
                    return
                item = {
                    "id": f"rule-{secrets.token_hex(4)}",
                    "createdAt": now_iso(),
                    "name": name,
                    "label": label,
                    "pattern": pattern,
                    "enabled": bool(payload.get("enabled", True)),
                }
                STATE.setdefault("customRules", []).insert(0, item)
                save_state(STATE)
                self._send_json(201, item)
                return

            if path == "/api/v2/report-jobs":
                allowed, _, reason = self._authorize("write")
                if not allowed:
                    self._send_json(401, {"error": reason})
                    return
                payload = self._read_json()
                item = {
                    "id": f"job-{secrets.token_hex(4)}",
                    "createdAt": now_iso(),
                    "format": payload.get("format", "json"),
                    "status": "queued",
                    "rulesetVersion": payload.get("rulesetVersion", "2026.1"),
                }
                STATE["reportJobs"].insert(0, item)
                save_state(STATE)
                self._send_json(201, item)
                return

            if path == "/api/ai/remediate":
                payload = self._read_json()
                findings = payload.get("findings", [])
                action_plan = []
                for finding in findings:
                    pii_type = str(finding.get("pii_type") or finding.get("label", "UNKNOWN")).upper()
                    mapped = POPIA_CONDITION_MAP.get(pii_type, {"conditions": ["Condition 7 - Security Safeguards"], "deadline_days": 30})
                    action_plan.append(
                        {
                            "piiType": pii_type,
                            "popiaConditions": mapped["conditions"],
                            "actions": [
                                f"Redact or pseudonymise all {pii_type} values in storage and transit",
                                f"Update data retention policy referencing {mapped['conditions'][0]}",
                                "Notify Information Officer and update POPIA register",
                                f"Obtain consent or lawful basis documentation within {mapped['deadline_days']} days",
                            ],
                            "deadlineDays": mapped["deadline_days"],
                            "severity": "critical" if mapped["deadline_days"] <= 7 else "high" if mapped["deadline_days"] <= 14 else "medium",
                        }
                    )
                action_plan.sort(key=lambda x: x["deadlineDays"])
                self._send_json(
                    200,
                    {
                        "actionPlan": action_plan,
                        "summary": {
                            "total": len(action_plan),
                            "critical": len([a for a in action_plan if a["severity"] == "critical"]),
                            "immediateActions": action_plan[0]["actions"] if action_plan else [],
                            "recommendation": (
                                "Immediate remediation required - critical PII detected"
                                if any(a["severity"] == "critical" for a in action_plan)
                                else "Address high-severity findings within 14 days per POPIA requirements"
                                if action_plan
                                else "No PII findings to remediate"
                            ),
                        },
                    },
                )
                return

            self._send_json(404, {"error": "Not found"})
        except Exception as exc:
            self._handle_exception(exc, request_id, "POST", path)

    def do_PATCH(self) -> None:
        request_id, path = self._request_context("PATCH")
        try:
            if path.startswith("/api/v2/remediations/"):
                allowed, _, reason = self._authorize("write")
                if not allowed:
                    self._send_json(401, {"error": reason})
                    return
                remediation_id = path.rsplit("/", 1)[-1]
                payload = self._read_json()
                target = next((item for item in STATE["remediations"] if item["id"] == remediation_id), None)
                if not target:
                    self._send_json(404, {"error": "Remediation not found."})
                    return
                target["status"] = payload.get("status", target["status"])
                target["owner"] = payload.get("owner", target["owner"])
                target["updatedAt"] = now_iso()
                save_state(STATE)
                self._send_json(200, target)
                return

            self._send_json(404, {"error": "Not found"})
        except Exception as exc:
            self._handle_exception(exc, request_id, "PATCH", path)


if __name__ == "__main__":
    print(json.dumps({"app": APP, "status": "starting", "url": f"http://{HOST}:{PORT}", "time": now_iso()}))
    server = HTTPServer((HOST, PORT), Handler)
    server.serve_forever()
