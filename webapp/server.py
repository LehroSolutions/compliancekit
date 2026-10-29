from __future__ import annotations

import contextlib
import copy
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import tempfile
import time
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Lock, RLock
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
STATE_FILE = Path(os.getenv("APP_DATA_FILE", Path(__file__).with_name("data.json")))
DB_FILE = Path(os.getenv("APP_DB_FILE", Path(__file__).with_name("data.sqlite")))
STORAGE_MODE = os.getenv("APP_STORAGE", "sqlite").strip().lower()
APP_ENV = os.getenv("APP_ENV", "development").strip().lower()
DEVELOPMENT_ENVS = frozenset({"development", "dev"})
DEFAULT_AUTH_SALT = "compliancekit-salt"
DEFAULT_APP_PASS = "admin123"
# Credential values that must never reach a non-development deployment. The shipped
# `.env.example` placeholders are included because copying that file sets them literally;
# without them an operator could "configure" the server by copying the template and still
# pass the startup check.
INSECURE_PASS_VALUES = frozenset({DEFAULT_APP_PASS, "", "changeme", "change-me-before-production", "password"})
INSECURE_SALT_VALUES = frozenset({DEFAULT_AUTH_SALT, "", "changeme", "change-me-before-production"})
HOST = os.getenv("APP_HOST", "127.0.0.1")
PORT = _env_int("APP_PORT", 5101)
AUTH_SALT = os.getenv("AUTH_SALT", DEFAULT_AUTH_SALT)
APP_USER = os.getenv("APP_USER", "admin")
APP_PASS = os.getenv("APP_PASS", DEFAULT_APP_PASS)
APP_ROLE = os.getenv("APP_ROLE", "admin")
ACCESS_TTL_MIN = _env_int("ACCESS_TTL_MIN", 15)
REFRESH_TTL_DAYS = _env_int("REFRESH_TTL_DAYS", 7)
MAX_BODY_BYTES = _env_int("MAX_BODY_BYTES", 1024 * 1024)
MAX_SCAN_TEXT_CHARS = _env_int("MAX_SCAN_TEXT_CHARS", 200_000)
MAX_REMEDIATE_FINDINGS = _env_int("MAX_REMEDIATE_FINDINGS", 200)

# --- Custom regex rule safety -------------------------------------------------
# Custom rule patterns are attacker-supplied: an operator (or anyone who has
# obtained a write-scoped token) stores a pattern that the scanner then executes
# against caller-supplied text. Python's stdlib `re` has no match timeout, so a
# pattern with catastrophic backtracking cannot be interrupted once started --
# the only reliable defence is to never compile or run such a pattern. The limits
# below bound the search space a single pattern can describe, so worst-case
# backtracking stays effectively linear in the (already capped) scan text.
MAX_CUSTOM_RULE_PATTERN_CHARS = 200
MAX_CUSTOM_RULE_QUANTIFIERS = 8
MAX_CUSTOM_RULE_REPEAT = 64
# Stored-rule ceiling (write-time rejection) and per-scan execution ceiling. The
# per-scan cap bounds worst-case cost to MAX_RULES_PER_SCAN * scan text even if
# every stored rule were pathological.
MAX_CUSTOM_RULES = 100
MAX_RULES_PER_SCAN = 25
MAX_CUSTOM_RULE_FINDINGS = 50
COMPILED_RULE_CACHE_MAX = 256

# Retention caps applied on every state write. Every collection below is
# newest-first, so trimming the tail drops the oldest records. Rationale per key:
#   scans          - unchanged 500-scan operating-history window.
#   remediations   - compliance work items; one per finding class per engagement.
#   policyProfiles - deployment configuration, not a ledger.
#   reportJobs     - render queue high-water mark; jobs are never replayed.
#   customRules    - matches the write-time ceiling above.
#   audit          - login/logout/refresh events; 1000 entries keeps a forensic
#                    horizon far beyond the refresh TTL while bounding growth.
RETENTION_CAPS = {
    "scans": 500,
    "remediations": 500,
    "policyProfiles": 100,
    "reportJobs": 200,
    "customRules": MAX_CUSTOM_RULES,
    "audit": 1000,
}
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
STATE_LOCK = RLock()
STATE_REVISION = 0
LOGIN_ATTEMPTS: dict[str, list[float]] = {}
LOGIN_WINDOW_SECONDS = 15 * 60
LOGIN_MAX_ATTEMPTS = 8


class RequestError(Exception):
    def __init__(self, code: int, message: str):
        self.code = code
        self.message = message
        super().__init__(message)


def utc_now() -> datetime:
    return datetime.now(UTC)


def now_iso() -> str:
    return utc_now().isoformat()


def hash_password(password: str) -> str:
    derived = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), AUTH_SALT.encode("utf-8"), 310_000)
    return f"pbkdf2_sha256$310000${derived.hex()}"


def verify_password(password: str, stored: str) -> bool:
    if stored.startswith("pbkdf2_sha256$"):
        return secure_equals(stored, hash_password(password))
    legacy = hashlib.sha256(f"{AUTH_SALT}:{password}".encode()).hexdigest()
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
    if STORAGE_MODE not in {"sqlite", "json"}:
        raise RuntimeError("APP_STORAGE must be sqlite or json.")
    if APP_ROLE not in ROLE_SCOPES:
        raise RuntimeError(f"Unsupported APP_ROLE '{APP_ROLE}'. Expected one of: {', '.join(ROLE_SCOPES)}")
    if ACCESS_TTL_MIN <= 0:
        raise RuntimeError("ACCESS_TTL_MIN must be greater than 0.")
    if REFRESH_TTL_DAYS <= 0:
        raise RuntimeError("REFRESH_TTL_DAYS must be greater than 0.")
    if MAX_BODY_BYTES <= 0:
        raise RuntimeError("MAX_BODY_BYTES must be greater than 0.")
    if MAX_SCAN_TEXT_CHARS <= 0:
        raise RuntimeError("MAX_SCAN_TEXT_CHARS must be greater than 0.")
    if APP_ENV not in DEVELOPMENT_ENVS:
        # Fail closed on everything that is not an explicit development intent. Matching
        # only the literals "prod"/"production" let `staging`, `Production`, or a typo
        # boot silently with the shipped default password.
        if APP_PASS in INSECURE_PASS_VALUES:
            raise RuntimeError(f"APP_PASS uses an insecure default in production (APP_ENV={APP_ENV!r}).")
        if AUTH_SALT in INSECURE_SALT_VALUES:
            raise RuntimeError(f"AUTH_SALT uses an insecure default in production (APP_ENV={APP_ENV!r}).")


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
        return validate_state(json.loads(STATE_FILE.read_text(encoding="utf-8")))
    return default_state()


def validate_state(state: Any) -> dict[str, Any]:
    collections = ("users", "scans", "remediations", "policyProfiles", "reportJobs", "customRules")
    if not isinstance(state, dict) or not all(isinstance(state.get(k), list) for k in collections):
        raise RuntimeError("Invalid stored state. Restore a verified backup before starting.")
    auth = state.get("auth")
    if not isinstance(auth, dict) or not all(
        isinstance(auth.get(k), list) for k in ("accessTokens", "refreshTokens", "audit")
    ):
        raise RuntimeError("Invalid stored authentication state. Restore a verified backup.")
    return state


def write_json_atomic(path: Path, payload: str) -> None:
    handle, name = tempfile.mkstemp(dir=path.parent, prefix=path.name, suffix=".tmp")
    temporary = Path(name)
    try:
        with os.fdopen(handle, "w", encoding="utf-8") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        temporary.replace(path)
    finally:
        with contextlib.suppress(OSError):
            temporary.unlink()


def prune_state(state: dict[str, Any]) -> None:
    """Trim every retained collection to its cap so state cannot grow without bound.

    Called from save_state so no mutation path can skip retention. Previously only
    scans were trimmed, while remediations, policy profiles, report jobs, custom
    rules and the auth audit log grew forever and were rewritten to disk on every
    request -- the central storage-limitation gap for a tool handling personal data.
    """
    for key, cap in RETENTION_CAPS.items():
        collection = state.get(key)
        if isinstance(collection, list) and len(collection) > cap:
            del collection[cap:]
    auth = state.get("auth")
    if isinstance(auth, dict):
        for key in ("accessTokens", "refreshTokens"):
            if isinstance(auth.get(key), list):
                auth[key] = auth[key][-100:]
        audit = auth.get("audit")
        if isinstance(audit, list) and len(audit) > RETENTION_CAPS["audit"]:
            del audit[RETENTION_CAPS["audit"]:]


def save_state(state: dict[str, Any]) -> None:
    global STATE_REVISION
    prune_state(state)
    if DB_CONN is not None:
        with DB_LOCK:
            DB_CONN.execute(
                "INSERT INTO state_store (id, payload, updated_at) VALUES (1, ?, ?) "
                "ON CONFLICT(id) DO UPDATE SET payload=excluded.payload, updated_at=excluded.updated_at",
                (json.dumps(state), now_iso()),
            )
            DB_CONN.commit()
        STATE_REVISION += 1
        return
    write_json_atomic(STATE_FILE, json.dumps(state, indent=2))
    STATE_REVISION += 1


def init_state() -> dict[str, Any]:
    global DB_CONN, STORAGE_BACKEND
    if STORAGE_MODE == "json":
        STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        STORAGE_BACKEND = "json-file"
        return load_json_state()
    DB_FILE.parent.mkdir(parents=True, exist_ok=True)
    conn = None
    try:
        conn = sqlite3.connect(DB_FILE, check_same_thread=False)
        conn.execute(
            "CREATE TABLE IF NOT EXISTS state_store (id INTEGER PRIMARY KEY CHECK (id = 1), payload TEXT NOT NULL, updated_at TEXT NOT NULL)"
        )
        row = conn.execute("SELECT payload FROM state_store WHERE id = 1").fetchone()
        DB_CONN = conn
        STORAGE_BACKEND = "sqlite"
        if row and row[0]:
            return validate_state(json.loads(row[0]))
        fallback_state = load_json_state()
        conn.execute(
            "INSERT INTO state_store (id, payload, updated_at) VALUES (1, ?, ?) "
            "ON CONFLICT(id) DO UPDATE SET payload=excluded.payload, updated_at=excluded.updated_at",
            (json.dumps(fallback_state), now_iso()),
        )
        conn.commit()
        return fallback_state
    except Exception as exc:
        log_event(
            "error",
            "state_init_failed",
            "startup",
            backend="sqlite",
            dbFile=str(DB_FILE),
            error=f"{type(exc).__name__}: {exc}",
        )
        if conn is not None:
            conn.close()
        DB_CONN = None
        raise RuntimeError("Cannot open stored state. Restore a verified backup before starting.") from exc


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



ATOM_ESCAPE = "\x00"
ATOM_CLASS = "\x01"
ATOM_ZERO_WIDTH = "\x02"
STRUCTURAL_CHARS = frozenset("()|^$")
ESCAPE_RANGES: dict[str, list[tuple[int, int]]] = {
    "d": [(0x30, 0x39)],
    "w": [(0x30, 0x39), (0x41, 0x5A), (0x5F, 0x5F), (0x61, 0x7A)],
    "s": [(0x09, 0x0D), (0x20, 0x20)],
}
ANY_RANGES = [(0x00, 0x10FFFF)]


def _parse_class(body: str) -> list[tuple[int, int]] | None:
    """Codepoint ranges matched by a [...] body, or None when the set cannot be bounded.

    None covers negated classes and any escape we do not model; callers must then assume the
    atom overlaps everything, which fails safe for the backtracking checks.
    """
    if body.startswith("^"):
        return None
    ranges: list[tuple[int, int]] = []
    index = 0
    while index < len(body):
        if body[index] == "\\" and index + 1 < len(body):
            mapped = ESCAPE_RANGES.get(body[index + 1].lower())
            if mapped is None:
                return None
            ranges.extend(mapped)
            index += 2
            continue
        start = ord(body[index])
        if index + 2 < len(body) and body[index + 1] == "-" and body[index + 2] != "]":
            ranges.append((start, ord(body[index + 2])))
            index += 3
            continue
        ranges.append((start, start))
        index += 1
    return ranges or None


def scan_pattern(pattern: str) -> tuple[str, list[tuple[int, int] | None]]:
    """Reduce a pattern to one skeleton character per atom, plus the ranges each atom matches.

    An escape (\\d) and a character class ([a-z]) each match exactly one character, so each
    collapses to a single sentinel. That keeps braces and quantifiers *inside* those
    constructs from being mistaken for real repetition, and keeps the structural checks below
    correct without depending on the private `sre_parse` API.
    """
    skeleton: list[str] = []
    ranges: list[tuple[int, int] | None] = []
    index = 0
    length = len(pattern)
    while index < length:
        char = pattern[index]
        if char == "\\":
            escape = pattern[index + 1] if index + 1 < length else ""
            mapped = ESCAPE_RANGES.get(escape.lower())
            if mapped is not None and escape.islower():
                skeleton.append(ATOM_ESCAPE)
                ranges.append(list(mapped))
            elif escape in ("D", "W", "S"):
                skeleton.append(ATOM_ESCAPE)
                ranges.append(None)  # complement of a known set: unbounded, assume overlap
            else:
                # Assertion or backreference: matches no character at all.
                skeleton.append(ATOM_ZERO_WIDTH)
                ranges.append(None)
            index += 2
            continue
        if char == "[":
            cursor = index + 1
            if cursor < length and pattern[cursor] == "^":
                cursor += 1
            if cursor < length and pattern[cursor] == "]":
                cursor += 1  # a leading ']' is a literal member
            body_start = cursor
            while cursor < length and pattern[cursor] != "]":
                cursor += 2 if pattern[cursor] == "\\" else 1
            skeleton.append(ATOM_CLASS)
            ranges.append(_parse_class(pattern[body_start:cursor]))
            index = cursor + 1
            continue
        if char == ".":
            skeleton.append(ATOM_CLASS)
            ranges.append(ANY_RANGES)
            index += 1
            continue
        skeleton.append(char)
        ranges.append([(ord(char), ord(char))])
        index += 1
    return "".join(skeleton), ranges


def _ranges_overlap(left: tuple[int, int] | None, right: tuple[int, int] | None) -> bool:
    if left is None or right is None:
        return True  # unbounded atom: assume the worst
    return any(lo1 <= hi2 and lo2 <= hi1 for lo1, hi1 in left for lo2, hi2 in right)


def _group_spans(skeleton: str) -> list[tuple[int, int, int]]:
    """Return (close_index, body_start, body_end) for every balanced (...) group."""
    spans: list[tuple[int, int, int]] = []
    stack: list[int] = []
    for index, char in enumerate(skeleton):
        if char == "(":
            stack.append(index)
        elif char == ")" and stack:
            start = stack.pop()
            spans.append((index, start + 1, index))
    return spans


def _quantifier_end(skeleton: str, start: int) -> int:
    if start >= len(skeleton):
        return -1
    """Return the index just past the quantifier beginning at start, else -1."""
    char = skeleton[start]
    if char in "*+?{":
        if char == "{":
            close = skeleton.find("}", start)
            if close == -1:
                return -1
            return close + 1
        return start + 1
    return -1


def unsafe_regex_reason(pattern: str) -> str | None:
    """Return why a custom rule pattern is unsafe to execute, or None if it is acceptable.

    Custom patterns are attacker-supplied and run inside a request thread against up to
    MAX_SCAN_TEXT_CHARS characters. `re` offers no timeout, so a pattern whose failure case
    is super-linear cannot be stopped once entered -- on a threading server that still burns
    a core indefinitely, and before the threading fix it froze every other client. These
    checks reject the shapes that produce super-linear backtracking while leaving ordinary
    PII rules working (anchored digits, single counted repeats, disjoint field classes).
    """
    if not pattern:
        return "Pattern is empty."
    if len(pattern) > MAX_CUSTOM_RULE_PATTERN_CHARS:
        return f"Pattern exceeds {MAX_CUSTOM_RULE_PATTERN_CHARS} characters."

    skeleton, ranges = scan_pattern(pattern)

    quantifier_starts: set[int] = set()
    index = 0
    while index < len(skeleton):
        end = _quantifier_end(skeleton, index)
        if end == -1:
            index += 1
            continue
        quantifier_starts.add(index)
        if skeleton[index] == "{":
            counts = [part for part in skeleton[index + 1 : end - 1].split(",") if part]
            if not counts or any(not part.isdigit() or len(part) > 9 for part in counts):
                # `{n,}` and `{n,m}` have no finite split count, so their cost is unbounded.
                return "Pattern uses an unbounded or malformed counted repeat."
            if max(int(part) for part in counts) > MAX_CUSTOM_RULE_REPEAT:
                # One large repeat is linear, but it is the multiplier that makes a chain of
                # them explode, so cap it before anything else is considered.
                return f"Counted repeat exceeds {MAX_CUSTOM_RULE_REPEAT}."
        index = end

    if len(quantifier_starts) > MAX_CUSTOM_RULE_QUANTIFIERS:
        # Backtracking cost multiplies across quantifiers even when each is separated.
        return f"Pattern uses more than {MAX_CUSTOM_RULE_QUANTIFIERS} quantifiers."

    # Overlapping adjacent quantifiers. Two quantified atoms that can match the same
    # character force the engine to try every split: a*a*, a{1000}a{1000}, [ab]*[bc]*,
    # \d{10}\d{10}. This is the shape behind a{1000}a{1000}a{1000}...b, which passes every
    # per-token check and still hangs. Requiring an intervening unquantified literal, or
    # disjoint character ranges, is what keeps \d{3}-\d{3} and [A-Z]{2}\d{6} working.
    previous_atom = -1
    index = 0
    while index < len(skeleton):
        if index in quantifier_starts:
            index = _quantifier_end(skeleton, index)
            continue
        char = skeleton[index]
        if char in STRUCTURAL_CHARS or char in "{}":
            index += 1
            continue
        if index + 1 in quantifier_starts:
            if previous_atom >= 0 and _ranges_overlap(ranges[previous_atom], ranges[index]):
                return "Two quantified atoms can match the same character; insert a literal separator."
            previous_atom = index
        else:
            previous_atom = -1
        index += 1

    for close, body_start, body_end in _group_spans(skeleton):
        if _quantifier_end(skeleton, close + 1) == -1:
            continue
        body = skeleton[body_start:body_end]
        if any(char in "*+{" for char in body):
            # Nested quantifier: (a+)+, (a*)*, (a{2,5}){2,5}. The inner and outer repeats can
            # split the same run of characters in exponentially many ways.
            return "Quantifier applied to a group that already contains a quantifier."
        if "|" in body:
            # Quantified alternation: (a|a)* and friends retry every branch at every offset.
            return "Quantifier applied to a group that contains an alternation."

    return None


COMPILED_RULE_CACHE: dict[str, re.Pattern[str] | None] = {}


def compile_custom_rule(pattern: str) -> re.Pattern[str] | None:
    """Compile and cache a custom rule, or return None when it is unsafe or invalid.

    Caching means a stored rule is compiled once per process instead of once per scan.
    re.compile is pure, so this changes cost only. Unsafe patterns are cached as None so a
    hostile rule is re-judged cheaply rather than re-analysed on every scan.
    """
    if pattern in COMPILED_RULE_CACHE:
        return COMPILED_RULE_CACHE[pattern]
    compiled: re.Pattern[str] | None = None
    if unsafe_regex_reason(pattern) is None:
        try:
            compiled = re.compile(pattern)
        except re.error:
            compiled = None
    if len(COMPILED_RULE_CACHE) >= COMPILED_RULE_CACHE_MAX:
        COMPILED_RULE_CACHE.clear()
    COMPILED_RULE_CACHE[pattern] = compiled
    return compiled


def apply_custom_rules(text: str, rules: list[dict[str, Any]]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    executed = 0
    for rule in rules:
        if not rule.get("enabled", True):
            continue
        if executed >= MAX_RULES_PER_SCAN:
            break
        pattern = str(rule.get("pattern") or "")
        compiled = compile_custom_rule(pattern)
        if compiled is None:
            continue
        executed += 1
        label = str(rule.get("label") or rule.get("name") or "CUSTOM")
        for match in compiled.finditer(text[:MAX_SCAN_TEXT_CHARS]):
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
            if len(findings) >= MAX_CUSTOM_RULE_FINDINGS:
                return findings
    return findings


class Handler(BaseHTTPRequestHandler):
    timeout = 10
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

    def _send_common_headers(self, content_type: str, script_nonce: str | None = None) -> None:
        self.send_header("Content-Type", content_type)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        # The dashboard ships one inline <script> block. 'unsafe-inline' would void the CSP
        # entirely, because it also re-permits injected inline scripts; a per-response nonce
        # keeps the inline block working while making that the only executable inline script.
        script_src = "script-src 'self'"
        if script_nonce:
            script_src = f"{script_src} 'nonce-{script_nonce}'"
        self.send_header("Content-Security-Policy", f"default-src 'self'; style-src 'self' 'unsafe-inline'; {script_src}; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")

    def _read_json(self) -> dict[str, Any]:
        if hasattr(self, "_payload"):
            return self._payload
        if self.headers.get("Transfer-Encoding"):
            raise RequestError(400, "Transfer-Encoding is not supported. Send Content-Length.")
        lengths = self.headers.get_all("Content-Length", [])
        if len(lengths) > 1:
            raise RequestError(400, "Send exactly one Content-Length header.")
        length_raw = lengths[0] if lengths else "0"
        if not length_raw.isascii() or not length_raw.isdecimal():
            raise RequestError(400, "Invalid Content-Length header.")
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
        if len(raw) != length:
            raise RequestError(400, "Incomplete request body.")
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
        if hasattr(self, "_state_before") and self._state_revision == STATE_REVISION:
            STATE.clear()
            STATE.update(self._state_before)
            if DB_CONN is not None:
                DB_CONN.rollback()
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
        # Constant-time like the password path: a byte-by-byte `==` here leaks how much of a
        # forged token was correct.
        match = next((item for item in STATE["auth"]["accessTokens"] if secure_equals(str(item["token"]), token)), None)
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
        save_state(STATE)  # save_state applies RETENTION_CAPS
        return {"summary": summary, "findings": masked}

    def do_GET(self) -> None:
        with STATE_LOCK:
            self._dispatch_get()

    def _dispatch_get(self) -> None:
        request_id, path = self._request_context("GET")
        try:
            if path == "/":
                nonce = secrets.token_urlsafe(16)
                html = (
                    INDEX.read_text(encoding="utf-8").replace("<script>", f'<script nonce="{nonce}">', 1).encode("utf-8")
                )
                self.send_response(200)
                self._send_common_headers("text/html; charset=utf-8", nonce)
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
        try:
            self._payload = self._read_json()
        except Exception as exc:
            self._handle_exception(exc, self._request_id(), "POST", self._path())
            return
        with STATE_LOCK:
            self._state_before = copy.deepcopy(STATE)
            self._state_revision = STATE_REVISION
            self._dispatch_post()

    def _dispatch_post(self) -> None:
        request_id, path = self._request_context("POST")
        try:
            if path == "/api/auth/login":
                payload = self._read_json()
                if any(
                    key in payload and not isinstance(payload[key], str)
                    for key in ("username", "password")
                ):
                    self._send_json(400, {"error": "username and password must be strings."})
                    return
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
                if not isinstance(payload.get("refreshToken"), str):
                    self._send_json(400, {"error": "refreshToken must be a string."})
                    return
                missing = validate_required(payload, ["refreshToken"])
                if missing:
                    self._send_json(400, {"error": "refreshToken is required."})
                    return
                self._cleanup_tokens()
                refresh = next(
                    (item for item in STATE["auth"]["refreshTokens"] if secure_equals(str(item["token"]), payload["refreshToken"])),
                    None,
                )
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
                allowed, session, reason = self._authorize("read")
                if not allowed or session is None:
                    self._send_json(401, {"error": reason})
                    return
                payload = self._read_json()
                token = self._bearer()
                STATE["auth"]["accessTokens"] = [item for item in STATE["auth"]["accessTokens"] if item["token"] != token]
                # A client-supplied refresh token was previously honoured verbatim, letting any
                # caller revoke other users' sessions. Only the caller's own token is dropped.
                user = next((item for item in STATE["users"] if item["id"] == session["userId"]), None)
                refresh_token = payload.get("refreshToken")
                if refresh_token:
                    STATE["auth"]["refreshTokens"] = [
                        item
                        for item in STATE["auth"]["refreshTokens"]
                        if item["token"] != refresh_token or (user is not None and item["userId"] != user["id"])
                    ]
                # Username is derived from the validated session: trusting payload["username"]
                # let an unauthenticated caller write forged entries into the audit log.
                self._record_auth_audit("logout", user["username"] if user else session["userId"], True)
                save_state(STATE)
                self._send_json(200, {"loggedOut": True})
                return

            if path == "/api/scan":
                allowed, _, reason = self._authorize("write")
                if not allowed:
                    self._send_json(401, {"error": reason})
                    return
                payload = self._read_json()
                text = str(payload.get("text", ""))[:MAX_SCAN_TEXT_CHARS]
                self._send_json(200, self._create_scan(text))
                return

            if path == "/api/v2/scans":
                allowed, _, reason = self._authorize("write")
                if not allowed:
                    self._send_json(401, {"error": reason})
                    return
                payload = self._read_json()
                text = str(payload.get("text", ""))[:MAX_SCAN_TEXT_CHARS]
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
                pattern = str(payload["pattern"])[: MAX_CUSTOM_RULE_PATTERN_CHARS + 1]
                if len(pattern) > MAX_CUSTOM_RULE_PATTERN_CHARS:
                    self._send_json(400, {"error": f"Pattern exceeds {MAX_CUSTOM_RULE_PATTERN_CHARS} characters."})
                    return
                if len(pattern) < 3:
                    self._send_json(400, {"error": "Pattern too short."})
                    return
                if any(token in pattern for token in ["(", ")", "(?", "*+", "++", "\\1"]):
                    self._send_json(400, {"error": "Pattern uses disallowed constructs."})
                    return
                # Allow only small bounded-quantifier braces ({n} / {n,m}); any
                # other brace use is rejected to avoid backtracking blowups.
                for token in re.findall(r"\{[^{}]*\}|\{", pattern):
                    if not re.fullmatch(r"\{\d{1,3}(,\d{1,3})?\}", token) or max(
                        int(part) for part in token.strip("{}").split(",") if part
                    ) > 1000:
                        self._send_json(400, {"error": "Pattern uses disallowed constructs."})
                        return
                # Reject stacked quantifiers (e.g. a** or a++ variants that slip
                # past the literal check) which can cause catastrophic backtracking.
                if re.search(r"[*+]\s*[*+]", pattern):
                    self._send_json(400, {"error": "Pattern uses disallowed constructs."})
                    return
                # Shared backtracking guard: the checks above all pass a{1000}a{1000}...b, which
                # still explodes. validate_custom_rule is the single definition of "safe to run",
                # reused verbatim at execution time so legacy state cannot bypass it.
                if unsafe_regex_reason(pattern) is not None:
                    self._send_json(400, {"error": "Pattern uses disallowed constructs."})
                    return
                try:
                    re.compile(pattern)
                except re.error as exc:
                    self._send_json(400, {"error": f"Invalid regex: {exc}"})
                    return
                if len(STATE.setdefault("customRules", [])) >= MAX_CUSTOM_RULES:
                    self._send_json(
                        400,
                        {"error": f"Custom rule limit reached ({MAX_CUSTOM_RULES}). Remove a rule before adding one."},
                    )
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
                allowed, _, reason = self._authorize("read")
                if not allowed:
                    self._send_json(401, {"error": reason})
                    return
                payload = self._read_json()
                findings = payload.get("findings", [])
                if not isinstance(findings, list):
                    self._send_json(400, {"error": "findings must be an array."})
                    return
                # Unbounded before: every entry built an action plan in the request thread.
                findings = findings[:MAX_REMEDIATE_FINDINGS]
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
        try:
            self._payload = self._read_json()
        except Exception as exc:
            self._handle_exception(exc, self._request_id(), "PATCH", self._path())
            return
        with STATE_LOCK:
            self._state_before = copy.deepcopy(STATE)
            self._state_revision = STATE_REVISION
            self._dispatch_patch()

    def _dispatch_patch(self) -> None:
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
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    server.serve_forever()
