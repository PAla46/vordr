"""Core types, constants and terminal helpers for Vörðr."""

from __future__ import annotations

import json
import os
import re
import sys
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlsplit

VERSION = "0.1.0"
TOOL = "Vörðr"
PROG = "vordr.py"
WIDTH = 54

SEVERITIES = ("critical", "high", "medium", "low", "info")
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}

# Headers worth recording in evidence and evaluating.
SECURITY_HEADERS = (
    "strict-transport-security",
    "x-content-type-options",
    "x-frame-options",
    "content-security-policy",
    "referrer-policy",
    "permissions-policy",
    "cache-control",
)

EVIDENCE_HEADERS = (
    "content-type",
    "content-length",
    "server",
    "x-powered-by",
    "x-aspnet-version",
    "via",
    "www-authenticate",
    "cache-control",
    "vary",
    "age",
    "location",
    "strict-transport-security",
    "access-control-allow-origin",
    "access-control-allow-credentials",
    "access-control-allow-methods",
    "retry-after",
    "x-ratelimit-limit",
    "x-ratelimit-remaining",
    "x-ratelimit-reset",
    "ratelimit-limit",
    "ratelimit-remaining",
    "ratelimit-reset",
)

DOC_PATHS = (
    "/openapi.json",
    "/swagger.json",
    "/v2/api-docs",
    "/v3/api-docs",
    "/swagger/v1/swagger.json",
    "/swagger-ui/index.html",
    "/swagger-ui.html",
    "/docs",
    "/redoc",
    "/api-docs",
    "/.well-known/security.txt",
)

# Paths that are legitimately unauthenticated. Prevents obvious false positives.
PUBLIC_PATH_RE = re.compile(
    r"(?i)(^/|/)(health|healthz|livez|readyz|ping|status|metrics|version|robots\.txt|"
    r"favicon\.ico|login|logout|signin|signup|register|token|oauth2?|\.well-known)(/|$|\?)"
)

# Field names that should never appear in an anonymous response body.
SENSITIVE_KEY_RE = re.compile(
    r"(?i)^(.*_)?("
    r"pass(word|wd|phrase)?|secret|token|api_?key|access_?key|private_?key|"
    r"session(_?id)?|cookie|authorization|auth_?token|refresh_?token|"
    r"ssn|social_?security|aadhaar|aadhar|pan_?number|tax_?id|national_?id|"
    r"date_?of_?birth|dob|birth_?date|"
    r"phone|mobile|msisdn|email|e_?mail|address|street|postal_?code|zip_?code|"
    r"iban|account_?number|card_?number|credit_?card|cvv|expiry_?date|"
    r"salary|income|latitude|longitude|gps|geo_?location|device_?id"
    r")(_.*)?$"
)

AUTH_FAILURE_RE = re.compile(
    r"(?i)(unauthori[sz]ed|unauthenticated|forbidden|access denied|not authorized|"
    r"invalid (token|credential|api key)|token (expired|invalid|missing)|"
    r"authentication required|login required|missing (token|credential))"
)

STACK_TRACE_MARKERS = (
    "Traceback (most recent call last)",
    "Whitelabel Error Page",
    "java.lang.",
    "org.springframework",
    "SQLSyntaxErrorException",
    "com.mysql",
    "psycopg2",
    "django.db",
    "Exception in thread",
    "at org.apache",
    "stack trace",
    "Debug mode",
)

RATE_HEADER_RE = re.compile(r"(?i)(x-)?rate.?limit|retry-after")

# OWASP API Security Top 10 (2023). ``checks`` maps to executed check ids.
OWASP = (
    {"id": "API1:2023", "name": "Broken Object Level Authorization",
     "checks": (), "why": "requires two authenticated identities and real object identifiers"},
    {"id": "API2:2023", "name": "Broken Authentication",
     "checks": ("anon", "forgery", "header_bypass", "path_variant"), "why": ""},
    {"id": "API3:2023", "name": "Broken Object Property Level Authorization",
     "checks": ("sensitive_fields",), "why": ""},
    {"id": "API4:2023", "name": "Unrestricted Resource Consumption",
     "checks": ("rate_limit",), "why": ""},
    {"id": "API5:2023", "name": "Broken Function Level Authorization",
     "checks": ("anon", "methods"), "why": ""},
    {"id": "API6:2023", "name": "Unrestricted Access to Sensitive Business Flows",
     "checks": (), "why": "requires business context and write operations"},
    {"id": "API7:2023", "name": "Server Side Request Forgery",
     "checks": (), "why": "requires injected payloads, deliberately out of scope"},
    {"id": "API8:2023", "name": "Security Misconfiguration",
     "checks": ("tls", "hsts", "cors", "headers", "error_verbosity", "methods", "cache"), "why": ""},
    {"id": "API9:2023", "name": "Improper Inventory Management",
     "checks": ("docs", "version_parity"), "why": ""},
    {"id": "API10:2023", "name": "Unsafe Consumption of Third-Party APIs",
     "checks": (), "why": "not observable black-box"},
)

CHECK_LABELS = {
    "tls": "TLS version, cipher and certificate",
    "hsts": "Strict-Transport-Security",
    "cors": "CORS policy",
    "headers": "HTTP security headers",
    "docs": "API documentation / spec exposure",
    "methods": "HTTP method exposure (OPTIONS/TRACE)",
    "anon": "Anonymous access to every endpoint",
    "forgery": "Forged credential rejection",
    "header_bypass": "Proxy/rewrite header bypass",
    "path_variant": "Path normalization authorization bypass",
    "sensitive_fields": "Sensitive field exposure in anonymous payloads",
    "cache": "Cacheability of protected responses",
    "rate_limit": "Rate limiting",
    "error_verbosity": "Error verbosity",
    "error_handling": "Unhandled errors on anonymous input",
    "version_parity": "API version parity",
    "sensitive_paths": "Common sensitive paths",
    "plaintext": "Plaintext HTTP availability",
    "lockout": "Account lockout (requires disposable account)",
}

# Header aliases, normalised to lowercase alphanumerics.
ALIASES = {
    "endpoint": {
        "endpoint", "endpoints", "path", "url", "uri", "route", "endpointpath",
        "apiendpoint", "api", "resource", "target", "fullurl", "requesturl",
    },
    "method": {"method", "verb", "httpmethod", "httpverb", "requestmethod"},
    "service": {
        "service", "servicename", "app", "application", "system", "component",
        "microservice", "repo", "repository",
    },
    "base_url": {
        "publicurl", "publicbaseurl", "baseurl", "host", "publichost",
        "edgeurl", "gatewayurl", "ingressbaseurl", "ingressurl", "domain",
    },
    "exposure": {"exposure", "scope", "visibility", "internetfacing", "channel"},
    "description": {
        "description", "function", "purpose", "summary", "notes", "note", "comment",
    },
    "auth_required": {
        "authrequired", "requiresauth", "auth", "protected", "authenticationrequired",
        "authreq", "requiresauthentication",
    },
    "auth_type": {
        "authentication", "authtype", "authscheme", "authenticationtype",
        "authenticationmechanism", "authtoken",
    },
    "rate_limit": {"ratelimit", "ratelimits", "throttle", "throttling", "ratelimitsheader"},
    "pii": {"piifields", "pii", "sensitivefields", "datafields"},
    "owner": {"owner", "team", "squad", "contact", "responsible"},
    "public_by_design": {"publicbydesign", "expectedpublic", "publicendpoint", "public"},
}

ALIAS_LOOKUP: dict[str, str] = {
    alias: canon for canon, names in ALIASES.items() for alias in names
}

TRUE_VALUES = {"y", "yes", "true", "1", "required", "mandatory", "t"}
FALSE_VALUES = {"n", "no", "false", "0", "none", "public", "optional"}

WRITE_METHODS = {"POST", "PUT", "PATCH", "DELETE", "TRACE", "CONNECT"}
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}


def now_iso() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def norm(value: Any) -> str:
    """Normalise a header or cell value for fuzzy matching."""
    return re.sub(r"[^a-z0-9]", "", str(value or "").lower())


def host_of(url: str) -> str:
    try:
        return (urlsplit(url).netloc or "").lower()
    except ValueError:
        return ""


def scheme_of(url: str) -> str:
    try:
        return (urlsplit(url).scheme or "").lower()
    except ValueError:
        return ""


def placeholder_names(path: str) -> list[str]:
    """Return placeholder names in ``/users/{id}``, ``/users/:id`` or ``/users/<id>``."""
    found = re.findall(r"\{([^{}/]+)\}|<([^<>/]+)>|:([A-Za-z_][A-Za-z0-9_]*)", path or "")
    names = [next(x for x in m if x) for m in found]
    return [n for n in names if n.lower() not in {"http", "https"}]


def resolve_placeholders(path: str, values: dict[str, str]) -> tuple[str, list[str]]:
    """Substitute known placeholders; return resolved path and unresolved names."""
    unresolved: list[str] = []

    def repl(m: re.Match) -> str:
        name = next((g for g in m.groups() if g), "")
        for key in (name, name.lower()):
            if key in values and str(values[key]).strip():
                return str(values[key]).strip()
        unresolved.append(name)
        return m.group(0)

    out = re.sub(r"\{([^{}/]+)\}|<([^<>/]+)>|:([A-Za-z_][A-Za-z0-9_]*)", repl, path or "")
    return out, unresolved


EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+\.[\w.]+")
JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}")
TOKEN_KV_RE = re.compile(r"(?i)\b(bearer|token|api[_-]?key|secret|password)\b\s*[:=]\s*\S+")
LONG_DIGITS_RE = re.compile(r"\b\d{7,}\b")


def redact(text: str, limit: int | None = None) -> str:
    """Remove anything that could be a secret or personal data before storing it."""
    if not text:
        return ""
    out = EMAIL_RE.sub("<email>", text)
    out = JWT_RE.sub("<jwt>", out)
    out = TOKEN_KV_RE.sub(lambda m: f"{m.group(1)}=<redacted>", out)
    out = LONG_DIGITS_RE.sub("<num>", out)
    out = re.sub(r"\s+", " ", out).strip()
    return out[:limit] if limit else out


def json_body(text: str) -> Any:
    try:
        return json.loads(text)
    except (ValueError, TypeError):
        return None


def record_count(body: Any) -> int:
    if isinstance(body, list):
        return len(body)
    if isinstance(body, dict):
        for key in ("data", "items", "results", "content", "records", "rows", "list"):
            if isinstance(body.get(key), list):
                return len(body[key])
        return 1 if body else 0
    return 0


def short(value: Any, width: int = 70) -> str:
    text = str(value or "").replace("\n", " ").strip()
    return text if len(text) <= width else text[: width - 1] + "…"


def truthy(value: Any) -> bool | None:
    n = norm(value)
    if n in TRUE_VALUES or n.startswith("yes"):
        return True
    if n in FALSE_VALUES or n.startswith("no"):
        return False
    return None


@dataclass
class Endpoint:
    method: str
    path: str
    url: str
    service: str = ""
    sheet: str = ""
    exposure: str = ""
    description: str = ""
    claimed_auth: str = ""
    claimed_auth_type: str = ""
    claimed_rate: str = ""
    pii_fields: str = ""
    owner: str = ""
    public_by_design: bool | None = None
    row: int = 0
    skip_reason: str = ""
    note: str = ""

    @property
    def label(self) -> str:
        return f"{self.method} {self.path or self.url}"

    @property
    def declared_protected(self) -> bool | None:
        if self.public_by_design is True:
            return False
        explicit = truthy(self.claimed_auth)
        if explicit is not None:
            return explicit
        if self.claimed_auth_type:
            return not re.search(r"(?i)(none|public|no auth|n/?a)", self.claimed_auth_type)
        return None


@dataclass
class Finding:
    title: str
    severity: str
    endpoint: str = "global"
    service: str = ""
    sheet: str = ""
    owasp: tuple[str, ...] = ()
    cwe: str = ""
    asvs: str = ""
    evidence: str = ""
    remediation: str = ""
    detail: str = ""
    obs_id: str = ""
    check: str = ""

    @property
    def rank(self) -> int:
        return SEV_RANK.get(self.severity, 99)


@dataclass
class EndpointResult:
    endpoint: Endpoint
    status: int | None = None
    auth_enforced: str = "not tested"
    bypass: bool = False
    findings: list[Finding] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    signals: list[tuple[str, str]] = field(default_factory=list)
    rate_limited: bool = False
    skipped: str = ""

    @property
    def worst(self) -> str:
        if not self.findings:
            return ""
        return min((f.severity for f in self.findings), key=lambda s: SEV_RANK.get(s, 99))


@dataclass
class Config:
    target: str = ""
    endpoints_file: str = ""
    out_dir: str = "vordr-out"
    author: str = ""
    profile: str = "safe"
    max_requests: int = 800
    delay_ms: int = 120
    timeout: float = 15.0
    verify_tls: bool = True
    scope_ack: bool = False
    allow_hosts: list[str] = field(default_factory=list)
    allow_private: bool = False
    include_internal: bool = False
    rate_probe: bool = False
    rate_burst: int = 25
    error_probe: bool = False
    weak_tls: bool = False
    limit: int = 0
    service_filter: str = ""
    sheet_filter: str = ""
    verbose: bool = False
    color: bool = True
    dry_run: bool = False
    fail_on: str = ""
    placeholders: dict[str, str] = field(default_factory=dict)
    expect_public: list[str] = field(default_factory=list)
    skip_checks: list[str] = field(default_factory=list)
    force_http: bool = False

    def wants(self, check: str) -> bool:
        return check not in self.skip_checks


class Printer:
    """shcheck-style terminal output: [+] pass, [-] fail, [!] observation."""

    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[36m"
    MAGENTA = "\033[35m"

    def __init__(self, color: bool = True, verbose: bool = False):
        self.color = color and os.environ.get("NO_COLOR") is None
        self.verbose = verbose
        self.lines: list[str] = []

    def _paint(self, code: str, text: str) -> str:
        return f"{code}{text}{self.RESET}" if self.color else text

    def emit(self, text: str = "") -> None:
        self.lines.append(text)
        print(text)

    def plain(self, text: str = "") -> None:
        self.emit(text)

    def bold(self, text: str) -> None:
        self.emit(self._paint(self.BOLD, text))

    def info(self, text: str) -> None:
        self.emit(f"{self._paint(self.BLUE, '[*]')} {text}")

    def passed(self, text: str) -> None:
        self.emit(f"{self._paint(self.GREEN, '[+]')} {text}")

    def failed(self, text: str) -> None:
        self.emit(f"{self._paint(self.RED, '[-]')} {text}")

    def warn(self, text: str) -> None:
        self.emit(f"{self._paint(self.YELLOW, '[!]')} {text}")

    def skip(self, text: str) -> None:
        self.emit(f"{self._paint(self.DIM, '[?]')} {self._paint(self.DIM, text)}")

    def untested(self, text: str) -> None:
        self.emit(f"{self._paint(self.DIM, '[ ]')} {self._paint(self.DIM, text)}")

    def finding(self, severity: str, text: str) -> None:
        tag = {"critical": "CRIT", "high": "HIGH", "medium": "MED ", "low": "LOW ", "info": "INFO"}.get(
            severity, "OBS "
        )
        color = {
            "critical": self.MAGENTA, "high": self.RED, "medium": self.YELLOW,
            "low": self.BLUE, "info": self.DIM,
        }.get(severity, self.DIM)
        self.emit(f"{self._paint(color, '[' + tag + ']')} {text}")

    def rule(self, char: str = "-") -> None:
        self.emit(char * WIDTH)

    def header(self, author: str) -> None:
        self.plain("=" * WIDTH)
        left = f" > {PROG} - {author} " if author else f" > {PROG} "
        dots = "." * max(0, WIDTH - len(left))
        self.plain(left + dots)
        self.rule()
        self.plain(" Anonymous-boundary API security assessment")
        self.plain(" OWASP API Security Top 10 (2023) mapped")
        self.plain("=" * WIDTH)
        self.plain()


def color_enabled(stream: Any = None) -> bool:
    stream = stream or sys.stdout
    if os.environ.get("NO_COLOR") is not None:
        return False
    try:
        return bool(stream.isatty())
    except (AttributeError, ValueError):
        return False
