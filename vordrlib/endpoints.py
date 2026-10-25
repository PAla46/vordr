"""Per-endpoint anonymous-boundary checks (mixed into :class:`Auditor`)."""

from __future__ import annotations

import re
import secrets
from typing import Any
from urllib.parse import urlsplit

from .model import (
    AUTH_FAILURE_RE,
    PUBLIC_PATH_RE,
    RATE_HEADER_RE,
    SAFE_METHODS,
    SENSITIVE_KEY_RE,
    STACK_TRACE_MARKERS,
    WRITE_METHODS,
    Endpoint,
    EndpointResult,
    Finding,
    json_body,
    record_count,
    short,
)

MARKER = {"critical": "fail", "high": "fail", "medium": "warn", "low": "warn", "info": "info"}


class EndpointMixin:
    """Expects the host class to provide cfg, engine, p, findings, results, executed."""

    def audit_all(self, endpoints: list[Endpoint]) -> list[EndpointResult]:
        testable = [e for e in endpoints if not e.skip_reason]
        self.p.rule()
        self.p.info(f"Endpoint assessment  {len(testable)} of {len(endpoints)} rows")
        for ep in endpoints:
            if ep.skip_reason:
                self.p.skip(f"{ep.label} — skipped: {ep.skip_reason}")
                self.results.append(EndpointResult(ep, skipped=ep.skip_reason))
                continue
            result = self._audit(ep)
            self.results.append(result)
            self._render(result)
            if self.engine.exhausted:
                self.p.warn("request budget exhausted; remaining endpoints not tested")
                break
        return self.results

    # ------------------------------------------------------------------ driver
    def _audit(self, ep: Endpoint) -> EndpointResult:
        res = EndpointResult(ep)
        method, content, extra = self._choose_method(res, ep)
        if method is None:
            return res

        response = self.engine.request(method, ep.url, note="anonymous access", content=content,
                                       headers=extra)
        self.executed.add("anon")
        if response is None:
            res.auth_enforced = "error"
            res.signals.append(("skip", "no response (network error or budget exhausted)"))
            return res

        res.status = response.status_code
        self._classify(res, response)
        self._rate_headers(res, response)

        protected = response.status_code in {401, 403}
        if protected and self.cfg.wants("methods"):
            self._methods(res, ep)
        if protected and self.cfg.wants("forgery"):
            self._forgery(res, ep)
        if protected and self.cfg.wants("header_bypass"):
            self._header_bypass(res, ep)
        if protected and self.cfg.wants("path_variant"):
            self._path_variants(res, ep)
        if self.cfg.error_probe and self.cfg.wants("error_verbosity"):
            self._error_probe(res, ep)
        return res

    def _choose_method(
        self, res: EndpointResult, ep: Endpoint,
    ) -> tuple[str | None, bytes | None, dict[str, str]]:
        if ep.method in SAFE_METHODS:
            return ep.method, None, {}
        if ep.method == "DELETE":
            res.signals.append(("skip", "DELETE is never sent, even in guarded profile"))
            res.skipped = "DELETE not sent"
            return None, None, {}
        if self.cfg.profile == "guarded" and ep.method in WRITE_METHODS:
            res.signals.append(("warn", "guarded profile: zero-length body, unusable content type"))
            return ep.method, b"", {"Content-Type": "application/x-vordr-probe"}
        res.signals.append(("skip", f"{ep.method} not sent in safe profile"))
        res.skipped = f"{ep.method} not sent"
        return None, None, {}

    # -------------------------------------------------------------- classification
    def _classify(self, res: EndpointResult, response: Any) -> None:
        ep = res.endpoint
        status = response.status_code
        body_text = response.text or ""
        body = json_body(body_text) if body_text[:1] in "{[" else None
        public_expected = self._public_expected(ep)
        declared = ep.declared_protected
        scheme = response.headers.get("www-authenticate", "")

        if status in {401, 403}:
            res.auth_enforced = "yes"
            detail = f"auth enforced (HTTP {status}"
            detail += f", WWW-Authenticate: {scheme})" if scheme else ", no WWW-Authenticate)"
            res.signals.append(("pass", detail))
            self.executed.add("forgery")
            return

        if status == 429:
            res.auth_enforced = "yes"
            res.rate_limited = True
            res.signals.append(("pass", "rate limited (HTTP 429) before payload handling"))
            self.executed.add("rate_limit")
            return

        if 200 <= status < 300:
            res.auth_enforced = "no"
            if self._auth_failure_in_body(body, body_text):
                self._add(res, Finding(
                    title="Authentication failure returned with HTTP 200",
                    severity="high", check="anon", owasp=("API2:2023",), cwe="CWE-287",
                    evidence=f"HTTP {status} with an auth-failure payload: {short(body_text, 120)}",
                    remediation="Return 401/403 with WWW-Authenticate; "
                                "do not signal auth failure in a 2xx body.",
                ))
            count = record_count(body)
            if public_expected:
                res.signals.append(("pass", f"expected public endpoint, HTTP {status}, {count} record(s)"))
            elif count == 0 and status == 204:
                res.signals.append(("info", f"HTTP {status} with empty body; no data returned"))
            else:
                severity = "critical" if declared is True else "high"
                because = ("inventory declares authentication is required"
                           if declared is True else "inventory does not declare this endpoint as public")
                res.bypass = True
                self._add(res, Finding(
                    title=f"Anonymous access returned data (HTTP {status})",
                    severity=severity, check="anon", owasp=("API2:2023", "API5:2023"),
                    cwe="CWE-306", asvs="V13.1",
                    evidence=f"HTTP {status}, {response.headers.get('content-type', '?')}, "
                             f"{len(body_text)} bytes, {count} record(s) — {because}",
                    remediation="Enforce authentication at the gateway and in the service; "
                                "verify with an unauthenticated request in CI.",
                ))
            self._sensitive_fields(res, body)
            self._cache(res, response, suppress=public_expected)
            if re.search(r"(?i)json", response.headers.get("content-type", "")):
                pass
            return

        if status == 404:
            baseline = self.info.get("baseline_404")
            if baseline == 404:
                res.auth_enforced = "concealed"
                res.signals.append(
                    ("info", "HTTP 404 — endpoint concealed or absent; cannot confirm enforcement")
                )
            else:
                res.auth_enforced = "unconfirmed"
                res.signals.append(("warn", f"HTTP 404 while unknown paths return {baseline}"))
            return

        if status == 405:
            res.auth_enforced = "unconfirmed"
            allow = response.headers.get("allow", "")
            res.signals.append(("info", f"HTTP 405; Allow: {short(allow, 50) or 'not advertised'}"))
            return

        if 300 <= status < 400:
            location = response.headers.get("location", "")
            res.auth_enforced = "unconfirmed"
            res.signals.append(("info", f"HTTP {status} -> {short(location, 60)}"))
            return

        if status >= 500:
            res.auth_enforced = "unconfirmed"
            self.executed.add("error_handling")
            self._add(res, Finding(
                title=f"Unhandled error on an unauthenticated request (HTTP {status})",
                severity="medium", check="error_handling", owasp=("API8:2023",), cwe="CWE-755",
                evidence=f"HTTP {status}: {short(body_text, 120)}",
                remediation="Return a generic 4xx/5xx body without internals; "
                            "alert on 5xx for anonymous traffic.",
            ))
            return

        res.auth_enforced = "unconfirmed"
        res.signals.append(("info", f"HTTP {status}"))

    @staticmethod
    def _auth_failure_in_body(body: Any, text: str) -> bool:
        if not body:
            return False
        values: list[str] = []

        def walk(node: Any, depth: int = 0) -> None:
            if depth > 2:
                return
            if isinstance(node, dict):
                for key, value in node.items():
                    if isinstance(value, (str, int, float)):
                        values.append(f"{key}={value}")
                    else:
                        walk(value, depth + 1)
            elif isinstance(node, list):
                for item in node[:3]:
                    walk(item, depth + 1)

        walk(body)
        haystack = " ".join(values) or text
        if AUTH_FAILURE_RE.search(haystack):
            keys = " ".join(str(k).lower() for k in (body.keys() if isinstance(body, dict) else []))
            return bool(re.search(r"error|message|detail|status|code|message", keys)) or len(haystack) < 400
        return False

    def _public_expected(self, ep: Endpoint) -> bool:
        if ep.declared_protected is False:
            return True
        if ep.path and PUBLIC_PATH_RE.search(ep.path):
            return True
        for pattern in self.cfg.expect_public:
            try:
                if re.search(pattern, ep.path):
                    return True
            except re.error:
                if pattern in ep.path:
                    return True
        return False

    # ------------------------------------------------------------ property checks
    def _sensitive_fields(self, res: EndpointResult, body: Any) -> None:
        if body is None:
            return
        self.executed.add("sensitive_fields")
        keys: set[str] = set()

        def walk(node: Any, depth: int = 0) -> None:
            if depth > 4 or len(keys) > 500:
                return
            if isinstance(node, dict):
                for key, value in node.items():
                    keys.add(str(key))
                    walk(value, depth + 1)
            elif isinstance(node, list):
                for item in node[:5]:
                    walk(item, depth + 1)

        walk(body)
        hits = sorted(k for k in keys if SENSITIVE_KEY_RE.match(k))
        if not hits:
            return
        shown = ", ".join(hits[:12])
        self._add(res, Finding(
            title=f"Sensitive field names present in anonymous payload: {shown}",
            severity="medium", check="sensitive_fields", owasp=("API3:2023",), cwe="CWE-213",
            asvs="V8.3.4",
            evidence=f"field names only (values redacted): {shown}",
            remediation="Return a response schema per role; never serialize internal objects directly.",
            detail="Only field names are reported. Values are redacted on capture.",
        ))

    def _cache(self, res: EndpointResult, response: Any, suppress: bool = False) -> None:
        if suppress:
            return
        self.executed.add("cache")
        cache = response.headers.get("cache-control", "").lower()
        if "no-store" in cache or "private" in cache:
            return
        if not cache or "public" in cache or "max-age" in cache:
            self._add(res, Finding(
                title="Response carrying data is cacheable by intermediaries",
                severity="low", check="cache", owasp=("API8:2023",), cwe="CWE-524",
                evidence=f"Cache-Control: {cache or '(absent)'} on HTTP {response.status_code}",
                remediation="Send Cache-Control: no-store on responses that contain user or tenant data.",
            ))

    def _rate_headers(self, res: EndpointResult, response: Any) -> None:
        hits = [k for k in response.headers if RATE_HEADER_RE.search(k)]
        if hits:
            res.signals.append(("pass", "rate-limit headers present: " + ", ".join(sorted(hits)[:4])))
            self.executed.add("rate_limit")
        elif self.cfg.rate_probe and self.rate_probed < 2 and res.endpoint.method == "GET":
            self.rate_probed += 1
            self._rate_probe(res)

    def _rate_probe(self, res: EndpointResult) -> None:
        n = max(5, min(self.cfg.rate_burst, 40))
        limited, headers = 0, {}
        for index in range(n):
            response = self.engine.request("GET", res.endpoint.url, note=f"rate probe {index + 1}/{n}")
            if response is None:
                break
            for key, value in response.headers.items():
                if RATE_HEADER_RE.search(key):
                    headers[key] = value
            if response.status_code in {429, 503}:
                limited += 1
        self.executed.add("rate_limit")
        if limited:
            res.rate_limited = True
            res.signals.append(("pass", f"rate limiting enforced: {limited}/{n} requests throttled"))
        else:
            self._add(res, Finding(
                title=f"No rate limiting observed in {n} sequential requests",
                severity="low", check="rate_limit", owasp=("API4:2023",), cwe="CWE-770",
                evidence=f"{n} sequential GETs, {limited} throttled, headers: {headers or 'none'}",
                remediation="Enforce per-identity and per-IP quotas at the gateway "
                            "and return 429 with Retry-After.",
                detail="Inconclusive by nature: per-key limits cannot be measured without a key.",
            ))

    def _methods(self, res: EndpointResult, ep: Endpoint) -> None:
        self.executed.add("methods")
        response = self.engine.request("OPTIONS", ep.url, note="method discovery")
        if response is None:
            return
        allow = response.headers.get("allow", "")
        advertised = [m.strip().upper() for m in allow.split(",") if m.strip()]
        risky = sorted(set(advertised) & {"PUT", "PATCH", "DELETE", "TRACE"})
        if risky:
            res.signals.append(("info", "OPTIONS advertises: " + ", ".join(risky)))
        if "TRACE" in advertised:
            self._add(res, Finding(
                title="TRACE method advertised",
                severity="low", check="methods", owasp=("API8:2023",), cwe="CWE-693",
                evidence=f"Allow: {short(allow, 80)}",
                remediation="Disable TRACE at the gateway.",
            ))

    # ------------------------------------------------------------------ bypasses
    def _forgery(self, res: EndpointResult, ep: Endpoint) -> None:
        variants = {
            "Bearer null": {"Authorization": "Bearer null"},
            "random bearer": {"Authorization": f"Bearer {secrets.token_urlsafe(24)}"},
            "arbitrary API key": {"X-API-Key": "vordr-" + secrets.token_hex(8)},
        }
        for label, headers in variants.items():
            if self.engine.remaining <= 8:
                return
            response = self.engine.request("GET", ep.url, note=f"forgery: {label}", headers=headers)
            if response is None:
                return
            if 200 <= response.status_code < 300 and not self._auth_failure_in_body(
                json_body(response.text or ""), response.text or ""
            ):
                res.bypass = True
                self._add(res, Finding(
                    title=f"Authentication bypass with a forged credential ({label})",
                    severity="critical", check="forgery", owasp=("API2:2023",), cwe="CWE-287",
                    asvs="V13.1.1",
                    evidence=f"{label} -> HTTP {response.status_code}, "
                             f"{record_count(json_body(response.text or ''))} record(s)",
                    remediation="Validate token signature, issuer, audience and expiry; "
                                "never trust the header shape.",
                ))
                return
        res.signals.append(("pass", "forged credentials rejected"))

    def _header_bypass(self, res: EndpointResult, ep: Endpoint) -> None:
        path = urlsplit(ep.url).path or "/"
        variants = {
            "X-Forwarded-For: 127.0.0.1": {"X-Forwarded-For": "127.0.0.1"},
            "X-Original-URL": {"X-Original-URL": path},
            "X-Forwarded-Host: localhost": {"X-Forwarded-Host": "localhost"},
        }
        for label, headers in variants.items():
            if self.engine.remaining <= 8:
                return
            response = self.engine.request("GET", ep.url, note=f"header bypass: {label}", headers=headers)
            if response is None:
                return
            if 200 <= response.status_code < 300 and record_count(json_body(response.text or "")) > 0:
                res.bypass = True
                self._add(res, Finding(
                    title=f"Authorization bypass via {label}",
                    severity="critical", check="header_bypass", owasp=("API2:2023", "API5:2023"),
                    cwe="CWE-290", evidence=f"{label} -> HTTP {response.status_code} with data",
                    remediation="Strip client-supplied forwarding headers at the edge; "
                                "never use them for auth decisions.",
                ))
                return
        res.signals.append(("pass", "proxy-header bypass rejected"))

    def _path_variants(self, res: EndpointResult, ep: Endpoint) -> None:
        base = urlsplit(ep.url)
        path = base.path or "/"
        variants = self._build_variants(path)
        for variant in variants:
            if self.engine.remaining <= 8:
                return
            url = base._replace(path=variant).geturl()
            response = self.engine.request("GET", url, note=f"path variant {variant}")
            if response is None:
                return
            if 200 <= response.status_code < 300 and record_count(json_body(response.text or "")) > 0:
                res.bypass = True
                self._add(res, Finding(
                    title="Authorization bypass via path normalization",
                    severity="high", check="path_variant", owasp=("API2:2023", "API5:2023"),
                    cwe="CWE-647", evidence=f"{variant} -> HTTP {response.status_code} with data",
                    remediation="Normalize and canonicalize the path before authorization; "
                                "make the gateway and the service agree on routing.",
                ))
                return
        res.signals.append(("pass", f"path normalization consistent ({len(variants)} variants)"))

    @staticmethod
    def _build_variants(path: str) -> list[str]:
        variants: list[str] = []
        if path.endswith("/"):
            variants.append(path.rstrip("/") or "/")
        else:
            variants.append(path + "/")
        parts = path.split("/")
        if len(parts) > 2 and parts[1]:
            variants.append("/" + parts[1].upper() + "/" + "/".join(parts[2:]))
            variants.append("/" + parts[1] + "//" + "/".join(parts[2:]))
            variants.append("/" + parts[1] + "/./" + "/".join(parts[2:]))
            variants.append("/" + parts[1] + "/%2e/" + "/".join(parts[2:]))
        out: list[str] = []
        for item in variants:
            if item != path and item not in out and len(item) < 300:
                out.append(item)
        return out[:4]

    def _error_probe(self, res: EndpointResult, ep: Endpoint) -> None:
        probe = {"vordr_probe": "{" * 4 + "x" * 48, "id": "9" * 40}
        response = self.engine.request("GET", ep.url, note="error verbosity probe", params=probe)
        if response is None:
            return
        self.executed.add("error_verbosity")
        body = response.text or ""
        hit = next((m for m in STACK_TRACE_MARKERS if m in body), "")
        if hit or response.status_code >= 500:
            self._add(res, Finding(
                title="Verbose error handling on malformed input",
                severity="medium", check="error_verbosity", owasp=("API8:2023",), cwe="CWE-209",
                evidence=f"HTTP {response.status_code}"
                         + (f", marker '{hit}'" if hit else ""),
                remediation="Disable debug output, catch parser errors and return a correlation id only.",
            ))

    # ------------------------------------------------------------------ rendering
    def _render(self, res: EndpointResult) -> None:
        ep = res.endpoint
        if not res.signals and not res.findings and not self.cfg.verbose:
            return
        self.p.plain()
        self.p.info(ep.label)
        for kind, text in res.signals:
            getattr(self.p, {"pass": "passed", "warn": "warn", "skip": "skip",
                             "info": "info", "fail": "failed"}.get(kind, "info"))(text)
        for finding in sorted(res.findings, key=lambda f: f.rank):
            if MARKER.get(finding.severity) == "fail":
                self.p.failed(finding.title)
            elif MARKER.get(finding.severity) == "info":
                self.p.info(finding.title)
            else:
                self.p.warn(finding.title)
