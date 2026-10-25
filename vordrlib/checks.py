"""Control checks: global host posture and per-endpoint anonymous-boundary tests."""

from __future__ import annotations

import re
import secrets
from typing import Any
from urllib.parse import urljoin, urlsplit

from .endpoints import EndpointMixin
from .engine import Engine, inspect_tls, probe_legacy_tls
from .model import (
    DOC_PATHS,
    Config,
    EndpointResult,
    Finding,
    Printer,
    host_of,
    scheme_of,
    short,
)

SENSITIVE_PATHS = (
    ("/.env", "critical", "Environment file"),
    ("/.git/config", "high", "Git repository metadata"),
    ("/actuator/env", "high", "Spring Boot actuator environment"),
    ("/actuator/heapdump", "high", "Spring Boot actuator heap dump"),
    ("/server-status", "medium", "Apache server-status"),
    ("/phpinfo.php", "medium", "PHP configuration dump"),
)

ADMIN_PATH_RE = re.compile(r"(?i)(^|/)(admin|internal|manage|management|root|superuser|backoffice)(/|$)")


class Auditor(EndpointMixin):
    def __init__(self, cfg: Config, engine: Engine, printer: Printer):
        self.cfg = cfg
        self.engine = engine
        self.p = printer
        self.findings: list[Finding] = []
        self.results: list[EndpointResult] = []
        self.executed: set[str] = set()
        self.info: dict[str, Any] = {"baseline_404": None, "tls": None}
        self.rate_probed = 0
        self._seen: set[str] = set()

    # ------------------------------------------------------------------ helpers
    def _add(self, res: EndpointResult | None, finding: Finding) -> Finding:
        # Findings emitted once per host would otherwise repeat for every endpoint.
        host_level = {"methods", "headers", "docs", "sensitive_paths", "cors",
                      "hsts", "tls", "plaintext"}
        if finding.check in host_level and finding.title in self._seen:
            return finding
        self._seen.add(finding.title)
        if res is not None:
            if finding.endpoint == "global":
                finding.endpoint = res.endpoint.label
            finding.service = finding.service or res.endpoint.service
            finding.sheet = finding.sheet or res.endpoint.sheet
            res.findings.append(finding)
        self.findings.append(finding)
        return finding

    def _ep(self, res: EndpointResult | None) -> dict[str, str]:
        ep = res.endpoint if res else None
        return {
            "endpoint": ep.label if ep else "global",
            "service": ep.service if ep else "",
            "sheet": ep.sheet if ep else "",
        }

    # ------------------------------------------------------------------- global
    def run_global(self, base: str) -> None:
        host = host_of(base)
        scheme = scheme_of(base)
        self.p.rule()
        self.p.info(f"Global controls  {scheme}://{host}")

        if scheme == "https":
            self._tls(host)
            self._plaintext(base, host)
        else:
            self.p.warn("target is plaintext http: TLS controls not applicable")
            self._add(None, Finding(
                title="Assessment target uses plaintext HTTP",
                severity="high", check="tls", owasp=("API8:2023",), cwe="CWE-319",
                evidence=f"base URL {base} has scheme http",
                remediation="Serve the API over HTTPS only and redirect port 80.",
            ))
            self.executed.add("tls")

        response = self.engine.request("GET", base, note="global baseline")
        if response is not None:
            self._response_headers(response, base)
            self._cors(base, response)
        self.info["baseline"] = response.status_code if response is not None else None

        self._docs(base)
        self._sensitive_paths(base)
        self._baseline_404(base)

    def _tls(self, host: str) -> None:
        tls = inspect_tls(host)
        self.info["tls"] = tls
        self.executed.add("tls")
        if not tls.ok:
            self.p.failed(f"TLS: {tls.error}")
            self._add(None, Finding(
                title="TLS negotiation or certificate validation failed",
                severity="high", check="tls", owasp=("API8:2023",), cwe="CWE-295",
                evidence=tls.error, remediation="Present a valid, publicly trusted certificate chain.",
            ))
            return
        expiry = f"expires {tls.not_after}" if tls.not_after else "expiry unknown"
        self.p.passed(f"TLS {tls.version} ({tls.cipher}), certificate valid, {expiry}")
        if tls.weak:
            self._add(None, Finding(
                title=f"Obsolete TLS version accepted ({tls.version})",
                severity="high", check="tls", owasp=("API8:2023",), cwe="CWE-326",
                evidence=f"negotiated {tls.version} / {tls.cipher}",
                remediation="Require TLS 1.2 or 1.3 and disable TLS 1.0/1.1.",
            ))
        if tls.days_left is not None and tls.days_left < 0:
            self._add(None, Finding(
                title="TLS certificate has expired",
                severity="high", check="tls", owasp=("API8:2023",), cwe="CWE-298",
                evidence=f"notAfter={tls.not_after}", remediation="Renew and automate certificate rotation.",
            ))
        elif tls.days_left is not None and tls.days_left < 21:
            self._add(None, Finding(
                title=f"TLS certificate expires in {tls.days_left} days",
                severity="medium", check="tls", owasp=("API8:2023",), cwe="CWE-298",
                evidence=f"notAfter={tls.not_after}",
                remediation="Renew before expiry and monitor with alerting.",
            ))
        if re.search(r"(?i)RC4|3DES|DES|EXPORT|NULL|MD5", tls.cipher or ""):
            self._add(None, Finding(
                title="Weak TLS cipher suite negotiated",
                severity="high", check="tls", owasp=("API8:2023",), cwe="CWE-327",
                evidence=tls.cipher, remediation="Restrict the cipher suite to AEAD algorithms.",
            ))
        if self.cfg.weak_tls:
            legacy = probe_legacy_tls(host)
            if legacy:
                self._add(None, Finding(
                    title="Legacy TLS versions accepted: " + ", ".join(legacy),
                    severity="high", check="tls", owasp=("API8:2023",), cwe="CWE-326",
                    evidence="successful handshake with " + ", ".join(legacy),
                    remediation="Disable TLS 1.0 and TLS 1.1 at the load balancer.",
                ))
            else:
                self.p.passed("Legacy TLS (1.0/1.1) refused")

    def _plaintext(self, base: str, host: str) -> None:
        plain = "http://" + host + (urlsplit(base).path or "/")
        response = self.engine.request("GET", plain, note="plaintext probe")
        self.executed.add("plaintext")
        if response is None:
            return
        location = response.headers.get("location", "")
        if response.status_code in {301, 302, 307, 308} and location.startswith("https://"):
            self.p.passed(f"HTTP -> HTTPS redirect ({response.status_code})")
        elif response.status_code < 400:
            self.p.failed("Plaintext HTTP serves content without redirect")
            self._add(None, Finding(
                title="API answers over plaintext HTTP",
                severity="high", check="plaintext", owasp=("API8:2023",), cwe="CWE-319",
                evidence=f"GET {plain} -> HTTP {response.status_code}",
                remediation="Redirect all HTTP traffic to HTTPS with HSTS.",
            ))
        else:
            self.p.warn(f"Plaintext HTTP returned {response.status_code} without HTTPS redirect")
            self._add(None, Finding(
                title="Plaintext HTTP not redirected to HTTPS",
                severity="medium", check="plaintext", owasp=("API8:2023",), cwe="CWE-319",
                evidence=f"GET {plain} -> HTTP {response.status_code}",
                remediation="Return 301/308 to the HTTPS origin for every HTTP request.",
            ))

    def _response_headers(self, response: Any, url: str) -> None:
        headers = {k.lower(): v for k, v in response.headers.items()}
        self.executed.add("headers")
        if scheme_of(url) == "https" and "strict-transport-security" not in headers:
            self.p.failed("HSTS not set: Strict-Transport-Security")
            self._add(None, Finding(
                title="Strict-Transport-Security (HSTS) not set",
                severity="medium", check="hsts", owasp=("API8:2023",), cwe="CWE-319",
                evidence=f"GET {url} -> HTTP {response.status_code}, no Strict-Transport-Security",
                remediation="Send max-age=31536000; includeSubDomains on all HTTPS responses.",
            ))
        else:
            if scheme_of(url) == "https":
                self.executed.add("hsts")
                self.p.passed("HSTS present: " + short(headers["strict-transport-security"], 50))
        if "x-content-type-options" not in headers:
            self._add(None, Finding(
                title="X-Content-Type-Options not set (MIME sniffing)",
                severity="low", check="headers", owasp=("API8:2023",), cwe="CWE-693",
                evidence=f"GET {url} -> no X-Content-Type-Options",
                remediation="Send X-Content-Type-Options: nosniff.",
            ))
        for header in ("server", "x-powered-by", "x-aspnet-version"):
            if headers.get(header):
                self.p.warn(f"{header} discloses {short(headers[header], 40)}")
                self._add(None, Finding(
                    title=f"Technology disclosure via {header}",
                    severity="low", check="headers", owasp=("API8:2023",), cwe="CWE-200",
                    evidence=f"{header}: {short(headers[header], 60)}",
                    remediation=f"Suppress {header} at the gateway or application server.",
                ))
                break
        if (headers.get("cache-control")
                and "no-store" not in headers["cache-control"].lower()
                and response.status_code >= 400):
            self._add(None, Finding(
                title="Authentication error responses are cacheable",
                severity="low", check="cache", owasp=("API8:2023",), cwe="CWE-524",
                evidence=f"Cache-Control: {short(headers['cache-control'], 60)} "
                         f"on HTTP {response.status_code}",
                remediation="Send Cache-Control: no-store on all authenticated and error responses.",
            ))

    def _cors(self, base: str, baseline: Any) -> None:
        self.executed.add("cors")
        origin = "https://vordr-probe.example"
        response = self.engine.request("GET", base, note="cors origin reflection",
                                       headers={"Origin": origin})
        if response is None:
            return
        acao = response.headers.get("access-control-allow-origin", "")
        acac = response.headers.get("access-control-allow-credentials", "").lower()
        credentialed = acac == "true"
        finding = None
        if acao == origin and credentialed:
            self.p.failed("CORS reflects arbitrary Origin with credentials")
            finding = Finding(
                title="CORS reflects an arbitrary Origin with credentials",
                severity="high", check="cors", owasp=("API8:2023",), cwe="CWE-942",
                evidence=f"Origin {origin} -> ACAO {origin}, ACAC true",
                remediation="Allow-list known browser origins; never reflect Origin with credentials.",
            )
        elif acao == origin:
            self.p.warn(f"CORS reflects arbitrary Origin ({origin})")
            finding = Finding(
                title="CORS reflects an arbitrary Origin",
                severity="medium", check="cors", owasp=("API8:2023",), cwe="CWE-942",
                evidence=f"Origin {origin} -> ACAO {origin}",
                remediation="Validate Origin against an allow-list.",
            )
        elif acao == "*" and credentialed:
            self.p.warn("CORS wildcard present with credentials flag")
            finding = Finding(
                title="CORS wildcard declared together with credentials",
                severity="low", check="cors", owasp=("API8:2023",), cwe="CWE-942",
                evidence="ACAO * with ACAC true (browsers reject this combination)",
                remediation="Use an explicit origin allow-list; drop the credentials flag for public data.",
            )
        elif acao == "*":
            self.p.warn("CORS wildcard: any web origin may read responses")
            finding = Finding(
                title="CORS allows any origin (Access-Control-Allow-Origin: *)",
                severity="low", check="cors", owasp=("API8:2023",), cwe="CWE-942",
                evidence="ACAO * on unauthenticated response",
                remediation="Restrict CORS to known origins if the API serves browser clients.",
            )
        elif not acao:
            self.p.passed("No permissive CORS headers")
        if finding:
            self._add(None, finding)
        null_response = self.engine.request("GET", base, note="cors null origin",
                                            headers={"Origin": "null"})
        if null_response is not None and null_response.headers.get(
            "access-control-allow-origin", ""
        ) == "null":
            self._add(None, Finding(
                title="CORS accepts the 'null' origin",
                severity="medium", check="cors", owasp=("API8:2023",), cwe="CWE-942",
                evidence="Origin: null -> ACAO: null",
                remediation="Reject the null origin; allow-list real origins only.",
            ))

    def _docs(self, base: str) -> None:
        self.executed.add("docs")
        for path in DOC_PATHS:
            url = urljoin(base.rstrip("/") + "/", path.lstrip("/"))
            response = self.engine.request("GET", url, note="documentation discovery")
            if response is None:
                return
            if response.status_code != 200:
                continue
            body = response.text or ""
            looks_like_spec = "openapi" in body.lower() or "swagger" in body.lower()
            if not looks_like_spec and "text/html" not in response.headers.get("content-type", ""):
                continue
            self.p.warn(f"API documentation exposed: {path}")
            self._add(None, Finding(
                title=f"API documentation publicly reachable ({path})",
                severity="medium", check="docs", owasp=("API9:2023",), cwe="CWE-200",
                evidence=f"GET {url} -> HTTP 200, {len(body)} bytes",
                remediation="Require authentication for documentation in production, "
                            "or publish a redacted spec.",
            ))
            return

    def _sensitive_paths(self, base: str) -> None:
        self.executed.add("sensitive_paths")
        for path, severity, label in SENSITIVE_PATHS:
            url = urljoin(base.rstrip("/") + "/", path.lstrip("/"))
            response = self.engine.request("GET", url, note=f"sensitive path {path}")
            if response is None:
                return
            if response.status_code == 200 and len(response.text or "") > 20:
                self.p.failed(f"{label} exposed: {path}")
                self._add(None, Finding(
                    title=f"{label} publicly reachable ({path})",
                    severity=severity, check="sensitive_paths", owasp=("API8:2023",), cwe="CWE-200",
                    evidence=f"GET {url} -> HTTP 200, {len(response.text)} bytes",
                    remediation="Block operational paths at the edge and rotate any exposed secrets.",
                ))

    def _baseline_404(self, base: str) -> None:
        probe = urljoin(base.rstrip("/") + "/", f"__vordr_{secrets.token_hex(6)}")
        response = self.engine.request("GET", probe, note="non-existent path baseline")
        if response is None:
            return
        self.info["baseline_404"] = response.status_code
        if response.status_code == 200:
            self.p.warn("Catch-all route: unknown paths return 200")
            self._add(None, Finding(
                title="Unknown paths return HTTP 200 (catch-all routing)",
                severity="medium", check="headers", owasp=("API9:2023",), cwe="CWE-200",
                evidence=f"GET {probe} -> HTTP 200",
                remediation="Return 404 for unknown resources so that 401/404 remain distinguishable.",
            ))
