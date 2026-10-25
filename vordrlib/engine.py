"""HTTP engine: request budget, throttling, evidence capture and TLS inspection."""

from __future__ import annotations

import hashlib
import ipaddress
import socket
import ssl
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import httpx

from .model import (
    EVIDENCE_HEADERS,
    Config,
    now_iso,
    redact,
)


class ScopeError(RuntimeError):
    pass


@dataclass
class TlsInfo:
    ok: bool = False
    version: str = ""
    cipher: str = ""
    subject: str = ""
    issuer: str = ""
    not_after: str = ""
    days_left: int | None = None
    error: str = ""
    weak: bool = False


def _parse_cert_time(value: str) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromtimestamp(ssl.cert_time_to_seconds(value), tz=UTC)
    except (ValueError, OverflowError):
        return None


def inspect_tls(host: str, port: int = 443, timeout: float = 8.0) -> TlsInfo:
    info = TlsInfo()
    context = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw, \
                context.wrap_socket(raw, server_hostname=host) as tls:
            info.ok = True
            info.version = tls.version() or ""
            cipher = tls.cipher()
            info.cipher = cipher[0] if cipher else ""
            cert = tls.getpeercert() or {}
        subject = ", ".join(f"{k}={v}" for part in cert.get("subject", ()) for k, v in part)
        issuer = ", ".join(f"{k}={v}" for part in cert.get("issuer", ()) for k, v in part)
        info.subject = subject
        info.issuer = issuer
        info.not_after = cert.get("notAfter", "")
        expires = _parse_cert_time(info.not_after)
        if expires:
            info.days_left = (expires - datetime.now(UTC)).days
    except ssl.SSLCertVerificationError as exc:
        info.error = f"certificate verification failed: {exc.verify_message}"
    except TimeoutError:
        info.error = "TLS handshake timed out"
    except OSError as exc:
        info.error = f"TLS handshake failed: {exc.strerror or exc}"
    except Exception as exc:  # noqa: BLE001 - report, never crash a scan
        info.error = f"TLS handshake failed: {exc}"
    info.weak = bool(info.ok and info.version in {"TLSv1", "TLSv1.1", "SSLv3", "SSLv2"})
    return info


def probe_legacy_tls(host: str, port: int = 443, timeout: float = 6.0) -> list[str]:
    """Return legacy TLS versions the host still accepts. Only called when asked."""
    accepted: list[str] = []
    for name in ("TLSv1", "TLSv1.1"):
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            version = getattr(ssl.TLSVersion, name)
            context.minimum_version = version
            context.maximum_version = version
            with socket.create_connection((host, port), timeout=timeout) as raw, \
                    context.wrap_socket(raw, server_hostname=host):
                accepted.append(name)
        except (ssl.SSLError, OSError, ValueError):
            continue
    return accepted


def is_private_host(host: str) -> bool:
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return False
    for info in infos:
        try:
            addr = ipaddress.ip_address(info[4][0])
        except ValueError:
            continue
        if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved:
            return True
    return False


class Engine:
    """A polite HTTP client. Every request is budgeted, spaced and recorded."""

    def __init__(self, cfg: Config, author: str = ""):
        self.cfg = cfg
        self.count = 0
        self.evidence: list[dict[str, Any]] = []
        self.exhausted = False
        self.aborted = False
        self.errors = 0
        contact = f"; contact {author}" if author else ""
        headers = {
            "User-Agent": f"vordr/0.1 (authorized API security assessment{contact})",
            "Accept": "application/json, text/plain, */*",
            "Accept-Encoding": "identity",
        }
        self.client = httpx.Client(
            verify=cfg.verify_tls,
            follow_redirects=False,
            timeout=httpx.Timeout(cfg.timeout, connect=min(10.0, cfg.timeout)),
            headers=headers,
            trust_env=False,
        )

    def close(self) -> None:
        self.client.close()

    @property
    def remaining(self) -> int:
        return max(0, self.cfg.max_requests - self.count)

    def request(
        self, method: str, url: str, *, note: str = "", headers: dict[str, str] | None = None,
        params: dict[str, str] | None = None, content: bytes | None = None,
    ) -> httpx.Response | None:
        if self.exhausted or self.aborted:
            return None
        if self.count >= self.cfg.max_requests:
            self.exhausted = True
            return None
        if self.cfg.delay_ms:
            time.sleep(self.cfg.delay_ms / 1000.0)

        started = time.monotonic()
        response: httpx.Response | None = None
        error = ""
        try:
            response = self.client.request(
                method, url, headers=headers, params=params, content=content,
            )
        except httpx.HTTPError as exc:
            error = type(exc).__name__ + (f": {exc}" if str(exc) else "")
            self.errors += 1

        self.count += 1
        elapsed = int((time.monotonic() - started) * 1000)
        self._record(method, url, note, response, error, elapsed)

        if response is not None and response.status_code == 429:
            self._respect_retry_after(response)
        if response is not None and response.status_code >= 500:
            self.errors += 1
            if self.errors >= 15:
                self.aborted = True
        return response

    def _respect_retry_after(self, response: httpx.Response) -> None:
        raw = response.headers.get("retry-after", "")
        try:
            wait = min(float(raw), 10.0)
        except (TypeError, ValueError):
            wait = 2.0
        if wait > 0:
            time.sleep(wait)

    def _record(
        self, method: str, url: str, note: str,
        response: httpx.Response | None, error: str, elapsed: int,
    ) -> None:
        entry: dict[str, Any] = {
            "ts": now_iso(),
            "method": method.upper(),
            "url": url,
            "note": note,
            "elapsed_ms": elapsed,
        }
        if response is None:
            entry.update({"error": error, "status": None})
        else:
            body = response.text or ""
            entry.update({
                "status": response.status_code,
                "headers": {
                    key: redact(value, 200)
                    for key, value in response.headers.items()
                    if key.lower() in EVIDENCE_HEADERS
                },
                "body_sha256": hashlib.sha256(body.encode("utf-8", "replace")).hexdigest(),
                "body_bytes": len(body.encode("utf-8", "replace")),
                "body_excerpt": redact(body, 600),
            })
        self.evidence.append(entry)


def check_scope(cfg: Config, hosts: list[str]) -> None:
    if not cfg.scope_ack:
        raise ScopeError(
            "authorization not acknowledged; re-run with --i-have-authorization "
            "or set scope_ack: true in the config"
        )
    allowed = {h.lower() for h in cfg.allow_hosts}
    for host in hosts:
        if host not in allowed:
            raise ScopeError(f"host {host} is not in --allow-hosts; refusing to send traffic")
        if is_private_host(host) and not cfg.allow_private:
            raise ScopeError(
                f"host {host} resolves to a private address; use --allow-private to override"
            )
