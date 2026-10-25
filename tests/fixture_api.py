#!/usr/bin/env python3
"""Deliberately weak local API used to exercise Vörðr end to end.

Never expose this on a public interface. It exists so that the tool's output
can be verified without touching a real system.

    python3 tests/fixture_api.py 8099
"""

from __future__ import annotations

import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PRODUCTS = [
    {"id": 1, "name": "Desk", "email": "buyer@example.com", "phone": "+15550100", "price": 120},
    {"id": 2, "name": "Lamp", "email": "buyer@example.com", "phone": "+15550101", "price": 40},
]


class Handler(BaseHTTPRequestHandler):
    server_version = "nginx/1.24.0"
    sys_version = ""

    def _send(self, status: int, body=None, headers: dict | None = None) -> None:
        payload = json.dumps(body).encode() if body is not None else b""
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Access-Control-Allow-Origin", self.headers.get("Origin", "*"))
        self.send_header("Access-Control-Allow-Credentials", "true")
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        if payload and self.command != "HEAD":
            self.wfile.write(payload)

    def do_GET(self) -> None:
        path = self.path.split("?", 1)[0].rstrip("/") or "/"
        if path == "/v1/users" or path == "/v1/orders/1":
            self._send(401, {"error": "unauthorized"}, {"WWW-Authenticate": "Bearer"})
        elif path == "/v1/products":
            self._send(200, PRODUCTS)
        elif path == "/v1/admin/stats":
            self._send(200, {"revenue": 99123, "users": 4412})
        elif path == "/health":
            self._send(200, {"status": "ok"})
        elif path == "/v1/leaky":
            self._send(500, {"error": "Traceback (most recent call last): boom"})
        elif path in {"/v1/users/", "/V1/users", "/v1//users"}:
            # The bug Vörðr is supposed to catch: a routing alias without the auth filter.
            self._send(200, [{"id": 9, "email": "leak@example.com"}])
        elif path == "/openapi.json":
            self._send(200, {"openapi": "3.0.0", "paths": {}})
        else:
            self._send(404, {"error": "not found"})

    def do_OPTIONS(self) -> None:
        self.send_response(200)
        self.send_header("Allow", "GET, OPTIONS, PUT, DELETE, TRACE")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_POST(self) -> None:
        self._send(401, {"error": "unauthorized"}, {"WWW-Authenticate": "Bearer"})

    def log_message(self, fmt: str, *args) -> None:
        sys.stderr.write("fixture: " + (fmt % args) + "\n")


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8099
    ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()
