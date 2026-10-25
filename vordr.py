#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.10"
# dependencies = [
#   "httpx>=0.27",
#   "openpyxl>=3.1",
#   "pyyaml>=6.0",
# ]
# ///
"""Vörðr — anonymous-boundary API security assessment.

Checks authentication enforcement, transport encryption, CORS, information
disclosure and (optionally) rate limiting across an API inventory, without
credentials and without sending a single request body.

    uv run vordr.py --make-template endpoints.xlsx
    uv run vordr.py https://api.example.com -e endpoints.xlsx --i-have-authorization

Named after the Old Norse *vörðr*: the warden, the cairn that marks and
watches a boundary.
"""

from __future__ import annotations

import sys

from vordrlib.cli import main

if __name__ == "__main__":
    sys.exit(main())
