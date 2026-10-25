#!/usr/bin/env python3
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

Runs with plain Python once the three dependencies are installed:

    python3 -m pip install -r requirements.txt
    ./vordr.py --make-template endpoints.xlsx
    ./vordr.py https://api.example.com -e endpoints.xlsx --i-have-authorization

Endpoints can come from an Excel sheet, a text file, repeated --url flags, stdin,
or an interactive prompt when no source is given.

The PEP 723 block above is inert to Python and only read by ``uv``, so
``uv run vordr.py ...`` keeps working if you prefer that. uv is not required.

Named after the Old Norse *vörðr*: the warden, the cairn that marks and
watches a boundary.
"""

from __future__ import annotations

import sys

try:
    from vordrlib.cli import main
except ModuleNotFoundError as exc:  # pragma: no cover - startup guard
    missing = exc.name or str(exc)
    sys.stderr.write(
        f"vordr: missing dependency '{missing}'\n\n"
        "Install the dependencies first:\n"
        "    python3 -m pip install -r requirements.txt\n\n"
        "Or, if you have uv and prefer not to install anything:\n"
        "    uv run vordr.py --help\n"
    )
    sys.exit(2)

if __name__ == "__main__":
    sys.exit(main())
