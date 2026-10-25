"""Inventory import: .xlsx / .csv / .txt with fuzzy header matching."""

from __future__ import annotations

import csv
import re
from collections import Counter
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from openpyxl import Workbook, load_workbook
from openpyxl.styles import Alignment, Font, PatternFill
from openpyxl.utils import get_column_letter

from .model import (
    ALIAS_LOOKUP,
    SAFE_METHODS,
    WRITE_METHODS,
    Config,
    Endpoint,
    norm,
    placeholder_names,
    resolve_placeholders,
    scheme_of,
    truthy,
)

INTERNAL_RE = re.compile(r"(?i)internal|private|non-?public|back-?office|intranet")
TEMPLATE_HEADERS = (
    "Service", "Method", "Endpoint", "Auth Required", "Public By Design",
    "Description", "Owner", "Notes",
)


class InventoryError(RuntimeError):
    pass


def _header_map(cells: list[Any]) -> dict[str, int] | None:
    mapping: dict[str, int] = {}
    hits = 0
    for idx, cell in enumerate(cells):
        canon = ALIAS_LOOKUP.get(norm(cell))
        if canon:
            hits += 1
            mapping.setdefault(canon, idx)
    if hits >= 2:
        return mapping
    return None


def _guess_endpoint_column(rows: list[list[Any]]) -> int:
    width = max((len(r) for r in rows), default=0)
    best, best_score = 0, -1
    for idx in range(width):
        score = 0
        for row in rows[:40]:
            value = str(row[idx] or "") if idx < len(row) else ""
            if value.startswith(("/", "http")):
                score += 1
        if score > best_score:
            best, best_score = idx, score
    if best_score <= 0:
        raise InventoryError("no endpoint column found: expected a header such as 'Endpoint' or 'Path'")
    return best


def _cell(row: list[Any], idx: int | None) -> str:
    if idx is None or idx >= len(row):
        return ""
    value = row[idx]
    return "" if value is None else str(value).strip()


def _build_endpoint(
    *, sheet: str, row: list[Any], mapping: dict[str, int],
    default_row: int, cfg: Config,
) -> Endpoint | None:
    raw = _cell(row, mapping.get("endpoint"))
    method = (_cell(row, mapping.get("method")) or "GET").upper()
    if not raw and not _cell(row, mapping.get("service")):
        return None

    note = ""
    if method in {"ALL", "*", "ANY", "BOTH"}:
        method, note = "GET", "inventory method 'ALL'; tested GET only"
    if method == "WEBSOCKET" or method not in SAFE_METHODS | WRITE_METHODS:
        return Endpoint(
            method=method or "GET", path=raw, url="", sheet=sheet, row=default_row,
            skip_reason=f"unsupported method {method or '(blank)'}",
        )

    base = _cell(row, mapping.get("base_url"))
    if raw.startswith(("http://", "https://")):
        url = raw
        path = urlsplit(raw).path or "/"
    else:
        path = raw if raw.startswith("/") else ("/" + raw if raw else "")
        root = base if base.startswith(("http://", "https://")) else cfg.target
        url = (root.rstrip("/") + path) if root else ""

    exposure = _cell(row, mapping.get("exposure"))
    ep = Endpoint(
        method=method,
        path=path or "/",
        url=url,
        service=_cell(row, mapping.get("service")),
        sheet=sheet,
        exposure=exposure,
        description=_cell(row, mapping.get("description")),
        claimed_auth=_cell(row, mapping.get("auth_required")),
        claimed_auth_type=_cell(row, mapping.get("auth_type")),
        claimed_rate=_cell(row, mapping.get("rate_limit")),
        pii_fields=_cell(row, mapping.get("pii")),
        owner=_cell(row, mapping.get("owner")),
        public_by_design=truthy(_cell(row, mapping.get("public_by_design"))),
        row=default_row,
        note=note,
    )

    if scheme_of(ep.url) not in {"http", "https"}:
        ep.skip_reason = "no public URL (internal-only or missing base URL)"
        return ep

    names = placeholder_names(ep.path)
    if names:
        resolved, unresolved = resolve_placeholders(ep.path, cfg.placeholders)
        if unresolved:
            ep.skip_reason = "unresolved identifier " + ", ".join("{" + n + "}" for n in unresolved)
            return ep
        if ep.path in ep.url:
            ep.url = ep.url.replace(ep.path, resolved)
        ep.path = resolved

    if method in WRITE_METHODS and cfg.profile == "safe":
        ep.skip_reason = f"write method {method} (safe profile: GET/HEAD/OPTIONS only)"
    return ep


def _parse_xlsx(path: Path, cfg: Config) -> tuple[list[Endpoint], dict]:
    workbook = load_workbook(path, read_only=True, data_only=True)
    endpoints: list[Endpoint] = []
    sheets: list[dict] = []
    try:
        for sheet in workbook.worksheets:
            if cfg.sheet_filter and cfg.sheet_filter.lower() not in sheet.title.lower():
                continue
            if sheet.title.strip().lower() in {"legend", "readme", "cover", "instructions", "notes"}:
                continue
            rows = [list(r) for r in sheet.iter_rows(values_only=True)]
            if not rows:
                continue
            header_idx, mapping = None, None
            for probe in range(min(12, len(rows))):
                mapping = _header_map(rows[probe])
                if mapping and "endpoint" in mapping:
                    header_idx = probe
                    break
            if header_idx is None:
                try:
                    mapping = {"endpoint": _guess_endpoint_column(rows)}
                except InventoryError:
                    continue
                header_idx = -1
            if not mapping:
                continue
            data = rows[header_idx + 1:] if header_idx >= 0 else rows
            count = 0
            for offset, row in enumerate(data, start=header_idx + 2):
                ep = _build_endpoint(
                    sheet=sheet.title, row=row, mapping=mapping,
                    default_row=offset, cfg=cfg,
                )
                if ep is not None:
                    endpoints.append(ep)
                    count += 1
            sheets.append({"name": sheet.title, "rows": count, "header_row": header_idx + 1})
    finally:
        workbook.close()
    return endpoints, {"sheets": sheets}


def _parse_csv(path: Path, cfg: Config) -> tuple[list[Endpoint], dict]:
    with path.open(newline="", encoding="utf-8-sig") as handle:
        rows = list(csv.reader(handle))
    if not rows:
        return [], {"sheets": []}
    mapping = _header_map(rows[0])
    start = 1
    if not mapping:
        mapping = {"endpoint": _guess_endpoint_column(rows)}
        start = 0
    endpoints = []
    for offset, row in enumerate(rows[start:], start=start + 1):
        ep = _build_endpoint(sheet="csv", row=row, mapping=mapping, default_row=offset, cfg=cfg)
        if ep is not None:
            endpoints.append(ep)
    return endpoints, {"sheets": [{"name": "csv", "rows": len(endpoints), "header_row": start}]}


def _parse_text(path: Path, cfg: Config) -> tuple[list[Endpoint], dict]:
    endpoints = []
    for offset, line in enumerate(path.read_text(encoding="utf-8-sig").splitlines(), start=1):
        text = line.split("#", 1)[0].strip()
        if not text:
            continue
        parts = text.split()
        method = "GET"
        if len(parts) > 1 and parts[0].upper() in SAFE_METHODS | WRITE_METHODS:
            method = parts[0].upper()
            text = " ".join(parts[1:])
        ep = _build_endpoint(
            sheet="list", row=[text], mapping={"endpoint": 0},
            default_row=offset, cfg=cfg,
        )
        if ep is not None:
            ep.method = method
            if method in WRITE_METHODS and cfg.profile == "safe":
                ep.skip_reason = f"write method {method} (safe profile: GET/HEAD/OPTIONS only)"
            endpoints.append(ep)
    return endpoints, {"sheets": [{"name": "list", "rows": len(endpoints), "header_row": 0}]}


def load_endpoints(cfg: Config) -> tuple[list[Endpoint], dict]:
    path = Path(cfg.endpoints_file).expanduser()
    if not path.exists():
        raise InventoryError(f"inventory not found: {path}")
    suffix = path.suffix.lower()
    if suffix in {".xlsx", ".xlsm", ".xltx"}:
        endpoints, meta = _parse_xlsx(path, cfg)
    elif suffix in {".csv", ".tsv"}:
        endpoints, meta = _parse_csv(path, cfg)
    elif suffix in {".txt", ".list", ".lst", ""}:
        endpoints, meta = _parse_text(path, cfg)
    else:
        raise InventoryError(f"unsupported inventory type: {suffix} (use .xlsx, .csv or .txt)")

    if cfg.service_filter:
        needle = cfg.service_filter.lower()
        endpoints = [e for e in endpoints if needle in (e.service + " " + e.description).lower()]

    seen: set[tuple[str, str]] = set()
    unique: list[Endpoint] = []
    for ep in endpoints:
        key = (ep.method, ep.url or ep.path)
        if key in seen:
            continue
        seen.add(key)
        unique.append(ep)

    if cfg.limit:
        unique = unique[: cfg.limit]

    meta.update({
        "file": str(path),
        "total": len(unique),
        "testable": sum(1 for e in unique if not e.skip_reason),
        "skipped": Counter(
            re.sub(r"\{[^}]+\}|:\w+|<[^>]+>", "{…}", e.skip_reason)
            for e in unique if e.skip_reason
        ),
        "hosts": sorted({h for h in (urlsplit(e.url).netloc for e in unique if e.url) if h}),
    })
    return unique, meta


def make_template(path: Path) -> None:
    workbook = Workbook()
    sheet = workbook.active
    sheet.title = "Endpoints"
    header_fill = PatternFill("solid", fgColor="1F3864")
    for col, name in enumerate(TEMPLATE_HEADERS, start=1):
        cell = sheet.cell(row=1, column=col, value=name)
        cell.font = Font(bold=True, color="FFFFFF")
        cell.fill = header_fill
        cell.alignment = Alignment(vertical="center")
        sheet.column_dimensions[get_column_letter(col)].width = max(14, len(name) + 4)
    sheet.freeze_panes = "A2"
    sheet.auto_filter.ref = f"A1:{get_column_letter(len(TEMPLATE_HEADERS))}1"
    sheet.append([
        "catalogue-api", "GET", "/v1/products", "Yes", "No",
        "Product catalogue listing", "catalogue-team", "Replace with your inventory",
    ])
    sheet.append([
        "catalogue-api", "GET", "/health", "No", "Yes",
        "Liveness probe", "platform-team", "Expected public endpoint",
    ])

    legend = workbook.create_sheet("Legend")
    legend.column_dimensions["A"].width = 22
    legend.column_dimensions["B"].width = 76
    entries = [
        ("Column", "Meaning"),
        ("Service", "Owning service or application. Used to group findings."),
        ("Method", "HTTP verb. Only GET, HEAD and OPTIONS are ever sent."),
        ("Endpoint", "Path (/v1/users) or full URL. {id}-style placeholders must be resolvable."),
        ("Auth Required", "Yes/No as declared by the owner. Observed anonymous 2xx contradicts 'Yes'."),
        ("Public By Design", "Yes suppresses false positives on /health, /login, /metrics."),
        ("Description", "Free text, copied into the report."),
        ("Owner", "Team to route remediation to."),
        ("Notes", "Free text."),
        ("", ""),
        ("Safety", "Vörðr never sends POST/PUT/PATCH/DELETE in the default safe profile."),
    ]
    for row_idx, (key, value) in enumerate(entries, start=1):
        legend.cell(row=row_idx, column=1, value=key).font = Font(bold=True)
        legend.cell(row=row_idx, column=2, value=value).alignment = Alignment(wrap_text=True)
    workbook.save(path)
