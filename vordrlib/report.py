"""Report writers: terminal footer, Markdown, Excel, JSON and evidence log."""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any

from openpyxl import Workbook
from openpyxl.styles import Alignment, Border, Font, PatternFill, Side
from openpyxl.utils import get_column_letter

from .model import (
    CHECK_LABELS,
    OWASP,
    SEVERITIES,
    Config,
    EndpointResult,
    Finding,
    Printer,
    now_iso,
    short,
)

SEV_FILL = {
    "critical": "7B1FA2", "high": "C62828", "medium": "EF6C00",
    "low": "1565C0", "info": "616161",
}
HEADER_FILL = "1F3864"
STATUS_FILL = {"tested": "C8E6C9", "partial": "FFF9C4", "not tested": "E0E0E0"}


def assign_ids(findings: list[Finding]) -> list[Finding]:
    ordered = sorted(findings, key=lambda f: (f.rank, f.title, f.endpoint))
    width = max(2, len(str(len(ordered))))
    for index, finding in enumerate(ordered, start=1):
        finding.obs_id = f"OBS-{index:0{width}d}"
    return ordered


def coverage_rows(executed: set[str]) -> list[dict[str, str]]:
    rows = []
    for category in OWASP:
        checks = category["checks"]
        if not checks:
            status = "not tested"
        elif set(checks) <= executed:
            status = "tested"
        elif set(checks) & executed:
            status = "partial"
        else:
            status = "not tested"
        rows.append({
            "id": category["id"],
            "name": category["name"],
            "status": status,
            "checks": ", ".join(CHECK_LABELS.get(c, c) for c in checks) or "—",
            "why": category["why"],
        })
    return rows


def summary_counts(findings: list[Finding], results: list[EndpointResult], meta: dict) -> dict[str, Any]:
    counts = Counter(f.severity for f in findings)
    return {
        "critical": counts.get("critical", 0),
        "high": counts.get("high", 0),
        "medium": counts.get("medium", 0),
        "low": counts.get("low", 0),
        "info": counts.get("info", 0),
        "findings": len(findings),
        "endpoints": meta.get("total", 0),
        "testable": meta.get("testable", 0),
        "skipped": sum(1 for r in results if r.skipped),
        "auth_enforced": sum(1 for r in results if r.auth_enforced == "yes"),
        "anonymous_access": sum(1 for r in results if r.auth_enforced == "no"),
        "bypasses": sum(1 for r in results if r.bypass),
    }


def render_footer(
    printer: Printer, findings: list[Finding], results: list[EndpointResult],
    meta: dict, cfg: Config, executed: set[str], requests: int, paths: dict[str, str],
) -> None:
    counts = Counter(f.severity for f in findings)
    skipped = sum(1 for r in results if r.skipped)
    untested = sum(1 for row in coverage_rows(executed) if row["status"] == "not tested")
    critical_high = counts.get("critical", 0) + counts.get("high", 0)
    printer.rule()
    printer.warn(f"Assessment of {', '.join(meta.get('hosts', [])) or cfg.target}")
    if critical_high:
        printer.failed(f"{critical_high} high or critical finding(s)")
    else:
        printer.passed("no high or critical findings on the anonymous boundary")
    printer.failed(f"{len(findings)} finding(s) total from {requests} request(s)")
    if counts.get("medium") or counts.get("low"):
        printer.warn(f"{counts.get('medium', 0)} medium and {counts.get('low', 0)} low observation(s)")
    if skipped:
        printer.skip(f"{skipped} endpoint(s) not tested (see report for reasons)")
    printer.untested(f"{untested} OWASP categor(y/ies) not tested — no credentials")
    printer.rule()
    if counts.get("critical") or counts.get("high"):
        printer.bold(" Top findings")
        for finding in [f for f in findings if f.severity in {"critical", "high"}][:8]:
            printer.finding(finding.severity, f"{finding.obs_id}  {short(finding.title, 66)}")
        printer.rule()
    printer.plain(" " + "   ".join(f"[+] {name}" for name in paths.values()))
    printer.plain()


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")


def write_evidence(path: Path, evidence: list[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8") as handle:
        for entry in evidence:
            handle.write(json.dumps(entry, ensure_ascii=False) + "\n")


def _md(value: Any) -> str:
    return str(value or "").replace("|", "\\|").replace("\n", " ")


def write_markdown(path: Path, *, cfg: Config, meta: dict, findings: list[Finding],
                   results: list[EndpointResult], executed: set[str], requests: int,
                   elapsed: float, started: str) -> None:
    counts = summary_counts(findings, results, meta)
    coverage = coverage_rows(executed)
    lines: list[str] = []
    lines.append("# Vörðr — API security assessment\n")
    lines.append(f"**Generated:** {now_iso()}  ")
    lines.append(f"**Started:** {started}  ")
    lines.append(f"**Duration:** {elapsed:.1f}s  ")
    lines.append(f"**Target host(s):** {', '.join(meta.get('hosts', [])) or cfg.target}  ")
    lines.append(f"**Inventory:** `{meta.get('file', '')}`  ")
    lines.append("**Scope:** anonymous boundary, no credentials supplied  ")
    lines.append(f"**Profile:** `{cfg.profile}` — methods sent: "
                 f"{'GET, HEAD, OPTIONS' if cfg.profile == 'safe' else 'GET, HEAD, OPTIONS + writes'}  ")
    lines.append(f"**Requests sent:** {requests}\n")

    lines.append("## Executive summary\n")
    lines.append("| Severity | Count |")
    lines.append("|---|---|")
    for severity in SEVERITIES:
        lines.append(f"| {severity.capitalize()} | {counts[severity]} |")
    lines.append(f"| **Total** | **{counts['findings']}** |\n")

    lines.append("| Metric | Value |")
    lines.append("|---|---|")
    lines.append(f"| Endpoints in inventory | {counts['endpoints']} |")
    lines.append(f"| Endpoints tested | {counts['testable']} |")
    lines.append(f"| Endpoints skipped | {counts['skipped']} |")
    lines.append(f"| Authentication enforced (401/403) | {counts['auth_enforced']} |")
    lines.append(f"| Answered anonymously (2xx) | {counts['anonymous_access']} |")
    lines.append(f"| Confirmed bypasses | {counts['bypasses']} |\n")

    top = [f for f in findings if f.severity in {"critical", "high"}]
    if top:
        lines.append("### Top risks\n")
        for finding in top[:10]:
            lines.append(f"- **{finding.obs_id}** ({finding.severity}) {finding.title} — "
                         f"`{short(finding.endpoint, 60)}`")
        lines.append("")

    lines.append("## Findings\n")
    if not findings:
        lines.append("No findings were recorded for the anonymous boundary.\n")
    for finding in findings:
        lines.append(f"### {finding.obs_id} — {finding.title}\n")
        lines.append("| Field | Value |")
        lines.append("|---|---|")
        lines.append(f"| Severity | **{finding.severity.upper()}** |")
        lines.append(f"| Endpoint | `{_md(finding.endpoint)}` |")
        if finding.service:
            lines.append(f"| Service | {_md(finding.service)} |")
        if finding.owasp:
            lines.append(f"| OWASP API Top 10 | {', '.join(finding.owasp)} |")
        if finding.cwe:
            lines.append(f"| CWE | {finding.cwe} |")
        if finding.asvs:
            lines.append(f"| ASVS | {finding.asvs} |")
        lines.append(f"| Evidence | {_md(finding.evidence)} |")
        lines.append(f"| Remediation | {_md(finding.remediation)} |")
        if finding.detail:
            lines.append(f"| Note | {_md(finding.detail)} |")
        lines.append("")

    lines.append("## Endpoint matrix\n")
    lines.append("| Service | Method | Endpoint | Anon status | Auth enforced | Bypass | Worst | Signals |")
    lines.append("|---|---|---|---|---|---|---|---|")
    for result in results:
        ep = result.endpoint
        signals = "; ".join(text for _, text in result.signals[:2])
        lines.append(
            f"| {_md(ep.service)} | {ep.method} | `{_md(ep.path)}` | "
            f"{result.status if result.status is not None else '—'} | {result.auth_enforced} | "
            f"{'yes' if result.bypass else 'no'} | {result.worst or '—'} | {_md(short(signals, 60))} |"
        )
    lines.append("")

    lines.append("## OWASP API Security Top 10 (2023) coverage\n")
    lines.append("| ID | Category | Coverage | Implemented checks | Limitation |")
    lines.append("|---|---|---|---|---|")
    for row in coverage:
        lines.append(f"| {row['id']} | {row['name']} | {row['status']} | "
                     f"{_md(row['checks'])} | {_md(row['why'])} |")
    lines.append("")

    lines.append("## Methodology and limitations\n")
    lines.append(
        "Every endpoint was requested **without credentials**. That measures the anonymous "
        "boundary only: whether authentication is enforced at all, whether it can be bypassed "
        "with forged credentials, proxy headers or path normalization, and what the host "
        "discloses to an unauthenticated client.\n"
    )
    lines.append("Not assessed, and not to be read as \"passed\":\n")
    lines.append("- **Authorization (BOLA / BFLA)** — requires two authenticated "
                 "identities and real object IDs.")
    lines.append("- **Token quality, expiry, revocation, session management** — requires valid tokens.")
    lines.append("- **Data exposure behind authentication, mass assignment, injection,** "
                 "**business-logic abuse** — requires authenticated write operations.")
    lines.append("- **Encryption at rest, masking, audit logging, key management** — "
                 "server-side configuration, not observable over the wire.")
    lines.append("")
    lines.append("Safety: only GET, HEAD and OPTIONS were sent. No request body was transmitted. "
                 "Write operations were identified and deliberately skipped. "
                 f"The run was capped at {cfg.max_requests} requests with a {cfg.delay_ms} ms delay.\n")

    lines.append("## Evidence\n")
    lines.append("`evidence.jsonl` contains one record per request: timestamp, method, URL, status, "
                 "selected response headers, body SHA-256, body length and a redacted excerpt. "
                 "Email addresses, bearer tokens and long digit sequences are redacted on capture.\n")

    path.write_text("\n".join(lines), encoding="utf-8")


def _style_header(sheet: Any, headers: list[str], widths: list[int]) -> None:
    thin = Side(style="thin", color="D0D0D0")
    border = Border(left=thin, right=thin, top=thin, bottom=thin)
    for index, name in enumerate(headers, start=1):
        cell = sheet.cell(row=1, column=index, value=name)
        cell.font = Font(bold=True, color="FFFFFF")
        cell.fill = PatternFill("solid", fgColor=HEADER_FILL)
        cell.alignment = Alignment(vertical="center", wrap_text=True)
        cell.border = border
        sheet.column_dimensions[get_column_letter(index)].width = widths[index - 1]
    sheet.freeze_panes = "A2"
    sheet.auto_filter.ref = f"A1:{get_column_letter(len(headers))}1"
    sheet.row_dimensions[1].height = 26


def _append(sheet: Any, values: list[Any], fills: dict[int, str] | None = None) -> None:
    thin = Side(style="thin", color="E0E0E0")
    border = Border(left=thin, right=thin, top=thin, bottom=thin)
    sheet.append(values)
    row = sheet.max_row
    for index in range(1, len(values) + 1):
        cell = sheet.cell(row=row, column=index)
        cell.alignment = Alignment(vertical="top", wrap_text=True)
        cell.border = border
        if fills and index in fills:
            cell.fill = PatternFill("solid", fgColor=fills[index])
            cell.font = Font(bold=True, color="FFFFFF")


def write_xlsx(path: Path, *, cfg: Config, meta: dict, findings: list[Finding],
               results: list[EndpointResult], executed: set[str], requests: int,
               elapsed: float, started: str, evidence: list[dict[str, Any]]) -> None:
    counts = summary_counts(findings, results, meta)
    coverage = coverage_rows(executed)
    workbook = Workbook()

    summary = workbook.active
    summary.title = "Summary"
    summary.column_dimensions["A"].width = 30
    summary.column_dimensions["B"].width = 84
    rows = [
        ("Tool", "Vörðr 0.1.0"),
        ("Generated", now_iso()),
        ("Started", started),
        ("Duration (s)", f"{elapsed:.1f}"),
        ("Target host(s)", ", ".join(meta.get("hosts", [])) or cfg.target),
        ("Inventory", meta.get("file", "")),
        ("Sheets", ", ".join(f"{s['name']} ({s['rows']})" for s in meta.get("sheets", []))),
        ("Profile", cfg.profile),
        ("Scope", "anonymous boundary; no credentials supplied"),
        ("Requests sent", requests),
        ("Max requests", cfg.max_requests),
        ("Endpoints total", counts["endpoints"]),
        ("Endpoints tested", counts["testable"]),
        ("Endpoints skipped", counts["skipped"]),
        ("Authentication enforced", counts["auth_enforced"]),
        ("Answered anonymously", counts["anonymous_access"]),
        ("Confirmed bypasses", counts["bypasses"]),
        ("Findings total", counts["findings"]),
    ]
    for severity in SEVERITIES:
        rows.append((f"Findings — {severity}", counts[severity]))
    for key, value in rows:
        summary.append([key, value])
        summary.cell(row=summary.max_row, column=1).font = Font(bold=True)
        summary.cell(row=summary.max_row, column=2).alignment = Alignment(wrap_text=True, vertical="top")
    summary.append(["", ""])
    summary.append(["Not assessed", ("BOLA/BFLA, token quality, data exposure behind auth, "
                                    "injection, business logic, encryption at rest, logging.")])
    summary.cell(row=summary.max_row, column=2).alignment = Alignment(wrap_text=True)
    summary.cell(row=summary.max_row, column=1).font = Font(bold=True, color="C62828")

    sheet = workbook.create_sheet("Findings")
    headers = ["ID", "Severity", "Service", "Endpoint", "Title", "OWASP", "CWE", "ASVS",
               "Evidence", "Remediation", "Note"]
    _style_header(sheet, headers, [9, 11, 20, 34, 46, 20, 11, 12, 52, 52, 34])
    for finding in findings:
        _append(sheet, [
            finding.obs_id, finding.severity.upper(), finding.service, finding.endpoint,
            finding.title, ", ".join(finding.owasp), finding.cwe, finding.asvs,
            finding.evidence, finding.remediation, finding.detail,
        ], fills={2: SEV_FILL.get(finding.severity, "616161")})

    matrix = workbook.create_sheet("Endpoint Matrix")
    headers = ["Service", "Sheet", "Method", "Endpoint", "URL", "Exposure", "Declared Auth",
               "Anonymous Status", "Auth Enforced", "Bypass", "Worst", "Observations"]
    _style_header(matrix, headers, [20, 14, 9, 34, 44, 18, 16, 12, 16, 9, 10, 60])
    for result in results:
        ep = result.endpoint
        _append(matrix, [
            ep.service, ep.sheet, ep.method, ep.path, ep.url, ep.exposure,
            ep.claimed_auth, result.status if result.status is not None else "",
            result.auth_enforced, "yes" if result.bypass else "no", result.worst,
            "; ".join(text for _, text in result.signals),
        ])

    owasp_sheet = workbook.create_sheet("OWASP Coverage")
    headers = ["ID", "Category", "Coverage", "Implemented checks", "Limitation"]
    _style_header(owasp_sheet, headers, [12, 44, 13, 60, 56])
    for row in coverage:
        _append(owasp_sheet, [row["id"], row["name"], row["status"], row["checks"], row["why"]],
                fills={3: STATUS_FILL.get(row["status"], "E0E0E0")})
        cell = owasp_sheet.cell(row=owasp_sheet.max_row, column=3)
        cell.font = Font(bold=True, color="000000")

    evidence_sheet = workbook.create_sheet("Evidence")
    headers = ["Timestamp", "Method", "URL", "Note", "Status", "ms", "Body bytes", "Body excerpt"]
    _style_header(evidence_sheet, headers, [22, 8, 60, 24, 8, 8, 11, 70])
    for entry in evidence[:2000]:
        _append(evidence_sheet, [
            entry.get("ts"), entry.get("method"), entry.get("url"), entry.get("note"),
            entry.get("status"), entry.get("elapsed_ms"), entry.get("body_bytes"),
            entry.get("body_excerpt") or entry.get("error", ""),
        ])

    workbook.save(path)
