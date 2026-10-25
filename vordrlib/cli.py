"""Command line interface and orchestration."""

from __future__ import annotations

import argparse
import sys
import time
from collections import Counter
from pathlib import Path
from typing import Any

import yaml

from .checks import Auditor
from .engine import Engine, ScopeError, check_scope
from .loader import InventoryError, load_endpoints, make_template
from .model import (
    SEVERITIES,
    VERSION,
    Config,
    Printer,
    color_enabled,
    host_of,
    scheme_of,
)
from .report import (
    assign_ids,
    coverage_rows,
    render_footer,
    summary_counts,
    write_evidence,
    write_json,
    write_markdown,
    write_xlsx,
)


def run() -> None:
    """Console-script entry point."""
    sys.exit(main())


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vordr.py",
        description="Vörðr — assess the anonymous security boundary of an API inventory. "
                    "Sends GET/HEAD/OPTIONS only and never transmits a request body.",
    )
    parser.add_argument("target", nargs="?", help="base URL, e.g. https://api.example.com")
    parser.add_argument("-e", "--endpoints", metavar="FILE",
                        help="inventory: .xlsx, .csv or .txt (one endpoint per line)")
    parser.add_argument("-c", "--config", metavar="FILE", help="YAML configuration file")
    parser.add_argument("-o", "--out", metavar="DIR", help="output directory (default: vordr-out)")
    parser.add_argument("--author", metavar="NAME", help="name shown in the banner and user agent")
    parser.add_argument("--profile", choices=("safe", "guarded"),
                        help="safe = GET/HEAD/OPTIONS only; guarded adds zero-length writes")
    parser.add_argument("--max-requests", type=int, metavar="N")
    parser.add_argument("--delay-ms", type=int, metavar="N")
    parser.add_argument("--timeout", type=float, metavar="S")
    parser.add_argument("--limit", type=int, metavar="N", help="only the first N endpoints")
    parser.add_argument("--service", metavar="SUBSTR", help="only endpoints whose service matches")
    parser.add_argument("--sheet", metavar="NAME", help="only this worksheet")
    parser.add_argument("--insecure", action="store_true", default=None,
                        help="do not verify TLS certificates when connecting")
    parser.add_argument("--i-have-authorization", action="store_true", default=None,
                        dest="scope_ack", help="confirm written authorization to test these hosts")
    parser.add_argument("--allow-hosts", metavar="HOST[,HOST]",
                        help="hosts that may be contacted (default: hosts in the inventory)")
    parser.add_argument("--allow-private", action="store_true", default=None,
                        help="allow hosts that resolve to private addresses")
    parser.add_argument("--include-internal", action="store_true", default=None,
                        help="keep internal-only rows in the report instead of skipping them")
    parser.add_argument("--rate-limit-probe", action="store_true", default=None,
                        help="opt-in: send a short sequential burst to look for 429 (default: off)")
    parser.add_argument("--rate-burst", type=int, metavar="N", help="burst size (default: 25)")
    parser.add_argument("--error-probe", action="store_true", default=None,
                        help="opt-in: send malformed query parameters to check error verbosity")
    parser.add_argument("--weak-tls", action="store_true", default=None,
                        help="additionally probe whether TLS 1.0/1.1 is accepted")
    parser.add_argument("--skip-checks", metavar="LIST", help="comma-separated check ids to skip")
    parser.add_argument("--param", action="append", metavar="NAME=VALUE", default=None,
                        help="value for a path placeholder such as {id} (repeatable)")
    parser.add_argument("--expect-public", metavar="SUBSTR[,SUBSTR]",
                        help="paths that are public by design")
    parser.add_argument("--dry-run", action="store_true", default=None,
                        help="print the request plan and send nothing")
    parser.add_argument("--fail-on", choices=SEVERITIES, metavar="SEVERITY",
                        help="exit 1 when a finding of this severity or worse exists")
    parser.add_argument("--verbose", action="store_true", default=None,
                        help="print a block for clean endpoints too")
    parser.add_argument("--no-color", action="store_true", default=None)
    parser.add_argument("--make-template", metavar="FILE",
                        help="write a blank inventory workbook and exit")
    parser.add_argument("--version", action="version", version=f"Vörðr {VERSION}")
    return parser


def _apply_yaml(cfg: Config, data: dict[str, Any]) -> None:
    safe = data.get("safe") or data.get("safety") or {}
    report = data.get("report") or {}
    checks = data.get("checks") or {}
    simple = {
        "target": data.get("target"),
        "endpoints_file": data.get("endpoints_file") or data.get("inventory"),
        "out_dir": report.get("out_dir") or data.get("out_dir"),
        "author": report.get("author") or data.get("author"),
        "profile": data.get("profile"),
        "scope_ack": data.get("scope_ack"),
        "fail_on": data.get("fail_on"),
    }
    for key, value in simple.items():
        if value is not None:
            setattr(cfg, key, value)
    numeric = {
        "max_requests": safe.get("max_requests") or data.get("max_requests"),
        "delay_ms": safe.get("delay_ms") if safe.get("delay_ms") is not None else data.get("delay_ms"),
        "timeout": safe.get("timeout") or data.get("timeout"),
        "rate_burst": safe.get("rate_burst") or data.get("rate_burst"),
        "limit": data.get("limit"),
    }
    for key, value in numeric.items():
        if value is not None:
            setattr(cfg, key, int(value) if key != "timeout" else float(value))
    flags = {
        "verify_tls": None if data.get("insecure") is None else not data.get("insecure"),
        "allow_private": safe.get("allow_private", data.get("allow_private")),
        "include_internal": safe.get("include_internal", data.get("include_internal")),
        "rate_probe": safe.get("rate_limit_probe", data.get("rate_limit_probe")),
        "error_probe": safe.get("error_probe", data.get("error_probe")),
        "weak_tls": safe.get("weak_tls", data.get("weak_tls")),
        "verbose": report.get("verbose", data.get("verbose")),
        "dry_run": data.get("dry_run"),
    }
    for key, value in flags.items():
        if value is not None:
            setattr(cfg, key, bool(value))
    if data.get("allow_hosts"):
        hosts = data["allow_hosts"]
        cfg.allow_hosts = [h.strip().lower() for h in hosts] if isinstance(hosts, list) else \
            [h.strip().lower() for h in str(hosts).split(",") if h.strip()]
    if data.get("placeholders"):
        cfg.placeholders = {str(k): str(v) for k, v in data["placeholders"].items()}
    if data.get("expect_public"):
        values = data["expect_public"]
        cfg.expect_public = list(values) if isinstance(values, list) else \
            [v.strip() for v in str(values).split(",") if v.strip()]
    if checks.get("skip"):
        values = checks["skip"]
        cfg.skip_checks = list(values) if isinstance(values, list) else \
            [v.strip() for v in str(values).split(",") if v.strip()]


def _config_from_args(args: argparse.Namespace) -> Config:
    cfg = Config()
    if args.config:
        path = Path(args.config).expanduser()
        if not path.exists():
            raise SystemExit(f"config not found: {path}")
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        if not isinstance(data, dict):
            raise SystemExit("config must be a YAML mapping")
        _apply_yaml(cfg, data)

    direct = {
        "target": args.target, "endpoints_file": args.endpoints,
        "out_dir": args.out, "author": args.author, "profile": args.profile,
        "max_requests": args.max_requests, "delay_ms": args.delay_ms,
        "timeout": args.timeout, "limit": args.limit, "service_filter": args.service,
        "sheet_filter": args.sheet, "rate_burst": args.rate_burst, "fail_on": args.fail_on,
    }
    for key, value in direct.items():
        if value is not None:
            setattr(cfg, key, value)
    flags = {
        "verify_tls": None if args.insecure is None else not args.insecure,
        "scope_ack": args.scope_ack, "allow_private": args.allow_private,
        "include_internal": args.include_internal, "rate_probe": args.rate_limit_probe,
        "error_probe": args.error_probe, "weak_tls": args.weak_tls,
        "dry_run": args.dry_run, "verbose": args.verbose,
    }
    for key, value in flags.items():
        if value is not None:
            setattr(cfg, key, value)
    if args.no_color:
        cfg.color = False
    if args.allow_hosts:
        cfg.allow_hosts = [h.strip().lower() for h in args.allow_hosts.split(",") if h.strip()]
    if args.skip_checks:
        cfg.skip_checks = [c.strip() for c in args.skip_checks.split(",") if c.strip()]
    if args.expect_public:
        cfg.expect_public = [p.strip() for p in args.expect_public.split(",") if p.strip()]
    for item in args.param or []:
        if "=" not in item:
            raise SystemExit(f"--param expects NAME=VALUE, got {item!r}")
        name, value = item.split("=", 1)
        cfg.placeholders[name] = value
    return cfg


def _print_plan(p: Printer, cfg: Config, endpoints: list, meta: dict) -> None:
    p.info("Dry run: no traffic will be sent")
    methods = Counter(e.method for e in endpoints if not e.skip_reason)
    if methods:
        p.info("Methods to send: " + ", ".join(f"{k} {v}" for k, v in sorted(methods.items())))
    estimates = 25 + meta["testable"] * (6 if cfg.rate_probe else 4)
    p.info(f"Estimated requests: ~{estimates} (hard cap {cfg.max_requests})")
    if meta["skipped"]:
        p.warn("Skipped rows:")
        for reason, count in meta["skipped"].most_common():
            p.skip(f"  {count:>4}  {reason}")
    p.rule()


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.make_template:
        path = Path(args.make_template).expanduser()
        make_template(path)
        print(f"[+] template written: {path}")
        return 0

    try:
        cfg = _config_from_args(args)
    except SystemExit as exc:
        print(exc, file=sys.stderr)
        return 2

    p = Printer(color=cfg.color and color_enabled(), verbose=cfg.verbose)
    p.header(cfg.author)

    if not cfg.endpoints_file:
        p.failed("no inventory supplied: use -e/--endpoints FILE")
        return 2
    try:
        endpoints, meta = load_endpoints(cfg)
    except InventoryError as exc:
        p.failed(str(exc))
        return 2

    hosts = meta.get("hosts", [])
    if not hosts:
        p.failed("no absolute endpoint URLs: supply a target base URL or a PublicURL column")
        return 2
    if not cfg.allow_hosts:
        cfg.allow_hosts = list(hosts)

    p.info(f"Inventory: {meta['file']}")
    for sheet in meta.get("sheets", []):
        p.info(f"  sheet {sheet['name']!r}: {sheet['rows']} row(s)")
    p.info(f"Endpoints: {meta['total']} total, {meta['testable']} testable")
    p.info(f"Hosts: {', '.join(hosts)}")
    p.info(f"Profile: {cfg.profile} — "
           f"{'GET, HEAD, OPTIONS only' if cfg.profile == 'safe' else 'GET, HEAD, OPTIONS + guarded writes'}")
    p.info(f"Budget: {cfg.max_requests} requests, {cfg.delay_ms} ms apart")
    if cfg.dry_run:
        _print_plan(p, cfg, endpoints, meta)
        return 0

    try:
        check_scope(cfg, hosts)
    except ScopeError as exc:
        p.failed(str(exc))
        return 2
    p.info("Authorization acknowledged. Starting assessment.")
    p.plain()

    started = time.strftime("%Y-%m-%dT%H:%M:%S%z")
    clock = time.monotonic()
    engine = Engine(cfg, author=cfg.author)
    auditor = Auditor(cfg, engine, p)
    first = next((e for e in endpoints if not e.skip_reason and e.url), None)
    if cfg.target:
        base = cfg.target
    elif first is not None:
        base = f"{scheme_of(first.url)}://{host_of(first.url)}"
    else:
        base = f"https://{hosts[0]}"
    if not base.startswith(("http://", "https://")):
        base = "https://" + base
    try:
        auditor.run_global(base)
        auditor.audit_all(endpoints)
    except KeyboardInterrupt:
        p.warn("interrupted; writing partial report")
    finally:
        elapsed = time.monotonic() - clock
        engine.close()

    findings = assign_ids(auditor.findings)
    executed = auditor.executed
    out_dir = Path(cfg.out_dir).expanduser()
    out_dir.mkdir(parents=True, exist_ok=True)
    paths = {
        "report.md": str(out_dir / "report.md"),
        "report.xlsx": str(out_dir / "report.xlsx"),
        "findings.json": str(out_dir / "findings.json"),
        "evidence.jsonl": str(out_dir / "evidence.jsonl"),
    }

    counts = summary_counts(findings, auditor.results, meta)
    payload = {
        "tool": "Vörðr",
        "version": VERSION,
        "generated": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "started": started,
        "duration_seconds": round(elapsed, 1),
        "target": cfg.target,
        "hosts": hosts,
        "inventory": meta["file"],
        "profile": cfg.profile,
        "requests_sent": engine.count,
        "scope": "anonymous boundary; no credentials supplied",
        "summary": counts,
        "findings": [
            {
                "id": f.obs_id, "severity": f.severity, "title": f.title,
                "endpoint": f.endpoint, "service": f.service, "sheet": f.sheet,
                "owasp": list(f.owasp), "cwe": f.cwe, "asvs": f.asvs,
                "evidence": f.evidence, "remediation": f.remediation, "note": f.detail,
            }
            for f in findings
        ],
        "endpoints": [
            {
                "service": r.endpoint.service, "method": r.endpoint.method,
                "path": r.endpoint.path, "url": r.endpoint.url,
                "skipped": r.skipped, "status": r.status,
                "auth_enforced": r.auth_enforced, "bypass": r.bypass,
                "worst": r.worst, "signals": [t for _, t in r.signals],
            }
            for r in auditor.results
        ],
        "coverage": coverage_rows(executed),
    }

    write_json(Path(paths["findings.json"]), payload)
    write_evidence(Path(paths["evidence.jsonl"]), engine.evidence)
    write_markdown(
        Path(paths["report.md"]), cfg=cfg, meta=meta, findings=findings,
        results=auditor.results, executed=executed, requests=engine.count,
        elapsed=elapsed, started=started,
    )
    write_xlsx(
        Path(paths["report.xlsx"]), cfg=cfg, meta=meta, findings=findings,
        results=auditor.results, executed=executed, requests=engine.count,
        elapsed=elapsed, started=started, evidence=engine.evidence,
    )

    render_footer(p, findings, auditor.results, meta, cfg, executed, engine.count, paths)

    if cfg.fail_on:
        threshold = SEVERITIES.index(cfg.fail_on)
        if any(SEVERITIES.index(f.severity) <= threshold for f in findings):
            return 1
    return 0
