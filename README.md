# Vörðr

**Anonymous-boundary API security assessment.** Point it at an inventory of API
endpoints and it tells you, endpoint by endpoint, whether authentication is
actually enforced, whether transport is encrypted, what the host discloses to an
unauthenticated client — and, just as importantly, which controls it could not
test without credentials.

Named after the Old Norse *vörðr*: the warden, the cairn that marks and watches a
boundary.

```
======================================================
 > vordr.py - Pala ...................................
------------------------------------------------------
 Anonymous-boundary API security assessment
 OWASP API Security Top 10 (2023) mapped
======================================================

[*] Inventory: api-inventory.xlsx
[*]   sheet 'API Inventory': 148 row(s)
[*] Endpoints: 148 total, 96 testable
[*] Hosts: prod.api.example.com
[*] Profile: safe — GET, HEAD, OPTIONS only
[*] Budget: 800 requests, 120 ms apart
[*] Authorization acknowledged. Starting assessment.

------------------------------------------------------
[*] Global controls  https://prod.api.example.com
[+] TLS 1.3 (TLS_AES_256_GCM_SHA384), certificate valid, expires 2027-02-11
[+] HSTS present: max-age=31536000; includeSubDomains
[-] CORS reflects arbitrary Origin with credentials

[*] GET /v1/users
[+] auth enforced (HTTP 401, WWW-Authenticate: Bearer)
[+] forged credentials rejected
[+] proxy-header bypass rejected
[+] path normalization consistent (4 variants)

[*] GET /v1/admin/stats
[-] Anonymous access returned data (HTTP 200)
[!] Response carrying data is cacheable by intermediaries

[*] GET /v1/orders/{orderId} — skipped: unresolved identifier {orderId}
[*] POST /v1/users — skipped: write method POST (safe profile: GET/HEAD/OPTIONS only)

------------------------------------------------------
[!] Assessment of prod.api.example.com
[-] 4 high or critical finding(s)
[-] 12 finding(s) total from 412 request(s)
[!] 4 medium and 4 low observation(s)
[?] 13 endpoint(s) not tested (see report for reasons)
[ ] 5 OWASP categor(y/ies) not tested — no credentials
------------------------------------------------------
```

## What it is, and what it is not

Existing API scanners assume you can authenticate. Audits often start with nothing
but an endpoint list. Vörðr is built for that first phase: it measures the
**anonymous boundary** and refuses to pretend that it measured more.

| Checkable without credentials | Not checkable without credentials |
|---|---|
| Is authentication enforced on each endpoint? | Authorization (BOLA / BFLA) |
| Does a forged credential get past it? | Token lifetime, revocation, session management |
| Do proxy headers or path variants bypass it? | Data exposure behind authentication |
| Is transport encrypted? TLS version, cert, HSTS? | Mass assignment, injection, business logic |
| Is CORS permissive? | Encryption at rest, masking, audit logging |
| Are docs, `.env`, actuator endpoints exposed? | Key management |
| What do error responses disclose? | |
| Are rate-limit headers present? | Whether the quota is right for the business |

Every report states the unassessed categories explicitly, so a green result is
never mistaken for a clean bill of health.

## Safety model

This tool is designed to be safe to run against a production inventory. It is a
posture checker, not an exploit tool.

- **GET, HEAD and OPTIONS only.** `POST`, `PUT`, `PATCH` and `DELETE` are never
  sent in the default `safe` profile — not even with an empty body.
- **No request body is ever transmitted.** No uploads, no form data, no injected
  payloads.
- **`--dry-run` prints the whole request plan** — count, methods, hosts — so you
  can get sign-off before a single packet leaves the machine.
- **Hard request budget** (`--max-requests`, default 800) and a delay between
  requests (default 120 ms), sequential by default.
- **Scope fence.** Refuses to run without `--i-have-authorization`, refuses hosts
  not in `--allow-hosts`, and refuses hosts that resolve to private addresses
  unless `--allow-private` is set.
- **Backs off** on `429`/`Retry-After` and aborts after repeated `5xx`.
- **Rate-limit probing is opt-in.** It is the only check with real traffic
  weight, and it is capped and sequential.
- **Evidence is redacted on capture.** Emails, JWTs, bearer tokens and long digit
  sequences are replaced before anything is written to disk. Sensitive-field
  findings report field *names*, never values.

## Install

Python 3.10+ and three packages. **uv is not required** — it is one of several
ways to run the tool.

Plain Python:

```bash
git clone https://github.com/PAla46/vordr.git
cd vordr

python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt

./vordr.py --version
```

As a system command (`vordr`) instead of `./vordr.py`:

```bash
pip install .
vordr --version
```

With uv, if you happen to have it — nothing is installed permanently:

```bash
uv run vordr.py --version
```

Dependencies: `httpx`, `openpyxl`, `pyyaml`. They are declared in three places
so every runner agrees: `requirements.txt` (pip), `pyproject.toml` (installs and
the `vordr` entry point) and a PEP 723 block in `vordr.py` (uv only, ignored by
Python).

## Quick start

```bash
# 1. Create an inventory workbook to fill in
./vordr.py --make-template api-inventory.xlsx

# 2. See exactly what would be sent, without sending anything
./vordr.py https://api.example.com \
  -e api-inventory.xlsx --i-have-authorization --dry-run

# 3. Run the assessment
./vordr.py https://api.example.com \
  -e api-inventory.xlsx \
  --i-have-authorization \
  --author "Your Name"

# 4. Read the results
ls vordr-out/
```

If you installed with `pip install .`, substitute `vordr` for `./vordr.py`.

Outputs:

| File | Contents |
|---|---|
| `vordr-out/report.md` | The audit deliverable: findings with OBS ids, endpoint matrix, OWASP coverage, methodology |
| `vordr-out/report.xlsx` | Summary, Findings, Endpoint Matrix, OWASP Coverage, Evidence sheets |
| `vordr-out/findings.json` | Machine-readable, for CI or further tooling |
| `vordr-out/evidence.jsonl` | One record per request: status, headers, body hash, redacted excerpt |

## Inventory formats

There are four ways to tell Vörðr what to test, and they can be mixed:

```bash
-e inventory.xlsx                          # Excel inventory
-e endpoints.txt                           # plain text, one endpoint per line
-u /v1/users -u /v1/orders/{id}            # manual, repeatable, no file
cat endpoints.txt | ./vordr.py ...         # stdin (piped input is detected)
./vordr.py ...                             # no source: prompts you interactively
```

### From a file

`.xlsx`, `.csv` and `.txt` are accepted. Headers are matched fuzzily, so an
inventory does not need to be reformatted. Every `.xlsx` sheet is read unless
`--sheet` is given; sheets named `Legend`, `README`, `Cover` or `Instructions`
are ignored.

| Column | Aliases | Required | Purpose |
|---|---|---|---|
| Endpoint | Path, URL, URI, Route | yes | Path (`/v1/users`) or full URL |
| Method | Verb, HTTP Method | no | Defaults to `GET` |
| Service | App, System, Repo | no | Groups findings |
| PublicURL | BaseURL, IngressBaseURL, Host | no | Prefix for relative paths |
| Auth Required | RequiresAuth, Protected | no | Declared intent; `Yes` + observed `2xx` is **critical** |
| Public By Design | ExpectedPublic | no | Suppresses false positives on `/health`, `/login` |
| Authentication | AuthType, AuthScheme | no | Free text, reported |
| RateLimit | Throttle | no | Free text, reported |
| PIIFields | SensitiveFields | no | Free text, reported |
| Exposure | Scope, Visibility | no | Rows with no public URL are skipped |
| Description / Owner / Notes | | no | Copied into the report |

The `Auth Required` column is the highest-value field in the sheet. It lets the
tool distinguish *"serves data anonymously"* from *"serves data anonymously
despite the owner declaring authentication is required"* — the difference between
a high and a critical finding.

For a plain text list, one endpoint per line; the method prefix is optional and
comments are ignored:

```
GET /v1/users
GET /v1/products
/v1/health
# this line is ignored
```

### Manually, or by pasting

For a handful of endpoints there is no need to create a file:

```bash
./vordr.py https://api.example.com \
  --i-have-authorization \
  -u /v1/users \
  -u /v1/admin/stats \
  -u "/v1/orders/{id}" --param id=12345
```

Or paste a list — `--stdin`, or simply pipe into the tool:

```bash
./vordr.py https://api.example.com --i-have-authorization --stdin
```

```bash
cat <<'EOF' | ./vordr.py https://api.example.com --i-have-authorization
GET /v1/users
/v1/products
/v1/orders/{id}
EOF
```

Run it with no source at all on a terminal and it prompts, one endpoint per line,
finishing on an empty line or `Ctrl-D`:

```
[*] Enter endpoints one per line, for example /v1/users or GET /v1/orders/{id}
[*] Finish with an empty line, or Ctrl-D. Placeholders use --param NAME=VALUE.
endpoint> /v1/users
endpoint> /v1/admin/stats
endpoint>
```

Manual and file sources can be combined; duplicates are removed. Endpoints given
with `-u` may be paths (joined with the target/base URL) or absolute URLs.

Path placeholders (`{id}`, `:id`, `<id>`) are never requested literally. Supply
values with `--param id=123` or a `placeholders:` block; anything unresolved is
listed as skipped, with the reason.

## Checks

**Host level**

- TLS version, cipher suite, certificate validity, expiry and chain
- Plaintext HTTP availability and HTTPS redirect
- HSTS, `X-Content-Type-Options`, technology disclosure headers
- CORS: origin reflection, `null` origin, wildcard with credentials
- Documentation exposure: `/openapi.json`, `/swagger.json`, `/v3/api-docs`, `/docs`, `/redoc`
- Operational paths: `/.env`, `/.git/config`, `/actuator/env`, `/actuator/heapdump`, `/server-status`
- A non-existent-path baseline, so `404` can be interpreted correctly

**Per endpoint**

- Anonymous request: `401/403` (enforced), `2xx` (exposed), `404` (concealed), `5xx` (unhandled)
- `WWW-Authenticate` scheme; auth failure signalled in a `2xx` body
- Declared versus observed authentication
- Sensitive field names in anonymous JSON payloads
- `Cache-Control` on data-bearing responses
- Forged credentials: null bearer, random bearer, arbitrary `X-API-Key`
- Proxy/rewrite bypass: `X-Forwarded-For`, `X-Original-URL`, `X-Forwarded-Host`
- Path normalisation: trailing slash, case change, `//`, `/./`, `%2e`
- `OPTIONS` allow-list, `TRACE`
- Passive rate-limit headers; opt-in sequential burst
- Opt-in error-verbosity probe

## OWASP coverage

Findings map to the OWASP API Security Top 10 (2023), with CWE and ASVS ids in
`findings.json` and `report.xlsx`.

| OWASP | Coverage without credentials |
|---|---|
| API1 BOLA | not tested — needs two identities and real object ids |
| API2 Broken Authentication | partial — anonymous enforcement, forgery, header and path bypass |
| API3 BOPLA | partial — sensitive field names in anonymous payloads |
| API4 Unrestricted Resource Consumption | partial — rate-limit headers, opt-in burst |
| API5 BFLA | partial — anonymous access to function-level paths, method exposure |
| API6 Sensitive Business Flows | not tested — needs business context |
| API7 SSRF | not tested by design — requires injected payloads |
| API8 Security Misconfiguration | covered for the anonymous surface |
| API9 Improper Inventory Management | partial — docs exposure, versioning |
| API10 Third-party Consumption | not observable black-box |

## Getting real authorization coverage

The single most valuable thing to request before an engagement is **two
low-privilege accounts in the same role, belonging to different users or
tenants** — plus the OpenAPI specification. That converts the assessment from
boundary hygiene into BOLA/BFLA testing, which is where the serious API risk
actually lives. If the client cannot provide them, the report says so.

## Configuration file

`audit.yml`:

```yaml
target: https://api.example.com
endpoints_file: api-inventory.xlsx
scope_ack: true
profile: safe
safe:
  max_requests: 800
  delay_ms: 120
  timeout: 15
  allow_private: false
  rate_limit_probe: false
  error_probe: false
  weak_tls: false
allow_hosts:
  - api.example.com
placeholders:
  id: "12345"
  orderId: "A-1001"
expect_public:
  - "^/health"
  - "^/v1/auth/login"
checks:
  skip:
    - rate_limit
report:
  author: Your Name
  out_dir: vordr-out
```

CLI flags override the file.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | completed, no finding at or above `--fail-on` |
| 1 | a finding at or above `--fail-on` was reported |
| 2 | usage, inventory or scope error — nothing was sent |

CI example:

```bash
./vordr.py https://api.staging.example.com \
  -e api-inventory.xlsx --i-have-authorization \
  --fail-on high --no-color
```

## Development

```bash
git clone https://github.com/PAla46/vordr.git
cd vordr
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt ruff

ruff check vordr.py vordrlib tests
./tests/smoke.sh          # starts a deliberately weak local API and asserts findings
```

The smoke test uses the active interpreter when it already has the
dependencies, and falls back to `uv run` otherwise, so it works in either setup.

Branches: `main` is stable, `dev` is where work happens. CI runs on plain pip
against Python 3.10 and 3.12.

## License

MIT. See [LICENSE](LICENSE).

## Ethics

Only run Vörðr against systems you own or have written permission to assess. The
`--i-have-authorization` flag exists so that permission is an explicit,
recorded decision rather than an assumption. Rate-limit probing is off by
default because it is the one check that generates load.
