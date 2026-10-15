# Clipeus — Domain Security Audit Tool

> ## ⚠️ Usage notice — scan only what you are authorised to scan
>
> **Only run Clipeus against domains, hosts and networks you own, or that you have
> explicit written permission to assess.** Unauthorised scanning may be illegal in
> your jurisdiction (e.g. computer-misuse and unauthorised-access laws) and may
> breach the terms of service of the hosts and providers involved.
>
> Know what each stage does before you run it:
>
> - **Enumeration is passive** — `recon/enum-bulk.sh` and `--subs-file` query public
>   sources (Certificate Transparency, passive-DNS aggregators) and resolve names.
> - **The audit is active** — it connects to every target: HTTP(S) requests, TLS
>   handshakes, a top-ports TCP scan by default (`--ports none` to disable), DNS zone
>   transfer (AXFR) attempts (`--no-axfr` to disable), and optional probes
>   (`--auth-paths`, `--cors`, `--origin`, `--banners`, `--jarm`).
> - **Third-party services** — CT, RDAP/WHOIS and DNS resolvers always see the names
>   you look up (`--no-rdap` / `--no-whois` to skip registration lookups). Opt-in only:
>   geo/ASN enrichment (`--geo`) sends target IPs to ip-api.com; `--auth-paths` sends
>   each apex to Microsoft's realm lookup (`login.microsoftonline.com`); Censys
>   (`--censys`) is metered and off by default.
> - **How it identifies itself** — page fetches to targets use a desktop Chrome
>   User-Agent (so it sees what real visitors see); registry/CT API calls identify as
>   `clipeus/<version>`. Tell the asset owner's security team what to expect.
> - **Evidence is sensitive** — `--raw-dir` saves full page bodies and response
>   headers, including `Set-Cookie` values. Treat it like any engagement data: keep it
>   local and confidential (`evidence/` is gitignored), and delete it when done.
>
> Scope your input list to the engagement, keep results confidential, and stop if
> you are unsure whether a target is in scope. You are responsible for how you use
> this tool.

`clipeus.py` takes a list of domains/hosts and produces a per-domain
security-posture report (config-issue focused, 125 columns: DNS, RDAP registration, TLS + cert detail,
HTTP, email auth, dangling/takeover risk, CDN, port exposure, favicon tech
fingerprinting, optional geo/ASN) with a rolled-up risk score.

Clipeus is built to be a **partner source in a recon/pentest pipeline** — it chains
with `subfinder`/`amass`/`httpx`/`nuclei` and feeds discoveries back into
enumeration, rather than being a standalone island.

See [ABOUT.md](ABOUT.md) for how and why Clipeus came about.

### About the name

**Clipeus** (*KLIP-ee-us*) is the Latin name for the large round shield of Greek
hoplites and early Roman soldiers. It's a cousin of the heraldic *escutcheon*, the
shield a coat of arms sits on, which comes from *scutum*, the Romans' other word for
a shield. That fits a tool for mapping and defending an organisation's brand estate:
the attack surface is the shield, and Clipeus shows where it has gaps.

It has **nothing to do with Microsoft's Clippy**, the paperclip assistant from Office.
Similar-sounding, entirely unrelated, and Clipeus will never ask whether you're
trying to write a letter.

## Requirements

- **Python 3.9+** (developed against 3.12)

| Package        | Required?   | Used for                                   |
|----------------|-------------|--------------------------------------------|
| `requests`     | **Required**| HTTP(S) probing, favicon, geo, harvest     |
| `dnspython`    | **Required**| A/AAAA/CNAME/NS/TXT/MX/SOA/CAA, AXFR, wildcard |
| `idna`         | Recommended | IDN/punycode host normalization (stdlib fallback) |
| `cryptography` | Optional    | TLS cert subject/issuer/expiry **and SANs** |
| `urllib3`      | with requests | Retry logic + warning suppression        |

No `aiohttp` and no `mmh3`: HTTP concurrency is a thread pool, and the
Shodan-style favicon MurmurHash3 is a bundled pure-Python implementation
(validated against `mmh3` vectors — run `python3 clipeus.py --selftest`).

**Optional external tool:** `--jarm` shells out to a real JARM CLI if one is on
`PATH` — `pyjarm` (preferred, `pip install pyjarm`, CLI `pyjarm <host>`) or the
`jarm` binary. We do **not** reimplement JARM, so fingerprints match canonical
JARM exactly; without the tool the column reads `N/A (no jarm)`.

### Install (recommended: project venv)

A virtualenv with every dependency (including `cryptography` and `pyjarm`) is the
supported setup:

```bash
cd Clipeus
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
```

Then run via the `./clipeus` wrapper (execs `clipeus.py` with the repo venv), or call `python3 clipeus.py` directly
so `--jarm` works automatically:

```bash
./clipeus --input hosts.txt --output out.csv --jarm
subfinder -dL scope.txt -silent | ./clipeus --format jsonl --output -
```

Or call the venv Python directly: `.venv/bin/python clipeus.py ...`.

Minimal install without the optionals (no cert SANs, no JARM):

```bash
pip install requests dnspython
```

`requirements.txt` pins the full set (`requests`, `dnspython`, `idna`,
`cryptography`, `pyjarm`, and their transitive deps).

## Pipeline usage (the core design)

```bash
# Chain straight off subfinder; stream JSONL for the next tool
subfinder -dL scope.txt -silent | python3 clipeus.py --format jsonl --output - \
    | jq -r 'select(.risk_score > 40) | .domain'

# Probe, and emit a clean live-URL feed for nuclei (report still goes to a file)
python3 clipeus.py --input hosts.txt --output audit.csv \
    --emit urls --emit-file live_urls.txt
nuclei -l live_urls.txt

# Close the enumeration loop: emit newly-discovered domains (cert SANs +
# external CNAME targets) back into your enum set
python3 clipeus.py --input hosts.txt --output audit.csv \
    --emit new-domains --emit-file discovered.txt
cat discovered.txt | anew all_scope.txt        # feed back to subfinder/amass

# Share a resolver set with the rest of the pipeline (write the effective set once,
# then hand the same file to clipeus, dnsx, puredns, ...)
python3 brand_config.py --resolvers > resolvers.txt
python3 clipeus.py --input hosts.txt --output audit.csv --resolvers resolvers.txt
```

Input is one host per line (or stdin via `--input -`, the default); `#` comments
and blanks are ignored; schemes/paths/ports/`user@` are stripped, IDNs are
punycode-encoded, and duplicates removed. Progress goes to **stderr**, so stdout
stays clean for piping.

### `--emit` categories

| Category      | Emits |
|---------------|-------|
| `urls`        | final resolved URL of each live host |
| `live`        | domains answering `200` on HTTP or HTTPS |
| `open-ports`  | `domain:port` for each open port |
| `takeover`    | domains flagged takeover Yes/Possibly |
| `sans`        | every hostname from certificate SANs |
| `new-domains` | SANs + external CNAME targets (loop-back enum feed) |

`--emit` is repeatable and writes a **deduplicated** stream to stdout (or
`--emit-file`). If both `--emit` and `--output` target stdout the run refuses to
start — send one to a file.

## Full audit usage

```bash
python3 clipeus.py --input domains.txt --output results.csv
python3 clipeus.py --input domains.txt --output results.json --format json --ports full
python3 clipeus.py --input big.txt --output big.jsonl --format jsonl \
    --workers 60 --rate 20 --jitter 0.3 --banners --harvest --jarm
# resumable: re-run the same command with --resume after an interruption
```

### Options

| Flag | Default | Description |
|------|---------|-------------|
| `--input` | `-` (stdin) | Domains file, or `-` for stdin |
| `--output` | `-` (stdout) | Output path, or `-` for stdout |
| `--format` | `csv` | `csv`, `json`, or `jsonl` (streaming) |
| `--workers` | `30` | Concurrent domains |
| `--timeout` | `8.0` | HTTP timeout (seconds) |
| `--rate` | `0` (off) | Global max external requests/sec |
| `--jitter` | `0` | Random 0..N s delay before each domain |
| `--ports` | `top` | `none`, `top` (~30), `standard` (1-1024+), `full` |
| `--ports-behind-cdn` | off | Port-scan even when a CDN/WAF is detected (default skips) |
| `--banners` | off | Grab TCP banners on open ports |
| `--harvest` | off | Harvest robots.txt / sitemap.xml / security.txt |
| `--jarm` | off | Real JARM via external `jarm` tool |
| `--ocsp` | off | OCSP stapling check via the `openssl` CLI (one extra handshake per host) |
| `--origin` | off | For CDN-fronted hosts, look for a directly reachable origin IP (see below) |
| `--auth-paths` | off | Probe ~23 login/reset paths per host and look up the apex's Microsoft 365 realm |
| `--dkim` | off | Probe common DKIM selectors; flag keys under 2048 bits |
| `--cors` | off | One extra GET per live host with a foreign `Origin`; flags reflected / null / credentialed CORS |
| `--no-spf-chain` | off | Skip the recursive SPF include-chain walk |
| `--no-email-hardening` | off | Skip the MTA-STS / TLS-RPT / BIMI / DANE checks |
| `--takeover-sigs FILE` | — | Extra takeover fingerprints (`can-i-take-over-xyz` `fingerprints.json` format) |
| `--ingest FILE` | — | nuclei (`-jsonl`) / httpx (`-json`) results to fold into the records (repeatable; file parsing only) |
| `--merge-out FILE` | — | With `--report-from` + `--ingest`: write the re-scored results here |
| `--baseline FILE` | — | Previous results (csv/json/jsonl); report what changed after the run |
| `--diff-out FILE` | stderr | Write the diff here (`.json` = JSON, otherwise Markdown) |
| `--report-html FILE` | — | Write a self-contained HTML report (needs `--output FILE`) |
| `--report-from FILE` | — | Skip the audit; build `--report-html` / `--baseline` diff from an existing results file |
| `--resolvers` | shared lookup | File of resolver IPs (one per line; bad lines are an error) |
| `--org-networks` | config `org_networks` | File of org CIDRs to tag as first-party (none ship in the code) |
| `--geo` | off | Opt in to ip-api.com geo/ASN lookups — sends each resolved IP to a third party over plain HTTP; off keeps engagement IPs private (`asn`/`country`/`city` = N/A, no ASN-based CDN detection) |
| `--no-axfr` | off | Skip AXFR zone-transfer checks |
| `--no-rdap` | off | Skip RDAP registration lookups |
| `--no-whois` | off | Skip the port-43 WHOIS fallback (used for `.ch` etc. where RDAP is empty) |
| `--subs-file FILE` | — | Enumerate subdomains (subfinder + crt.sh + Censys) into FILE, then audit them |
| `--no-ct` | off | Disable crt.sh CT enumeration |
| `--censys` | off (opt-in) | Enable Censys hosts-index enumeration (metered/credit-limited) |
| `--no-censys` | — | Force Censys off even if `--censys` is given |
| `--censys-max N` | `0` (no cap) | Stop calling Censys after N API calls in this run |
| `--ct-tld TLD` | — | Sweep an entire brand TLD via CT + Censys, e.g. `--ct-tld brand` (repeatable) |
| `--config FILE` | auto | Brand/engagement config (`$CLIPEUS_CONFIG`, `brand.json`, `~/.config/clipeus/brand.json`); see `brand.example.json` |
| `--approved-mx` | *(from config)* | Approved MX domains; others flag `independent-mail`. Unset = mail policy not checked |
| `--approved-redirect` | *(from config)* | Approved redirect targets; others flag `redirect-offsite`. Unset = redirect policy not checked |
| `--accurate` | off | Favor accuracy over speed: low concurrency, long timeouts, DNS retries |
| `--log FILE` | — | Append live progress here (`tail -f` friendly) |
| `--raw` | off | Embed a nested `raw` object per record (JSON/JSONL only) |
| `--raw-dir DIR` | — | Dump per-host evidence files (body/headers/cert/dns/rdap) |
| `--emit` | — | Feed for the next tool (repeatable; see table) |
| `--emit-file` | stdout | Write the `--emit` feed here |
| `--resume` | off | Skip domains already in `--output` |
| `--checkpoint-interval` | `50` | (json only) flush partial results every N |
| `--quiet` | off | Suppress per-domain progress lines |
| `--selftest` | — | Run internal checks and exit |

## Config-issue auditing

Built for finding **fixable misconfigurations** across a brand's domain inventory
and spotting off-policy domains. Each record gets:

- **`disposition`** — `dead-dns` / `dead-nohttp` / `dangling` / `redirect-approved`
  / `redirect-self` / `redirect-offsite` / `live` / `responding`. Finds dead and
  strangely-directed domains at a glance.
- **`config_issues`** — a single actionable list per domain: `no-dns-resolution`,
  `cert-hostname-mismatch`, `legacy-tls`, `spf-missing`, `dmarc-missing`,
  `caa-missing`, `hsts-missing`, `independent-MX(...)`, `redirects-offsite(...)`,
  `dangling/takeover`, `axfr-open`, `cert-expiring(Nd)`, …
- **`independent_mail` / `service_independent`** — domains running their own mail
  (MX not under `--approved-mx`) or a live service not redirecting to the approved
  domain — i.e. working, non-core services worth reviewing.
- **`.ch` (and other RDAP-less TLDs)** fall back to a raw port-43 WHOIS query
  (SWITCH `whois.nic.ch`, IANA referral for others) so registrar still resolves.

```bash
# Full config audit with subdomain enumeration + a brand-TLD sweep,
# accurate mode, tailable log:
./clipeus --input domains.txt --output audit.jsonl --format jsonl \
    --subs-file /tmp/subdomains.txt --ct-tld brand \
    --accurate --log /tmp/scan.log --raw --raw-dir /tmp/evidence
tail -f /tmp/scan.log
```

### Subdomain enumeration & CT / Censys

`--subs-file` runs a pre-pass that discovers subdomains via **subfinder** (batch)
plus **certificate transparency** — crt.sh when reachable, and the **Censys** hosts
index as a fallback/supplement (reads the key from
`~/.config/subfinder/provider-config.yaml`, or `CENSYS_API_ID`/`CENSYS_API_SECRET`).
Discovered subdomains are written live to the file **and folded into the audit**.
**Censys limits.** Each in-scope registrable domain (and each `--ct-tld`) costs one call to the
legacy Search v2 `hosts/aggregate` endpoint, with up to 3 retries on HTTP 429 (every attempt counts
as a call). Use `--censys-max N` to stop after N calls — the run logs the total, and Censys is then
skipped for the rest of the run. HTTP 401/402/403/410 (rejected key, exhausted credits, or the legacy API no longer
offered to the account) disables Censys for the run immediately with one warning instead of one
per domain. **Censys is opt-in:** it runs only when you pass `--censys` (credentials alone no longer
enable it), because the current Censys plans are credit-limited. For mass runs leave it off and
run a separate `--censys` pass over just the apex domains, bounded with `--censys-max`. The code still targets the legacy endpoint; moving to Censys's current platform API is
pending confirmation of its endpoint, auth and quota.

`--ct-tld brand` sweeps an entire brand gTLD — the only practical way to enumerate
`*.brand`, since there's no zone transfer or brute-forceable namespace.

## TLS hygiene & HSTS

Taken from the certificate and HTTPS response already fetched, so no extra requests:

- **`hsts_max_age` / `hsts_flags`** — parsed from the *HTTPS* response (browsers ignore
  HSTS over plain HTTP). Issues: `hsts-short-maxage(N)` (< 180 days),
  `hsts-invalid-maxage`.
- **`cert_key`** (`RSA-2048`, `EC-secp256r1`, …) → `cert-weak-key(...)` below 2048 bits.
- **`cert_sig_alg`** (signature hash) → `cert-weak-signature(sha1|md5)`.
- **`cert_sct_count`** — embedded Certificate Transparency SCTs (informational; SCTs can
  also arrive via TLS extension or OCSP, so a `0` is not flagged).
- **`cert_revocation`** — which of `ocsp` / `crl` endpoints the cert advertises, or `none`.
  The CRL is not downloaded; this records what the cert points to.
- **`--ocsp`** adds `tls_ocsp_stapling` (`stapled(good|revoked|unknown)` / `not-stapled`)
  using `openssl s_client -status`, since the stdlib `ssl` module cannot read staples.
  Issues: `ocsp-stapling-missing` (only when the cert advertises OCSP),
  `cert-revoked(ocsp)`.

## Exposed services, cookies, email transport

- **Exposed services** — open ports are now scored and listed. `PORT_RISK` maps ports to a
  severity (critical 25 pts: telnet, SMB, Docker API; high 15: FTP, NFS, ZooKeeper, MSSQL,
  Oracle, MySQL, RDP, Postgres, VNC, WinRM, Redis, Elasticsearch, Memcached, MongoDB;
  medium 8: cleartext POP3/IMAP, MQTT, Docker TLS, Webmin), capped at 40 total. Each shows up
  as `exposed-<service>(<port>)` in `config_issues`. 11211 and 27017 joined the default port
  list. Ports are still skipped behind a CDN unless `--ports-behind-cdn`.
- **Cookie flags** — `cookie_flags` lists each cookie as `name(!Secure,HttpOnly,SameSite=Lax)`
  (`!` = missing), read from every `Set-Cookie` in the redirect chain. Issues:
  `cookie-no-secure(...)` (set over HTTPS without `Secure`) and
  `session-cookie-no-httponly(...)` (names matching `sess|sid|token|auth|jwt|login|sso`).
- **Email transport** (domains with a real MX; null MX `0 .` is treated as "no mail"):
  `mta_sts` (`absent` / `enforce` / `testing` / `mode-none` / `policy-unreachable` /
  `policy-invalid` — the policy file is fetched), `tls_rpt`, `bimi`, and `dane` (TLSA on the
  first three MX hosts, only when DNSSEC is on). Issues: `mta-sts-missing`,
  `mta-sts-not-enforced(...)`, `mta-sts-policy-broken(...)`. `--dkim` probes
  common selectors (selectors are arbitrary, so "none found" proves nothing) and reports
  `dkim_selectors` plus `dkim-key-under-2048(sel:bits)`.

## SPF chain, header quality, CORS, security.txt

- **SPF include chain** (default; DNS only, cached, ≤30 queries per domain, `--no-spf-chain` to
  skip). `spf_lookups` is the RFC 7208 lookup count across the whole `include:`/`redirect=`
  chain (the old check only counted top-level tokens). `spf_chain_issues` →
  `spf-lookup-limit(N)` (> 10 means SPF fails outright), `spf-include-unregistered(domain)`
  (the included domain's registrable name is NXDOMAIN — anyone can register it and authorise
  senders; +25 risk), `spf-include-no-record(host)`, `spf-include-loop(host)`,
  `spf-broad-range(cidr)` (the domain's own `ip4` ≤ /16 or `ip6` ≤ /32).
- **Header quality** (from the response already fetched): `csp_issues` →
  `csp-unsafe-inline` (ignored when a nonce/hash is present), `csp-unsafe-eval`,
  `csp-wildcard-script-src`, `csp-no-script-restriction`, `csp-report-only`;
  `frame_protection` (`csp`/`xfo`/`both`/`none`) → `clickjacking-unprotected` on HTML pages;
  `version_disclosure` → `server-version-disclosed(...)` for `Server`/`X-Powered-By` banners
  with version numbers.
- **`--cors`** sends one GET with `Origin: https://cors-probe.invalid` (redirects not followed)
  and records `cors`: `none`, `restricted`, `wildcard`, `reflects-origin`, `null-origin`, each
  possibly `+credentials`. Issues: `cors-reflects-origin`, `cors-null-origin`, and the
  credentialed variants (+25 risk). A bare `*` is recorded but not flagged.
- **`security.txt`** (with `--harvest`): `security_txt` = `valid` / `expired` / `no-contact` /
  `no-expires` / `missing` per RFC 9116; a soft-404 HTML page is not mistaken for one.
  Issues: `security-txt-expired`, `security-txt-invalid(...)`.
- **New `--emit` feeds:** `origins` (candidate IPs), `exposed` (`domain:port` for risky services),
  `auth-urls` (login/reset URLs found by `--auth-paths`).

## Auth surface (`--auth-paths`)

Probes the host's own login and password-reset paths (`/login`, `/admin`, `/wp-login.php`,
`/forgot-password`, …). **Redirects are not followed**, so no third-party host is contacted;
an external `Location` is recorded in `auth_sso` instead. A page counts only if it returns
200, differs from a random-path "not found" baseline (so catch-all hosts do not flood the
results), and contains a password field (login) or reset text plus an email/text input
(reset). `auth_pages` lists what was found; `admin-login-exposed(...)` is raised for
`/admin*` and `/wp-login*` (+10 risk). For the registrable apex only, `m365_realm`
(`Managed` / `Federated(host)`) comes from Microsoft's public `getuserrealm` endpoint, which
means the domain name is sent to Microsoft. It adds ~24 requests per host; use `--rate`.

## Ingesting nuclei / httpx results (`--ingest`)

Clipeus does no vulnerability scanning itself; this folds the output of tools you ran separately
into the same records, risk score and report. It only **reads files** — no network access.

```bash
# during an audit: results for hosts in this run are attached as they are processed
./clipeus --input hosts.txt --output audit.jsonl --format jsonl --ingest nuclei.jsonl --ingest httpx.json
# after the fact: re-score an existing results file (config_issues + risk are recomputed)
./clipeus --report-from audit.jsonl --ingest nuclei.jsonl --merge-out audit-merged.jsonl --report-html report.html
```

Records are matched by hostname, or by IP against the host's A records. New columns:
`scanner_findings` (`severity:template-id`, worst first, ≤ 10 shown then `+N`),
`scanner_max_severity`, `httpx_tech`. Medium-and-above findings become
`nuclei-<severity>(<template-id>)` issues; risk points are critical +30 / high +20 /
medium +10, capped at 50 (low and info are listed but not scored). Input is untrusted: template
ids are reduced to a safe character set, lines that are malformed or carry an unknown severity
are skipped (and counted on stderr), and a JSON array is accepted as well as JSONL.
Merge re-runs the classifier on the stored fields, so it works best on full Clipeus output.

## Baseline diff & HTML report

```bash
./clipeus --input domains.txt --output 2026-10.jsonl --format jsonl \
      --baseline 2026-09.jsonl --diff-out changes.md --report-html report.html
./clipeus --report-from 2026-10.jsonl --baseline 2026-09.jsonl --report-html report.html   # no scan
```

The diff is keyed by domain and reports new domains, domains missing from this run (removed
**or** an incomplete run), issues gained and resolved, changes to `disposition`,
`takeover_risk`, `dangling_status`, `origin_exposed`, `ports`, `cert_sha256`, `tls_valid`,
`ns_servers` and `mx_records`, and risk moves of 10 points or more. The HTML report is one
self-contained file (inline CSS/JS, no network, strict CSP, every value HTML-escaped):
summary cards, disposition and common-issue charts, the 25 highest-risk hosts, and a
filterable, sortable table (capped at the 5000 highest-risk rows).

## Takeover fingerprints

`TAKEOVER_PROVIDERS` now includes the `Vulnerable` entries of the community
[can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz) list that have a
hostname CNAME and a plain-text fingerprint. To pick up newer entries without editing code,
download its `fingerprints.json` and pass it with `--takeover-sigs`. Entries needing a regex
or an HTTP-status match are skipped. Body matching now HTML-unescapes first (`&#39;`).
Elastic Beanstalk moved to the NXDOMAIN-only class (a live app's 404 is no longer flagged).

## Origin discovery (`--origin`)

Port scanning is skipped behind a CDN, so a directly reachable origin would otherwise go
unnoticed. For hosts where a CDN/WAF was detected, `--origin` gathers candidate IPs from:

| Source | Weight | Notes |
|--------|--------|-------|
| IP-bearing response headers (`X-Real-IP`, `X-Forwarded-For`, `Via`, …) | 8 | already fetched; no extra requests |
| Cert SAN names under the same registrable domain, resolved | 6 | |
| MX hosts under the same registrable domain, resolved | 4 | third-party mail providers are ignored |

Candidates are dropped if they are private/reserved, one of the host's own edge IPs, in a
published Cloudflare range, or (with `--geo`) in a known CDN ASN. Survivors get a bonus
for each extra agreeing source (+5), for answering on 443/80 (+5), and for presenting the
**same certificate** as the edge when a TLS handshake is made with the host's SNI (+20).
Only a handshake is made — no HTTP request is sent to the candidate. Candidates scoring
under 10 are discarded.

Output: `origin_candidates` (`ip(score=N;methods=a+b[;cert-match])`) and `origin_exposed`:
`Yes` (cert match → `origin-ip-exposed(ip)`, +25 risk), `Possibly`
(`possible-origin-exposure`, +10), or `No`. Treat `Possibly` as a lead to verify, not a finding.

## Raw output & evidence

Two independent modes:

- **`--raw`** (JSON/JSONL only) embeds a nested `raw` object in each record: full
  HTTP/HTTPS response headers, all DNS answer sets, the certificate PEM, and the
  raw RDAP JSON. The large HTML body is *not* inlined (use `--raw-dir` for that).
- **`--raw-dir DIR`** writes a per-host evidence folder — `body.html`,
  `headers.json`, `cert.pem`, `dns.json`, `rdap.json`, `meta.json` — for keeping
  the underlying proof behind every finding.

```bash
./clipeus --input hosts.txt --output audit.jsonl --format jsonl --raw --raw-dir evidence/
```

## What it checks

- **DNS** — A/AAAA (**all A records**), CNAME chain (cycle-safe), NS (hierarchy
  walk), MX, SOA, CAA, **PTR/reverse DNS**, **DNSSEC**, high-entropy TXT tokens;
  **failure modes split** (OK/NXDOMAIN/NOANSWER/SERVFAIL/TIMEOUT); **wildcard-zone
  detection** so wildcards don't create phantom hosts.
- **Registration (RDAP)** — registrar, creation/expiry dates, **domain age in
  days**, and status codes (`clientHold`, `pendingDelete`, …) over plain HTTPS,
  no dependency. The standout signal for freshly-registered look-alikes.
- **Email auth** — SPF and DMARC parsing (policy strength, lookups, `pct`, `rua`),
  with one-level parent DMARC inheritance.
- **Dangling / takeover** — CNAME→NXDOMAIN/NoAnswer, unresolvable NS, and a
  ~30-provider takeover fingerprint table matched against the live body.
- **TLS** — health, **validity verdict** (valid / expired / hostname-mismatch /
  self-signed / untrusted-chain), version range (1.0–1.3), **negotiated cipher**,
  cert subject/issuer, **not-before / expiry / days-left**, **SHA-256 fingerprint**
  (cert pivot), **SANs**, optional real **JARM**.
- **HTTP** — separate HTTP/HTTPS status, redirect quality + count, **latency**,
  title, `Server` / **X-Powered-By**, **Set-Cookie names**, **content-type**,
  **body SHA-256** (parked-page clustering), missing security headers, **CDN/WAF
  identification**, **CMS detection**, **harvested emails**, favicon MurmurHash3 →
  tech **plus a ready `http.favicon.hash:` Shodan pivot**, external script origins,
  `/api/vN` endpoints, HTML comments, copyright year, login-page detection (incl.
  Microsoft/Entra tenant ID).
- **Network** — private-IP exposure, org-CIDR membership, open ports (auto-skipped
  behind a CDN unless `--ports-behind-cdn`), optional **service banners**.
- **Loop-back** — certificate SANs + external CNAME targets surfaced as
  `discovered_domains` / the `new-domains` emit feed for the next enum pass.
- **Harvest** — robots.txt / sitemap.xml / security.txt disclosed paths.
- **Risk score** — weighted 0–100 with a readable `score_notes` breakdown.

## Configuration

- **Brand/engagement config:** policy values are **not** baked into the code. `clipeus.py` and
  `classify.py` read an optional JSON file — `--config FILE`, else `$CLIPEUS_CONFIG`, else
  `brand.json` beside `clipeus.py`, else `~/.config/clipeus/brand.json`. Keys (all optional):
  `approved_mx`, `approved_redirect`, `brand_keywords` (extra banking/finance signals for
  `classify.py`), `resolvers` (DNS resolver IPs — see **DNS integrity** below), and
  `nsec3.zone` / `nsec3.known` (for `recon/nsec3-enum.py`). Copy
  `brand.example.json` to `brand.json` and fill it in; `brand.json` is gitignored so engagement
  values stay local. With no config (or an unset list), the matching policy check is simply
  skipped, so the shipped tool is brand-neutral. CLI `--approved-mx` / `--approved-redirect`
  override the config.
- **Org networks:** set `org_networks` in `brand.json`, or pass `--org-networks cidrs.txt`. No ranges ship in the code.
- **DNS integrity (important):** resolver choice directly determines what this tool can
  see, so it is a first-class configuration item — not an afterthought. Use **unfiltered,
  quota-free, authoritative-faithful** public resolvers only:
  - A **filtering** resolver (e.g. Quad9, most ISP/enterprise resolvers, "safe" DNS) blocks
    or rewrites domains it deems malicious — i.e. exactly the suspicious/parked/takeover
    candidates this tool exists to find. It would silently hide findings.
  - A **quota'd or rate-limited** resolver returns partial/`SERVFAIL`/truncated answers on a
    large run, producing false `no-dns-resolution` / `dead-dns` dispositions.
  - A resolver that **rewrites `NXDOMAIN`** (captive portals, ad-blockers, some ISPs) breaks
    takeover and wildcard detection outright.

  **Recommended: Cloudflare + Google, which are unfiltered and unmetered** — the built-in
  default is `1.1.1.1 1.0.0.1 8.8.8.8 8.8.4.4`. The tool deliberately bypasses the system
  resolver (`/etc/resolv.conf`) for this reason. Override via the config `resolvers` key
  (persistent, validated as IPs) or `--resolvers resolvers.txt` (per-run). **One precedence
  for every tool** — `clipeus.py`, `classify.py`, every `recon/` script, and `dnsx` inside
  `enum-bulk.sh` / `enum-portfolio.sh` all resolve through `brand_config.effective_resolvers()`:
  `--resolvers FILE` / `$CLIPEUS_RESOLVERS` > config `resolvers` > tuning `dns_servers` >
  Cloudflare + Google. Shell tools get it from `python3 brand_config.py --resolvers`;
  `clipeus --show-config` shows which one a run will use.
- **Takeover / CDN signatures:** extend `TAKEOVER_PROVIDERS` / `CDN_SIGNATURES`.
- **Favicon tech:** add `hash: "Name"` pairs to `TECH_FAVICON_HASHES`.

## Notes / caveats

- **Geo/ASN enrichment is opt-in (`--geo`)** because it sends every resolved IP to
  ip-api.com over plain HTTP (their free tier has no HTTPS) — a confidentiality leak
  for engagement targets. When enabled it is rate-limited by the free tier (45 req/min,
  429-aware); use your own enrichment for very large scans, and `--rate` to stay polite.
- Port scanning is a TCP connect scan, bounded per host and skipped behind CDNs by
  default. Banner grabbing reads the service greeting (or sends a bare `HEAD` on web
  ports).
- Ctrl-C flushes partial results before exiting.
- **Authorized use only.** Run this only against domains/hosts you own or have
  explicit written permission to assess.

## Configuration & tuning (policy lives outside the code)

Clipeus keeps policy and tunables **out of the script** so the same build works
unmodified across engagements. Precedence, highest first:

| Layer | How | What it holds |
|---|---|---|
| CLI flags | `--resolvers`, `--org-networks`, `--takeover-sigs`, `--ports`, … | per-run overrides |
| Brand/engagement config | `--config FILE` · `$CLIPEUS_CONFIG` · `brand.json` beside `clipeus.py` · `~/.config/clipeus/brand.json` | `approved_mx`, `approved_redirect`, `brand_keywords`, `resolvers`, `org_networks`, `nsec3` (secret — gitignored) |
| Tuning file | `$CLIPEUS_TUNING` · `clipeus.tuning.json` beside `clipeus.py` · `~/.config/clipeus/tuning.json` | operational policy: `dns_servers`, `top_ports`, `dkim_selectors`, `dkim_min_bits`, `hsts_min_max_age`, `spf_max_queries`, `scanner_points`, `nxdomain_only_providers`, `max_body_bytes` (per-response cap, default 2 MiB; cut bodies set `body_truncated=Yes`), … |
| In-code defaults | — | sane fallback so Clipeus always runs standalone |

Any key you omit falls back to the layer below it; a missing file changes nothing.
Copy `clipeus.tuning.example.json` → `clipeus.tuning.json` to customise. Inspect the
**effective** configuration at any time:

```
clipeus --show-config          # prints merged tuning + override sources as JSON
```

## Recommended workflow (enumerate → audit → analyse)

Clipeus is one stage of a three-stage pipeline; the design assumes all three:

**1. Enumerate — breadth, with a *mix* of Kali tooling (never one source).**
`recon/enum-bulk.sh` runs subfinder (~30 passive sources incl. CT), a dedicated
crt.sh pass, optional amass/assetfinder, and dnsx validation, chunked and in
parallel. Each source is probed and skipped if absent, so it degrades gracefully.

```
./recon/enum-bulk.sh -i apexes.txt -o out/enum        # subdomains.txt(.all)
```

**2. Audit — Clipeus over roots + discovered subs, lossless output.**

```
# targets = your apexes + every discovered name. Use the .all file: it keeps names
# that don't resolve, which is where dangling-CNAME takeover candidates live.
cat apexes.txt out/enum/subdomains.txt.all | sort -u > out/targets.txt
clipeus --input out/targets.txt --output out/audit.jsonl --format jsonl \
        --raw-dir out/evidence
```
Resolvers come from the shared lookup (unfiltered Cloudflare + Google unless you
configure otherwise); add `--resolvers FILE` only to override for one run.

**3. Analyse — by a human analyst or an AI / Claude CLI.**
The JSONL is intentionally **raw and not pre-scored for you**: it records observed
facts (cert dates, CNAME chains, DNS/mail state) plus the tool's own `risk_score`
as *one column*, so an analyst or agent can re-derive severity independently rather
than inherit the tool's weighting. Drive it from a Claude CLI via env/flags
(`CLIPEUS_TUNING`, `CLIPEUS_CONFIG`), introspect with `--show-config`, and fold in
other tools with `--ingest nuclei.jsonl --ingest httpx.json`.

> Provenance (tools used, resolvers, version, timestamp) belongs in the run log —
> **not** in the per-host records — so the raw data stays unbiased for step 3.

## Operating modes

Clipeus is built to be run two ways, and the config model serves both:

- **By hand, by well-run IT** — edit `clipeus.tuning.json` / `brand.json` with a
  documented example to copy, run `clipeus --show-config` to confirm what's active,
  and drive scans with explicit flags.
- **Inside a Claude / agent CLI** — everything is overridable by environment
  (`CLIPEUS_TUNING`, `CLIPEUS_CONFIG`) and flags with no interactive prompts;
  `--show-config` gives machine-readable introspection; raw/lossless output
  (`--format jsonl`, `--raw-dir`) lets an agent analyse results without inheriting
  the tool's own scoring; and missing optional tools degrade gracefully to a basic
  pass rather than failing.
