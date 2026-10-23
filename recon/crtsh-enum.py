#!/usr/bin/env python3
"""
crtsh-enum.py — throttled, resilient crt.sh subdomain enumerator.

A stand-alone fallback for when CertSpotter is keyless-rate-limited and subfinder
isn't installed. Feeds the same out/subdomains.txt that clipeus.py
would produce, so the downstream audit is unchanged.

Why this exists: crt.sh at high volume returns HTTP 502/503/HTML instead of JSON,
truncates, and rate-limits. This client:
  * paces requests to a global rate (default 1.5 req/s) with per-request jitter,
  * retries with exponential backoff on 429/5xx/HTML/JSON-decode errors,
  * queries the crt.sh JSON API once per registrable domain (%25.<domain>),
  * parses name_value (newline-separated, may hold wildcards + SAN bundles),
  * keeps only in-scope names (endswith the queried apex), strips *. wildcards,
  * optionally DNS-validates (default on): only resolvable names reach the main
    output; the full raw set is written to <output>.all (matches clipeus's
    --subs-file / .all convention).

Usage:
  crtsh-enum.py --input out/scan-roots.txt --output out/subdomains.txt \
                [--rate 1.5] [--workers 3] [--retries 4] [--no-resolve] [--append]

Exit: writes <output> (resolvable) and <output>.all (raw union incl. apexes).
"""
from __future__ import annotations
import argparse, json, random, sys, threading, time, urllib.parse, urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
import os as _os, sys as _sys
_sys.path.insert(0, _os.path.join(_os.path.dirname(_os.path.realpath(__file__)), ".."))
import brand_config  # noqa: E402  (shared DNS config: one resolver setting for every tool)

try:
    import dns.resolver
    _R = dns.resolver.Resolver()
    _R.nameservers = brand_config.resolvers_or_exit()
    _R.timeout = _R.lifetime = 4.0
    _HAVE_DNS = True
except Exception:
    _HAVE_DNS = False

FAILED: list = []   # apexes whose crt.sh query never succeeded (must not read as "no subdomains")

UA = "clipeus-recon/1.0 (+crtsh-enum; authorized brand-portfolio audit)"

_rl_lock = threading.Lock()
_next_slot = [0.0]

def _pace(rate: float):
    """Global token-bucket-ish spacing so N workers still honor one req/s budget."""
    if rate <= 0:
        return
    gap = 1.0 / rate
    with _rl_lock:
        now = time.monotonic()
        wait = max(0.0, _next_slot[0] - now)
        _next_slot[0] = max(now, _next_slot[0]) + gap
    if wait:
        time.sleep(wait)

def fetch_crtsh(domain: str, rate: float, retries: int, log) -> set[str]:
    """Return set of hostnames from crt.sh for %25.<domain>, or empty on failure."""
    q = urllib.parse.quote(f"%.{domain}")
    url = f"https://crt.sh/?q={q}&output=json"
    backoff = 2.0
    for attempt in range(1, retries + 1):
        _pace(rate)
        time.sleep(random.uniform(0, 0.4))  # jitter
        try:
            req = urllib.request.Request(url, headers={"User-Agent": UA,
                                                       "Accept": "application/json"})
            with urllib.request.urlopen(req, timeout=90) as r:
                raw = r.read().decode("utf-8", "replace").strip()
            if not raw or raw[0] not in "[{":       # HTML error page / empty
                raise ValueError("non-JSON body")
            data = json.loads(raw)
        except Exception as e:
            if attempt == retries:
                log(f"[crtsh] {domain}: FAILED after {retries} ({type(e).__name__})")
                FAILED.append(domain)
                return set()
            time.sleep(backoff + random.uniform(0, 1.5))
            backoff *= 2
            continue
        names: set[str] = set()
        for entry in data:
            for nv in str(entry.get("name_value", "")).splitlines():
                nv = nv.strip().lower().lstrip("*.").rstrip(".")
                if nv and (nv == domain or nv.endswith("." + domain)):
                    names.add(nv)
        log(f"[crtsh] {domain}: {len(names)} names")
        return names
    return set()

def resolves(host: str) -> bool:
    if not _HAVE_DNS:
        return True
    for rr in ("A", "AAAA", "CNAME"):
        try:
            if _R.resolve(host, rr):
                return True
        except Exception:
            continue
    return False

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", required=True)
    ap.add_argument("--output", required=True)
    ap.add_argument("--rate", type=float, default=1.5, help="global req/s (default 1.5)")
    ap.add_argument("--workers", type=int, default=3)
    ap.add_argument("--retries", type=int, default=4)
    ap.add_argument("--no-resolve", action="store_true",
                    help="skip DNS validation; write raw union only")
    ap.add_argument("--append", action="store_true",
                    help="merge into existing --output instead of overwriting")
    ap.add_argument("--log", default="-")
    args = ap.parse_args()

    logf = sys.stderr if args.log == "-" else open(args.log, "a")
    def log(m): print(f"{time.strftime('%H:%M:%S')} {m}", file=logf, flush=True)

    roots = []
    seen = set()
    for line in open(args.input, encoding="utf-8"):
        d = line.strip().lower().rstrip(".")
        if d and not d.startswith("#") and d not in seen:
            seen.add(d); roots.append(d)
    log(f"[*] crt.sh enum over {len(roots)} domains @ {args.rate} req/s, {args.workers} workers")

    raw_all: set[str] = set(roots)  # apexes belong in the audit set too
    if args.append:
        try:
            raw_all |= {l.strip() for l in open(args.output + ".all") if l.strip()}
        except FileNotFoundError:
            pass

    done = 0
    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        futs = {ex.submit(fetch_crtsh, d, args.rate, args.retries, log): d for d in roots}
        for fut in as_completed(futs):
            raw_all |= fut.result()
            done += 1
            if done % 100 == 0:
                log(f"[*] {done}/{len(roots)} queried, {len(raw_all)} names so far")

    if FAILED:
        open(args.output + ".failed", "w").write("\n".join(sorted(FAILED)) + "\n")
        log(f"[!] crt.sh FAILED for {len(FAILED)} domains -> {args.output}.failed (re-run these; "
            "an empty result for them is a coverage gap, not 'no subdomains')")
    # write raw union
    raw_sorted = sorted(raw_all)
    open(args.output + ".all", "w").write("\n".join(raw_sorted) + "\n")
    log(f"[*] raw union: {len(raw_sorted)} names -> {args.output}.all")

    if args.no_resolve:
        open(args.output, "w").write("\n".join(raw_sorted) + "\n")
        log(f"[*] wrote {len(raw_sorted)} (unresolved) -> {args.output}")
        return 0

    # DNS-validate in parallel
    live = []
    with ThreadPoolExecutor(max_workers=min(50, 8 * args.workers)) as ex:
        for host, ok in zip(raw_sorted, ex.map(resolves, raw_sorted)):
            if ok:
                live.append(host)
    existing = []
    if args.append:
        try:
            existing = [l.strip() for l in open(args.output) if l.strip()]
        except FileNotFoundError:
            pass
    final = sorted(set(live) | set(existing))
    open(args.output, "w").write("\n".join(final) + "\n")
    log(f"[*] resolvable: {len(final)} -> {args.output}  (dropped {len(raw_sorted)-len(live)} dead)")
    return 0

if __name__ == "__main__":
    sys.exit(main())
