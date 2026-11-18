#!/usr/bin/env python3
"""censys-ip-names.py — hostnames Censys has seen on known IP addresses, kept to scope.

Works on the Censys Free plan (asset lookups; search needs a paid plan). For every
address it asks Censys which DNS names point there (forward and reverse) and keeps
only names under the in-scope apexes: a shared address carries other people's names
too. Output is the in-scope names not already in --known, ready to append to the
audit target list.

Addresses come from a file (one per line) or from an audit JSONL (`a_records` of
each record). Private addresses are skipped, and with --skip-cdn so are hosts the
audit classed as CDN-hosted (shared edges: many lookups, few in-scope names).

Credentials only from the environment: CENSYS_API_TOKEN (and CENSYS_ORG_ID if you
have one). One lookup call covers up to 100 addresses; --max caps the calls.

Usage:
  censys-ip-names.py --from-audit audit.jsonl --scope apexes.txt --known targets.txt \\
                     --output new-names.txt [--skip-cdn] [--max 20] [--dry-run]
  censys-ip-names.py --input ips.txt --scope apexes.txt --output new-names.txt
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.realpath(__file__)), ".."))
import clipeus  # noqa: E402


def _public(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def addresses(args) -> list:
    ips = set()
    if args.input:
        ips |= {ln.strip() for ln in open(args.input, encoding="utf-8") if ln.strip() and not ln.startswith("#")}
    if args.from_audit:
        for ln in open(args.from_audit, encoding="utf-8"):
            try:
                r = json.loads(ln)
            except ValueError:
                continue
            if args.skip_cdn and r.get("hosting_class") == "cdn":
                continue
            ips |= {x.strip() for x in str(r.get("a_records", "")).split(",") if x.strip()}
    return sorted(ip for ip in ips if _public(ip))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    src = ap.add_argument_group("addresses")
    src.add_argument("--input", help="file with one IP address per line")
    src.add_argument("--from-audit", help="audit JSONL; its a_records are used")
    ap.add_argument("--skip-cdn", action="store_true", help="skip hosts the audit classed as CDN-hosted")
    ap.add_argument("--scope", required=True, help="in-scope apex domains, one per line")
    ap.add_argument("--known", help="names already targeted (left out of the output)")
    ap.add_argument("--output", required=True, help="new in-scope names, one per line")
    ap.add_argument("--evidence", help="also write {ip: [names]} as JSON here")
    ap.add_argument("--max", type=int, default=0, help="cap on API calls (100 addresses each; 0 = no cap)")
    ap.add_argument("--dry-run", action="store_true", help="count addresses and calls, call nothing")
    a = ap.parse_args()
    if not (a.input or a.from_audit):
        ap.error("give --input and/or --from-audit")
    ips = addresses(a)
    calls = (len(ips) + 99) // 100
    print(f"[censys-ip] {len(ips)} public addresses -> {calls} lookup call(s)"
          + (f", capped at {a.max}" if a.max else ""), file=sys.stderr)
    if a.dry_run:
        return 0
    if not clipeus._censys_platform():
        print("[censys-ip] CENSYS_API_TOKEN is not set in the environment", file=sys.stderr)
        return 2
    clipeus._CENSYS["max"] = a.max
    scope = [ln.strip().lower() for ln in open(a.scope, encoding="utf-8") if ln.strip() and not ln.startswith("#")]
    found = clipeus.censys_ip_names(ips, scope, log=lambda m: print(m, file=sys.stderr))
    known = set()
    if a.known:
        known = {ln.strip().lower().rstrip(".") for ln in open(a.known, encoding="utf-8") if ln.strip()}
    names = sorted({n for v in found.values() for n in v} - known)
    with open(a.output, "w", encoding="utf-8") as fh:
        fh.write("\n".join(names) + ("\n" if names else ""))
    if a.evidence:
        with open(a.evidence, "w", encoding="utf-8") as fh:
            json.dump(found, fh, indent=1, sort_keys=True)
    print(f"[censys-ip] {clipeus._CENSYS['calls']} call(s); {len(found)} addresses carry in-scope names; "
          f"{len(names)} new name(s) -> {a.output}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
