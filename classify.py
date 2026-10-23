#!/usr/bin/env python3
"""
classify.py — content-categorize an audited domain inventory into 8 buckets.

Reads a Clipeus audit (JSONL) plus the per-host evidence bodies saved by
--raw-dir, "reads" each page (title + visible text, multilingual), and writes a
wide CSV with a category, a human-readable comment, and the matched signals so
the result is filterable in a spreadsheet.

Usage:
  classify.py --audit /tmp/audit.jsonl --evidence /tmp/evidence \
              --output /tmp/classified.csv [--config brand.json]
"""
from __future__ import annotations
import argparse
import csv
import html
import ipaddress
import json
import os
import re
from concurrent.futures import ThreadPoolExecutor
from functools import lru_cache

import brand_config

try:
    import dns.resolver
    _R = dns.resolver.Resolver()
    _R.nameservers = list(brand_config.DEFAULT_RESOLVERS)   # replaced in main() by the shared lookup
    _R.timeout = _R.lifetime = 4.0
    _HAVE_DNS = True
except Exception:
    _HAVE_DNS = False


@lru_cache(maxsize=100000)
def cymru_asn(ip: str) -> tuple[str, str]:
    """(asn, asn_name) via Team Cymru's IP->ASN DNS service — fast, unmetered."""
    if not _HAVE_DNS or not ip or ip == "N/A":
        return "", ""
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return "", ""
    try:
        rev = ".".join(reversed(ip.split(".")))
        ans = _R.resolve(f"{rev}.origin.asn.cymru.com", "TXT")
        # "13335 | 104.16.0.0/12 | US | arin | ..."
        asn = str(ans[0]).strip('"').split("|")[0].strip().split()[0]
        name = ""
        try:
            n = _R.resolve(f"AS{asn}.asn.cymru.com", "TXT")
            name = str(n[0]).strip('"').split("|")[-1].strip()
        except Exception:
            pass
        return f"AS{asn}", name
    except Exception:
        return "", ""

CATEGORIES = ["banking-finance", "real-estate", "sponsorship-sports-events",
              "art-culture-foundation", "corporate-business", "parked-forsale",
              "redirect", "dead-or-empty"]

# Multilingual keyword signals (DE/FR/IT/EN). Weighted: title hits count more.
KW = {
    "banking-finance": [
        "bank", "banking", "e-banking", "ebanking", "wealth", "invest",
        "asset management", "vermögensverwaltung", "anlage", "hypothek", "mortgage",
        "wertschriften", "portfolio", "financial", "finanz", "börse", "trading",
        "vorsorge", "pension", "private banking", "iban", "konto",
        "login", "authenticate", "e-trading", "depot",
    ],
    "real-estate": [
        "immobilien", "immobilier", "immobiliare", "überbauung", "ueberbauung",
        "wohnen", "wohnung", "mietwohnung", "eigentumswohnung", "neubau", "areal",
        "wohnpark", "wohnüberbauung", "quartier", "residenz", "residence", "logement",
        "appartement", "alloggi", "real estate", "property", "apartments", "flats",
        "zu vermieten", "zu verkaufen", "mieten", "kaufen", "erstvermietung",
        "grundstück", "makler", "immo", "wohnbau", "siedlung", "attika", "loft",
        "bezugsbereit", "wohntraum", "stockwerkeigentum", "renditeobjekt",
    ],
    "sponsorship-sports-events": [
        "sponsor", "sponsoring", "partnerschaft", "event", "festival", "gala",
        "championship", "cup", "open", "turnier", "tournament", "golf", "tennis",
        "ski", "regatta", "sailing", "marathon", "race", "trophy", "league",
        "meisterschaft", "wettbewerb", "veranstaltung", "manifestation", "concours",
        "olympi", "fifa", "uefa", "athletics",
    ],
    "art-culture-foundation": [
        "art", "kunst", "museum", "gallery", "galerie", "kultur", "culture",
        "cultura", "stiftung", "foundation", "fondation", "fondazione", "charity",
        "wohltätig", "art collection", "kunstsammlung", "exhibition", "ausstellung",
        "orchestra", "orchester", "theater", "theatre", "biennale", "philanthrop",
    ],
    "corporate-business": [
        "advisory", "consulting", "beratung", "gmbh", "ag", "sarl", "holding",
        "group", "gruppe", "solutions", "services", "management", "partners",
        "capital", "ventures", "company", "unternehmen", "corporate", "kanzlei",
        "treuhand", "law", "recht", "engineering", "technolog", "software",
    ],
}

PARKED = [
    "domain for sale", "buy this domain", "this domain is for sale", "domain is parked",
    "parked", "sedoparking", "sedo.com", "hugedomains", "godaddy", "dan.com",
    "coming soon", "under construction", "website coming soon", "in costruzione",
    "en construction", "im aufbau", "demnächst", "namecheap", "afternic",
    "domainparking", "parkingcrew", "bodis", "future home of", "default web page",
    "apache2 default", "nginx welcome", "it works!", "welcome to nginx",
    "diese domain", "domain steht zum verkauf",
]

from functools import lru_cache as _lru


@_lru(maxsize=4096)
def _kw_re(word: str):
    # word-boundary match; keywords with spaces/hyphens matched as phrases
    return re.compile(r"(?<![a-z0-9])" + re.escape(word) + r"(?![a-z0-9])")


TAG_RE = re.compile(r"<(script|style)[^>]*>.*?</\1>", re.I | re.S)
STRIP_RE = re.compile(r"<[^>]+>")
LANG_RE = re.compile(r'<html[^>]*\blang=["\']?([a-zA-Z-]{2,5})', re.I)
WS_RE = re.compile(r"\s+")


def page_text(body: str) -> str:
    body = TAG_RE.sub(" ", body)
    body = STRIP_RE.sub(" ", body)
    body = html.unescape(body)
    return WS_RE.sub(" ", body).strip().lower()


def safe_name(domain: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "_", domain)[:150] or "unknown"


try:
    import tldextract
    _TLDX = tldextract.TLDExtract(cache_dir="/tmp/tldextract_cache",
                                  include_psl_private_domains=True)
    _TLDX("example.com")
    _HAVE_PSL = True
except Exception:
    _HAVE_PSL = False


def registrable(host: str) -> str:
    host = (host or "").strip().rstrip(".").lower()
    if not host:
        return host
    if _HAVE_PSL:
        try:
            ext = _TLDX(host)
            top = getattr(ext, "top_domain_under_public_suffix", None) or ext.registered_domain
            if top:
                return top
        except Exception:
            pass
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    multi = {"co.uk", "org.uk", "com.au", "co.jp", "co.nz", "com.br"}
    return ".".join(parts[-3:]) if ".".join(parts[-2:]) in multi else ".".join(parts[-2:])


def classify(rec: dict, body: str) -> tuple[str, str, str, str]:
    """Return (category, comment, signals, lang)."""
    title = (rec.get("page_title") or "").strip()
    title_l = title.lower()
    text = page_text(body) if body else ""
    blob = (title_l + " " + text)[:200000]
    lang_m = LANG_RE.search(body) if body else None
    lang = (lang_m.group(1).split("-")[0].lower() if lang_m else "")

    disp = rec.get("disposition", "")
    http, https = rec.get("http_status", "0"), rec.get("https_status", "0")
    responded = http not in ("0", "") or https not in ("0", "")
    fwd = rec.get("is_forwarded") == "Yes"
    final_reg = registrable(_host(rec.get("final_url", ""))) if fwd else ""

    # --- hard states first ---
    if disp in ("dead-dns", "dead-nohttp") or (not responded and not body):
        why = {"dead-dns": "does not resolve (NXDOMAIN/none)",
               "dead-nohttp": "resolves but no browser-trusted service"}.get(disp, "no service/content")
        if rec.get("https_status") == "cert-error":
            ins = rec.get("insecure_https", "")
            why = ("invalid TLS cert (browser rejects); HTTP=" + str(rec.get("http_status", "?"))
                   + (f"; ignoring cert -> {ins}" if ins else ""))
        return "dead-or-empty", why, "", lang

    # --- parked / placeholder ---
    park_hits = [k for k in PARKED if k in blob]
    if park_hits and len(text) < 4000:
        return ("parked-forsale",
                f"parking/placeholder page ({park_hits[0]})",
                ";".join(park_hits[:4]), lang)

    # --- score content categories (word-boundary match: 'art' must not match
    #     'start', 'cup' must not match 'cupboard', etc.) ---
    scores, hits = {}, {}
    for cat, words in KW.items():
        h = []
        s = 0
        for w in words:
            pat = _kw_re(w)
            if pat.search(title_l):
                s += 3; h.append(w)
            elif pat.search(text):
                s += 1; h.append(w)
        if s:
            scores[cat] = s
            hits[cat] = h

    best = max(scores, key=scores.get) if scores else None
    best_score = scores.get(best, 0)

    # --- offsite redirect: the content belongs to the TARGET, not this domain, so
    #     classify as redirect (target noted) regardless of keyword score. This is
    #     the case of a lapsed/parked lookalike now pointing to an unrelated site. ---
    if fwd and final_reg and final_reg != registrable(rec.get("domain", "")):
        return ("redirect", f"redirects offsite to {final_reg}", "", lang)

    if best and best_score >= 2:
        note = title[:80] if title and title != "N/A" else (text[:80] if text else "")
        return (best, f'{note}'.strip() or f"matched {best}", ";".join(hits[best][:6]), lang)

    # --- responded but nothing matched ---
    if responded:
        note = title[:80] if title and title not in ("N/A", "") else "live page, no category keywords"
        return ("corporate-business", note, ";".join(hits.get(best, [])[:4]) if best else "", lang)
    return "dead-or-empty", "no usable content", "", lang


def _host(url: str) -> str:
    m = re.search(r"https?://([^/:]+)", url or "")
    return m.group(1).lower() if m else ""


COLUMNS = ["domain", "is_subdomain", "category", "category_comment", "category_signals",
           "lang", "resolves", "serves_content", "tls_trusted", "insecure_https", "disposition",
           "http_status", "https_status", "final_url", "redirect_target",
           "page_title", "server", "cms", "content_type", "size", "has_login_form",
           "ip", "a_records", "cname", "asn", "asn_name", "ptr",
           "registrar", "mx_records", "spf_issues", "dmarc_issues", "tls_valid",
           "config_issues", "risk_score"]


def build_row(rec: dict, body: str) -> tuple[str, dict]:
    cat, comment, signals, lang = classify(rec, body)
    fwd = rec.get("is_forwarded") == "Yes"
    ip = rec.get("ip", "N/A")
    asn, asn_name = cymru_asn(ip)
    resolves = "Yes" if (rec.get("dns_status") == "OK" or ip not in ("N/A", "")
                         or rec.get("cname", "N/A") != "N/A") else "No"
    serves = "Yes" if (rec.get("http_status") == "200" or rec.get("https_status") == "200"
                       or int(rec.get("size", 0) or 0) > 0) else "No"
    return cat, {
        "domain": rec.get("domain", ""), "is_subdomain": rec.get("is_subdomain", "No"),
        "category": cat, "category_comment": comment, "category_signals": signals, "lang": lang,
        "resolves": resolves, "serves_content": serves,
        "tls_trusted": rec.get("tls_trusted", "N/A"), "insecure_https": rec.get("insecure_https", ""),
        "disposition": rec.get("disposition", ""),
        "http_status": rec.get("http_status", ""), "https_status": rec.get("https_status", ""),
        "final_url": rec.get("final_url", ""),
        "redirect_target": _host(rec.get("final_url", "")) if fwd else "",
        "page_title": rec.get("page_title", ""), "server": rec.get("server", ""),
        "cms": rec.get("cms", ""), "content_type": rec.get("content_type", ""),
        "size": rec.get("size", ""), "has_login_form": rec.get("has_login_form", ""),
        "ip": ip, "a_records": rec.get("a_records", ""), "cname": rec.get("cname", ""),
        "asn": asn, "asn_name": asn_name, "ptr": rec.get("ptr", ""),
        "registrar": rec.get("rdap_registrar", ""), "mx_records": rec.get("mx_records", ""),
        "spf_issues": rec.get("spf_issues", ""), "dmarc_issues": rec.get("dmarc_issues", ""),
        "tls_valid": rec.get("tls_valid", ""), "config_issues": rec.get("config_issues", ""),
        "risk_score": rec.get("risk_score", ""),
    }


def probe(domain: str, timeout: float = 8.0) -> tuple[dict, str]:
    try:
        return _probe(domain, timeout)
    except Exception as exc:
        return ({"domain": domain, "dns_status": "ERROR", "disposition": "dead-or-empty",
                 "http_status": "0", "https_status": "0"}, "")


def _probe(domain: str, timeout: float = 8.0) -> tuple[dict, str]:
    """Standalone fetch: resolve + grab the homepage, return (rec, body)."""
    import clipeus
    rec = {"domain": domain, "ip": "N/A", "a_records": "", "cname": "N/A",
           "dns_status": "", "http_status": "0", "https_status": "0",
           "page_title": "N/A", "final_url": "N/A", "is_forwarded": "No",
           "size": 0, "server": "N/A", "content_type": "N/A", "disposition": ""}
    a, status = clipeus.resolve_a_status(domain)
    rec["dns_status"] = status
    if a:
        rec["ip"] = a[0]
        rec["a_records"] = ",".join(a)
    chain = clipeus.cname_chain(domain)
    if chain:
        rec["cname"] = " -> ".join(chain)
    resolves = bool(a or chain or clipeus._resolve(domain, "AAAA"))

    body = ""
    import requests
    sess = requests.Session()
    sess.headers.update({"User-Agent": "Mozilla/5.0 (compatible; clipeus-classify/1)"})
    rec["tls_trusted"] = "N/A"
    rec["insecure_https"] = ""
    winner = None  # only ever a TRUSTED 200 (valid-cert HTTPS or plain HTTP)

    # HTTPS with certificate verification ON — what a real browser gets.
    try:
        r = sess.get(f"https://{domain}", timeout=timeout, verify=True, allow_redirects=True)
        rec["https_status"] = str(r.status_code)
        rec["tls_trusted"] = "Yes"
        if r.status_code == 200:
            winner = r
    except requests.exceptions.SSLError:
        # cert invalid (expired / self-signed / hostname mismatch) — a browser
        # rejects this, so it is NOT trusted content. Peek insecurely for the
        # record only; never let it drive the category.
        rec["https_status"] = "cert-error"
        rec["tls_trusted"] = "No"
        try:
            ri = sess.get(f"https://{domain}", timeout=timeout, verify=False, allow_redirects=True)
            rec["insecure_https"] = f"{ri.status_code}->{ri.url}"[:120]
        except Exception:
            pass
    except Exception:
        rec["https_status"] = "0"

    # HTTP (no certificate involved).
    try:
        r = sess.get(f"http://{domain}", timeout=timeout, verify=False, allow_redirects=True)
        rec["http_status"] = str(r.status_code)
        if r.status_code == 200 and (winner is None or winner.status_code != 200):
            winner = r
    except Exception:
        pass

    if winner is not None:
        body = winner.text
        rec["final_url"] = winner.url
        rec["size"] = len(body)
        rec["server"] = winner.headers.get("Server", "N/A")
        rec["content_type"] = winner.headers.get("Content-Type", "N/A").split(";")[0].strip()
        m = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
        rec["page_title"] = m.group(1).strip()[:200] if m else "N/A"
        if _host(winner.url) and _host(winner.url) != domain.lower():
            rec["is_forwarded"] = "Yes"

    rec["is_subdomain"] = "Yes" if domain != clipeus.registrable_domain(domain) else "No"
    # "responded" for disposition means a TRUSTED response (a browser could load it).
    trusted_resp = winner is not None
    any_status = rec["http_status"] not in ("0", "") or rec["https_status"] not in ("0", "")
    if not resolves:
        rec["disposition"] = "dead-dns"
    elif trusted_resp:
        rec["disposition"] = "redirect" if rec["is_forwarded"] == "Yes" else "live"
    elif any_status:
        # resolves and answered, but nothing a browser trusts (cert-error / 4xx/5xx)
        rec["disposition"] = "dead-nohttp"
    else:
        rec["disposition"] = "dead-nohttp"
    return rec, body


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--audit", help="Clipeus audit JSONL (reuse saved pages)")
    ap.add_argument("--evidence", help="raw-dir with saved bodies (with --audit)")
    ap.add_argument("--input", help="domains/subdomains file — fetch pages standalone")
    ap.add_argument("--output", required=True)
    ap.add_argument("--workers", type=int, default=25, help="concurrent fetches (--input mode)")
    ap.add_argument("--timeout", type=float, default=8.0)
    ap.add_argument("--config", help="brand config (brand_keywords extend the banking bucket); "
                                     "default lookup as for clipeus")
    ap.add_argument("--dedup-www", action="store_true",
                    help="skip www.X when X is also in --input (redundant with apex)")
    args = ap.parse_args()
    if not args.audit and not args.input:
        ap.error("provide --audit (+--evidence) or --input")
    try:
        cfg, _path = brand_config.load(args.config)
    except ValueError as exc:
        ap.error(f"config {exc}")
    KW["banking-finance"] += [k for k in cfg["brand_keywords"] if k not in KW["banking-finance"]]
    if _HAVE_DNS:
        _R.nameservers = brand_config.resolvers_or_exit(cfg=cfg)

    counts = {c: 0 for c in CATEGORIES}
    n = 0
    with open(args.output, "w", newline="") as fo:
        w = csv.DictWriter(fo, fieldnames=COLUMNS, extrasaction="ignore")
        w.writeheader()

        if args.audit:
            for line in open(args.audit):
                line = line.strip()
                if not line:
                    continue
                rec = json.loads(line)
                body = ""
                if args.evidence:
                    bp = os.path.join(args.evidence, safe_name(rec.get("domain", "")), "body.html")
                    try:
                        with open(bp, encoding="utf-8", errors="ignore") as bf:
                            body = bf.read()
                    except FileNotFoundError:
                        pass
                cat, row = build_row(rec, body)
                counts[cat] += 1; n += 1
                w.writerow(row)
        else:
            import clipeus
            doms = clipeus.read_inputs(args.input, dedup_www=args.dedup_www)
            print(f"fetching + classifying {len(doms)} domains ({args.workers} workers)...")
            with ThreadPoolExecutor(max_workers=args.workers) as ex:
                for i, (rec, body) in enumerate(ex.map(lambda d: probe(d, args.timeout), doms), 1):
                    cat, row = build_row(rec, body)
                    counts[cat] += 1; n += 1
                    w.writerow(row)
                    if i % 500 == 0:
                        print(f"  {i}/{len(doms)}")

    print(f"classified {n} records -> {args.output}")
    for c in CATEGORIES:
        print(f"  {c:26} {counts[c]}")


if __name__ == "__main__":
    main()
