#!/usr/bin/env python3
"""
Clipeus — Domain Security Audit Tool
=============================================
Definitive consolidation of the domain_scan_* / domain_probe_* line, built to be
a *partner source* in a recon/pentest pipeline (subfinder/amass -> clipeus ->
nuclei/httpx/Shodan) rather than a standalone island.

Pipeline features:
  * Reads hosts from --input FILE or stdin ("-"); dedups + normalizes (IDN-safe).
  * Streams CSV / JSON / JSONL; "--output -" writes to stdout, progress to stderr.
  * --emit feeds the next tool: urls / live / open-ports / takeover / sans /
    new-domains printed as a clean deduped list (to stdout or --emit-file).
  * Closes the enumeration loop: certificate SANs and external CNAME targets are
    surfaced as newly-discovered domains for the next enum pass.
  * Wildcard-DNS detection so wildcard zones don't create phantom live hosts.
  * --resolvers FILE to share a resolver set with massdns/dnsx/puredns.

Enrichment:
  * CDN/WAF identification, Shodan favicon-hash pivot query, optional TCP banner
    grab (--banners), robots/sitemap/security.txt path harvest (--harvest),
    optional real JARM via the external `jarm` tool (--jarm).

Robustness:
  * Graceful Ctrl-C: partial results are flushed before exit.
  * Global rate limit (--rate) + per-domain jitter (--jitter) to stay polite.
  * DNS failure modes split (OK/NXDOMAIN/NOANSWER/SERVFAIL/TIMEOUT).
  * opt-in ip-api geo/ASN (--geo) with 429 handling; --selftest runs internal checks and exits.

Only requires `requests` + `dnspython` (`idna`, `cryptography` optional). No
`aiohttp` / `mmh3`: HTTP is threaded and the favicon MurmurHash3 is bundled.

Additional checks:
  * TLS/HSTS hygiene: HSTS max-age/flags, cert key size + signature hash, embedded SCT
    count, advertised OCSP/CRL endpoints, optional OCSP stapling check (--ocsp).
  * --origin: origin-IP discovery behind CDNs (header leaks, same-domain MX/SAN hosts,
    TLS-handshake certificate comparison), scored and reported as origin_candidates.
  * Exposed-service scoring (PORT_RISK), cookie flag analysis, MTA-STS / TLS-RPT / BIMI /
    DANE (+ opt-in --dkim), opt-in --auth-paths login-surface probing.
  * Expanded takeover fingerprints (+ --takeover-sigs FILE for the community JSON list).
  * --baseline / --diff-out run-to-run diff and --report-html / --report-from HTML report.

See README.md for the full option and dependency reference.
"""

from __future__ import annotations

__version__ = "26.10.0"  # CalVer YY.MM.patch; single source of truth (pyproject + banner + UA read this)

import argparse
import base64
import csv
import hashlib
import html
import ipaddress
import json
import os
import random
import re
import shutil
import signal
import socket
import ssl
import string
import subprocess
import sys
import threading
import time
import warnings
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict
from functools import lru_cache
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

import brand_config

import requests
from requests.adapters import HTTPAdapter

import dns.resolver
import dns.exception
import dns.query
import dns.zone
import dns.message
import dns.flags

try:
    from urllib3.util.retry import Retry
    _HAVE_RETRY = True
except Exception:  # pragma: no cover
    _HAVE_RETRY = False

try:
    import idna
    _HAVE_IDNA = True
except Exception:  # pragma: no cover
    _HAVE_IDNA = False

try:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except Exception:  # pragma: no cover
    pass

warnings.filterwarnings("ignore", category=DeprecationWarning)


# =====================================================================
# CONFIG
# =====================================================================

# ---- external tuning (operator-editable policy, kept OUT of the code) --------
# Every value below can be overridden WITHOUT editing this script, so the one
# file serves both hand-run operators (edit clipeus.tuning.json) and agent / CLI
# drivers (export CLIPEUS_TUNING=/path, or drop the file beside the script). A
# missing file or key falls back to the in-code default on the same line, so
# Clipeus always runs standalone. `--show-config` prints what actually loaded.
def _load_tuning() -> dict:
    cand = []
    if os.environ.get("CLIPEUS_TUNING"):
        cand.append(os.environ["CLIPEUS_TUNING"])
    _here = os.path.dirname(os.path.realpath(__file__))
    cand += [os.path.join(_here, "clipeus.tuning.json"),
             os.path.expanduser("~/.config/clipeus/tuning.json")]
    for _p in cand:
        try:
            if _p and os.path.isfile(_p):
                with open(_p, encoding="utf-8") as _fh:
                    _d = json.load(_fh)
                if isinstance(_d, dict):
                    _d["_source"] = _p
                    return _d
        except Exception as _e:
            sys.stderr.write(f"[warn] tuning file {_p} ignored: {_e}\n")
    return {}

_TUNING = _load_tuning()

_TUNE_KEYS: set = set()   # every key the code asks for; --show-config flags the rest as unknown


def _tune(key, default, merge=False):
    """External override for `key`, type-checked against `default`.

    A value of the wrong shape is reported on stderr and ignored, so a bad tuning
    file can never crash the tool or silently corrupt a run. Int defaults need ints,
    list defaults need lists of the same item type, dict defaults are merged (a
    partial dict only changes the keys it names), and merge=True unions a list with
    the default instead of replacing it (for safety lists that must not shrink)."""
    _TUNE_KEYS.add(key)
    if key not in _TUNING:
        return default
    val = _TUNING[key]

    def bad(why):
        sys.stderr.write(f"[warn] tuning '{key}' ignored ({why}); using default\n")
        return default

    def same(v, t):
        return isinstance(v, t) and not isinstance(v, bool)

    if isinstance(default, int) and not isinstance(default, bool):
        return val if same(val, int) else bad("expected an integer")
    if isinstance(default, dict):
        if not isinstance(val, dict):
            return bad("expected an object")
        sample = next(iter(default.values()), None)
        if sample is not None and not all(same(v, type(sample)) for v in val.values()):
            return bad(f"values must be {type(sample).__name__}")
        return {**default, **val}
    if isinstance(default, (list, tuple)):
        if not isinstance(val, list):
            return bad("expected a list")
        if default and not all(same(v, type(default[0])) for v in val):
            return bad(f"list items must be {type(default[0]).__name__}")
        return list(dict.fromkeys([*default, *val])) if merge else val
    return val


CHROME_HEADERS = {
    "User-Agent": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                   "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"),
    "Accept": ("text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,"
               "image/webp,image/apng,*/*;q=0.8"),
    "Sec-CH-UA": '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
    "Sec-CH-UA-Mobile": "?0",
    "Sec-CH-UA-Platform": '"Windows"',
    "Upgrade-Insecure-Requests": "1",
}
DEFAULT_UA = CHROME_HEADERS["User-Agent"]

# Organization-owned network ranges. Hosts resolving into these are tagged as
# internal/first-party (org_range=Yes) so external look-alikes stand out. These are
# engagement-specific, so none ship in the code: set "org_networks" in brand.json
# or pass --org-networks <file> (one CIDR per line). Precedence: file > config > [].
ORG_NETWORKS_DEFAULT: List[str] = []

# favicon MurmurHash3 -> technology. Extend as you fingerprint more assets.
TECH_FAVICON_HASHES = {
    81586312: "Jenkins",
    116323821: "Spring Boot",
    -335242539: "F5 BIG-IP",
}

TOP_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 1433, 1521,
             1883, 2049, 2181, 2375, 2376, 3306, 3389, 5000, 5432, 5900, 5985,
             6379, 8000, 8080, 8443, 9200, 10000, 11211, 27017]
TOP_PORTS = _tune("top_ports", TOP_PORTS)
STANDARD_PORTS = sorted(set(range(1, 1025)) | set(TOP_PORTS))
FULL_PORTS = sorted(set(range(1, 1025)) | set(TOP_PORTS) |
                    {1433, 1521, 1883, 2049, 2181, 2375, 2376, 3306, 3389, 5000,
                     5001, 5432, 5900, 5985, 6379, 8080, 8443, 9200, 10000, 11211, 27017})

# Internet-exposed services that should rarely be reachable: port -> (severity, label).
# Severity feeds the risk score (critical 25 / high 15 / medium 8); the total is capped.
PORT_RISK = {
    23: ("critical", "telnet"), 445: ("critical", "smb"), 2375: ("critical", "docker-api"),
    21: ("high", "ftp"), 2049: ("high", "nfs"), 2181: ("high", "zookeeper"),
    1433: ("high", "mssql"), 1521: ("high", "oracle"), 3306: ("high", "mysql"),
    3389: ("high", "rdp"), 5432: ("high", "postgres"), 5900: ("high", "vnc"),
    5985: ("high", "winrm"), 6379: ("high", "redis"), 9200: ("high", "elasticsearch"),
    11211: ("high", "memcached"), 27017: ("high", "mongodb"),
    110: ("medium", "pop3-cleartext"), 143: ("medium", "imap-cleartext"),
    1883: ("medium", "mqtt"), 2376: ("medium", "docker-tls"), 10000: ("medium", "webmin"),
}
PORT_RISK_POINTS = {"critical": 25, "high": 15, "medium": 8}
PORT_RISK_CAP = 40
# Ports where the server speaks first (safe to bare-read a banner).
BANNER_TALK_FIRST = {21, 22, 23, 25, 110, 143, 3306, 5432, 6379, 587, 993, 995}
WEB_PORTS = {80, 443, 8000, 8080, 8443, 5000, 9200, 10000}

SECURITY_HEADERS = [
    "Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options",
    "X-Content-Type-Options", "Referrer-Policy", "Permissions-Policy",
    "X-XSS-Protection",
]

# DNS integrity matters here: resolver choice directly affects what this tool can
# see. Use UNFILTERED public resolvers only — a resolver that blocks "malicious"
# domains (e.g. Quad9) or rewrites NXDOMAIN would hide the very exposure we hunt,
# and a quota'd/rate-limited one gives non-authoritative or partial answers. The
# built-in default is Cloudflare (1.1.1.1 = unfiltered "no-blocks") then Google,
# both quota-free and non-filtering; dnspython tries them in order. Override per-run
# with --resolvers FILE, or persistently via the config "resolvers" key. See README.
_DNS_DEFAULT = list(brand_config.DEFAULT_RESOLVERS)
DNS_SERVERS = _tune("dns_servers", _DNS_DEFAULT)
try:
    DNS_SERVERS = [str(ipaddress.ip_address(x)) for x in DNS_SERVERS] or _DNS_DEFAULT
except ValueError as _e:
    sys.stderr.write(f"[warn] tuning 'dns_servers' ignored ({_e}); using default\n")
    DNS_SERVERS = _DNS_DEFAULT

# --dkim probes these common selectors (DKIM selectors are arbitrary, so absence proves nothing).
DKIM_SELECTORS = ("default", "google", "selector1", "selector2", "k1", "k2", "k3", "mail",
                  "dkim", "s1", "s2", "smtp", "mandrill", "mxvault", "zendesk1", "zendesk2",
                  "sig1", "everlytickey1", "cm", "scph0123")
DKIM_SELECTORS = tuple(_tune("dkim_selectors", list(DKIM_SELECTORS)))
DKIM_MIN_BITS = _tune("dkim_min_bits", 2048)

# CDN/WAF fingerprints: any match across server header / arbitrary header key /
# ASN substring / CNAME substring identifies the edge.
CDN_SIGNATURES = {
    "Cloudflare": {"server": ["cloudflare"], "header": ["cf-ray", "cf-cache-status"],
                   "asn": ["13335"], "cname": ["cloudflare"]},
    "Akamai": {"server": ["akamaighost", "akamai"], "header": ["x-akamai", "akamai-"],
               "asn": ["20940", "16625", "35994"], "cname": ["akamai", "edgekey", "edgesuite"]},
    "Fastly": {"server": ["fastly"], "header": ["x-served-by", "x-fastly", "fastly-"],
               "asn": ["54113"], "cname": ["fastly"]},
    "CloudFront": {"server": ["cloudfront"], "header": ["x-amz-cf-id", "x-amz-cf-pop"],
                   "asn": ["16509"], "cname": ["cloudfront.net"]},
    "Imperva/Incapsula": {"server": ["incapsula"], "header": ["x-iinfo", "incap-ses", "x-cdn"],
                          "cname": ["incapdns"]},
    "Sucuri": {"server": ["sucuri"], "header": ["x-sucuri-id", "x-sucuri-cache"], "cname": ["sucuri"]},
    "Azure Front Door": {"header": ["x-azure-ref", "x-msedge-ref"],
                         "cname": ["azureedge.net", "azurefd.net", "trafficmanager.net"]},
    "Google": {"server": ["gws", "esf", "google frontend"], "asn": ["15169"], "cname": ["googlehosted"]},
}

# Published edge ranges used to discard CDN IPs from origin candidates
# (https://www.cloudflare.com/ips-v4). Other CDNs are filtered by ASN lookup
# via CDN_SIGNATURES["asn"] (only with --geo).
CDN_RANGES = {
    "Cloudflare": [
        "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
        "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
        "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
        "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
    ],
}
_CDN_NETS = [ipaddress.ip_network(c) for cidrs in CDN_RANGES.values() for c in cidrs]

# Response headers that sometimes disclose a backend / client address.
IP_LEAK_HEADERS = ("x-real-ip", "x-forwarded-for", "x-cluster-client-ip", "x-client-ip",
                   "client-ip", "x-backend-server", "x-originating-ip", "x-server-ip", "via")
ORIGIN_METHOD_WEIGHTS = {"headers": 8, "san": 6, "mx": 4}
ORIGIN_MIN_SCORE = 10
ORIGIN_MAX_NAMES = 25          # SAN names resolved per host
ORIGIN_MAX_CANDIDATES = 10     # candidates probed per host
HSTS_MIN_MAX_AGE = _tune("hsts_min_max_age", 15552000)    # 180 days

# Per-response cap for audited hosts: a hostile or broken host can't exhaust memory
# or stall a worker with a huge or slow-drip body. Bodies beyond it are cut and the
# record says so (body_truncated=Yes). Tunable 64 KiB..50 MiB.
MAX_BODY_BYTES = _tune("max_body_bytes", 2 * 1024 * 1024)
if not 64 * 1024 <= MAX_BODY_BYTES <= 50 * 1024 * 1024:
    sys.stderr.write("[warn] tuning 'max_body_bytes' out of range (64 KiB-50 MiB); using 2 MiB\n")
    MAX_BODY_BYTES = 2 * 1024 * 1024

# Subdomain-takeover fingerprints: provider substring -> body signatures.
TAKEOVER_PROVIDERS = {
    "azurewebsites.net": ["404", "web app doesn't exist", "error 404"],
    "azureedge.net": ["404", "no route matches"],
    "cloudapp.azure.com": ["404", "cloudapp.azure.com page not found"],
    "cloudapp.net": ["404", "page not found"],
    "trafficmanager.net": ["404", "traffic manager"],
    "amazonaws.com": ["nosuchbucket", "the specified bucket does not exist", "no such bucket"],
    "s3-website": ["nosuchbucket", "no such bucket"],
    "cloudfront.net": ["bad request", "viewererrorpagenotfound"],
    "elasticbeanstalk.com": [],            # NXDOMAIN-only (see NXDOMAIN_ONLY_PROVIDERS)
    "herokudns.com": ["no such app"],
    "herokuapp.com": ["no such app", "heroku | no such app"],
    "github.io": ["there isn't a github pages site here", "404"],
    "fastly.net": ["fastly error: unknown domain"],
    "pantheonsite.io": ["the gods are wise", "site not found", "404 error unknown site"],
    "wpengine.com": ["this domain is not configured"],
    "kinstacdn.com": ["no site found"],
    "vercel.app": ["the deployment could not be found"],
    "netlify.app": ["not found - request id"],
    "myshopify.com": ["sorry, this shop is currently unavailable"],
    "bigcartel.com": ["oops! we couldn't find that page"],
    "readme.io": ["project doesn't exist", "project doesnt exist",
                  "the creators of this project are still working on making everything perfect"],
    "zendesk.com": ["this help center no longer exists"],
    "surge.sh": ["project not found"],
    "ghost.io": ["this site is no longer available", "failed to resolve dns path for this host"],
    "bitbucket.io": ["repository not found"],
    "gitlab.io": ["the page you're looking for could not be found"],
    "webflow.io": ["the page you are looking for doesn't exist"],
    "unbounce.com": ["the requested url was not found"],
    "uservoice.com": ["this uservoice subdomain is currently available"],
    "squarespace.com": ["no such account"],
    "tilda.ws": ["please renew your subscription"],
    # Added from the community can-i-take-over-xyz list (status: Vulnerable). More can be
    # loaded at runtime with --takeover-sigs FILE (same JSON format).
    "agilecrm.com": ["sorry, this page is no longer available."],
    "animaapp.io": ["the page you were looking for does not exist."],
    "hatenablog.com": ["404 blog is not found"],
    "helpjuice.com": ["we could not find what you're looking for."],
    "helpscoutdocs.com": ["no settings were found for this company:"],
    "youtrack.cloud": ["is not a registered incloud youtrack"],
    "surveysparrow.com": ["account not found."],
    "uberflip.com": ["the url you've accessed does not provide a hub."],
    "strikinglydns.com": ["page not found."],
    "worksites.net": ["sorry, but the website you"],
    "furyns.com": ["404: this page could not be found."],
    "ngrok.io": ["ngrok.io not found"],
    "wordpress.com": ["do you want to register"],
    # NXDOMAIN-class: claimable only when the target itself does not resolve.
    "trydiscourse.com": [],
    "blob.core.windows.net": [], "azure-api.net": [], "azurehdinsight.net": [],
    "azurecontainer.io": [], "database.windows.net": [], "azuredatalakestore.net": [],
    "search.windows.net": [], "azurecr.io": [], "redis.cache.windows.net": [],
    "servicebus.windows.net": [], "visualstudio.com": [],
}

# Providers where a takeover requires the CNAME target to be authoritatively
# NXDOMAIN (i.e. the label is free to re-register), NOT merely a "404" body.
# For these, a served HTTP body proves the target RESOLVES -> a live/owned app
# returning 404, which is the opposite of claimable. (Azure Traffic Manager /
# classic cloud services fall here; e.g. a brand careers host returns 404 but its TM
# profile is live.) The resolve-to-provider class above (github.io, S3,
# azurewebsites, ...) is different: there the name resolves to the provider and
# the provider itself serves the "no such site" fingerprint, so a body signature
# IS the valid signal.
NXDOMAIN_ONLY_PROVIDERS = (
    "trafficmanager.net", "cloudapp.azure.com", "cloudapp.net", "elasticbeanstalk.com",
    "trydiscourse.com", "blob.core.windows.net", "azure-api.net", "azurehdinsight.net",
    "azurecontainer.io", "database.windows.net", "azuredatalakestore.net",
    "search.windows.net", "azurecr.io", "redis.cache.windows.net", "servicebus.windows.net",
    "visualstudio.com")
# merge=True: a tuning file can ADD providers but never drop one, because dropping
# a provider removes its NXDOMAIN gate and turns ordinary 404s into takeover findings.
NXDOMAIN_ONLY_PROVIDERS = tuple(_tune("nxdomain_only_providers", list(NXDOMAIN_ONLY_PROVIDERS), merge=True))

RESOLVER = dns.resolver.Resolver()
RESOLVER.nameservers = DNS_SERVERS
RESOLVER.timeout = 2.5
RESOLVER.lifetime = 5.0
RESOLVER.cache = dns.resolver.LRUCache()

_print_lock = threading.Lock()
STOP = threading.Event()          # set on SIGINT so workers short-circuit
_DNS_RETRIES = 0                  # extra DNS attempts on timeout (raised by --accurate)


# =====================================================================
# RATE LIMITER (global, thread-safe token drip)
# =====================================================================

class RateLimiter:
    """Allow at most `rate` acquisitions per second across all threads (0 = off)."""
    def __init__(self, rate: float):
        self.min_interval = 1.0 / rate if rate and rate > 0 else 0.0
        self._lock = threading.Lock()
        self._next = 0.0

    def wait(self) -> None:
        if not self.min_interval:
            return
        with self._lock:
            now = time.monotonic()
            sleep_for = self._next - now
            if sleep_for > 0:
                time.sleep(sleep_for)
                now = time.monotonic()
            self._next = max(now, self._next) + self.min_interval


RL = RateLimiter(0)  # replaced in main()


# =====================================================================
# PURE-PYTHON MURMURHASH3 (x86_32, signed) — replaces the mmh3 dependency
# =====================================================================

def murmur3_x86_32(data: bytes, seed: int = 0) -> int:
    """MurmurHash3 x86_32 returning a signed 32-bit int, matching mmh3.hash()."""
    c1, c2 = 0xCC9E2D51, 0x1B873593
    length = len(data)
    h1 = seed & 0xFFFFFFFF
    rounded_end = length & ~0x03

    for i in range(0, rounded_end, 4):
        k1 = (data[i] | (data[i + 1] << 8) |
              (data[i + 2] << 16) | (data[i + 3] << 24)) & 0xFFFFFFFF
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1
        h1 = ((h1 << 13) | (h1 >> 19)) & 0xFFFFFFFF
        h1 = (h1 * 5 + 0xE6546B64) & 0xFFFFFFFF

    k1 = 0
    tail = length & 0x03
    if tail == 3:
        k1 ^= data[rounded_end + 2] << 16
    if tail >= 2:
        k1 ^= data[rounded_end + 1] << 8
    if tail >= 1:
        k1 ^= data[rounded_end]
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1

    h1 ^= length
    h1 ^= h1 >> 16
    h1 = (h1 * 0x85EBCA6B) & 0xFFFFFFFF
    h1 ^= h1 >> 13
    h1 = (h1 * 0xC2B2AE35) & 0xFFFFFFFF
    h1 ^= h1 >> 16
    return h1 - 0x100000000 if h1 & 0x80000000 else h1


# =====================================================================
# HOST NORMALIZATION
# =====================================================================

_CP1252_SLOPPY = {0x81, 0x8d, 0x8f, 0x90, 0x9d}  # byte positions undefined in CP1252


def _sloppy_cp1252_bytes(s: str) -> bytes:
    """Encode as Windows-1252, passing the five undefined byte positions
    (0x81/0x8d/0x8f/0x90/0x9d) through as their raw C1 values — what ftfy calls
    'sloppy-windows-1252'. Needed to reverse mojibake whose original UTF-8 bytes
    included one of those (e.g. a katakana brand IDN exported in the wrong codec)."""
    out = bytearray()
    for ch in s:
        try:
            out += ch.encode("cp1252")
        except UnicodeEncodeError:
            if ord(ch) in _CP1252_SLOPPY:
                out.append(ord(ch))
            else:
                raise
    return bytes(out)


def _repair_mojibake(s: str) -> str:
    """Recover UTF-8 text that was mis-saved as Latin-1/CP1252 (e.g. an IDN list
    exported in the wrong encoding: 'ãƒ‰ãƒ¡ã‚¤ãƒ³' -> 'ドメイン'). Correctly
    encoded UTF-8 IDNs have codepoints >255 and fail the encode step, so they're
    left untouched — only genuine mojibake is repaired. Iterates so double/triple
    encodings unwind, and uses sloppy-CP1252 so entries with 0x8d-class bytes
    (which strict CP1252 would reject and drop) are recovered too."""
    if s.isascii():
        return s
    cur = s
    for _ in range(4):  # double/triple mojibake needs more than one pass
        for enc in (_sloppy_cp1252_bytes, lambda x: x.encode("latin-1")):
            try:
                fixed = enc(cur).decode("utf-8")
            except (UnicodeEncodeError, UnicodeDecodeError):
                continue
            if fixed != cur and "�" not in fixed:
                cur = fixed
                break
        else:
            break  # no encoding made progress → stable
    return cur


def normalize_host(line: str) -> Optional[str]:
    """Clean an input line into a bare hostname (strip scheme/path/port, IDN-encode).
    Repairs mojibake IDNs and returns None for hostnames that cannot be encoded."""
    s = line.strip()
    if not s or s.startswith("#"):
        return None
    if "://" in s:
        s = urlparse(s).netloc or urlparse("//" + s).netloc
    s = s.split("/")[0].split("@")[-1]
    if s.startswith("[") and "]" in s:            # bracketed IPv6
        s = s[1:s.index("]")]
    elif s.count(":") == 1:                        # host:port (not IPv6)
        s = s.split(":")[0]
    s = _repair_mojibake(s).strip(".").lower()
    if not s:
        return None
    try:
        ipaddress.ip_address(s)
        return s
    except ValueError:
        pass
    if s.isascii():
        return s  # already a plain ASCII hostname
    if _HAVE_IDNA:
        try:
            return idna.encode(s, uts46=True).decode("ascii")
        except idna.IDNAError:
            pass
    try:
        return s.encode("idna").decode("ascii")
    except Exception:
        return None  # non-ASCII that cannot be IDNA-encoded is not a valid host


# =====================================================================
# DATA RECORD
# =====================================================================

@dataclass
class AuditRecord:
    domain: str
    dns_status: str = "N/A"             # OK / NXDOMAIN / NOANSWER / SERVFAIL / TIMEOUT
    ac: str = "N/A"
    ip: str = "N/A"
    is_private_ip: str = "No"
    ipv6: str = "N/A"
    a_records: str = "N/A"             # all resolved A records
    ptr: str = "N/A"                   # reverse DNS of primary IP
    dnssec: str = "N/A"                # Yes/No (AD flag from validating resolver)
    wildcard: str = "No"
    ns_servers: str = "N/A"
    cname: str = "N/A"
    asn: str = "N/A"
    country: str = "N/A"
    city: str = "N/A"
    org_range: str = "No"
    cdn: str = "No"
    rdap_registrar: str = "N/A"
    rdap_created: str = "N/A"
    rdap_expires: str = "N/A"
    domain_age_days: str = "N/A"
    rdap_status: str = "N/A"
    tls_health: str = "N/A"
    tls_valid: str = "N/A"             # valid / expired / hostname-mismatch / self-signed / untrusted
    tls_min: str = "N/A"
    tls_max: str = "N/A"
    tls_cipher: str = "N/A"
    jarm: str = "N/A"
    http_status: str = "0"
    https_status: str = "0"
    axfr_vuln: str = "No"
    page_title: str = "N/A"
    final_url: str = "N/A"
    is_forwarded: str = "No"
    redirect_quality: str = "N/A"
    is_login_page: str = "No"
    has_login_form: str = "No"
    microsoft_tenant_id: str = "N/A"
    auth_pages: str = "N/A"            # --auth-paths: /path(login|reset) pages found beyond the landing page
    auth_sso: str = "N/A"              # --auth-paths: external hosts that login paths redirect to
    m365_realm: str = "N/A"            # --auth-paths: Managed / Federated(host) for the apex domain
    size: int = 0
    latency_ms: str = "N/A"
    content_type: str = "N/A"
    body_sha256: str = "N/A"
    redirect_count: int = 0
    server: str = "N/A"
    powered_by: str = "N/A"
    cookie_names: str = "N/A"
    cookie_flags: str = "N/A"          # name(!Secure,HttpOnly,SameSite=Lax) per cookie; ! = missing
    cookie_no_secure: str = "None"     # cookies set over HTTPS without the Secure flag
    session_cookie_no_httponly: str = "None"
    cms: str = "N/A"
    emails: str = "None"
    favicon_hash: str = "N/A"
    shodan_favicon_query: str = "N/A"
    identified_tech: str = "Unknown"
    sec_headers_missing: str = "N/A"
    hsts: str = "No"
    hsts_max_age: str = "N/A"          # seconds from the HTTPS response, "invalid" if unparseable
    hsts_flags: str = "N/A"            # includeSubDomains / preload
    csp: str = "No"
    scanner_findings: str = "None"     # --ingest: severity:template-id from nuclei results (worst first)
    scanner_max_severity: str = "N/A"  # --ingest: critical/high/medium/low/info
    httpx_tech: str = "N/A"            # --ingest: technologies reported by httpx
    csp_issues: str = "None"           # unsafe-inline / unsafe-eval / wildcard-script-src / ...
    frame_protection: str = "N/A"      # csp / xfo / both / none (clickjacking)
    version_disclosure: str = "None"   # Server / X-Powered-By values carrying a version number
    cors: str = "N/A"                  # --cors: none / restricted / wildcard / reflects-origin[+credentials] / null-origin
    security_txt: str = "N/A"          # --harvest: valid / expired / no-contact / no-expires / missing
    xframe: str = "No"
    spf: str = "None"
    spf_issues: str = "None"
    spf_lookups: str = "N/A"           # DNS lookups across the whole include chain (limit 10)
    spf_chain_issues: str = "None"     # include_no_spf(x) / include_unregistered(x) / broad_ip4(x) ...
    dmarc: str = "None"
    dmarc_issues: str = "None"
    mx_records: str = "None"
    mta_sts: str = "N/A"               # absent / enforce / testing / mode-none / policy-unreachable / policy-invalid
    tls_rpt: str = "N/A"               # Yes/No (_smtp._tls TXT)
    bimi: str = "N/A"                  # Yes/No (default._bimi TXT)
    dane: str = "N/A"                  # Yes/No (TLSA on MX hosts; needs DNSSEC)
    dkim_selectors: str = "N/A"        # --dkim: selector(bits) found among common selectors
    dkim_weak: str = "None"            # --dkim: selector:bits below DKIM_MIN_BITS
    soa_record: str = "N/A"
    caa_records: str = "None"
    txt_entropy_keys: str = "None"
    page_type: str = "N/A"
    dangling_status: str = "No"
    dangling_detail: str = "N/A"
    takeover_risk: str = "No"
    takeover_detail: str = "N/A"
    ports: str = ""
    port_banners: str = "N/A"
    supply_chain_scripts: str = "None"
    api_endpoints: str = "None"
    disclosed_paths: str = "None"
    code_comments: str = "None"
    copyright_year: str = "N/A"
    cert_subject: str = "N/A"
    cert_issuer: str = "N/A"
    cert_not_before: str = "N/A"
    cert_expiry: str = "N/A"
    cert_days_left: str = "N/A"
    cert_sha256: str = "N/A"
    cert_sans: str = "N/A"
    cert_key: str = "N/A"              # RSA-2048 / EC-secp256r1 / Ed25519 ...
    cert_sig_alg: str = "N/A"          # signature hash (sha256, sha1, md5 ...)
    cert_sct_count: str = "N/A"        # embedded CT SCTs
    cert_revocation: str = "N/A"       # which of ocsp,crl the cert advertises (or none)
    tls_ocsp_stapling: str = "N/A"     # --ocsp: stapled(good|revoked|unknown) / not-stapled
    discovered_domains: str = "None"   # SANs + external CNAME targets (loop-back)
    origin_exposed: str = "No"         # --origin: Yes (cert match) / Possibly / No
    origin_candidates: str = "None"    # --origin: ip(score=N;methods=a+b[;cert-match])
    disposition: str = "N/A"           # dead-dns/dead-nohttp/redirect-offsite/redirect-approved/parked/live
    is_subdomain: str = "No"           # discovered via subdomain enumeration
    mx_approved: str = "N/A"           # Yes/No/None — does mail route via the approved domain
    independent_mail: str = "No"       # has its own MX not under the approved domain
    service_independent: str = "No"    # live service NOT redirecting to the approved domain
    config_issues: str = "None"        # actionable, fixable misconfigurations
    dirty_forwarding: str = "No"
    risk_score: int = 0
    score_notes: str = ""
    error: str = ""
    body_truncated: str = "No"   # Yes = response cut at MAX_BODY_BYTES / deadline


FIELDNAMES = [f.name for f in AuditRecord.__dataclass_fields__.values()]


# =====================================================================
# DNS
# =====================================================================

@lru_cache(maxsize=200000)
def _resolve(domain: str, rtype: str) -> Tuple[str, ...]:
    try:
        ans = RESOLVER.resolve(domain, rtype)
        if rtype == "NS":
            return tuple(str(r.target).rstrip(".").lower() for r in ans)
        if rtype == "TXT":
            return tuple("".join(
                s.decode("utf-8", "ignore") if isinstance(s, bytes) else s
                for s in r.strings) for r in ans)
        if rtype == "MX":
            return tuple(f"{r.preference} {str(r.exchange).rstrip('.')}" for r in ans)
        return tuple(str(r).rstrip(".") for r in ans)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers,
            dns.exception.Timeout):
        return ()
    except Exception:
        return ()


@lru_cache(maxsize=200000)
def resolve_a_status(domain: str) -> Tuple[Tuple[str, ...], str]:
    """A-record lookup that reports the DNS failure mode for triage.
    Retries on timeout when --accurate raised _DNS_RETRIES."""
    for attempt in range(_DNS_RETRIES + 1):
        try:
            ans = RESOLVER.resolve(domain, "A")
            return tuple(str(r).rstrip(".") for r in ans), "OK"
        except dns.resolver.NXDOMAIN:
            return (), "NXDOMAIN"
        except dns.resolver.NoAnswer:
            return (), "NOANSWER"
        except dns.resolver.NoNameservers:
            return (), "SERVFAIL"
        except dns.exception.Timeout:
            if attempt < _DNS_RETRIES:
                continue
            return (), "TIMEOUT"
        except Exception:
            return (), "ERROR"
    return (), "TIMEOUT"


def cname_chain(host: str, limit: int = 8) -> List[str]:
    chain, current, seen = [], host, set()
    for _ in range(limit):
        if current in seen:
            break
        seen.add(current)
        recs = _resolve(current, "CNAME")
        if not recs:
            break
        tgt = recs[0].rstrip(".").lower()
        chain.append(tgt)
        current = tgt
    return chain


@lru_cache(maxsize=100000)
def wildcard_ips(parent: str) -> Tuple[str, ...]:
    """Resolve a random label under `parent`; a hit means the zone is wildcarded."""
    rand = "".join(random.choices(string.ascii_lowercase + string.digits, k=20))
    try:
        ans = RESOLVER.resolve(f"{rand}.{parent}", "A")
        return tuple(str(r) for r in ans)
    except Exception:
        return ()


def get_dns_audit(domain: str, rec: AuditRecord) -> Dict[str, Any]:
    chain = cname_chain(domain)
    if chain:
        rec.cname = " -> ".join(chain)

    a_records, rec.dns_status = resolve_a_status(domain)
    if a_records:
        rec.ip = a_records[0]
        rec.ac = rec.ip
        rec.a_records = ",".join(a_records)
    elif chain:
        rec.ac = chain[-1]

    aaaa = _resolve(domain, "AAAA")
    if aaaa:
        rec.ipv6 = aaaa[0]

    rec.dnssec = check_dnssec(domain)

    # Wildcard check (only meaningful for subdomains, not apex).
    parts = domain.split(".")
    if len(parts) > 2 and rec.ip != "N/A":
        wc = wildcard_ips(".".join(parts[1:]))
        if wc and rec.ip in wc:
            rec.wildcard = "Yes"

    ns_records: Tuple[str, ...] = ()
    for i in range(len(parts) - 1):
        ns_records = _resolve(".".join(parts[i:]), "NS")
        if ns_records:
            rec.ns_servers = ",".join(sorted(ns_records))
            break

    txts = _resolve(domain, "TXT")
    spf_info = parse_spf(list(txts))
    if spf_info["spf_present"]:
        rec.spf = spf_info["spf_record"]
    if spf_info["spf_issues"]:
        rec.spf_issues = ",".join(spf_info["spf_issues"])
    keys = [t[:20] + "..." for t in txts
            if "v=spf1" not in t.lower() and re.search(r"[A-Za-z0-9/+_-]{32,}", t)]
    if keys:
        rec.txt_entropy_keys = ",".join(keys[:3])

    dmarc_txts = list(_resolve(f"_dmarc.{domain}", "TXT"))
    inherited = False
    if not any(t.lower().startswith("v=dmarc1") for t in dmarc_txts) and len(parts) > 2:
        parent = list(_resolve(f"_dmarc.{'.'.join(parts[1:])}", "TXT"))
        if any(t.lower().startswith("v=dmarc1") for t in parent):
            dmarc_txts, inherited = parent, True
    dmarc_info = parse_dmarc(dmarc_txts)
    if dmarc_info["dmarc_present"]:
        rec.dmarc = dmarc_info["dmarc_record"] + (" (Inherited)" if inherited else "")
    if dmarc_info["dmarc_issues"]:
        rec.dmarc_issues = ",".join(dmarc_info["dmarc_issues"])

    mx = _resolve(domain, "MX")
    if mx:
        rec.mx_records = ",".join(sorted(mx))
    soa = _resolve(domain, "SOA")
    if soa:
        rec.soa_record = soa[0]
    caa = _resolve(domain, "CAA")
    if caa:
        rec.caa_records = ",".join(caa)

    return {"chain": chain, "ns": list(ns_records), "a_records": list(a_records),
            "aaaa": list(aaaa), "txts": list(txts),
            "has_resolution": bool(a_records or aaaa or chain)}


@lru_cache(maxsize=100000)
def check_dnssec(domain: str) -> str:
    """Ask a validating resolver; the AD (Authenticated Data) flag => DNSSEC-signed."""
    try:
        q = dns.message.make_query(domain, "A", want_dnssec=True)
        for server in RESOLVER.nameservers:
            try:
                r = dns.query.udp(q, server, timeout=3)
                return "Yes" if (r.flags & dns.flags.AD) else "No"
            except Exception:
                continue
    except Exception:
        pass
    return "N/A"


@lru_cache(maxsize=100000)
def reverse_dns(ip: str) -> str:
    if ip == "N/A":
        return "N/A"
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return "N/A"


# Fallback multi-label suffixes if the Public Suffix List isn't available.
_MULTI_SUFFIXES = {"co.uk", "org.uk", "gov.uk", "ac.uk", "co.jp", "com.au",
                   "co.nz", "com.br", "co.za", "com.cn", "co.in"}

# Public Suffix List via tldextract (bundled snapshot, works offline). Without it,
# multi-part ccTLDs like com.ro / co.kr are mis-parsed, which makes CT/Censys
# enumeration query an entire public suffix and pull in unrelated domains.
try:
    import tldextract
    # include_psl_private_domains=True so free-hosting/second-level registries in
    # the PSL private section (net.ru, com.ru, github.io, ...) are treated as
    # public suffixes — otherwise we'd enumerate an entire *.net.ru registry.
    _TLDX = tldextract.TLDExtract(cache_dir="/tmp/tldextract_cache",
                                  include_psl_private_domains=True)
    _TLDX("example.com")  # warm/validate the bundled snapshot
    _HAVE_PSL = True
except Exception:
    _HAVE_PSL = False


def registrable_domain(host: str) -> str:
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
    # fallback heuristic
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    last2 = ".".join(parts[-2:])
    if last2 in _MULTI_SUFFIXES:
        return ".".join(parts[-3:])
    return last2


@lru_cache(maxsize=50000)
def get_rdap(domain: str) -> Tuple[str, str, str, str, str, dict]:
    """RDAP over HTTPS (no dependency). Returns registrar, created, expires,
    age_days, status, raw. Great for spotting freshly-registered look-alikes."""
    reg = registrable_domain(domain)
    RL.wait()
    try:
        # RDAP servers commonly 403 browser-like UAs; use a neutral client UA.
        r = requests.get(f"https://rdap.org/domain/{reg}", timeout=8,
                         headers={"User-Agent": f"clipeus/{__version__} (RDAP client)"})
        if r.status_code != 200:
            return "N/A", "N/A", "N/A", "N/A", "N/A", {}
        d = r.json()
    except Exception:
        return "N/A", "N/A", "N/A", "N/A", "N/A", {}

    registrar = "N/A"
    for ent in d.get("entities", []):
        if "registrar" in ent.get("roles", []):
            for v in ent.get("vcardArray", [[], []])[1]:
                if v and v[0] == "fn":
                    registrar = v[3]
                    break
    created = expires = "N/A"
    for ev in d.get("events", []):
        act = ev.get("eventAction", "")
        if act == "registration":
            created = ev.get("eventDate", "N/A")[:10]
        elif act == "expiration":
            expires = ev.get("eventDate", "N/A")[:10]
    age_days = "N/A"
    if created != "N/A":
        try:
            from datetime import datetime, timezone
            dt = datetime.fromisoformat(created)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            age_days = str((datetime.now(timezone.utc) - dt).days)
        except Exception:
            pass
    status = ",".join(d.get("status", [])) or "N/A"
    raw = {"registrar": registrar, "status": d.get("status", []),
           "events": d.get("events", []), "nameservers":
           [n.get("ldhName") for n in d.get("nameservers", [])]}
    return registrar, created, expires, age_days, status, raw


# TLD -> whois server for the fallback path (RDAP-less registries like SWITCH/.ch).
_TLD_WHOIS = {"ch": "whois.nic.ch", "li": "whois.nic.li"}


@lru_cache(maxsize=2000)
def _iana_whois_server(tld: str) -> Optional[str]:
    try:
        resp = _whois_raw("whois.iana.org", tld)
        for line in resp.splitlines():
            if line.lower().startswith("refer:"):
                return line.split(":", 1)[1].strip()
    except Exception:
        pass
    return None


def _whois_raw(server: str, query: str) -> str:
    with socket.create_connection((server, 43), timeout=12) as s:
        s.sendall((query + "\r\n").encode())
        chunks = []
        while True:
            data = s.recv(4096)
            if not data:
                break
            chunks.append(data)
        return b"".join(chunks).decode("utf-8", "ignore")


@lru_cache(maxsize=50000)
def whois_fallback(domain: str) -> Tuple[str, str, str, str, dict]:
    """Raw port-43 WHOIS for registries without public RDAP (e.g. SWITCH/.ch).
    Returns registrar, created, status, source, raw. Dates are often withheld
    (SWITCH redacts them), so `created` may stay N/A while registrar/NS resolve."""
    reg = registrable_domain(domain)
    tld = reg.rsplit(".", 1)[-1].lower()
    server = _TLD_WHOIS.get(tld) or _iana_whois_server(tld)
    if not server:
        return "N/A", "N/A", "N/A", "N/A", {}
    RL.wait()
    try:
        resp = _whois_raw(server, reg)
    except Exception:
        return "N/A", "N/A", "N/A", "N/A", {}

    low = resp.lower()
    # Registered? Most registries echo the domain or say "no match" when free.
    if any(m in low for m in ("no match", "not found", "no entries found",
                              "no object found", "is available")):
        return "N/A", "N/A", "unregistered", server, {"raw": resp[:2000]}

    def grab(labels):
        for i, line in enumerate(resp.splitlines()):
            for lab in labels:
                if line.lower().strip().startswith(lab):
                    val = line.split(":", 1)[1].strip() if ":" in line else ""
                    # SWITCH puts the value on the NEXT line under a bare label.
                    if not val:
                        rest = resp.splitlines()[i + 1:i + 3]
                        val = next((r.strip() for r in rest if r.strip()), "")
                    if val:
                        return val
        return "N/A"

    registrar = grab(["registrar:", "registrar name:", "sponsoring registrar:"])
    created = grab(["creation date:", "created:", "registered on:",
                    "registration date:", "created on:"])[:10]
    status = grab(["domain status:", "status:", "eppstatus:"])
    return registrar, created if created != "N/A" else "N/A", status, server, {"raw": resp[:3000]}


def check_axfr(domain: str, ns_servers: str) -> str:
    if ns_servers == "N/A":
        return "No"
    for ns in ns_servers.split(","):
        try:
            z = dns.zone.from_xfr(dns.query.xfr(ns.strip(), domain, timeout=3))
            if z:
                return "Vulnerable"
        except Exception:
            continue
    return "No"


def parse_spf(txts: List[str]) -> Dict[str, Any]:
    spf = [t for t in txts if t.lower().startswith("v=spf1")]
    res = {"spf_present": bool(spf), "spf_record": spf[0] if spf else None, "spf_issues": []}
    if not spf:
        res["spf_issues"].append("spf_missing")
        return res
    if len(spf) > 1:
        res["spf_issues"].append("spf_multiple_records")
    tokens = spf[0].split()
    all_mech = next((t for t in tokens if t.endswith("all")), None)
    if not all_mech:
        res["spf_issues"].append("spf_no_all")
    elif all_mech in ("+all", "?all"):
        res["spf_issues"].append("spf_all_too_permissive")
    elif all_mech == "~all":
        res["spf_issues"].append("spf_softfail_all")
    if any(t.startswith("ptr") for t in tokens):
        res["spf_issues"].append("spf_uses_ptr")
    lookups = sum(1 for t in tokens
                  if t.startswith(("include:", "redirect=", "exists:", "a:", "mx:")))
    lookups += sum(1 for t in tokens if t in ("a", "mx"))
    if lookups > 10:
        res["spf_issues"].append("spf_lookup_limit_exceeded")
    elif lookups > 8:
        res["spf_issues"].append("spf_lookup_near_limit")
    return res


SPF_MAX_QUERIES = _tune("spf_max_queries", 30)   # DNS queries spent walking one include chain
SPF_BROAD_V4, SPF_BROAD_V6 = 16, 32


@lru_cache(maxsize=50000)
def _spf_txt(name: str) -> Tuple[str, ...]:
    return tuple(t for t in _resolve(name, "TXT") if t.lower().startswith("v=spf1"))


@lru_cache(maxsize=50000)
def _unregistered(reg_domain: str) -> bool:
    return _target_claimable_nxdomain(reg_domain)


def analyze_spf_chain(domain: str, record: str) -> Dict[str, Any]:
    """Walk include:/redirect= recursively. Returns total DNS lookups (RFC 7208 limit: 10)
    and problems: includes with no SPF record, includes whose registrable domain is
    unregistered (anyone can register it and authorise senders), loops, oversized ranges."""
    state = {"lookups": 0, "queries": 0}
    issues: List[str] = []

    def walk(name: str, rec_text: str, path: Tuple[str, ...]) -> None:
        for tok in rec_text.split()[1:]:
            t = tok.lstrip("+-~?")
            low = t.lower()
            if low.startswith(("ip4:", "ip6:")):
                if not path:                       # only judge ranges the domain itself publishes
                    try:
                        net = ipaddress.ip_network(t[4:], strict=False)
                        limit = SPF_BROAD_V4 if net.version == 4 else SPF_BROAD_V6
                        if net.prefixlen <= limit:
                            issues.append(f"broad_range({net})")
                    except ValueError:
                        pass
                continue
            if low.startswith("include:"):
                target = t[8:]
            elif low.startswith("redirect="):
                target = t[9:]
            elif (low in ("a", "mx", "ptr") or low.startswith(("a:", "a/", "mx:", "mx/", "ptr:", "exists:"))):
                state["lookups"] += 1
                continue
            else:
                continue
            state["lookups"] += 1
            target = target.lower().rstrip(".")
            if not target or "%" in target:         # empty or macro-expanded: cannot follow
                continue
            if target in path or target == domain:
                issues.append(f"include_loop({target})")
                continue
            if state["queries"] >= SPF_MAX_QUERIES:
                if "chain_truncated" not in issues:
                    issues.append("chain_truncated")
                return
            state["queries"] += 1
            recs = _spf_txt(target)
            if not recs:
                reg = registrable_domain(target)
                issues.append(f"include_unregistered({reg})" if _unregistered(reg)
                              else f"include_no_spf({target})")
                continue
            walk(target, recs[0], path + (target,))

    walk(domain, record, ())
    return {"lookups": state["lookups"], "issues": list(dict.fromkeys(issues))}


def parse_dmarc(txts: List[str]) -> Dict[str, Any]:
    dmarc = [t for t in txts if t.lower().startswith("v=dmarc1")]
    res = {"dmarc_present": bool(dmarc), "dmarc_record": dmarc[0] if dmarc else None,
           "dmarc_issues": []}
    if not dmarc:
        res["dmarc_issues"].append("dmarc_missing")
        return res
    tags = {}
    for part in dmarc[0].split(";"):
        part = part.strip()
        if "=" in part:
            k, v = part.split("=", 1)
            tags[k.strip().lower()] = v.strip()
    policy = tags.get("p")
    if not policy or policy == "none":
        res["dmarc_issues"].append("dmarc_policy_none")
    elif policy == "quarantine":
        res["dmarc_issues"].append("dmarc_policy_quarantine")
    if not tags.get("rua"):
        res["dmarc_issues"].append("dmarc_rua_missing")
    pct = tags.get("pct")
    if pct and pct.isdigit() and int(pct) < 100:
        res["dmarc_issues"].append("dmarc_pct_not_100")
    return res


def detect_dangling(domain: str, chain: List[str], ns: List[str],
                    has_resolution: bool) -> Tuple[str, str]:
    if chain:
        final = chain[-1]
        try:
            RESOLVER.resolve(final, "A")
        except dns.resolver.NXDOMAIN:
            return "Yes", f"CNAME target NXDOMAIN: {final}"
        except dns.resolver.NoAnswer:
            return "Possibly", f"CNAME target has no A/AAAA: {final}"
        except dns.exception.Timeout:
            return "Possibly", f"CNAME target timeout: {final}"
        except Exception:
            pass
    if ns:
        unresolved = []
        for server in ns:
            # Resolve NS names through the configured RESOLVER (Cloudflare-first),
            # NOT socket.gethostbyname() — the latter leaks to the system resolver
            # (here: Tailscale MagicDNS), which can filter/answer differently and
            # skew the takeover heuristic. NXDOMAIN => genuinely unresolvable.
            try:
                RESOLVER.resolve(server, "A")
            except dns.resolver.NXDOMAIN:
                unresolved.append(server)
            except Exception:
                # NoAnswer (name exists, maybe AAAA-only), timeout, SERVFAIL:
                # don't flag as unresolvable — avoids false takeover positives.
                pass
        if unresolved and len(unresolved) == len(ns):
            return "Yes", f"All NS unresolvable: {','.join(unresolved)}"
        if unresolved:
            return "Possibly", f"Some NS unresolvable: {','.join(unresolved)}"
    if not has_resolution and ns:
        return "Possibly", "Has NS but no A/AAAA/CNAME resolution"
    return "No", "N/A"


def _target_claimable_nxdomain(target: str) -> bool:
    """True only if `target` is authoritatively NXDOMAIN (the label is free to
    re-register), resolved through the configured Cloudflare-first RESOLVER. A
    NoAnswer (name exists via AAAA/CNAME) or any resolution => NOT claimable."""
    try:
        RESOLVER.resolve(target, "A")
        return False
    except dns.resolver.NXDOMAIN:
        return True
    except dns.resolver.NoAnswer:
        return not (_resolve(target, "AAAA") or _resolve(target, "CNAME"))
    except Exception:
        return False


def load_takeover_fingerprints(path: str) -> int:
    """Merge a can-i-take-over-xyz style fingerprints.json into the takeover tables.
    Only `vulnerable` entries with a hostname CNAME are used; "NXDOMAIN" fingerprints go to
    the NXDOMAIN-only set, HTTP-status / regex fingerprints are skipped. Returns entries added."""
    global NXDOMAIN_ONLY_PROVIDERS
    with open(path, encoding="utf-8") as fh:
        entries = json.load(fh)
    added = 0
    for e in entries if isinstance(entries, list) else []:
        if not isinstance(e, dict) or not e.get("vulnerable"):
            continue
        fp = str(e.get("fingerprint") or "").strip()
        if fp.startswith("HTTP_STATUS") or ".*" in fp:
            continue
        for cname in e.get("cname") or []:
            cname = str(cname).strip().lower()
            if not cname or re.fullmatch(r"[\d.]+", cname):
                continue
            if fp.upper() == "NXDOMAIN":
                if cname not in NXDOMAIN_ONLY_PROVIDERS:
                    NXDOMAIN_ONLY_PROVIDERS += (cname,)
                TAKEOVER_PROVIDERS.setdefault(cname, [])
                added += 1
            elif len(fp) >= 12:
                sigs = TAKEOVER_PROVIDERS.setdefault(cname, [])
                if fp.lower() not in sigs:
                    sigs.append(fp.lower())
                    added += 1
    return added


def detect_takeover(chain: List[str], body: str) -> Tuple[str, str]:
    if not chain:
        return "No", "N/A"
    body_l = html.unescape(body or "").lower()
    for tgt in chain:
        tl = tgt.lower()
        for provider, sigs in TAKEOVER_PROVIDERS.items():
            if provider in tl:
                # NXDOMAIN-class providers: a body signature is NOT sufficient —
                # verify the target is genuinely unresolvable/claimable, else a
                # live app's 404 becomes a false takeover.
                if any(p in tl for p in NXDOMAIN_ONLY_PROVIDERS):
                    if _target_claimable_nxdomain(tgt):
                        return "Yes", f"{provider} target NXDOMAIN (claimable)"
                    return "No", f"CNAME to {provider} but target resolves (live/owned)"
                # Resolve-to-provider class: the provider serves the unclaimed
                # fingerprint page, so a matching body signature is the signal.
                hit = next((s for s in sigs if s in body_l), None)
                if hit:
                    return "Yes", f"{provider} + signature '{hit}'"
                return "Possibly", f"CNAME to {provider} (no body signature)"
    return "No", "N/A"


# =====================================================================
# TLS
# =====================================================================

def get_tls(host: str) -> Dict[str, str]:
    out = {"health": "N/A", "valid": "N/A", "min": "N/A", "max": "N/A", "cipher": "N/A",
           "cert_subject": "N/A", "cert_issuer": "N/A", "cert_not_before": "N/A",
           "cert_expiry": "N/A", "cert_days_left": "N/A", "cert_sha256": "N/A",
           "cert_sans": "N/A", "cert_pem": "", "cert_key": "N/A", "cert_sig_alg": "N/A",
           "cert_sct_count": "N/A", "cert_revocation": "N/A"}
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, 443), timeout=2.5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ss:
                out["health"] = "Healthy"
                cipher = ss.cipher()
                if cipher:
                    out["cipher"] = cipher[0]
                der = ss.getpeercert(binary_form=True)
                if der:
                    _fill_cert(der, out)
    except Exception:
        return out

    out["valid"] = _validate_cert(host)

    found = []
    for name, ver in [("TLSv1.0", ssl.TLSVersion.TLSv1),
                      ("TLSv1.1", ssl.TLSVersion.TLSv1_1),
                      ("TLSv1.2", ssl.TLSVersion.TLSv1_2),
                      ("TLSv1.3", ssl.TLSVersion.TLSv1_3)]:
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            try:
                ctx.set_ciphers("ALL:@SECLEVEL=0")
            except ssl.SSLError:
                pass
            ctx.minimum_version = ctx.maximum_version = ver
            with socket.create_connection((host, 443), timeout=1.5) as sock:
                with ctx.wrap_socket(sock, server_hostname=host):
                    found.append(name)
        except Exception:
            continue
    if found:
        out["min"], out["max"] = found[0], found[-1]
    return out


def _validate_cert(host: str) -> str:
    """Second handshake with full validation; classify why it fails if it does."""
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=2.5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host):
                return "valid"
    except ssl.SSLCertVerificationError as e:
        reason = (str(e) or "").lower()
        if "expired" in reason:
            return "expired"
        if "hostname mismatch" in reason or "doesn't match" in reason:
            return "hostname-mismatch"
        if "self signed" in reason or "self-signed" in reason:
            return "self-signed"
        if "local issuer" in reason or "unable to get" in reason:
            return "untrusted-chain"
        return "invalid"
    except Exception:
        return "N/A"


def _fill_cert(der: bytes, out: Dict[str, str]) -> None:
    out["cert_sha256"] = hashlib.sha256(der).hexdigest()
    try:
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend
        cert = x509.load_der_x509_certificate(der, default_backend())
        out["cert_subject"] = cert.subject.rfc4514_string()[:80]
        out["cert_issuer"] = cert.issuer.rfc4514_string()[:80]
        expiry = getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after
        before = getattr(cert, "not_valid_before_utc", None) or cert.not_valid_before
        out["cert_expiry"] = expiry.strftime("%Y-%m-%d")
        out["cert_not_before"] = before.strftime("%Y-%m-%d")
        try:
            from datetime import datetime, timezone
            exp = expiry if expiry.tzinfo else expiry.replace(tzinfo=timezone.utc)
            out["cert_days_left"] = str((exp - datetime.now(timezone.utc)).days)
        except Exception:
            pass
        try:
            from cryptography.hazmat.primitives.serialization import Encoding
            out["cert_pem"] = cert.public_bytes(Encoding.PEM).decode("ascii")
        except Exception:
            pass
        try:
            ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            names = ext.value.get_values_for_type(x509.DNSName)
            if names:
                out["cert_sans"] = ",".join(sorted(set(names)))
        except x509.ExtensionNotFound:
            pass
        _fill_cert_hygiene(cert, out)
    except Exception:
        pass


def _fill_cert_hygiene(cert: Any, out: Dict[str, str]) -> None:
    """Key strength, signature hash, embedded SCTs and advertised revocation endpoints."""
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
    try:
        pk = cert.public_key()
        if isinstance(pk, rsa.RSAPublicKey):
            out["cert_key"] = f"RSA-{pk.key_size}"
        elif isinstance(pk, ec.EllipticCurvePublicKey):
            out["cert_key"] = f"EC-{pk.curve.name}"
        elif isinstance(pk, dsa.DSAPublicKey):
            out["cert_key"] = f"DSA-{pk.key_size}"
        elif isinstance(pk, ed25519.Ed25519PublicKey):
            out["cert_key"] = "Ed25519"
        elif isinstance(pk, ed448.Ed448PublicKey):
            out["cert_key"] = "Ed448"
    except Exception:
        pass
    try:
        h = cert.signature_hash_algorithm
        out["cert_sig_alg"] = h.name if h is not None else "none(eddsa)"
    except Exception:
        pass
    try:
        sct = cert.extensions.get_extension_for_class(x509.PrecertificateSignedCertificateTimestamps)
        out["cert_sct_count"] = str(len(sct.value))
    except x509.ExtensionNotFound:
        out["cert_sct_count"] = "0"
    except Exception:
        pass
    try:
        kinds = []
        try:
            aia = cert.extensions.get_extension_for_class(x509.AuthorityInformationAccess)
            if any(d.access_method == x509.oid.AuthorityInformationAccessOID.OCSP for d in aia.value):
                kinds.append("ocsp")
        except x509.ExtensionNotFound:
            pass
        try:
            cdp = cert.extensions.get_extension_for_class(x509.CRLDistributionPoints)
            if any(dp.full_name for dp in cdp.value):
                kinds.append("crl")
        except x509.ExtensionNotFound:
            pass
        out["cert_revocation"] = ",".join(kinds) if kinds else "none"
    except Exception:
        pass


def parse_hsts(value: str) -> Dict[str, Any]:
    """Parse a Strict-Transport-Security header value."""
    out: Dict[str, Any] = {"max_age": None, "include_subdomains": False, "preload": False}
    for part in value.split(";"):
        tok = part.strip()
        low = tok.lower()
        if low.startswith("max-age"):
            v = tok.partition("=")[2].strip().strip('"')
            if v.isdigit():
                out["max_age"] = int(v)
        elif low == "includesubdomains":
            out["include_subdomains"] = True
        elif low == "preload":
            out["preload"] = True
    return out


def parse_ocsp_status(text: str) -> str:
    """Interpret `openssl s_client -status` output."""
    low = text.lower()
    if "ocsp response status: successful" in low:
        m = re.search(r"cert status:\s*(\w+)", low)
        return f"stapled({m.group(1)})" if m else "stapled(unknown)"
    if "no response sent" in low:
        return "not-stapled"
    return "N/A"


def check_ocsp_stapling(host: str, timeout: float = 8.0) -> str:
    """OCSP stapling via the openssl CLI (the stdlib ssl module cannot read staples)."""
    exe = shutil.which("openssl")
    if not exe:
        return "N/A (no openssl)"
    RL.wait()
    try:
        proc = subprocess.run(
            [exe, "s_client", "-connect", f"{host}:443", "-servername", host, "-status"],
            input=b"", capture_output=True, timeout=timeout)
    except (subprocess.TimeoutExpired, OSError):
        return "N/A"
    return parse_ocsp_status(proc.stdout.decode("utf-8", "ignore"))


def jarm_fingerprint(host: str) -> str:
    """Real JARM via an external tool if installed; else 'N/A (no jarm)'.

    Reimplementing JARM's exact cipher/extension tables by hand would risk
    fingerprints that silently don't match canonical JARM, so we shell out to the
    real thing. Preferred: `pip install pyjarm` (CLI: `pyjarm <host>`); the
    `jarm` binary is also accepted.
    """
    exe = shutil.which("pyjarm") or shutil.which("jarm")
    if not exe:
        return "N/A (no jarm)"
    try:
        proc = subprocess.run([exe, host], capture_output=True, text=True, timeout=30)
        m = re.search(r"\b([0-9a-f]{62})\b", proc.stdout)
        if m:
            fp = m.group(1)
            # all-zero JARM means no TLS / no handshake — report as N/A.
            return "N/A" if set(fp) == {"0"} else fp
        for line in proc.stdout.splitlines():
            if "JARM" in line.upper() and ":" in line:
                return line.split(":", 1)[1].strip()
    except Exception:
        pass
    return "N/A"


# =====================================================================
# HTTP
# =====================================================================

def build_session(timeout: float) -> requests.Session:
    s = requests.Session()
    s.headers.update({"User-Agent": DEFAULT_UA})
    if _HAVE_RETRY:
        retry = Retry(total=1, backoff_factor=0.3,
                      status_forcelist=[502, 503, 504], allowed_methods=["GET", "HEAD"])
        adapter = HTTPAdapter(max_retries=retry, pool_connections=20, pool_maxsize=20)
        s.mount("http://", adapter)
        s.mount("https://", adapter)
    return s


def _get(session: requests.Session, url: str, timeout: float, **kw) -> Optional[requests.Response]:
    """GET an audited host with a bounded body. `timeout` in requests is per socket
    read, so a slow-drip server could otherwise hold a worker indefinitely; reading is
    streamed and stops at MAX_BODY_BYTES or a total deadline (2x timeout), whichever
    comes first. resp.content/.text then hold the capped body; resp.truncated says
    whether anything was cut."""
    RL.wait()
    try:
        resp = session.get(url, timeout=timeout, verify=False, stream=True, **kw)
    except requests.exceptions.RequestException:
        return None
    deadline = time.monotonic() + timeout * 2
    buf, truncated = bytearray(), False
    # read1() returns as soon as ANY bytes arrive, so the deadline is checked even
    # against a 1-byte-per-second drip; iter_content(n) would block until n bytes.
    read1 = getattr(resp.raw, "read1", None)
    try:
        while True:
            chunk = (read1(65536, decode_content=True) if read1
                     else resp.raw.read(1024, decode_content=True))
            if not chunk:
                break
            buf += chunk
            if len(buf) >= MAX_BODY_BYTES or time.monotonic() > deadline:
                truncated = True
                break
    except Exception:            # socket timeout / reset / decode error mid-body
        truncated = True
    finally:
        resp.close()
    resp._content = bytes(buf[:MAX_BODY_BYTES])
    resp._content_consumed = True
    resp.truncated = truncated
    return resp


def _fetch(session: requests.Session, url: str, timeout: float) -> Optional[requests.Response]:
    resp = _get(session, url, timeout, allow_redirects=True)
    if resp is None:
        return None
    text_l = resp.text.lower()
    if resp.status_code in (401, 403) or "outdated browser" in text_l:
        resp2 = _get(session, url, timeout, allow_redirects=True, headers=CHROME_HEADERS)
        if resp2 is not None and resp2.status_code == 200 and "outdated browser" not in resp2.text.lower():
            return resp2
    return resp


def detect_cdn(headers: Any, server: str, asn: str, cname: str) -> str:
    header_keys = " ".join(k.lower() for k in headers.keys()) if headers else ""
    server_l, asn_l, cname_l = server.lower(), asn.lower(), cname.lower()
    for name, sig in CDN_SIGNATURES.items():
        if any(x in server_l for x in sig.get("server", [])):
            return name
        if any(x in header_keys for x in sig.get("header", [])):
            return name
        if any(x in cname_l for x in sig.get("cname", [])):
            return name
        if any(x in asn_l for x in sig.get("asn", [])):
            return name
    return "No"


CMS_SIGNATURES = [
    (r'wp-content|wp-includes|<meta name="generator" content="WordPress', "WordPress"),
    (r'Drupal.settings|sites/all/|<meta name="Generator" content="Drupal', "Drupal"),
    (r'/media/jui/|Joomla!|<meta name="generator" content="Joomla', "Joomla"),
    (r'cdn\.shopify\.com|Shopify\.theme', "Shopify"),
    (r'/typo3temp/|/typo3conf/', "TYPO3"),
    (r'wix\.com|X-Wix-', "Wix"),
    (r'squarespace\.com|static1\.squarespace', "Squarespace"),
    (r'ghost\.io|content="Ghost', "Ghost"),
    (r'<meta name="generator" content="Hugo', "Hugo"),
    (r'Adobe Experience Manager|/etc/designs/|/etc/clientlibs/', "Adobe AEM"),
]


def grade_csp(csp: str) -> List[str]:
    """Weaknesses in an enforced Content-Security-Policy value."""
    directives: Dict[str, List[str]] = {}
    for part in csp.split(";"):
        bits = part.strip().split()
        if bits:
            directives.setdefault(bits[0].lower(), [b.lower() for b in bits[1:]])
    script = directives.get("script-src") or directives.get("default-src")
    if script is None:
        return ["no-script-restriction"]
    issues = []
    protected = any(x.startswith(("'nonce-", "'sha")) or x == "'strict-dynamic'" for x in script)
    if "'unsafe-inline'" in script and not protected:   # browsers ignore it beside a nonce/hash
        issues.append("unsafe-inline")
    if "'unsafe-eval'" in script:
        issues.append("unsafe-eval")
    if any(x in ("*", "http:", "https:", "data:") for x in script):
        issues.append("wildcard-script-src")
    return issues


def probe_cors(session: requests.Session, url: str, timeout: float) -> str:
    """One GET with a foreign Origin; classify how Access-Control-Allow-Origin responds."""
    origin = "https://cors-probe.invalid"
    r = _get(session, url, timeout, allow_redirects=False, headers={"Origin": origin})
    if r is None:
        return "N/A"
    acao = r.headers.get("Access-Control-Allow-Origin", "").strip()
    creds = r.headers.get("Access-Control-Allow-Credentials", "").strip().lower() == "true"
    if not acao:
        return "none"
    if acao == origin:
        return "reflects-origin+credentials" if creds else "reflects-origin"
    if acao.lower() == "null":
        return "null-origin+credentials" if creds else "null-origin"
    return "wildcard" if acao == "*" else "restricted"


_SECURITY_TXT_FIELDS = ("contact:", "expires:", "policy:", "encryption:", "canonical:",
                        "acknowledgments:", "preferred-languages:", "hiring:")


def validate_security_txt(text: str) -> str:
    """RFC 9116 essentials: Contact and Expires present, Expires not in the past."""
    low = text.lower()
    if re.search(r"<html", low) or not any(f in low for f in _SECURITY_TXT_FIELDS):
        return "missing"                                  # a soft-404 page, not a security.txt
    if "contact:" not in low:
        return "no-contact"
    m = re.search(r"(?im)^\s*expires:\s*(\S+)", text)
    if not m:
        return "no-expires"
    try:
        from datetime import datetime, timezone
        when = datetime.fromisoformat(m.group(1).replace("Z", "+00:00"))
        if when.tzinfo is None:
            when = when.replace(tzinfo=timezone.utc)
        if when < datetime.now(timezone.utc):
            return "expired"
    except ValueError:
        return "no-expires"
    return "valid"


SESSION_COOKIE_RE = re.compile(r"sess|^sid$|_sid$|token|auth|jwt|login|sso|jsessionid|phpsessid", re.I)


def _set_cookie_lines(resp: requests.Response) -> List[str]:
    try:
        return list(resp.raw.headers.getlist("Set-Cookie"))
    except Exception:
        value = resp.headers.get("Set-Cookie")
        # requests folds repeated headers with ", "; split only where a new name= starts.
        return re.split(r",(?=\s*[^;,=\s]+=)", value) if value else []


def parse_set_cookie(line: str) -> Optional[Dict[str, Any]]:
    parts = [p.strip() for p in line.split(";")]
    name, eq, _ = parts[0].partition("=")
    name = name.strip()
    if not eq or not name:
        return None
    attrs = {}
    for part in parts[1:]:
        k, _, v = part.partition("=")
        attrs[k.strip().lower()] = v.strip()
    return {"name": name, "secure": "secure" in attrs, "httponly": "httponly" in attrs,
            "samesite": attrs.get("samesite") or ""}


def analyze_cookies(responses: List[requests.Response], rec: AuditRecord) -> None:
    """Flag cookies set over HTTPS without Secure, and session-like cookies without HttpOnly."""
    seen: Dict[str, Dict[str, Any]] = {}
    for resp in responses:
        https = urlparse(resp.url).scheme == "https"
        for line in _set_cookie_lines(resp):
            c = parse_set_cookie(line)
            if c:
                c["https"] = https
                seen[c["name"]] = c          # last Set-Cookie for a name wins
    if not seen:
        return
    flags, no_secure, no_httponly = [], [], []
    for name, c in sorted(seen.items()):
        parts = ["Secure" if c["secure"] else "!Secure",
                 "HttpOnly" if c["httponly"] else "!HttpOnly",
                 f"SameSite={c['samesite']}" if c["samesite"] else "!SameSite"]
        flags.append(f"{name}({','.join(parts)})")
        if c["https"] and not c["secure"]:
            no_secure.append(name)
        if SESSION_COOKIE_RE.search(name) and not c["httponly"]:
            no_httponly.append(name)
    rec.cookie_flags = "; ".join(flags[:8])
    if no_secure:
        rec.cookie_no_secure = ",".join(no_secure[:8])
    if no_httponly:
        rec.session_cookie_no_httponly = ",".join(no_httponly[:8])


# =====================================================================
# AUTH SURFACE (--auth-paths)
# =====================================================================

LOGIN_PATHS = ("/login", "/signin", "/sign-in", "/log-in", "/auth", "/auth/login",
               "/account/login", "/user/login", "/users/sign_in", "/admin", "/admin/login",
               "/wp-login.php", "/portal/login", "/member/login", "/sso", "/saml/login")
RESET_PATHS = ("/forgot-password", "/password-reset", "/reset-password", "/password/forgot",
               "/account/recovery", "/user/password/new", "/wp-login.php?action=lostpassword")
ADMIN_PATH_RE = re.compile(r"^/(admin|wp-login)", re.I)
_PASSWORD_INPUT_RE = re.compile(r"<input[^>]{1,512}type=[\"']?password", re.I)
_USER_INPUT_RE = re.compile(r"<input[^>]{1,512}type=[\"']?(?:email|text)", re.I)
_RESET_TEXT_RE = re.compile(r"(?:forgot|reset|recover)[^<]{0,40}password|password[^<]{0,40}(?:reset|recovery)",
                            re.I)


def classify_auth_body(path: str, body: str) -> str:
    """'login' / 'reset' / '' for a 200 response body."""
    if path in RESET_PATHS or "lostpassword" in path:
        return "reset" if _RESET_TEXT_RE.search(body) and _USER_INPUT_RE.search(body) else ""
    return "login" if _PASSWORD_INPUT_RE.search(body) else ""


@lru_cache(maxsize=20000)
def m365_realm(domain: str) -> str:
    RL.wait()
    try:
        r = requests.get("https://login.microsoftonline.com/getuserrealm.srf",
                         params={"login": f"user@{domain}", "json": "1"}, timeout=5)
        if r.status_code == 200:
            d = r.json()
            ns = d.get("NameSpaceType", "Unknown")
            if ns == "Federated" and d.get("AuthURL"):
                return f"Federated({urlparse(d['AuthURL']).netloc})"
            return ns
    except (requests.exceptions.RequestException, ValueError):
        pass
    return "Unknown"


def probe_auth_surface(domain: str, rec: AuditRecord, session: requests.Session,
                       timeout: float) -> None:
    """Probe well-known login / reset paths on the host itself (redirects are NOT followed,
    so no third-party host is contacted; an external Location is recorded as SSO)."""
    if domain == registrable_domain(domain):
        rec.m365_realm = m365_realm(domain)
    scheme = "https" if rec.https_status != "0" else ("http" if rec.http_status != "0" else "")
    if not scheme or rec.is_forwarded == "Yes":
        return
    base = f"{scheme}://{domain}"
    # Soft-404 baseline: catch-all hosts answer 200 for any path.
    junk = _get(session, f"{base}/{''.join(random.choices(string.ascii_lowercase, k=14))}",
                timeout, allow_redirects=False)
    base_len = len(junk.content) if junk is not None and junk.status_code == 200 else None
    base_has_pw = bool(junk is not None and junk.status_code == 200
                       and _PASSWORD_INPUT_RE.search(junk.text))
    found, sso = [], set()
    for path in LOGIN_PATHS + RESET_PATHS:
        if STOP.is_set():
            break
        resp = _get(session, base + path, timeout, allow_redirects=False)
        if resp is None:
            continue
        if resp.status_code in (301, 302, 303, 307, 308):
            host = urlparse(urljoin(base + path, resp.headers.get("Location", ""))).netloc.lower()
            if host and host.split(":")[0] != domain:
                sso.add(host.split(":")[0])
            continue
        if resp.status_code != 200:
            continue
        if base_len is not None and abs(len(resp.content) - base_len) <= max(64, base_len // 50):
            continue                                  # same as the not-found page
        kind = classify_auth_body(path, resp.text)
        if kind == "login" and base_has_pw:
            continue                                  # every path shows a login form
        if kind:
            found.append(f"{path.split('?')[0]}({kind})")
    rec.auth_pages = ",".join(found[:10]) if found else "none-found"
    rec.auth_sso = ",".join(sorted(sso)[:5]) if sso else "none-found"


def get_web_data(domain: str, session: requests.Session, args: argparse.Namespace,
                 rec: AuditRecord, raw: dict) -> str:
    timeout = args.timeout
    https = _fetch(session, f"https://{domain}", timeout)
    http = _fetch(session, f"http://{domain}", timeout)

    rec.https_status = str(https.status_code) if https is not None else "0"
    rec.http_status = str(http.status_code) if http is not None else "0"
    if http is not None and http.history:
        rec.redirect_quality = _redirect_quality(http.history[0])

    for label, resp in (("https", https), ("http", http)):
        if resp is not None:
            raw[label] = {"status": resp.status_code, "url": resp.url,
                          "headers": dict(resp.headers),
                          "redirects": [h.url for h in resp.history]}

    winner = None
    if https is not None and https.status_code == 200:
        winner = https
    elif http is not None and http.status_code == 200:
        winner = http
    elif https is not None:
        winner = https
    elif http is not None:
        winner = http
    if winner is None:
        return ""

    body = winner.text
    rec.body_truncated = "Yes" if getattr(winner, "truncated", False) else "No"
    rec.final_url = winner.url
    rec.size = len(body)
    rec.redirect_count = len(winner.history)
    rec.latency_ms = str(int(winner.elapsed.total_seconds() * 1000))
    rec.content_type = winner.headers.get("Content-Type", "N/A").split(";")[0].strip() or "N/A"
    rec.body_sha256 = hashlib.sha256(winner.content).hexdigest()
    rec.server = winner.headers.get("Server", "N/A")
    rec.powered_by = winner.headers.get("X-Powered-By", "N/A")
    cookies = list(winner.cookies.keys()) or re.findall(r"(?im)^set-cookie:\s*([^=]+)=",
                                                        str(winner.headers))
    if cookies:
        rec.cookie_names = ",".join(sorted(set(cookies))[:8])
    analyze_cookies(list(winner.history) + [winner], rec)
    rec.hsts = "Yes" if "Strict-Transport-Security" in winner.headers else "No"
    # Browsers ignore HSTS delivered over plain HTTP, so grade the HTTPS response.
    hsts_val = https.headers.get("Strict-Transport-Security") if https is not None else None
    if hsts_val:
        h = parse_hsts(hsts_val)
        rec.hsts_max_age = str(h["max_age"]) if h["max_age"] is not None else "invalid"
        flags = [n for n, on in (("includeSubDomains", h["include_subdomains"]),
                                 ("preload", h["preload"])) if on]
        rec.hsts_flags = ",".join(flags) if flags else "none"
    rec.csp = "Yes" if "Content-Security-Policy" in winner.headers else "No"
    rec.xframe = winner.headers.get("X-Frame-Options", "No")
    csp_val = winner.headers.get("Content-Security-Policy", "")
    csp_found = []
    if csp_val:
        csp_found = grade_csp(csp_val)
    elif winner.headers.get("Content-Security-Policy-Report-Only"):
        csp_found = ["report-only"]
    if csp_found:
        rec.csp_issues = ",".join(csp_found)
    has_fa = "frame-ancestors" in csp_val.lower()
    has_xfo = bool(winner.headers.get("X-Frame-Options"))
    rec.frame_protection = ("both" if has_fa and has_xfo else "csp" if has_fa
                            else "xfo" if has_xfo else "none")
    disclosed = [f"{h}: {winner.headers[h]}" for h in ("Server", "X-Powered-By", "X-AspNet-Version")
                 if re.search(r"\d+\.\d+", winner.headers.get(h, ""))]
    if disclosed:
        rec.version_disclosure = " | ".join(disclosed)[:120]
    missing = [h for h in SECURITY_HEADERS if h not in winner.headers]
    rec.sec_headers_missing = ",".join(missing) if missing else "None"
    rec.page_type = "Static" if rec.size < 10000 else "Dynamic"
    rec.cdn = detect_cdn(winner.headers, rec.server, rec.asn, rec.cname)
    raw["winner"] = {"url": winner.url, "headers": dict(winner.headers),
                     "body_len": len(body), "truncated": getattr(winner, "truncated", False)}

    m = re.search(r"<title[^>]{0,512}>(.{0,4096}?)</title>", body, re.I | re.S)
    rec.page_title = m.group(1).strip()[:200] if m else "N/A"
    if urlparse(winner.url).netloc.lower() != domain.lower():
        rec.is_forwarded = "Yes"

    for pattern, name in CMS_SIGNATURES:
        if re.search(pattern, body):
            rec.cms = name
            break

    emails = set(re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", body))
    emails = {e for e in emails if not e.lower().endswith((".png", ".jpg", ".gif", ".svg"))}
    if emails:
        rec.emails = ",".join(sorted(emails)[:5])

    analyze_html(body, winner.url, rec)
    _favicon(session, winner.url, timeout, rec)
    if args.harvest:
        harvest_paths(session, winner.url, timeout, rec)
    raw["body"] = body
    return body


def _redirect_quality(first_hop: requests.Response) -> str:
    loc = first_hop.headers.get("Location", "")
    if first_hop.status_code in (301, 302, 307, 308) and loc:
        return "good_http_to_https" if urlparse(loc).scheme == "https" else "bad_http_to_http"
    return "no_redirect"


LOGIN_PATTERNS = [
    # lookaheads are bounded scans the engine never re-enters, so a page of repeated
    # partial tags can't trigger the name x value backtracking cross-product.
    (r'<input(?=[^>]{0,512}name=["\']lastRequestAuthMethod["\'])(?=[^>]{0,512}value=["\']authenticate["\'])',
     "Auth Form (Banking)"),
    (r'lastRequestAuthMethod["\']\s*:\s*["\']authenticate["\']', "React Auth (Banking)"),
    (r'<form[^>]{0,512}action=["\'][^"\']{0,512}login[^"\']{0,512}["\']', "Login Form Action"),
    (r'sTenantId["\']\s*:\s*["\']([a-fA-F0-9-]{36})["\']', "Microsoft/Entra"),
    (r'okta-sign-in', "Okta"),
    (r'(AuthGetContractNrDialog|AuthLoginDialog)', "SPA Auth Template"),
    (r'(Fingerprint2|nevisdetect|ThreatMetrix)', "Auth Fingerprinting"),
    (r'type=["\']password["\']', "Password Form"),
]


def analyze_html(html: str, url: str, rec: AuditRecord) -> None:
    for pattern, label in LOGIN_PATTERNS:
        m = re.search(pattern, html, re.I)
        if m:
            rec.has_login_form = "Yes"
            rec.is_login_page = f"Yes ({label})"
            if label == "Microsoft/Entra" and m.groups():
                rec.microsoft_tenant_id = m.group(1)
            break
    else:
        if any(x in html for x in ("$Config", "estsfed")):
            rec.has_login_form = "Yes"
            rec.is_login_page = "Yes (Microsoft/Entra)"

    y = re.search(r"©\s*(\d{4})|Copyright\s*(\d{4})", html, re.I)
    if y:
        rec.copyright_year = y.group(1) or y.group(2)

    host = urlparse(url).netloc.lower()
    scripts = {s for s in re.findall(r'src=["\']https?://([^/\s"\']+)', html) if s.lower() != host}
    if scripts:
        rec.supply_chain_scripts = ",".join(list(scripts)[:5])

    apis = set(re.findall(r'["\'](/api/v[0-9][^"\']*)["\']', html))
    if apis:
        rec.api_endpoints = ",".join(list(apis)[:3])

    comments = re.findall(r"<!--(.*?)-->", html, re.S)
    meaningful = [c.strip()[:40] for c in comments if len(c.strip()) > 5]
    if meaningful:
        rec.code_comments = " | ".join(meaningful[:3])


def _favicon(session: requests.Session, base_url: str, timeout: float, rec: AuditRecord) -> None:
    fav = _get(session, base_url.rstrip("/") + "/favicon.ico", min(timeout, 4))
    if fav is not None and fav.status_code == 200 and fav.content:
        h = murmur3_x86_32(base64.encodebytes(fav.content))
        rec.favicon_hash = str(h)
        rec.shodan_favicon_query = f"http.favicon.hash:{h}"
        rec.identified_tech = TECH_FAVICON_HASHES.get(h, "Unknown")


def harvest_paths(session: requests.Session, base_url: str, timeout: float, rec: AuditRecord) -> None:
    """Pull disclosed paths / extra hosts from robots.txt, sitemap, security.txt."""
    found: List[str] = []
    rec.security_txt = "missing"
    for path in ("/robots.txt", "/security.txt", "/.well-known/security.txt", "/sitemap.xml"):
        r = _get(session, urljoin(base_url, path), min(timeout, 5), allow_redirects=True)
        if r is None or r.status_code != 200:
            continue
        text = r.text[:20000]
        if "robots" in path:
            found += re.findall(r"(?:Disallow|Allow):\s*(\S+)", text, re.I)
            found += re.findall(r"Sitemap:\s*(\S+)", text, re.I)
        elif "security.txt" in path:
            found += re.findall(r"(?:Contact|Policy):\s*(\S+)", text, re.I)
            verdict = validate_security_txt(text)
            if verdict != "missing" and rec.security_txt == "missing":
                rec.security_txt = verdict
        elif "sitemap" in path:
            found += re.findall(r"<loc>\s*(.*?)\s*</loc>", text, re.I)[:20]
    if found:
        uniq = list(dict.fromkeys(found))[:15]
        rec.disclosed_paths = " | ".join(uniq)


# =====================================================================
# GEO / ASN
# =====================================================================

@lru_cache(maxsize=20000)
def get_geo_asn(ip: str) -> Tuple[str, str, str]:
    if ip == "N/A":
        return "N/A", "N/A", "N/A"
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return "N/A", "N/A", "N/A"
    RL.wait()
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}?fields=status,country,city,as", timeout=4)
        if r.status_code == 429:
            time.sleep(2.0)
            r = requests.get(f"http://ip-api.com/json/{ip}?fields=status,country,city,as", timeout=4)
        if r.status_code == 200:
            d = r.json()
            if d.get("status") == "success":
                return (d.get("as", "Unknown"), d.get("country", "Unknown"),
                        d.get("city", "Unknown"))
    except requests.exceptions.RequestException:
        pass
    return "Unknown", "Unknown", "Unknown"


# =====================================================================
# PORTS
# =====================================================================

def scan_ports(ip: str, ports: List[int], grab_banners: bool,
               workers: int = 100) -> Tuple[List[int], Dict[int, str]]:
    if ip == "N/A" or not ports:
        return [], {}
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return [], {}

    open_ports: List[int] = []
    banners: Dict[int, str] = {}

    def probe(port: int) -> Optional[int]:
        if STOP.is_set():
            return None
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.6)
                if s.connect_ex((ip, port)) != 0:
                    return None
                if grab_banners:
                    banners[port] = _grab_banner(s, port)
                return port
        except OSError:
            return None

    with ThreadPoolExecutor(max_workers=min(workers, len(ports))) as ex:
        for fut in as_completed(ex.submit(probe, p) for p in ports):
            r = fut.result()
            if r is not None:
                open_ports.append(r)
    return sorted(open_ports), banners


def _grab_banner(sock: socket.socket, port: int) -> str:
    try:
        sock.settimeout(1.5)
        if port in WEB_PORTS and port not in BANNER_TALK_FIRST:
            try:
                sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
            except OSError:
                return ""
        data = sock.recv(256)
        return data.decode("latin-1", "ignore").strip().replace("\r", " ").replace("\n", " ")[:120]
    except OSError:
        return ""


# =====================================================================
# LOOP-BACK: discovered domains
# =====================================================================

# =====================================================================
# EMAIL TRANSPORT HARDENING (MTA-STS, TLS-RPT, BIMI, DANE, DKIM)
# =====================================================================

def mx_hosts(mx_records: str) -> List[str]:
    """Exchange hostnames from the "pref host,pref host" string; null MX ("0 .") yields none."""
    out = []
    for entry in (mx_records or "").split(","):
        parts = entry.split()
        if len(parts) >= 2 and parts[-1] != ".":
            out.append(parts[-1].rstrip(".").lower())
    return out


def parse_mta_sts_policy(text: str) -> str:
    m = re.search(r"(?im)^\s*mode\s*:\s*(\w+)", text or "")
    mode = m.group(1).lower() if m else ""
    return {"enforce": "enforce", "testing": "testing", "none": "mode-none"}.get(mode, "policy-invalid")


def check_mta_sts(domain: str, session: requests.Session, timeout: float) -> str:
    txts = _resolve(f"_mta-sts.{domain}", "TXT")
    if not any(t.lower().startswith("v=stsv1") for t in txts):
        return "absent"
    resp = _get(session, f"https://mta-sts.{domain}/.well-known/mta-sts.txt", timeout,
                allow_redirects=False)
    if resp is None or resp.status_code != 200:
        return "policy-unreachable"
    return parse_mta_sts_policy(resp.text)


def dkim_key_bits(txt: str) -> Optional[int]:
    """Public-key size from a DKIM TXT record; None if unknown, 0 if the key is revoked."""
    m = re.search(r"\bp=([A-Za-z0-9+/=\s]*)", txt)
    if not m:
        return None
    b64 = re.sub(r"\s", "", m.group(1))
    if not b64:
        return 0
    try:
        from cryptography.hazmat.primitives.serialization import load_der_public_key
        key = load_der_public_key(base64.b64decode(b64 + "=" * (-len(b64) % 4)))
        return getattr(key, "key_size", None)
    except Exception:
        return None


def check_email_hardening(domain: str, rec: AuditRecord, session: requests.Session,
                          timeout: float, dkim: bool) -> None:
    hosts = mx_hosts(rec.mx_records)
    if not hosts:
        return
    rec.mta_sts = check_mta_sts(domain, session, timeout)
    rec.tls_rpt = "Yes" if any(t.lower().startswith("v=tlsrptv1")
                               for t in _resolve(f"_smtp._tls.{domain}", "TXT")) else "No"
    rec.bimi = "Yes" if any(t.lower().startswith("v=bimi1")
                            for t in _resolve(f"default._bimi.{domain}", "TXT")) else "No"
    if rec.dnssec == "Yes":
        rec.dane = "Yes" if any(_resolve(f"_25._tcp.{h}", "TLSA") for h in hosts[:3]) else "No"
    else:
        rec.dane = "N/A (no dnssec)"
    if dkim:
        found, weak = [], []
        for sel in DKIM_SELECTORS:
            if STOP.is_set():
                break
            recs = [t for t in _resolve(f"{sel}._domainkey.{domain}", "TXT")
                    if "v=dkim1" in t.lower() or re.search(r"\bp=", t)]
            if recs:
                bits = dkim_key_bits(recs[0])
                found.append(f"{sel}({bits if bits else '?' if bits is None else 'revoked'})")
                if bits and bits < DKIM_MIN_BITS:
                    weak.append(f"{sel}:{bits}")
        rec.dkim_selectors = ",".join(found) if found else "none-found"
        if weak:
            rec.dkim_weak = ",".join(weak)


# =====================================================================
# ORIGIN DISCOVERY (--origin): is the real server reachable behind the CDN?
# =====================================================================

def is_origin_candidate(ip: str, edge_ips: set) -> bool:
    """Public address that is not one of the host's own edge IPs or a known CDN range."""
    try:
        ip_obj = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if not ip_obj.is_global or ip in edge_ips:
        return False
    return not any(ip_obj in n for n in _CDN_NETS if n.version == ip_obj.version)


def score_origin(methods: set, reachable: bool, cert_match: bool) -> int:
    score = sum(ORIGIN_METHOD_WEIGHTS.get(m, 0) for m in methods)
    if len(methods) > 1:
        score += 5 * (len(methods) - 1)
    if reachable:
        score += 5
    if cert_match:
        score += 20
    return score


def _probe_origin_ip(ip: str, sni: str, timeout: float = 2.5) -> Tuple[bool, str]:
    """(80/443 reachable, sha256 of the cert presented for `sni` on 443 or '').
    A handshake only — no HTTP request is sent to the candidate."""
    reachable, fp = False, ""
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((ip, 443), timeout=timeout) as sock:
            reachable = True
            with ctx.wrap_socket(sock, server_hostname=sni) as ss:
                der = ss.getpeercert(binary_form=True)
                if der:
                    fp = hashlib.sha256(der).hexdigest()
    except OSError:
        pass
    if not reachable:
        try:
            with socket.create_connection((ip, 80), timeout=timeout):
                reachable = True
        except OSError:
            pass
    return reachable, fp


def discover_origin(domain: str, rec: AuditRecord, raw: dict,
                    use_geo: bool = True) -> List[Dict[str, Any]]:
    """Collect candidate origin IPs for a CDN-fronted host and score them.

    Sources: IP-bearing response headers (already fetched), same-registrable-domain
    MX hosts, and same-registrable-domain cert SAN names. Candidates are dropped if
    they are edge/CDN addresses, then confirmed with a TLS handshake that compares the
    certificate presented for `domain` to the one served at the edge."""
    edge = {a for a in rec.a_records.split(",") if a and a != "N/A"}
    own_reg = registrable_domain(domain)
    found: Dict[str, set] = {}

    def add(ip: str, method: str) -> None:
        if is_origin_candidate(ip, edge):
            found.setdefault(ip, set()).add(method)

    for label in ("https", "http"):
        for name, value in (raw.get(label, {}).get("headers") or {}).items():
            if name.lower() in IP_LEAK_HEADERS:
                for ip in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", str(value)):
                    add(ip, "headers")

    for exch in mx_hosts(rec.mx_records):
        if registrable_domain(exch) == own_reg:
            for ip in _resolve(exch, "A"):
                add(ip, "mx")

    if rec.cert_sans not in ("N/A", ""):
        names = [n.strip().lstrip("*.").lower() for n in rec.cert_sans.split(",")]
        names = sorted({n for n in names if n and n != domain and registrable_domain(n) == own_reg})
        for name in names[:ORIGIN_MAX_NAMES]:
            for ip in _resolve(name, "A"):
                add(ip, "san")

    ranked = sorted(found.items(), key=lambda kv: -score_origin(kv[1], False, False))
    results: List[Dict[str, Any]] = []
    for ip, methods in ranked[:ORIGIN_MAX_CANDIDATES]:
        if STOP.is_set():
            break
        if use_geo:
            asn = get_geo_asn(ip)[0]
            if detect_cdn({}, "", asn, "") != "No":
                continue
        reachable, fp = _probe_origin_ip(ip, domain)
        cert_match = bool(fp) and fp == rec.cert_sha256
        score = score_origin(methods, reachable, cert_match)
        if score >= ORIGIN_MIN_SCORE:
            results.append({"ip": ip, "score": score, "methods": sorted(methods),
                            "reachable": reachable, "cert_match": cert_match})
    results.sort(key=lambda r: -r["score"])
    return results


def collect_discovered(domain: str, rec: AuditRecord, chain: List[str]) -> List[str]:
    """SANs + external CNAME targets = new enumeration candidates."""
    out = set()
    if rec.cert_sans not in ("N/A", ""):
        for s in rec.cert_sans.split(","):
            s = s.strip().lstrip("*.").lower()
            if s and s != domain and "." in s:
                out.add(s)
    for tgt in chain:
        t = tgt.strip().rstrip(".").lower()
        if t and t != domain:
            out.add(t)
    return sorted(out)


# =====================================================================
# RISK SCORE
# =====================================================================

def score_risk(rec: AuditRecord) -> Tuple[int, List[str]]:
    score, notes = 0, []

    def add(pts: int, why: str):
        nonlocal score
        score += pts
        notes.append(f"{why} (+{pts})")

    if rec.axfr_vuln == "Vulnerable":
        add(40, "AXFR")
    if rec.dangling_status == "Yes":
        add(45, "Dangling")
    elif rec.dangling_status == "Possibly":
        add(30, "Possibly Dangling")
    if rec.takeover_risk == "Yes":
        add(45, "Takeover")
    elif rec.takeover_risk == "Possibly":
        add(25, "Possible Takeover")
    if rec.is_private_ip == "Yes":
        add(30, "Private IP exposed")
    if rec.has_login_form == "Yes" and rec.org_range == "No":
        add(30, "External login page")
    if "spf_missing" in rec.spf_issues or "spf_all_too_permissive" in rec.spf_issues:
        add(20, "SPF weak/missing")
    if "dmarc_missing" in rec.dmarc_issues or "dmarc_policy_none" in rec.dmarc_issues:
        add(15, "DMARC weak/missing")
    if rec.tls_min in ("TLSv1.0", "TLSv1.1"):
        add(20, f"Legacy TLS ({rec.tls_min})")
    if rec.tls_health != "Healthy" and (rec.http_status != "0" or rec.https_status != "0"):
        add(15, "TLS unhealthy")
    if rec.caa_records == "None":
        add(5, "Missing CAA")
    if rec.hsts == "No" and (rec.http_status != "0" or rec.https_status != "0"):
        add(5, "Missing HSTS")
    if rec.mta_sts == "absent":
        add(3, "No MTA-STS")
    elif rec.mta_sts in ("policy-unreachable", "policy-invalid"):
        add(5, "MTA-STS policy broken")
    if re.search(r"/(admin|wp-login)[^,]*\(login\)", rec.auth_pages):
        add(10, "Admin login path exposed")
    if rec.spf_lookups.isdigit() and int(rec.spf_lookups) > 10:
        add(10, f"SPF exceeds 10 lookups ({rec.spf_lookups})")
    if "include_unregistered(" in rec.spf_chain_issues:
        add(25, "SPF include of unregistered domain")
    elif "include_no_spf(" in rec.spf_chain_issues:
        add(10, "SPF include has no record")
    if "broad_range(" in rec.spf_chain_issues:
        add(5, "SPF authorises an oversized range")
    if rec.csp_issues not in ("None", "report-only"):
        add(3, f"Weak CSP ({rec.csp_issues})")
    if rec.cors.endswith("+credentials"):
        add(25, f"CORS {rec.cors}")
    elif rec.cors in ("reflects-origin", "null-origin"):
        add(10, f"CORS {rec.cors}")
    pts = sum(SCANNER_POINTS.get(i.partition(":")[0], 0) for i in rec.scanner_findings.split(","))
    if pts:
        add(min(SCANNER_POINTS_CAP, pts), f"Scanner findings ({rec.scanner_max_severity} max)")
    if rec.dkim_weak != "None":
        add(3, f"Weak DKIM key ({rec.dkim_weak})")
    if rec.session_cookie_no_httponly != "None":
        add(5, "Session cookie without HttpOnly")
    if rec.cookie_no_secure != "None":
        add(3, "Cookie without Secure on HTTPS")
    exposed = exposed_services(rec.ports)
    if exposed:
        pts = min(PORT_RISK_CAP, sum(PORT_RISK_POINTS[sev] for _, sev, _ in exposed))
        add(pts, "Exposed services: " + ",".join(f"{lbl}/{prt}" for lbl, _, prt in exposed))
    if _weak_cert_key(rec.cert_key):
        add(10, f"Weak cert key ({rec.cert_key})")
    if rec.cert_sig_alg in ("md5", "sha1"):
        add(10, f"Weak cert signature ({rec.cert_sig_alg})")
    if rec.tls_ocsp_stapling.startswith("stapled(revoked"):
        add(30, "Certificate revoked (OCSP)")
    if rec.origin_exposed == "Yes":
        add(25, "Origin IP exposed behind CDN")
    elif rec.origin_exposed == "Possibly":
        add(10, "Possible origin IP exposure")
    return min(100, score), notes


def exposed_services(ports: str) -> List[Tuple[str, str, int]]:
    """[(label, severity, port)] for risky ports in a comma-separated `ports` string."""
    out = []
    for tok in (ports or "").split(","):
        tok = tok.strip()
        if tok.isdigit() and int(tok) in PORT_RISK:
            sev, label = PORT_RISK[int(tok)]
            out.append((label, sev, int(tok)))
    return sorted(out, key=lambda t: (-PORT_RISK_POINTS[t[1]], t[2]))


def _weak_cert_key(cert_key: str) -> bool:
    m = re.fullmatch(r"(RSA|DSA)-(\d+)", cert_key or "")
    return bool(m) and int(m.group(2)) < 2048


# =====================================================================
# PER-DOMAIN PIPELINE
# =====================================================================

def process_domain(domain: str, session: requests.Session, args: argparse.Namespace,
                   org_networks: List[Any], port_list: List[int]) -> AuditRecord:
    rec = AuditRecord(domain=domain)
    raw: Dict[str, Any] = {"domain": domain}
    rec._raw = raw  # type: ignore[attr-defined]  (excluded from CSV/flat output)
    if STOP.is_set():
        rec.error = "skipped (interrupted)"
        return rec
    if args.jitter > 0:
        time.sleep(random.uniform(0, args.jitter))
    try:
        dns_bits = get_dns_audit(domain, rec)
        raw["dns"] = {"a": dns_bits["a_records"], "aaaa": dns_bits["aaaa"],
                      "ns": dns_bits["ns"], "cname": dns_bits["chain"],
                      "txt": dns_bits["txts"]}

        if rec.ip != "N/A":
            try:
                ip_obj = ipaddress.ip_address(rec.ip)
                rec.is_private_ip = "Yes" if ip_obj.is_private else "No"
                rec.org_range = "Yes" if any(ip_obj in n for n in org_networks) else "No"
            except ValueError:
                pass
            rec.ptr = reverse_dns(rec.ip)

        if args.geo and not args.no_geo:
            rec.asn, rec.country, rec.city = get_geo_asn(rec.ip)

        if not args.no_rdap:
            (rec.rdap_registrar, rec.rdap_created, rec.rdap_expires,
             rec.domain_age_days, rec.rdap_status, raw["rdap"]) = get_rdap(domain)
            # WHOIS fallback for registries without public RDAP (e.g. .ch/SWITCH).
            if rec.rdap_registrar == "N/A" and not args.no_whois:
                w_reg, w_created, w_status, w_src, w_raw = whois_fallback(domain)
                if w_reg != "N/A":
                    rec.rdap_registrar = f"{w_reg} (whois)"
                if w_created != "N/A":
                    rec.rdap_created = w_created
                    try:
                        from datetime import datetime, timezone
                        dt = datetime.fromisoformat(w_created)
                        if dt.tzinfo is None:
                            dt = dt.replace(tzinfo=timezone.utc)
                        rec.domain_age_days = str((datetime.now(timezone.utc) - dt).days)
                    except Exception:
                        pass
                if w_status != "N/A" and rec.rdap_status == "N/A":
                    rec.rdap_status = w_status
                raw["whois"] = {"source": w_src, **w_raw}

        if not args.no_tls:
            tls = get_tls(domain)
            rec.tls_health, rec.tls_valid = tls["health"], tls["valid"]
            rec.tls_min, rec.tls_max, rec.tls_cipher = tls["min"], tls["max"], tls["cipher"]
            rec.cert_subject, rec.cert_issuer = tls["cert_subject"], tls["cert_issuer"]
            rec.cert_not_before, rec.cert_expiry = tls["cert_not_before"], tls["cert_expiry"]
            rec.cert_days_left, rec.cert_sha256 = tls["cert_days_left"], tls["cert_sha256"]
            rec.cert_sans = tls["cert_sans"]
            rec.cert_key, rec.cert_sig_alg = tls["cert_key"], tls["cert_sig_alg"]
            rec.cert_sct_count, rec.cert_revocation = tls["cert_sct_count"], tls["cert_revocation"]
            if tls["cert_pem"]:
                raw["cert_pem"] = tls["cert_pem"]
            if args.jarm and rec.tls_health == "Healthy":
                rec.jarm = jarm_fingerprint(domain)
            if args.ocsp and rec.tls_health == "Healthy":
                rec.tls_ocsp_stapling = check_ocsp_stapling(domain)

        if not args.no_axfr:
            rec.axfr_vuln = check_axfr(domain, rec.ns_servers)

        if rec.spf not in ("None", "", "N/A") and not args.no_spf_chain:
            chain = analyze_spf_chain(domain, rec.spf)
            rec.spf_lookups = str(chain["lookups"])
            if chain["issues"]:
                rec.spf_chain_issues = ",".join(chain["issues"])

        body = get_web_data(domain, session, args, rec, raw)

        rec.dangling_status, rec.dangling_detail = detect_dangling(
            domain, dns_bits["chain"], dns_bits["ns"], dns_bits["has_resolution"])
        rec.takeover_risk, rec.takeover_detail = detect_takeover(dns_bits["chain"], body)

        if args.cors and (rec.https_status != "0" or rec.http_status != "0") and rec.is_forwarded != "Yes":
            scheme = "https" if rec.https_status != "0" else "http"
            rec.cors = probe_cors(session, f"{scheme}://{domain}/", args.timeout)

        if args.auth_paths:
            probe_auth_surface(domain, rec, session, args.timeout)

        if not args.no_email_hardening:
            check_email_hardening(domain, rec, session, args.timeout, args.dkim)

        if args.origin and rec.cdn != "No":
            origins = discover_origin(domain, rec, raw, use_geo=args.geo and not args.no_geo)
            raw["origin"] = origins
            if origins:
                rec.origin_candidates = ",".join(
                    f"{o['ip']}(score={o['score']};methods={'+'.join(o['methods'])}"
                    f"{';cert-match' if o['cert_match'] else ''})" for o in origins)
                rec.origin_exposed = "Yes" if any(o["cert_match"] for o in origins) else "Possibly"

        # CDN edges make host port scans meaningless; skip unless forced.
        if port_list and (rec.cdn == "No" or args.ports_behind_cdn):
            ports, banners = scan_ports(rec.ip, port_list, args.banners)
            rec.ports = ",".join(map(str, ports))
            if banners:
                rec.port_banners = " | ".join(f"{p}:{b}" for p, b in sorted(banners.items()) if b)
            raw["ports"] = {"open": ports, "banners": banners}

        discovered = collect_discovered(domain, rec, dns_bits["chain"])
        if discovered:
            rec.discovered_domains = ",".join(discovered)

        if INGEST:
            apply_ingest(rec, INGEST)

        rec.dirty_forwarding = "Yes" if (rec.is_forwarded == "Yes"
                                         and rec.tls_health != "Healthy") else "No"
        classify_domain(rec, args.approved_mx, args.approved_redirect)
        rec.risk_score, notes = score_risk(rec)
        rec.score_notes = "; ".join(notes)
    except Exception as exc:
        rec.error = f"{type(exc).__name__}: {exc}"
    return rec


def classify_domain(rec: AuditRecord, approved_mx: List[str],
                    approved_redirect: List[str]) -> None:
    """Set disposition + config_issues + mail/service-independence flags.
    Focus: surface fixable misconfigurations and off-policy domains."""
    resolves = rec.dns_status == "OK" or rec.ip != "N/A" or rec.cname != "N/A"
    responds = rec.http_status not in ("0", "") or rec.https_status not in ("0", "")

    # --- Mail routing vs the approved MX domain ---
    if rec.mx_records in ("None", "", "N/A"):
        rec.mx_approved = "None"
    else:
        exchanges = mx_hosts(rec.mx_records)
        if not exchanges:                       # null MX ("0 .") = domain sends/receives no mail
            rec.mx_approved = "None"
        elif not approved_mx:                   # no approved-MX policy configured: nothing to judge
            rec.mx_approved = "N/A"
        else:
            ok = all(any(e == a or e.endswith("." + a) for a in approved_mx) for e in exchanges)
            rec.mx_approved = "Yes" if ok else "No"
            if not ok:
                rec.independent_mail = "Yes"

    # --- Redirect target vs approved landing domain ---
    final_host = urlparse(rec.final_url).netloc.lower().split(":")[0] if rec.final_url != "N/A" else ""
    final_reg = registrable_domain(final_host) if final_host else ""
    redirects_to_approved = any(final_reg == a or final_reg.endswith("." + a)
                                for a in approved_redirect) if final_reg else False

    live_200 = rec.http_status == "200" or rec.https_status == "200"

    # --- Disposition ---
    if not resolves:
        rec.disposition = "dead-dns"
    elif not responds:
        rec.disposition = "dead-nohttp"
    elif rec.dangling_status == "Yes" or rec.takeover_risk == "Yes":
        rec.disposition = "dangling"
    elif rec.is_forwarded == "Yes":
        own_reg = registrable_domain(rec.domain)
        if redirects_to_approved:
            rec.disposition = "redirect-approved"
        elif final_reg == own_reg:
            rec.disposition = "redirect-self"      # www -> apex, normal
        else:
            rec.disposition = "redirect-offsite"
    elif live_200:
        rec.disposition = "live"
    else:
        rec.disposition = "responding"  # non-200 but answering (403/500/etc.)

    # A live service on its own domain that does NOT redirect to the approved
    # domain = a working, non-core-banking service worth reviewing.
    if approved_redirect and live_200 and rec.is_forwarded != "Yes":
        rec.service_independent = "Yes"

    # --- Actionable, fixable config issues ---
    issues = []
    if rec.disposition == "dead-dns":
        issues.append("no-dns-resolution")
    if rec.disposition == "dead-nohttp":
        issues.append("resolves-but-no-service")
    if rec.disposition == "dangling":
        issues.append("dangling/takeover")
    if rec.disposition == "redirect-offsite":
        issues.append(f"redirects-offsite({final_reg})")
    if approved_redirect and rec.disposition == "redirect-self" and not redirects_to_approved:
        issues.append("redirects-to-own-apex-not-approved")
    if rec.independent_mail == "Yes":
        issues.append(f"independent-MX({rec.mx_records.split(',')[0].split()[-1] if rec.mx_records not in ('None','N/A','') else '?'})")
    if rec.service_independent == "Yes":
        issues.append("independent-service-not-redirecting")
    if "spf_missing" in rec.spf_issues:
        issues.append("spf-missing")
    elif rec.spf_issues not in ("None", ""):
        issues.append(f"spf({rec.spf_issues})")
    if "dmarc_missing" in rec.dmarc_issues:
        issues.append("dmarc-missing")
    elif rec.dmarc_issues not in ("None", ""):
        issues.append(f"dmarc({rec.dmarc_issues})")
    if rec.tls_valid in ("expired", "hostname-mismatch", "self-signed", "untrusted-chain"):
        issues.append(f"cert-{rec.tls_valid}")
    if rec.tls_min in ("TLSv1.0", "TLSv1.1"):
        issues.append(f"legacy-tls({rec.tls_min})")
    if rec.cert_days_left not in ("N/A", "") and rec.cert_days_left.lstrip("-").isdigit() and int(rec.cert_days_left) < 21:
        issues.append(f"cert-expiring({rec.cert_days_left}d)")
    if rec.caa_records == "None" and responds:
        issues.append("caa-missing")
    if rec.hsts == "No" and responds:
        issues.append("hsts-missing")
    if rec.hsts_max_age.isdigit() and int(rec.hsts_max_age) < HSTS_MIN_MAX_AGE:
        issues.append(f"hsts-short-maxage({rec.hsts_max_age})")
    elif rec.hsts_max_age == "invalid":
        issues.append("hsts-invalid-maxage")
    if rec.mta_sts == "absent":
        issues.append("mta-sts-missing")
    elif rec.mta_sts in ("testing", "mode-none"):
        issues.append(f"mta-sts-not-enforced({rec.mta_sts})")
    elif rec.mta_sts in ("policy-unreachable", "policy-invalid"):
        issues.append(f"mta-sts-policy-broken({rec.mta_sts})")
    admin = [m.group(0) for pg in rec.auth_pages.split(",")
             for m in [re.match(r"/[^()]+(?=\(login\))", pg)] if m and ADMIN_PATH_RE.match(m.group(0))]
    if admin:
        issues.append(f"admin-login-exposed({','.join(admin)})")
    if rec.spf_lookups.isdigit() and int(rec.spf_lookups) > 10 \
            and "spf_lookup_limit_exceeded" not in rec.spf_issues:
        issues.append(f"spf-lookup-limit({rec.spf_lookups})")
    if rec.spf_chain_issues != "None":
        for item in rec.spf_chain_issues.split(","):
            kind, _, arg = item.partition("(")
            name = {"include_unregistered": "spf-include-unregistered", "include_no_spf": "spf-include-no-record",
                    "include_loop": "spf-include-loop", "broad_range": "spf-broad-range",
                    "chain_truncated": "spf-chain-truncated"}.get(kind)
            if name:
                issues.append(f"{name}({arg}" if arg else name)
    if rec.csp_issues != "None":
        issues += [f"csp-{c}" for c in rec.csp_issues.split(",")]
    if rec.frame_protection == "none" and "html" in rec.content_type.lower() and rec.https_status == "200":
        issues.append("clickjacking-unprotected")
    if rec.version_disclosure != "None":
        issues.append(f"server-version-disclosed({rec.version_disclosure.split('|')[0].strip()})")
    if rec.cors in ("reflects-origin", "null-origin"):
        issues.append(f"cors-{rec.cors}")
    elif rec.cors in ("reflects-origin+credentials", "null-origin+credentials"):
        issues.append(f"cors-{rec.cors.replace('+', '-')}")
    if rec.security_txt == "expired":
        issues.append("security-txt-expired")
    elif rec.security_txt in ("no-contact", "no-expires"):
        issues.append(f"security-txt-invalid({rec.security_txt})")
    for item in rec.scanner_findings.split(","):
        sev, _, tid = item.partition(":")
        if sev in ("critical", "high", "medium") and tid:
            issues.append(f"nuclei-{sev}({tid})")
    if rec.dkim_weak != "None":
        issues.append(f"dkim-key-under-{DKIM_MIN_BITS}({rec.dkim_weak})")
    if rec.cookie_no_secure != "None":
        issues.append(f"cookie-no-secure({rec.cookie_no_secure})")
    if rec.session_cookie_no_httponly != "None":
        issues.append(f"session-cookie-no-httponly({rec.session_cookie_no_httponly})")
    if _weak_cert_key(rec.cert_key):
        issues.append(f"cert-weak-key({rec.cert_key})")
    if rec.cert_sig_alg in ("md5", "sha1"):
        issues.append(f"cert-weak-signature({rec.cert_sig_alg})")
    if rec.tls_ocsp_stapling == "not-stapled" and "ocsp" in rec.cert_revocation:
        issues.append("ocsp-stapling-missing")
    elif rec.tls_ocsp_stapling.startswith("stapled(revoked"):
        issues.append("cert-revoked(ocsp)")
    if rec.origin_exposed == "Yes":
        ips = re.findall(r"([0-9A-Fa-f:.]+)\([^)]*cert-match[^)]*\)", rec.origin_candidates)
        issues.append(f"origin-ip-exposed({','.join(ips)})")
    elif rec.origin_exposed == "Possibly":
        issues.append("possible-origin-exposure")
    if rec.axfr_vuln == "Vulnerable":
        issues.append("axfr-open")
    for label, _sev, port in exposed_services(rec.ports):
        issues.append(f"exposed-{label}({port})")
    rec.config_issues = "; ".join(issues) if issues else "None"


# =====================================================================
# OUTPUT
# =====================================================================

class OutputWriter:
    """Streams records to CSV/JSONL (constant memory); JSON is buffered.

    With `raw=True` (JSON/JSONL only) each record carries a nested `raw` object;
    `raw_dir` additionally dumps per-host evidence files.
    """
    def __init__(self, path: str, fmt: str, resume: bool,
                 raw: bool = False, raw_dir: Optional[str] = None):
        self.fmt = fmt
        self.is_stdout = (path == "-")
        self.raw = raw and fmt in ("json", "jsonl")
        self.raw_dir = raw_dir
        self.records: List[dict] = []
        if raw_dir:
            os.makedirs(raw_dir, exist_ok=True)
        existing = os.path.exists(path) and not self.is_stdout
        append = resume and existing
        if self.is_stdout:
            self.fh = sys.stdout
        else:
            self.fh = open(path, "a" if (append and fmt in ("csv", "jsonl")) else "w",
                           newline="" if fmt == "csv" else None)
        if fmt == "csv":
            self.w = csv.DictWriter(self.fh, fieldnames=FIELDNAMES, extrasaction="ignore")
            if not (append and existing):
                self.w.writeheader()
        elif fmt == "json" and append:
            self.records = load_done_records(path, "json")

    def write(self, rec: AuditRecord) -> None:
        d = asdict(rec)
        raw = getattr(rec, "_raw", None)
        if self.raw_dir and raw:
            _dump_raw_dir(self.raw_dir, rec.domain, raw)
        if self.raw and raw:
            # Inline raw excludes the full body (kept only in --raw-dir).
            d["raw"] = {k: v for k, v in raw.items() if k != "body"}
        if self.fmt == "csv":
            self.w.writerow(d)
            self.fh.flush()
        elif self.fmt == "jsonl":
            self.fh.write(json.dumps(d) + "\n")
            self.fh.flush()
        else:
            self.records.append(d)

    def flush_json(self) -> None:
        if self.fmt == "json":
            self.fh.seek(0)
            self.fh.truncate()
            json.dump(self.records, self.fh, indent=2)
            self.fh.flush()

    def close(self) -> None:
        self.flush_json()
        if not self.is_stdout:
            self.fh.close()


def _dump_raw_dir(base: str, domain: str, raw: dict) -> None:
    """Write per-host evidence: body.html, headers.json, cert.pem, dns.json, rdap.json."""
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", domain)[:150] or "unknown"
    d = os.path.join(base, safe)
    try:
        os.makedirs(d, exist_ok=True)
        if raw.get("body"):
            with open(os.path.join(d, "body.html"), "w", encoding="utf-8", errors="ignore") as f:
                f.write(raw["body"])
        if raw.get("winner"):
            with open(os.path.join(d, "headers.json"), "w") as f:
                json.dump(raw["winner"].get("headers", {}), f, indent=2)
        if raw.get("cert_pem"):
            with open(os.path.join(d, "cert.pem"), "w") as f:
                f.write(raw["cert_pem"])
        if raw.get("dns"):
            with open(os.path.join(d, "dns.json"), "w") as f:
                json.dump(raw["dns"], f, indent=2)
        if raw.get("rdap"):
            with open(os.path.join(d, "rdap.json"), "w") as f:
                json.dump(raw["rdap"], f, indent=2)
        meta = {k: v for k, v in raw.items()
                if k not in ("body", "cert_pem") and not isinstance(v, (bytes,))}
        with open(os.path.join(d, "meta.json"), "w") as f:
            json.dump(meta, f, indent=2, default=str)
    except OSError:
        pass


def load_done_records(path: str, fmt: str) -> List[dict]:
    if not os.path.exists(path):
        return []
    try:
        if fmt == "json":
            with open(path) as fi:
                return json.load(fi)
        if fmt == "jsonl":
            with open(path) as fi:
                return [json.loads(ln) for ln in fi if ln.strip()]
        with open(path, newline="") as fi:
            return list(csv.DictReader(fi))
    except Exception:
        return []


def done_domains(path: str, fmt: str) -> set:
    return {r.get("domain") for r in load_done_records(path, fmt) if r.get("domain")}


# =====================================================================
# INGEST (--ingest): fold nuclei / httpx result files into the records (file parsing only)
# =====================================================================

SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
SCANNER_POINTS = _tune("scanner_points", {"critical": 30, "high": 20, "medium": 10})
SCANNER_POINTS_CAP = _tune("scanner_points_cap", 50)
INGEST_MAX_PER_HOST = 10
INGEST: Optional[Dict[str, Any]] = None        # set in main() from --ingest


def _safe_token(value: Any, limit: int = 80) -> str:
    """Make untrusted text safe for our ';' / ',' / '(' delimited columns."""
    return re.sub(r"[^A-Za-z0-9._:/@+-]", "_", str(value))[:limit]


def _host_key(value: Any) -> str:
    """Lower-cased hostname/IP from a URL, host:port or bare host."""
    v = str(value or "").strip().lower()
    if "://" in v:
        v = urlparse(v).netloc
    v = v.rsplit("@", 1)[-1]
    if v.startswith("["):
        v = v[1:].split("]")[0]
    elif v.count(":") == 1:
        v = v.split(":")[0]
    return v.rstrip(".")


def load_ingest(paths: List[str]) -> Dict[str, Any]:
    """Parse nuclei (-jsonl) and httpx (-json) output into {'nuclei': {host: {(sev, id)}},
    'httpx': {host: {tech}}, 'lines': n, 'skipped': n}. Malformed lines are skipped."""
    idx: Dict[str, Any] = {"nuclei": {}, "httpx": {}, "lines": 0, "skipped": 0}

    def records(path: str):
        with open(path, encoding="utf-8", errors="replace") as fh:
            first = fh.read(1)
            fh.seek(0)
            if first == "[":                        # a JSON array instead of JSONL
                try:
                    yield from (r for r in json.load(fh) if isinstance(r, dict))
                except ValueError:
                    idx["skipped"] += 1
                return
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except ValueError:
                    idx["skipped"] += 1
                    continue
                if isinstance(obj, dict):
                    yield obj
                else:
                    idx["skipped"] += 1

    for path in paths:
        for obj in records(path):
            idx["lines"] += 1
            tid = obj.get("template-id") or obj.get("template_id")
            if tid:                                                  # nuclei
                info = obj.get("info") if isinstance(obj.get("info"), dict) else {}
                sev = str(info.get("severity") or obj.get("severity") or "").lower()
                if sev not in SEV_RANK:
                    idx["skipped"] += 1
                    continue
                keys = {_host_key(obj.get(k)) for k in ("host", "matched-at", "url", "ip")}
                for key in filter(None, keys):
                    idx["nuclei"].setdefault(key, set()).add((sev, _safe_token(tid)))
            elif obj.get("tech") is not None or obj.get("webserver") or obj.get("status_code") is not None \
                    or obj.get("status-code") is not None:           # httpx
                techs = obj.get("tech") if isinstance(obj.get("tech"), list) else []
                keys = {_host_key(obj.get(k)) for k in ("input", "url", "host")}
                for key in filter(None, keys):
                    idx["httpx"].setdefault(key, set()).update(_safe_token(t, 40) for t in techs)
            else:
                idx["skipped"] += 1
    return idx


def apply_ingest(rec: AuditRecord, idx: Dict[str, Any]) -> None:
    """Attach nuclei findings / httpx tech whose host (or IP) matches this record."""
    keys = [rec.domain.lower()] + [a for a in rec.a_records.split(",") if a and a != "N/A"]
    findings, techs = set(), set()
    for k in keys:
        findings |= idx["nuclei"].get(k, set())
        techs |= idx["httpx"].get(k, set())
    if findings:
        ranked = sorted(findings, key=lambda f: (-SEV_RANK[f[0]], f[1]))
        shown = [f"{sev}:{tid}" for sev, tid in ranked[:INGEST_MAX_PER_HOST]]
        extra = len(ranked) - len(shown)
        rec.scanner_findings = ",".join(shown) + (f",+{extra}" if extra > 0 else "")
        rec.scanner_max_severity = ranked[0][0]
    if techs:
        rec.httpx_tech = ",".join(sorted(techs)[:12])


# =====================================================================
# BASELINE DIFF + HTML REPORT (post-processing of a results file)
# =====================================================================

DIFF_TRACKED_FIELDS = ("disposition", "takeover_risk", "dangling_status", "origin_exposed",
                       "ports", "cert_sha256", "tls_valid", "ns_servers", "mx_records")
DIFF_RISK_DELTA = 10


def fmt_from_path(path: str) -> str:
    low = path.lower()
    return "jsonl" if low.endswith(".jsonl") else "json" if low.endswith(".json") else "csv"


def load_results(path: str) -> List[dict]:
    """Load a results file (csv/json/jsonl by extension); raises OSError/ValueError if unusable."""
    if not os.path.exists(path):
        raise OSError(f"{path}: no such file")
    recs = load_done_records(path, fmt_from_path(path))
    if not recs:
        raise ValueError(f"{path}: no records could be read")
    return recs


def _issue_set(rec: dict) -> set:
    val = str(rec.get("config_issues") or "")
    return {t.strip() for t in val.split(";") if t.strip() and t.strip() != "None"}


def _risk(rec: dict) -> int:
    try:
        return int(float(rec.get("risk_score") or 0))
    except (TypeError, ValueError):
        return 0


def diff_results(old: List[dict], new: List[dict]) -> Dict[str, Any]:
    """Compare two result sets keyed by domain."""
    o = {r["domain"]: r for r in old if r.get("domain")}
    n = {r["domain"]: r for r in new if r.get("domain")}
    out: Dict[str, Any] = {"old_count": len(o), "new_count": len(n),
                           "added": [], "removed": [], "new_issues": [], "resolved_issues": [],
                           "changes": [], "risk_up": [], "risk_down": []}
    for d in sorted(n.keys() - o.keys()):
        out["added"].append({"domain": d, "risk": _risk(n[d]), "issues": sorted(_issue_set(n[d]))})
    for d in sorted(o.keys() - n.keys()):
        out["removed"].append({"domain": d, "risk": _risk(o[d])})
    for d in sorted(n.keys() & o.keys()):
        a, b = o[d], n[d]
        gained, lost = _issue_set(b) - _issue_set(a), _issue_set(a) - _issue_set(b)
        if gained:
            out["new_issues"].append({"domain": d, "issues": sorted(gained)})
        if lost:
            out["resolved_issues"].append({"domain": d, "issues": sorted(lost)})
        for f in DIFF_TRACKED_FIELDS:
            va, vb = str(a.get(f) if a.get(f) is not None else ""), str(b.get(f) if b.get(f) is not None else "")
            if va != vb:
                out["changes"].append({"domain": d, "field": f, "old": va, "new": vb})
        delta = _risk(b) - _risk(a)
        if delta >= DIFF_RISK_DELTA:
            out["risk_up"].append({"domain": d, "old": _risk(a), "new": _risk(b), "delta": delta})
        elif delta <= -DIFF_RISK_DELTA:
            out["risk_down"].append({"domain": d, "old": _risk(a), "new": _risk(b), "delta": delta})
    out["risk_up"].sort(key=lambda r: -r["delta"])
    out["risk_down"].sort(key=lambda r: r["delta"])
    return out


def render_diff_text(diff: Dict[str, Any], old_label: str, new_label: str, limit: int = 200) -> str:
    def section(title: str, rows: List[str]) -> List[str]:
        if not rows:
            return []
        lines = [f"## {title} ({len(rows)})"] + [f"- {r}" for r in rows[:limit]]
        if len(rows) > limit:
            lines.append(f"- … {len(rows) - limit} more")
        return lines + [""]

    n_new = sum(len(x["issues"]) for x in diff["new_issues"]) + sum(len(x["issues"]) for x in diff["added"])
    n_res = sum(len(x["issues"]) for x in diff["resolved_issues"])
    lines = [f"# Scan diff: {old_label} -> {new_label}", "",
             f"Domains: {diff['old_count']} -> {diff['new_count']} "
             f"(+{len(diff['added'])} new, -{len(diff['removed'])} not in this run)",
             f"Issues: {n_new} new, {n_res} resolved | risk up >= {DIFF_RISK_DELTA}: "
             f"{len(diff['risk_up'])} | risk down: {len(diff['risk_down'])}", ""]
    lines += section("New domains", [f"{x['domain']}  risk={x['risk']}  " + ("; ".join(x["issues"]) or "no issues")
                                     for x in diff["added"]])
    lines += section("Not in this run (removed or run incomplete)",
                     [f"{x['domain']}  (was risk={x['risk']})" for x in diff["removed"]])
    lines += section("New issues", [f"{x['domain']}: " + "; ".join(x["issues"]) for x in diff["new_issues"]])
    lines += section("Resolved issues", [f"{x['domain']}: " + "; ".join(x["issues"]) for x in diff["resolved_issues"]])
    lines += section("Changed fields", [f"{x['domain']}  {x['field']}: {x['old'] or '-'} -> {x['new'] or '-'}"
                                        for x in diff["changes"]])
    lines += section("Risk increased", [f"{x['domain']}  {x['old']} -> {x['new']} (+{x['delta']})"
                                        for x in diff["risk_up"]])
    lines += section("Risk decreased", [f"{x['domain']}  {x['old']} -> {x['new']} ({x['delta']})"
                                        for x in diff["risk_down"]])
    return "\n".join(lines).rstrip() + "\n"


_REPORT_CSS = """
:root{--bg:#fff;--fg:#1b1f24;--muted:#5b6670;--card:#f4f6f8;--line:#d8dee4;--accent:#0b5cad;--bar:#0b5cad;--warn:#b35900;--bad:#b42318}
@media (prefers-color-scheme:dark){:root{--bg:#14181c;--fg:#e6eaee;--muted:#9aa5b0;--card:#1d2328;--line:#2f373e;--accent:#6aa9ee;--bar:#4a8fd8;--warn:#e0a050;--bad:#f2766b}}
*{box-sizing:border-box}body{margin:0;padding:24px 16px;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif}
main{max-width:1200px;margin:0 auto}h1{font-size:1.5rem;margin:0 0 4px}h2{font-size:1.1rem;margin:28px 0 10px}
.sub{color:var(--muted);margin:0 0 20px}.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px}
.card{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:12px 14px}.card b{display:block;font-size:1.6rem}.card span{color:var(--muted);font-size:.85rem}
.bars{display:grid;grid-template-columns:minmax(120px,260px) 1fr 60px;gap:6px 10px;align-items:center}
.bars .track{background:var(--card);border-radius:4px;height:14px;overflow:hidden}.bars .fill{background:var(--bar);height:100%}.bars .n{text-align:right;color:var(--muted)}
.wrap{overflow-x:auto;border:1px solid var(--line);border-radius:8px}table{border-collapse:collapse;width:100%;font-size:.85rem}
th,td{padding:6px 10px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}th{background:var(--card);cursor:pointer;white-space:nowrap;position:sticky;top:0}
td.issues{max-width:520px;word-break:break-word}td.num{text-align:right}.risk-hi{color:var(--bad);font-weight:600}.risk-mid{color:var(--warn);font-weight:600}
input[type=search]{width:100%;max-width:420px;padding:8px 10px;border:1px solid var(--line);border-radius:6px;background:var(--bg);color:var(--fg);margin:0 0 10px}
pre{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:12px;overflow-x:auto;font-size:.8rem;white-space:pre-wrap}
"""

_REPORT_JS = """
(function(){var q=document.getElementById('q'),t=document.getElementById('all'),c=document.getElementById('count');
if(!t)return;var body=t.tBodies[0];
function upd(){var f=q.value.toLowerCase(),n=0;for(var i=0;i<body.rows.length;i++){var r=body.rows[i],
ok=!f||r.textContent.toLowerCase().indexOf(f)>-1;r.hidden=!ok;if(ok)n++;}c.textContent=n+' shown';}
q.addEventListener('input',upd);
Array.prototype.forEach.call(t.tHead.rows[0].cells,function(th,idx){function s(){var num=th.dataset.num==='1',
dir=th.dataset.dir==='asc'?-1:1;th.dataset.dir=dir===1?'asc':'desc';
var rows=Array.prototype.slice.call(body.rows);rows.sort(function(a,b){var x=a.cells[idx].dataset.s||a.cells[idx].textContent,
y=b.cells[idx].dataset.s||b.cells[idx].textContent;if(num){x=parseFloat(x)||0;y=parseFloat(y)||0;return(x-y)*-dir;}
return x.localeCompare(y)*dir;});rows.forEach(function(r){body.appendChild(r);});}
th.addEventListener('click',s);th.addEventListener('keydown',function(e){if(e.key==='Enter')s();});});upd();})();
"""


def _bars(rows: List[Tuple[str, int]]) -> str:
    if not rows:
        return "<p class='sub'>None.</p>"
    top = max(n for _, n in rows) or 1
    out = ["<div class='bars'>"]
    for label, n in rows:
        out.append(f"<div>{html.escape(label)}</div><div class='track'><div class='fill' "
                   f"style='width:{max(2, round(100 * n / top))}%'></div></div><div class='n'>{n}</div>")
    out.append("</div>")
    return "".join(out)


def render_html_report(records: List[dict], title: str, source: str,
                       diff: Optional[Dict[str, Any]] = None, diff_text: str = "",
                       max_rows: int = 5000) -> str:
    """Self-contained HTML (inline CSS/JS, no network). Every record value is escaped."""
    esc = html.escape
    total = len(records)
    risks = [_risk(r) for r in records]
    with_issues = sum(1 for r in records if _issue_set(r))
    high = sum(1 for x in risks if x >= 50)
    live = sum(1 for r in records if r.get("disposition") in ("live", "responding"))
    avg = round(sum(risks) / total, 1) if total else 0
    disp: Dict[str, int] = {}
    issue_counts: Dict[str, int] = {}
    for r in records:
        disp[str(r.get("disposition") or "N/A")] = disp.get(str(r.get("disposition") or "N/A"), 0) + 1
        for tok in _issue_set(r):
            key = tok.split("(")[0]
            issue_counts[key] = issue_counts.get(key, 0) + 1
    top_issues = sorted(issue_counts.items(), key=lambda kv: -kv[1])[:15]
    by_risk = sorted(records, key=lambda r: -_risk(r))

    def risk_cls(v: int) -> str:
        return "risk-hi" if v >= 50 else "risk-mid" if v >= 25 else ""

    def row(r: dict) -> str:
        rk = _risk(r)
        cells = [
            f"<td>{esc(str(r.get('domain', '')))}</td>",
            f"<td>{esc(str(r.get('disposition', '')))}</td>",
            f"<td class='num {risk_cls(rk)}' data-s='{rk}'>{rk}</td>",
            f"<td class='issues'>{esc('; '.join(sorted(_issue_set(r))) or '-')}</td>",
            f"<td>{esc(str(r.get('cdn', '')))}</td>",
            f"<td>{esc(str(r.get('tls_valid', '')))}</td>",
            f"<td class='num'>{esc(str(r.get('cert_days_left', '')))}</td>",
            f"<td>{esc(str(r.get('origin_exposed', '')))}</td>",
        ]
        return "<tr>" + "".join(cells) + "</tr>"

    heads = [("Domain", 0), ("Disposition", 0), ("Risk", 1), ("Config issues", 0),
             ("CDN", 0), ("TLS", 0), ("Cert days", 1), ("Origin", 0)]
    thead = "".join(f"<th tabindex='0' data-num='{n}'>{h}</th>" for h, n in heads)
    top_rows = "".join(row(r) for r in by_risk[:25])
    all_rows = "".join(row(r) for r in by_risk[:max_rows])
    truncated = f"<p class='sub'>Showing the {max_rows} highest-risk of {total} rows.</p>" if total > max_rows else ""
    diff_html = ""
    if diff is not None:
        diff_html = f"<h2>Changes since baseline</h2><pre>{esc(diff_text)}</pre>"
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'">
<title>{esc(title)}</title><style>{_REPORT_CSS}</style></head><body><main>
<h1>{esc(title)}</h1><p class="sub">Source: {esc(source)} &middot; {total} domains</p>
<div class="cards">
<div class="card"><b>{total}</b><span>domains</span></div>
<div class="card"><b>{with_issues}</b><span>with config issues</span></div>
<div class="card"><b>{high}</b><span>risk 50 or higher</span></div>
<div class="card"><b>{live}</b><span>live / responding</span></div>
<div class="card"><b>{avg}</b><span>average risk</span></div></div>
{diff_html}
<h2>Disposition</h2>{_bars(sorted(disp.items(), key=lambda kv: -kv[1]))}
<h2>Most common issues</h2>{_bars(top_issues)}
<h2>Highest risk</h2><div class="wrap"><table><thead><tr>{thead}</tr></thead><tbody>{top_rows}</tbody></table></div>
<h2>All domains</h2><input type="search" id="q" placeholder="Filter domains, issues, CDN..." aria-label="Filter"> <span id="count" class="sub"></span>
<div class="wrap"><table id="all"><thead><tr>{thead}</tr></thead><tbody>{all_rows}</tbody></table></div>{truncated}
</main><script>{_REPORT_JS}</script></body></html>
"""


def merge_results(src: str, dst: str, idx: Dict[str, Any], args: argparse.Namespace, log) -> str:
    """Re-score an existing results file with ingested scanner data; writes `dst`."""
    try:
        recs = load_results(src)
    except (OSError, ValueError) as exc:
        sys.exit(f"error: --report-from {exc}")
    writer = OutputWriter(dst, fmt_from_path(dst), False)
    matched = 0
    for d in recs:
        if not d.get("domain"):
            continue
        rec = AuditRecord(**{k: d[k] for k in FIELDNAMES if k in d})
        apply_ingest(rec, idx)
        classify_domain(rec, args.approved_mx, args.approved_redirect)
        rec.risk_score, notes = score_risk(rec)
        rec.score_notes = "; ".join(notes)
        matched += rec.scanner_findings != "None"
        writer.write(rec)
    writer.close()
    log(f"[*] merged scanner data into {matched}/{len(recs)} records -> {dst}")
    return dst


def post_process(results_path: str, baseline: Optional[str], report_html: Optional[str],
                 diff_out: Optional[str], log) -> None:
    try:
        current = load_results(results_path)
    except (OSError, ValueError) as exc:
        sys.exit(f"error: {exc}")
    diff, diff_text = None, ""
    if baseline:
        try:
            old = load_results(baseline)
        except (OSError, ValueError) as exc:
            sys.exit(f"error: --baseline {exc}")
        diff = diff_results(old, current)
        diff_text = render_diff_text(diff, os.path.basename(baseline), os.path.basename(results_path))
        log(f"[*] diff vs {baseline}: +{len(diff['added'])} new, -{len(diff['removed'])} gone, "
            f"{len(diff['new_issues'])} domains with new issues, {len(diff['resolved_issues'])} resolved, "
            f"{len(diff['risk_up'])} risk up")
        if diff_out:
            with open(diff_out, "w", encoding="utf-8") as fh:
                if diff_out.lower().endswith(".json"):
                    json.dump(diff, fh, indent=2)
                else:
                    fh.write(diff_text)
            log(f"[*] diff written to {diff_out}")
        else:
            print(diff_text, file=sys.stderr)
    if report_html:
        page = render_html_report(current, "Domain audit report", os.path.basename(results_path),
                                  diff, diff_text)
        with open(report_html, "w", encoding="utf-8") as fh:
            fh.write(page)
        log(f"[*] HTML report written to {report_html}")



class EmitSink:
    CATEGORIES = {"urls", "live", "open-ports", "takeover", "sans", "new-domains",
                  "origins", "exposed", "auth-urls"}

    def __init__(self, categories: List[str], path: Optional[str]):
        self.cats = set(categories)
        self.seen: set = set()
        self.fh = sys.stdout if (path in (None, "-")) else open(path, "a")

    def feed(self, rec: AuditRecord) -> None:
        for line in self._lines(rec):
            if line and line not in self.seen:
                self.seen.add(line)
                self.fh.write(line + "\n")
        self.fh.flush()

    def _lines(self, rec: AuditRecord) -> List[str]:
        out: List[str] = []
        if "urls" in self.cats and rec.final_url != "N/A":
            out.append(rec.final_url)
        if "live" in self.cats and (rec.http_status == "200" or rec.https_status == "200"):
            out.append(rec.domain)
        if "open-ports" in self.cats and rec.ports:
            out += [f"{rec.domain}:{p}" for p in rec.ports.split(",")]
        if "takeover" in self.cats and rec.takeover_risk in ("Yes", "Possibly"):
            out.append(rec.domain)
        if "sans" in self.cats and rec.cert_sans not in ("N/A", ""):
            out += [s.strip().lstrip("*.") for s in rec.cert_sans.split(",")]
        if "new-domains" in self.cats and rec.discovered_domains not in ("None", ""):
            out += [d.strip() for d in rec.discovered_domains.split(",")]
        if "origins" in self.cats and rec.origin_candidates != "None":
            out += re.findall(r"(?:^|,)([0-9A-Fa-f:.]+)\(score=", rec.origin_candidates)
        if "exposed" in self.cats:
            out += [f"{rec.domain}:{port}" for _lbl, _sev, port in exposed_services(rec.ports)]
        if "auth-urls" in self.cats and rec.auth_pages not in ("N/A", "none-found", ""):
            scheme = "https" if rec.https_status != "0" else "http"
            out += [f"{scheme}://{rec.domain}{m.group(1)}"
                    for m in (re.match(r"(/[^()]*)\(", pg) for pg in rec.auth_pages.split(",")) if m]
        return out

    def close(self) -> None:
        if self.fh is not sys.stdout:
            self.fh.close()


# =====================================================================
# SELFTEST
# =====================================================================

def selftest() -> int:
    import tempfile
    ok = True

    def check(cond, label):
        nonlocal ok
        print(f"  [{'PASS' if cond else 'FAIL'}] {label}", file=sys.stderr)
        ok = ok and cond

    check(murmur3_x86_32(b"") == 0, "murmur3 empty == 0")
    check(murmur3_x86_32(b"foo") == -156908512, "murmur3 'foo'")
    check(murmur3_x86_32(b"hello") == 613153351, "murmur3 'hello'")
    check(normalize_host("https://Foo.com:8443/login?a=1") == "foo.com", "normalize URL")
    check(normalize_host("# comment") is None, "normalize comment skipped")
    check(normalize_host("xn--already.com") == "xn--already.com", "normalize punycode")
    # mojibake IDN recovery: reproduce a bad export (UTF-8 bytes decoded via
    # sloppy-CP1252) without embedding mojibake in the source, then normalize it.
    def _mk_mojibake(real: str) -> str:
        out = []
        for byte in real.encode("utf-8"):
            try:
                out.append(bytes([byte]).decode("cp1252"))
            except UnicodeDecodeError:
                out.append(chr(byte))
        return "".join(out)
    if _HAVE_IDNA:
        check(normalize_host(_mk_mojibake("データベース") + ".com")
              == "xn--zcklx7evic.com", "normalize mojibake IDN -> punycode")
        check(normalize_host(_mk_mojibake("ネットワーク") + ".com")
              == "xn--pckwbps6o0c.com",
              "normalize sloppy-cp1252 (0x8d) mojibake IDN -> punycode")
    check(_repair_mojibake("already fine") == "already fine", "repair leaves ASCII untouched")
    check(normalize_host("ドメイン.com") == "xn--eckwd4c7c.com", "normalize clean IDN untouched")
    spf = parse_spf(["v=spf1 include:a include:b +all"])
    check("spf_all_too_permissive" in spf["spf_issues"], "SPF +all flagged")
    dm = parse_dmarc(["v=DMARC1; p=none"])
    check("dmarc_policy_none" in dm["dmarc_issues"], "DMARC p=none flagged")
    check(detect_cdn({"cf-ray": "x"}, "cloudflare", "AS13335", "")[:5] == "Cloud", "CDN detect")
    check(len(FIELDNAMES) == len(set(FIELDNAMES)), "fieldnames unique")
    check(registrable_domain("a.b.example.com") == "example.com", "registrable domain")
    check(registrable_domain("foo.bar.co.uk") == "bar.co.uk", "registrable multi-suffix")
    check(registrable_domain("ikea.com.ro") == "ikea.com.ro", "registrable com.ro (PSL)")
    check(registrable_domain("x.api.pactrip.co.kr") == "pactrip.co.kr", "registrable co.kr (PSL)")
    check(registrable_domain("mail.chavastai.net.ru") == "chavastai.net.ru",
          "registrable net.ru (PSL private)")
    check(registrable_domain("x.com.ru") == "x.com.ru", "registrable com.ru (PSL private)")
    for f in ("rdap_created", "ptr", "cert_sha256", "tls_valid", "body_sha256", "cms",
              "hsts_max_age", "cert_key", "cert_sig_alg", "cert_revocation",
              "tls_ocsp_stapling", "origin_candidates", "origin_exposed"):
        check(f in FIELDNAMES, f"field present: {f}")

    h = parse_hsts('max-age=31536000; includeSubDomains; preload')
    check(h == {"max_age": 31536000, "include_subdomains": True, "preload": True}, "HSTS full parse")
    check(parse_hsts('max-age="600"')["max_age"] == 600, "HSTS quoted max-age")
    check(parse_hsts("includeSubDomains")["max_age"] is None, "HSTS missing max-age")
    check(parse_ocsp_status("OCSP response: no response sent") == "not-stapled", "OCSP not stapled")
    check(parse_ocsp_status("OCSP Response Status: successful (0x0)\n Cert Status: good")
          == "stapled(good)", "OCSP stapled good")
    check(parse_ocsp_status("OCSP Response Status: successful\n Cert Status: revoked")
          == "stapled(revoked)", "OCSP stapled revoked")
    check(parse_ocsp_status("garbage") == "N/A", "OCSP unparseable")

    check(is_origin_candidate("8.8.8.8", set()), "origin: public IP is a candidate")
    check(not is_origin_candidate("10.0.0.5", set()), "origin: private IP rejected")
    check(not is_origin_candidate("104.16.1.1", set()), "origin: Cloudflare range rejected")
    check(not is_origin_candidate("8.8.8.8", {"8.8.8.8"}), "origin: edge IP rejected")
    check(not is_origin_candidate("not-an-ip", set()), "origin: junk rejected")
    check(score_origin({"headers"}, False, False) < ORIGIN_MIN_SCORE, "origin: lone unreachable leak below threshold")
    check(score_origin({"san"}, True, False) >= ORIGIN_MIN_SCORE, "origin: reachable SAN host kept")
    check(score_origin({"mx"}, True, False) < ORIGIN_MIN_SCORE, "origin: lone MX host below threshold")
    check(score_origin({"mx", "san"}, False, True) > score_origin({"mx", "san"}, False, False),
          "origin: cert match raises score")
    check(_weak_cert_key("RSA-1024") and not _weak_cert_key("RSA-2048")
          and not _weak_cert_key("EC-secp256r1"), "weak key detection")

    try:
        from datetime import datetime, timedelta, timezone
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives.serialization import Encoding
        from cryptography.x509.oid import NameOID

        def _mk(bits: int, algo: Any) -> bytes:
            key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
            name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "t.example")])
            now = datetime.now(timezone.utc)
            cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                    .public_key(key.public_key()).serial_number(1)
                    .not_valid_before(now - timedelta(days=1))
                    .not_valid_after(now + timedelta(days=30))
                    .add_extension(x509.SubjectAlternativeName([x509.DNSName("t.example")]), False)
                    .sign(key, algo))
            return cert.public_bytes(Encoding.DER)

        strong: Dict[str, str] = {"cert_key": "N/A", "cert_sig_alg": "N/A",
                                  "cert_sct_count": "N/A", "cert_revocation": "N/A"}
        _fill_cert(_mk(2048, hashes.SHA256()), strong)
        check(strong["cert_key"] == "RSA-2048" and strong["cert_sig_alg"] == "sha256",
              "cert hygiene: RSA-2048/sha256")
        check(strong["cert_sct_count"] == "0" and strong["cert_revocation"] == "none",
              "cert hygiene: no SCT / no revocation endpoints")
        weak: Dict[str, str] = dict(strong)
        _fill_cert(_mk(1024, hashes.SHA256()), weak)  # modern backends won't sign with SHA-1
        check(_weak_cert_key(weak["cert_key"]), "cert hygiene: RSA-1024 flagged")
    except ImportError:
        print("  [SKIP] cert hygiene (cryptography not installed)", file=sys.stderr)
    except Exception as exc:  # backend refuses to mint a weak test cert
        print(f"  [SKIP] weak-cert hygiene ({type(exc).__name__}: {exc})", file=sys.stderr)
    # --- exposed services
    check([lbl for lbl, _, _ in exposed_services("22,80,445,6379,9999")] == ["smb", "redis"],
          "exposed services ordered by severity")
    check(exposed_services("") == [] and exposed_services("80,443") == [], "no exposed services")
    r = AuditRecord(domain="x.test"); r.ports = "445,6379,3306,23"
    check(any(n.startswith("Exposed services") and n.endswith(f"(+{PORT_RISK_CAP})") for n in score_risk(r)[1]),
          "exposed services score capped")

    # --- cookies
    c = parse_set_cookie("sid=abc; Path=/; Secure; HttpOnly; SameSite=Lax")
    check(c == {"name": "sid", "secure": True, "httponly": True, "samesite": "Lax"}, "Set-Cookie full flags")
    c = parse_set_cookie("JSESSIONID=1; Path=/")
    check(c is not None and not c["secure"] and not c["httponly"], "Set-Cookie bare")
    check(parse_set_cookie("garbage") is None, "Set-Cookie junk rejected")
    resp = requests.Response()
    resp.url = "https://c.test/"
    resp.headers["Set-Cookie"] = "JSESSIONID=1; Path=/, theme=dark; Path=/; Secure, ok=1; Secure; HttpOnly"
    cr = AuditRecord(domain="c.test")
    analyze_cookies([resp], cr)
    check("JSESSIONID" in cr.cookie_no_secure and "theme" not in cr.cookie_no_secure, "cookie Secure flagging")
    check(cr.session_cookie_no_httponly == "JSESSIONID", "session cookie HttpOnly flagging")

    # --- email transport hardening
    check(mx_hosts("10 mail.a.com,20 B.com") == ["mail.a.com", "b.com"], "mx_hosts parse")
    check(mx_hosts("0 ") == [] and mx_hosts("None") == [] and mx_hosts("") == [], "mx_hosts null MX")
    check(parse_mta_sts_policy("version: STSv1\nmode: enforce\nmax_age: 86400") == "enforce", "MTA-STS enforce")
    check(parse_mta_sts_policy("mode: testing") == "testing", "MTA-STS testing")
    check(parse_mta_sts_policy("mode: none") == "mode-none", "MTA-STS mode none")
    check(parse_mta_sts_policy("<html>") == "policy-invalid", "MTA-STS invalid")
    try:
        from cryptography.hazmat.primitives.asymmetric import rsa as _rsa
        from cryptography.hazmat.primitives.serialization import Encoding as _E, PublicFormat as _PF
        for bits in (1024, 2048):
            der = _rsa.generate_private_key(public_exponent=65537, key_size=bits).public_key() \
                .public_bytes(_E.DER, _PF.SubjectPublicKeyInfo)
            check(dkim_key_bits("v=DKIM1; k=rsa; p=" + base64.b64encode(der).decode()) == bits,
                  f"DKIM key size {bits}")
    except ImportError:
        print("  [SKIP] DKIM key size (cryptography not installed)", file=sys.stderr)
    check(dkim_key_bits("v=DKIM1; p=") == 0, "DKIM revoked key")

    # --- auth surface
    check(classify_auth_body("/login", '<form><input type="password" name=p></form>') == "login", "auth: login form")
    check(classify_auth_body("/login", "<p>hello</p>") == "", "auth: no form")
    check(classify_auth_body("/forgot-password", "<h1>Forgot your password?</h1><input type=email>") == "reset",
          "auth: reset form")
    check(classify_auth_body("/forgot-password", "<h1>Forgot your password?</h1>") == "", "auth: reset needs input")

    # --- takeover fingerprint loader
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as tf:
        json.dump([{"vulnerable": True, "cname": ["selftest-svc.example"], "fingerprint": "No such selftest site here"},
                   {"vulnerable": True, "cname": ["1.2.3.4"], "fingerprint": "ignored ip cname entry"},
                   {"vulnerable": True, "cname": ["status.example"], "fingerprint": "HTTP_STATUS=500"},
                   {"vulnerable": False, "cname": ["nope.example"], "fingerprint": "not vulnerable entry"}], tf)
    try:
        before = dict(TAKEOVER_PROVIDERS)
        check(load_takeover_fingerprints(tf.name) == 1, "takeover loader adds only usable entries")
        check(detect_takeover(["a.selftest-svc.example"], "<p>No such selftest site here</p>")[0] == "Yes",
              "takeover loader fingerprint matches")
    finally:
        TAKEOVER_PROVIDERS.clear()
        TAKEOVER_PROVIDERS.update(before)
        os.unlink(tf.name)
    check(detect_takeover(["x.helpjuice.com"], "We could not find what you&#39;re looking for.")[0] == "Yes",
          "takeover: HTML-entity body matches")

    # --- header quality / CORS / security.txt
    check(grade_csp("default-src 'self'") == [], "CSP: strict default-src is clean")
    check(grade_csp("script-src 'self' 'unsafe-inline' 'unsafe-eval'") == ["unsafe-inline", "unsafe-eval"],
          "CSP: unsafe-inline + unsafe-eval")
    check(grade_csp("script-src 'unsafe-inline' 'nonce-abc'") == [], "CSP: nonce neutralises unsafe-inline")
    check(grade_csp("script-src https: *") == ["wildcard-script-src"], "CSP: wildcard source")
    check(grade_csp("img-src 'self'") == ["no-script-restriction"], "CSP: no script restriction")

    class _CR:
        def __init__(self, h): self.headers = h
    _og = globals()["_get"]
    try:
        for hdrs, want in (({"Access-Control-Allow-Origin": "https://cors-probe.invalid",
                             "Access-Control-Allow-Credentials": "true"}, "reflects-origin+credentials"),
                           ({"Access-Control-Allow-Origin": "https://cors-probe.invalid"}, "reflects-origin"),
                           ({"Access-Control-Allow-Origin": "*"}, "wildcard"),
                           ({"Access-Control-Allow-Origin": "https://app.example"}, "restricted"),
                           ({}, "none")):
            globals()["_get"] = lambda *a, _h=hdrs, **k: _CR(_h)
            check(probe_cors(None, "https://x.test/", 1) == want, f"CORS probe: {want}")
    finally:
        globals()["_get"] = _og
    check(validate_security_txt("Contact: mailto:a@b.c\nExpires: 2999-01-01T00:00:00Z") == "valid", "security.txt valid")
    check(validate_security_txt("Contact: mailto:a@b.c\nExpires: 2001-01-01T00:00:00Z") == "expired", "security.txt expired")
    check(validate_security_txt("Contact: mailto:a@b.c") == "no-expires", "security.txt no Expires")
    check(validate_security_txt("Expires: 2999-01-01T00:00:00Z") == "no-contact", "security.txt no Contact")
    check(validate_security_txt("<html>Not found</html>") == "missing", "security.txt soft-404 ignored")

    # --- emit feeds
    er = AuditRecord(domain="e.test")
    er.ports, er.https_status = "80,445,6379", "200"
    er.origin_candidates = "45.33.32.2(score=31;methods=san;cert-match),45.33.32.3(score=13;methods=headers)"
    er.auth_pages = "/login(login),/forgot-password(reset)"
    sink = EmitSink(["origins", "exposed", "auth-urls"], "/dev/null")
    got = sink._lines(er)
    sink.close()
    check(got == ["45.33.32.2", "45.33.32.3", "e.test:445", "e.test:6379",
                  "https://e.test/login", "https://e.test/forgot-password"], "emit: origins / exposed / auth-urls")

    # --- nuclei / httpx ingest
    with tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False) as tf:
        tf.write(json.dumps({"template-id": "CVE-2024-0001", "info": {"severity": "High"},
                             "host": "https://i.test:8443", "matched-at": "https://i.test:8443/x", "ip": "45.33.32.9"}) + "\n")
        tf.write(json.dumps({"template-id": "evil;id,\n(x)", "info": {"severity": "critical"}, "host": "i.test"}) + "\n")
        tf.write(json.dumps({"template-id": "tech-detect", "info": {"severity": "info"}, "host": "i.test"}) + "\n")
        tf.write(json.dumps({"template-id": "bogus-sev", "info": {"severity": "weird"}, "host": "i.test"}) + "\n")
        tf.write(json.dumps({"input": "i.test", "url": "https://i.test", "status_code": 200, "tech": ["Nginx", "PHP"]}) + "\n")
        tf.write("not json\n[1,2]\n")
    try:
        ix = load_ingest([tf.name])
        check(ix["skipped"] == 3, "ingest: malformed / unknown-severity lines skipped")
        ir = AuditRecord(domain="i.test")
        ir.a_records = "45.33.32.9"
        apply_ingest(ir, ix)
        check(ir.scanner_findings.split(",")[0].startswith("critical:evil") and ir.scanner_max_severity == "critical",
              "ingest: worst severity first, hostile id sanitised")
        check(all(c not in ir.scanner_findings.replace(",", "") for c in ";()\n "), "ingest: no delimiter injection")
        check(ir.httpx_tech == "Nginx,PHP", "ingest: httpx tech attached")
        ir.dns_status = "OK"
        classify_domain(ir, ["x"], ["x"])
        check("nuclei-critical(" in ir.config_issues and "nuclei-high(CVE-2024-0001)" in ir.config_issues
              and "nuclei-info" not in ir.config_issues, "ingest: medium+ findings become issues")
        check(any(n.startswith("Scanner findings (critical max)") for n in score_risk(ir)[1]), "ingest: risk points")
        other = AuditRecord(domain="other.test")
        apply_ingest(other, ix)
        check(other.scanner_findings == "None", "ingest: unrelated host untouched")
    finally:
        os.unlink(tf.name)

    # --- Censys guard rails (HTTP stubbed)
    class _Resp:
        def __init__(self, code, body=None): self.status_code, self._b, self.headers = code, body or {}, {}
        def json(self): return self._b
    _rg, _cc = requests.get, globals()["_censys_creds"]
    _calls = []
    try:
        globals()["_censys_creds"] = lambda: ("id", "secret")
        requests.get = lambda *a, **k: (_calls.append(1), _Resp(200, {"result": {"buckets": [{"key": "a.cen.test"}]}}))[1]
        _CENSYS.update(calls=0, max=2)
        _censys_disabled.clear()
        res = [censys_hostnames("cen.test") for _ in range(3)]
        check(res[0] == ["a.cen.test"] and res[2] == [] and len(_calls) == 2, "Censys: --censys-max stops at the cap")
        check(_censys_disabled.is_set(), "Censys: cap disables for the rest of the run")
        _CENSYS.update(calls=0, max=0)
        _censys_disabled.clear()
        _calls.clear()
        requests.get = lambda *a, **k: (_calls.append(1), _Resp(401))[1]
        censys_hostnames("cen.test"); censys_hostnames("other.test")
        check(len(_calls) == 1 and _censys_disabled.is_set(), "Censys: 401 disables after a single call")
    finally:
        requests.get, globals()["_censys_creds"] = _rg, _cc
        _CENSYS.update(calls=0, max=0)
        _censys_disabled.clear()

    # --- response cap: local server only, no external traffic
    import http.server as _hs
    class _Big(_hs.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            body = b"A" * (MAX_BODY_BYTES + 100_000)
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            try:
                self.wfile.write(body)
            except Exception:
                pass
    _srv = _hs.ThreadingHTTPServer(("127.0.0.1", 0), _Big)
    threading.Thread(target=_srv.serve_forever, daemon=True).start()
    try:
        _r = _get(build_session(5.0), f"http://127.0.0.1:{_srv.server_address[1]}/", 5.0)
        check(_r is not None and len(_r.content) == MAX_BODY_BYTES and _r.truncated,
              "response body capped at MAX_BODY_BYTES and flagged truncated")
    finally:
        _srv.shutdown()
    check("body_truncated" in FIELDNAMES and FIELDNAMES[-1] == "body_truncated",
          "body_truncated is the last column (existing order unchanged)")
    for _html, _what in (('<input name="lastRequestAuthMethod" value="authenticate">', "name,value"),
                         ('<input value="authenticate" name="lastRequestAuthMethod">', "value,name")):
        _rec = AuditRecord(domain="x")
        analyze_html(_html, "http://x/", _rec)
        check(_rec.is_login_page == "Yes (Auth Form (Banking))", f"login form detected ({_what} order)")

    # --- brand config + policy gating
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as bf:
        json.dump({"approved_mx": [" Mail.Example "], "brand_keywords": ["acme"],
                   "nsec3": {"zone": ".Zone.", "known": ["a"]}}, bf)
    try:
        bc, bp = brand_config.load(bf.name)
        check(bp == bf.name and bc["approved_mx"] == ["mail.example"] and bc["nsec3"]["zone"] == "zone",
              "config: loads and normalises")
        check(bc["approved_redirect"] == [], "config: missing keys keep defaults")
        with open(bf.name, "w") as fh:
            fh.write('{"approved_mx": "not-a-list"}')
        try:
            brand_config.load(bf.name)
            check(False, "config: wrong type rejected")
        except ValueError:
            check(True, "config: wrong type rejected")
        try:
            brand_config.load(bf.name + ".missing")
            check(False, "config: explicit missing file rejected")
        except ValueError:
            check(True, "config: explicit missing file rejected")
    finally:
        os.unlink(bf.name)
    pr = AuditRecord(domain="www.p.test")
    pr.dns_status, pr.ip, pr.http_status, pr.https_status = "OK", "1.2.3.4", "200", "200"
    pr.mx_records, pr.final_url = "10 mx.other.test", "https://www.p.test/"
    classify_domain(pr, [], [])
    check(pr.independent_mail == "No" and pr.mx_approved == "N/A" and pr.service_independent == "No"
          and "independent" not in pr.config_issues, "policy unset: independent-* checks skipped")
    pr2 = AuditRecord(domain="www.p.test")
    pr2.dns_status, pr2.ip, pr2.http_status, pr2.https_status = "OK", "1.2.3.4", "200", "200"
    pr2.mx_records, pr2.final_url = "10 mx.other.test", "https://www.p.test/"
    classify_domain(pr2, ["approved.test"], ["approved.test"])
    check(pr2.independent_mail == "Yes" and pr2.service_independent == "Yes"
          and "independent-MX(mx.other.test)" in pr2.config_issues, "policy set: independent-* flagged")

    # --- SPF include chain (DNS stubbed)
    _real = (globals()["_spf_txt"], globals()["_unregistered"])
    fake = {"a.test": ("v=spf1 ip4:1.2.3.4 include:c.test",), "c.test": ("v=spf1 mx a -all",),
            "x.test": ("v=spf1 include:y.test -all",), "y.test": ("v=spf1 include:x.test -all",)}
    globals()["_spf_txt"] = lambda n: fake.get(n, ())
    globals()["_unregistered"] = lambda reg: reg == "b.test"
    try:
        r1 = analyze_spf_chain("example.test", "v=spf1 include:a.test include:b.test ip4:10.0.0.0/8 -all")
        check(r1["lookups"] == 5, "SPF chain counts nested lookups")
        check("include_unregistered(b.test)" in r1["issues"], "SPF include of unregistered domain")
        check("broad_range(10.0.0.0/8)" in r1["issues"], "SPF oversized own range")
        r2 = analyze_spf_chain("x.test", "v=spf1 include:y.test -all")
        check("include_loop(x.test)" in r2["issues"], "SPF include loop")
        r3 = analyze_spf_chain("example.test", "v=spf1 include:nope.test -all")
        check(r3["issues"] == ["include_no_spf(nope.test)"], "SPF include without record")
        many = "v=spf1 " + " ".join(f"include:a{i}.test" for i in range(12)) + " -all"
        check(analyze_spf_chain("example.test", many)["lookups"] > 10, "SPF over 10 lookups detected")
    finally:
        globals()["_spf_txt"], globals()["_unregistered"] = _real

    # --- baseline diff + report
    old = [{"domain": "a.test", "config_issues": "hsts-missing; dmarc-missing", "risk_score": "10",
            "disposition": "live", "ports": ""},
           {"domain": "gone.test", "config_issues": "None", "risk_score": 0}]
    new = [{"domain": "a.test", "config_issues": "dmarc-missing; exposed-redis(6379)", "risk_score": 40,
            "disposition": "live", "ports": "6379"},
           {"domain": "b.test", "config_issues": "None", "risk_score": 0}]
    d = diff_results(old, new)
    check([x["domain"] for x in d["added"]] == ["b.test"] and [x["domain"] for x in d["removed"]] == ["gone.test"],
          "diff: added / removed domains")
    check(d["new_issues"][0]["issues"] == ["exposed-redis(6379)"] and
          d["resolved_issues"][0]["issues"] == ["hsts-missing"], "diff: new / resolved issues")
    check(d["risk_up"][0]["delta"] == 30 and any(c["field"] == "ports" for c in d["changes"]),
          "diff: risk delta and field change")
    page = render_html_report([{"domain": "<script>alert(1)</script>", "config_issues": "x\"onload=1",
                                "risk_score": 5}], "t", "src")
    check("<script>alert(1)</script>" not in page and "&lt;script&gt;alert(1)" in page,
          "report: record values HTML-escaped")

    print(f"selftest: {'ALL PASS' if ok else 'FAILURES'}", file=sys.stderr)
    return 0 if ok else 1


# =====================================================================
# MAIN
# =====================================================================

def load_networks(path: Optional[str], configured: Optional[List[str]] = None) -> List[Any]:
    """Org CIDRs: --org-networks file, else brand config org_networks, else the (empty) default."""
    raw = list(configured) if configured else ORG_NETWORKS_DEFAULT
    if path and os.path.exists(path):
        with open(path) as fi:
            raw = [ln.strip() for ln in fi if ln.strip() and not ln.startswith("#")]
    nets = []
    for n in raw:
        try:
            nets.append(ipaddress.ip_network(n, strict=False))
        except ValueError:
            pass
    return nets


def read_inputs(source: str, dedup_www: bool = False) -> List[str]:
    fh = sys.stdin if source in ("-", None) else open(source)
    seen, hosts = set(), []
    try:
        for line in fh:
            h = normalize_host(line)
            if h and h not in seen:
                seen.add(h)
                hosts.append(h)
    finally:
        if fh is not sys.stdin:
            fh.close()
    if dedup_www:
        # drop www.X when X is already in the set (redundant with the apex scan)
        hosts = [h for h in hosts if not (h.startswith("www.") and h[4:] in seen)]
    return hosts


def moved_www(source: str) -> List[str]:
    """www.X entries whose apex X is also in `source` — to route into the
    subdomains set so they're scanned once (as a subdomain), not dropped."""
    hosts = read_inputs(source)  # no dedup
    hostset = set(hosts)
    return [h for h in hosts if h.startswith("www.") and h[4:] in hostset]


def ct_subdomains(query: str, log=None) -> List[str]:
    """Certificate-transparency host discovery via crt.sh. `query` may be a
    registrable domain (foo.com) or a bare brand TLD (e.g. 'brand') to sweep
    every logged *.brand hostname. crt.sh is flaky, so we retry a few times."""
    out: set = set()
    url = f"https://crt.sh/?q=%25.{query}&output=json"
    for attempt in range(4):
        if STOP.is_set():
            break
        RL.wait()
        try:
            r = requests.get(url, timeout=30,
                             headers={"User-Agent": f"clipeus/{__version__} (CT client)"})
            if r.status_code != 200 or not r.text.strip().startswith(("[", "{")):
                time.sleep(3)
                continue
            q = query.lstrip(".")
            for entry in r.json():
                for name in (entry.get("name_value", "") or "").splitlines():
                    h = normalize_host(name.replace("*.", ""))
                    if h and (h == q or h.endswith("." + q)):
                        out.add(h)
            break
        except Exception:
            time.sleep(3)
            continue
    if log:
        log(f"[ct] crt.sh {query}: {len(out)} hostnames"
            + ("" if out else " (crt.sh may be down)"))
    return sorted(out)


_SUBFINDER_CFG = os.path.expanduser("~/.config/subfinder/provider-config.yaml")


def _censys_creds() -> Optional[Tuple[str, str]]:
    """Censys API id/secret from env, else reused from the subfinder provider config."""
    cid, csec = os.environ.get("CENSYS_API_ID"), os.environ.get("CENSYS_API_SECRET")
    if cid and csec:
        return cid, csec
    try:
        txt = open(_SUBFINDER_CFG).read()
        m = re.search(r'^censys:\s*\["([^"]+)"\]', txt, re.M)
        if m and ":" in m.group(1):
            a, b = m.group(1).split(":", 1)
            return a, b
    except Exception:
        pass
    return None


# Run-wide Censys guard rails: a call cap (--censys-max, 0 = unlimited) and a kill switch that
# trips on credential/endpoint failures so one bad key doesn't produce a warning per domain.
_CENSYS = {"calls": 0, "max": 0}
_censys_lock = threading.Lock()
_censys_disabled = threading.Event()


def _censys_disable(reason: str, log=None) -> None:
    with _censys_lock:
        first = not _censys_disabled.is_set()
        _censys_disabled.set()
    if first and log:
        log(f"[censys] disabled for the rest of this run: {reason}")


def _censys_take_call(log=None) -> bool:
    """Reserve one API call; False (and disable) once the --censys-max cap is reached."""
    with _censys_lock:
        if _censys_disabled.is_set():
            return False
        cap = _CENSYS["max"]
        if cap and _CENSYS["calls"] >= cap:
            pass
        else:
            _CENSYS["calls"] += 1
            return True
    _censys_disable(f"--censys-max {cap} API calls reached", log)
    return False


def censys_hostnames(query: str, log=None) -> List[str]:
    """Hostnames under `query` (a domain or a bare brand TLD like 'brand') from the
    Censys legacy Search v2 hosts index, via a single dns.names aggregation call.
    Quota-light: ~1 API call per query. Returns [] if no creds / on error."""
    creds = _censys_creds()
    if not creds or _censys_disabled.is_set():
        return []
    q = query.lstrip(".")
    out: set = set()
    for attempt in range(4):
        if STOP.is_set() or not _censys_take_call(log):
            break
        try:
            RL.wait()
            r = requests.get("https://search.censys.io/api/v2/hosts/aggregate",
                             params={"q": f"dns.names: *.{q}", "field": "dns.names",
                                     "num_buckets": 1000},
                             auth=creds, headers={"Accept": "application/json"}, timeout=30)
            if r.status_code == 200:
                for b in r.json().get("result", {}).get("buckets", []):
                    h = normalize_host(b.get("key", ""))
                    if h and (h == q or h.endswith("." + q)):
                        out.add(h)
                break
            if r.status_code == 429:
                wait = int(r.headers.get("Retry-After", "0") or 0) or (2 ** attempt + 1)
                if attempt < 3:
                    time.sleep(min(wait, 30))
                    continue
                if log:
                    log(f"[censys] {q}: 429 (gave up after retries)")
                break
            if r.status_code in (401, 402, 403, 410):
                _censys_disable(f"HTTP {r.status_code} — credentials rejected, credits exhausted, "
                                f"or the legacy Search v2 API is no longer available", log)
                break
            if log:
                log(f"[censys] {q}: HTTP {r.status_code}")
            break
        except Exception as exc:
            if log:
                log(f"[censys] {q}: ERROR {exc}")
            break
    if log:
        log(f"[censys] {q}: {len(out)} hostnames")
    return sorted(out)


_certspotter_disabled = threading.Event()   # trips on first 429 (keyless rate limit)
CERTSPOTTER_MAX_WAIT = _tune("certspotter_max_wait", 200)   # honor Retry-After up to this many seconds


def _certspotter_token() -> Optional[str]:
    t = os.environ.get("CERTSPOTTER_TOKEN")
    if t:
        return t.strip()
    for p in ("~/.config/certspotter/token", "~/.certspotter_token"):
        try:
            return open(os.path.expanduser(p)).read().strip()
        except Exception:
            pass
    return None


def certspotter_hostnames(domain: str, log=None) -> List[str]:
    """Subdomains via CertSpotter (sslmate) CT API — the reliable crt.sh
    replacement. Keyless works but is quickly rate-limited (429 -> disabled for
    the run); set CERTSPOTTER_TOKEN (free) for full results at scale."""
    if _certspotter_disabled.is_set():
        return []
    token = _certspotter_token()
    headers = {"User-Agent": f"clipeus/{__version__}"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    out: set = set()
    after = None
    for _ in range(15):
        if STOP.is_set():
            break
        RL.wait()
        params = {"domain": domain, "include_subdomains": "true", "expand": "dns_names"}
        if after:
            params["after"] = after
        try:
            r = requests.get("https://api.certspotter.com/v1/issuances",
                             params=params, headers=headers, timeout=30)
        except Exception:
            break
        if r.status_code == 429:
            if not token:
                _certspotter_disabled.set()
                if log:
                    log("[certspotter] rate-limited (keyless) — disabled for this run; "
                        "set CERTSPOTTER_TOKEN for full coverage")
                break
            ra = int(r.headers.get("Retry-After", "60") or 60)
            if ra > CERTSPOTTER_MAX_WAIT:
                if log:
                    log(f"[certspotter] {domain}: 429 (Retry-After {ra}s > cap) — skipping")
                break
            if log:
                log(f"[certspotter] {domain}: 429 — waiting {ra}s then retrying")
            slept = 0
            while slept < ra and not STOP.is_set():
                time.sleep(min(5, ra - slept)); slept += 5
            continue  # retry same page
        if r.status_code != 200:
            break
        data = r.json()
        if not data:
            break
        for c in data:
            for n in c.get("dns_names", []):
                h = normalize_host(n.replace("*.", ""))
                if h and (h == domain or h.endswith("." + domain)):
                    out.add(h)
        after = data[-1].get("id")
        if len(data) < 100:
            break
    if log:
        log(f"[certspotter] {domain}: {len(out)} hostnames")
    return sorted(out)


def enumerate_subdomains(apexes: List[str], subs_file: str, log,
                         use_ct: bool = True, ct_tlds: Optional[List[str]] = None,
                         use_censys: bool = True, use_certspotter: bool = True,
                         enum_workers: int = 6, resolve_subs: bool = True,
                         sf_timeout: int = 15, sf_maxtime: int = 5,
                         sf_all: bool = False, use_subfinder: bool = True,
                         drop_www: bool = False) -> List[str]:
    """Discover subdomains via subfinder AND certificate-transparency (crt.sh),
    merged and deduped. Writes to subs_file live (tail-friendly). `ct_tlds` sweeps
    whole brand TLDs through CT (e.g. ['brand'] for every *.brand hostname)."""
    exe = (shutil.which("subfinder") or (
        os.path.expanduser("~/go/bin/subfinder")
        if os.path.exists(os.path.expanduser("~/go/bin/subfinder")) else None)
        ) if use_subfinder else None
    seen: set = set(apexes)       # names written to the (validated) subs file
    seen_all: set = set(apexes)   # everything discovered (raw), for the .all sidecar
    discovered: List[str] = []
    regs = sorted({registrable_domain(a) for a in apexes})

    add_lock = threading.Lock()
    fo_all = None                 # opened inside the with-block when resolve_subs

    def _resolves(host: str) -> bool:
        """A/AAAA/CNAME check — is this a live name worth scanning?"""
        try:
            a, _ = resolve_a_status(host)
            if a:
                return True
            return bool(_resolve(host, "AAAA") or _resolve(host, "CNAME"))
        except Exception:
            return False

    def _filter_live(hosts: List[str]) -> List[str]:
        hosts = [h for h in hosts if h]
        if not hosts:
            return []
        out = []
        with ThreadPoolExecutor(max_workers=min(20, len(hosts))) as ex:
            for h, ok in zip(hosts, ex.map(_resolves, hosts)):
                if ok:
                    out.append(h)
        return out

    def add(hosts, tag):
        # 1) record raw discovered (dedup) to the .all sidecar
        with add_lock:
            new_raw = [h for h in hosts if h and h not in seen_all]
            for h in new_raw:
                seen_all.add(h)
                if fo_all:
                    fo_all.write(h + "\n")
            if fo_all:
                fo_all.flush()
        # 2) validate resolvability (outside the lock, in parallel)
        live = _filter_live(new_raw) if resolve_subs else new_raw
        # 3) write validated names to the scan-ready subs file
        with add_lock:
            new = 0
            for h in live:
                if h not in seen:
                    seen.add(h)
                    discovered.append(h)
                    fo.write(h + "\n")
                    new += 1
            fo.flush()
            extra = f" (-{len(new_raw) - len(live)} dead)" if resolve_subs and new_raw else ""
            log(f"[{tag}] +{new} live{extra} (total {len(discovered)})")

    # Health-gate crt.sh once so a dead server doesn't waste hours of retries.
    ct_ok = False
    if use_ct or ct_tlds:
        try:
            probe = requests.get("https://crt.sh/?q=example.com&output=json", timeout=20,
                                 headers={"User-Agent": f"clipeus/{__version__} (CT client)"})
            ct_ok = probe.status_code == 200 and probe.text.strip().startswith(("[", "{"))
        except Exception:
            ct_ok = False
        if not ct_ok:
            log("[ct] crt.sh appears DOWN (502/timeout) — skipping CT enumeration this run")

    with open(subs_file, "a") as fo:
        if resolve_subs:
            fo_all = open(subs_file + ".all", "a")
            log(f"[*] validate-on-discovery ON — resolvable names -> {subs_file}, "
                f"raw discovered -> {subs_file}.all")
        # subfinder in ONE batch (-dL): it parallelizes internally (far faster
        # than one invocation per domain for a large list).
        if exe and regs:
            import tempfile
            tf = tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False)
            tf.write("\n".join(regs)); tf.close()
            outf = tf.name + ".out"
            cmd = [exe, "-dL", tf.name, "-silent",
                   "-timeout", str(sf_timeout), "-max-time", str(sf_maxtime),
                   "-o", outf]
            if sf_all:
                cmd.append("-all")
            log(f"[subs] subfinder batch over {len(regs)} apex domains "
                f"(timeout={sf_timeout}s max-time={sf_maxtime}m all={sf_all}) ...")
            try:
                subprocess.run(cmd, capture_output=True, text=True,
                               timeout=max(1800, 8 * len(regs)))
            except subprocess.TimeoutExpired:
                log("[subs] subfinder overall TIMEOUT — keeping partial results")
            except Exception as exc:
                log(f"[subs] subfinder ERROR {exc}")
            finally:
                # Read results from -o file so partial output survives a timeout.
                try:
                    with open(outf) as rf:
                        add([normalize_host(l) for l in rf], "subs")
                except FileNotFoundError:
                    log("[subs] no subfinder output file (0 results)")
                for p in (tf.name, outf):
                    try:
                        os.unlink(p)
                    except OSError:
                        pass
        elif not exe:
            log("[subs] subfinder " + ("disabled" if not use_subfinder
                else "not found") + " — using CertSpotter + Censys for discovery")

        censys_ok = use_censys and _censys_creds() is not None
        cs_ok = use_certspotter
        if not use_censys and _censys_creds() is not None:
            log("[censys] credentials present but Censys is opt-in — pass --censys to use it "
                "(metered; see --censys-max)")
        if censys_ok:
            log("[censys] credentials found — using Censys hosts index"
                + ("" if ct_ok else " (crt.sh down, Censys is a primary CT source)"))
        if cs_ok:
            log("[certspotter] enabled" + (" (with token)" if _certspotter_token()
                else " (keyless — set CERTSPOTTER_TOKEN for scale)"))

        # Per-domain CT: crt.sh when up, CertSpotter + Censys as reliable sources.
        # Parallelized across domains (bounded) so a large list doesn't take hours;
        # a 429 from a keyless source trips its own run-wide disable.
        if use_ct or censys_ok or cs_ok:
            done_ctr = [0]

            def do_reg(item):
                i, reg = item
                if STOP.is_set():
                    return
                if ct_ok and use_ct:
                    add(ct_subdomains(reg, log), f"ct {i}/{len(regs)} {reg}")
                if cs_ok and not _certspotter_disabled.is_set():
                    add(certspotter_hostnames(reg, log), f"certspotter {i}/{len(regs)} {reg}")
                if censys_ok:
                    add(censys_hostnames(reg, log), f"censys {i}/{len(regs)} {reg}")
                with add_lock:
                    done_ctr[0] += 1
                    if done_ctr[0] % 100 == 0:
                        log(f"[enum] {done_ctr[0]}/{len(regs)} domains queried")

            with ThreadPoolExecutor(max_workers=max(1, enum_workers)) as ex:
                list(ex.map(do_reg, enumerate(regs, 1)))

        # Whole-TLD sweeps (e.g. a .brand gTLD): crt.sh if up, else Censys.
        for j, tld in enumerate(ct_tlds or [], 1):
            if STOP.is_set():
                break
            tld = tld.lstrip(".")
            if ct_ok:
                log(f"[ct-tld {j}] crt.sh sweep of .{tld} ...")
                add(ct_subdomains(tld, log), f"ct-tld .{tld}")
            if censys_ok:
                log(f"[censys-tld {j}] Censys sweep of .{tld} ...")
                add(censys_hostnames(tld, log), f"censys-tld .{tld}")
    if fo_all:
        fo_all.close()
    if _CENSYS["calls"]:
        log(f"[censys] {_CENSYS['calls']} API calls made this run"
            + (f" (cap {_CENSYS['max']})" if _CENSYS["max"] else " (no cap — see --censys-max)"))

    # Drop redundant www.X when X is already in scope (input or discovered) — the
    # apex checks already cover it. www.X is kept only when X isn't otherwise known.
    if drop_www and discovered:
        covered = set(apexes) | set(discovered)
        filtered = [h for h in discovered
                    if not (h.startswith("www.") and h[4:] in covered)]
        removed = len(discovered) - len(filtered)
        if removed:
            with open(subs_file, "w") as f:
                f.write("\n".join(filtered) + ("\n" if filtered else ""))
            log(f"[www] dropped {removed} redundant www.* (parent already in scope)")
            discovered = filtered
    return discovered


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description=f"Clipeus v{__version__} — Domain Security Audit Tool",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    p.add_argument("--input", default="-", help="Domains file, or '-' for stdin")
    p.add_argument("--output", default="-", help="Output path, or '-' for stdout")
    p.add_argument("--format", choices=["csv", "json", "jsonl"], default="csv")
    p.add_argument("--workers", type=int, default=30, help="Concurrent domains")
    p.add_argument("--timeout", type=float, default=8.0, help="HTTP timeout (s)")
    p.add_argument("--rate", type=float, default=0.0, help="Global max external requests/sec (0=off)")
    p.add_argument("--jitter", type=float, default=0.0, help="Random 0..N s delay before each domain")
    p.add_argument("--ports", choices=["none", "top", "standard", "full"], default="top")
    p.add_argument("--ports-behind-cdn", action="store_true",
                   help="Port-scan even when a CDN/WAF is detected (default: skip)")
    p.add_argument("--banners", action="store_true", help="Grab TCP banners on open ports")
    p.add_argument("--harvest", action="store_true",
                   help="Harvest robots.txt / sitemap.xml / security.txt paths")
    p.add_argument("--jarm", action="store_true", help="Real JARM via external `jarm` tool")
    p.add_argument("--ocsp", action="store_true",
                   help="Check OCSP stapling via the openssl CLI (one extra handshake per host)")
    p.add_argument("--auth-paths", action="store_true",
                   help="Probe ~23 well-known login/reset paths per host (no redirects followed) "
                        "and look up the apex's Microsoft 365 realm")
    p.add_argument("--ingest", action="append", default=[], metavar="FILE",
                   help="nuclei (-jsonl) or httpx (-json) results to fold into the records "
                        "(repeatable; file parsing only, no network)")
    p.add_argument("--merge-out", metavar="FILE",
                   help="With --report-from + --ingest: write the re-scored results here "
                        "(.jsonl/.json/.csv)")
    p.add_argument("--baseline", metavar="FILE",
                   help="Previous results file (csv/json/jsonl); report what changed after the run")
    p.add_argument("--diff-out", metavar="FILE",
                   help="Write the --baseline diff here (.json = JSON, else Markdown); default: stderr")
    p.add_argument("--report-html", metavar="FILE",
                   help="Write a self-contained HTML report of the results (needs --output FILE)")
    p.add_argument("--report-from", metavar="FILE",
                   help="Skip the audit: build --report-html / --baseline diff from this results file")
    p.add_argument("--takeover-sigs", metavar="FILE",
                   help="Extra takeover fingerprints (can-i-take-over-xyz fingerprints.json format)")
    p.add_argument("--cors", action="store_true",
                   help="One extra GET per live host with a foreign Origin header to detect "
                        "reflected / null / credentialed CORS")
    p.add_argument("--no-spf-chain", action="store_true",
                   help="Skip the recursive SPF include-chain walk (DNS only, cached)")
    p.add_argument("--no-email-hardening", action="store_true",
                   help="Skip MTA-STS / TLS-RPT / BIMI / DANE checks (run only for domains with MX)")
    p.add_argument("--dkim", action="store_true",
                   help="Probe common DKIM selectors and flag keys under 2048 bits "
                        f"({len(DKIM_SELECTORS)} extra DNS queries per mail domain)")
    p.add_argument("--origin", action="store_true",
                   help="For CDN-fronted hosts, look for a directly reachable origin IP "
                        "(header leaks, same-domain MX/SAN hosts; TLS-handshake confirmation)")
    p.add_argument("--resolvers", help="File of resolver IPs (one per line)")
    p.add_argument("--org-networks", help="File of org CIDRs, one per line (overrides config org_networks)")
    p.add_argument("--geo", action="store_true",
                   help="Opt in to ip-api.com geo/ASN lookups. Sends each resolved IP to a third "
                        "party over plain HTTP (free tier has no HTTPS); off by default so "
                        "engagement IPs stay private. Off = asn/country/city are N/A and "
                        "ASN-based CDN detection is skipped")
    p.add_argument("--no-geo", action="store_true", help=argparse.SUPPRESS)  # legacy; geo is off by default
    p.add_argument("--no-axfr", action="store_true", help="Skip AXFR zone-transfer checks")
    p.add_argument("--no-tls", action="store_true",
                   help="Skip TLS/cert probing (much faster; for content-only passes)")
    p.add_argument("--no-rdap", action="store_true",
                   help="Skip RDAP registration lookups (registrar/created/status)")
    p.add_argument("--no-whois", action="store_true",
                   help="Skip the port-43 WHOIS fallback used when RDAP is empty (.ch etc.)")
    p.add_argument("--config", metavar="FILE",
                   help="Brand/engagement config (default: $CLIPEUS_CONFIG, brand.json beside "
                        "clipeus.py, ~/.config/clipeus/brand.json); see brand.example.json")
    p.add_argument("--approved-mx", default=None,
                   help="Comma list of approved MX domains; others flag independent-mail "
                        "(default: approved_mx from the config; unset = mail policy not checked)")
    p.add_argument("--approved-redirect", default=None,
                   help="Comma list of approved redirect targets; others flag redirect-offsite "
                        "(default: approved_redirect from the config; unset = redirect policy not checked)")
    p.add_argument("--subs-file", help="Enumerate subdomains (subfinder + crt.sh CT logs) "
                                       "into this file, then audit them too")
    p.add_argument("--enumerate-only", action="store_true",
                   help="Only enumerate subdomains to --subs-file; skip the audit")
    p.add_argument("--normalize-only", action="store_true",
                   help="Only normalize --input (strip scheme/path/port, repair mojibake, "
                        "IDN->punycode, dedupe) to --output/stdout; un-encodable lines go to "
                        "<output>.review (or stderr). Use as an early input-cleaning pass.")
    p.add_argument("--drop-www", action="store_true",
                   help="Drop www.X subdomains when X is already in scope "
                        "(default keeps them — www.X is a real enumerated subdomain)")
    p.add_argument("--dedup-www-input", action="store_true",
                   help="When reading --input, skip www.X if X is also present "
                        "(avoids scanning www.xyz.com when xyz.com is in the source)")
    p.add_argument("--no-ct", action="store_true",
                   help="Disable crt.sh certificate-transparency enumeration")
    p.add_argument("--censys", action="store_true",
                   help="Enable Censys hosts-index enumeration (opt-in: metered/credit-limited, "
                        "needs CENSYS_API_ID/SECRET or a subfinder provider key; see --censys-max)")
    p.add_argument("--no-censys", action="store_true",
                   help="Force Censys off even if --censys is given (overrides --censys)")
    p.add_argument("--censys-max", type=int, default=0, metavar="N",
                   help="Stop calling Censys after N API calls this run (0 = unlimited). "
                        "Credential errors (401/402/403/410) always disable it for the run")
    p.add_argument("--no-certspotter", action="store_true",
                   help="Disable CertSpotter CT enumeration (the reliable crt.sh replacement)")
    p.add_argument("--ct-tld", action="append", default=[],
                   help="Sweep an entire brand TLD (crt.sh + Censys), e.g. --ct-tld brand (repeatable)")
    p.add_argument("--enum-workers", type=int, default=6,
                   help="Concurrent domains during subdomain enumeration (CertSpotter/Censys)")
    p.add_argument("--subfinder-timeout", type=int, default=15,
                   help="subfinder per-source timeout (s) — caps a slow source")
    p.add_argument("--subfinder-maxtime", type=int, default=5,
                   help="subfinder per-domain max enumeration time (minutes)")
    p.add_argument("--subfinder-all", action="store_true",
                   help="Use subfinder -all (every source, slower); off by default since "
                        "CertSpotter+Censys already provide CT depth")
    p.add_argument("--no-subfinder", action="store_true",
                   help="Skip subfinder entirely (it's ~sequential and slow on large "
                        "lists); rely on parallel CertSpotter + Censys instead")
    p.add_argument("--no-resolve-subs", action="store_true",
                   help="Don't DNS-validate discovered subdomains (write raw, noisy set). "
                        "Default validates: only resolvable names reach the subs file "
                        "(full raw set saved to <subs-file>.all)")
    p.add_argument("--accurate", action="store_true",
                   help="Favor accuracy over speed: low concurrency, long timeouts, DNS retries")
    p.add_argument("--log", dest="logfile", help="Append live progress here (tail -f friendly)")
    p.add_argument("--raw", action="store_true",
                   help="Embed a nested `raw` object per record (JSON/JSONL only)")
    p.add_argument("--raw-dir", help="Dump per-host evidence files (body/headers/cert/dns/rdap)")
    p.add_argument("--emit", action="append", default=[], choices=sorted(EmitSink.CATEGORIES),
                   help="Also emit a feed for the next tool (repeatable)")
    p.add_argument("--emit-file", help="Write --emit feed here instead of stdout")
    p.add_argument("--resume", action="store_true", help="Skip domains already in --output")
    p.add_argument("--checkpoint-interval", type=int, default=50)
    p.add_argument("--quiet", action="store_true", help="Suppress per-domain progress")
    p.add_argument("--version", action="version", version=f"clipeus {__version__}")
    p.add_argument("--selftest", action="store_true", help="Run internal checks and exit")
    p.add_argument("--show-config", action="store_true",
                   help="Print the effective tuning/config (JSON) and exit — "
                        "for operators and agent/CLI introspection")
    return p


def _show_resolvers(resolvers_file, config):
    """Effective resolvers + source for --show-config (same lookup a real run uses)."""
    try:
        cfg = brand_config.load(config)[0]
        ips, src = brand_config.effective_resolvers(resolvers_file, cfg)
        return {"servers": ips, "source": src}
    except ValueError as exc:
        return {"error": str(exc)}


def main() -> None:
    args = build_parser().parse_args()
    if args.selftest:
        sys.exit(selftest())

    if args.show_config:
        eff = {
            "tuning_source": _TUNING.get("_source", "(none — in-code defaults)"),
            "tuned_keys": sorted(k for k in _TUNING if not k.startswith("_")),
            "effective": {
                "resolvers": _show_resolvers(args.resolvers, args.config),
                "top_ports": TOP_PORTS,
                "dkim_selectors": list(DKIM_SELECTORS),
                "dkim_min_bits": DKIM_MIN_BITS,
                "hsts_min_max_age": HSTS_MIN_MAX_AGE,
                "spf_max_queries": SPF_MAX_QUERIES,
                "scanner_points": SCANNER_POINTS,
                "scanner_points_cap": SCANNER_POINTS_CAP,
                "certspotter_max_wait": CERTSPOTTER_MAX_WAIT,
                "max_body_bytes": MAX_BODY_BYTES,
                "nxdomain_only_providers": list(NXDOMAIN_ONLY_PROVIDERS),
            },
            "external_overrides": {
                "resolvers": "--resolvers FILE | $CLIPEUS_RESOLVERS | config resolvers | tuning dns_servers | default",
                "org_networks": "--org-networks FILE | config org_networks | none",
                "takeover_fingerprints": "--takeover-sigs FILE (supplements built-ins)",
                "brand_policy": "--config FILE | $CLIPEUS_CONFIG | brand.json | ~/.config/clipeus/brand.json",
                "tuning": "$CLIPEUS_TUNING | clipeus.tuning.json | ~/.config/clipeus/tuning.json",
            },
        }
        print(json.dumps(eff, indent=2, ensure_ascii=False))
        sys.exit(0)

    # --accurate: trade speed for thoroughness.
    if args.accurate:
        args.workers = min(args.workers, 8)
        args.timeout = max(args.timeout, 15.0)
        RESOLVER.timeout = 5.0
        RESOLVER.lifetime = 12.0
        global _DNS_RETRIES
        _DNS_RETRIES = 2

    try:
        brand_cfg, brand_path = brand_config.load(args.config)
    except ValueError as exc:
        sys.exit(f"error: config {exc}")
    if brand_path:
        print(f"[*] config: {brand_path}", file=sys.stderr)

    def _domain_list(cli: Optional[str], key: str) -> List[str]:
        if cli is None:
            return list(brand_cfg[key])
        return [d.strip().lower() for d in cli.split(",") if d.strip()]

    args.approved_mx = _domain_list(args.approved_mx, "approved_mx")
    args.approved_redirect = _domain_list(args.approved_redirect, "approved_redirect")

    global RL, INGEST
    RL = RateLimiter(args.rate)
    _CENSYS["max"] = max(0, args.censys_max)

    if args.ingest:
        try:
            INGEST = load_ingest(args.ingest)
        except OSError as exc:
            sys.exit(f"error: --ingest: {exc}")
        print(f"[*] ingest: {INGEST['lines']} records read "
              f"({len(INGEST['nuclei'])} hosts with findings, {len(INGEST['httpx'])} with httpx data, "
              f"{INGEST['skipped']} skipped)", file=sys.stderr)

    if args.takeover_sigs:
        try:
            n = load_takeover_fingerprints(args.takeover_sigs)
        except (OSError, ValueError) as exc:
            sys.exit(f"error: --takeover-sigs {args.takeover_sigs}: {exc}")
        print(f"[*] loaded {n} takeover fingerprints from {args.takeover_sigs}", file=sys.stderr)

    # Resolvers: one precedence shared by every Clipeus tool (brand_config.effective_resolvers):
    # --resolvers FILE / $CLIPEUS_RESOLVERS > config "resolvers" > tuning "dns_servers" > default.
    try:
        servers, src = brand_config.effective_resolvers(args.resolvers, brand_cfg)
    except ValueError as exc:
        sys.exit(f"error: resolvers {exc}")
    RESOLVER.nameservers = servers
    print(f"[*] resolvers: {', '.join(servers)} (from {src})", file=sys.stderr)

    # Live progress log (tail -f friendly), plus stderr.
    log_fh = open(args.logfile, "a") if args.logfile else None

    def log(msg: str) -> None:
        line = f"{time.strftime('%H:%M:%S')} {msg}"
        with _print_lock:
            if not args.quiet:
                print(line, file=sys.stderr)
            if log_fh:
                log_fh.write(line + "\n")
                log_fh.flush()

    # Report-only mode: no network, just post-process an existing results file.
    if args.merge_out and not args.report_from:
        sys.exit("error: --merge-out is used with --report-from")
    if args.report_from:
        if not (args.report_html or args.baseline or args.merge_out):
            sys.exit("error: --report-from needs --report-html, --baseline and/or --merge-out")
        source = args.report_from
        if args.merge_out:
            if INGEST is None:
                sys.exit("error: --merge-out needs --ingest")
            source = merge_results(args.report_from, args.merge_out, INGEST, args, log)
        if args.report_html or args.baseline:
            post_process(source, args.baseline, args.report_html, args.diff_out, log)
        return
    if (args.baseline or args.report_html) and args.output == "-":
        sys.exit("error: --baseline / --report-html need --output FILE (not stdout)")

    # Guard against two sinks fighting over stdout.
    emit_to_stdout = bool(args.emit) and not args.emit_file
    if emit_to_stdout and args.output == "-":
        sys.exit("error: --emit and --output both target stdout; set --emit-file or --output FILE")

    port_list = {"none": [], "top": TOP_PORTS,
                 "standard": STANDARD_PORTS, "full": FULL_PORTS}[args.ports]
    org_networks = load_networks(args.org_networks, brand_cfg.get("org_networks"))

    signal.signal(signal.SIGINT, lambda *_: STOP.set())

    if args.normalize_only:
        src = sys.stdin if args.input in ("-", None) else open(args.input)
        seen, cleaned, review = set(), [], []
        try:
            for raw in src:
                line = raw.rstrip("\n")
                if not line.strip() or line.lstrip().startswith("#"):
                    continue
                h = normalize_host(line)
                if h:
                    if h not in seen:
                        seen.add(h); cleaned.append(h)
                else:
                    review.append(line)   # non-empty, non-comment, yet un-encodable
        finally:
            if src is not sys.stdin:
                src.close()
        out = args.output
        if out in (None, "-"):
            sys.stdout.write("\n".join(cleaned) + ("\n" if cleaned else ""))
            for r in review:
                print(f"[review] could not normalize: {r!r}", file=sys.stderr)
        else:
            with open(out, "w", encoding="utf-8") as fo:
                fo.write("\n".join(cleaned) + ("\n" if cleaned else ""))
            if review:
                with open(out + ".review", "w", encoding="utf-8") as fr:
                    fr.write("\n".join(review) + "\n")
        log(f"[*] normalize-only: {len(cleaned)} hosts"
            + (f", {len(review)} un-encodable -> review" if review else ""))
        if log_fh:
            log_fh.close()
        return

    domains = read_inputs(args.input, dedup_www=args.dedup_www_input)
    log(f"[*] Clipeus v{__version__} | loaded {len(domains)} input domains | "
        f"workers={args.workers} accurate={args.accurate} ports={args.ports}")

    # Subdomain enumeration pre-pass (subfinder + crt.sh CT) -> subs_file, audited too.
    sub_targets: set = set()
    if args.subs_file or args.ct_tld:
        subs_out = args.subs_file or "/tmp/clipeus_subs.txt"
        log(f"[*] enumerating subdomains (subfinder{'' if args.no_ct else ' + crt.sh'}"
            f"{', ct-tld=' + ','.join(args.ct_tld) if args.ct_tld else ''}) -> {subs_out}")
        subs = enumerate_subdomains(domains, subs_out, log,
                                    use_ct=not args.no_ct, ct_tlds=args.ct_tld,
                                    use_censys=args.censys and not args.no_censys,
                                    use_certspotter=not args.no_certspotter,
                                    enum_workers=args.enum_workers,
                                    resolve_subs=not args.no_resolve_subs,
                                    sf_timeout=args.subfinder_timeout,
                                    sf_maxtime=args.subfinder_maxtime,
                                    sf_all=args.subfinder_all,
                                    use_subfinder=not args.no_subfinder,
                                    drop_www=args.drop_www)
        log(f"[*] subdomain enumeration done: +{len(subs)} subdomains")
        existing = set(domains)
        for s in subs:
            sub_targets.add(s)
            if s not in existing:
                existing.add(s)
                domains.append(s)

    if args.enumerate_only:
        log(f"[*] enumerate-only: wrote subdomains to {args.subs_file}; skipping audit")
        if log_fh:
            log_fh.close()
        return

    done = done_domains(args.output, args.format) if args.resume else set()
    todo = [d for d in domains if d not in done]
    total = len(todo)

    if args.raw and args.format == "csv":
        log("[!] --raw needs --format json/jsonl; use --raw-dir for CSV runs. Ignoring inline --raw.")

    log(f"[*] auditing {total} domains ({len(done)} already done) -> {args.output}")

    writer = OutputWriter(args.output, args.format, args.resume,
                          raw=args.raw, raw_dir=args.raw_dir)
    emit = EmitSink(args.emit, args.emit_file) if args.emit else None
    session = build_session(args.timeout)
    completed = 0

    try:
        with ThreadPoolExecutor(max_workers=args.workers) as ex:
            futures = {ex.submit(process_domain, d, session, args, org_networks, port_list): d
                       for d in todo}
            for fut in as_completed(futures):
                rec = fut.result()
                if rec.domain in sub_targets:
                    rec.is_subdomain = "Yes"
                writer.write(rec)
                if emit:
                    emit.feed(rec)
                completed += 1
                tag = (f"ERR {rec.error}" if rec.error else
                       f"{rec.disposition:16} issues=[{rec.config_issues[:60]}] risk:{rec.risk_score}")
                log(f"[{completed}/{total}] {rec.domain:<38} {tag}")
                if writer.fmt == "json" and completed % args.checkpoint_interval == 0:
                    writer.flush_json()
                if STOP.is_set():
                    log("[!] interrupted — flushing partial results...")
                    ex.shutdown(wait=False, cancel_futures=True)
                    break
    finally:
        writer.close()
        if emit:
            emit.close()

    log(f"[*] Done. {completed} records -> {args.output}")
    if (args.baseline or args.report_html) and completed:
        post_process(args.output, args.baseline, args.report_html, args.diff_out, log)
    if log_fh:
        log_fh.close()


if __name__ == "__main__":
    main()
