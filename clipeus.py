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

__version__ = "26.11.2"  # CalVer YY.MM.patch; single source of truth (pyproject + banner + UA read this)

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
import dns.rcode
import dns.rdatatype

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
    "azurewebsites.net", "azureedge.net",
    "trafficmanager.net", "cloudapp.azure.com", "cloudapp.net", "elasticbeanstalk.com",
    "trydiscourse.com", "blob.core.windows.net", "azure-api.net", "azurehdinsight.net",
    "azurecontainer.io", "database.windows.net", "azuredatalakestore.net",
    "search.windows.net", "azurecr.io", "redis.cache.windows.net", "servicebus.windows.net",
    "visualstudio.com")
# merge=True: a tuning file can ADD providers but never drop one, because dropping
# a provider removes its NXDOMAIN gate and turns ordinary 404s into takeover findings.
NXDOMAIN_ONLY_PROVIDERS = tuple(_tune("nxdomain_only_providers", list(NXDOMAIN_ONLY_PROVIDERS), merge=True))

# Body signatures too generic to prove an unclaimed resource: any app can serve them.
# A match is recorded as an observation (takeover_risk=Possibly), never as Yes.
WEAK_TAKEOVER_SIGNATURES = {"404", "error 404", "page not found", "not found", "bad request"}

# Can a deleted resource's provider name be registered again by anyone? "released" only
# where that is the provider's documented behaviour; everything else stays "unknown"
# until an analyst checks the provider (some reserve names, or offer unique hostnames).
# Keys match as substrings of the CNAME target; the longest matching key wins, so a
# service inside a provider domain can differ from the domain (S3 buckets vs ELB names).
TAKEOVER_NAME_POLICY = {
    "cloudapp.azure.com": "released", "cloudapp.net": "released",
    "trafficmanager.net": "released", "elasticbeanstalk.com": "released",
    ".s3.amazonaws.com": "released", ".s3-": "released", ".s3.": "released", "s3-website": "released",
    "elb.amazonaws.com": "reserved (random load-balancer id)",
}
TAKEOVER_NAME_POLICY.update(_tune("takeover_name_policy", {}))

# Providers that require a DNS verification record before a custom hostname can be bound
# to a new resource. If the record exists for this host, a stranger who recreates the
# resource cannot attach the hostname. "{host}" is replaced by the audited name.
TAKEOVER_BINDING_TXT = {
    "azurewebsites.net": "asuid.{host}",
    "azurefd.net": "_dnsauth.{host}",
}
TAKEOVER_BINDING_TXT.update(_tune("takeover_binding_txt", {}))

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
        return s if _HOST_RE.match(s) else None  # plain ASCII hostname
    out = None
    if _HAVE_IDNA:
        try:
            out = idna.encode(s, uts46=True).decode("ascii")
        except idna.IDNAError:
            pass
    if out is None:
        try:
            out = s.encode("idna").decode("ascii")
        except Exception:
            return None  # non-ASCII that cannot be IDNA-encoded is not a valid host
    return out if _HOST_RE.match(out) else None


# Hostname syntax after IDNA encoding: labels of letters, digits, '-' and '_' (service
# labels such as _dmarc). Anything else, e.g. spaces carried through IDNA, is not a host.
_HOST_RE = re.compile(r"^(?!-)[a-z0-9_-]{1,63}(?:\.(?!-)[a-z0-9_-]{1,63})*$")


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
    is_subdomain: str = "No"           # Yes when the host is below its root_domain
    mx_approved: str = "N/A"           # Yes/No/None — does mail route via the approved domain
    independent_mail: str = "No"       # has its own MX not under the approved domain
    service_independent: str = "No"    # live service NOT redirecting to the approved domain
    config_issues: str = "None"        # actionable, fixable misconfigurations
    dirty_forwarding: str = "No"
    risk_score: int = 0
    score_notes: str = ""
    error: str = ""
    body_truncated: str = "No"   # Yes = response cut at MAX_BODY_BYTES / deadline
    technology: str = ""         # consolidated stack (see detect_technology); "; "-separated
    platform_risk: str = ""      # out-of-date / non-enterprise platforms (see assess_platforms)
    # --- Appended in 26.11.1; every column above keeps its position and meaning. ---
    root_domain: str = "N/A"           # portfolio root this host sits under (see host_root)
    tls_handshake: str = "N/A"         # ok / failed / no-listener (nothing on 443)
    tls_hostname: str = "N/A"          # pass / fail (certificate names vs this host)
    tls_trust: str = "N/A"             # pass / self-signed / untrusted-chain / invalid
    tls_dates: str = "N/A"             # pass / expired / not-yet-valid
    tls_protocol: str = "N/A"          # pass / legacy(TLSv1.0) — lowest version accepted
    cert_defects: str = "None"         # every certificate defect, not just the first: expired;self-signed
    dangling_class: str = "N/A"        # see detect_dangling: nxdomain / no-web-records / dangling-cname ...
    takeover_target_missing: str = "N/A"     # Yes / No — the provider resource behind the CNAME is gone
    takeover_recreatable: str = "N/A"        # released / reserved / unknown (provider name policy)
    takeover_binding_protected: str = "N/A"  # Yes (verification TXT present) / No / not-required / unknown
    takeover_confidence: str = "N/A"         # High / Medium / Low
    takeover_claim_verified: str = "N/A"     # "No (manual)": claiming is never attempted
    port_services: str = "None"        # port:service(source); source = banner / port-guess
    network_owner: str = "N/A"         # ASN (with --geo) or provider inferred from PTR / CNAME
    hosting_class: str = "N/A"         # org / private / cdn / cloud / third-party / unknown
    managed_by: str = "N/A"            # org-network / org-provider(x) / not-verified
    reachability: str = "N/A"          # dns:ok;tcp:ok;tls:ok;http:200 — how far a client gets
    private_endpoint: str = "No"       # Yes(reason) when the name points at a private endpoint
    assessed_status: str = "N/A"       # HTTP status of the response whose headers/cookies were graded
    cookie_context: str = "None"       # name@URL that set it (session-like cookies marked *)
    spf_raw_chunks: str = "N/A"        # the TXT strings as published, when the SPF record is split
    risk_exposure: int = 0             # risk_score part: reachable / claimable exposure
    risk_hygiene: int = 0              # risk_score part: missing hardening
    risk_confidence: str = "N/A"       # High / Medium / Low — how much of the score is confirmed
    endpoint_ids: str = "None"         # ip:port endpoints observed for this host
    site_id: str = "N/A"               # hash of final host + body: same site behind many names
    checks: str = ""                   # check=state;... state = passed/failed/not_applicable/not_run/timeout/error
    scanned_at: str = ""               # UTC time this record was produced
    clipeus_version: str = ""
    rules_version: str = ""            # hash of the takeover / port / platform rules in effect
    # --- Appended in 26.11.2. ---
    takeover_outcome: str = "N/A"      # none / provider-binding-review / protected / dangling-reserved /
                                       # potentially-reclaimable / claimable-by-policy /
                                       # claimable-by-signature / claimable-ns-domain / verified
    takeover_evidence: str = "N/A"     # the observations the outcome was derived from
    ns_parent: str = "N/A"             # NS the parent zone's referral delegates this name to
    ns_own: str = "N/A"                # NS the name's own zone answers with (child side)
    ns_resolution: str = "N/A"         # nameserver=address|NXDOMAIN|NOANSWER|TIMEOUT;...
    ns_registration: str = "N/A"       # registrable domain of each unresolvable NS = registration result
    rdap_result: str = "N/A"           # ok / whois / not-registered / unsupported-tld / rate-limited /
                                       # timeout / http-NNN / parse-error (per registrable domain)
    overrides: str = "None"            # manual findings merged from --overrides: field=value (date, by; evidence)


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


def _resolve_txt_chunks(domain: str) -> Tuple[Tuple[str, ...], ...]:
    """TXT records as the individual character-strings they were published in."""
    try:
        return tuple(tuple(s.decode("utf-8", "ignore") if isinstance(s, bytes) else s
                           for s in r.strings) for r in RESOLVER.resolve(domain, "TXT"))
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

    # ns_servers keeps its meaning (NS of the closest enclosing zone, used for AXFR);
    # own_ns is only the name's OWN delegation, which is what dangling checks may judge.
    ns_records: Tuple[str, ...] = ()
    own_ns: Tuple[str, ...] = ()
    zone = ""
    for i in range(len(parts) - 1):
        ns_records = _resolve(".".join(parts[i:]), "NS")
        if ns_records:
            rec.ns_servers = ",".join(sorted(ns_records))
            zone = ".".join(parts[i:])
            own_ns = ns_records if i == 0 else ()
            break

    txts = _resolve(domain, "TXT")
    spf_info = parse_spf(list(txts))
    if spf_info["spf_record"]:
        rec.spf = spf_info["spf_record"]
        chunks = next((c for c in _resolve_txt_chunks(domain) if "".join(c) == rec.spf), ())
        if len(chunks) > 1:
            rec.spf_raw_chunks = " ".join(json.dumps(c) for c in chunks)
    if spf_info["spf_issues"]:
        rec.spf_issues = ",".join(spf_info["spf_issues"])
    keys = [t[:20] + "..." for t in txts
            if "v=spf1" not in t.lower() and re.search(r"[A-Za-z0-9/+_-]{32,}", t)]
    if keys:
        rec.txt_entropy_keys = ",".join(keys[:3])

    # DMARC falls back to the organizational domain (RFC 7489 6.6.3), not the parent.
    dmarc_txts = list(_resolve(f"_dmarc.{domain}", "TXT"))
    inherited = False
    org = registrable_domain(domain)
    if not any(t.lower().startswith("v=dmarc1") for t in dmarc_txts) and org and org != domain:
        parent = list(_resolve(f"_dmarc.{org}", "TXT"))
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
    # CAA is inherited down the tree (RFC 8659 3): climb to the organizational domain.
    for i in range(len(parts) - 1):
        name = ".".join(parts[i:])
        caa = _resolve(name, "CAA")
        if caa:
            rec.caa_records = ",".join(caa) + (f" (Inherited from {name})" if i else "")
            break
        if name == org:
            break

    return {"chain": chain, "ns": list(own_ns), "zone_ns": list(ns_records), "zone": zone,
            "a_records": list(a_records), "aaaa": list(aaaa), "txts": list(txts),
            "has_resolution": bool(a_records or aaaa or chain)}


@lru_cache(maxsize=100000)
def check_dnssec(domain: str) -> str:
    """Ask a validating resolver; the AD (Authenticated Data) flag on an answer that
    exists (NOERROR, including NODATA) => DNSSEC-signed."""
    try:
        q = dns.message.make_query(domain, "A", want_dnssec=True)
        for server in RESOLVER.nameservers:
            try:
                r = dns.query.udp(q, server, timeout=3)
                # An authenticated NXDOMAIN only proves the parent zone is signed
                if r.rcode() == dns.rcode.NXDOMAIN:
                    return "No"
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


RDAP_RETRIES = 3              # attempts per registrable domain (429 / 5xx / timeout)
RDAP_BACKOFF = (2.0, 5.0)     # seconds between attempts unless Retry-After says less (cap 10 s)


def _age_days(created: str) -> str:
    if created in ("N/A", ""):
        return "N/A"
    try:
        from datetime import datetime, timezone
        dt = datetime.fromisoformat(created)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return str((datetime.now(timezone.utc) - dt).days)
    except Exception:
        return "N/A"


RDAP_BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"
_RDAP_BOOTSTRAP: Optional[Dict[str, str]] = None   # TLD -> registry RDAP base; {} = unavailable
_RDAP_BOOTSTRAP_LOCK = threading.Lock()


def _rdap_base(reg: str) -> Optional[str]:
    """The registry's own RDAP server for this domain, from the IANA bootstrap (loaded once
    per run). Querying registries directly avoids a shared redirector's rate limit, and a
    TLD missing from the bootstrap has no RDAP: "" means that, None means the bootstrap
    could not be loaded (then rdap.org is used)."""
    global _RDAP_BOOTSTRAP
    with _RDAP_BOOTSTRAP_LOCK:
        if _RDAP_BOOTSTRAP is None:
            try:
                r = requests.get(RDAP_BOOTSTRAP_URL, timeout=15,
                                 headers={"User-Agent": f"clipeus/{__version__} (RDAP client)"})
                svc = r.json().get("services", []) if r.status_code == 200 else []
                _RDAP_BOOTSTRAP = {t.lower(): urls[0] for tlds, urls in svc for t in tlds if urls}
            except Exception:
                _RDAP_BOOTSTRAP = {}
    if not _RDAP_BOOTSTRAP:
        return None
    labels = reg.lower().split(".")
    for i in range(len(labels)):
        base = _RDAP_BOOTSTRAP.get(".".join(labels[i:]))
        if base:
            return base
    return ""


def _registry_is_authoritative(reg: str) -> bool:
    """Can the TLD registry say this name is unregistered? Yes for name.tld, and for
    second levels a ccTLD registry runs (example.co.uk). Not for names under a privately
    run suffix of a generic TLD (example.eu.com): the .com registry only knows eu.com."""
    labels = reg.split(".")
    return len(labels) <= 2 or len(labels[-1]) == 2


def _rdap_query(reg: str) -> Dict[str, Any]:
    """One RDAP lookup with retries. `result` says why a field is empty: ok,
    not-registered (the registry answered 404), unsupported-tld (no RDAP server known),
    rate-limited, timeout, http-NNN, parse-error. A failed lookup is never read as
    "not registered"."""
    out: Dict[str, Any] = {"registrar": "N/A", "created": "N/A", "expires": "N/A",
                           "status": "N/A", "raw": {}, "result": "error"}
    base = _rdap_base(reg)
    if base == "":
        out["result"] = "unsupported-tld"
        return out
    url = f"{base.rstrip('/')}/domain/{reg}" if base else f"https://rdap.org/domain/{reg}"
    for attempt in range(RDAP_RETRIES):
        if STOP.is_set():
            break
        RL.wait()
        try:
            # RDAP servers commonly 403 browser-like UAs; use a neutral client UA.
            r = requests.get(url, timeout=8,
                             headers={"User-Agent": f"clipeus/{__version__} (RDAP client)"})
        except requests.Timeout:
            out["result"] = "timeout"
        except requests.RequestException:
            out["result"] = "error"
        else:
            if r.status_code == 200:
                try:
                    d = r.json()
                except ValueError:
                    out["result"] = "parse-error"
                    return out
                out.update(_parse_rdap(d), result="ok")
                return out
            if r.status_code == 404:
                # A registry's 404 means no such registration. Through rdap.org (bootstrap
                # unavailable) only a 404 after the redirect to a registry means that.
                if not (base or r.history):
                    out["result"] = "unsupported-tld"
                else:
                    out["result"] = ("not-registered" if _registry_is_authoritative(reg)
                                     else "not-found(tld-registry)")
                return out
            if r.status_code != 429 and r.status_code < 500:
                out["result"] = f"http-{r.status_code}"
                return out
            out["result"] = "rate-limited" if r.status_code == 429 else f"http-{r.status_code}"
            wait = r.headers.get("Retry-After", "")
            if wait.isdigit() and attempt < RDAP_RETRIES - 1:
                time.sleep(min(int(wait), 10))
                continue
        if attempt < RDAP_RETRIES - 1:
            time.sleep(RDAP_BACKOFF[min(attempt, len(RDAP_BACKOFF) - 1)])
    return out


def _parse_rdap(d: dict) -> Dict[str, Any]:
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
    status = ",".join(d.get("status", [])) or "N/A"
    raw = {"registrar": registrar, "status": d.get("status", []),
           "events": d.get("events", []), "nameservers":
           [n.get("ldhName") for n in d.get("nameservers", [])]}
    return {"registrar": registrar, "created": created, "expires": expires,
            "status": status, "raw": raw}


_REG_CACHE: Dict[Tuple[str, bool], Dict[str, Any]] = {}
_REG_LOCKS: Dict[Tuple[str, bool], threading.Lock] = {}
_REG_GUARD = threading.Lock()


def lookup_registration(reg: str, use_whois: bool = True) -> Dict[str, Any]:
    """Registration data for a registrable domain, looked up once per run however many
    hostnames sit under it (one lookup per host rate-limits the RDAP service and turns
    good domains into errors). RDAP first; WHOIS when RDAP gives no answer."""
    key = (reg, use_whois)
    with _REG_GUARD:
        lock = _REG_LOCKS.setdefault(key, threading.Lock())
    with lock:
        if key in _REG_CACHE:
            return _REG_CACHE[key]
        res = _rdap_query(reg)
        if use_whois and res["result"] not in ("ok", "not-registered"):
            w_reg, w_created, w_status, w_src, w_raw = whois_fallback(reg)
            if w_status == "unregistered":
                res["result"] = ("not-registered(whois)" if _registry_is_authoritative(reg)
                                 else "not-found(tld-registry)")
            elif w_reg != "N/A" or w_created != "N/A":
                res.update(registrar=f"{w_reg} (whois)" if w_reg != "N/A" else "N/A",
                           created=w_created, result="whois")
                if w_status != "N/A":
                    res["status"] = w_status
            if w_src != "N/A":
                res["whois_raw"] = {"source": w_src, **w_raw}
        res["age_days"] = _age_days(res["created"])
        _REG_CACHE[key] = res
        return res


def get_rdap(domain: str) -> Tuple[str, str, str, str, str, dict]:
    """Back-compatible tuple view of lookup_registration (RDAP only)."""
    r = lookup_registration(registrable_domain(domain), use_whois=False)
    return r["registrar"], r["created"], r["expires"], r["age_days"], r["status"], r["raw"]


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
                              "no object found", "is available", "no data found")):
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


_SPF_VERSION_RE = re.compile(r"^v=spf1(?:\s|$)", re.I)


def is_spf_record(txt: str) -> bool:
    """RFC 7208 4.5: the record is "v=spf1" followed by a space or the end of the string.
    "v=spf1mx..." (strings split without spaces, joined as published) is not SPF."""
    return bool(_SPF_VERSION_RE.match(txt or ""))


def parse_spf(txts: List[str]) -> Dict[str, Any]:
    spf = [t for t in txts if is_spf_record(t)]
    res = {"spf_present": bool(spf), "spf_record": spf[0] if spf else None, "spf_issues": []}
    if not spf:
        bad = [t for t in txts if t.lower().startswith("v=spf1")]
        if bad:
            # Receivers ignore it, so the domain effectively has no SPF; keep the text.
            res["spf_record"] = bad[0]
            res["spf_issues"].append("spf_malformed_version")
        else:
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
    return tuple(t for t in _resolve(name, "TXT") if is_spf_record(t))


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


def _parent_delegation(domain: str, zone_ns: List[str]) -> Tuple[str, ...]:
    """NS names the enclosing zone delegates `domain` to, read from that zone's own
    referral (non-recursive query), so a delegation whose servers no longer answer is
    still visible."""
    return _parent_delegation_cached(domain.lower(), tuple(zone_ns))


@lru_cache(maxsize=20000)
def _parent_delegation_cached(domain: str, zone_ns: Tuple[str, ...]) -> Tuple[str, ...]:
    for server in zone_ns[:3]:
        try:
            ip = RESOLVER.resolve(server, "A")[0].to_text()
            q = dns.message.make_query(domain, "NS")
            q.flags &= ~dns.flags.RD
            r = dns.query.udp(q, ip, timeout=3)
            for rrset in list(r.answer) + list(r.authority):
                if (rrset.rdtype == dns.rdatatype.NS
                        and rrset.name.to_text().rstrip(".").lower() == domain.lower()):
                    return tuple(str(x.target).rstrip(".").lower() for x in rrset)
            return ()
        except Exception:
            continue
    return ()


@lru_cache(maxsize=20000)
def _enclosing_zone(domain: str) -> Tuple[str, Tuple[str, ...]]:
    """The closest zone above `domain` that has NS records, and those NS."""
    parts = domain.split(".")
    for i in range(1, len(parts)):
        name = ".".join(parts[i:])
        ns = _resolve(name, "NS")
        if ns:
            return name, tuple(sorted(ns))
    return "", ()


@lru_cache(maxsize=20000)
def _ns_address(name: str) -> str:
    """First IPv4 address of a nameserver, or why there is none."""
    try:
        return RESOLVER.resolve(name, "A")[0].to_text()
    except dns.resolver.NXDOMAIN:
        return "NXDOMAIN"
    except dns.resolver.NoAnswer:
        return "AAAA-only" if _resolve(name, "AAAA") else "NOANSWER"
    except dns.exception.Timeout:
        return "TIMEOUT"
    except Exception:
        return "ERROR"


def delegation_evidence(domain: str, own_ns: List[str], zone: str, zone_ns: List[str],
                        has_resolution: bool, dns_status: str, use_whois: bool = True
                        ) -> Dict[str, Any]:
    """Both sides of a delegation, kept apart: the parent zone's referral and the name's
    own NS answer, each nameserver's address, and for every nameserver that does not
    exist, whether its registrable domain is registered. Collected only where the name
    is a zone cut or its resolution failed (where a delegation can dangle)."""
    failed = not has_resolution and dns_status in ("SERVFAIL", "TIMEOUT", "ERROR")
    if not own_ns and not failed:
        return {}
    if own_ns:
        _zone, parent_servers = _enclosing_zone(domain)
    else:                       # the NS walk already stopped at the enclosing zone
        parent_servers = tuple(zone_ns) if zone != domain else ()
    parent = _parent_delegation(domain, list(parent_servers)) if parent_servers else ()
    names = sorted(set(parent) | set(own_ns))
    if not names:
        return {}
    addr = {n: _ns_address(n) for n in names}
    regs: Dict[str, str] = {}
    for n, a in addr.items():
        if a == "NXDOMAIN":
            r = registrable_domain(n)
            if r and r not in regs:
                regs[r] = lookup_registration(r, use_whois)["result"]
    return {"parent": tuple(parent), "own": tuple(own_ns), "addresses": addr, "registration": regs}


def detect_dangling(domain: str, chain: List[str], ns: List[str], has_resolution: bool,
                    dns_status: str = "OK", zone_ns: Optional[List[str]] = None
                    ) -> Tuple[str, str, str]:
    """(status, detail, class). `ns` is the name's OWN delegation only: the NS of an
    enclosing zone says nothing about whether this name dangles. Classes:
    dangling-cname, dangling-delegation, lame-delegation (dangling, or suspect);
    nxdomain, no-web-records, dns-failure, ok (not dangling)."""
    if chain:
        final = chain[-1]
        try:
            RESOLVER.resolve(final, "A")
        except dns.resolver.NXDOMAIN:
            return "Yes", f"CNAME target NXDOMAIN: {final}", "dangling-cname"
        except dns.resolver.NoAnswer:
            if not _resolve(final, "AAAA"):
                return "Possibly", f"CNAME target has no A/AAAA: {final}", "dangling-cname"
        except dns.exception.Timeout:
            return "No", f"CNAME target timeout: {final}", "dns-failure"
        except Exception:
            pass
    delegation = list(ns)
    if not delegation and not has_resolution and dns_status in ("SERVFAIL", "TIMEOUT", "ERROR") and zone_ns:
        delegation = list(_parent_delegation(domain, zone_ns))
    if delegation:
        unresolved = []
        for server in delegation:
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
        if unresolved and len(unresolved) == len(delegation):
            return "Yes", f"All NS unresolvable: {','.join(unresolved)}", "dangling-delegation"
        if unresolved:
            return "Possibly", f"Some NS unresolvable: {','.join(unresolved)}", "dangling-delegation"
        if not has_resolution and dns_status in ("SERVFAIL", "TIMEOUT", "ERROR"):
            # Delegated, but the delegated servers do not answer for the zone: a deleted
            # hosted zone at a DNS provider looks like this and may be re-creatable.
            return ("Possibly", f"Lame delegation: {','.join(delegation)} do not answer for {domain}",
                    "lame-delegation")
    if not has_resolution:
        if dns_status == "NXDOMAIN":
            return "No", "Name does not exist", "nxdomain"
        if dns_status == "NOANSWER":
            return "No", "Name exists without address records (mail/TXT-only or parked zone)", "no-web-records"
        return "No", f"DNS failure ({dns_status})", "dns-failure"
    return "No", "N/A", "ok"


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
                # fingerprint page, so a specific body signature is the signal. A
                # generic one ("404") is only an observation.
                strong = next((s for s in sigs if s not in WEAK_TAKEOVER_SIGNATURES and s in body_l), None)
                if strong:
                    return "Yes", f"{provider} + signature '{strong}'"
                weak = next((s for s in sigs if s in WEAK_TAKEOVER_SIGNATURES and s in body_l), None)
                if weak:
                    return "Possibly", f"CNAME to {provider}; generic '{weak}' observed (not proof)"
                return "Possibly", f"CNAME to {provider} (no body signature)"
    return "No", "N/A"


# Azure App Service "secure unique default hostname": app-<16 chars>.<region>-NN.azurewebsites.net.
# Such a name embeds a random hash, so nobody can create another app with it.
_UNIQUE_DEFAULT_HOST_RE = re.compile(r"-[a-z0-9]{16}\.[a-z0-9]+-\d{2}\.azurewebsites\.net$")
TAKEOVER_OUTCOMES = ("none", "provider-binding-review", "protected", "dangling-reserved",
                     "potentially-reclaimable", "claimable-by-policy", "claimable-by-signature",
                     "claimable-ns-domain", "verified")


def assess_takeover(host: str, chain: List[str], risk: str, detail: str,
                    ns_ev: Optional[Dict[str, Any]] = None) -> Dict[str, str]:
    """Final takeover verdict, derived only from the evidence fields. `risk`/`detail` are
    detect_takeover's observation; the returned risk/detail replace them, so a protected
    or unverified record never carries an unconditional "claimable". Claimability is
    never tested (that would mean claiming it): the best outcome without an analyst's
    override is claimable-by-policy / -signature / -ns-domain, all "claim not verified"."""
    out = {"risk": "No", "detail": "N/A", "outcome": "none", "evidence": "N/A",
           "target_missing": "N/A", "recreatable": "N/A", "binding": "N/A",
           "confidence": "N/A", "verified": "N/A"}
    if risk in ("Yes", "Possibly") and chain:
        provider = next((p for tgt in chain for p in TAKEOVER_PROVIDERS if p in tgt.lower()), "")
        target = chain[-1].lower()
        if "NXDOMAIN" in detail or ("signature '" not in detail and _target_claimable_nxdomain(target)):
            out["target_missing"], seen = "Yes", "target NXDOMAIN"
        elif "signature '" in detail and risk == "Yes":
            sig = detail.split("signature '", 1)[1].rstrip("'")
            out["target_missing"], seen = "provider-unclaimed", f"provider page '{sig}'"
        else:
            out["target_missing"] = "No"
            seen = "target resolves" + (f"; generic '{detail.split(chr(39))[1]}' page" if "generic '" in detail else "")
        policy = TAKEOVER_NAME_POLICY.get(max((k for k in TAKEOVER_NAME_POLICY if k in target),
                                              key=len, default=""), "unknown")
        if _UNIQUE_DEFAULT_HOST_RE.search(target):
            out["recreatable"] = "reserved (unique default hostname)"
        elif policy == "released":
            out["recreatable"] = "released (provider policy)"
        else:
            out["recreatable"] = policy
        tmpl = TAKEOVER_BINDING_TXT.get(provider)
        if tmpl:
            out["binding"] = "Yes" if _resolve(tmpl.format(host=host), "TXT") else "No"
        else:
            out["binding"] = "none-known"
        if out["target_missing"] == "No":
            out["outcome"] = "provider-binding-review"
        elif out["binding"] == "Yes":
            out["outcome"] = "protected"
        elif out["recreatable"].startswith("reserved"):
            out["outcome"] = "dangling-reserved"
        elif out["target_missing"] == "provider-unclaimed":
            out["outcome"], out["risk"], out["confidence"] = "claimable-by-signature", "Yes", "High"
        elif out["recreatable"].startswith("released"):
            out["outcome"], out["risk"], out["confidence"] = "claimable-by-policy", "Yes", "High"
        else:
            out["outcome"], out["risk"], out["confidence"] = "potentially-reclaimable", "Possibly", "Medium"
        bind = {"Yes": "verification record present", "No": "no verification record",
                "none-known": "no verification scheme known"}[out["binding"]]
        out["detail"] = f"{out['outcome']}: {provider} {seen}; name {out['recreatable']}; {bind}"
        out["evidence"] = (f"provider={provider};target={target};target_missing={out['target_missing']};"
                           f"recreatable={out['recreatable']};binding={out['binding']}")
    elif ns_ev and ns_ev.get("registration"):
        addr, regs = ns_ev["addresses"], ns_ev["registration"]
        free = sorted(r for r, res in regs.items() if res.startswith("not-registered"))
        if free:
            hit = [n for n, a in addr.items() if a == "NXDOMAIN" and registrable_domain(n) in free]
            alive = [n for n, a in addr.items() if a not in ("NXDOMAIN",)]
            out.update(outcome="claimable-ns-domain", risk="Yes", target_missing="Yes",
                       recreatable="registrable (registry: not registered)", binding="N/A",
                       confidence="Medium" if alive else "High")
            out["detail"] = (f"claimable-ns-domain: delegated to {','.join(hit)}; "
                             f"{','.join(free)} not registered; {len(hit)} of {len(addr)} nameservers")
            out["evidence"] = ";".join(f"{r}={regs[r]}" for r in sorted(regs))
    if out["outcome"] != "none":
        out["verified"] = "No (manual)"
        if out["risk"] != "No":
            out["detail"] += "; claim not verified"
    return out


# =====================================================================
# TLS
# =====================================================================

TLS_PORT = 443
# Order in which defects pick the single legacy `tls_valid` label.
CERT_DEFECT_ORDER = ("expired", "untrusted-chain", "self-signed", "invalid",
                     "hostname-mismatch", "not-yet-valid")
_X509_V_FLAG_NO_CHECK_TIME = 0x200000   # OpenSSL: verify the chain, ignore validity dates


def get_tls(host: str, ip: Optional[str] = None) -> Dict[str, str]:
    """TLS probe. Each property is judged on its own (handshake, hostname, trust, dates,
    protocol) so one defect never hides another; `health` is derived from all of them."""
    out = {"health": "N/A", "valid": "N/A", "min": "N/A", "max": "N/A", "cipher": "N/A",
           "cert_subject": "N/A", "cert_issuer": "N/A", "cert_not_before": "N/A",
           "cert_expiry": "N/A", "cert_days_left": "N/A", "cert_sha256": "N/A",
           "cert_sans": "N/A", "cert_pem": "", "cert_key": "N/A", "cert_sig_alg": "N/A",
           "cert_sct_count": "N/A", "cert_revocation": "N/A",
           "handshake": "N/A", "hostname": "N/A", "trust": "N/A", "dates": "N/A",
           "protocol": "N/A", "defects": "None"}
    # Connect to the address the audit resolved (with SNI = host), never via the system
    # resolver, so TLS results describe the same server as the DNS columns.
    addr = ip or host
    try:
        sock = socket.create_connection((addr, TLS_PORT), timeout=2.5)
    except OSError:
        out["handshake"] = "no-listener"
        return out
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with sock, ctx.wrap_socket(sock, server_hostname=host) as ss:
            out["handshake"] = "ok"
            cipher = ss.cipher()
            if cipher:
                out["cipher"] = cipher[0]
            der = ss.getpeercert(binary_form=True)
            if der:
                _fill_cert(der, out)
    except Exception:
        out["handshake"], out["health"] = "failed", "Failed"
        return out

    out["trust"] = _verify_trust(host, addr)
    out["dates"] = _cert_dates_state(out.get("_not_before"), out.get("_not_after"))
    if out.get("_names") is not None:
        out["hostname"] = "pass" if _hostname_matches(host, out["_names"]) else "fail"

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
            with socket.create_connection((addr, TLS_PORT), timeout=1.5) as sock:
                with ctx.wrap_socket(sock, server_hostname=host):
                    found.append(name)
        except Exception:
            continue
    if found:
        out["min"], out["max"] = found[0], found[-1]
        out["protocol"] = "pass" if found[0] in ("TLSv1.2", "TLSv1.3") else f"legacy({found[0]})"
    _summarise_tls(out)
    return out


def _summarise_tls(out: Dict[str, str]) -> None:
    """Derive cert_defects, the legacy single tls_valid label and overall health."""
    defects = []
    if out["dates"] in ("expired", "not-yet-valid"):
        defects.append(out["dates"])
    if out["trust"] in ("self-signed", "untrusted-chain", "invalid"):
        defects.append(out["trust"])
    if out["hostname"] == "fail":
        defects.append("hostname-mismatch")
    defects.sort(key=CERT_DEFECT_ORDER.index)
    out["defects"] = ";".join(defects) if defects else "None"
    if defects:
        out["valid"] = defects[0]
    elif out["trust"] == "pass" and out["hostname"] != "fail":
        out["valid"] = "valid"
    judged = [out[k] for k in ("hostname", "trust", "dates", "protocol") if out[k] != "N/A"]
    out["health"] = "Healthy" if judged and all(v == "pass" for v in judged) else "Degraded"


def _verify_trust(host: str, addr: Optional[str] = None) -> str:
    """Chain trust on its own: a validating handshake that ignores the hostname and the
    validity dates (those are judged separately), so an expired chain still reports its
    trust result instead of only "expired"."""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        try:
            ctx.verify_flags |= _X509_V_FLAG_NO_CHECK_TIME
        except (ValueError, OverflowError):
            pass
        with socket.create_connection((addr or host, TLS_PORT), timeout=2.5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host):
                return "pass"
    except ssl.SSLCertVerificationError as e:
        return _trust_reason(str(e))
    except Exception:
        return "N/A"


def _trust_reason(message: str) -> str:
    reason = (message or "").lower()
    if "self signed" in reason or "self-signed" in reason:
        return "self-signed"
    if "local issuer" in reason or "unable to get" in reason or "unknown ca" in reason:
        return "untrusted-chain"
    return "invalid"


def _cert_dates_state(not_before: Any, not_after: Any) -> str:
    if not_before is None or not_after is None:
        return "N/A"
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc)
    if now > not_after:
        return "expired"
    if now < not_before:
        return "not-yet-valid"
    return "pass"


def _hostname_matches(host: str, names: List[str]) -> bool:
    """RFC 6125 matching: exact name, or a left-most `*.` wildcard covering one label."""
    h = host.lower().rstrip(".")
    for n in names:
        n = n.lower().rstrip(".")
        if n == h:
            return True
        if n.startswith("*.") and "." in h and h.split(".", 1)[1] == n[2:]:
            return True
    return False


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
            out["_not_after"] = exp
            out["_not_before"] = before if before.tzinfo else before.replace(tzinfo=timezone.utc)
            out["cert_days_left"] = str((exp - datetime.now(timezone.utc)).days)
        except Exception:
            pass
        # Names for hostname matching: SANs, or the subject CN when there is no SAN.
        try:
            out["_names"] = list(cert.extensions.get_extension_for_class(
                x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName))
        except x509.ExtensionNotFound:
            cns = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
            out["_names"] = [str(cns[0].value)] if cns else []
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


_TECH_HEADER_RULES = [   # (header, regex on value, label; "\\1" = captured version)
    ("X-Powered-By", r"PHP/?([\d.]*)", "PHP"), ("X-Powered-By", r"ASP\.NET", "ASP.NET"),
    ("X-Powered-By", r"Express", "Express"), ("X-Powered-By", r"Next\.js", "Next.js"),
    ("X-Powered-By", r"Nuxt", "Nuxt"), ("X-Powered-By", r"Servlet|JSP", "Java"),
    ("X-Powered-By", r"WordPress", "WordPress"), ("X-AspNet-Version", r".", "ASP.NET"),
    ("X-AspNetMvc-Version", r".", "ASP.NET MVC"), ("X-Drupal-Cache", r".", "Drupal"),
    ("X-Generator", r"Drupal", "Drupal"), ("X-Pingback", r".", "WordPress"),
    ("X-Varnish", r".", "Varnish"), ("X-Magento-Tags", r".", "Magento"),
    ("Server", r"Apache(?:/([\d.]+))?", "Apache"), ("Server", r"nginx(?:/([\d.]+))?", "nginx"),
    ("Server", r"Microsoft-IIS(?:/([\d.]+))?", "IIS"), ("Server", r"Tomcat|Jetty|WebLogic|WebSphere", "Java"),
    ("Server", r"openresty", "OpenResty"), ("Server", r"LiteSpeed", "LiteSpeed"),
]
_TECH_COOKIES = {"phpsessid": "PHP", "jsessionid": "Java", "asp.net_sessionid": "ASP.NET",
                 "laravel_session": "Laravel", "connect.sid": "Node.js", "cfid": "ColdFusion",
                 "cftoken": "ColdFusion", "ci_session": "CodeIgniter", "wordpress_test_cookie": "WordPress"}
_TECH_BODY_RULES = [
    (r"/wp-(?:content|includes)/", "WordPress"), (r"/sites/default/files/|Drupal\.settings", "Drupal"),
    (r"/media/jui/|Joomla!", "Joomla"), (r"typo3(?:temp|conf)/|TYPO3", "TYPO3"),
    (r"__NEXT_DATA__|/_next/static/", "Next.js"), (r"/_nuxt/|__NUXT__", "Nuxt"),
    (r"ng-version=|<app-root", "Angular"), (r"data-reactroot|__REACT_DEVTOOLS", "React"),
    (r"/static/frontend/.*Magento|Mage\.Cookies", "Magento"), (r"cdn\.shopify\.com", "Shopify"),
    (r"<meta[^>]{0,200}content=[\"']Wix\.com", "Wix"), (r"jquery[.-]?([\d.]{3,8})?(?:\.min)?\.js", "jQuery"),
]


def detect_technology(headers: Any, body: str, cms: str = "", cdn: str = "") -> str:
    """Consolidate the visible technology stack from response headers, cookies, markup and
    the CMS/CDN fields into one "; "-separated string (versions kept when disclosed).
    Strong evidence (header/cookie/markup) yields the bare name; a lone '.php' link yields
    'PHP (inferred)'. Pure function: no I/O, bounded regexes."""
    found: Dict[str, str] = {}

    def add(name: str, ver: str = "") -> None:
        if name and (name not in found or (ver and not found[name])):
            found[name] = ver

    hdr = {str(k).lower(): str(v) for k, v in (headers.items() if headers else [])}
    for h, rx, label in _TECH_HEADER_RULES:
        m = re.search(rx, hdr.get(h.lower(), ""), re.I)
        if m:
            add(label, (m.group(1) or "") if m.groups() else "")
    for ck in re.findall(r"(?im)(?:^|[\s,])([A-Za-z0-9_.-]{2,40})=", hdr.get("set-cookie", "")):
        add(_TECH_COOKIES.get(ck.lower(), ""))
    head = (body or "")[:400_000]
    for m in re.finditer(r"<meta[^>]{0,200}name=[\"']generator[\"'][^>]{0,200}content=[\"']([^\"'<]{1,80})", head, re.I):
        g = m.group(1).strip()
        mv = re.match(r"([A-Za-z][A-Za-z0-9 .!_-]{0,40}?)\s+v?([\d][\d.]*)", g)
        add(mv.group(1).strip() if mv else g, mv.group(2) if mv else "")
    for rx, label in _TECH_BODY_RULES:
        m = re.search(rx, head, re.I)
        if m:
            add(label, m.group(1) if label == "jQuery" and m.groups() and m.group(1) else "")
    if cms and cms not in ("N/A", "None", ""):
        add(cms)
    if "PHP" not in found and re.search(r"""(?:href|src|action)=["'][^"'>\s]{0,200}\.php(?:[?"'#])""", head, re.I):
        found["PHP (inferred)"] = ""
    if cdn and cdn not in ("N/A", "None", "No", ""):
        add(cdn)
    return "; ".join(f"{n}/{v}" if v else n for n, v in found.items())


def _load_platforms() -> dict:
    """Platform currency rules (clipeus.platforms.json). Policy, not code: override with
    $CLIPEUS_PLATFORMS or ~/.config/clipeus/platforms.json."""
    cand = []
    if os.environ.get("CLIPEUS_PLATFORMS"):
        cand.append(os.environ["CLIPEUS_PLATFORMS"])
    _here = os.path.dirname(os.path.realpath(__file__))
    cand += [os.path.join(_here, "clipeus.platforms.json"),
             os.path.expanduser("~/.config/clipeus/platforms.json"),
             os.path.join(sys.prefix, "share", "clipeus", "clipeus.platforms.json")]
    for _p in cand:
        try:
            if _p and os.path.isfile(_p):
                with open(_p, encoding="utf-8") as _fh:
                    _d = json.load(_fh)
                if isinstance(_d, dict):
                    _d["_source"] = _p
                    return _d
        except Exception as _e:
            sys.stderr.write(f"[warn] platforms file {_p} ignored: {_e}\n")
    return {}


PLATFORMS = _load_platforms()


def _vtuple(v: str) -> tuple:
    return tuple(int(x) for x in re.findall(r"\d+", v)[:3]) or (0,)


def assess_platforms(technology: str, server: str = "", powered_by: str = "",
                     today: Optional[str] = None, rules: Optional[dict] = None, extra: str = "") -> str:
    """Flag out-of-date and non-enterprise platforms from the technology string and the
    raw Server / X-Powered-By values, per the rules file. Returns "; "-separated notes
    such as 'PHP/8.1.4: end-of-life 2025-12-31'. `extra` (e.g. the certificate issuer) is only
    searched by the non-enterprise rules. Pure function (today = YYYY-MM-DD)."""
    rules = PLATFORMS if rules is None else rules
    if not rules:
        return ""
    today = today or time.strftime("%Y-%m-%d")
    notes: List[str] = []
    seen = set()

    def add(msg: str) -> None:
        if msg not in seen:
            seen.add(msg)
            notes.append(msg)

    versions: Dict[str, str] = {}
    for tok in re.split(r"[;,]", technology or ""):
        m = re.match(r"\s*([A-Za-z][A-Za-z .+_-]*?)\s*/\s*(\d[\w.]*)", tok)
        if m:
            versions.setdefault(m.group(1).strip().lower(), m.group(2))
    for raw in (server or "", powered_by or ""):
        for m in re.finditer(r"([A-Za-z][A-Za-z.+_-]*)/(\d[\w.]*)", raw):
            versions.setdefault(m.group(1).lower(), m.group(2))
    versions.setdefault("iis", versions.get("microsoft-iis", ""))
    if not versions["iis"]:
        del versions["iis"]

    for prod, spec in (rules.get("eol_cycles") or {}).items():
        ver = versions.get(prod.lower())
        if not ver:
            continue
        cyc = sorted(spec.get("cycles", []), key=lambda c: _vtuple(c["cycle"]))
        if not cyc:
            continue
        v2 = _vtuple(ver)[:2]
        if len(v2) < 2:          # "Apache/2" carries no minor version: nothing to judge
            continue
        hit = next((c for c in cyc if _vtuple(c["cycle"])[:2] == v2), None)
        if hit is None and spec.get("older_than_first_is_eol") and v2 < _vtuple(cyc[0]["cycle"])[:2]:
            add(f"{prod}/{ver}: end-of-life (older than {cyc[0]['cycle']})")
        elif hit is not None:
            eol = hit.get("eol", "")
            if eol and eol <= today:
                add(f"{prod}/{ver}: end-of-life {eol}")
            elif eol and eol < time.strftime("%Y-%m-%d", time.gmtime(time.mktime(
                    time.strptime(today, "%Y-%m-%d")) + 183 * 86400)):
                add(f"{prod}/{ver}: support ends {eol}")
    for rule in rules.get("min_version") or []:
        ver = versions.get(str(rule.get("product", "")).lower())
        if ver and _vtuple(ver) < _vtuple(rule.get("min", "0")):
            add(f"{rule['product']}/{ver}: below {rule['min']} ({rule.get('reason', 'outdated')})")
    for rule in rules.get("unmaintained") or []:
        ver = versions.get(str(rule.get("product", "")).lower())
        if not ver:
            continue
        pre = str(rule.get("version_prefix", ""))
        if (ver == pre) if rule.get("exact") else ver.startswith(pre):
            add(f"{rule['product']}/{ver}: {rule.get('reason', 'unmaintained')}")
    hay = " ".join((technology or "", server or "", powered_by or "", extra or ""))
    for rule in rules.get("non_enterprise") or []:
        if rule.get("match") and rule["match"].lower() in hay.lower():
            add(f"{rule['match']}: non-enterprise ({rule.get('reason', '')})")
    return "; ".join(notes)


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
                c["url"] = f"{resp.url}({resp.status_code})"
                seen[c["name"]] = c          # last Set-Cookie for a name wins
    if not seen:
        return
    rec.cookie_context = "; ".join(
        f"{name}{'*' if SESSION_COOKIE_RE.search(name) else ''}@{c['url']}"
        for name, c in sorted(seen.items())[:8])
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
    rec.assessed_status = str(winner.status_code)
    # Browser-enforced headers only mean something on an HTML page; X-Frame-Options is
    # redundant when CSP frame-ancestors is set; X-XSS-Protection is obsolete in browsers.
    if "html" not in rec.content_type.lower():
        rec.sec_headers_missing = f"N/A (not HTML: {rec.content_type})"
    else:
        missing = [h for h in SECURITY_HEADERS if h not in winner.headers
                   and h != "X-XSS-Protection" and not (h == "X-Frame-Options" and has_fa)]
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

    rec.technology = detect_technology(winner.headers, body, rec.cms, rec.cdn)

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


PORT_NAMES = {21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http", 110: "pop3",
              143: "imap", 443: "https", 587: "smtp", 993: "imaps", 995: "pop3s", 8000: "http",
              8080: "http", 8443: "https"}
PORT_NAMES.update({p: lbl for p, (_sev, lbl) in PORT_RISK.items()})

# Banner -> service. Checked in order; the first match wins.
_BANNER_RULES = [
    (re.compile(r"^SSH-", re.I), "ssh"),
    (re.compile(r"MiniServ", re.I), "webmin"),
    (re.compile(r"^HTTP/\d", re.I), "http"),
    (re.compile(r"^220[ -].*\bftp", re.I), "ftp"),
    (re.compile(r"^220[ -].*\b(e?smtp|mail|postfix|exim|sendmail)\b", re.I), "smtp"),
    (re.compile(r"^\+OK", re.I), "pop3"),
    (re.compile(r"^\* OK", re.I), "imap"),
    (re.compile(r"mysql|mariadb|caching_sha2_password", re.I), "mysql"),
    (re.compile(r"^-(ERR|NOAUTH|DENIED)", re.I), "redis"),
    (re.compile(r"^RFB \d", re.I), "vnc"),
]
# Banner services that satisfy a PORT_RISK label.
_BANNER_SATISFIES = {"pop3": "pop3-cleartext", "imap": "imap-cleartext"}
# PORT_RISK labels that are HTTP APIs: an HTTP banner is consistent but does not confirm them.
_HTTP_API_LABELS = {"docker-api", "elasticsearch", "winrm"}


def identify_service(port: int, banner: str) -> Tuple[str, str]:
    """(service, source). source "banner" = the service said what it is; "port-guess" =
    only the port number suggests it."""
    b = (banner or "").strip()
    if b:
        if b.startswith("\xff") and port == 23:
            return "telnet", "banner"
        if b.startswith("220") and port == 21:
            return "ftp", "banner"
        for rx, svc in _BANNER_RULES:
            if rx.search(b):
                return svc, "banner"
    return PORT_NAMES.get(port, "unknown"), "port-guess"


def describe_port_services(ports: List[int], banners: Dict[int, str], tls_ports: Any = ()) -> str:
    """tls_ports: ports where a TLS handshake already succeeded (that identifies HTTPS)."""
    out = []
    for p in ports:
        svc, src = identify_service(p, banners.get(p, ""))
        if p in tls_ports and svc in ("http", "https"):
            svc, src = "https", "tls-handshake"
        out.append(f"{p}:{svc}?({src})" if src == "port-guess" else f"{p}:{svc}({src})")
    return ";".join(out) if out else "None"


def _parse_port_services(value: str) -> Dict[int, Tuple[str, str]]:
    out = {}
    for m in re.finditer(r"(\d+):([\w.-]+?)\??\(([\w-]+)\)", value or ""):
        out[int(m.group(1))] = (m.group(2), m.group(3))
    return out


def _grab_banner(sock: socket.socket, port: int) -> str:
    try:
        sock.settimeout(1.5)
        if port in WEB_PORTS and port not in BANNER_TALK_FIRST:
            try:
                sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
            except OSError:
                return ""
        # Banners often arrive in more than one packet (status line, then headers):
        # keep reading briefly so identifying lines like "Server:" are not lost.
        data = b""
        deadline = time.monotonic() + 1.5
        while len(data) < 1024 and time.monotonic() < deadline:
            try:
                chunk = sock.recv(1024 - len(data))
            except OSError:
                break
            if not chunk:
                break
            data += chunk
            sock.settimeout(max(0.05, min(0.3, deadline - time.monotonic())))
        return data.decode("latin-1", "ignore").strip().replace("\r", " ").replace("\n", " ")[:200]
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

def name_exists(rec: AuditRecord) -> bool:
    """The name is in the DNS (any record type), so name-level controls apply to it."""
    return rec.dns_status in ("OK", "NOANSWER") or rec.cname != "N/A"


def mail_controls_apply(rec: AuditRecord) -> bool:
    """SPF/DMARC/CAA judge names that exist. A registered domain needs them even when it
    sends no mail (that is how spoofing is blocked); a subdomain only when it has MX —
    otherwise the organizational domain's DMARC covers it."""
    if not name_exists(rec):
        return False
    return rec.is_subdomain != "Yes" or rec.mx_records not in ("None", "", "N/A")


def score_parts(rec: AuditRecord) -> Dict[str, Any]:
    """Risk split into exposure (reachable or claimable) and hygiene (missing hardening).
    Only checks that ran and apply to this name score. Points from unconfirmed
    observations are marked and lower the confidence."""
    parts = {"exposure": 0, "hygiene": 0}
    notes: List[str] = []
    unconfirmed = [0]

    def add(kind: str, pts: int, why: str, confirmed: bool = True):
        parts[kind] += pts
        if not confirmed:
            unconfirmed[0] += pts
        notes.append(f"{why} (+{pts}{'' if confirmed else ', unconfirmed'})")

    responds = rec.http_status not in ("0", "") or rec.https_status not in ("0", "")

    # --- exposure
    if rec.axfr_vuln == "Vulnerable":
        add("exposure", 40, "AXFR")
    # Takeover and dangling score once, from the derived verdict: a claimable name is
    # exposure; a stale record nobody else can claim is hygiene.
    if rec.takeover_risk == "Yes":
        verified = rec.takeover_outcome == "verified"
        add("exposure", 45, f"Takeover ({rec.takeover_outcome}"
            f"{'' if verified else ', claim not verified'})", confirmed=verified)
    elif rec.takeover_risk == "Possibly":
        add("exposure", 25, f"Possible takeover ({rec.takeover_outcome})", confirmed=False)
    elif rec.dangling_class == "unresponsive-cloud-ip":
        add("exposure", 10, "Possibly dangling (unresponsive-cloud-ip)", confirmed=False)
    elif rec.dangling_status in ("Yes", "Possibly"):
        add("hygiene", 10 if rec.dangling_status == "Yes" else 5,
            f"Stale DNS record ({rec.dangling_class})", confirmed=rec.dangling_status == "Yes")
    if rec.is_private_ip == "Yes":
        add("exposure", 30, "Private IP exposed")
    if rec.has_login_form == "Yes" and rec.managed_by in ("not-verified", "N/A") and rec.org_range == "No":
        add("exposure", 30, "Login page outside org networks and managed providers")
    if re.search(r"/(admin|wp-login)[^,]*\(login\)", rec.auth_pages):
        add("exposure", 10, "Admin login path exposed")
    if "include_unregistered(" in rec.spf_chain_issues:
        add("exposure", 25, "SPF include of unregistered domain")
    if rec.cors.endswith("+credentials"):
        add("exposure", 25, f"CORS {rec.cors}")
    elif rec.cors in ("reflects-origin", "null-origin"):
        add("exposure", 10, f"CORS {rec.cors}")
    pts = sum(SCANNER_POINTS.get(i.partition(":")[0], 0) for i in rec.scanner_findings.split(","))
    if pts:
        add("exposure", min(SCANNER_POINTS_CAP, pts), f"Scanner findings ({rec.scanner_max_severity} max)")
    exposed = exposed_services(rec.ports, rec.port_services)
    if exposed:
        full = sum(PORT_RISK_POINTS[sev] for _, sev, _, ok in exposed if ok)
        half = sum(PORT_RISK_POINTS[sev] // 2 for _, sev, _, ok in exposed if not ok)
        total = min(PORT_RISK_CAP, full + half)
        label = ",".join(f"{lbl}/{prt}" + ("" if ok else "?") for lbl, _, prt, ok in exposed)
        add("exposure", total, f"Exposed services: {label}", confirmed=bool(full))
    if rec.tls_ocsp_stapling.startswith("stapled(revoked"):
        add("exposure", 30, "Certificate revoked (OCSP)")
    if rec.origin_exposed == "Yes":
        add("exposure", 25, "Origin IP exposed behind CDN")
    elif rec.origin_exposed == "Possibly":
        add("exposure", 10, "Possible origin IP exposure", confirmed=False)

    # --- hygiene (only where the control applies and its check ran)
    if mail_controls_apply(rec):
        if any(k in rec.spf_issues for k in ("spf_missing", "spf_malformed_version", "spf_all_too_permissive")):
            add("hygiene", 20, "SPF missing/invalid/permissive")
        if "dmarc_missing" in rec.dmarc_issues or "dmarc_policy_none" in rec.dmarc_issues:
            add("hygiene", 15, "DMARC weak/missing")
        if rec.caa_records == "None":
            add("hygiene", 5, "Missing CAA")
    if rec.tls_min in ("TLSv1.0", "TLSv1.1"):
        add("hygiene", 20, f"Legacy TLS ({rec.tls_min})")
    if responds and rec.tls_handshake != "N/A" and rec.tls_health != "Healthy":
        why = rec.cert_defects if rec.cert_defects != "None" else f"handshake {rec.tls_handshake}"
        add("hygiene", 15, f"TLS unhealthy ({why})")
    if rec.hsts == "No" and responds:
        add("hygiene", 5, "Missing HSTS")
    if rec.mta_sts == "absent":
        add("hygiene", 3, "No MTA-STS")
    elif rec.mta_sts in ("policy-unreachable", "policy-invalid"):
        add("hygiene", 5, "MTA-STS policy broken")
    if rec.spf_lookups.isdigit() and int(rec.spf_lookups) > 10:
        add("hygiene", 10, f"SPF exceeds 10 lookups ({rec.spf_lookups})")
    if "include_no_spf(" in rec.spf_chain_issues and "include_unregistered(" not in rec.spf_chain_issues:
        add("hygiene", 10, "SPF include has no record")
    if "broad_range(" in rec.spf_chain_issues:
        add("hygiene", 5, "SPF authorises an oversized range")
    if rec.csp_issues not in ("None", "report-only"):
        add("hygiene", 3, f"Weak CSP ({rec.csp_issues})")
    if rec.dkim_weak != "None":
        add("hygiene", 3, f"Weak DKIM key ({rec.dkim_weak})")
    if rec.session_cookie_no_httponly != "None":
        add("hygiene", 5, "Session cookie without HttpOnly")
    if rec.cookie_no_secure != "None":
        add("hygiene", 3, "Cookie without Secure on HTTPS")
    if _weak_cert_key(rec.cert_key):
        add("hygiene", 10, f"Weak cert key ({rec.cert_key})")
    if rec.cert_sig_alg in ("md5", "sha1"):
        add("hygiene", 10, f"Weak cert signature ({rec.cert_sig_alg})")

    total = parts["exposure"] + parts["hygiene"]
    if not total:
        conf = "N/A"
    elif unconfirmed[0] == 0:
        conf = "High"
    elif unconfirmed[0] * 2 < total:
        conf = "Medium"
    else:
        conf = "Low"
    return {"exposure": parts["exposure"], "hygiene": parts["hygiene"], "confidence": conf,
            "score": min(100, total), "notes": notes}


def score_risk(rec: AuditRecord) -> Tuple[int, List[str]]:
    """(risk_score, notes). Also fills risk_exposure / risk_hygiene / risk_confidence."""
    p = score_parts(rec)
    rec.risk_exposure, rec.risk_hygiene, rec.risk_confidence = p["exposure"], p["hygiene"], p["confidence"]
    return p["score"], p["notes"]


def exposed_services(ports: str, port_services: str = "") -> List[Tuple[str, str, int, bool]]:
    """[(label, severity, port, confirmed)] for risky ports in a comma-separated `ports`
    string. confirmed = a banner identified the service. A banner naming a different
    service (e.g. a plain web server on 10000) removes the port from the risky list."""
    ident = _parse_port_services(port_services)
    out = []
    for tok in (ports or "").split(","):
        tok = tok.strip()
        if not (tok.isdigit() and int(tok) in PORT_RISK):
            continue
        port = int(tok)
        sev, label = PORT_RISK[port]
        svc, src = ident.get(port, ("", "port-guess"))
        confirmed = False
        if src in ("banner", "tls-handshake"):
            if svc == label or _BANNER_SATISFIES.get(svc) == label:
                confirmed = True
            elif not (svc == "http" and label in _HTTP_API_LABELS):
                continue                     # the banner says it is something else
        out.append((label, sev, port, confirmed))
    return sorted(out, key=lambda t: (-PORT_RISK_POINTS[t[1]], t[2]))


def _weak_cert_key(cert_key: str) -> bool:
    m = re.fullmatch(r"(RSA|DSA)-(\d+)", cert_key or "")
    return bool(m) and int(m.group(2)) < 2048


# =====================================================================
# HOSTING, ROOTS, REACHABILITY, CHECK STATES, PROVENANCE
# =====================================================================

# Provider markers matched (case-insensitive substring) against the ASN name (--geo),
# reverse DNS and CNAME chain. A match makes the host "cloud"-hosted by that provider.
CLOUD_PROVIDER_MARKERS = {
    "aws": ("amazon", "amazonaws.com"),
    "azure": ("microsoft", "azure", "windows.net", "cloudapp.net", "msedge.net"),
    "gcp": ("google", "googleusercontent.com", "1e100.net"),
    "oracle": ("oracle", "oraclecloud"),
    "ibm": ("softlayer", "ibm cloud"),
    "alibaba": ("alibaba", "aliyun"),
    "digitalocean": ("digitalocean",),
    "linode": ("linode",),
    "hetzner": ("hetzner",),
    "ovh": ("ovh",),
}
CLOUD_PROVIDER_MARKERS.update({k: tuple(v) for k, v in _tune("cloud_provider_markers", {}).items()})
# Name fragments that mark a private endpoint (resolves publicly, served privately).
PRIVATE_ENDPOINT_MARKERS = tuple(_tune("private_endpoint_markers", [".privatelink."]))


def classify_hosting(rec: AuditRecord, org_networks_hit: bool,
                     managed_providers: List[str]) -> Tuple[str, str, str]:
    """(network_owner, hosting_class, managed_by). Network location is NOT management:
    a host outside the org's address space may still be run by the org on a provider it
    uses (brand config `managed_providers`). Nothing here claims a host is unmanaged."""
    if rec.ip == "N/A":
        return "N/A", "N/A", "N/A"
    evidence = " ".join(x for x in (rec.asn, rec.ptr, rec.cname) if x not in ("N/A", "Unknown")).lower()
    provider = next((name for name, marks in CLOUD_PROVIDER_MARKERS.items()
                     if any(m in evidence for m in marks)), "")
    if rec.asn not in ("N/A", "Unknown", ""):
        owner = rec.asn
    elif provider:
        owner = provider
    elif rec.ptr not in ("N/A", ""):
        owner = registrable_domain(rec.ptr) or "unknown"
    else:
        owner = "unknown"
    if rec.is_private_ip == "Yes":
        hclass = "private"
    elif org_networks_hit:
        hclass = "org"
    elif rec.cdn not in ("No", "", "N/A"):
        hclass = "cdn"
        provider = provider or rec.cdn.split()[0].lower()
    elif provider:
        hclass = "cloud"
    elif rec.ptr not in ("N/A", ""):
        hclass = "third-party"
    else:
        hclass = "unknown"
    managed = {m.lower() for m in managed_providers}
    if org_networks_hit:
        managed_by = "org-network"
    elif provider and provider in managed:
        managed_by = f"org-provider({provider})"
    elif owner.lower() in managed:
        managed_by = f"org-provider({owner.lower()})"
    else:
        managed_by = "not-verified"
    return owner, hclass, managed_by


def host_root(host: str, roots: Any = ()) -> str:
    """The portfolio root a host sits under: the longest matching configured root
    (--roots / config `roots`), else its registrable domain (Public Suffix List). A bare
    TLD (a brand TLD entered on its own) is its own root."""
    h = (host or "").lower().rstrip(".")
    best = ""
    for r in roots or ():
        if (h == r or h.endswith("." + r)) and len(r) > len(best):
            best = r
    return best or registrable_domain(h) or h


def private_endpoint(rec: AuditRecord) -> str:
    if rec.is_private_ip == "Yes":
        return "Yes(private-ip)"
    names = f"{rec.domain} {rec.cname}".lower()
    hit = next((m for m in PRIVATE_ENDPOINT_MARKERS if m.lower() in names), None)
    return f"Yes(name:{hit.strip('.')})" if hit else "No"


def describe_reachability(rec: AuditRecord, port_scanned: bool) -> str:
    """How far a client gets: DNS -> TCP -> TLS -> HTTP, each observed separately."""
    dns_state = {"OK": "ok"}.get(rec.dns_status, rec.dns_status.lower() if rec.dns_status != "N/A" else "n/a")
    responds = rec.http_status not in ("0", "") or rec.https_status not in ("0", "")
    if rec.ip == "N/A":
        tcp = "n/a"
    elif responds or rec.tls_handshake in ("ok", "failed") or rec.ports:
        tcp = "ok"
    elif port_scanned:
        tcp = "closed"
    else:
        tcp = "unknown"
    tls = {"ok": "ok", "failed": "failed", "no-listener": "none"}.get(rec.tls_handshake, "n/a")
    http = rec.https_status if rec.https_status not in ("0", "") else rec.http_status
    http = http if http not in ("0", "") else "none"
    return f"dns:{dns_state};tcp:{tcp};tls:{tls};http:{http}"


def endpoint_ids(rec: AuditRecord) -> str:
    if rec.ip == "N/A":
        return "None"
    ports = [p for p in (rec.ports or "").split(",") if p.strip()]
    if not ports:
        if rec.tls_handshake in ("ok", "failed"):
            ports.append("443")
        if rec.http_status not in ("0", ""):
            ports.append("80")
    return ",".join(f"{rec.ip}:{p}" for p in sorted(set(ports), key=int)) or "None"


def site_id(rec: AuditRecord) -> str:
    if rec.body_sha256 in ("N/A", "") or rec.final_url in ("N/A", ""):
        return "N/A"
    host = urlparse(rec.final_url).netloc.lower()
    return hashlib.sha256(f"{host}|{rec.body_sha256}".encode()).hexdigest()[:16]


CHECK_STATES = ("passed", "failed", "not_applicable", "not_run", "timeout", "error")


def describe_checks(rec: AuditRecord, args: argparse.Namespace, port_list: List[int]) -> str:
    """One state per check, so "nothing found" and "never looked" are distinguishable."""
    st: Dict[str, str] = {}
    responds = rec.http_status not in ("0", "") or rec.https_status not in ("0", "")
    st["dns"] = {"OK": "passed", "NXDOMAIN": "passed", "NOANSWER": "passed",
                 "TIMEOUT": "timeout"}.get(rec.dns_status, "error")
    if args.no_rdap:
        st["rdap"] = "not_run"
    else:
        st["rdap"] = ("passed" if rec.rdap_result in ("ok", "whois") or rec.rdap_result.startswith("not-registered")
                      else "timeout" if rec.rdap_result == "timeout" else "error")
    if args.no_tls:
        st["tls"] = "not_run"
    elif rec.tls_handshake in ("N/A", "no-listener"):
        st["tls"] = "not_applicable"
    else:
        st["tls"] = "passed" if rec.tls_health == "Healthy" else "failed"
    has_addr = rec.ip != "N/A" or rec.ipv6 != "N/A"
    st["http"] = "not_applicable" if not has_addr else ("passed" if responds else "failed")
    if mail_controls_apply(rec):
        st["spf"] = "failed" if any(k in rec.spf_issues for k in
                                    ("spf_missing", "spf_malformed_version", "spf_all_too_permissive")) else "passed"
        st["dmarc"] = "failed" if ("dmarc_missing" in rec.dmarc_issues
                                   or "dmarc_policy_none" in rec.dmarc_issues) else "passed"
        st["caa"] = "failed" if rec.caa_records == "None" else "passed"
    else:
        st["spf"] = st["dmarc"] = st["caa"] = "not_applicable"
    has_mx = bool(mx_hosts(rec.mx_records))
    if args.no_email_hardening:
        st["mta_sts"] = "not_run"
    elif not has_mx:
        st["mta_sts"] = "not_applicable"
    else:
        st["mta_sts"] = "passed" if rec.mta_sts == "enforce" else "failed"
    st["dkim"] = ("not_run" if not args.dkim else "not_applicable" if not has_mx
                  else "failed" if rec.dkim_weak != "None" else "passed")
    st["axfr"] = ("not_run" if args.no_axfr else "not_applicable" if rec.soa_record == "N/A"
                  else "failed" if rec.axfr_vuln == "Vulnerable" else "passed")
    if not port_list:
        st["ports"] = "not_run"
    elif rec.ip == "N/A" or (rec.cdn not in ("No", "") and not args.ports_behind_cdn):
        st["ports"] = "not_applicable"
    else:
        st["ports"] = "failed" if exposed_services(rec.ports, rec.port_services) else "passed"
    st["banners"] = "not_run" if (args.no_banners or not port_list) else (
        "passed" if rec.ports else "not_applicable")
    st["takeover"] = ("failed" if rec.takeover_risk in ("Yes", "Possibly")
                      else "not_applicable" if rec.cname == "N/A" and rec.ns_resolution == "N/A"
                      else "passed")
    st["dangling"] = ("failed" if rec.dangling_status in ("Yes", "Possibly")
                      else "timeout" if rec.dangling_class == "dns-failure" and rec.dns_status == "TIMEOUT"
                      else "passed")
    st["cors"] = "not_run" if not args.cors else ("not_applicable" if not responds else
                                                  "failed" if rec.cors not in ("none", "restricted", "N/A") else "passed")
    st["auth_paths"] = "not_run" if not args.auth_paths else ("not_applicable" if not responds else "passed")
    st["origin"] = "not_run" if not args.origin else ("not_applicable" if rec.cdn == "No" else
                                                      "failed" if rec.origin_exposed != "No" else "passed")
    st["harvest"] = "not_run" if not args.harvest else ("not_applicable" if not responds else "passed")
    st["scanner"] = "not_run" if INGEST is None else ("failed" if rec.scanner_findings not in ("None", "not_run")
                                                      else "passed")
    return ";".join(f"{k}={v}" for k, v in st.items())


def parse_checks(value: str) -> Dict[str, str]:
    return dict(p.split("=", 1) for p in (value or "").split(";") if "=" in p)


def _rules_version() -> str:
    material = json.dumps({"takeover": TAKEOVER_PROVIDERS, "nx": NXDOMAIN_ONLY_PROVIDERS,
                           "weak": sorted(WEAK_TAKEOVER_SIGNATURES), "names": TAKEOVER_NAME_POLICY,
                           "binding": TAKEOVER_BINDING_TXT, "ports": PORT_RISK,
                           "platforms": {k: v for k, v in PLATFORMS.items() if k != "_source"}},
                          sort_keys=True, default=str)
    return hashlib.sha256(material.encode()).hexdigest()[:12]


RULES_VERSION = ""          # set by refresh_rules_version() once the rule tables are final


def refresh_rules_version() -> str:
    global RULES_VERSION
    RULES_VERSION = _rules_version()
    return RULES_VERSION


def _utc_now() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# =====================================================================
# PER-DOMAIN PIPELINE
# =====================================================================

def process_domain(domain: str, session: requests.Session, args: argparse.Namespace,
                   org_networks: List[Any], port_list: List[int]) -> AuditRecord:
    rec = AuditRecord(domain=domain)
    rec.clipeus_version, rec.rules_version = __version__, RULES_VERSION
    rec.root_domain = host_root(domain, getattr(args, "roots", ()))
    rec.is_subdomain = "Yes" if domain != rec.root_domain else "No"
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
                      "ns": dns_bits["ns"], "zone": dns_bits["zone"], "zone_ns": dns_bits["zone_ns"],
                      "cname": dns_bits["chain"], "txt": dns_bits["txts"]}

        org_hit = False
        if rec.ip != "N/A":
            try:
                ip_obj = ipaddress.ip_address(rec.ip)
                rec.is_private_ip = "Yes" if ip_obj.is_private else "No"
                org_hit = any(ip_obj in n for n in org_networks)
                rec.org_range = "Yes" if org_hit else "No"
            except ValueError:
                pass
            rec.ptr = reverse_dns(rec.ip)

        if args.geo and not args.no_geo:
            rec.asn, rec.country, rec.city = get_geo_asn(rec.ip)

        if not args.no_rdap:
            reg_info = lookup_registration(registrable_domain(domain), use_whois=not args.no_whois)
            rec.rdap_registrar, rec.rdap_created = reg_info["registrar"], reg_info["created"]
            rec.rdap_expires, rec.domain_age_days = reg_info["expires"], reg_info["age_days"]
            rec.rdap_status, rec.rdap_result = reg_info["status"], reg_info["result"]
            raw["rdap"] = reg_info["raw"]
            if reg_info.get("whois_raw"):
                raw["whois"] = reg_info["whois_raw"]

        has_addr = rec.ip != "N/A" or rec.ipv6 != "N/A"
        if not args.no_tls and has_addr:
            tls = get_tls(domain, next((a for a in (rec.ip, rec.ipv6) if a != "N/A"), None))
            rec.tls_health, rec.tls_valid = tls["health"], tls["valid"]
            rec.tls_handshake, rec.tls_hostname, rec.tls_trust = tls["handshake"], tls["hostname"], tls["trust"]
            rec.tls_dates, rec.tls_protocol, rec.cert_defects = tls["dates"], tls["protocol"], tls["defects"]
            rec.tls_min, rec.tls_max, rec.tls_cipher = tls["min"], tls["max"], tls["cipher"]
            rec.cert_subject, rec.cert_issuer = tls["cert_subject"], tls["cert_issuer"]
            rec.cert_not_before, rec.cert_expiry = tls["cert_not_before"], tls["cert_expiry"]
            rec.cert_days_left, rec.cert_sha256 = tls["cert_days_left"], tls["cert_sha256"]
            rec.cert_sans = tls["cert_sans"]
            rec.cert_key, rec.cert_sig_alg = tls["cert_key"], tls["cert_sig_alg"]
            rec.cert_sct_count, rec.cert_revocation = tls["cert_sct_count"], tls["cert_revocation"]
            if tls["cert_pem"]:
                raw["cert_pem"] = tls["cert_pem"]
            if args.jarm and rec.tls_handshake == "ok":
                rec.jarm = jarm_fingerprint(domain)
            if args.ocsp and rec.tls_handshake == "ok":
                rec.tls_ocsp_stapling = check_ocsp_stapling(domain)

        if not args.no_axfr and rec.soa_record != "N/A":      # only a zone apex can be transferred
            rec.axfr_vuln = check_axfr(domain, rec.ns_servers)

        if rec.spf not in ("None", "", "N/A") and not args.no_spf_chain:
            chain = analyze_spf_chain(domain, rec.spf)
            rec.spf_lookups = str(chain["lookups"])
            if chain["issues"]:
                rec.spf_chain_issues = ",".join(chain["issues"])

        # HTTP goes through the system resolver; only fetch names the audit's own
        # resolvers can resolve, or the web columns would describe a different answer.
        body = get_web_data(domain, session, args, rec, raw) if dns_bits["has_resolution"] else ""

        rec.dangling_status, rec.dangling_detail, rec.dangling_class = detect_dangling(
            domain, dns_bits["chain"], dns_bits["ns"], dns_bits["has_resolution"],
            rec.dns_status, dns_bits["zone_ns"])
        ns_ev = delegation_evidence(domain, dns_bits["ns"], dns_bits["zone"], dns_bits["zone_ns"],
                                    dns_bits["has_resolution"], rec.dns_status,
                                    use_whois=not args.no_whois) if not args.no_rdap else {}
        if ns_ev:
            rec.ns_parent = ",".join(ns_ev["parent"]) or "None"
            rec.ns_own = ",".join(ns_ev["own"]) or "None"
            rec.ns_resolution = ";".join(f"{n}={a}" for n, a in ns_ev["addresses"].items())
            rec.ns_registration = ";".join(f"{r}={v}" for r, v in sorted(ns_ev["registration"].items())) or "N/A"
        obs_risk, obs_detail = detect_takeover(dns_bits["chain"], body)
        tk = assess_takeover(domain, dns_bits["chain"], obs_risk, obs_detail, ns_ev)
        (rec.takeover_risk, rec.takeover_detail, rec.takeover_outcome, rec.takeover_evidence,
         rec.takeover_target_missing, rec.takeover_recreatable, rec.takeover_binding_protected,
         rec.takeover_confidence, rec.takeover_claim_verified) = (
            tk["risk"], tk["detail"], tk["outcome"], tk["evidence"], tk["target_missing"],
            tk["recreatable"], tk["binding"], tk["confidence"], tk["verified"])

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
        port_scanned = bool(port_list) and rec.ip != "N/A" and (rec.cdn == "No" or args.ports_behind_cdn)
        if port_scanned:
            ports, banners = scan_ports(rec.ip, port_list, not args.no_banners)
            rec.ports = ",".join(map(str, ports))
            if banners and any(banners.values()):
                rec.port_banners = " | ".join(f"{p}:{b}" for p, b in sorted(banners.items()) if b)
            rec.port_services = describe_port_services(
                ports, banners, {TLS_PORT} if rec.tls_handshake == "ok" else ())
            raw["ports"] = {"open": ports, "banners": banners}

        discovered = collect_discovered(domain, rec, dns_bits["chain"])
        if discovered:
            rec.discovered_domains = ",".join(discovered)

        if INGEST:
            apply_ingest(rec, INGEST)

        rec.network_owner, rec.hosting_class, rec.managed_by = classify_hosting(
            rec, org_hit, getattr(args, "managed_providers", []))
        rec.private_endpoint = private_endpoint(rec)
        rec.reachability = describe_reachability(rec, port_scanned)
        rec.endpoint_ids, rec.site_id = endpoint_ids(rec), site_id(rec)
        # An address at a cloud provider that answers nothing may be a released IP.
        if (rec.dangling_class == "ok" and rec.hosting_class == "cloud" and not rec.ports
                and rec.http_status in ("0", "") and rec.https_status in ("0", "")
                and rec.tls_handshake in ("N/A", "no-listener")):
            rec.dangling_status, rec.dangling_class = "Possibly", "unresponsive-cloud-ip"
            rec.dangling_detail = f"{rec.ip} ({rec.network_owner}) answers on no probed port"
        if INGEST is None:
            rec.scanner_findings = "not_run"

        if rec.domain in OVERRIDES:
            apply_overrides(rec, OVERRIDES[rec.domain])
        rec.dirty_forwarding = "Yes" if (rec.is_forwarded == "Yes"
                                         and rec.tls_health != "Healthy") else "No"
        rec.platform_risk = assess_platforms(
            rec.technology, "" if rec.server == "N/A" else rec.server,
            "" if rec.powered_by == "N/A" else rec.powered_by, extra=rec.cert_issuer)
        classify_domain(rec, args.approved_mx, args.approved_redirect)
        rec.risk_score, notes = score_risk(rec)
        rec.score_notes = "; ".join(notes)
        rec.checks = describe_checks(rec, args, port_list)
    except Exception as exc:
        rec.error = f"{type(exc).__name__}: {exc}"
        rec.checks = "pipeline=error"
    rec.scanned_at = _utc_now()
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
    if mail_controls_apply(rec):
        if "spf_missing" in rec.spf_issues:
            issues.append("spf-missing")
        elif rec.spf_issues not in ("None", ""):
            issues.append(f"spf({rec.spf_issues})")
        if "dmarc_missing" in rec.dmarc_issues:
            issues.append("dmarc-missing")
        elif rec.dmarc_issues not in ("None", ""):
            issues.append(f"dmarc({rec.dmarc_issues})")
    if rec.cert_defects not in ("None", "", "N/A"):
        issues += [f"cert-{d}" for d in rec.cert_defects.split(";")]
    elif rec.tls_valid in ("expired", "hostname-mismatch", "self-signed", "untrusted-chain"):
        issues.append(f"cert-{rec.tls_valid}")      # records written before cert_defects existed
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
    for label, _sev, port, confirmed in exposed_services(rec.ports, rec.port_services):
        issues.append(f"exposed-{label}({port})" if confirmed else f"exposed-{label}-unconfirmed({port})")
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
    out: Dict[str, Any] = {"unit": "hostnames", "old_count": len(o), "new_count": len(n),
                           "added": [], "removed": [], "new_issues": [], "resolved_issues": [],
                           "transient": [], "persistent_issues": 0,
                           "changes": [], "risk_up": [], "risk_down": []}
    for d in sorted(n.keys() - o.keys()):
        out["added"].append({"domain": d, "risk": _risk(n[d]), "issues": sorted(_issue_set(n[d]))})
    for d in sorted(o.keys() - n.keys()):
        out["removed"].append({"domain": d, "risk": _risk(o[d])})
    for d in sorted(n.keys() & o.keys()):
        a, b = o[d], n[d]
        gained, lost = _issue_set(b) - _issue_set(a), _issue_set(a) - _issue_set(b)
        out["persistent_issues"] += len(_issue_set(a) & _issue_set(b))
        if gained:
            out["new_issues"].append({"domain": d, "issues": sorted(gained)})
        if lost:
            # An issue that vanished while this run could not look (DNS/TLS/HTTP timed out
            # or errored) is not resolved: report it as transient.
            states = parse_checks(str(b.get("checks") or ""))
            blind = sorted(k for k in ("dns", "tls", "http") if states.get(k) in ("timeout", "error"))
            if blind or b.get("error"):
                out["transient"].append({"domain": d, "issues": sorted(lost),
                                         "why": ",".join(blind) or "error"})
            else:
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
    n_tr = sum(len(x["issues"]) for x in diff.get("transient", []))
    lines = [f"# Scan diff: {old_label} -> {new_label}", "",
             f"Hostnames: {diff['old_count']} -> {diff['new_count']} "
             f"(+{len(diff['added'])} new, -{len(diff['removed'])} not in this run)",
             f"Issues (per hostname): {n_new} new, {n_res} resolved, {n_tr} not re-checked (transient), "
             f"{diff.get('persistent_issues', 0)} persistent | risk up >= {DIFF_RISK_DELTA}: "
             f"{len(diff['risk_up'])} | risk down: {len(diff['risk_down'])}", ""]
    lines += section("New domains", [f"{x['domain']}  risk={x['risk']}  " + ("; ".join(x["issues"]) or "no issues")
                                     for x in diff["added"]])
    lines += section("Not in this run (removed or run incomplete)",
                     [f"{x['domain']}  (was risk={x['risk']})" for x in diff["removed"]])
    lines += section("New issues", [f"{x['domain']}: " + "; ".join(x["issues"]) for x in diff["new_issues"]])
    lines += section("Resolved issues", [f"{x['domain']}: " + "; ".join(x["issues"]) for x in diff["resolved_issues"]])
    lines += section("Not re-checked this run (transient, not resolved)",
                     [f"{x['domain']} [{x['why']}]: " + "; ".join(x["issues"]) for x in diff.get("transient", [])])
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
<h1>{esc(title)}</h1><p class="sub">Source: {esc(source)} &middot; {total} hostnames (one row per hostname)</p>
<div class="cards">
<div class="card"><b>{total}</b><span>hostnames</span></div>
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
        if rec.scanner_findings == "not_run":
            rec.scanner_findings = "None"          # the scanner has now run for this record
        apply_ingest(rec, idx)
        classify_domain(rec, args.approved_mx, args.approved_redirect)
        rec.risk_score, notes = score_risk(rec)
        rec.score_notes = "; ".join(notes)
        matched += rec.scanner_findings not in ("None", "not_run")
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



# Fields an override may never set: identity and provenance of the record.
OVERRIDE_PROTECTED = {"domain", "checks", "scanned_at", "clipeus_version", "rules_version", "overrides"}
OVERRIDES: Dict[str, List[Dict[str, Any]]] = {}


def load_overrides(path: str) -> Dict[str, List[Dict[str, Any]]]:
    """Manual findings to merge into records: {"overrides": [{"host", "set": {field: value},
    "evidence", "observed_at", "analyst"}]}. Every entry must say what was observed and
    when; an override without evidence is refused rather than silently applied."""
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    items = data.get("overrides", []) if isinstance(data, dict) else data
    fields = {k for k, v in AuditRecord.__dataclass_fields__.items()}
    out: Dict[str, List[Dict[str, Any]]] = {}
    for i, it in enumerate(items if isinstance(items, list) else []):
        where = f"override #{i + 1}"
        if not isinstance(it, dict):
            raise ValueError(f"{where}: not an object")
        host = normalize_host(str(it.get("host", "")))
        if not host:
            raise ValueError(f"{where}: missing or invalid host")
        for key in ("evidence", "observed_at"):
            if not str(it.get(key, "")).strip():
                raise ValueError(f"{where} ({host}): '{key}' is required")
        sets = it.get("set")
        if not isinstance(sets, dict) or not sets:
            raise ValueError(f"{where} ({host}): 'set' must name at least one field")
        for k in sets:
            if k not in fields or k in OVERRIDE_PROTECTED:
                raise ValueError(f"{where} ({host}): field '{k}' cannot be overridden")
        out.setdefault(host, []).append(
            {"set": {k: str(v) for k, v in sets.items()}, "evidence": str(it["evidence"]).strip(),
             "observed_at": str(it["observed_at"]).strip(), "analyst": str(it.get("analyst", "")).strip()})
    return out


def apply_overrides(rec: AuditRecord, items: List[Dict[str, Any]]) -> None:
    notes = []
    for it in items:
        for k, v in it["set"].items():
            cur = getattr(rec, k)
            setattr(rec, k, int(v) if isinstance(cur, int) and v.lstrip("-").isdigit() else v)
        who = f", {it['analyst']}" if it["analyst"] else ""
        notes.append(f"{','.join(f'{k}={v}' for k, v in it['set'].items())} "
                     f"({it['observed_at']}{who}; {it['evidence']})")
    rec.overrides = " | ".join(notes)


class RunStats:
    """Counts with explicit units, so a total is never ambiguous: hostnames, distinct IPs,
    distinct certificates, distinct sites (same content behind many names)."""
    def __init__(self) -> None:
        self.hostnames = 0
        self.ips: set = set()
        self.certs: set = set()
        self.sites: set = set()
        self.errors = 0

    def add(self, rec: AuditRecord) -> None:
        self.hostnames += 1
        self.errors += bool(rec.error)
        if rec.ip != "N/A":
            self.ips.add(rec.ip)
        if rec.cert_sha256 not in ("N/A", ""):
            self.certs.add(rec.cert_sha256)
        if rec.site_id not in ("N/A", ""):
            self.sites.add(rec.site_id)

    def as_dict(self) -> Dict[str, int]:
        return {"hostnames": self.hostnames, "distinct_ips": len(self.ips),
                "distinct_certificates": len(self.certs), "distinct_sites": len(self.sites),
                "records_with_errors": self.errors}


def _sha256_file(path: Optional[str]) -> str:
    if not path or not os.path.isfile(path):
        return "N/A"
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(1 << 16), b""):
            h.update(block)
    return h.hexdigest()


def write_manifest(output: str, args: argparse.Namespace, config_path: Optional[str],
                   started: str, finished: str, domains: List[str], stats: "RunStats",
                   inventory: Optional[Dict[str, Any]] = None,
                   run: Optional[Dict[str, int]] = None) -> str:
    """<output>.manifest.json: what produced this file, so a report built from it can be
    reproduced. Holds hashes and counts, never the configuration's content."""
    tuning_src = _TUNING.get("_source")
    flags = {k: v for k, v in sorted(vars(args).items())
             if k not in ("roots", "managed_providers", "approved_mx", "approved_redirect")
             and isinstance(v, (str, int, float, bool, list, type(None)))}
    # Paths are reduced to file names so the manifest can travel without local layout.
    flags = {k: (os.path.basename(v) if isinstance(v, str) and os.sep in v else v) for k, v in flags.items()}
    manifest = {
        "clipeus_version": __version__,
        "rules_version": RULES_VERSION,
        "started": started, "finished": finished,
        "output": os.path.basename(output),
        "input": {"path": os.path.basename(args.input) if args.input != "-" else "-",
                  "sha256": _sha256_file(args.input if args.input != "-" else None),
                  "hosts": len(domains),
                  "inventory": {k: v for k, v in (inventory or {}).items() if k != "excluded"},
                  "excluded_file": (os.path.basename(output) + ".excluded.txt"
                                    if inventory and inventory.get("excluded") else "N/A")},
        "run": run or {},
        "overrides": {"sha256": _sha256_file(getattr(args, "overrides", None)),
                      "hosts": len(OVERRIDES)},
        "config": {"sha256": _sha256_file(config_path), "roots": len(args.roots),
                   "managed_providers": len(args.managed_providers),
                   "approved_mx": len(args.approved_mx), "approved_redirect": len(args.approved_redirect)},
        "tuning_sha256": _sha256_file(tuning_src) if isinstance(tuning_src, str) else "N/A",
        "platforms_sha256": _sha256_file(PLATFORMS.get("_source")) if PLATFORMS.get("_source") else "N/A",
        "resolvers": list(RESOLVER.nameservers),
        "flags": flags,
        "counts": stats.as_dict(),
        "subdomain_rule": "is_subdomain = host differs from root_domain; root_domain = longest "
                          "configured root that is a suffix of the host, else its registrable domain",
    }
    path = output + ".manifest.json"
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=2)
    return path


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
            out += [f"{rec.domain}:{port}" for _lbl, _sev, port, _ok in exposed_services(rec.ports, rec.port_services)]
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

def _tls_selftest(check) -> None:
    """Local TLS server (127.0.0.1 only) with generated certificates: verifies that
    defects are judged independently. No external traffic."""
    import tempfile
    from datetime import datetime, timedelta, timezone
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    def serve(days_from: int, days_to: int, san: str):
        key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, san)])
        now = datetime.now(timezone.utc)
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                .public_key(key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now + timedelta(days=days_from)).not_valid_after(now + timedelta(days=days_to))
                .add_extension(x509.SubjectAlternativeName([x509.DNSName(san)]), False)
                .sign(key, hashes.SHA256()))
        td = tempfile.mkdtemp()
        cf, kf = os.path.join(td, "c.pem"), os.path.join(td, "k.pem")
        with open(cf, "wb") as fh:
            fh.write(cert.public_bytes(serialization.Encoding.PEM))
        with open(kf, "wb") as fh:
            fh.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                       serialization.NoEncryption()))
        sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        sctx.load_cert_chain(cf, kf)
        lsock = socket.socket()
        lsock.bind(("127.0.0.1", 0))
        lsock.listen(16)
        lsock.settimeout(0.5)
        stop = threading.Event()

        def loop():
            while not stop.is_set():
                try:
                    conn, _ = lsock.accept()
                except OSError:
                    continue
                try:
                    with sctx.wrap_socket(conn, server_side=True):
                        pass
                except Exception:
                    pass
        threading.Thread(target=loop, daemon=True).start()
        return lsock, stop, td

    saved = TLS_PORT
    for days, san, want in (((-30, -1), "other.example", "expired;self-signed;hostname-mismatch"),
                            ((-1, 30), "localhost", "self-signed")):
        lsock, stop, td = serve(days[0], days[1], san)
        try:
            globals()["TLS_PORT"] = lsock.getsockname()[1]
            out = get_tls("localhost")
            check(out["handshake"] == "ok" and out["defects"] == want and out["health"] == "Degraded",
                  f"TLS local server: defects={out['defects']} (want {want})")
        finally:
            globals()["TLS_PORT"] = saved
            stop.set()
            lsock.close()
            shutil.rmtree(td, ignore_errors=True)


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
    # S11: TXT strings split without spaces join into "v=spf1mx..." — not an SPF record.
    spf = parse_spf(["v=spf1mxinclude:_spf.example.net~all"])
    check(not spf["spf_present"] and spf["spf_issues"] == ["spf_malformed_version"]
          and spf["spf_record"].startswith("v=spf1mx"), "SPF without a space after v=spf1 is malformed")
    check(is_spf_record("v=spf1") and is_spf_record("V=SPF1 -all") and not is_spf_record("v=spf10 -all"),
          "SPF version tag must end at a space or end of record")
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
    check([e[0] for e in exposed_services("22,80,445,6379,9999")] == ["smb", "redis"],
          "exposed services ordered by severity")
    check(exposed_services("") == [] and exposed_services("80,443") == [], "no exposed services")
    r = AuditRecord(domain="x.test"); r.ports = "445,6379,3306,23"
    r.port_services = "23:telnet(banner);445:smb(banner);3306:mysql(banner);6379:redis(banner)"
    check(any(n.startswith("Exposed services") and n.endswith(f"(+{PORT_RISK_CAP})") for n in score_risk(r)[1]),
          "exposed services score capped")
    # A port number alone is not a service (S07): banner decides, port guess scores half.
    check(identify_service(10000, "HTTP/1.0 200 Document follows Server: MiniServ/2.105") == ("webmin", "banner"),
          "service: Webmin confirmed by its MiniServ banner")
    check(identify_service(10000, "HTTP/1.1 200 OK Server: nginx") == ("http", "banner"),
          "service: plain web server on 10000 is not Webmin")
    check(identify_service(10000, "") == ("webmin", "port-guess"), "service: no banner = port guess")
    check(describe_port_services([22, 10000], {22: "SSH-2.0-OpenSSH_9.6"}) == "22:ssh(banner);10000:webmin?(port-guess)",
          "service: port_services marks guesses with ?")
    check(exposed_services("10000", "10000:http(banner)") == [], "service: contradicting banner drops the port")
    check(exposed_services("10000", "10000:webmin?(port-guess)") == [("webmin", "medium", 10000, False)],
          "service: unconfirmed port stays, marked unconfirmed")
    _a, _b = socket.socketpair()
    def _two_packets():
        _b.sendall(b"HTTP/1.0 302 Moved Temporarily\r\n")
        time.sleep(0.15)
        _b.sendall(b"Date: x\r\nServer: MiniServ\r\n\r\n")
    threading.Thread(target=_two_packets, daemon=True).start()
    try:
        _ban = _grab_banner(_a, 22)
    finally:
        _a.close(); _b.close()
    check(identify_service(10000, _ban)[0] == "webmin", "banner: a banner split over two packets is read whole")
    check(describe_port_services([443], {443: "HTTP/1.1 400 Bad Request"}, {443}) == "443:https(tls-handshake)",
          "service: 443 with a TLS handshake is https")
    r2 = AuditRecord(domain="x.test"); r2.ports = "10000"; r2.port_services = "10000:webmin?(port-guess)"
    check(score_parts(r2)["exposure"] == PORT_RISK_POINTS["medium"] // 2 and score_parts(r2)["confidence"] == "Low",
          "service: unconfirmed port scores half, low confidence")

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
    check(cr.cookie_context.startswith("JSESSIONID*@https://c.test/"), "cookie context: setter URL, session marked")

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
    _i = FIELDNAMES.index("platform_risk")
    check(FIELDNAMES[_i - 2:_i + 2] == ["body_truncated", "technology", "platform_risk", "root_domain"]
          and FIELDNAMES.index("domain") == 0,
          "existing column order unchanged; 26.11.1 columns appended after platform_risk")
    _pr = assess_platforms("PHP/8.1.4; nginx/1.18.0; jQuery/1.11.1; Apache/2.4.58", "IdeaWebServer/6.4.2",
                           today="2026-10-26", rules=PLATFORMS)
    check("PHP/8.1.4: end-of-life 2025-12-31" in _pr and "nginx/1.18.0" in _pr and "jQuery/1.11.1: below 3.5.0" in _pr
          and "IdeaWebServer: non-enterprise" in _pr and "Apache/2.4.58" not in _pr,
          f"platform_risk flags EOL, old and non-enterprise: {_pr[:80]}")
    check("home.pl" in _pr and "JetBrains" not in _pr, "platform_risk: IdeaWebServer is shared hosting, not an IDE")
    check(assess_platforms("PHP/8.2.34", today="2026-10-26", rules=PLATFORMS).startswith("PHP/8.2.34: support ends 2026-12-31"),
          "platform_risk warns 6 months ahead of PHP 8.2 support end")
    check(assess_platforms("PHP/8.4.25; nginx/1.24.0; jQuery/3.7.1", today="2026-10-26", rules=PLATFORMS) == "",
          "platform_risk is empty for current platforms")
    check(assess_platforms("PHP/8.1.4", rules={}) == "", "platform_risk is empty without a rules file")
    check(assess_platforms("Apache/2", today="2026-10-26", rules=PLATFORMS) == "",
          "platform_risk ignores a bare major version (Apache/2)")
    check("Vesta: non-enterprise" in assess_platforms("", extra="O=Vesta Control Panel", rules=PLATFORMS),
          "platform_risk: non-enterprise rules also read the certificate issuer")
    _t = detect_technology({"X-Powered-By": "PHP/8.3.35", "Server": "nginx/1.25.0",
                            "Set-Cookie": "PHPSESSID=abc; path=/"},
                           '<meta name="generator" content="WordPress 6.5"><a href="/x.php">', "", "Cloudflare")
    check(_t == "PHP/8.3.35; nginx/1.25.0; WordPress/6.5; Cloudflare", f"technology detection: {_t}")
    check(detect_technology({}, '<a href="/login.php?x=1">') == "PHP (inferred)", "technology: .php link is inferred only")
    check(detect_technology({}, "") == "", "technology: empty when nothing visible")
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

    # --- 26.11.1 regression tests (reviewer findings S01-S17; DNS stubbed, local TLS only)
    check(_hostname_matches("a.example.com", ["*.example.com"]) and not _hostname_matches("a.b.example.com", ["*.example.com"])
          and _hostname_matches("example.com", ["EXAMPLE.com."]) and not _hostname_matches("example.com", ["*.example.com"]),
          "hostname matching: one-label wildcard only")
    t = {"handshake": "ok", "hostname": "fail", "trust": "self-signed", "dates": "expired", "protocol": "pass",
         "valid": "N/A", "health": "N/A", "defects": "None"}
    _summarise_tls(t)
    check(t["defects"] == "expired;self-signed;hostname-mismatch" and t["valid"] == "expired" and t["health"] == "Degraded",
          "TLS: every defect kept, expiry not hidden, health Degraded (S01/S02)")
    t = {"handshake": "ok", "hostname": "pass", "trust": "pass", "dates": "pass", "protocol": "legacy(TLSv1.0)",
         "valid": "N/A", "health": "N/A", "defects": "None"}
    _summarise_tls(t)
    check(t["valid"] == "valid" and t["health"] == "Degraded" and t["defects"] == "None",
          "TLS: valid cert on a legacy protocol is not Healthy")
    try:
        _tls_selftest(check)
    except ImportError:
        print("  [SKIP] TLS handshake tests (cryptography not installed)", file=sys.stderr)

    _saved = {k: globals()[k] for k in ("_target_claimable_nxdomain", "_resolve")}
    try:
        globals()["_target_claimable_nxdomain"] = lambda t: t.startswith("gone")
        globals()["_resolve"] = lambda name, rtype: ("token",) if name.startswith("asuid.protected") else ()
        check(detect_takeover(["live.azurewebsites.net"], "<h1>404 Not Found</h1>")[0] == "No",
              "takeover: a live Azure app's 404 is not a takeover (S03)")
        risk, det = detect_takeover(["gone.azurewebsites.net"], "")
        tk = assess_takeover("open.example.com", ["gone.azurewebsites.net"], risk, det)
        check(tk["risk"] == "Possibly" and tk["outcome"] == "potentially-reclaimable" and tk["binding"] == "No"
              and tk["recreatable"] == "unknown" and tk["verified"] == "No (manual)"
              and "claimable" not in tk["detail"].replace("reclaimable", ""),
              "takeover: missing Azure app, no asuid, reuse unknown = potentially reclaimable, never 'claimable'")
        tk = assess_takeover("protected.example.com", ["gone.azurewebsites.net"], risk, det)
        check(tk["risk"] == "No" and tk["outcome"] == "protected" and tk["binding"] == "Yes",
              "takeover: an asuid verification record makes a missing app 'protected', not a takeover")
        uq = "app-abcdefgh12345678.eastus-01.azurewebsites.net"
        globals()["_target_claimable_nxdomain"] = lambda t: True
        risk_u, det_u = detect_takeover([uq], "")
        check(assess_takeover("u.example.com", [uq], risk_u, det_u)["outcome"] == "dangling-reserved",
              "takeover: a unique default hostname cannot be recreated (dangling, reserved)")
        globals()["_target_claimable_nxdomain"] = lambda t: t.startswith("gone")
        risk, det = detect_takeover(["gone.eastus.cloudapp.azure.com"], "")
        tk = assess_takeover("x.example.com", ["gone.eastus.cloudapp.azure.com"], risk, det)
        check(tk["risk"] == "Yes" and tk["outcome"] == "claimable-by-policy" and tk["confidence"] == "High"
              and tk["recreatable"] == "released (provider policy)" and tk["detail"].endswith("claim not verified"),
              "takeover: released cloudapp label = claimable by policy, says it is unverified")
        risk, det = detect_takeover(["x.github.io"], "<title>404</title>")
        check(risk == "Possibly" and assess_takeover("g.example.com", ["x.github.io"], risk, det)["outcome"]
              == "provider-binding-review", "takeover: generic 404 body is an observation only")
        risk, det = detect_takeover(["x.cloudfront.net"], "<html>ok</html>")
        tk = assess_takeover("c.example.com", ["x.cloudfront.net"], risk, det)
        check(tk["risk"] == "No" and tk["outcome"] == "provider-binding-review",
              "takeover: provider association alone is a binding review, not a finding")
        elb = "gone-lb-123.us-east-1.elb.amazonaws.com"
        risk, det = detect_takeover([elb], "")
        check(assess_takeover("e.example.com", [elb], risk, det)["outcome"] == "dangling-reserved",
              "takeover: a deleted load balancer's random name cannot be reissued (dangling, reserved)")
        risk, det = detect_takeover(["x.github.io"], "There isn't a GitHub Pages site here.")
        tk = assess_takeover("g.example.com", ["x.github.io"], risk, det)
        check(tk["risk"] == "Yes" and tk["outcome"] == "claimable-by-signature",
              "takeover: provider-specific unclaimed page = claimable by signature")
        ns_ev = {"parent": ("ns-1.exampel.test", "ns-2.example.test"), "own": (),
                 "addresses": {"ns-1.exampel.test": "NXDOMAIN", "ns-2.example.test": "NXDOMAIN"},
                 "registration": {"exampel.test": "not-registered", "example.test": "ok"}}
        tk = assess_takeover("d.example.org", [], "No", "N/A", ns_ev)
        check(tk["risk"] == "Yes" and tk["outcome"] == "claimable-ns-domain" and tk["confidence"] == "High"
              and "exampel.test not registered" in tk["detail"],
              "takeover: a delegation to a nameserver whose domain is unregistered is claimable")
        ns_ev["registration"]["exampel.test"] = "rate-limited"
        check(assess_takeover("d.example.org", [], "No", "N/A", ns_ev)["outcome"] == "none",
              "takeover: a failed registration lookup is never read as 'not registered'")
        # S05: names that do not exist, or exist without addresses, are not dangling.
        check(detect_dangling("a.example.com", [], [], False, "NXDOMAIN") == ("No", "Name does not exist", "nxdomain"),
              "dangling: NXDOMAIN under a delegated zone is not dangling")
        check(detect_dangling("a.example.com", [], [], False, "NOANSWER")[2] == "no-web-records",
              "dangling: a name with only MX/TXT is not dangling")
        check(detect_dangling("a.example.com", [], [], False, "SERVFAIL")[2] == "dns-failure",
              "dangling: SERVFAIL without a delegation is a DNS failure")
    finally:
        globals().update(_saved)

    nx = AuditRecord(domain="gone.example.com")
    nx.dns_status, nx.is_subdomain = "NXDOMAIN", "Yes"
    nx.spf_issues, nx.dmarc_issues = "spf_missing", "dmarc_missing"
    classify_domain(nx, [], [])
    check(score_risk(nx)[0] == 0 and "spf-missing" not in nx.config_issues,
          "score: a name that does not exist gets no SPF/DMARC/CAA points (S09)")
    ap = AuditRecord(domain="example.com")
    ap.dns_status, ap.spf_issues, ap.dmarc_issues = "OK", "spf_missing", "dmarc_missing"
    check(score_parts(ap)["hygiene"] == 40 and score_parts(ap)["exposure"] == 0,
          "score: an existing registered domain without SPF/DMARC/CAA scores as hygiene")
    sd = AuditRecord(domain="www.example.com")
    sd.dns_status, sd.is_subdomain, sd.spf_issues = "OK", "Yes", "spf_missing"
    check(score_parts(sd)["hygiene"] == 0, "score: SPF on a subdomain without MX is not applicable")

    check(host_root("a.b.example.com") == "example.com" and host_root("a.b.example.com", {"b.example.com"}) == "b.example.com"
          and host_root("example") == "example", "roots: longest configured root, else registrable domain (S10)")
    hr = AuditRecord(domain="h.example.com")
    hr.ip, hr.ptr = "203.0.113.7", "ec2-203-0-113-7.compute-1.amazonaws.com"
    check(classify_hosting(hr, False, []) == ("aws", "cloud", "not-verified")
          and classify_hosting(hr, False, ["aws"])[2] == "org-provider(aws)"
          and classify_hosting(hr, True, [])[1:] == ("org", "org-network"),
          "hosting: network location is not management (S08)")
    hr.cname = "x.privatelink.example.net"
    check(private_endpoint(hr) == "Yes(name:privatelink)", "private endpoint marker (S15)")

    ck_args = build_parser().parse_args([])
    cr2 = AuditRecord(domain="example.com")
    cr2.dns_status, cr2.ip, cr2.https_status = "OK", "203.0.113.7", "200"
    states = parse_checks(describe_checks(cr2, ck_args, TOP_PORTS))
    check(states.get("scanner") == "not_run" and states.get("cors") == "not_run" and states.get("http") == "passed"
          and set(states.values()) <= set(CHECK_STATES), "checks: typed states, not-run is explicit (S12)")

    old = [{"domain": "t.test", "config_issues": "hsts-missing", "risk_score": 5}]
    new = [{"domain": "t.test", "config_issues": "None", "risk_score": 0, "checks": "dns=timeout"}]
    d = diff_results(old, new)
    check(d["transient"] and not d["resolved_issues"], "diff: an issue not re-checked is transient, not resolved (S17)")

    st = RunStats()
    for ip, cert in (("192.0.2.1", "c1"), ("192.0.2.1", "c1"), ("192.0.2.2", "c2")):
        sr = AuditRecord(domain="s.test"); sr.ip, sr.cert_sha256 = ip, cert
        st.add(sr)
    check(st.as_dict()["hostnames"] == 3 and st.as_dict()["distinct_ips"] == 2
          and st.as_dict()["distinct_certificates"] == 2, "counts: hostnames vs distinct IPs/certs (S13)")
    with tempfile.TemporaryDirectory() as td:
        ma = build_parser().parse_args(["--input", "-"])
        ma.roots, ma.managed_providers, ma.approved_mx, ma.approved_redirect = frozenset(), [], [], []
        mp = write_manifest(os.path.join(td, "out.jsonl"), ma, None, "t0", "t1", ["a.test"], st)
        with open(mp) as fh:
            m = json.load(fh)
        check(m["clipeus_version"] == __version__ and m["counts"]["hostnames"] == 3 and m["input"]["hosts"] == 1,
              "manifest: version, inputs and unit-labelled counts (S14)")

    check(normalize_host("xn--  -1dac2z.example") is None and normalize_host("a b.example.com") is None
          and normalize_host("_dmarc.example.com") == "_dmarc.example.com",
          "normalize: hostnames with spaces are rejected, service labels kept")
    with tempfile.TemporaryDirectory() as td:
        ip = os.path.join(td, "in.txt")
        with open(ip, "w", encoding="utf-8") as fh:
            fh.write("# list\nexample.com\nEXAMPLE.com\n\nbad host.example\nwww.example.com\n")
        inv: Dict[str, Any] = {}
        hosts = read_inputs(ip, inventory=inv)
        check(hosts == ["example.com", "www.example.com"] and inv["lines"] == 6 and inv["blank_or_comment"] == 2
              and inv["duplicates"] == 1 and inv["invalid"] == 1 and len(inv["excluded"]) == 2,
              "inventory: every input line is accounted for")
        op = os.path.join(td, "ov.json")
        with open(op, "w") as fh:
            json.dump({"overrides": [{"host": "Example.com", "set": {"takeover_outcome": "verified",
                       "takeover_claim_verified": "Yes"}, "evidence": "test", "observed_at": "2026-01-01",
                       "analyst": "selftest"}]}, fh)
        ov = load_overrides(op)
        orc = AuditRecord(domain="example.com")
        apply_overrides(orc, ov["example.com"])
        check(orc.takeover_outcome == "verified" and "2026-01-01, selftest; test" in orc.overrides,
              "overrides: applied with date, analyst and evidence")
        with open(op, "w") as fh:
            json.dump([{"host": "example.com", "set": {"risk_score": "0"}, "observed_at": "2026-01-01"}], fh)
        try:
            load_overrides(op)
            check(False, "overrides: entry without evidence is refused")
        except ValueError:
            check(True, "overrides: entry without evidence is refused")
    _saved_get = requests.get
    try:
        class _R:
            def __init__(self, code, hist): self.status_code, self.history, self.headers = code, hist, {}
        _saved_boot = globals()["_RDAP_BOOTSTRAP"]
        globals()["_RDAP_BOOTSTRAP"] = {"example": "https://rdap.invalid/"}
        requests.get = lambda *a, **k: _R(404, [])
        check(_rdap_query("free.example")["result"] == "not-registered", "rdap: registry 404 = not registered")
        check(_rdap_query("x.test")["result"] == "unsupported-tld", "rdap: TLD not in the IANA bootstrap = no RDAP")
        check(_rdap_query("a.private.example")["result"] == "not-found(tld-registry)",
              "rdap: a TLD registry's 404 for a name under a private suffix is not 'not registered'")
        globals()["RDAP_BACKOFF"] = (0.0,)
        requests.get = lambda *a, **k: _R(429, [])
        check(_rdap_query("y.example")["result"] == "rate-limited", "rdap: rate limiting is recorded, not 'error'")
    finally:
        requests.get = _saved_get
        globals()["RDAP_BACKOFF"] = (2.0, 5.0)
        globals()["_RDAP_BOOTSTRAP"] = _saved_boot

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


def read_inputs(source: str, dedup_www: bool = False,
                inventory: Optional[Dict[str, Any]] = None) -> List[str]:
    """Hosts from the input, normalised and de-duplicated. With `inventory`, also account
    for every line: counts per outcome, plus the excluded lines with their reason, so the
    number of hosts scanned can be reconciled with the number of lines supplied."""
    fh = sys.stdin if source in ("-", None) else open(source, encoding="utf-8", errors="replace")
    seen, hosts = set(), []
    inv = {"lines": 0, "blank_or_comment": 0, "invalid": 0, "duplicates": 0, "www_dropped": 0,
           "hosts": 0, "excluded": []}
    try:
        for n, line in enumerate(fh, 1):
            inv["lines"] += 1
            text = line.strip()
            if not text or text.startswith("#"):
                inv["blank_or_comment"] += 1
                continue
            h = normalize_host(line)
            if not h:
                inv["invalid"] += 1
                inv["excluded"].append((n, "invalid-hostname", text))
            elif h in seen:
                inv["duplicates"] += 1
                inv["excluded"].append((n, f"duplicate-of:{h}", text))
            else:
                seen.add(h)
                hosts.append(h)
    finally:
        if fh is not sys.stdin:
            fh.close()
    if dedup_www:
        # drop www.X when X is already in the set (redundant with the apex scan)
        kept = [h for h in hosts if not (h.startswith("www.") and h[4:] in seen)]
        inv["www_dropped"] = len(hosts) - len(kept)
        hosts = kept
    inv["hosts"] = len(hosts)
    if inventory is not None:
        inventory.update(inv)
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
    p.add_argument("--banners", action="store_true", help=argparse.SUPPRESS)  # legacy; banners are on by default
    p.add_argument("--no-banners", action="store_true",
                   help="Don't read service banners on open ports (then services are port guesses only)")
    p.add_argument("--roots", metavar="FILE",
                   help="Portfolio roots, one per line: sets root_domain / is_subdomain "
                        "(default: config roots, else each host's registrable domain)")
    p.add_argument("--overrides", metavar="FILE",
                   help="Manual findings (JSON) merged into matching records, each with evidence, "
                        "observation date and analyst; recorded in the overrides column")
    p.add_argument("--no-manifest", action="store_true",
                   help="Don't write <output>.manifest.json (run provenance: version, rules, inputs, counts)")
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
            "platforms_source": PLATFORMS.get("_source", "(none — platform_risk disabled)"),
            "platforms_as_of": PLATFORMS.get("_as_of", ""),
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
                "takeover_name_policy": TAKEOVER_NAME_POLICY,
                "takeover_binding_txt": TAKEOVER_BINDING_TXT,
                "cloud_provider_markers": sorted(CLOUD_PROVIDER_MARKERS),
                "private_endpoint_markers": list(PRIVATE_ENDPOINT_MARKERS),
                "rules_version": refresh_rules_version(),
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
    args.managed_providers = list(brand_cfg.get("managed_providers", []))
    roots = list(brand_cfg.get("roots", []))
    if args.roots:
        try:
            roots = [h for h in (normalize_host(ln) for ln in open(args.roots, encoding="utf-8")) if h]
        except OSError as exc:
            sys.exit(f"error: --roots {exc}")
    args.roots = frozenset(roots)

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
    refresh_rules_version()

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

    inventory: Dict[str, Any] = {}
    domains = read_inputs(args.input, dedup_www=args.dedup_www_input, inventory=inventory)
    if inventory["excluded"]:
        log(f"[*] input: {inventory['lines']} lines -> {inventory['hosts']} hosts "
            f"({inventory['invalid']} invalid, {inventory['duplicates']} duplicates excluded)")
    if args.overrides:
        try:
            OVERRIDES.update(load_overrides(args.overrides))
        except (OSError, ValueError) as exc:
            sys.exit(f"error: --overrides {args.overrides}: {exc}")
        log(f"[*] overrides: {sum(len(v) for v in OVERRIDES.values())} entries for {len(OVERRIDES)} hosts")
    log(f"[*] Clipeus v{__version__} | loaded {len(domains)} input domains | "
        f"workers={args.workers} accurate={args.accurate} ports={args.ports}")

    # Subdomain enumeration pre-pass (subfinder + crt.sh CT) -> subs_file, audited too.
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
    stats = RunStats()
    started = _utc_now()

    try:
        with ThreadPoolExecutor(max_workers=args.workers) as ex:
            futures = {ex.submit(process_domain, d, session, args, org_networks, port_list): d
                       for d in todo}
            for fut in as_completed(futures):
                rec = fut.result()
                stats.add(rec)
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
    if args.output != "-" and not args.no_manifest:
        input_hosts = inventory.get("hosts", 0)
        mpath = write_manifest(args.output, args, brand_path, started, _utc_now(), domains, stats,
                               inventory=inventory,
                               run={"input_hosts": input_hosts,
                                    "enumerated_hosts": len(domains) - input_hosts,
                                    "already_done": len(done), "attempted": total,
                                    "completed": completed, "interrupted": int(STOP.is_set())})
        if inventory.get("excluded"):
            with open(args.output + ".excluded.txt", "w", encoding="utf-8") as fh:
                fh.write("# line\treason\tinput\n")
                fh.writelines(f"{n}\t{why}\t{txt}\n" for n, why, txt in inventory["excluded"])
        log(f"[*] manifest -> {mpath}")
    if (args.baseline or args.report_html) and completed:
        post_process(args.output, args.baseline, args.report_html, args.diff_out, log)
    if log_fh:
        log_fh.close()


if __name__ == "__main__":
    main()
