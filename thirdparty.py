#!/usr/bin/env python3
"""thirdparty.py — resources a page loads from other hosts, and whether someone else
could serve them.

A page that loads a script, stylesheet or iframe from a host that no longer exists,
from a deleted cloud bucket, or from a domain that has lapsed hands that slot to
whoever claims it first: the browser runs their code with the page's origin. The
page itself still looks fine, so the name-level takeover checks never see it.

For each page the audit already loaded, this module:
  * collects <script src>, stylesheet / preload <link href> and <iframe>/<frame src>,
    plus iframes and scripts that inline JavaScript injects (markup in a string, a
    .src assignment) (level 1), and follows up to IFRAME_MAX iframe documents to collect theirs
    (level 2);
  * judges each referenced host once per run, from evidence:
      claimable-domain        the host's registrable domain is not registered
      claimable-by-policy     a takeover-class provider target is NXDOMAIN and the
                              provider releases such names
      claimable-by-signature  the provider answers the exact resource URL with its
                              "no such bucket/site" page
      potentially-claimable   a provider target is NXDOMAIN, reuse policy unknown
      stale                   the host is gone, or the provider resource answers
                              404/410, but nobody can be shown to claim it
  * grades the page: third-party scripts without Subresource Integrity, iframes
    without a sandbox, and CSP host sources that admit shared-tenant or public-package
    hosts (anyone can get a name under *.cloudfront.net or publish to a package CDN).

Requests: one GET of the exact resource URL, and only when the host or its CNAME is
at a takeover-class provider (that is where the "unclaimed" signatures live), plus
the iframe documents followed for level 2. Nothing else is sent to third parties: no
ports, no TLS probes, no paths the page does not reference.

The network is injected (resolve / registration / fetch callables) so the logic is
testable offline; clipeus.py supplies the shared resolver, RDAP and HTTP session.
"""
from __future__ import annotations

import threading
import re
from html.parser import HTMLParser
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

RESOURCE_MAX = 40          # resources judged per page (level 1 + level 2)
IFRAME_MAX = 5             # iframe documents followed for level 2

CLAIMABLE = ("claimable-domain", "claimable-by-policy", "claimable-by-signature",
             "potentially-claimable")

# Host sources in a CSP that admit content anyone can publish: a tenant subdomain at
# a shared provider, or any package on a public package CDN.
SHARED_TENANT_SUFFIXES = (
    "cloudfront.net", "amazonaws.com", "azurewebsites.net", "azureedge.net", "azurefd.net",
    "blob.core.windows.net", "web.core.windows.net", "trafficmanager.net", "cloudapp.azure.com",
    "github.io", "gitlab.io", "herokuapp.com", "netlify.app", "vercel.app", "pages.dev",
    "workers.dev", "appspot.com", "firebaseapp.com", "web.app", "storage.googleapis.com",
    "googleusercontent.com", "surge.sh", "glitch.me", "ngrok.io", "fastly.net")
PUBLIC_PACKAGE_HOSTS = ("cdn.jsdelivr.net", "unpkg.com", "cdnjs.cloudflare.com",
                        "esm.sh", "cdn.skypack.dev", "rawgit.com", "raw.githubusercontent.com")
CSP_FETCH_DIRECTIVES = ("script-src", "script-src-elem", "style-src", "style-src-elem",
                        "frame-src", "child-src", "default-src")


# ---------------------------------------------------------------- page parsing

# Resources injected by inline JavaScript: markup in a string ('<iframe src="//x/">',
# a lightbox or consent loader) or a loader assigning .src. A browser fetches them
# when the code runs, so they count for takeover; their attributes are not graded.
_INJECTED_TAG_RE = re.compile(r"""<(iframe|script)\b[^>]{0,400}?\bsrc\s*=\s*\\?["']([^"'\\\s>]{4,400})""", re.I)
_SRC_ASSIGN_RE = re.compile(r"""\.src\s*=\s*["']((?:https?:)?//[^"'\s]{4,400})["']""", re.I)


class _Collector(HTMLParser):
    def __init__(self, base: str):
        super().__init__(convert_charrefs=True)
        self.base = base
        self.items: List[Dict[str, Any]] = []
        self._in_script = False

    def handle_endtag(self, tag):
        if tag == "script":
            self._in_script = False

    def handle_data(self, data):
        if not self._in_script or len(data) < 12:
            return
        for tag, ref in _INJECTED_TAG_RE.findall(data):
            self._add(tag.lower(), ref, {}, injected=True)
        for ref in _SRC_ASSIGN_RE.findall(data):
            self._add("script", ref, {}, injected=True)

    def _add(self, kind: str, ref: Optional[str], attrs: Dict[str, Optional[str]],
             injected: bool = False):
        ref = (ref or "").strip()
        if not ref or ref.startswith(("data:", "blob:", "javascript:", "about:", "#")):
            return
        url = urljoin(self.base, ref)
        if urlparse(url).scheme not in ("http", "https") or not urlparse(url).hostname:
            return
        self.items.append({"kind": kind, "url": url,
                           "integrity": bool((attrs.get("integrity") or "").strip()),
                           "sandbox": attrs.get("sandbox") if "sandbox" in attrs else None,
                           "injected": injected})

    def handle_starttag(self, tag, attrs_list):
        a = {k.lower(): v for k, v in attrs_list}
        if tag == "base" and a.get("href"):
            self.base = urljoin(self.base, a["href"])
        elif tag == "script":
            if a.get("src"):
                self._add("script", a["src"], a)
            else:
                self._in_script = True
        elif tag == "link" and a.get("href"):
            rel = (a.get("rel") or "").lower().split()
            as_ = (a.get("as") or "").lower()
            if "stylesheet" in rel or ("preload" in rel and as_ == "style"):
                self._add("style", a["href"], a)
            elif "modulepreload" in rel or ("preload" in rel and as_ == "script"):
                self._add("script", a["href"], a)
        elif tag in ("iframe", "frame") and a.get("src"):
            self._add("iframe", a["src"], a)

    def handle_startendtag(self, tag, attrs_list):
        self.handle_starttag(tag, attrs_list)
        self._in_script = False


def extract_resources(html: str, base_url: str) -> List[Dict[str, Any]]:
    """[{kind: script|style|iframe, url, integrity: bool, sandbox: str|None, injected:
    bool}], in page order, one entry per distinct (kind, url). injected = found in
    inline JavaScript (markup in a string, or a .src assignment), not as a tag."""
    c = _Collector(base_url)
    try:
        c.feed(html or "")
        c.close()
    except Exception:
        pass
    seen, out = set(), []
    for it in c.items:
        key = (it["kind"], it["url"])
        if key not in seen:
            seen.add(key)
            out.append(it)
    return out


def csp_source_risks(csp: str, provider_suffixes: Tuple[str, ...] = ()) -> List[str]:
    """CSP host sources that let anyone publish content the page will run or show:
    directive:source(shared-tenant|public-package)."""
    out: List[str] = []
    shared = tuple(dict.fromkeys(SHARED_TENANT_SUFFIXES + tuple(provider_suffixes)))
    for part in (csp or "").split(";"):
        bits = part.strip().split()
        if not bits or bits[0].lower() not in CSP_FETCH_DIRECTIVES:
            continue
        d = bits[0].lower()
        for src in bits[1:]:
            s = src.lower().strip()
            if s.startswith("'") or s in ("*", "http:", "https:", "data:", "blob:"):
                continue                      # keywords; bare wildcards are grade_csp's job
            host = urlparse(s if "://" in s else "https://" + s).hostname or ""
            if not host:
                continue
            bare = host[2:] if host.startswith("*.") else host
            if host.startswith("*.") and any(bare == x or bare.endswith("." + x) for x in shared):
                out.append(f"{d}:{s}(shared-tenant)")
            elif any(host == p or host.endswith("." + p) for p in PUBLIC_PACKAGE_HOSTS):
                out.append(f"{d}:{s}(public-package)")
    return list(dict.fromkeys(out))


# ---------------------------------------------------------------- judgement

class Judge:
    """Judges resource hosts once per run (thread-safe cache).

    resolve(host) -> (status, chain): status OK / NXDOMAIN / NOANSWER / FAIL, chain the
                     CNAME targets (without host).
    registration(reg) -> 'not-registered' / 'registered' / 'unknown'
    fetch(url) -> (status_code, body_text) or None
    provider_of(names) -> provider key or '' (takeover-class provider in host/chain)
    nx_only(provider) -> True when only NXDOMAIN proves the provider target free
    policy(target) -> 'released' / 'reserved…' / 'unknown'
    signature(provider, body) -> strong unclaimed signature found, or ''
    registrable(host) -> registrable domain
    """

    def __init__(self, resolve: Callable, registration: Callable, fetch: Callable,
                 provider_of: Callable, nx_only: Callable, policy: Callable,
                 signature: Callable, registrable: Callable):
        self.resolve, self.registration, self.fetch = resolve, registration, fetch
        self.provider_of, self.nx_only, self.policy = provider_of, nx_only, policy
        self.signature, self.registrable = signature, registrable
        self._hosts: Dict[str, Tuple[str, str, str]] = {}
        self._urls: Dict[str, Tuple[str, str]] = {}
        self._lock = threading.Lock()

    def host(self, host: str) -> Tuple[str, str, str]:
        """(verdict, reason, provider) for the host alone; verdict 'ok' when it
        resolves (a provider host may still be judged by URL)."""
        with self._lock:
            if host in self._hosts:
                return self._hosts[host]
        status, chain = self.resolve(host)
        provider = self.provider_of([host] + list(chain))
        verdict, reason = "ok", status.lower()
        if status in ("NXDOMAIN", "NOANSWER"):
            target = (list(chain) or [host])[-1]
            reg = self.registrable(target)
            reg_state = self.registration(reg) if reg else "unknown"
            if reg_state == "not-registered":
                verdict, reason = "claimable-domain", f"{reg} not registered"
            elif provider:
                pol = self.policy(target)
                if pol == "released":
                    verdict, reason = "claimable-by-policy", f"{provider} target {target} NXDOMAIN; name released"
                elif pol.startswith("reserved"):
                    verdict, reason = "stale", f"{provider} target {target} NXDOMAIN; name {pol}"
                else:
                    verdict, reason = "potentially-claimable", f"{provider} target {target} NXDOMAIN; reuse policy unknown"
            else:
                verdict, reason = "stale", f"{target} {status}"
        elif status == "FAIL":
            verdict, reason = "unknown", "dns lookup failed"
        with self._lock:
            self._hosts[host] = (verdict, reason, provider)
        return verdict, reason, provider

    def url(self, url: str) -> Tuple[str, str]:
        """(verdict, reason) for one resource URL."""
        host = (urlparse(url).hostname or "").lower()
        verdict, reason, provider = self.host(host)
        if verdict != "ok" or not provider or self.nx_only(provider):
            return verdict, reason
        with self._lock:
            if url in self._urls:
                return self._urls[url]
        got = self.fetch(url)
        if got is None:
            res = ("unknown", "resource did not load")
        else:
            code, body = got
            sig = self.signature(provider, body or "")
            if sig:
                res = ("claimable-by-signature", f"{provider} answers '{sig}' (HTTP {code})")
            elif code in (404, 410):
                res = ("stale", f"{provider} resource HTTP {code}")
            else:
                res = ("ok", f"HTTP {code}")
        with self._lock:
            self._urls[url] = res
        return res


def assess_page(html: str, page_url: str, page_host: str, judge: Judge,
                csp: str = "", fetch_doc: Optional[Callable[[str], Optional[str]]] = None,
                registrable: Callable[[str], str] = lambda h: h,
                provider_suffixes: Tuple[str, ...] = (), max_resources: int = RESOURCE_MAX,
                max_iframes: int = IFRAME_MAX) -> Dict[str, str]:
    """Record columns for one page: resource_hosts, resource_takeover, resource_stale,
    resource_integrity, iframe_sandbox, csp_source_risks."""
    out = {"resource_hosts": "None", "resource_takeover": "None", "resource_stale": "None",
           "resource_integrity": "N/A", "iframe_sandbox": "N/A", "csp_source_risks": "None"}
    risks = csp_source_risks(csp, provider_suffixes)
    if risks:
        out["csp_source_risks"] = ";".join(risks)
    page_host = page_host.lower()
    page_reg = registrable(page_host)
    level1 = extract_resources(html, page_url)
    items: List[Tuple[int, str, Dict[str, Any]]] = [(1, page_host, it) for it in level1]
    if fetch_doc:
        frames = [it for it in level1 if it["kind"] == "iframe"
                  and (urlparse(it["url"]).hostname or "").lower() != page_host][:max_iframes]
        for fr in frames:
            fh = (urlparse(fr["url"]).hostname or "").lower()
            if judge.host(fh)[0] != "ok":
                continue                      # judged as a level-1 resource below
            doc = fetch_doc(fr["url"])
            if doc:
                items += [(2, fh, it) for it in extract_resources(doc, fr["url"])
                          if it["kind"] in ("script", "style", "iframe")]
    hosts: Dict[str, set] = {}
    takeover, stale, no_sri, sandbox = [], [], [], []
    judged = 0
    for level, parent, it in items:
        host = (urlparse(it["url"]).hostname or "").lower()
        if not host or host == page_host:
            continue
        third = registrable(host) != page_reg
        hosts.setdefault(host, set()).add(it["kind"])
        if level == 1 and third and not it.get("injected"):
            if it["kind"] == "script" and not it["integrity"]:
                no_sri.append(host)
            if it["kind"] == "iframe":
                sandbox.append(f"{host}={'none' if it['sandbox'] is None else (it['sandbox'] or 'all')}")
        if judged >= max_resources:
            continue
        judged += 1
        verdict, reason = judge.url(it["url"])
        via = f" via iframe {parent}" if level == 2 else ""
        if verdict in CLAIMABLE:
            takeover.append(f"{verdict}:{it['kind']}:{it['url'][:160]}{via} ({reason})")
        elif verdict == "stale":
            stale.append(f"{host}({it['kind']}{via}: {reason})")
    if hosts:
        names = sorted(hosts)
        out["resource_hosts"] = ",".join(f"{h}({'+'.join(sorted(hosts[h]))})" for h in names[:30]) + (
            f",+{len(names) - 30} more" if len(names) > 30 else "")
    if takeover:
        out["resource_takeover"] = ";".join(dict.fromkeys(takeover))
    if stale:
        out["resource_stale"] = ";".join(dict.fromkeys(stale))
    third_scripts = [it for it in level1 if it["kind"] == "script" and not it.get("injected")
                     and registrable((urlparse(it["url"]).hostname or "").lower()) != page_reg]
    if third_scripts:
        out["resource_integrity"] = (f"no-sri({len(no_sri)}/{len(third_scripts)}):"
                                     + ",".join(sorted(set(no_sri)))) if no_sri else "all-sri"
    if sandbox:
        out["iframe_sandbox"] = ";".join(dict.fromkeys(sandbox))
    return out


# ---------------------------------------------------------------- mail-side records

def dmarc_rua_targets(dmarc_record: str) -> List[str]:
    """Report destinations' domains from rua= / ruf= (mailto: URIs)."""
    out: List[str] = []
    for part in (dmarc_record or "").split(";"):
        k, _, v = part.strip().partition("=")
        if k.strip().lower() not in ("rua", "ruf"):
            continue
        for uri in v.split(","):
            uri = uri.strip()
            if uri.lower().startswith("mailto:") and "@" in uri:
                dom = uri.split("@", 1)[1].split("!", 1)[0].strip().lower().rstrip(".")
                if dom:
                    out.append(dom)
    return list(dict.fromkeys(out))


def assess_dmarc_rua(domain: str, dmarc_record: str, registration: Callable[[str], str],
                     registrable: Callable[[str], str], txt: Callable[[str], Tuple[str, ...]]) -> str:
    """'None', or ';'-joined unregistered(x) (anyone can register the report domain and
    receive the reports) / unauthorised(x) (an external destination without the
    RFC 7489 authorisation record, so receivers drop the reports)."""
    org = registrable(domain)
    issues = []
    for dest in dmarc_rua_targets(dmarc_record):
        reg = registrable(dest)
        if not reg or reg == org:
            continue
        if registration(reg) == "not-registered":
            issues.append(f"unregistered({reg})")
        elif not any(t.lower().startswith("v=dmarc1") for t in txt(f"{org}._report._dmarc.{dest}")):
            issues.append(f"unauthorised({dest})")
    return ";".join(dict.fromkeys(issues)) or "None"


MX_CLAIMABLE = ("domain-unregistered", "provider-released")


def mx_claimable(value: Any) -> bool:
    """True when an mx_dangling value names an exchange someone else could take."""
    return any(m in str(value or "") for m in MX_CLAIMABLE)


def assess_mx(hosts: List[str], resolve: Callable[[str], Tuple[str, List[str]]],
              registration: Callable[[str], str], registrable: Callable[[str], str],
              provider_of: Callable[[List[str]], str] = lambda n: "",
              policy: Callable[[str], str] = lambda t: "unknown") -> str:
    """'None', or ';'-joined host=reason for exchanges that do not resolve. Claimable
    (anyone can receive the domain's mail, including certificate-validation mail):
    host=NXDOMAIN(domain-unregistered:x) — the exchange's domain is not registered;
    host=NXDOMAIN(provider-released:p) — a deleted cloud name the provider gives out
    again (e.g. a cloudapp label). host=NXDOMAIN(provider:p) — provider name, reuse
    policy unknown. Otherwise host=NXDOMAIN / NOANSWER: a stale record."""
    out = []
    for h in hosts:
        status, chain = resolve(h)
        if status not in ("NXDOMAIN", "NOANSWER"):
            continue
        target = (list(chain) or [h])[-1]
        reg = registrable(target)
        provider = provider_of([h] + list(chain))
        if status == "NXDOMAIN" and reg and registration(reg) == "not-registered":
            out.append(f"{h}=NXDOMAIN(domain-unregistered:{reg})")
        elif status == "NXDOMAIN" and provider and policy(target) == "released":
            out.append(f"{h}=NXDOMAIN(provider-released:{provider})")
        elif status == "NXDOMAIN" and provider:
            out.append(f"{h}=NXDOMAIN(provider:{provider})")
        else:
            out.append(f"{h}={status}")
    return ";".join(out) or "None"
