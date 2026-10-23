#!/usr/bin/env python3
"""
posture-analyze.py — turn a clipeus JSONL audit into owner-fixable findings.

Reads one or more clipeus `--format jsonl` audit files and emits:
  * <out>/posture-findings.csv   — one row per (host, issue), severity-tagged,
                                    with the concrete value and a fix hint.
  * <out>/posture-summary.json   — issue-class counts + top offenders (for the MD report).
  * stdout                       — a compact console summary.

Issue classes (the (c) brief): dangling DNS / subdomain-takeover risk, missing/lax
SPF, missing/lax DMARC, dirty TLS forwarding (HTTPS->HTTP or off-brand redirect,
cert hostname mismatch on a redirector), weak/legacy TLS versions, expiring/expired
certs, missing CAA, missing DNSSEC, open AXFR, plus a few always-useful signals.

Usage:
  posture-analyze.py --audit out/audit-roots.jsonl [out/audit-subs.jsonl ...] \
                     --out out/analysis
"""
from __future__ import annotations
import argparse, csv, json, os, sys
from collections import defaultdict, Counter
from functools import lru_cache
import os as _os, sys as _sys
_sys.path.insert(0, _os.path.join(_os.path.dirname(_os.path.realpath(__file__)), ".."))
import brand_config  # noqa: E402  (shared DNS config: one resolver setting for every tool)

try:
    import dns.resolver as _dnsr
    _RES = _dnsr.Resolver(); _RES.nameservers = brand_config.resolvers_or_exit()
    _RES.timeout = _RES.lifetime = 4.0
    _HAVE_DNS = True
except Exception:
    _HAVE_DNS = False

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

# CNAME targets whose backing resource is first-come claimable if the label is
# unregistered — i.e. NXDOMAIN target == real subdomain-takeover candidate.
TAKEOVER_PRONE = ("cloudapp.azure.com", "trafficmanager.net", "azurewebsites.net",
                  "cloudfront.net", "s3.amazonaws.com", "s3-website", "github.io",
                  "herokuapp.com", "herokudns.com", "fastly.net", "azureedge.net",
                  "elasticbeanstalk.com", "storage.googleapis.com", "ghost.io",
                  "pantheonsite.io", "readthedocs.io", "surge.sh", "bitbucket.io")

# Findings emitted by clipeus arrive as tokens in `config_issues`, e.g.
# "exposed-redis(6379)". Token prefix -> (severity, issue class, fix hint). Longest prefix wins.
V24_TOKENS = {
    "exposed-telnet": ("critical", "exposed-service", "Close the port at the perimeter; use SSH."),
    "exposed-smb": ("critical", "exposed-service", "Block SMB from the internet; use VPN/zero-trust access."),
    "exposed-docker-api": ("critical", "exposed-service", "Never expose the Docker API; bind to localhost/TLS-auth."),
    "exposed-": ("high", "exposed-service", "Restrict this service to trusted networks; require auth and TLS."),
    "exposed-pop3-cleartext": ("medium", "exposed-service", "Offer only implicit-TLS mail ports."),
    "exposed-imap-cleartext": ("medium", "exposed-service", "Offer only implicit-TLS mail ports."),
    "exposed-mqtt": ("medium", "exposed-service", "Require TLS and authentication on the broker."),
    "exposed-docker-tls": ("medium", "exposed-service", "Restrict the TLS-auth Docker port to management networks."),
    "exposed-webmin": ("medium", "exposed-service", "Restrict the admin panel to management networks."),
    "origin-ip-exposed": ("high", "origin-exposed", "Allow only the CDN's ranges to reach the origin; rotate exposed IPs."),
    "possible-origin-exposure": ("low", "origin-exposed", "Verify whether the candidate IPs serve the site directly."),
    "mta-sts-missing": ("low", "mta-sts", "Publish _mta-sts TXT and a policy at mta-sts.<domain>."),
    "mta-sts-not-enforced": ("low", "mta-sts", "Move the MTA-STS policy from testing/none to enforce."),
    "mta-sts-policy-broken": ("medium", "mta-sts", "Fix the unreachable/invalid MTA-STS policy file."),
    "dkim-key-under-2048": ("low", "dkim-weak-key", "Rotate DKIM keys to 2048-bit RSA or Ed25519."),
    "cookie-no-secure": ("low", "cookie-flags", "Set the Secure flag on cookies served over HTTPS."),
    "session-cookie-no-httponly": ("medium", "cookie-flags", "Set HttpOnly (and SameSite) on session cookies."),
    "cert-weak-key": ("high", "cert-weak-crypto", "Reissue with RSA >= 2048 or ECDSA P-256."),
    "cert-weak-signature": ("medium", "cert-weak-crypto", "Reissue with a SHA-256+ signature."),
    "cert-revoked": ("high", "cert-revoked", "Replace the revoked certificate immediately."),
    "ocsp-stapling-missing": ("info", "ocsp-stapling", "Enable OCSP stapling on the TLS terminator."),
    "hsts-short-maxage": ("low", "hsts-weak", "Raise HSTS max-age to >= 15552000 (ideally 1 year + includeSubDomains)."),
    "hsts-invalid-maxage": ("low", "hsts-weak", "Fix the malformed HSTS max-age directive."),
    "admin-login-exposed": ("medium", "admin-exposed", "Restrict admin/login paths by IP, VPN or SSO; add MFA."),
    "spf-lookup-limit": ("medium", "spf-chain", "Flatten/trim the SPF include chain to <= 10 DNS lookups."),
    "spf-include-unregistered": ("high", "spf-chain", "Remove the include or re-register the domain: anyone can authorise senders."),
    "spf-include-no-record": ("medium", "spf-chain", "Remove or fix the SPF include that publishes no SPF record."),
    "spf-broad-range": ("low", "spf-chain", "Narrow the oversized ip4/ip6 range in SPF."),
    "csp-": ("low", "header-quality", "Tighten Content-Security-Policy (no unsafe-inline/eval or wildcard sources)."),
    "clickjacking-unprotected": ("low", "header-quality", "Add CSP frame-ancestors or X-Frame-Options."),
    "server-version-disclosed": ("info", "header-quality", "Suppress version banners in Server/X-Powered-By."),
    "cors-reflects-origin-credentials": ("high", "cors", "Use an explicit origin allow-list; never reflect Origin with credentials."),
    "cors-": ("medium", "cors", "Use an explicit origin allow-list instead of * or reflection."),
    "security-txt-": ("info", "security-txt", "Publish a valid, unexpired /.well-known/security.txt."),
    "nuclei-critical": ("critical", "scanner-finding", "Triage and remediate the nuclei finding."),
    "nuclei-high": ("high", "scanner-finding", "Triage and remediate the nuclei finding."),
    "nuclei-medium": ("medium", "scanner-finding", "Triage and remediate the nuclei finding."),
}

# Issue class -> MITRE ATT&CK (Enterprise v15) techniques and NIST SP 800-53 Rev 5 controls.
COMPLIANCE = {
    "subdomain-takeover": (["T1583.001", "T1584.001"], ["CM-8", "SC-22"]),
    "takeover-unverified": (["T1583.001"], ["CM-8", "SC-22"]),
    "dangling-cname": (["T1584.001"], ["CM-8", "SC-22"]),
    "spf-missing": (["T1656", "T1566.001", "T1566.002"], ["SI-8", "SC-20"]),
    "spf-weak": (["T1656", "T1566"], ["SI-8", "SC-20"]),
    "dmarc-missing": (["T1656", "T1566.001", "T1566.002"], ["SI-8", "SC-20", "SC-23"]),
    "dmarc-weak": (["T1656", "T1566"], ["SI-8", "SC-23"]),
    "dirty-tls-forwarding": (["T1557", "T1040"], ["SC-8", "SC-23"]),
    "redirect-quality": (["T1557"], ["SC-8"]),
    "legacy-tls": (["T1557", "T1040"], ["SC-8", "SC-13"]),
    "tls-health": (["T1557"], ["SC-8", "SC-13"]),
    "cert-invalid": (["T1557"], ["SC-17", "SC-23"]),
    "cert-expired": (["T1557"], ["SC-17"]),
    "cert-expiring": ([], ["SC-17"]),
    "caa-missing": (["T1587.003"], ["SC-17", "SC-12"]),
    "dnssec-off": (["T1584.002"], ["SC-20", "SC-21"]),
    "axfr-open": (["T1590.002"], ["SC-20", "SC-22"]),
    "exposed-service": (["T1133", "T1210", "T1021"], ["SC-7", "CM-7", "AC-17"]),
    "origin-exposed": (["T1590.005", "T1190"], ["SC-7"]),
    "mta-sts": (["T1557", "T1040"], ["SC-8", "SC-23", "SI-8"]),
    "dkim-weak-key": (["T1656", "T1566"], ["SC-12", "SC-13", "SI-8"]),
    "cookie-flags": (["T1539"], ["SC-23", "SC-8"]),
    "cert-weak-crypto": (["T1557"], ["SC-12", "SC-13", "SC-17"]),
    "cert-revoked": (["T1557"], ["SC-17"]),
    "ocsp-stapling": ([], ["SC-17"]),
    "hsts-weak": (["T1557"], ["SC-8", "SC-23"]),
    "admin-exposed": (["T1078", "T1110", "T1190"], ["IA-2", "AC-17", "CM-7"]),
    "spf-chain": (["T1656", "T1583.001"], ["SI-8", "SC-20", "CM-8"]),
    "header-quality": (["T1189", "T1592.002"], ["SC-18", "SC-7"]),
    "cors": (["T1190"], ["AC-4", "SC-7"]),
    "security-txt": ([], ["IR-6"]),
    "scanner-finding": (["T1190"], ["RA-5", "SI-2"]),
}


def _v24_findings(r: dict):
    """Yield findings for clipeus tokens in config_issues."""
    for tok in (t.strip() for t in _s(r.get("config_issues")).split(";")):
        if not tok or tok == "None":
            continue
        base = tok.split("(")[0]
        hit = max((k for k in V24_TOKENS if base == k or (k.endswith("-") and base.startswith(k))),
                  key=len, default=None)
        if hit:
            sev, cls, fix = V24_TOKENS[hit]
            yield (sev, cls, tok, fix)


def _s(v) -> str:
    return "" if v is None else str(v).strip()

def _truthy_no(v) -> bool:
    """clipeus uses 'No'/'None'/'N/A'/'' for absent; anything else is present."""
    return _s(v).lower() not in ("", "no", "none", "n/a", "0", "false", "-")

def _final_target(cname: str) -> str:
    """Last hop of a 'a -> b -> c' CNAME chain string, cleaned to a hostname."""
    t = cname.split("->")[-1].strip() if "->" in cname else cname.strip()
    return t.rstrip(".").split()[0] if t else ""

@lru_cache(maxsize=20000)
def _target_resolves(target: str):
    """(resolves: bool|None, note). None == unknown (no DNS lib). NXDOMAIN => False =
    dangling => genuinely claimable. Any address/CNAME answer => True => live."""
    if not _HAVE_DNS or not target:
        return None, "unverified"
    for rr in ("A", "AAAA", "CNAME"):
        try:
            if _RES.resolve(target, rr):
                return True, "target-resolves-live"
        except _dnsr.NXDOMAIN:
            return False, "target-NXDOMAIN"
        except _dnsr.NoAnswer:
            continue
        except _dnsr.NoNameservers:
            return False, "target-SERVFAIL/no-ns"
        except Exception:
            return None, "resolve-error"
    return False, "target-no-address"

def analyze_record(r: dict):
    """Yield (severity, issue_class, detail, fix) tuples for one host."""
    host = r.get("domain", "?")
    status = _s(r.get("status") or r.get("disposition") or r.get("dns_status"))
    out = []

    # ---- Dangling DNS / subdomain-takeover -------------------------------
    # Real takeover risk (CNAME -> claimable third-party service) is the critical
    # case. "dangling_status=Possibly / Has NS but no A/AAAA/CNAME" is NOT that: it
    # is a registered-but-unconfigured/parked zone with no address records, which is
    # normal in a defensive portfolio — flag it low/info, never critical.
    # clipeus flags takeover_risk='Possibly' for ANY CNAME to a takeover-prone
    # provider, WITHOUT confirming the target is actually claimable — and wildcard DNS
    # (e.g. *.example.com) multiplies one target into hundreds of identical
    # flags. So we VERIFY: resolve the final CNAME target. NXDOMAIN/no-address => the
    # backing resource is gone => genuinely claimable => real takeover. Resolves live
    # => it's just a cloud-hosted name, not a finding.
    tk = _s(r.get("takeover_risk"))
    cname = _s(r.get("cname"))
    if _truthy_no(tk):
        target = _final_target(cname)
        prone = next((p for p in TAKEOVER_PRONE if p in target.lower()), "")
        resolves, note = _target_resolves(target)
        if resolves is False:
            out.append(("critical", "subdomain-takeover",
                        f"dangling CNAME -> {target} [{note}] (provider={prone or 'unknown'})",
                        "Remove the stale CNAME, or reclaim the target label in the same "
                        "cloud region/account before an attacker registers it."))
        elif resolves is None:
            out.append(("medium", "takeover-unverified",
                        f"CNAME -> {target} (takeover-prone; could not verify target)",
                        "Manually confirm the target resource still exists and is owned by you."))
        else:
            out.append(("info", "cloud-cname",
                        f"CNAME -> {target} [{note}]",
                        "No action: target is live/owned (not a dangling takeover)."))
    dang = _s(r.get("dangling_status"))
    dang_detail = _s(r.get("dangling_detail"))
    if _truthy_no(dang) and not _truthy_no(tk):
        # dangling flag without a takeover-prone CNAME already handled above
        if _truthy_no(cname):
            target = _final_target(cname)
            resolves, note = _target_resolves(target)
            if resolves is False:
                out.append(("high", "dangling-cname",
                            f"CNAME -> {target} does not resolve [{note}]",
                            "Remove the stale CNAME or repoint it to a live, owned target."))
            # if the CNAME target resolves, it's not dangling -> no finding
        else:
            # NS delegated but apex publishes no A/AAAA/CNAME -> unconfigured/parked zone.
            out.append(("low", "unconfigured-zone",
                        f"{dang}: {dang_detail or 'NS present, no address records'}",
                        "Cosmetic for a defensive registration; if unused, park on a controlled sinkhole/hold DNS."))

    # ---- SPF -------------------------------------------------------------
    spf_iss = _s(r.get("spf_issues"))
    if "spf_missing" in spf_iss or _s(r.get("spf")).lower() in ("none", "", "n/a"):
        # Only meaningful if the domain can send/receive mail or exists at all.
        out.append(("medium", "spf-missing",
                    f"spf={_s(r.get('spf')) or 'None'}",
                    "Publish an SPF TXT record; if the domain never sends mail use 'v=spf1 -all'."))
    elif spf_iss:
        sev = "medium" if ("too_permissive" in spf_iss or "+all" in spf_iss or "lookup_limit_exceeded" in spf_iss) else "low"
        out.append((sev, "spf-weak", spf_iss,
                    "Tighten SPF: end with -all, keep <10 DNS lookups, drop +all/ptr."))

    # ---- DMARC -----------------------------------------------------------
    dm_iss = _s(r.get("dmarc_issues"))
    if "dmarc_missing" in dm_iss or _s(r.get("dmarc")).lower() in ("none", "", "n/a"):
        out.append(("medium", "dmarc-missing",
                    f"dmarc={_s(r.get('dmarc')) or 'None'}",
                    "Publish _dmarc TXT; start 'v=DMARC1; p=none; rua=...' then move to p=reject."))
    elif dm_iss:
        sev = "low" if "policy_none" in dm_iss else "medium"
        out.append((sev, "dmarc-weak", dm_iss,
                    "Move DMARC policy toward p=quarantine/reject; add rua reporting."))

    # ---- Dirty TLS forwarding -------------------------------------------
    if _truthy_no(r.get("dirty_forwarding")):
        out.append(("high", "dirty-tls-forwarding",
                    f"{_s(r.get('dirty_forwarding'))} final={_s(r.get('final_url'))}",
                    "Serve a valid cert for this name and 301 to HTTPS; never downgrade HTTPS->HTTP mid-redirect."))
    rq = _s(r.get("redirect_quality"))
    if rq and rq.lower() not in ("ok", "good", "clean", "approved", "n/a", ""):
        out.append(("low", "redirect-quality", f"{rq} -> {_s(r.get('final_url'))}",
                    "Review redirect target/chain; keep it on-brand and HTTPS end-to-end."))

    # ---- TLS version / health -------------------------------------------
    tmin = _s(r.get("tls_min")); tmax = _s(r.get("tls_max"))
    def _legacy(v):  # TLS 1.0/1.1/SSLv3
        v = v.lower().replace("tls", "").replace("v", "").strip()
        return v in ("1.0", "1", "1.1", "1_0", "1_1") or "sslv3" in v or "ssl3" in v
    if tmin and _legacy(tmin):
        out.append(("medium", "legacy-tls",
                    f"min={tmin} max={tmax} cipher={_s(r.get('tls_cipher'))}",
                    "Disable TLS 1.0/1.1; require TLS 1.2+ (prefer 1.3)."))
    th = _s(r.get("tls_health"))
    if th and th.lower() not in ("ok", "good", "healthy", "n/a", ""):
        out.append(("low", "tls-health", th, "Review TLS configuration (cipher/protocol/chain)."))

    # ---- Cert validity / hostname / expiry ------------------------------
    tv = _s(r.get("tls_valid"))
    if tv and tv.lower() not in ("yes", "valid", "ok", "true", "n/a", ""):
        sev = "medium" if "expired" in tv.lower() else "low"
        out.append((sev, "cert-invalid", tv,
                    "Install a cert whose SAN matches this hostname and is unexpired."))
    dleft = r.get("cert_days_left")
    try:
        d = int(dleft)
        if d < 0:
            out.append(("high", "cert-expired", f"{d}d ago ({_s(r.get('cert_expiry'))})",
                        "Renew/replace the expired certificate."))
        elif d <= 21:
            out.append(("medium", "cert-expiring", f"{d}d left ({_s(r.get('cert_expiry'))})",
                        "Renew now; automate renewal (ACME) to avoid lapse."))
    except (TypeError, ValueError):
        pass

    # ---- CAA / DNSSEC / AXFR --------------------------------------------
    cfg = _s(r.get("config_issues"))
    caa = r.get("caa_records")
    if ("caa" in cfg.lower() and "miss" in cfg.lower()) or (isinstance(caa, (list, str)) and not _truthy_no(caa) and _truthy_no(r.get("tls_valid"))):
        out.append(("low", "caa-missing", "no CAA record",
                    "Add a CAA record pinning your CA(s) to limit mis-issuance."))
    if _s(r.get("dnssec")).lower() in ("no", "off", "false", "unsigned") and _truthy_no(status):
        out.append(("info", "dnssec-off", "unsigned zone",
                    "Enable DNSSEC at the registrar/DNS host."))
    if _truthy_no(r.get("axfr_vuln")):
        out.append(("high", "axfr-open", _s(r.get("axfr_vuln")),
                    "Restrict AXFR zone transfers to authorized secondaries only."))

    out.extend(_v24_findings(r))
    return host, status, out

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--audit", nargs="+", required=True)
    ap.add_argument("--out", default="out/analysis")
    args = ap.parse_args()
    os.makedirs(args.out, exist_ok=True)

    rows = []
    class_counts = Counter()
    attack_counts = Counter()
    nist_counts = Counter()
    sev_counts = Counter()
    offenders = defaultdict(list)
    n_hosts = 0
    statuses = Counter()

    for path in args.audit:
        for line in open(path, encoding="utf-8"):
            line = line.strip()
            if not line:
                continue
            try:
                r = json.loads(line)
            except json.JSONDecodeError:
                continue
            n_hosts += 1
            host, status, issues = analyze_record(r)
            statuses[status or "unknown"] += 1
            for sev, cls, detail, fix in issues:
                attack, nist = COMPLIANCE.get(cls, ([], []))
                rows.append({"host": host, "status": status, "severity": sev,
                             "issue": cls, "detail": detail, "fix": fix,
                             "attack": ";".join(attack), "nist": ";".join(nist),
                             "risk_score": r.get("risk_score", "")})
                for t in attack:
                    attack_counts[t] += 1
                for c in nist:
                    nist_counts[c] += 1
                class_counts[cls] += 1
                sev_counts[sev] += 1
                offenders[cls].append(host)

    rows.sort(key=lambda x: (SEV_ORDER.get(x["severity"], 9), x["issue"], x["host"]))
    csv_path = os.path.join(args.out, "posture-findings.csv")
    with open(csv_path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["severity", "issue", "host", "status",
                                          "detail", "fix", "attack", "nist", "risk_score"])
        w.writeheader()
        for row in rows:
            w.writerow({k: row[k] for k in w.fieldnames})

    summary = {
        "hosts_analyzed": n_hosts,
        "findings_total": len(rows),
        "by_severity": dict(sev_counts),
        "by_issue": dict(class_counts.most_common()),
        "by_status": dict(statuses.most_common()),
        "by_attack": dict(attack_counts.most_common()),
        "by_nist": dict(nist_counts.most_common()),
        "top_offenders": {c: sorted(set(h))[:25] for c, h in offenders.items()},
    }
    json.dump(summary, open(os.path.join(args.out, "posture-summary.json"), "w"), indent=2)

    print(f"hosts analyzed : {n_hosts}")
    print(f"findings       : {len(rows)}")
    print("by severity    :", dict(sev_counts))
    print("by issue class :")
    for c, n in class_counts.most_common():
        print(f"   {n:5}  {c}")
    print("host status mix:", dict(statuses.most_common()))
    print("ATT&CK         :", dict(attack_counts.most_common(8)))
    print("NIST 800-53    :", dict(nist_counts.most_common(8)))
    print(f"\nwrote {csv_path}")
    return 0

if __name__ == "__main__":
    sys.exit(main())
