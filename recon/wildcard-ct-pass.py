#!/usr/bin/env python3
"""
wildcard-ct-pass.py — careful, CT-led subdomain resolution for a WILDCARD apex.

For a domain whose zone answers *every* label (e.g. *.example.com), naive
enumeration spirals: any guessed name "resolves", inflating phantom hosts and
duplicate takeover findings (a single wildcard apex can turn into hundreds of
phantom subdomains and false takeover candidates).

Approach:
  1. Take subdomain names ONLY from Certificate Transparency (CertSpotter) — names
     that were actually issued a certificate, i.e. real provisioning, not guesses.
  2. Establish the WILDCARD BASELINE: resolve several random non-existent labels;
     record the answer set (A records and/or CNAME target) the wildcard sinks to.
  3. Resolve each CT name once, slowly, via Cloudflare. Classify:
       - answer == wildcard baseline  -> 'wildcard-echo' (real name, but just the
         wildcard sink; NOT a distinct host — collapse these, don't report N copies)
       - answer != wildcard baseline  -> 'distinct' (genuinely provisioned host,
         worth attention) — the first of these is the signal the spiral has hit
         something real
       - CNAME target NXDOMAIN         -> 'dangling' (a real takeover finding)

Cloudflare-first resolver (unfiltered), Google/Quad9 fallback. Deliberately serial
with a polite delay — accuracy over speed.
"""
import json, os, sys, time, random, string
import urllib.request
import dns.resolver, dns.exception
import os as _os, sys as _sys
_sys.path.insert(0, _os.path.join(_os.path.dirname(_os.path.realpath(__file__)), ".."))
import brand_config  # noqa: E402  (shared DNS config: one resolver setting for every tool)

APEX = sys.argv[1] if len(sys.argv) > 1 else "example.com"
OUT  = sys.argv[2] if len(sys.argv) > 2 else f"wildcard-{APEX}.json"
DELAY = 0.7  # seconds between DNS lookups — slow and careful

R = dns.resolver.Resolver()
R.nameservers = brand_config.resolvers_or_exit()
R.timeout = R.lifetime = 5.0


def _answer(name):
    """Return (kind, sorted_values) for a name: CNAME chain end or A set, or a
    marker. Used both for the wildcard baseline and per-name classification."""
    # CNAME first (chain), then A.
    try:
        c = R.resolve(name, "CNAME")
        target = str(c[0].target).rstrip(".").lower()
        # does the CNAME target itself resolve?
        try:
            R.resolve(target, "A")
            return ("cname", (target,))
        except dns.resolver.NXDOMAIN:
            return ("cname-nxdomain", (target,))
        except Exception:
            return ("cname", (target,))
    except dns.resolver.NXDOMAIN:
        return ("nxdomain", ())
    except (dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout, Exception):
        pass
    try:
        a = R.resolve(name, "A")
        return ("a", tuple(sorted(str(x) for x in a)))
    except dns.resolver.NXDOMAIN:
        return ("nxdomain", ())
    except Exception:
        return ("noanswer", ())


def certspotter_names(apex):
    tok = ""
    for p in ("~/.config/certspotter/token", "~/.certspotter_token"):
        p = os.path.expanduser(p)
        if os.path.exists(p):
            tok = open(p).read().strip(); break
    url = ("https://api.certspotter.com/v1/issuances?domain=" + apex +
           "&include_subdomains=true&expand=dns_names&match_wildcards=false")
    req = urllib.request.Request(url)
    if tok:
        req.add_header("Authorization", "Bearer " + tok)
    names = set()
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            data = json.load(r)
        for iss in data:
            for dn in iss.get("dns_names", []):
                dn = dn.lstrip("*.").rstrip(".").lower()
                if dn == apex or dn.endswith("." + apex):
                    names.add(dn)
    except Exception as e:
        print(f"[!] CertSpotter fetch failed: {e}", file=sys.stderr)
    return sorted(names)


def main():
    print(f"[*] wildcard CT pass for {APEX} (Cloudflare-first, serial, delay={DELAY}s)")
    # 1. wildcard baseline
    baselines = set()
    for _ in range(4):
        rand = "".join(random.choice(string.ascii_lowercase) for _ in range(16))
        k, v = _answer(f"{rand}.{APEX}")
        if k in ("a", "cname"):
            baselines.add((k, v))
        time.sleep(DELAY)
    wildcard = bool(baselines)
    print(f"[*] wildcard baseline: {'WILDCARD' if wildcard else 'no wildcard'} -> {sorted(baselines)}")

    # 2. CT names
    ct = certspotter_names(APEX)
    print(f"[*] CertSpotter returned {len(ct)} distinct CT names under {APEX}")

    # 3. resolve each, classify against baseline
    rows, distinct, echo, dangling, dead = [], [], [], [], []
    for name in ct:
        k, v = _answer(name)
        if k == "cname-nxdomain":
            cls = "dangling"; dangling.append(name)
        elif k == "nxdomain":
            cls = "nxdomain"; dead.append(name)
        elif k in ("a", "cname") and (k, v) in baselines:
            cls = "wildcard-echo"; echo.append(name)
        elif k in ("a", "cname"):
            cls = "distinct"; distinct.append(name)
        else:
            cls = "noanswer"; dead.append(name)
        rows.append({"name": name, "kind": k, "value": list(v), "class": cls})
        print(f"    {cls:14s} {name} -> {k}:{','.join(v) if v else '-'}")
        time.sleep(DELAY)

    result = {
        "apex": APEX, "wildcard": wildcard,
        "baseline": [list(b[1]) for b in sorted(baselines)],
        "ct_count": len(ct),
        "distinct": distinct, "wildcard_echo": echo,
        "dangling": dangling, "dead": dead,
        "rows": rows,
    }
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w") as f:
        json.dump(result, f, indent=2)
    print(f"\n[=] {APEX}: {len(ct)} CT names | distinct={len(distinct)} "
          f"wildcard-echo={len(echo)} dangling={len(dangling)} dead={len(dead)}")
    print(f"[=] written {OUT}")
    if distinct:
        print("[=] DISTINCT (genuinely provisioned, worth attention):")
        for n in distinct:
            print("      -", n)
    if dangling:
        print("[!] DANGLING (CNAME target NXDOMAIN — real takeover candidate):")
        for n in dangling:
            print("      -", n)


if __name__ == "__main__":
    main()
