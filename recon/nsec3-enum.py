#!/usr/bin/env python3
"""
nsec3-enum.py — pure-Python NSEC3 zone-walk + wordlist crack (no C deps).

Enumerate the members of a DNSSEC-signed zone that refuses AXFR and hides its
member list — e.g. a brand gTLD like `.brand`. Works when NSEC3 opt-out is OFF
(NSEC3PARAM flags=0 => every name is covered) and iteration count is low.

Method:
  1. Query the zone's authoritative NS directly for random non-existent names with
     the DO bit set; the NXDOMAIN proof carries NSEC3 records. Harvest every
     (owner-hash -> next-hash) pair until the hash chain saturates.
  2. Crack: hash each candidate (a built-in CT-known set + an optional wordlist)
     with dnspython's nsec3_hash(salt,iterations,algo) and match against the
     harvested owner-hashes -> recover the plaintext member label.

Only needs dnspython. Cloudflare-first for the NS lookup. No OpenSSL/C build
(unlike n3map). For NSEC (not NSEC3) zones use `ldns-walk` instead.

Usage:  nsec3-enum.py <zone> [wordlist] [--max-probes N]
"""
import sys, os, random, string, base64, time
import dns.resolver, dns.message, dns.query, dns.name, dns.rdatatype, dns.dnssec, dns.flags

sys.path.insert(0, os.path.join(os.path.dirname(os.path.realpath(__file__)), ".."))
import brand_config  # noqa: E402  (zone / seed labels live in brand.json, not in this script)
_CFG, _ = brand_config.load()

ZONE = sys.argv[1].rstrip(".").lower() if len(sys.argv) > 1 else _CFG["nsec3"]["zone"]
if not ZONE:
    sys.exit("usage: nsec3-enum.py <zone> [wordlist] [--max-probes N]   (or set nsec3.zone in brand.json)")
WORDLIST = next((a for a in sys.argv[2:] if not a.startswith("--")), None)
MAX_PROBES = 6000
for i, a in enumerate(sys.argv):
    if a == "--max-probes" and i + 1 < len(sys.argv):
        MAX_PROBES = int(sys.argv[i + 1])

# CT-known second-levels for the target zone (seed candidates); extend freely.
KNOWN = ["www", "mail", "mx", "ns", "ns1", "ns2", "portal", "login", "vpn", "remote", "cloud",
         "api", "app", "web", "test", "dev", "staging", "prod", "group", "internal"]
KNOWN += [k for k in _CFG["nsec3"]["known"] if k not in KNOWN]   # engagement-specific seeds

_R = dns.resolver.Resolver()
_R.nameservers = brand_config.resolvers_or_exit(cfg=_CFG)
_R.timeout = _R.lifetime = 5.0


def ns_ips(zone):
    ips = []
    for ns in _R.resolve(zone, "NS"):
        try:
            ips += [str(a) for a in _R.resolve(str(ns.target), "A")]
        except Exception:
            pass
    return ips


def nsec3_params(zone, nsip):
    q = dns.message.make_query(zone, "NSEC3PARAM", want_dnssec=True)
    r = dns.query.udp(q, nsip, timeout=5)
    for rr in r.answer:
        if rr.rdtype == dns.rdatatype.NSEC3PARAM:
            p = rr[0]
            salt = "" if p.salt in (b"", b"-", None) else p.salt.hex()
            return p.algorithm, p.flags, p.iterations, salt
    raise SystemExit(f"[!] {zone} has no NSEC3PARAM (not NSEC3-signed?)")


def _covered(h, chain):
    """Is hash h inside a known NSEC3 interval (owner, next) — i.e. already proven
    nonexistent, so not worth another query? Handles the ring wrap."""
    for o, n in chain.items():
        if o < n:
            if o < h < n:
                return True
        else:  # wrap-around interval (largest hash -> smallest)
            if h > o or h < n:
                return True
    return h in chain            # h is itself a known owner


def harvest(zone, nsip, algo, iters, salt):
    """Coverage-guided walk: hash each random candidate FIRST and only spend a
    query when its hash falls in an as-yet-uncovered gap. This follows the whole
    NSEC3 ring efficiently instead of hammering the one big gap. Saturates (and
    stops) once the ring is closed and fresh candidates are all pre-covered."""
    chain = {}                   # owner-hash -> next-hash
    optout = None                # true opt-out flag, read from an actual NSEC3 RR
    probes = 0
    stale = 0                    # consecutive candidates already covered
    while probes < MAX_PROBES and stale < 1500:
        label = "".join(random.choice(string.ascii_lowercase + string.digits)
                        for _ in range(random.randint(6, 14)))
        fqdn = f"{label}.{zone}"
        try:
            h = dns.dnssec.nsec3_hash(fqdn, salt or None, iters, algo)
        except Exception:
            continue
        if _covered(h, chain):
            stale += 1
            continue
        stale = 0
        probes += 1
        try:
            q = dns.message.make_query(fqdn, "A", want_dnssec=True)
            r = dns.query.udp(q, nsip, timeout=5)
        except Exception:
            continue
        for rr in r.authority:
            if rr.rdtype != dns.rdatatype.NSEC3:
                continue
            if optout is None:
                optout = bool(rr[0].flags & 0x01)   # real opt-out, from the RR
            owner = rr.name.labels[0].decode().upper()
            nxt = base64.b32encode(rr[0].next).decode().translate(_B32HEX).upper()
            chain[owner] = nxt
        if probes % 25 == 0:
            print(f"    ...{probes} targeted queries, {len(chain)} NSEC3 records",
                  file=sys.stderr)
    return set(chain), chain, probes, optout



# base32 -> base32hex translation (RFC4648 alphabet -> extended-hex used by NSEC3)
_B32HEX = str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567",
                        "0123456789ABCDEFGHIJKLMNOPQRSTUV")


def crack(owners, zone, algo, iters, salt, wordlist):
    cands = list(dict.fromkeys(KNOWN))
    if wordlist and os.path.exists(wordlist):
        with open(wordlist, encoding="utf-8", errors="ignore") as f:
            cands += [ln.strip() for ln in f if ln.strip() and not ln.startswith("#")]
    hit = {}
    for w in cands:
        fqdn = zone if w in ("", "@", zone) else f"{w}.{zone}"
        try:
            h = dns.dnssec.nsec3_hash(fqdn, salt or None, iters, algo)
        except Exception:
            continue
        if h in owners and fqdn not in hit.values():
            hit[h] = fqdn
    return hit


def main():
    print(f"[*] NSEC3-walking {ZONE}")
    ips = ns_ips(ZONE)
    if not ips:
        raise SystemExit(f"[!] no NS IPs for {ZONE}")
    nsip = ips[0]
    algo, flags, iters, salt = nsec3_params(ZONE, nsip)
    # NB: NSEC3PARAM.flags is ALWAYS 0 per RFC 5155 — the real opt-out flag lives
    # on the NSEC3 RRs themselves, captured during the walk below.
    print(f"[*] NSEC3PARAM: alg={algo} iterations={iters} salt={salt or '-'}  via NS {nsip}")
    owners, chain, probes, optout = harvest(ZONE, nsip, algo, iters, salt)
    print(f"[*] real opt-out (from NSEC3 RRs): "
          f"{'ON — insecure delegations NOT covered; NOT walkable' if optout else 'OFF — every name covered; fully walkable'}")
    print(f"[=] harvested {len(owners)} distinct NSEC3 owner-hashes in {probes} probes")
    hit = crack(owners, ZONE, algo, iters, salt, WORDLIST)
    print(f"[=] cracked {len(hit)}/{len(owners)} to plaintext:")
    for h in sorted(hit):
        print("      ", hit[h])
    uncracked = sorted(owners - set(hit))
    print(f"[=] {len(uncracked)} owner-hashes NOT cracked (need a bigger wordlist):")
    for h in uncracked[:40]:
        print("      ", h)
    # write recovered member FQDNs for the next stage (resolve + dangle-check)
    out = f"{ZONE}-members.txt"
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w") as f:
        f.write("\n".join(sorted(set(hit.values()))) + "\n")
    print(f"[=] recovered member names -> {out}")


if __name__ == "__main__":
    main()
