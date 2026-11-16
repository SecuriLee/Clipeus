#!/usr/bin/env python3
"""dns-exists.py — keep the names that exist in DNS, drop the ones that do not.

Certificate-transparency enumeration returns every name ever put on a certificate;
most old ones no longer exist. Auditing them costs time and finds nothing. But a
plain "does it resolve" filter (A/AAAA) would also drop the most important names:
a dangling CNAME answers NXDOMAIN for its address, because the chain ends at a
target that is gone, while the CNAME record itself is still in the zone.

A name is KEPT when any of these holds:
  * it has an address (A/AAAA)                     live
  * a CNAME is published for it, target or not     dangling CNAME candidate
  * it is delegated (NS), working or not           dangling delegation candidate
  * the answer is not clean (SERVFAIL, timeout)    lame delegation / unknown
It is DROPPED only on a clean NXDOMAIN with no CNAME in the answer, or a clean
NOERROR with no address, CNAME or NS (e.g. a TXT-only name), unless --keep-empty.

Resolvers come from the shared Clipeus lookup (brand_config), never a filtering one.

Usage:
  dns-exists.py --input names.txt --output kept.txt [--dropped dropped.txt] [--workers 50]
"""
from __future__ import annotations

import argparse
import os
import sys
from concurrent.futures import ThreadPoolExecutor

sys.path.insert(0, os.path.join(os.path.dirname(os.path.realpath(__file__)), ".."))
import brand_config  # noqa: E402

import dns.exception    # noqa: E402
import dns.rdatatype    # noqa: E402
import dns.resolver     # noqa: E402

R = dns.resolver.Resolver(configure=False)
R.nameservers = brand_config.resolvers_or_exit()
R.timeout, R.lifetime = 3.0, 8.0


def classify(name: str, keep_empty: bool = False) -> str:
    """'address' / 'cname' / 'ns' / 'unclear' / 'empty' (kept) or 'nxdomain' / 'empty' (dropped)."""
    unclear = False
    for rtype in ("A", "AAAA"):
        try:
            ans = R.resolve(name, rtype, raise_on_no_answer=False)
            if any(rr.rdtype == dns.rdatatype.CNAME for rr in ans.response.answer):
                return "cname"
            if ans.rrset is not None:
                return "address"
        except dns.resolver.NXDOMAIN as e:
            # A dangling CNAME: NXDOMAIN for the address, CNAME chain in the answer.
            for resp in e.responses().values():
                if any(rr.rdtype == dns.rdatatype.CNAME for rr in resp.answer):
                    return "cname"
            return "nxdomain" if not unclear else "unclear"
        except (dns.resolver.NoNameservers, dns.exception.Timeout):
            unclear = True
        except Exception:
            unclear = True
    try:
        R.resolve(name, "CNAME")
        return "cname"
    except dns.resolver.NXDOMAIN:
        return "unclear" if unclear else "nxdomain"
    except dns.resolver.NoAnswer:
        pass
    except Exception:
        unclear = True
    try:
        R.resolve(name, "NS")
        return "ns"
    except dns.resolver.NoAnswer:
        pass
    except dns.resolver.NXDOMAIN:
        return "unclear" if unclear else "nxdomain"
    except Exception:
        unclear = True
    if unclear:
        return "unclear"
    return "empty-kept" if keep_empty else "empty"


KEEP = {"address", "cname", "ns", "unclear", "empty-kept"}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--input", required=True)
    ap.add_argument("--output", required=True)
    ap.add_argument("--dropped", help="also write the dropped names (with their reason) here")
    ap.add_argument("--workers", type=int, default=50)
    ap.add_argument("--keep-empty", action="store_true",
                    help="keep names that exist without address/CNAME/NS (e.g. TXT-only)")
    a = ap.parse_args()
    names = sorted({ln.strip().lower().rstrip(".") for ln in open(a.input, encoding="utf-8")
                    if ln.strip() and not ln.startswith("#")})
    with ThreadPoolExecutor(max_workers=a.workers) as ex:
        res = list(ex.map(lambda n: (n, classify(n, a.keep_empty)), names))
    kept = [n for n, c in res if c in KEEP]
    with open(a.output, "w", encoding="utf-8") as fh:
        fh.write("\n".join(kept) + ("\n" if kept else ""))
    if a.dropped:
        with open(a.dropped, "w", encoding="utf-8") as fh:
            fh.writelines(f"{n}\t{c}\n" for n, c in res if c not in KEEP)
    counts: dict = {}
    for _, c in res:
        counts[c] = counts.get(c, 0) + 1
    print(f"[dns-exists] {len(names)} names: kept {len(kept)}, dropped {len(names) - len(kept)} "
          f"({', '.join(f'{k}={v}' for k, v in sorted(counts.items()))})", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
