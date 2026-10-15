"""Optional brand / engagement configuration, kept out of the code so the tools stay neutral.

Looked up in this order (first hit wins):
  1. the path passed explicitly (--config FILE)
  2. $CLIPEUS_CONFIG
  3. brand.json next to this file
  4. ~/.config/clipeus/brand.json
With no file the defaults below apply (policy checks that need a list are simply skipped).

Schema (all keys optional; see brand.example.json):
  approved_mx        list of domains whose MX hosts count as "approved" mail routing
  approved_redirect  list of registrable domains that redirects are expected to land on
  brand_keywords     extra keywords for classify.py's banking/finance bucket
  nsec3.zone         default zone for recon/nsec3-enum.py
  nsec3.known        extra seed labels for nsec3-enum.py
  resolvers          list of resolver IPs to use instead of the built-in default
                     (use unfiltered public resolvers; see README "DNS integrity")
  org_networks       list of CIDRs owned by the organisation; hosts resolving into them
                     are tagged first-party (org_range=Yes). Overridden by --org-networks.
"""
from __future__ import annotations

import json
import os
from typing import Any, Dict, List, Optional, Tuple

HERE = os.path.dirname(os.path.realpath(__file__))

# Unfiltered, non-rewriting resolvers. Every Clipeus tool resolves through
# effective_resolvers() so DNS behaviour is one configuration item everywhere.
DEFAULT_RESOLVERS = ["1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4"]
DEFAULTS: Dict[str, Any] = {"approved_mx": [], "approved_redirect": [], "brand_keywords": [],
                            "resolvers": [], "org_networks": [], "nsec3": {"zone": "", "known": []}}


def candidate_paths(explicit: Optional[str] = None) -> List[str]:
    if explicit:
        return [explicit]
    paths = []
    if os.environ.get("CLIPEUS_CONFIG"):
        paths.append(os.environ["CLIPEUS_CONFIG"])
    paths += [os.path.join(HERE, "brand.json"),
              os.path.expanduser("~/.config/clipeus/brand.json")]
    return paths


def _str_list(value: Any, key: str) -> List[str]:
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise ValueError(f"'{key}' must be a list of strings")
    return [v.strip().lower() for v in value if v.strip()]


def _ip_list(value: Any, key: str) -> List[str]:
    """Like _str_list but each entry must parse as an IPv4/IPv6 address (resolver IPs)."""
    import ipaddress
    out = []
    for v in _str_list(value, key):
        try:
            ipaddress.ip_address(v)
        except ValueError:
            raise ValueError(f"'{key}' entry {v!r} is not a valid IP address")
        out.append(v)
    return out


def _cidr_list(value: Any, key: str) -> List[str]:
    """Each entry must parse as an IPv4/IPv6 network (host bits allowed)."""
    import ipaddress
    out = []
    for v in _str_list(value, key):
        try:
            ipaddress.ip_network(v, strict=False)
        except ValueError:
            raise ValueError(f"'{key}' entry {v!r} is not a valid CIDR")
        out.append(v)
    return out


def load(explicit: Optional[str] = None) -> Tuple[Dict[str, Any], Optional[str]]:
    """Return (config, path_used). An explicit path that cannot be read is an error;
    missing implicit files just yield the defaults."""
    cfg: Dict[str, Any] = json.loads(json.dumps(DEFAULTS))
    for path in candidate_paths(explicit):
        if not os.path.isfile(path):
            if explicit:
                raise ValueError(f"{path}: no such file")
            continue
        try:
            with open(path, encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, ValueError) as exc:
            raise ValueError(f"{path}: {exc}")
        if not isinstance(data, dict):
            raise ValueError(f"{path}: top level must be an object")
        for key in ("approved_mx", "approved_redirect", "brand_keywords"):
            if key in data:
                cfg[key] = _str_list(data[key], key)
        if "resolvers" in data:
            cfg["resolvers"] = _ip_list(data["resolvers"], "resolvers")
        if "org_networks" in data:
            cfg["org_networks"] = _cidr_list(data["org_networks"], "org_networks")
        nsec3 = data.get("nsec3", {})
        if not isinstance(nsec3, dict):
            raise ValueError("'nsec3' must be an object")
        if "zone" in nsec3:
            if not isinstance(nsec3["zone"], str):
                raise ValueError("'nsec3.zone' must be a string")
            cfg["nsec3"]["zone"] = nsec3["zone"].strip().strip(".").lower()
        if "known" in nsec3:
            cfg["nsec3"]["known"] = _str_list(nsec3["known"], "nsec3.known")
        return cfg, path
    return cfg, None


def _read_ip_file(path: str) -> List[str]:
    """Resolver file: one IP per line, '#' comments allowed. Bad lines are an error."""
    import ipaddress
    if not os.path.isfile(path):
        raise ValueError(f"{path}: no such file")
    ips, bad = [], []
    with open(path, encoding="utf-8") as fh:
        for n, line in enumerate(fh, 1):
            line = line.split("#", 1)[0].strip()
            if not line:
                continue
            try:
                ips.append(str(ipaddress.ip_address(line)))
            except ValueError:
                bad.append(f"line {n}: {line!r}")
    if bad:
        raise ValueError(f"{path}: not IP addresses: " + ", ".join(bad))
    if not ips:
        raise ValueError(f"{path}: no resolver IPs")
    return ips


def _tuning_dns_servers() -> List[str]:
    """dns_servers from the tuning file (same lookup as clipeus.py), if valid."""
    import ipaddress
    cand = [os.environ.get("CLIPEUS_TUNING", ""), os.path.join(HERE, "clipeus.tuning.json"),
            os.path.expanduser("~/.config/clipeus/tuning.json")]
    for p in cand:
        if p and os.path.isfile(p):
            try:
                with open(p, encoding="utf-8") as fh:
                    ds = json.load(fh).get("dns_servers")
                return [str(ipaddress.ip_address(x)) for x in ds] if isinstance(ds, list) else []
            except (OSError, ValueError, AttributeError, TypeError):
                return []
    return []


def effective_resolvers(resolvers_file: Optional[str] = None,
                        cfg: Optional[Dict[str, Any]] = None) -> Tuple[List[str], str]:
    """The resolvers every tool should use, and where they came from. Precedence:
    resolvers file (--resolvers / $CLIPEUS_RESOLVERS) > brand.json "resolvers" >
    tuning "dns_servers" > DEFAULT_RESOLVERS. `cfg=None` loads brand.json implicitly."""
    path = resolvers_file or os.environ.get("CLIPEUS_RESOLVERS")
    if path:
        return _read_ip_file(path), path
    if cfg is None:
        cfg = load()[0]
    if cfg.get("resolvers"):
        return list(cfg["resolvers"]), "config"
    tuned = _tuning_dns_servers()
    if tuned:
        return tuned, "tuning"
    return list(DEFAULT_RESOLVERS), "default"


def resolvers_or_exit(resolvers_file: Optional[str] = None,
                      cfg: Optional[Dict[str, Any]] = None) -> List[str]:
    """effective_resolvers() for scripts: a bad resolver/config file exits cleanly."""
    try:
        return effective_resolvers(resolvers_file, cfg)[0]
    except ValueError as exc:
        raise SystemExit(f"error: resolvers {exc}")


if __name__ == "__main__":
    # Shell tools use this to get the same resolvers as the Python tools:
    #   python3 brand_config.py --resolvers [FILE]   -> one IP per line
    import sys
    if len(sys.argv) >= 2 and sys.argv[1] == "--resolvers":
        try:
            ips, src = effective_resolvers(sys.argv[2] if len(sys.argv) > 2 else None)
        except ValueError as exc:
            sys.exit(f"error: resolvers {exc}")
        print(f"[*] resolvers from {src}", file=sys.stderr)
        print("\n".join(ips))
    else:
        sys.exit("usage: brand_config.py --resolvers [FILE]")
