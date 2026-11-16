#!/usr/bin/env python3
"""crtsh_db.py — certificate-transparency names from crt.sh's public PostgreSQL replica.

crt.sh's web JSON endpoint rate-limits (HTTP 429) and silently truncates large
results: a domain with thousands of logged certificates can come back with a
handful of names. The same data is served read-only over PostgreSQL
(host crt.sh, port 5432, user guest, database certwatch), which answers large
queries in full. This module queries it with psycopg (3), psycopg2, or the
`psql` client, whichever is available; no extra dependency is required when
`psql` is installed.

It is a shared public service: keep one connection at a time per host, batch domains and let
failures surface. A query that fails raises CrtshDbError; callers must record
the domain as a coverage gap, never as "no subdomains".

CLI (used by recon/enum-bulk.sh):
    crtsh_db.py [--batch=N] example.com [more.example ...]   # names on stdout, one per line
    exit 0 when every query succeeded, 3 when any failed (failed domains on stderr)
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import time
from typing import Dict, Iterable, List, Set

HOST = os.environ.get("CRTSH_DB_HOST", "crt.sh")
PORT = int(os.environ.get("CRTSH_DB_PORT", "5432"))
USER, DBNAME = "guest", "certwatch"
STATEMENT_TIMEOUT_S = 240

# Full-text match on the certificate's identities narrows the search through the
# index. Several domains are OR-ed into one query (tsquery ||): the server's cost is
# mostly per query, so a batch of 20 costs about what two single queries do. Names
# are assigned back to their domain by suffix afterwards.
def _sql(n: int) -> str:
    terms = " || ".join(f"plainto_tsquery('certwatch', %(q{i})s)" for i in range(n))
    return ("SELECT DISTINCT lower(ci.name_value) FROM certificate_and_identities ci "
            f"WHERE ({terms}) @@ identities(ci.certificate)")


class CrtshDbError(RuntimeError):
    pass


def _clean_all(names: Iterable[str]) -> Set[str]:
    out: Set[str] = set()
    for n in names:
        n = (n or "").strip().lower().rstrip(".")
        while n.startswith("*."):
            n = n[2:]
        if n and " " not in n and "@" not in n and "." in n:
            out.add(n)
    return out


def _via_driver(domains: List[str], timeout: int) -> List[str]:
    params = {f"q{i}": d for i, d in enumerate(domains)}
    sql = _sql(len(domains))
    try:
        import psycopg  # type: ignore
        with psycopg.connect(host=HOST, port=PORT, user=USER, dbname=DBNAME,
                             connect_timeout=timeout, autocommit=True) as conn:
            conn.execute(f"SET statement_timeout = {STATEMENT_TIMEOUT_S * 1000}")
            return [r[0] for r in conn.execute(sql, params).fetchall()]
    except ImportError:
        pass
    import psycopg2  # type: ignore  (ImportError propagates to the caller)
    conn = psycopg2.connect(host=HOST, port=PORT, user=USER, dbname=DBNAME, connect_timeout=timeout)
    try:
        conn.autocommit = True
        with conn.cursor() as cur:
            cur.execute(f"SET statement_timeout = {STATEMENT_TIMEOUT_S * 1000}")
            cur.execute(sql, params)
            return [r[0] for r in cur.fetchall()]
    finally:
        conn.close()


def _via_psql(domains: List[str], timeout: int) -> List[str]:
    psql = shutil.which("psql")
    if not psql:
        raise CrtshDbError("no PostgreSQL client: install psycopg/psycopg2 or psql")
    # psql has no bind parameters on the command line; domains are validated by
    # the caller (hostname characters only), and quotes are doubled regardless.
    sql = _sql(len(domains))
    for i, d in enumerate(domains):
        sql = sql.replace(f"%(q{i})s", "'" + d.replace("'", "''") + "'")
    env = dict(os.environ, PGCONNECT_TIMEOUT=str(timeout),
               PGOPTIONS=f"-c statement_timeout={STATEMENT_TIMEOUT_S * 1000}")
    p = subprocess.run([psql, "-h", HOST, "-p", str(PORT), "-U", USER, "-d", DBNAME,
                        "-At", "-v", "ON_ERROR_STOP=1", "-c", sql],
                       capture_output=True, text=True, env=env, timeout=STATEMENT_TIMEOUT_S + 30)
    if p.returncode != 0:
        raise CrtshDbError((p.stderr or "psql failed").strip().splitlines()[-1][:200])
    return p.stdout.splitlines()


def _valid(domain: str) -> bool:
    return bool(domain) and all(c.isalnum() or c in "-._" for c in domain) and "." in domain.strip(".")


_BUSY = ("max_client_conn", "too many connections", "Connection refused", "accepting TCP/IP",
         "could not connect", "timeout expired", "server closed the connection")


def query_many(domains: List[str], retries: int = 6, timeout: int = 20) -> Dict[str, Set[str]]:
    """{domain: in-domain hostnames ever logged} for a batch, from one query.
    The shared server often refuses connections when full; those attempts back off
    longer. Raises CrtshDbError when the batch never succeeds."""
    doms = sorted({d.strip().lower().rstrip(".") for d in domains if d.strip()})
    bad = [d for d in doms if not _valid(d)]
    if bad:
        raise CrtshDbError(f"not a hostname: {bad[0]!r}")
    last = ""
    for attempt in range(1, retries + 1):
        try:
            try:
                rows = _via_driver(doms, timeout)
            except ImportError:
                rows = _via_psql(doms, timeout)
            out: Dict[str, Set[str]] = {d: set() for d in doms}
            # longest domain first, so a name lands in the most specific queried domain
            by_len = sorted(doms, key=len, reverse=True)
            for n in _clean_all(rows):
                d = next((d for d in by_len if n == d or n.endswith("." + d)), None)
                if d:
                    out[d].add(n)
            return out
        except CrtshDbError as e:
            last = str(e)
            if "no PostgreSQL client" in last:
                break
        except Exception as e:          # connection refused/full, timeout, server-side cancel
            msg = str(e).strip()
            last = f"{type(e).__name__}: {msg.splitlines()[0][:160] if msg else ''}"
        if attempt < retries:
            busy = any(b.lower() in last.lower() for b in _BUSY)
            time.sleep((20 if busy else 5) * attempt)
    raise CrtshDbError(f"crt.sh database query for {len(doms)} domain(s) failed: {last}")


def query(domain: str, retries: int = 6, timeout: int = 20) -> Set[str]:
    """In-domain hostnames ever logged for one domain. Raises CrtshDbError on failure."""
    d = domain.strip().lower().rstrip(".")
    return query_many([d], retries, timeout).get(d, set())


def query_batches(domains: Iterable[str], batch: int = 20, log=None):
    """Yield (domain, names | None) for every domain; None marks a failed query
    (a coverage gap, never 'no subdomains')."""
    doms = list(dict.fromkeys(d.strip().lower().rstrip(".") for d in domains if d.strip()))
    for i in range(0, len(doms), max(1, batch)):
        chunk = doms[i:i + max(1, batch)]
        try:
            res = query_many(chunk)
            for d in chunk:
                yield d, res.get(d, set())
        except CrtshDbError as e:
            if log:
                log(f"[crtsh-db] batch of {len(chunk)} failed: {e}")
            for d in chunk:
                yield d, None


def main(argv: List[str]) -> int:
    if not argv or argv[0] in ("-h", "--help"):
        print(__doc__.strip())
        return 0 if argv else 2
    batch = 20
    if argv[0].startswith("--batch="):
        batch, argv = int(argv[0].split("=", 1)[1]), argv[1:]
    failed = 0
    for d, names in query_batches(argv, batch, log=lambda m: print(m, file=sys.stderr)):
        if names is None:
            failed += 1
            print(f"FAILED {d}", file=sys.stderr)
            continue
        for n in sorted(names):
            print(n)
    sys.stdout.flush()
    return 3 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
