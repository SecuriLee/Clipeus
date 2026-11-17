"""watch.py — continuous monitoring of the higher-risk part of a Clipeus audit.

A full audit is slow and runs rarely; a claimable record can be taken over the day
after it. Watch mode re-audits only the hosts whose last record shows higher risk,
compares each new record with the previous one, and raises an alert on a
significant change. Run it from cron or a systemd timer, e.g. the high tier every
30 minutes and the elevated tier every few hours; a full audit (the baseline)
still runs on its own schedule and can be fed back in with --watch.

Tiers are derived from the evidence in each record, not from a host list:
  high      a takeover or hijack is possible or observed, the page serves search
            spam, a nameserver's domain is unregistered, or a CNAME dangles towards
            a target whose claimability is unknown
  elevated  a provider binding to review, a cloud IP that answers on nothing, a lame
            delegation, a dangling record nobody can reclaim, or exposure at or above
            the tuning value watch_elevated_exposure (default 40)
A host whose risk clears stays in the elevated tier for watch_keep_days (default 7),
so a record that is fixed and broken again is still watched. A host that gives no
result within watch_host_timeout seconds (default 300; slow, filtered or tarpitted)
is skipped for that run with its state kept, so a tarpit neither hangs the run nor
raises false alerts; three timeouts in a row are logged.

To keep alerts meaningful: address and nameserver lists are compared as sets; a DNS
field that comes back empty once keeps its last value until a second run agrees; and
a move inside the provider the name already uses (same first CNAME hop, or addresses
in the same ASN, still resolving) is logged as info rather than alerted.

Alerts go to every configured sink at once: an append-only JSONL log (always), any
number of webhooks (one JSON POST per run, accepted by Slack, Teams, Discord and
generic receivers), and email over SMTP (STARTTLS, SSL or plain; with credentials,
or without for an IP-allow-listed relay; smtp_connect dials another address while
TLS is verified against smtp_host). Temporary failures (greylisting, a busy relay,
webhook 429/5xx) are retried; anything still undelivered is kept in an outbox and
re-sent on the next run. Secrets are read only from the environment: the SMTP password from
CLIPEUS_SMTP_PASSWORD (or the variable named by password_env), each webhook URL from
the variable named by url_env. A password or URL in the config file is an error.
"""
from __future__ import annotations

import ipaddress
import json
import os
import smtplib
import ssl
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from typing import Any, Callable, Dict, List, Optional, Tuple

SEVERITIES = ("info", "warning", "critical")
_SEV = {s: i for i, s in enumerate(SEVERITIES)}

HIGH_OUTCOMES = {"potentially-reclaimable", "claimable-by-policy", "claimable-by-signature",
                 "claimable-ns-domain", "hijack-suspected", "verified"}
ELEVATED_OUTCOMES = {"provider-binding-review", "protected", "dangling-reserved"}
ELEVATED_CLASSES = {"unresponsive-cloud-ip", "lame-delegation"}

# Fields compared between two records of the same host. Anything else may change
# freely (latency, scan time, ...) without an alert.
SNAPSHOT_FIELDS = ("dns_status", "cname", "a_records", "ipv6", "ns_servers", "ns_registration",
                   "http_status", "https_status", "final_url", "page_title", "body_sha256",
                   "cert_sha256", "cert_issuer", "cert_not_before", "disposition",
                   "dangling_status", "dangling_class", "takeover_risk", "takeover_outcome",
                   "content_abuse", "ports", "risk_score", "risk_exposure", "asn", "scanned_at")

# List-valued fields: compared as sets, so a resolver returning the same records in
# another order is not a change.
SET_FIELDS = ("a_records", "ipv6", "ns_servers", "ports")
# DNS fields where one empty answer is more often a failed lookup than a real change:
# an empty value replaces a known one only when two runs in a row agree.
CONFIRM_EMPTY_FIELDS = ("cname", "a_records", "ipv6", "ns_servers")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse(ts: str) -> Optional[datetime]:
    try:
        return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        return None


def tier_of(rec: Dict[str, Any], elevated_exposure: int = 40) -> Optional[str]:
    """'high', 'elevated' or None, from the record's own evidence.
    High means someone else could take the name now or already has: a takeover
    risk or claimable outcome, search spam on the page, an unregistered nameserver
    domain, or a dangling CNAME whose claimability is unknown. Stale records nobody
    else can claim (protected, reserved, a dead nameserver in a registered domain)
    are elevated: still watched, so a change is seen, but not as an emergency."""
    outcome = rec.get("takeover_outcome", "N/A")
    if (rec.get("takeover_risk") in ("Yes", "Possibly") or outcome in HIGH_OUTCOMES
            or rec.get("content_abuse", "None") not in ("None", "", "N/A")
            or "not-registered" in str(rec.get("ns_registration", ""))
            or rec.get("dangling_class") == "dangling-cname" and outcome in ("none", "N/A", "")):
        return "high"
    try:
        exposure = int(rec.get("risk_exposure") or 0)
    except (TypeError, ValueError):
        exposure = 0
    if (outcome in ELEVATED_OUTCOMES or rec.get("dangling_class") in ELEVATED_CLASSES
            or rec.get("dangling_status") in ("Yes", "Possibly") or exposure >= elevated_exposure):
        return "elevated"
    return None


# Snapshot field -> the check in the record's `checks` column that produces it. A
# field whose check did not run this time (e.g. a watch run with --ports none) is
# left out, so "not looked at" never reads as "gone". A check that failed is left out
# too: its partial output (e.g. a filter answering every port) is not a result.
FIELD_CHECK = {"ports": "ports", "cert_sha256": "tls", "cert_issuer": "tls", "cert_not_before": "tls",
               "ns_registration": "rdap"}


def _empty(v: Any) -> bool:
    return v is None or str(v).strip() in ("", "N/A", "None")


def _norm(field: str, v: Any) -> str:
    if field in SET_FIELDS and not _empty(v):
        return ",".join(sorted({x.strip() for x in str(v).split(",") if x.strip()}))
    return str(v if v is not None else "N/A")


def snapshot(rec: Dict[str, Any]) -> Dict[str, Any]:
    checks = dict(p.split("=", 1) for p in str(rec.get("checks", "")).split(";") if "=" in p)
    return {k: (_norm(k, rec.get(k, "N/A")) if k in SET_FIELDS else rec.get(k, "N/A"))
            for k in SNAPSHOT_FIELDS
            if not (k in FIELD_CHECK and checks.get(FIELD_CHECK[k]) in ("not_run", "failed"))}


_LOCAL_NETS = tuple(ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "127.0.0.0/8",
    "169.254.0.0/16", "fc00::/7", "fe80::/10", "::1/128"))


def private_only(snap: Dict[str, Any]) -> bool:
    """True when every published address is private (RFC 1918, CGNAT, loopback, link-local, ULA):
    what answers there depends on the scanning host's own network, not the Internet."""
    addrs = [a.strip() for f in ("a_records", "ipv6") if not _empty(snap.get(f))
             for a in str(snap.get(f)).split(",") if a.strip()]
    try:
        return bool(addrs) and all(any(ipaddress.ip_address(a) in n for n in _LOCAL_NETS)
                                   for a in addrs)
    except ValueError:
        return False


def hold_empty(entry: Dict[str, Any], new: Dict[str, Any]) -> List[str]:
    """Keep the last known value of a DNS field that came back empty once.
    The empty value is accepted when the next run sees it too. Mutates `new`
    and entry['pending_empty']; returns the fields held this run."""
    old = entry.get("snapshot", {})
    pending = set(entry.get("pending_empty", []))
    held = []
    for f in CONFIRM_EMPTY_FIELDS:
        if f in old and f in new and _empty(new[f]) and not _empty(old[f]):
            if f in pending:
                pending.discard(f)          # second empty answer in a row: real
            else:
                pending.add(f)
                new[f] = old[f]
                held.append(f)
        else:
            pending.discard(f)
    entry["pending_empty"] = sorted(pending)
    return held


def _first_hop(chain: Any) -> str:
    return "" if _empty(chain) else str(chain).split("->")[0].strip().lower().rstrip(".")


def _registered_ns(value: str) -> Dict[str, str]:
    out = {}
    for part in str(value or "").split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            out[k.strip()] = v.strip()
    return out


def compare(host: str, tier: str, old: Dict[str, Any], new: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Significant changes between two snapshots of one host, as alert events."""
    ev: List[Dict[str, Any]] = []

    def add(sev: str, kind: str, detail: str, field: str = "", before: Any = None, after: Any = None):
        ev.append({"host": host, "tier": tier, "severity": sev, "kind": kind, "detail": detail,
                   "field": field, "before": before, "after": after})

    def changed(f: str) -> bool:
        if f not in old or f not in new:      # not observed on one side: no comparison
            return False
        return _norm(f, old.get(f, "N/A")) != _norm(f, new.get(f, "N/A"))

    high = tier == "high"
    risk_rank = {"No": 0, "N/A": 0, "Possibly": 1, "Yes": 2}
    r0, r1 = risk_rank.get(old.get("takeover_risk"), 0), risk_rank.get(new.get("takeover_risk"), 0)
    if r1 > r0 or (changed("takeover_outcome") and new.get("takeover_outcome") in HIGH_OUTCOMES):
        add("critical", "takeover-risk",
            f"takeover {old.get('takeover_outcome')} -> {new.get('takeover_outcome')}",
            "takeover_outcome", old.get("takeover_outcome"), new.get("takeover_outcome"))
    if new.get("content_abuse", "None") not in ("None", "", "N/A") and changed("content_abuse"):
        add("critical", "abusive-content", f"page serves {new.get('content_abuse')}",
            "content_abuse", old.get("content_abuse"), new.get("content_abuse"))
    was_dead = old.get("dns_status") != "OK" or (old.get("http_status") in ("0", 0, "N/A")
                                                and old.get("https_status") in ("0", 0, "N/A"))
    now_up = new.get("dns_status") == "OK" and (new.get("http_status") not in ("0", 0, "N/A")
                                                or new.get("https_status") not in ("0", 0, "N/A"))
    if was_dead and now_up:
        add("critical" if high else "warning", "started-serving",
            f"now answers: {new.get('https_status') or new.get('http_status')} '{new.get('page_title')}'",
            "disposition", old.get("disposition"), new.get("disposition"))
    if changed("cert_sha256") and new.get("cert_sha256") not in ("N/A", "", None):
        add("critical" if high else "warning", "new-certificate",
            f"certificate {new.get('cert_issuer')} from {new.get('cert_not_before')}",
            "cert_sha256", old.get("cert_sha256"), new.get("cert_sha256"))
    reg0, reg1 = _registered_ns(old.get("ns_registration")), _registered_ns(new.get("ns_registration"))
    for dom, res in reg1.items():
        if reg0.get(dom, "").startswith("not-registered") and not res.startswith("not-registered"):
            add("critical", "ns-domain-registered",
                f"nameserver domain {dom} is now registered ({res})", "ns_registration",
                reg0.get(dom), res)
    # Moves inside the provider the name already points at (traffic-manager failover,
    # CDN address rotation) are the provider's business, not a new target: the name's
    # own CNAME is unchanged, or the addresses stay in the same network (ASN), and it
    # still resolves. Logged as info; a takeover or dangling change is judged above.
    resolves = new.get("dns_status") == "OK"
    same_hop = bool(_first_hop(old.get("cname"))) and _first_hop(old.get("cname")) == _first_hop(new.get("cname"))
    same_asn = not _empty(old.get("asn")) and str(old.get("asn")) == str(new.get("asn"))
    for f, kind in (("cname", "dns-target-changed"), ("a_records", "address-changed"),
                    ("ipv6", "address-changed"), ("ns_servers", "nameservers-changed"),
                    ("ports", "ports-changed")):
        if changed(f):
            internal = resolves and (same_hop if f == "cname" else
                                     f in ("a_records", "ipv6") and (same_hop or same_asn))
            add("info" if internal else "warning", kind + ("-within-provider" if internal else ""),
                f"{f}: {old.get(f)} -> {new.get(f)}", f, old.get(f), new.get(f))
    if changed("disposition") and not (was_dead and now_up):
        add("warning", "disposition-changed", f"{old.get('disposition')} -> {new.get('disposition')}",
            "disposition", old.get("disposition"), new.get("disposition"))
    if changed("page_title"):
        add("warning" if high else "info", "title-changed",
            f"title '{old.get('page_title')}' -> '{new.get('page_title')}'",
            "page_title", old.get("page_title"), new.get("page_title"))
    elif changed("body_sha256") and new.get("body_sha256") not in ("N/A", "", None):
        add("warning" if high else "info", "content-changed", "page content changed", "body_sha256",
            old.get("body_sha256"), new.get("body_sha256"))
    try:
        d = int(new.get("risk_score") or 0) - int(old.get("risk_score") or 0)
    except (TypeError, ValueError):
        d = 0
    if d >= 20:
        add("warning", "risk-increased", f"risk score +{d} ({old.get('risk_score')} -> {new.get('risk_score')})",
            "risk_score", old.get("risk_score"), new.get("risk_score"))
    if private_only(new) and not any(e["kind"] in ("takeover-risk", "abusive-content", "ns-domain-registered")
                                     for e in ev):
        # Only the scanning host's own network can reach a private address; what
        # answers there says nothing about the Internet-facing posture.
        for e in ev:
            if e["severity"] != "info":
                e["severity"] = "info"
                e["detail"] += " (private address: seen from the scanning host's network only)"
    cleared = r1 < r0 or (old.get("dangling_status") in ("Yes", "Possibly") and new.get("dangling_status") == "No")
    if cleared and not any(e["severity"] == "critical" for e in ev):
        # The record was fixed: the DNS/disposition changes are how the fix looks,
        # not new problems. Keep them in the log, out of the alerts.
        for e in ev:
            e["severity"] = "info"
    if cleared:
        add("info", "risk-cleared",
            f"takeover {old.get('takeover_outcome')} -> {new.get('takeover_outcome')}; "
            f"dangling {old.get('dangling_class')} -> {new.get('dangling_class')}",
            "takeover_outcome", old.get("takeover_outcome"), new.get("takeover_outcome"))
    return ev


# ---------------------------------------------------------------- state

def load_state(path: str) -> Dict[str, Any]:
    if not os.path.isfile(path):
        return {"version": 1, "hosts": {}}
    with open(path, encoding="utf-8") as fh:
        st = json.load(fh)
    if not isinstance(st, dict) or not isinstance(st.get("hosts"), dict):
        raise ValueError(f"{path}: not a Clipeus watch state file")
    return st


def save_state(path: str, st: Dict[str, Any]) -> None:
    d = os.path.dirname(os.path.abspath(path))
    fd, tmp = tempfile.mkstemp(prefix=".watch-", dir=d)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(st, fh, indent=1, sort_keys=True)
    os.replace(tmp, path)


def seed_from_baselines(st: Dict[str, Any], paths: List[str], elevated_exposure: int) -> Tuple[int, int]:
    """Add the tiered hosts of each baseline audit; a baseline record newer than the
    host's last check replaces its snapshot (a fresh full audit supersedes the state)."""
    added = refreshed = 0
    for p in paths:
        with open(p, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except ValueError:
                    continue
                host = rec.get("domain")
                t = tier_of(rec, elevated_exposure)
                if not host:
                    continue
                cur = st["hosts"].get(host)
                if cur is None:
                    if t:
                        st["hosts"][host] = {"tier": t, "snapshot": snapshot(rec), "since": _iso(_now()),
                                             "last_checked": "", "cleared_at": ""}
                        added += 1
                    continue
                seen = _parse(rec.get("scanned_at", ""))
                last = _parse(cur.get("snapshot", {}).get("scanned_at", ""))
                if seen and (last is None or seen > last):
                    cur["snapshot"] = snapshot(rec)
                    if t:
                        cur["tier"], cur["cleared_at"] = t, ""
                    refreshed += 1
    return added, refreshed


# ---------------------------------------------------------------- alerts

DEFAULT_PASSWORD_ENV = "CLIPEUS_SMTP_PASSWORD"


def _env_secret(conf: Dict[str, Any], key: str, default_env: str = "") -> str:
    """Secrets come only from the environment: `<key>_env` names the variable."""
    env = conf.get(key + "_env") or default_env
    return os.environ.get(env, "") if env else ""


def summary_text(events: List[Dict[str, Any]], label: str) -> str:
    worst = max((e["severity"] for e in events), key=lambda s: _SEV[s], default="info")
    lines = [f"Clipeus watch{(' ' + label) if label else ''}: {len(events)} change(s), worst {worst}"]
    for e in sorted(events, key=lambda e: (-_SEV[e["severity"]], e["host"])):
        lines.append(f"[{e['severity']}] {e['host']} ({e['tier']}): {e['kind']} — {e['detail']}")
    return "\n".join(lines)


def send_webhook(conf: Dict[str, Any], text: str, events: List[Dict[str, Any]], timeout: float = 15) -> None:
    import requests
    url = _env_secret(conf, "url")
    if not url:
        raise ValueError(f"webhook: environment variable {conf.get('url_env')!r} is empty or unset")
    fmt = conf.get("format", "generic")
    if fmt == "slack":
        body: Dict[str, Any] = {"text": text}
    elif fmt == "discord":
        body = {"content": text[:1990]}
    elif fmt == "teams":
        body = {"@type": "MessageCard", "@context": "https://schema.org/extensions",
                "summary": text.splitlines()[0], "text": text.replace("\n", "  \n")}
    else:
        body = {"text": text, "events": events}
    r = requests.post(url, json=body, timeout=timeout, headers=conf.get("headers") or {})
    if r.status_code >= 300:
        raise RuntimeError(f"webhook HTTP {r.status_code}")


def email_body(text: str, events: List[Dict[str, Any]]) -> str:
    """Plain-text mail: the summary, then one readable block per change."""
    out = [text, "", "Details", "======="]
    for e in sorted(events, key=lambda e: (-_SEV[e["severity"]], e["host"])):
        out += ["", f"{e['host']}  [{e['severity']}, {e['tier']} tier]", f"  {e['kind']}: {e['detail']}"]
        if e.get("field") and (e.get("before") is not None or e.get("after") is not None):
            out += [f"  {e['field']} before: {e.get('before')}", f"  {e['field']} after:  {e.get('after')}"]
    out += ["", "--", "Sent by Clipeus watch mode. The full event log is kept on the scanning host."]
    return "\n".join(out)


class _VerifiedSMTPSSL(smtplib.SMTP_SSL):
    """SMTP over implicit TLS that verifies the certificate against `tls_name`
    whatever address it connects to."""
    def __init__(self, tls_name: str, **kw):
        self.tls_name = tls_name
        super().__init__(**kw)

    def _get_socket(self, host, port, timeout):
        import socket as _socket
        raw = _socket.create_connection((host, port), timeout, self.source_address)
        return self.context.wrap_socket(raw, server_hostname=self.tls_name)


def send_email(conf: Dict[str, Any], to: List[str], subject: str, text: str,
               events: List[Dict[str, Any]], timeout: float = 30) -> None:
    host = conf.get("smtp_host")
    if not host or not to:
        raise ValueError("email needs smtp_host and at least one recipient")
    security = conf.get("security", "starttls")
    port = int(conf.get("smtp_port") or {"ssl": 465, "starttls": 587}.get(security, 25))
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = conf.get("from") or f"clipeus@{host}"
    msg["To"] = ", ".join(to)
    msg.set_content(email_body(text, events))
    ctx = ssl.create_default_context()
    # smtp_connect: the address to dial when it differs from the certificate's name
    # (e.g. a relay that allow-lists a VPN address). TLS is still verified against
    # smtp_host, so the certificate must name smtp_host.
    addr = conf.get("smtp_connect") or host
    if security == "ssl":
        s: smtplib.SMTP = _VerifiedSMTPSSL(host, timeout=timeout, context=ctx)
    else:
        s = smtplib.SMTP(timeout=timeout)
    s.connect(addr, port)
    s._host = host                    # smtplib verifies STARTTLS against _host
    try:
        if security == "starttls":
            s.starttls(context=ctx)
        user = conf.get("username")
        if user:                      # no username: an IP-allow-listed relay
            pw = _env_secret(conf, "password", DEFAULT_PASSWORD_ENV)
            if not pw:
                raise ValueError(f"email: login {user!r} set but environment variable "
                                 f"{conf.get('password_env') or DEFAULT_PASSWORD_ENV} is empty or unset")
            s.login(user, pw)
        s.send_message(msg)
    finally:
        try:
            s.quit()
        except Exception:
            pass


def _transient(exc: Exception) -> bool:
    """Worth retrying: SMTP 4xx (greylisting, busy), network errors, webhook 429/5xx."""
    if isinstance(exc, smtplib.SMTPResponseException):
        return 400 <= exc.smtp_code < 500
    if isinstance(exc, (smtplib.SMTPServerDisconnected, smtplib.SMTPConnectError, OSError, TimeoutError)):
        return True
    msg = str(exc)
    return "webhook HTTP 429" in msg or "webhook HTTP 5" in msg


def _deliver(send: Callable[[], None], waits: List[int], log: Callable[[str], None], what: str) -> None:
    """Call `send`; on a transient failure wait and retry (waits in seconds)."""
    for i, wait in enumerate([0] + list(waits)):
        if wait:
            log(f"[watch] {what}: retrying in {wait}s")
            time.sleep(wait)
        try:
            send()
            return
        except Exception as exc:
            if not _transient(exc) or i == len(waits):
                raise
            log(f"[watch] {what}: temporary failure ({type(exc).__name__}: {str(exc)[:80]})")


def _outbox_add(path: str, item: Dict[str, Any]) -> None:
    box = []
    if os.path.isfile(path):
        try:
            box = json.load(open(path, encoding="utf-8"))
        except ValueError:
            box = []
    box.append(item)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(box, fh, indent=1)


def flush_outbox(alerts: Dict[str, Any], log: Callable[[str], None]) -> int:
    """Re-send alerts a previous run could not deliver. Returns how many remain."""
    path = alerts.get("outbox")
    if not path or not os.path.isfile(path):
        return 0
    try:
        box = json.load(open(path, encoding="utf-8"))
    except ValueError:
        box = []
    keep = []
    for item in box:
        try:
            if item["sink"] == "email":
                send_email(alerts.get("email") or {}, item["to"], item["subject"] + " (delayed)",
                           f"Delayed: first attempted {item['time']}\n\n" + item["text"], item["events"])
            else:
                hook = next((h for h in alerts.get("webhooks", []) if h.get("id") == item["sink"]), None)
                if hook is None:
                    raise ValueError("webhook no longer configured")
                send_webhook(hook, f"(delayed, first attempted {item['time']})\n" + item["text"], item["events"])
            log(f"[watch] delivered delayed alert from {item['time']} via {item['sink']}")
        except Exception as exc:
            keep.append(item)
            log(f"[watch] delayed alert via {item['sink']} still undelivered ({type(exc).__name__})")
    if keep:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(keep, fh, indent=1)
    else:
        os.remove(path)
    return len(keep)


def dispatch(events: List[Dict[str, Any]], alerts: Dict[str, Any], log: Callable[[str], None],
             label: str = "") -> int:
    """Log every event; send webhooks and email when an event reaches min_severity.
    Transient failures are retried (alerts.retry_waits, default 60 and 180 s); what
    still fails goes to the outbox and is re-sent at the start of the next run.
    Returns the number of failed sinks (a failed sink never stops the others)."""
    failed = 0
    waits = [int(w) for w in alerts.get("retry_waits", [60, 180])]
    stamp = _iso(_now())
    log_path = alerts.get("log")
    if log_path and events:
        with open(log_path, "a", encoding="utf-8") as fh:
            for e in events:
                fh.write(json.dumps({"time": stamp, **e}, ensure_ascii=False) + "\n")
    floor = _SEV.get(alerts.get("min_severity", "warning"), 1)
    loud = [e for e in events if _SEV[e["severity"]] >= floor]
    if not loud:
        return 0
    text = summary_text(loud, label)
    for hook in alerts.get("webhooks", []):
        try:
            _deliver(lambda: send_webhook(hook, text, loud), waits, log, f"webhook {hook.get('id')}")
            log(f"[watch] webhook sent ({hook.get('format', 'generic')})")
        except Exception as exc:
            failed += 1
            log(f"[watch] webhook FAILED: {type(exc).__name__}: {exc}")
            if alerts.get("outbox"):
                _outbox_add(alerts["outbox"], {"time": stamp, "sink": hook.get("id"), "text": text,
                                               "events": loud})
    email = alerts.get("email") or {}
    if email.get("to"):
        worst = max((e["severity"] for e in loud), key=lambda s: _SEV[s])
        subject = f"{email.get('subject_prefix', '[Clipeus watch]')} {worst}: {len(loud)} change(s)"
        try:
            _deliver(lambda: send_email(email, list(email["to"]), subject, text, loud), waits, log, "email")
            log(f"[watch] email sent to {len(email['to'])} recipient(s)")
        except Exception as exc:
            failed += 1
            log(f"[watch] email FAILED: {type(exc).__name__}: {exc}")
            if alerts.get("outbox"):
                _outbox_add(alerts["outbox"], {"time": stamp, "sink": "email", "to": list(email["to"]),
                                               "subject": subject, "text": text, "events": loud})
    return failed


def merge_alert_config(cfg_alerts: Dict[str, Any], args: Any, state_path: str) -> Dict[str, Any]:
    """Config file 'alerts' block, with CLI flags added on top."""
    a = json.loads(json.dumps(cfg_alerts or {}))
    if not isinstance(a, dict):
        raise ValueError("'alerts' must be an object")
    a.setdefault("webhooks", [])
    if not isinstance(a["webhooks"], list):
        raise ValueError("'alerts.webhooks' must be a list")
    for w in a["webhooks"]:
        if not isinstance(w, dict) or "url" in w or not w.get("url_env"):
            raise ValueError("alerts.webhooks entries must be objects with url_env (the name of an "
                             "environment variable holding the URL); a webhook URL is a secret and "
                             "is not read from the config file")
    for env in getattr(args, "alert_webhook_env", None) or []:
        a["webhooks"].append({"url_env": env})
    for i, w in enumerate(a["webhooks"]):
        w.setdefault("id", f"webhook-{i + 1}")
    email = a.get("email") or {}
    if not isinstance(email, dict):
        raise ValueError("'alerts.email' must be an object")
    if "password" in email:
        raise ValueError("alerts.email.password is not read from the config file: put the password "
                         f"in an environment variable ({DEFAULT_PASSWORD_ENV} by default, or the name "
                         "given in password_env)")
    for k, v in (("smtp_host", getattr(args, "alert_smtp_host", None)),
                 ("smtp_port", getattr(args, "alert_smtp_port", None)),
                 ("security", getattr(args, "alert_smtp_security", None)),
                 ("username", getattr(args, "alert_smtp_user", None)),
                 ("from", getattr(args, "alert_email_from", None))):
        if v:
            email[k] = v
    to = list(email.get("to") or [])
    to += list(getattr(args, "alert_email", None) or [])
    if to:
        email["to"] = sorted(set(to))
    a["email"] = email
    if getattr(args, "alert_log", None):
        a["log"] = args.alert_log
    a.setdefault("log", state_path + ".alerts.log")
    a.setdefault("outbox", state_path + ".outbox.json")
    if getattr(args, "alert_min_severity", None):
        a["min_severity"] = args.alert_min_severity
    if a.get("min_severity", "warning") not in _SEV:
        raise ValueError(f"alerts.min_severity must be one of {', '.join(SEVERITIES)}")
    return a


# ---------------------------------------------------------------- run

def audit_with_deadline(hosts: List[str], audit_host: Callable[[str], Any], workers: int,
                        host_timeout: int) -> Tuple[List[Tuple[str, Any]], List[str]]:
    """Audit hosts in parallel; a host still running after `host_timeout` seconds is
    abandoned (a tarpit can drip bytes under every per-request timeout). Returns
    (finished results, timed-out hosts). Abandoned threads are left behind; the
    caller must end the process without waiting for them."""
    started: Dict[str, float] = {}

    def one(h: str):
        started[h] = time.monotonic()
        return audit_host(h)
    ex = ThreadPoolExecutor(max_workers=max(1, min(workers, len(hosts) or 1)))
    futs = {ex.submit(one, h): h for h in hosts}
    results: List[Tuple[str, Any]] = []
    timed_out: List[str] = []
    pending = set(futs)
    while pending:
        done = {f for f in pending if f.done()}
        for f in done:
            try:
                results.append((futs[f], f.result()))
            except Exception as exc:
                results.append((futs[f], {"error": f"{type(exc).__name__}: {exc}"}))
        pending -= done
        now = time.monotonic()
        for f in list(pending):
            h = futs[f]
            if h in started and now - started[h] > host_timeout:
                timed_out.append(h)
                pending.discard(f)
        if pending:
            time.sleep(0.5)
    ex.shutdown(wait=False, cancel_futures=True)
    return results, timed_out


def run(args: Any, alerts_cfg: Dict[str, Any], log: Callable[[str], None],
        audit_host: Callable[[str], Any], elevated_exposure: int = 40, keep_days: int = 7,
        workers: int = 8, host_timeout: int = 300) -> int:
    """One watch cycle. Returns the process exit code: 0 quiet, 4 alerts raised,
    5 a sink failed (alerts may not have been delivered)."""
    state_path = args.watch_state or os.path.join(
        os.path.dirname(os.path.abspath(args.watch[0])) if args.watch else ".", "clipeus-watch.json")
    alerts = merge_alert_config(alerts_cfg, args, state_path)
    if getattr(args, "alert_test", False):
        ev = [{"host": "example.com", "tier": "high", "severity": "critical", "kind": "test",
               "detail": "Clipeus watch test alert: every configured sink should receive this",
               "field": "", "before": None, "after": None}]
        failed = dispatch(ev, {**alerts, "min_severity": "info", "retry_waits": [], "outbox": ""}, log, "test")
        log(f"[watch] test alert sent; {failed} sink(s) failed; log -> {alerts['log']}")
        return 5 if failed else 0

    left = flush_outbox(alerts, log)
    st = load_state(state_path)
    if args.watch:
        added, refreshed = seed_from_baselines(st, args.watch, elevated_exposure)
        log(f"[watch] baseline: +{added} hosts, {refreshed} refreshed -> {state_path}")
    if not st["hosts"]:
        log("[watch] nothing to watch: no host in the baseline is high or elevated")
        save_state(state_path, st)
        return 0

    want = {"high": ("high",), "elevated": ("elevated",), "all": ("high", "elevated")}[args.watch_tiers]
    due = sorted(h for h, v in st["hosts"].items() if v.get("tier") in want)
    log(f"[watch] checking {len(due)} host(s), tiers {','.join(want)} "
        f"({sum(1 for v in st['hosts'].values() if v.get('tier') == 'high')} high, "
        f"{sum(1 for v in st['hosts'].values() if v.get('tier') == 'elevated')} elevated watched)")

    events: List[Dict[str, Any]] = []
    now = _now()
    results, timed_out = audit_with_deadline(due, audit_host, workers, host_timeout)
    for host in timed_out:
        entry = st["hosts"][host]
        entry["timeouts"] = int(entry.get("timeouts", 0)) + 1
        log(f"[watch] {host}: no result within {host_timeout}s (slow or tarpitted); state kept, "
            f"{entry['timeouts']} timeout(s) in a row")
        if entry["timeouts"] == 3:
            events.append({"host": host, "tier": entry.get("tier"), "severity": "info",
                           "kind": "repeated-timeout",
                           "detail": f"no result within {host_timeout}s on 3 runs in a row "
                                     "(slow, filtered or tarpitted); nothing compared",
                           "field": "", "before": None, "after": None})
    for host, rec in results:
        entry = st["hosts"][host]
        entry["timeouts"] = 0
        if rec is None or rec.get("error"):
            log(f"[watch] {host}: audit error ({(rec or {}).get('error', 'none returned')}); state kept")
            continue
        new = snapshot(rec)
        for f in hold_empty(entry, new):
            log(f"[watch] {host}: {f} came back empty; last value kept until the next run confirms")
        old_tier = entry.get("tier")
        events += compare(host, old_tier, entry.get("snapshot", {}), new)
        t = tier_of(rec, elevated_exposure)
        if t:
            entry["tier"], entry["cleared_at"] = t, ""
            if t != old_tier:
                events.append({"host": host, "tier": t, "severity": "warning" if t == "high" else "info",
                               "kind": "tier-changed", "detail": f"tier {old_tier} -> {t}",
                               "field": "tier", "before": old_tier, "after": t})
        else:
            cleared = _parse(entry.get("cleared_at", "")) or now
            entry["cleared_at"] = _iso(cleared)
            entry["tier"] = "elevated" if now - cleared < timedelta(days=keep_days) else "retired"
        entry["snapshot"], entry["last_checked"] = new, _iso(now)
    retired = [h for h, v in st["hosts"].items() if v.get("tier") == "retired"]
    for h in retired:
        del st["hosts"][h]
    st["last_run"] = {"at": _iso(now), "tiers": list(want), "checked": len(due), "events": len(events)}
    save_state(state_path, st)

    for e in sorted(events, key=lambda e: (-_SEV[e["severity"]], e["host"])):
        log(f"[watch] [{e['severity']}] {e['host']} ({e['tier']}): {e['kind']} — {e['detail']}")
    failed = dispatch(events, alerts, log, ",".join(want))
    floor = _SEV.get(alerts.get("min_severity", "warning"), 1)
    loud = sum(1 for e in events if _SEV[e["severity"]] >= floor)
    log(f"[watch] done: {len(events)} change(s), {loud} alerted, {len(retired)} retired; "
        f"log -> {alerts['log']}")
    if failed or left:
        return 5
    return 4 if loud else 0
