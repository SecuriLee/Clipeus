#!/usr/bin/env bash
# enum-portfolio.sh — orchestrate the installed Kali recon tooling to enumerate
# subdomains from a domain/TLD list, then validate and HTTP-probe the results.
#
#   enum-portfolio.sh <domains.txt> <outdir> [options]
#
# Stages (each tool is optional — missing ones are skipped with a note):
#   passive   subfinder (-all), amass (passive), assetfinder, chaos
#   ct        crt.sh (curl+jq), the bundled crtsh-enum.py
#   brute     (--brute) dnsx / gobuster / ffuf DNS wordlist against a resolver set
#   permute   (--permute) gotator / dnsgen / altdns, else a bundled permutator
#   deep      (--deep) amass active, theHarvester, dnsrecon, dnsenum, fierce
#   resolve   dnsx (or puredns/massdns/shuffledns) — only resolvable names kept
#   probe     httpx — live hosts + JSONL metadata
#
# Output layout under <outdir>:
#   raw/<source>.txt   per-source hits      candidates.txt  merged+deduped
#   resolved.txt       resolvable names     live.txt        HTTP(S)-answering
#   httpx.jsonl        httpx metadata       enum.log        run log
#   The resolved.txt is the file to feed into clipeus --input.
#
# AUTHORISED USE ONLY. Run only against domains you own or are contracted to test.
set -uo pipefail

# ---- args -------------------------------------------------------------------
BRUTE=0 PERMUTE=0 DEEP=0 WORDLIST="" RESOLVERS="" THREADS=40
DOMAINS="" OUTDIR=""
usage() { sed -n '2,30p' "$0"; exit "${1:-0}"; }
while [ $# -gt 0 ]; do
  case "$1" in
    --brute) BRUTE=1 ;;
    --permute) PERMUTE=1 ;;
    --deep) DEEP=1 ;;
    --wordlist) WORDLIST="$2"; shift ;;
    --resolvers) RESOLVERS="$2"; shift ;;
    --threads) THREADS="$2"; shift ;;
    -h|--help) usage 0 ;;
    -*) echo "unknown option: $1" >&2; usage 1 ;;
    *) if [ -z "$DOMAINS" ]; then DOMAINS="$1"; elif [ -z "$OUTDIR" ]; then OUTDIR="$1"; fi ;;
  esac
  shift
done
[ -n "$DOMAINS" ] && [ -n "$OUTDIR" ] || usage 1
[ -r "$DOMAINS" ] || { echo "cannot read domains file: $DOMAINS" >&2; exit 1; }

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
mkdir -p "$OUTDIR/raw"
LOG="$OUTDIR/enum.log"
: > "$LOG"
log() { echo "$(date +%H:%M:%S) $*" | tee -a "$LOG"; }
have() { command -v "$1" >/dev/null 2>&1; }
# anew-like dedup append: keep order, drop dups, lower-case, strip blanks/comments
merge() { grep -vE '^\s*(#|$)' | tr '[:upper:]' '[:lower:]' | sed 's/^\*\.//; s/\.$//' | sort -u; }

# normalised apex list (one registrable-ish name per line; punycode left as-is)
APEX="$OUTDIR/raw/_apex.txt"
merge < "$DOMAINS" > "$APEX"
log "[*] $(wc -l < "$APEX") apex domains loaded from $(basename "$DOMAINS")"

# ---- wordlist / resolvers ---------------------------------------------------
if [ -z "$WORDLIST" ]; then
  for w in /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt \
           /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
           /usr/share/seclists/Discovery/DNS/dns-Jhaddix.txt; do
    [ -r "$w" ] && { WORDLIST="$w"; break; }
  done
fi
# Resolvers: the same lookup every Clipeus tool uses (brand_config.py --resolvers):
# --resolvers FILE / $CLIPEUS_RESOLVERS > brand.json > tuning > Cloudflare + Google.
_RES_OUT="$OUTDIR/raw/_resolvers.txt"
if command -v python3 >/dev/null 2>&1; then
  python3 "$HERE/../brand_config.py" --resolvers ${RESOLVERS:+"$RESOLVERS"} > "$_RES_OUT" 2>>"$LOG" \
    || { echo "resolver config error (see $LOG)" >&2; exit 1; }
elif [ -n "$RESOLVERS" ]; then
  cp "$RESOLVERS" "$_RES_OUT"
else
  printf '1.1.1.1\n1.0.0.1\n8.8.8.8\n8.8.4.4\n' > "$_RES_OUT"
fi
RESOLVERS="$_RES_OUT"

# ---- passive ----------------------------------------------------------------
if have subfinder; then
  log "[passive] subfinder -all over $(wc -l < "$APEX") domains ..."
  subfinder -dL "$APEX" -all -silent -o "$OUTDIR/raw/subfinder.txt" >>"$LOG" 2>&1 \
    && log "[passive] subfinder: $(wc -l < "$OUTDIR/raw/subfinder.txt" 2>/dev/null || echo 0)"
else log "[passive] subfinder MISSING — skip"; fi

if have amass; then
  log "[passive] amass enum -passive ..."
  # </dev/null so a sudo/interactive prompt fails fast instead of hanging the run
  amass enum -passive -df "$APEX" -nocolor -o "$OUTDIR/raw/amass.txt" </dev/null >>"$LOG" 2>&1 \
    && log "[passive] amass: $(wc -l < "$OUTDIR/raw/amass.txt" 2>/dev/null || echo 0)" \
    || log "[passive] amass returned non-zero (needs sudo/config?) — continuing"
else log "[passive] amass MISSING — skip"; fi

if have assetfinder; then
  log "[passive] assetfinder ..."
  while read -r d; do assetfinder --subs-only "$d"; done < "$APEX" > "$OUTDIR/raw/assetfinder.txt" 2>>"$LOG"
  log "[passive] assetfinder: $(wc -l < "$OUTDIR/raw/assetfinder.txt" 2>/dev/null || echo 0)"
else log "[passive] assetfinder MISSING — skip"; fi

if have chaos; then
  log "[passive] chaos ..."
  while read -r d; do chaos -d "$d" -silent; done < "$APEX" > "$OUTDIR/raw/chaos.txt" 2>>"$LOG"
  log "[passive] chaos: $(wc -l < "$OUTDIR/raw/chaos.txt" 2>/dev/null || echo 0)"
fi

# ---- certificate transparency ----------------------------------------------
log "[ct] crt.sh (curl) ..."
: > "$OUTDIR/raw/crtsh.txt"
while read -r d; do
  curl -s --max-time 20 "https://crt.sh/?q=%25.${d}&output=json" \
    | jq -r '.[].name_value' 2>/dev/null
  sleep 0.3
done < "$APEX" >> "$OUTDIR/raw/crtsh.txt" 2>>"$LOG"
log "[ct] crt.sh raw lines: $(wc -l < "$OUTDIR/raw/crtsh.txt" 2>/dev/null || echo 0)"
if [ -r "$HERE/crtsh-enum.py" ]; then
  log "[ct] crtsh-enum.py (retrying API, resolving) ..."
  python3 "$HERE/crtsh-enum.py" --input "$APEX" --output "$OUTDIR/raw/crtsh-enum.txt" \
    --no-resolve --log "$LOG" >>"$LOG" 2>&1 || true
fi

# ---- deep (active / OSINT, slower, noisier) --------------------------------
if [ "$DEEP" = 1 ]; then
  have amass && { log "[deep] amass enum -active ..."; amass enum -active -df "$APEX" -o "$OUTDIR/raw/amass-active.txt" >>"$LOG" 2>&1 || true; }
  if have theHarvester; then
    log "[deep] theHarvester (per apex, crtsh+bing+duckduckgo) ..."
    while read -r d; do theHarvester -d "$d" -b crtsh,bing,duckduckgo 2>/dev/null \
      | grep -oE "[a-zA-Z0-9._-]+\.${d//./\\.}"; done < "$APEX" >> "$OUTDIR/raw/theharvester.txt" 2>>"$LOG"
    log "[deep] theHarvester: $(wc -l < "$OUTDIR/raw/theharvester.txt" 2>/dev/null || echo 0)"
  fi
  for t in dnsrecon dnsenum fierce; do have "$t" && log "[deep] $t available (per-apex; run selectively, not batched here)"; done
fi

# ---- brute force ------------------------------------------------------------
if [ "$BRUTE" = 1 ]; then
  if [ -z "$WORDLIST" ] || [ ! -r "$WORDLIST" ]; then
    log "[brute] no wordlist found — skip (pass --wordlist FILE)"
  elif have dnsx; then
    log "[brute] dnsx wordlist=$(basename "$WORDLIST") ($(wc -l < "$WORDLIST") words) x $(wc -l < "$APEX") apexes ..."
    dnsx -d "$APEX" -w "$WORDLIST" -r "$RESOLVERS" -t "$THREADS" -silent \
      -o "$OUTDIR/raw/brute.txt" >>"$LOG" 2>&1 || true
    log "[brute] dnsx hits: $(wc -l < "$OUTDIR/raw/brute.txt" 2>/dev/null || echo 0)"
  elif have gobuster; then
    log "[brute] gobuster dns (per apex) ..."
    while read -r d; do gobuster dns -q -d "$d" -w "$WORDLIST" -r 1.1.1.1 -t "$THREADS" 2>/dev/null \
      | awk '/Found:/{print $2}'; done < "$APEX" > "$OUTDIR/raw/brute.txt" 2>>"$LOG"
    log "[brute] gobuster hits: $(wc -l < "$OUTDIR/raw/brute.txt" 2>/dev/null || echo 0)"
  else
    log "[brute] no dnsx/gobuster — skip"
  fi
fi

# ---- candidate merge --------------------------------------------------------
cat "$OUTDIR"/raw/*.txt 2>/dev/null | merge > "$OUTDIR/candidates.all.txt"
# keep only names equal to, or a subdomain of, an in-scope apex (anchored suffix
# match — crt.sh returns unrelated certs that merely contain the apex mid-string)
python3 - "$APEX" "$OUTDIR/candidates.all.txt" > "$OUTDIR/candidates.txt" <<'PY'
import sys
apex = {l.strip().lower() for l in open(sys.argv[1]) if l.strip()}
for line in open(sys.argv[2]):
    h = line.strip().lower()
    if not h or "." not in h:
        continue
    parts = h.split(".")
    if any(".".join(parts[i:]) in apex for i in range(len(parts))):
        print(h)
PY
log "[*] candidates: $(wc -l < "$OUTDIR/candidates.all.txt") raw -> $(wc -l < "$OUTDIR/candidates.txt") in-scope"

# ---- permutations (optional) -----------------------------------------------
if [ "$PERMUTE" = 1 ]; then
  if have gotator; then
    log "[permute] gotator ..."
    gotator -sub "$OUTDIR/candidates.txt" -perm <(printf 'dev\ntest\nstage\nuat\nprod\napi\nvpn\nold\nnew\nadmin\n') \
      -depth 1 -numbers 3 -mindup -silent 2>>"$LOG" | sort -u > "$OUTDIR/raw/perm.txt" || true
  elif have dnsgen; then
    log "[permute] dnsgen ..."; dnsgen "$OUTDIR/candidates.txt" 2>>"$LOG" | sort -u > "$OUTDIR/raw/perm.txt" || true
  else
    log "[permute] gotator/dnsgen MISSING — bundled permutator"
    python3 - "$OUTDIR/candidates.txt" > "$OUTDIR/raw/perm.txt" <<'PY'
import sys
words = ["dev","test","stage","staging","uat","prod","api","vpn","old","new","admin","internal","portal","mail"]
seen=set()
for line in open(sys.argv[1]):
    h=line.strip()
    if not h or "." not in h: continue
    label,_,rest=h.partition(".")
    for w in words:
        for cand in (f"{w}-{label}.{rest}", f"{label}-{w}.{rest}", f"{w}.{h}"):
            if cand not in seen: seen.add(cand); print(cand)
PY
  fi
  cat "$OUTDIR/raw/perm.txt" 2>/dev/null | merge >> "$OUTDIR/candidates.txt"
  sort -u -o "$OUTDIR/candidates.txt" "$OUTDIR/candidates.txt"
  log "[permute] candidates after permutation: $(wc -l < "$OUTDIR/candidates.txt")"
fi

# ---- resolve / validate -----------------------------------------------------
if have dnsx; then
  log "[resolve] dnsx validating $(wc -l < "$OUTDIR/candidates.txt") candidates ..."
  dnsx -l "$OUTDIR/candidates.txt" -r "$RESOLVERS" -t "$THREADS" -silent \
    -o "$OUTDIR/resolved.txt" >>"$LOG" 2>&1 || true
else
  log "[resolve] dnsx MISSING — python fallback resolver"
  python3 - "$OUTDIR/candidates.txt" > "$OUTDIR/resolved.txt" <<'PY'
import sys,socket
socket.setdefaulttimeout(3)
for line in open(sys.argv[1]):
    h=line.strip()
    if not h: continue
    try: socket.gethostbyname(h); print(h)
    except Exception: pass
PY
fi
sort -u -o "$OUTDIR/resolved.txt" "$OUTDIR/resolved.txt"
log "[*] resolvable names: $(wc -l < "$OUTDIR/resolved.txt")"

# ---- HTTP probe -------------------------------------------------------------
# Kali name-clash: /usr/bin/httpx is often the python httpx *library* CLI, not
# ProjectDiscovery's prober (shipped as httpx-toolkit). Pick the PD one.
PDHTTPX=""
for c in httpx-toolkit httpx; do
  have "$c" && "$c" -version >/dev/null 2>&1 && { PDHTTPX="$c"; break; }
done
if [ -n "$PDHTTPX" ]; then
  log "[probe] $PDHTTPX ..."
  "$PDHTTPX" -l "$OUTDIR/resolved.txt" -silent -json -o "$OUTDIR/httpx.jsonl" \
    -title -tech-detect -status-code -t "$THREADS" >>"$LOG" 2>&1 || true
  jq -r '.url' "$OUTDIR/httpx.jsonl" 2>/dev/null | sed -E 's#^https?://##; s#[:/].*##' | sort -u > "$OUTDIR/live.txt"
  log "[probe] live hosts: $(wc -l < "$OUTDIR/live.txt" 2>/dev/null || echo 0)"
else
  log "[probe] ProjectDiscovery httpx MISSING (httpx-toolkit) — skip; resolved.txt is your target set"
fi

log "[*] DONE. Feed into the auditor:"
log "    python3 $HERE/../clipeus.py --input $OUTDIR/resolved.txt --output audit.jsonl --format jsonl --accurate"
