#!/bin/bash
# enum-bulk.sh — scalable subdomain enumeration over a LARGE apex list (thousands).
#
# Why this exists: a single `subfinder -dL huge.txt` processes domains roughly
# serially and returns nothing until the whole list is done, and a shared source
# (crt.sh) gets rate-limited (429) when many workers hit it at once. This driver
# chunks the apex list, runs a MIX of discovery sources per chunk under bounded
# parallelism and a hard per-chunk timeout, then resolves with dnsx. Output grows
# continuously and no single stalled source can hang the run.
#
# SOURCES (a mix; each is probed at startup and SKIPPED if unusable — graceful
# fallback to "basic" with whatever is present):
#   subfinder   aggregates ~30 passive sources, incl. crt.sh / CertSpotter CT
#   crt.sh      dedicated Certificate-Transparency pass (survives subfinder CT throttling)
#   amass       passive mode, best-effort (skipped if it needs sudo / is absent)
#   assetfinder best-effort (skipped if absent)
#   dnsx        validates/resolves discovered names (falls back to raw-only if absent)
# At minimum ONE discovery source must be usable, or the script exits.
#
# OUTPUTS (raw preserved for unbiased downstream analysis):
#   <out>/subdomains.txt.all   every discovered name (union of all sources, deduped) — RAW
#   <out>/subdomains.txt       dnsx-resolvable subset (validated)
#   <out>/chunks/chunk_*.{subf,crt,amass,af,raw,subs,err}  per-chunk source breakdown
#   <out>/enum-bulk.log        per-chunk progress (time, per-source counts, rc)
set -u

# ---- args / config ----------------------------------------------------------
IN=""
OUT=""
RESOLVERS_IN=""
CHUNK_SIZE=${CHUNK_SIZE:-50}
PAR=${PAR:-8}
PER_CHUNK_TIMEOUT=${PER_CHUNK_TIMEOUT:-1800}   # seconds hard cap per chunk
SUBFINDER_TIMEOUT=${SUBFINDER_TIMEOUT:-15}     # per-source timeout inside subfinder
SUBFINDER_MAXTIME=${SUBFINDER_MAXTIME:-2}      # minutes cap inside subfinder
CRTSH=${CRTSH:-1}                              # 1=do dedicated crt.sh pass, 0=skip
USE_AMASS=${USE_AMASS:-0}                      # amass passive is slow + low-yield at
                                               # scale → opt-in via --amass only
while [ $# -gt 0 ]; do
  case "$1" in
    -i|--input)  IN="$2"; shift ;;
    -o|--output) OUT="$2"; shift ;;
    --chunk)     CHUNK_SIZE="$2"; shift ;;
    --par)       PAR="$2"; shift ;;
    --resolvers) RESOLVERS_IN="$2"; shift ;;
    --no-crtsh)  CRTSH=0 ;;
    --amass)     USE_AMASS=1 ;;
    -h|--help)   grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
  shift
done
[ -n "$IN" ] && [ -r "$IN" ] || { echo "need readable --input FILE" >&2; exit 2; }
[ -n "$OUT" ] || { echo "need --output DIR" >&2; exit 2; }
mkdir -p "$OUT/chunks"
LOG="$OUT/enum-bulk.log"

# Resolvers for dnsx: the same lookup every Clipeus tool uses (brand_config.py
# --resolvers): --resolvers FILE / $CLIPEUS_RESOLVERS > brand.json > tuning >
# Cloudflare + Google. Never dnsx's own built-in list (it includes filtering resolvers).
RESOLVERS="$OUT/resolvers.txt"
if command -v python3 >/dev/null 2>&1; then
  python3 "$(dirname "$0")/../brand_config.py" --resolvers ${RESOLVERS_IN:+"$RESOLVERS_IN"} \
    > "$RESOLVERS" 2>>"$LOG" || { echo "resolver config error (see $LOG)" >&2; exit 2; }
elif [ -n "$RESOLVERS_IN" ]; then
  cp "$RESOLVERS_IN" "$RESOLVERS"
else
  printf '1.1.1.1\n1.0.0.1\n8.8.8.8\n8.8.4.4\n' > "$RESOLVERS"
fi

have() { command -v "$1" >/dev/null 2>&1; }

# ---- probe sources (graceful fallback) --------------------------------------
HAVE_SUBFINDER=0; have subfinder && HAVE_SUBFINDER=1
HAVE_ASSETFINDER=0; have assetfinder && HAVE_ASSETFINDER=1
HAVE_DNSX=0; have dnsx && HAVE_DNSX=1
HAVE_CRTSH=0; [ "$CRTSH" = 1 ] && have curl && have jq && HAVE_CRTSH=1
# amass: opt-in (slow + low-yield at scale). The Kali /usr/bin/amass is a wrapper
# that sudo-downloads libpostal on every run; call the REAL binary to skip that —
# no sudoers change needed.
HAVE_AMASS=0; AMASS_BIN=""
if [ "$USE_AMASS" = 1 ]; then
  for cand in /usr/lib/amass/amass "$(command -v amass 2>/dev/null)"; do
    [ -n "$cand" ] && [ -x "$cand" ] || continue
    if timeout 20 "$cand" -version </dev/null >/dev/null 2>&1; then
      AMASS_BIN="$cand"; HAVE_AMASS=1; break
    fi
  done
fi

SRC_SUMMARY="subfinder=$HAVE_SUBFINDER crt.sh=$HAVE_CRTSH amass=$HAVE_AMASS assetfinder=$HAVE_ASSETFINDER | resolve: dnsx=$HAVE_DNSX"
if [ $((HAVE_SUBFINDER+HAVE_CRTSH+HAVE_AMASS+HAVE_ASSETFINDER)) -eq 0 ]; then
  echo "FATAL: no usable discovery source (need at least one of subfinder/crt.sh/amass/assetfinder)" >&2
  exit 3
fi

# ---- normalise input (EARLY) then split into chunks -------------------------
rm -f "$OUT/chunks"/chunk_* 2>/dev/null
APEXES="$OUT/chunks/_apexes.txt"
# Prefer clipeus --normalize-only: repairs mojibake, IDN->punycode (xn--),
# strips scheme/path/port, dedupes, and quarantines un-encodable lines to
# <file>.review — subfinder/dnsx need A-labels, so raw mojibake would no-op.
# Falls back to a basic shell normalise if clipeus is unavailable.
CLIPEUS_PY="${CLIPEUS_PY:-}"
if [ -z "$CLIPEUS_PY" ]; then
  for cand in "$(dirname "$0")/../clipeus.py" \
              "$HOME/github/Clipeus/clipeus.py"; do
    [ -r "$cand" ] && { CLIPEUS_PY="$cand"; break; }
  done
fi
if [ -n "$CLIPEUS_PY" ] && command -v python3 >/dev/null 2>&1; then
  python3 "$CLIPEUS_PY" --input "$IN" --normalize-only --output "$APEXES" 2>>"$LOG" || \
    { echo "$(date +%T) normalize-only failed; falling back to basic normalise" | tee -a "$LOG"; CLIPEUS_PY=""; }
fi
if [ -z "$CLIPEUS_PY" ] || [ ! -s "$APEXES" ]; then
  grep -vE '^\s*(#|$)' "$IN" | tr 'A-Z' 'a-z' | awk '{$1=$1};1' | sort -u > "$APEXES"
fi
NREVIEW=$( [ -f "$APEXES.review" ] && wc -l < "$APEXES.review" || echo 0 )
split -l "$CHUNK_SIZE" -d -a 4 "$APEXES" "$OUT/chunks/chunk_"
NCHUNKS=$(ls "$OUT/chunks"/chunk_[0-9]* 2>/dev/null | grep -v '\.' | wc -l)
NAPEX=$(wc -l < "$OUT/chunks/_apexes.txt")
echo "$(date +%T) START | $NAPEX apexes ($NREVIEW un-encodable->review) | $NCHUNKS chunks of $CHUNK_SIZE | par=$PAR | timeout=${PER_CHUNK_TIMEOUT}s | sources: $SRC_SUMMARY" | tee -a "$LOG"

# ---- per-chunk worker -------------------------------------------------------
# crt.sh for one domain, resilient: retry on 429/empty with backoff, non-fatal.
crtsh_one() {
  # Fast-fail so a throttled crt.sh can't blow the per-chunk budget: 2 tries,
  # 10s cap each, 2s backoff → ≤~24s worst case per domain, usually <2s.
  local d="$1" tries=0 out
  while [ $tries -lt 2 ]; do
    out=$(curl -s --max-time 10 "https://crt.sh/?q=%25.${d}&output=json" 2>/dev/null \
          | jq -r '.[].name_value' 2>/dev/null | tr 'A-Z' 'a-z' | sed 's/^\*\.//' \
          | grep -E "(^|\.)${d//./\\.}$" )
    if [ -n "$out" ]; then echo "$out"; return 0; fi
    tries=$((tries+1)); sleep 2
  done
  return 0
}
export -f crtsh_one

run_chunk() {
  local c="$1" name t0 t1 rc=0
  name=$(basename "$c"); t0=$(date +%s)
  : > "$c.raw"

  # subfinder (its own source mix, incl CT)
  if [ "$HAVE_SUBFINDER" = 1 ]; then
    subfinder -dL "$c" -silent -timeout "$SUBFINDER_TIMEOUT" -max-time "$SUBFINDER_MAXTIME" \
      -o "$c.subf" </dev/null >/dev/null 2>>"$c.err" || true
    [ -f "$c.subf" ] && cat "$c.subf" >> "$c.raw"
  fi
  # dedicated crt.sh pass (sequential within the chunk → gentle on crt.sh)
  if [ "$HAVE_CRTSH" = 1 ]; then
    : > "$c.crt"
    while read -r d; do [ -n "$d" ] && crtsh_one "$d" >> "$c.crt"; done < "$c"
    cat "$c.crt" >> "$c.raw"
  fi
  # amass passive (best-effort; only if probed usable)
  if [ "$HAVE_AMASS" = 1 ]; then
    : > "$c.amass"
    while read -r d; do
      [ -n "$d" ] && timeout 90 "$AMASS_BIN" enum -passive -d "$d" -silent </dev/null 2>>"$c.err" >> "$c.amass"
    done < "$c"
    cat "$c.amass" >> "$c.raw"
  fi
  # assetfinder (best-effort)
  if [ "$HAVE_ASSETFINDER" = 1 ]; then
    : > "$c.af"
    while read -r d; do [ -n "$d" ] && assetfinder --subs-only "$d" </dev/null 2>>"$c.err" >> "$c.af"; done < "$c"
    cat "$c.af" >> "$c.raw"
  fi

  # dedupe this chunk's raw union (per-source files survive even if a later
  # source timed out — resolution happens ONCE at merge, not per chunk)
  sort -u -o "$c.raw" "$c.raw"
  t1=$(date +%s)
  local nr; nr=$(wc -l < "$c.raw" 2>/dev/null || echo 0)
  echo "$(date +%T) done $name | $((t1-t0))s | raw=$nr | rc=$rc" | tee -a "$LOG"
}
# dispatcher: apply the hard per-chunk timeout, never let one failure abort the pool
_dispatch() { timeout "$PER_CHUNK_TIMEOUT" bash -c 'run_chunk "$1"' _ "$1" || true; }
export -f run_chunk crtsh_one _dispatch
export HAVE_SUBFINDER HAVE_CRTSH HAVE_AMASS HAVE_ASSETFINDER HAVE_DNSX AMASS_BIN
export SUBFINDER_TIMEOUT SUBFINDER_MAXTIME PER_CHUNK_TIMEOUT LOG

# run with bounded parallelism; hard timeout per chunk
find "$OUT/chunks" -maxdepth 1 -type f -name 'chunk_[0-9][0-9][0-9][0-9]' -print0 \
  | xargs -0 -P "$PAR" -I{} bash -c '_dispatch "$1"' _ {}

# ---- merge + single resolution pass ----------------------------------------
# RAW = union of every source across all chunks (unbiased discovery record).
cat "$OUT/chunks"/chunk_*.raw 2>/dev/null | sort -u > "$OUT/subdomains.txt.all"
NRAW=$(wc -l < "$OUT/subdomains.txt.all")
echo "$(date +%T) RAW MERGED | raw=$NRAW" | tee -a "$LOG"
# VALIDATED = dnsx over the whole raw set in one pass (dnsx handles large lists
# efficiently; keep the unresolvable names in .all for takeover/dangling analysis).
if [ "$HAVE_DNSX" = 1 ] && [ "$NRAW" -gt 0 ]; then
  echo "$(date +%T) resolving $NRAW names with dnsx ..." | tee -a "$LOG"
  dnsx -l "$OUT/subdomains.txt.all" -r "$RESOLVERS" -silent </dev/null 2>>"$LOG" | sort -u > "$OUT/subdomains.txt"
else
  cp "$OUT/subdomains.txt.all" "$OUT/subdomains.txt"
fi
echo "$(date +%T) ALL DONE | raw=$NRAW validated=$(wc -l <"$OUT/subdomains.txt")" | tee -a "$LOG"
