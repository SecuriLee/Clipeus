# CLAUDE.md — operating Clipeus

Guidance for Claude / agents working in this repo. Read before changing or running anything.

## What this is
Clipeus is an **external attack-surface audit & subdomain-enumeration toolkit**. Given apex domains or hosts it produces a per-host security record (DNS, TLS/cert, mail authentication, HTTP/content, hosting, subdomain-takeover posture). Entry point: `clipeus.py` (or the `./clipeus` wrapper, or `clipeus` after `pip install -e .`).

## The intended workflow (three stages — assume all three)
1. **Enumerate** (breadth, a *mix* of tools — never one source): `recon/enum-bulk.sh -i apexes.txt -o out/enum` runs subfinder (~30 passive sources incl. CT) + a dedicated crt.sh pass + optional amass/assetfinder + dnsx validation, chunked/parallel, each source skipped if absent.
2. **Audit**: build targets from the apexes plus the *raw* enumeration output (non-resolving names are the takeover candidates): `cat apexes.txt out/enum/subdomains.txt.all | sort -u > out/targets.txt`, then `clipeus --input out/targets.txt --output out/audit.jsonl --format jsonl --raw-dir out/evidence`. Resolvers come from the shared lookup; only pass `--resolvers FILE` to override.
3. **Analyse** (human or AI/Claude CLI): read the JSONL. It is **raw and not pre-scored for you** — it records observed facts plus the tool's own `risk_score` as *one column*. Re-derive severity independently; do **not** inherit `risk_score` as truth. Verify any takeover/critical by hand (`dig`/`openssl`) before reporting it.

## Running it
- `clipeus --help` — all flags. `clipeus --version` → CalVer. `clipeus --selftest` — internal checks (run this after any code change; it must print `ALL PASS`).
- `clipeus --show-config` — prints the effective merged configuration as JSON (use for introspection before a run).
- Pipeline: `subfinder -dL scope.txt -silent | clipeus --input - --output - --format jsonl | jq ...`; `--emit <artifact> --emit-file -` streams one artifact type; `--ingest nuclei.jsonl --ingest httpx.json` folds external results back in.
- Big lists: chunk via `recon/enum-bulk.sh`, don't run one giant `subfinder -dL`.

## Configuration (policy lives OUTSIDE the code)
Precedence, highest first: **CLI flags** → **brand/engagement config** (`--config` / `$CLIPEUS_CONFIG` / `brand.json` beside `clipeus.py` / `~/.config/clipeus/brand.json`) → **tuning file** (`$CLIPEUS_TUNING` / `clipeus.tuning.json` / `~/.config/clipeus/tuning.json`) → **in-code defaults** (always runs standalone). Examples to copy: `brand.example.json`, `clipeus.tuning.example.json`.

## DNS integrity (important)
Resolve with **unfiltered** resolvers only — default is Cloudflare + Google (`1.1.1.1/1.0.0.1/8.8.8.8/8.8.4.4`). Never use a filtering/NXDOMAIN-rewriting resolver: it masks the dangling-delegation and takeover conditions the audit exists to find.
DNS is **one configuration item for every tool**: all Python tools call `brand_config.effective_resolvers()` and the shell scripts call `python3 brand_config.py --resolvers` (passed to `dnsx -r`). Precedence: `--resolvers FILE` / `$CLIPEUS_RESOLVERS` > `brand.json` `resolvers` > tuning `dns_servers` > default. Never hardcode a resolver list in a script; never let `dnsx` fall back to its built-in list.

## Versioning
Single source of truth: `__version__` in `clipeus.py` (CalVer `YY.MM.patch`). The banner, `--version`, User-Agent strings, and `pyproject.toml` (dynamic `attr = "clipeus.__version__"`) all read it. **To bump: change that one line, then re-tag** (`git tag -a vYY.MM.patch`). Don't hardcode a version anywhere else.

## Guardrails (do not violate)
- **Never commit** `brand.json` or `clipeus.tuning.json` (real engagement policy; gitignored). Only the `*.example.json` files are tracked.
- **Keep the code brand-neutral**: no client names, real client domains, personal paths (`/home/...`), or emails in code, comments, examples, or test fixtures. Use `example.com` and generic strings.
- **Authorized use only**: scan only targets the user owns or has explicit written permission to assess. The audit stage is *active* (HTTP/TLS connections, a top-ports scan by default, AXFR attempts) — never add targets on your own initiative (e.g. third-party hosts discovered in results, CDNs, providers), and if scope is unclear, ask before running. Enumeration here is passive; don't add intrusive/exploitation behaviour by default.
- **Outputs are confidential**: audit results (`*.jsonl`, `*.csv`, `evidence/`) stay local and gitignored — never push them or upload to shared/public hosting.
- Before any commit, run `clipeus --selftest` and scan the diff for the above leaks.

## Layout
```
clipeus.py                     entrypoint; __version__ lives here
brand_config.py  classify.py   support modules
brand.example.json             example engagement policy (copy -> brand.json)
clipeus.tuning.example.json    example operational tuning (copy -> clipeus.tuning.json)
clipeus                        venv-aware launcher
pyproject.toml  requirements.txt
recon/                         enum-bulk.sh + crtsh/nsec3/wildcard/posture helpers
```
