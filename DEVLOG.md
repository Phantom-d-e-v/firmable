# Dev log

## 2026-10-27, day 1

- **00:30** Download in progress. Peeked at the partial file: zstd → JSONL → **Shodan banners**.
  Changes the whole plan: signals are technical exposure, not firmographics.
- **00:31** Profiled 100k head records (`scripts/profile_keys.py`). See `docs/data-notes.md`.
- **00:32** Throughput: zstd decompresses ~1.6 GB/s raw on one stream, so JSON parsing is the bottleneck.
- **00:33** Ingest v1 (process pool). Bug caught: `ProcessPoolExecutor.map` drains the
  whole input iterator up front, so it would hold 75 GB in RAM on the full file. Switched to a bounded
  in-flight deque. Also `hash()` is salted per process, so the file_id wasn't stable and
  idempotency was broken. Switched to sha1.
- **00:34** Browser download died at 10.6 GB and restarted. Need a resumable download.
- **00:35** Bench: 300k banners in 5.0s on 15 workers (~60k/s, ~400 MB/s raw JSON).
  2.1 GB raw → 17 MB Parquet. Full file ETA ≈ 3 min.
- **00:36** First company ranking was all ISPs (`ttnet.com.tr`, `wanadoo.fr`): PTR
  hostnames. Added `domain_source` + PTR detector + data-driven infra rule
  (PTR share, distinct orgs, owner-chosen-name share). Real SMBs now surface
  (e.g. a medical practice with an exposed DB and EOL software). Shared hosting still leaks
  through; open question.

## 2026-10-27, full file

- Download landed: 17.6 GB, not ~10.6 GB as the partial suggested. Moved data to `data-firmable/`
  and added it to `.gitignore` before anything else.
- Full ingest: 14.6M banners in 206.6s on 15 workers, 836 MB Parquet. Company build ~5s.
- Bug: `len(NULL exposures)` made `score_v0` NULL for most companies (any_signal == exposed
  was the giveaway). Fixed with `coalesce(..., [])`.
- Hosters still dominated the top. Tried ASN tenancy, which doesn't separate walmart.com (Google
  Cloud) from hosters. Co-tenancy per domain does: sakura 140, nazwa 3, mit/walmart 0.
  Added shared-IP exclusion (≥5 domains/IP) and a VPS-name rule.
- A suspicious cluster of ~998 hosts with the same WebLogic KEVs turned out to be honeypots, partly tagged.
  Now one honeypot banner drops the whole IP (90k IPs).
- Rapid Reset (CVE-2023-44487) was 173k of the KEV hits, version-inferred on nginx. KEV CVEs
  on >20k banners are now ambient. Top reasons are now pitchable: ProxyLogon,
  SharePoint ToolShell, TeamCity, Drupalgeddon, BlueKeep.

## 2026-10-27, random sample + eval harness

- Read the uniform random sample (`scripts/readable_sample.py`). New: victim-side backdoor
  modules (`ta14-353a`, `xiaongmai-backdoor`) are now `is_compromised`; `njrat`/`blackshades`
  were slipping past the C2 filter; ~25 unmapped exposure modules added (TeamViewer, X11,
  WebLogic, SAP router, PLCs, Heidenhain CNC, ...); SaaS tenant domains → infra.
- Extractor is versioned (`EXTRACT_VERSION`) in the manifest key, so logic changes re-run files.
- Score split into `s_*` components + rule-based `vertical` and `segment`.
- Bug, again: `list_sum([])` is NULL. Fixed, and `build_companies` now *fails* if any score is
  NULL. A third occurrence can't ship silently.
- Eval: blind stratified label set (200), local labelling UI, precision@k / nDCG / ablation.
  Smoke-tested with random labels (metrics ≈ random, as they should be).

## 2026-10-27, hosted app

- `pipeline/export_app.py`: 280k companies + top-25 evidence banners each → 27 MB Parquet,
  shipped in the image and loaded into in-memory DuckDB at startup.
- FastAPI (`app/main.py`): list/filter/sort, account detail with rank, stats, CSV export.
- UI (`app/static/index.html`): ranked list, account drawer, deterministic talking points.
  Caught in browser testing: talking points quoted a *hoster's* hostname sharing the IP
  (`webdisk.afs.bbk.temporary.site` for cje.net); now only hostnames under the account's domain.
- `.gitignore`'s `data/` would have silently excluded `app/data/` and shipped an app with no
  data. Scoped to `/data/`.
- Declined to install `httpx2` (unknown package suggested by an error message); tested the
  API with curl against a real server instead, and ran the app from an `app/`-only copy to
  mimic the container.

## 2026-10-27, live + attribution round 2

- Live on Render: https://breach-radar.onrender.com (all endpoints 200, <1 s warm).
- Live check exposed caloris.ro: one IP posing as backdoor + ICS + DVR + DICOM. 52k IPs
  claim ≥3 exposure classes; only 2–4% are tagged honeypots, and many sit on Incapsula edges
  that accept every port (ca.gov "exposing" ICS). Rules: exposures/compromise on CDN banners
  don't count; IPs with ≥4 classes are treated as honeypots (4,232 IPs). 3 classes is kept,
  because one Windows box with RDP+SMB+MSSQL is legitimately 3.
- Org-owned networks: first cut (dominant domain per non-cloud ASN) gave Equinix→lawyer.com,
  Orange Romania→protv.ro. Those are busiest tenants, not owners. Adding "network owner name must match
  the domain" (containment / acronym / cert O) leaves 401 ASNs (MIT, Komerční banka, Ford,
  UKG Kronos, ekom21) and +10.6k attributed banners.
- Timing signal: cert expiring ≤14 days (+3, 3,339 companies), surfaced as a talking point.
- `attributed` table: scoring and app evidence read the same rows, so they can't disagree.
- docs/production.md: queue-per-file design, cost model from measured throughput, diff-based
  triggers, monitoring, CRM feedback loop.

## 2026-10-27, verticals, API tests, write-up

- Vertical rules v2: registry TLDs first (ucsd.edu was "healthcare" because it exposes DICOM),
  then multilingual keywords over domain + cert O + network owner name (skipped for hosters/telcos).
  Hand spot-check of 90 random companies: ~80% precision. False positives fixed: "hospital" and
  German "spital" are substrings of "hospitality"; "fabrik", "chemi" ("alchemists").
  Spotted bancoitau.cf: a lookalike bank domain on a free TLD, a brand-impersonation signal for later.
- API tests run a real uvicorn on a free port (7 tests: ordering/pagination, filters, reasons
  backed by components, detail rank, errors, SQL-injection safety, CSV filters). 16 tests total.
- README written up with exact funnel numbers from the current build.
