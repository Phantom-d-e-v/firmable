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
