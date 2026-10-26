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
