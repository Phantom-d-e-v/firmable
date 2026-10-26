# Production design: hundreds to thousands of files a month

Everything below is sized from **measured** numbers on one file, not guesses:

| measured (one file, 16 vCPU laptop, 15 workers) | value |
|---|---|
| input | 17.6 GB zstd, 14.6M banners, ~19 h of crawl |
| ingest (decompress + parse + extract + write) | 206.6 s, ~68k banners/s |
| output | 836 MB Parquet (~21x smaller than the compressed input) |
| attribution + scoring over that Parquet | ~8 s |
| app export | 27 MB |

## Shape of the system

```
object store (raw .jsonl.zst)
   │  new-object event
   ▼
queue (one message per file) ──▶ N stateless workers: `python -m pipeline.ingest <file>`
                                   │  writes banners/file_id=…/part-*.parquet
                                   │  appends to manifest (key = name:size:mtime:vEXTRACT_VERSION)
                                   ▼
                         Parquet lake (partitioned by month / file)
                                   │  nightly (or per N files)
                                   ▼
                    build_companies (DuckDB) ─▶ companies + attributed + diffs
                                   │
                                   ▼
                    export_app ─▶ app image / object store ─▶ API (stateless, many replicas)
```

**Why this shape**
- **The unit of work is one file.** Ingest is embarrassingly parallel *across* files; inside a
  file, one reader decompresses (zstd ~1.5 GB/s, never the bottleneck) and a process pool
  parses. Scaling is therefore "more workers on the queue", with no coordination between them.
- **Idempotent by construction.** The manifest key includes the extractor version, so a crashed
  worker's retry re-does its own file (stale partition is replaced), a duplicate delivery
  is a no-op, and bumping `EXTRACT_VERSION` triggers a clean backfill.
- **Extraction and scoring are decoupled.** Raw JSON is parsed exactly once. Changing
  weights, attribution rules or noise filters is a rescoring of compact Parquet (seconds
  per file's worth), never a re-read of terabytes.
- **The serving layer holds no state.** The app ships the export and holds no state, so it scales horizontally and
  deploys are atomic (new export = new image or new object version).

## Volume and cost (1,000 files / month)

Compute: 1,000 × 206.6 s ≈ **57 hours of a 16-vCPU worker per month** (≈ 2 workers running
continuously, or 60 workers for one hour after a monthly drop).

| item | quantity / month | rate assumption (verify current pricing) | ≈ / month |
|---|---|---|---|
| ingest compute | 57 h × 16 vCPU | $0.20–0.70 per 16-vCPU-hour (spot vs on-demand ARM) | **$11–40** |
| Parquet storage | ~840 GB | ~$0.023 / GB-month object storage | ~$19 |
| scoring rebuild | one DuckDB box, minutes per day | as above | < $10 |
| raw storage | 17.6 TB if retained | lifecycle to cold storage / delete after ingest | policy choice |

The dominant cost is **keeping raw data**, not processing it. Recommendation: keep raw for a
short replay window (e.g. 30 days), keep Parquet indefinitely.

Bottlenecks in order, if volume grows 10x:
1. JSON parsing CPU. The next step is `simdjson`/Rust for the extractor (2–4x), not more machines.
2. The monthly company rebuild over ~10 TB of Parquet. Switch from "rebuild everything" to
   per-file partial aggregates (`company_partials`) merged incrementally (a map-reduce
   shape). Counts, sums, max, bool_or and distinct lists merge directly; `mode()` (org,
   country) needs per-file value counts carried in the partial, then re-ranked on merge.
3. Attribution tables (`infra_domains`, `hoster_domains`, `asn_owner`) are global. Recompute
   them on a rolling 30-day window rather than all history, so hosters can change over time.

## Turning scans into triggers (what sales actually wants)

One file is a snapshot. The value across files is **change**:
- `new_exposure`: (company, ip, port, exposure) present this week and absent last week, e.g.
  "RDP appeared on acme.com on Tuesday". That's the highest-intent trigger.
- `new_kev`: CISA adds a CVE to KEV and we already know who runs the affected product. This is
  a **re-score with no re-ingest** (CVEs are joined at scoring time).
- `cert_expiring`: already shipped (≤ 14 days).
- `remediated`: exposure disappeared. Either someone else sold them a fix (competitive
  intel) or they fixed it themselves; both are outcomes for the feedback loop.

Implementation: a `diff` table keyed on `(company_domain, ip, port, exposure|cve)` between the
latest two snapshots, surfaced in the app as a "new this week" feed and pushed to the CRM.

## Data quality and monitoring

Per-file metrics written to the manifest and alerted on drift:
`lines`, parse failures (1 in 14.6M on this file), % banners with an owner-chosen domain
(5.9%), % honeypot-tagged, % CDN, top modules. A sudden change in any of these means the
upstream format or the crawler changed, so stop scoring before it reaches sales.

Rule regressions are guarded by tests (`tests/`), the NULL-score guard in
`build_companies.py`, and the labelled eval set (`eval/`). Any change to weights or
attribution must not lower precision@25.

## Feedback loop

Hand labels are a bootstrap. In production the labels come from the CRM: meetings booked,
opportunities created, deals won and lost per account and signal. That's when the hand-set weights
become a learned model (e.g. logistic regression over the `s_*` components and raw
features, which stays explainable, retrained monthly, and is evaluated on the same precision@k).
