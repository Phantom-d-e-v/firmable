# Cybersecurity Sales Intelligence

> Which businesses need cybersecurity help right now, and why?

**Live app:** _TBD_ · **Write-up:** this file · **Data notes:** [docs/data-notes.md](docs/data-notes.md) · **Dev log:** [DEVLOG.md](DEVLOG.md)

## The data
The input is a Shodan banner export: each line is one internet-facing service on one IP:port.
That makes the signal *observed exposure*, which a salesperson can quote back to the prospect:
"your RDP is open to the internet", "your firewall runs a version on CISA's exploited list".

## Pipeline

```
.jsonl.zst ──stream──▶ batch ──process pool──▶ extract (per banner) ──▶ Parquet (partitioned by file)
                                                                      │
                     manifest (idempotent, re-runs are no-ops) ◀──────┘
Parquet ──DuckDB──▶ infra filtering ─▶ company rollup ─▶ score + reason codes ─▶ app
```

| metric | value (dev machine, 16 cores, 15 workers) |
|---|---|
| input | 17.6 GB zstd, 14.6M banners, 5.0M IPs, ~19 h crawl window |
| ingest | **206.6 s** (~68k banners/s) |
| output | 836 MB Parquet (~21x smaller than the compressed input) |
| company build + scoring | ~5 s for 280k companies |
| 1,000 files/month | _TBD: $ estimate_ |

## Signals
_TBD: need × fit × timing × reachability, each with evidence._

## Scoring
_TBD: v0 is transparent weights with reason codes (`pipeline/companies.sql`)._

## How I know it works
_TBD: hand-labelled set, precision@k, ablations, LLM accuracy + cost._

## Key decisions & trade-offs
_TBD_

## What I'd do next
_TBD_

## The app
FastAPI + one static page, serving `app/data/*.parquet` (27 MB, exported by
`pipeline/export_app.py`) from in-memory DuckDB. No database server; list queries ~40 ms.

- **Ranked accounts** with filters (vertical, size, country, exposed service, signal),
  sortable, deep-linkable (filters live in the URL), CSV export.
- **Account view**: deterministic talking points built from the evidence (no LLM, so no
  hallucinated CVEs), score breakdown per component, and the top 25 services as proof.

## Running locally
```bash
python -m venv .venv && .venv/bin/pip install -r requirements.txt
.venv/bin/python -m pipeline.ingest path/to/dump.jsonl.zst   # raw → Parquet (idempotent)
.venv/bin/python -m pipeline.build_companies                  # attribution + scoring
.venv/bin/python -m pipeline.export_app                       # slim dataset for the app
.venv/bin/uvicorn app.main:app --port 8000                    # http://127.0.0.1:8000
.venv/bin/python -m pytest -q tests
```

## Deploying
`Dockerfile` builds only `app/` (code + Parquet). On Render: New → Blueprint → this repo
(`render.yaml`, free plan, health check `/healthz`). Any container host works the same way.
