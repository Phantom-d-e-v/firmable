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

| metric | value (dev machine, 16 cores) |
|---|---|
| raw → Parquet | ~125x smaller |
| throughput | ~60k banners/s (~400 MB/s raw JSON) |
| one file (~10M banners) | ~3 min _(to confirm on the full file)_ |
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

## Running locally
```bash
python -m venv .venv && .venv/bin/pip install -r requirements.txt
.venv/bin/python -m pipeline.ingest path/to/dump.jsonl.zst
.venv/bin/python -m pipeline.build_companies
.venv/bin/python -m pytest -q tests
```
