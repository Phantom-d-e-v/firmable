# Firmable take-home: cybersecurity sales intelligence

Rank companies most likely to need cybersecurity help, from Shodan banner dumps
(zstd JSONL, ~10M banners/file, hundreds–thousands of files/month).

## Layout
- `pipeline/extract.py`: pure per-banner feature extraction (unit-tested).
- `pipeline/ingest.py`: streaming, parallel, idempotent `.zst` to Parquet (manifest in `data/parquet/_manifest.jsonl`).
- `pipeline/companies.sql` + `build_companies.py`: infra filtering, company rollup, score + reason codes (DuckDB).
- `eval/`: hand labels and evaluation (precision@k, signal ablations).
- `app/`: the hosted UI/API (serves the precomputed DuckDB/Parquet).
- `docs/data-notes.md`: what's actually in the data. Keep it updated.
- `DEVLOG.md`: timestamped log of decisions, dead ends, and AI mistakes caught.

## Conventions
- Python in `.venv` (`.venv/bin/python`); run modules as `python -m pipeline.<x>` from the repo root.
- Raw data lives outside git (`data/` is ignored). Never load a whole dump into memory; stream it.
- Every score component must emit a human-readable reason. No unexplained points.
- Read any LLM-produced labels or classifications against the hand-labelled eval set before trusting them, and log the cost.
- `pytest -q tests` before committing.
