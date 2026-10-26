"""Streaming, parallel, idempotent ingestion of Shodan .jsonl.zst dumps into Parquet.

    python -m pipeline.ingest <file.zst|file.jsonl> [--out data/parquet] [--workers N] [--limit N]

Design (so one file or a thousand a month look the same):
  * one reader streams-decompresses (zstd ~1.5 GB/s raw) and cuts line batches;
  * a process pool parses + extracts features (JSON parsing is the bottleneck);
  * each worker writes its own Parquet part -> no big objects shipped back;
  * a manifest keyed by (name, size, mtime) makes re-runs no-ops, so the same
    command can be pointed at a bucket listing by a scheduler / queue consumer.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import sys
import time
from collections import deque
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

import polars as pl
import zstandard

from pipeline.extract import extract_line

BATCH_LINES = 20_000


def _iter_batches(path: Path, limit: int | None):
    raw = open(path, "rb")
    stream = zstandard.ZstdDecompressor().stream_reader(raw, read_size=1 << 22) if path.suffix == ".zst" else raw
    text = io.BufferedReader(stream, buffer_size=1 << 24)
    batch, n = [], 0
    for line in text:
        batch.append(line)
        n += 1
        if len(batch) >= BATCH_LINES:
            yield batch
            batch = []
        if limit and n >= limit:
            break
    if batch:
        yield batch
    raw.close()


def _process(args) -> tuple[int, int]:
    batch, out_path, file_id = args
    rows = [r for r in map(extract_line, batch) if r is not None]
    for r in rows:
        r["file_id"] = file_id
    if rows:
        pl.DataFrame(rows, infer_schema_length=None).write_parquet(out_path, compression="zstd")
    return len(batch), len(rows)


def file_key(path: Path) -> str:
    st = path.stat()
    return f"{path.name}:{st.st_size}:{int(st.st_mtime)}"


def ingest(path: Path, out: Path, workers: int, limit: int | None = None) -> dict:
    manifest = out / "_manifest.jsonl"
    key = file_key(path)
    if manifest.exists() and any(json.loads(l)["key"] == key for l in manifest.open()):
        print(f"skip (already ingested): {key}")
        return {}
    file_id = hashlib.sha1(key.encode()).hexdigest()[:10]
    part_dir = out / "banners" / f"file_id={file_id}"
    part_dir.mkdir(parents=True, exist_ok=True)

    t0, seen, kept = time.time(), 0, 0
    # Bounded in-flight queue: Executor.map would drain the whole 75 GB iterator up front.
    with ProcessPoolExecutor(workers) as pool:
        inflight: deque = deque()
        for i, batch in enumerate(_iter_batches(path, limit)):
            inflight.append(pool.submit(_process, (batch, part_dir / f"part-{i:06d}.parquet", file_id)))
            if len(inflight) >= workers * 2:
                s, k = inflight.popleft().result()
                seen, kept = seen + s, kept + k
                if seen % 500_000 < BATCH_LINES:
                    print(f"  {seen:>11,} lines  {seen / (time.time() - t0):,.0f} lines/s", file=sys.stderr)
        for fut in inflight:
            s, k = fut.result()
            seen, kept = seen + s, kept + k
    stats = {"key": key, "file_id": file_id, "lines": seen, "rows": kept,
             "seconds": round(time.time() - t0, 1), "workers": workers, "limit": limit}
    if not limit:  # partial runs are dev runs; don't mark the file done
        with manifest.open("a") as f:
            f.write(json.dumps(stats) + "\n")
    print(json.dumps(stats))
    return stats


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("path", type=Path)
    ap.add_argument("--out", type=Path, default=Path("data/parquet"))
    ap.add_argument("--workers", type=int, default=max(1, (os.cpu_count() or 2) - 1))
    ap.add_argument("--limit", type=int)
    a = ap.parse_args()
    ingest(a.path, a.out, a.workers, a.limit)


if __name__ == "__main__":
    main()
