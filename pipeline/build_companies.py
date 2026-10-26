"""Build the company table from banner Parquet.

    python -m pipeline.build_companies [--parquet data/parquet] [--db data/companies.duckdb]

Re-scoring is cheap: it reads the compact banner Parquet, never the raw dumps.
"""
from __future__ import annotations

import argparse
import time
from pathlib import Path

import duckdb

SQL = Path(__file__).with_name("companies.sql")


def build(parquet: Path, db: Path) -> None:
    t0 = time.time()
    con = duckdb.connect(str(db))
    con.execute(f"create or replace view banners as select * from "
                f"read_parquet('{parquet}/banners/*/*.parquet', hive_partitioning=true, union_by_name=true)")
    con.execute(SQL.read_text())
    n = con.execute("select count(*) from companies").fetchone()[0]
    print(f"companies: {n:,} in {time.time() - t0:.1f}s -> {db}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--parquet", type=Path, default=Path("data/parquet"))
    ap.add_argument("--db", type=Path, default=Path("data/companies.duckdb"))
    a = ap.parse_args()
    build(a.parquet, a.db)


if __name__ == "__main__":
    main()
