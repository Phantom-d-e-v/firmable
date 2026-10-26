"""Draw a stratified, *blind* set of companies to hand-label.

    python -m eval.make_label_set [--db data/companies.duckdb] [--n 200]

Strata cover the whole score range (top, upper-mid, lower-mid, zero/negative, random),
so precision@k and "does a higher score mean a better account?" can both be measured.
The score itself is never written to the label set: the labeller sees evidence only.
Re-running appends new companies, so it never overwrites ones already labelled.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import duckdb

OUT = Path(__file__).with_name("label_set.jsonl")

STRATA = [  # (name, where-clause, share of n)
    ("top", "score_v0 >= (select quantile_cont(score_v0, 0.995) from companies)", 0.25),
    ("upper", "score_v0 >= 20 and score_v0 < (select quantile_cont(score_v0, 0.995) from companies)", 0.25),
    ("lower", "score_v0 between 1 and 19", 0.2),
    ("zero", "score_v0 <= 0", 0.15),
    ("random", "true", 0.15),
]

EVIDENCE = """
    select c.company_domain, c.org, c.country, c.cert_org, c.vertical, c.segment, c.services, c.ips,
           c.reasons, c.products, c.exposures, c.kev_cves,
           (select list(distinct http_title) filter (where http_title is not null)[1:5]
              from banners b where b.company_domain = c.company_domain) as titles,
           (select list(distinct h)[1:8] from (select unnest(hostnames) h from banners b
              where b.company_domain = c.company_domain)) as hostnames,
           (select list(distinct port)[1:12] from banners b where b.company_domain = c.company_domain) as ports
    from companies c where c.company_domain in (select unnest(?))
"""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", default="data/companies.duckdb")
    ap.add_argument("--parquet", default="data/parquet")
    ap.add_argument("--n", type=int, default=200)
    ap.add_argument("--seed", type=float, default=0.42)
    ap.add_argument("--out", type=Path, default=OUT)
    a = ap.parse_args()

    con = duckdb.connect(a.db, read_only=True)
    con.execute(f"create temp view banners as select * from read_parquet('{a.parquet}/banners/*/*.parquet')")
    con.execute(f"select setseed({a.seed})")
    have = {json.loads(l)["company_domain"] for l in a.out.open()} if a.out.exists() else set()

    picked: list[tuple[str, str]] = []
    for name, where, share in STRATA:
        k = round(a.n * share)
        rows = con.execute(
            f"select company_domain from companies where {where} "
            f"and company_domain not in (select unnest(?)) order by random() limit {k}",
            [list(have | {d for _, d in picked})]).fetchall()
        picked += [(name, r[0]) for r in rows]

    cols = [d[0] for d in con.execute(EVIDENCE, [[d for _, d in picked]]).description]
    ev = {r[0]: dict(zip(cols, r)) for r in con.execute(EVIDENCE, [[d for _, d in picked]]).fetchall()}
    with a.out.open("a") as f:
        for stratum, d in picked:
            f.write(json.dumps({"stratum": stratum, **ev[d]}, default=str) + "\n")
    print(f"+{len(picked)} companies -> {a.out} ({len(have) + len(picked)} total)")


if __name__ == "__main__":
    main()
