"""Score the current ranking against hand labels.

    python -m eval.run [--db data/companies.duckdb]

Gain: call = 1, maybe = 0.5, no / not_company = 0. Ranking is over the labelled
pool only (the label set is stratified across the score range, so this says whether a
higher score means a better account, not absolute precision over 280k companies).
Ablation removes one score component at a time and reports the change in precision@25.
"""
from __future__ import annotations

import argparse
import json
import random
from pathlib import Path

import duckdb

LABELS = Path(__file__).with_name("labels.jsonl")
GAIN = {"call": 1.0, "maybe": 0.5, "no": 0.0, "not_company": 0.0}
KS = (10, 25, 50)


def precision_at(ranked: list[float], k: int) -> float:
    top = ranked[:k]
    return sum(top) / len(top) if top else float("nan")


def ndcg(ranked: list[float]) -> float:
    import math
    dcg = sum(g / math.log2(i + 2) for i, g in enumerate(ranked))
    ideal = sum(g / math.log2(i + 2) for i, g in enumerate(sorted(ranked, reverse=True)))
    return dcg / ideal if ideal else float("nan")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", default="data/companies.duckdb")
    ap.add_argument("--labels", type=Path, default=LABELS)
    a = ap.parse_args()

    labels = {}
    for l in a.labels.open():
        r = json.loads(l)
        labels[r["company_domain"]] = r["verdict"]  # last label wins
    con = duckdb.connect(a.db, read_only=True)
    comps = [c for (c,) in con.execute(
        "select column_name from information_schema.columns "
        "where table_name = 'companies' and column_name like 's\\_%' escape '\\'").fetchall()]
    rows = con.execute(f"select company_domain, score_v0, {', '.join(comps)} from companies "
                       f"where company_domain in (select unnest(?))", [list(labels)]).fetchall()
    scored = {r[0]: dict(zip(["score", *comps], r[1:])) for r in rows}

    # Labelled companies the current pipeline filtered out (infra rules) rank last.
    filtered = [d for d in labels if d not in scored]
    n = len(labels)
    print(f"labels: {n}  ·  " + "  ".join(f"{v}={sum(1 for x in labels.values() if x == v)}" for v in GAIN))
    print(f"filtered out by infra rules: {len(filtered)} "
          f"({sum(labels[d] == 'not_company' for d in filtered)} of them labelled not_company)")

    def rank(key) -> list[float]:
        order = sorted(scored, key=key, reverse=True) + filtered
        return [GAIN[labels[d]] for d in order]

    base = rank(lambda d: scored[d]["score"])
    rnd = [GAIN[v] for v in labels.values()]
    random.Random(0).shuffle(rnd)
    print("\n            " + "  ".join(f"P@{k:<4}" for k in KS) + "  nDCG")
    for name, r in (("score_v0", base), ("random", rnd)):
        print(f"{name:10}  " + "  ".join(f"{precision_at(r, k):.2f}  " for k in KS) + f"  {ndcg(r):.3f}")

    top50 = (sorted(scored, key=lambda d: scored[d]["score"], reverse=True) + filtered)[:50]
    print(f"\nnot_company in top 50: {sum(labels[d] == 'not_company' for d in top50)}")

    print("\nmean gain by score bucket (should rise left→right):")
    buckets = [(-99, 0), (1, 9), (10, 19), (20, 39), (40, 999)]
    for lo, hi in buckets:
        g = [GAIN[labels[d]] for d in scored if lo <= scored[d]["score"] <= hi]
        print(f"  {lo:>4}..{hi:<4} n={len(g):<4} gain={sum(g) / len(g):.2f}" if g else f"  {lo:>4}..{hi:<4} n=0")

    print("\nablation (P@25 without component; negative delta = component helps):")
    p25 = precision_at(base, 25)
    for c in comps:
        r = rank(lambda d, c=c: scored[d]["score"] - (scored[d][c] or 0))
        print(f"  -{c:15} P@25={precision_at(r, 25):.2f}  delta={precision_at(r, 25) - p25:+.2f}")


if __name__ == "__main__":
    main()
