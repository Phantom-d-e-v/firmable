"""Agreement between two label files on the companies both labelled.

    python -m eval.agreement [eval/labels.jsonl] [eval/labels_ai.jsonl]

The AI labels are only trusted as far as they agree with a human on the overlap.
Reports raw agreement and Cohen's kappa, plus the disagreements to read by hand.
"""
from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path


def load(p: Path) -> dict[str, str]:
    return {(r := json.loads(l))["company_domain"]: r["verdict"] for l in p.open()}


def main():
    a_path, b_path = (Path(x) for x in (sys.argv[1:3] or ["eval/labels.jsonl", "eval/labels_ai.jsonl"]))
    a, b = load(a_path), load(b_path)
    both = sorted(set(a) & set(b))
    if not both:
        raise SystemExit("no overlap")
    n = len(both)
    po = sum(a[d] == b[d] for d in both) / n
    ca, cb = Counter(a[d] for d in both), Counter(b[d] for d in both)
    pe = sum(ca[v] * cb[v] for v in ca) / n ** 2
    kappa = (po - pe) / (1 - pe) if pe < 1 else float("nan")
    print(f"overlap {n}  ·  agreement {po:.1%}  ·  Cohen's kappa {kappa:.2f}")
    for d in both:
        if a[d] != b[d]:
            print(f"  {d:40s} {a_path.stem}={a[d]:12s} {b_path.stem}={b[d]}")


if __name__ == "__main__":
    main()
