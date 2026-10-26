# Evaluation

There's no ground truth for "this company will buy cybersecurity", so I made my own and kept it honest:

1. **Blind, stratified label set** (`make_label_set.py`): ~200 companies drawn across the
   score range (top 0.5%, ≥20, 1–19, ≤0, random). The score is never shown to the labeller.
2. **Labelling** (`label_server.py`, http://127.0.0.1:8765): one account at a time with its
   evidence (signals, cert org, page titles, hostnames, ports, products, KEV CVEs). Verdicts:
   `call` / `maybe` / `no` / `not_company` (hoster, ISP, SaaS platform, the main failure mode).
   Labels are append-only in `labels.jsonl` (last one wins) and committed.
3. **Metrics** (`run.py`): precision@10/25/50 and nDCG over the labelled pool vs a random
   ordering, mean gain per score bucket (should rise with score), `not_company` count in
   the top 50, and a leave-one-component-out ablation on P@25.

```bash
.venv/bin/python -m eval.make_label_set --n 200
.venv/bin/python -m eval.label_server
.venv/bin/python -m eval.run
```

Caveats: one labeller (me), and labels judge the same evidence the score uses. So this
measures whether the weighting matches a salesperson's judgement, not whether accounts
convert. In production the label source would be CRM outcomes (meetings booked, deals won).
