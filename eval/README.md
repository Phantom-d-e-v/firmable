# Evaluation

There's no ground truth for "this company will buy cybersecurity", so I made my own and kept it honest:

1. **Blind, stratified label set** (`make_label_set.py`): ~200 companies drawn across the
   score range (top 0.5%, ≥20, 1–19, ≤0, random). The score is never shown to the labeller.
2. **Labelling** (`label_server.py`, http://127.0.0.1:8765): one account at a time with its
   evidence (signals, cert org, page titles, hostnames, ports, products, KEV CVEs). Verdicts:
   `call` / `maybe` / `no` / `not_company` (hoster, ISP, SaaS platform, the main failure mode).
   Labels are append-only in `labels.jsonl` (last one wins).
3. **Metrics** (`run.py`): precision@10/25/50 and nDCG over the labelled pool vs a random
   ordering, mean gain per score bucket (should rise with score), `not_company` count in
   the top 50, and a leave-one-component-out ablation on P@25.

```bash
.venv/bin/python -m eval.make_label_set --n 200
.venv/bin/python -m eval.label_server
.venv/bin/python -m eval.run
```

## Labels used here: `labels_ai.jsonl`

The 200 labels were made by Claude (Opus 5.5, in the coding session, no API spend), not
by a human. To keep them as honest as possible:

- **Blind**: cards were shown without stratum or score, in a shuffled order, with the same
  fields the labelling UI shows.
- **Rubric written first**: *call* means a real organisation with a specific, quotable issue
  (backdoor, KEV on a real app or edge device, exposed DB/RDP/ICS). *maybe* means a real
  business with a weaker or version-inferred signal. *no* means personal, parked or hobby
  sites, or nothing meaningful. *not_company* means a hoster, ISP, SaaS tenant or wrong attribution.
- **Re-checked**: a second blind pass in a new order (`labels_ai_pass2.jsonl`) agreed on
  199/200. The one disagreement was resolved and is noted in the label.
- **Human rater** (`labels_human.jsonl`, 23 labels, urgent-need question): 48% exact
  (kappa 0.28), 70% on worth-contacting (kappa 0.44); v1 on these labels P@10 0.80, nDCG 0.95
  (random 0.52 / 0.80). `labels_human_lead.jsonl` is an earlier batch of 21 that answered
  "is this a lead at all?", kept for the record. `labels.jsonl` is the raw label-server log of both.
- **Second rater** (`labels_rater.jsonl`): a fresh-context AI agent, prompted as a founder
  judging for a sales team, given only the UI fields for 30 stratified companies. Agreement:
  47% exact (kappa 0.18), 80% on worth-contacting (kappa 0.59). v1 on its labels: P@10 0.85,
  nDCG 0.97 (random 0.35 / 0.69).
- **Circularity risk**: the same agent wrote the scoring rules. The labels did disagree with
  them (EPSS, EOL and TLS hygiene hurt precision under v0), but that doesn't replace a human.
  So `agreement.py` measures it: label any subset with `label_server.py`, which writes
  `labels.jsonl`, then run `python -m eval.agreement` for Cohen's kappa and the disagreements.

```bash
.venv/bin/python -m eval.run --labels eval/labels_ai.jsonl
```

Caveats: one labeller, and labels judge the same evidence the score uses. So this
measures whether the weighting matches a salesperson's judgement, not whether accounts
convert. In production the label source would be CRM outcomes (meetings booked, deals won).
