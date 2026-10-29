# Breach Radar: cybersecurity sales intelligence

> Out of millions of internet-facing machines, which **companies** need cybersecurity help
> right now, why, and what does the rep say on the first call?

**Live app:** https://breach-radar.onrender.com (free tier, so the first load after idle takes ~30–60 s)
· **Data notes:** [docs/data-notes.md](docs/data-notes.md) · **Production design & cost:** [docs/production.md](docs/production.md)
· **Evaluation:** [eval/](eval/README.md) · **Dev log:** [DEVLOG.md](DEVLOG.md)

## How a rep uses it

B2B prospecting is "who do I call, and what do I open with". So every account comes with **evidence a
rep can quote**, never just a number:

- **"Who's on fire?"** Filter *Backdoor detected* (160 companies with an implant signature on a
  host) or *Known-exploited CVE* (6,512). Open with incident response.
- **"Work my territory."** Filter by vertical, size (SMB / mid-market / enterprise) and country, sort by
  priority, export CSV to the CRM.
- **"Give me a reason to call this week."** *Cert expiring ≤14 days* (3,339 companies) is a soft opener.
- **Account view.** Talking points generated deterministically from the evidence, e.g.
  *"webmail.cje.net:443 runs Outlook Web App affected by CVE-2021-34523 (ProxyShell) and 6 more, on
  CISA's Known Exploited Vulnerabilities list"*, plus a score breakdown and the 25 most relevant services.

## The data, and why reading it by hand mattered

The file is a **Shodan banner export**: 17.6 GB zstd JSONL, **14.6M services on 5.0M IPs**, ~19 hours of
crawl. One line = one service on one IP:port, with HTTP/TLS details, product fingerprints and CVEs
annotated with **CVSS, EPSS and CISA KEV**.

The obvious approach (group by domain, count CVEs) produces a ranking of **ISPs, hosting companies and honeypots**.
Almost all the work was separating real companies and real risk from that noise. Each
trap below was found by reading records and checking numbers, and each is now a rule with a count:

| trap | what naive analysis concludes | rule | removed |
|---|---|---|---|
| `org` is the **network owner** (Cloudflare, Google, Incapsula), not the company | "Google is the riskiest company" | attribute by cert CN / HTTP Host the company chose | — |
| reverse-DNS hostnames name the **ISP** | ttnet.com.tr, wanadoo.fr are top prospects | PTR-pattern detector + domain provenance | 59,570 infra domains (all rules) |
| **hosting providers' customers** inherit the provider's name | sakura.ne.jp has 886 KEVs | co-tenancy: a domain naming machines whose certs belong to *other* companies is a hoster | 527 hosters |
| **shared IPs** (1 IP, 1,000 sites) | every tenant "exposes FTP" | IPs with ≥5 domains are unattributable | 2,642 IPs |
| **SaaS tenants** (`x.myshopify.com`) | the platform is the prospect | platform domains → infra | — |
| **honeypots**, only partly tagged | a 1k-host AWS cluster "runs every WebLogic KEV" | one honeypot banner drops the IP | 90,476 IPs |
| **multi-persona IPs** | one IP is a backdoor + PLC + DVR + DICOM server | ≥4 unrelated exposure classes ⇒ honeypot | 4,232 IPs |
| **CDN edges answer every port** | ca.gov "exposes ICS" | exposures on CDN banners don't count | — |
| **attacker C2 servers** (RATs) | "remcos-pro-rat" hosts are victims | C2 modules excluded | 78,630 banners |
| **version-inferred KEVs everywhere** | 38k companies "run known-exploited CVEs" | KEVs on >20k banners are ambient (e.g. HTTP/2 Rapid Reset on every nginx) | 3 CVEs → 6.5k companies |

And signals that only show up when you read records yourself:
- **Backdoor modules flag victims, not attackers**: `ta14-353a` (the Sony-hack implant from the US-CERT
  alert) and `xiaongmai-backdoor`. These are the strongest "call now" signal in the file.
- **Exposed services that reveal the vertical**: DICOM (41k medical imaging servers), automated
  tank gauges (28k, fuel retail), Heidenhain CNC (`lsv2`, manufacturing), BACnet, PLCs.
- **84% of banners carry no domain.** When a network (ASN) belongs to the company itself *and*
  its registered name matches the domain (MIT's AS3, Komerční banka, Ford), its unnamed IPs are
  attributed too. The name check is what rejects "Equinix → lawyer.com, its busiest tenant".
- **Exposed AI infrastructure** (≈3.5k Ollama, 428 MCP servers): small now, but a 2026 attack surface.

Funnel: 14.6M banners → 2.26M with any domain → **669k attributed to 280,380 companies** →
106k with at least one signal → **442 hot (score ≥ 20)**: 355 SMB, 58 mid-market, 29 enterprise.
(Under v0 weights it was 7,971 hot. The eval below shows most of those were noise.)

## Scoring

Transparent weights, one column per component (`pipeline/companies.sql`), so each one can be
explained to a rep and ablated in evaluation:

| component | points | why it predicts buying |
|---|---|---|
| backdoor / implant detected | +25 | already compromised: incident-response budget appears overnight |
| known-exploited CVEs (CISA KEV) | +8 each, max 5 | attackers are using these today; often a compliance deadline |
| the two ubiquitous version-inferred KEVs (jQuery XSS CVE-2020-11023, Apache local privesc CVE-2019-0211) | +3 once | real, but not remote initial access; on ~3.5k banners each |
| exposed ICS / medical | +10 | regulated, high-impact, rarely staffed for security |
| exposed remote access, DBs, app servers, VPN/edge, DevOps | +8 | the top initial-access vectors for ransomware |
| exposed file shares, router admin, door/time clocks | +6 | |
| exposed cameras, printers | +3 | low value alone, but a hygiene tell |
| EPSS ≥ 50% | +3 | tie-breaker (was +10; see eval) |
| end-of-life software | +2 | tie-breaker (was +6): inferred from version banners |
| TLS hygiene (expired/self-signed, TLS 1.0/1.1) | up to +2 | tie-breaker (was up to +7) |
| certificate expiring ≤14 days | +3 | **timing**: a reason to call this week |
| security.txt, or everything behind a CDN | −5 each | already invested: lower need |

**Fit** is a separate axis, not mixed into need: vertical (rules: registry TLDs first, then
multilingual keywords over the domain, cert organisation and owner name, then exposed-service type)
and size (IPs observed). A rep filters on fit and sorts on need.

## How I know it works

There's no ground truth for "will buy", so I built one and kept it honest ([eval/](eval/README.md)):

- **Blind, stratified hand labels**: 200 companies across the score range (top 0.5%, ≥20, 1–19, ≤0,
  random), labelled *call / maybe / no / not-a-company* in a local UI that hides the score.
  `not_company` exists because mis-attribution (hosters posing as companies) is the main failure mode.
- **Metrics**: precision@10/25/50 and nDCG vs random ordering, mean gain per score bucket
  (must rise with score), `not_company` count in the top 50, leave-one-component-out ablation.
- **Who labelled**: Claude, blind to score and stratum, against a rubric written before
  labelling (no API spend; it ran in the coding session). The same agent wrote the rules, so
  this is circular by construction. [`eval/agreement.py`](eval/agreement.py) measures agreement
  with any human-labelled subset (Cohen's kappa plus the disagreements). It's the first thing
  I'd run before trusting these numbers further.
- **Re-check**: a second blind pass over all 200 in a new order matched the first on 199/200
  (the one change is applied). That checks consistency and bookkeeping. It isn't an independent rater.
- **Second rater**: a fresh-context AI agent, prompted as a founder judging for a sales team, saw
  only the labelling-UI fields for a stratified 30, with no rubric and no other labels
  ([`eval/labels_rater.jsonl`](eval/labels_rater.jsonl)). It is still not a human.
  - Exact 4-way agreement: 47% (kappa 0.18).
  - "Worth contacting" (call/maybe vs no/not-company): 24/30 (kappa 0.59).
  - The disagreements are calibration. The rater is more generous (47% worth contacting vs 27%),
    and it labels personal sites *not_company* where I used *no*.
  - On its labels, v1 still ranks well: P@10 0.85 vs 0.35 random, nDCG 0.97 vs 0.69.
  - So the *ordering* holds across raters even where the threshold differs. That's why the app
    sorts by score rather than relying on one cut-off.
- **Results** (200 labels: 9 call, 40 maybe, 141 no, 10 not-a-company; ties scored as the
  expected value over random tie-breaks, random = mean of 1,000 shuffles):

  | | P@10 | P@25 | P@50 | nDCG | gain by bucket ≤0 / 1–9 / 10–19 / ≥20 |
  |---|---|---|---|---|---|
  | random | 0.14 | 0.14 | 0.15 | 0.59 | |
  | v0 (hand-set weights) | 0.30 | 0.40 | 0.39 | 0.86 | 0.01 / 0.03 / 0.00 / 0.27 |
  | **v1 (after ablation)** | **0.65** | **0.48** | **0.41** | **0.95** | 0.01 / 0.13 / 0.41 / 0.61 |

  The ablation was the useful part. Under v0, **removing** EPSS (+0.04 P@25), EOL (+0.06) or TLS
  hygiene (+0.07) *improved* the ranking. They fire on version banners of tiny personal sites,
  which drowned out the KEV, backdoor and exposure signals that did help. v1 demotes them to
  tie-breakers, and gain now rises monotonically with score. Caveat: v1 was tuned on the same
  200 labels, so the v1 row is optimistic. The changes were kept coarse (three weights, one
  CVE list) to limit overfitting, and a fresh label set is the honest test.
- **Remaining failure mode**: 5 of the top 50 are still *not_company* (a VoIP reseller, a web
  agency's shared server, a dynamic-DNS service, an IoT vendor's default cert on customer routers).
  That's the next attribution rule to write.
- **Vertical rules spot-check**: 90 random companies (15 per vertical) read by hand: ~80%
  precision (government best at 14/15, industrial weakest at ~10/15). The false-positive patterns
  found ("hospital" inside "hospitality", "fabrik" in an IT firm's name) were fixed.
- **Guards**: 16 tests (extraction rules, API behaviour incl. SQL-injection safety and "every
  reason shown has a score component behind it"), and the build **fails** if any score is NULL
  (this bug happened twice during development; see the dev log).

## Key decisions and trade-offs

- **Rules, not a model (yet).** No outcome labels exist, so a learned model would just fit my
  intuitions with less transparency. Every rule has a count and a reason; the eval decides whether it stays.
  The production path to a model (CRM outcomes → logistic regression over the same components) is in
  [docs/production.md](docs/production.md).
- **No LLM at runtime.** Talking points are built from evidence with templates, so they can't
  hallucinate a CVE in front of a prospect. Where an LLM would earn its cost: classifying the 94%
  "other" vertical long tail from page titles and cert organisations, measured against the hand labels
  with cost per 1,000 companies logged. Not done here (no API key in scope); the eval harness is ready for it.
- **Precision over coverage in attribution.** Every rule above throws real companies away
  (e.g. an SMB on a shared IP). A rep calling a hosting provider about "their" vulnerability burns trust
  faster than a missed account costs.
- **DuckDB + Parquet, no database server.** One file ingests in 3.4 min on a laptop; rescoring takes
  ~10 s; the app ships a 27 MB export. That's the right size for one month of data and still
  correct at 1,000 files/month with the queue-per-file design.
- **Extraction is versioned.** `EXTRACT_VERSION` is part of the ingest manifest key, so a logic change
  re-runs files and re-runs of unchanged files do nothing.

## Pipeline and scale

```
.jsonl.zst ──stream──▶ batches ──process pool──▶ extract (per banner) ──▶ Parquet (per file)
                                                     manifest (idempotent, versioned) ◀──┘
Parquet ──DuckDB──▶ attribution + noise rules ─▶ `attributed` ─▶ company rollup ─▶ score + reasons ─▶ app export
```

| metric | value (dev machine, 16 vCPU, 15 workers) |
|---|---|
| input | 17.6 GB zstd, 14.6M banners, 5.0M IPs |
| ingest | **206.6 s** (~68k banners/s), 1 unparseable line |
| output | 836 MB Parquet |
| attribution + scoring | ~10 s for 280k companies |
| 1,000 files/month | ~57 worker-hours ≈ **$11–40 compute**, ~$19 Parquet storage ([docs/production.md](docs/production.md)) |

## How I built it (AI-native loop)

Built with Claude Code as a pair. The pattern that worked: **the agent writes and runs, I insist
every claim is checked against the data before it's believed.** The [dev log](DEVLOG.md) records the
cases where that mattered: a process pool that would have queued the whole decompressed file
(~100 GB) in RAM, a non-deterministic file id that broke idempotency, NULL scores silently dropping
most companies (twice), a gitignore rule that would have deployed the app without its data, an
unfamiliar package an error message suggested installing (blocked by the permission check and
replaced with real-server tests), and a hosting provider's hostname nearly quoted to a prospect. Each was caught by a number that
didn't add up, and each is now a test, a guard or a rule. Labelling was delegated to the agent too,
which is why the eval states it plainly and ships an agreement check against human labels.

## What I'd do next

1. **Triggers from change across files**: new exposure this week, newly-KEV'd CVE on a known
   product, remediation as an outcome signal (design in [docs/production.md](docs/production.md)).
2. **LLM vertical + company-name enrichment** for the "other" long tail, evaluated on labels with cost tracked.
3. **Brand-impersonation signal**: lookalike domains (e.g. a bank's name on a free TLD) are phishing
   infrastructure aimed at a real company, which is a strong reason to call *that* company.
4. **Learned weights from CRM outcomes**, keeping the same explainable components.
5. **Contacts / reachability** (security.txt contacts, WHOIS org, LinkedIn) to close the loop to a person.

## Running locally

```bash
python -m venv .venv && .venv/bin/pip install -r requirements.txt
.venv/bin/python -m pipeline.ingest path/to/dump.jsonl.zst   # raw → Parquet (idempotent)
.venv/bin/python -m pipeline.build_companies                  # attribution + scoring
.venv/bin/python -m pipeline.export_app                       # slim dataset for the app
.venv/bin/uvicorn app.main:app --port 8000                    # http://127.0.0.1:8000
.venv/bin/python -m pytest -q tests
```

Deploy: `Dockerfile` builds only `app/` (code + Parquet). On Render: New → Blueprint → this repo
(`render.yaml`, health check `/healthz`).
