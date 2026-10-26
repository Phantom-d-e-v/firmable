# Data notes (living document)

First pass from the head of the file (100k–300k records) while the download was in
progress, 2026-10-27. **Re-check every number against random samples across the full
file** — the head is timestamp-ordered, so it may not be representative.

## What the file is

- One `zstd`-compressed JSONL file, ~10.6 GB compressed, ~7x expansion (1 GB → 7.05 GB).
- **Shodan banner export**: one line = one service observed on one IP:port at one time.
- ~944k records per compressed GB → **~10–11M banners, ~75 GB raw** for the whole file.
- Avg ~7 KB/record (raw `data` banner + parsed HTML dominate).

## Field coverage (100k head sample)

| field | coverage | notes |
|---|---|---|
| `org` / `isp` / `asn` | 100% | **network owner, not the company** (Incapsula, Google, Cloudflare top) |
| `hostnames` / `domains` | 100% key, 72% non-empty | mostly reverse-DNS of hosters/ISPs |
| `http.*` | 31% | headers, title, `components` (tech stack + versions), `waf`, `securitytxt` |
| `tags` | 73% | `cdn` 45%, `cloud` 25%, `honeypot` 1.6%, `eol-product` 1.4%, `self-signed`, `vpn`, `compromised` |
| `cpe23` / `product` | 23% | stack fingerprint |
| `ssl.*` | 6.5% | cert subject/issuer/expiry, TLS versions, JARM/JA3S |
| `vulns` | 2.8% | per-CVE `cvss`, **`epss`**, **`kev`**, `verified` |
| protocol blocks | <1% each | `rdp_encryption`, `smb`, `mongodb`, `redis`, `fortinet`, `microsoft_exchange`, `kubernetes`, `mcp`, … |

## Findings / traps

1. **`org` is the hosting provider, not the prospect.** Top orgs are CDNs and clouds.
   Only when the org owns its own ASN (e.g. `Wal-Mart Stores, Inc.`, universities,
   governments) does `org` name the company.
2. **Reverse-DNS hostnames point at ISPs.** Naively grouping by domain makes
   `ttnet.com.tr`, `wanadoo.fr`, `plus.net` the "biggest companies". Fixed with
   per-banner `domain_source` (cert > http_host > hostname > ptr) and a PTR-pattern
   detector, then a data-driven infra rule (see `pipeline/companies.sql`).
3. **Shared hosting is the next layer of noise.** `sakura.ne.jp`, `nazwa.pl`,
   `hostgator.com` still rank high: the hoster's own cert is on the customers' box.
   Open question: attribute to the hoster (bad prospect) or try to recover the tenant.
4. **Version-inferred CVEs are noisy.** 756 hosts carry the same 10+ ancient Apache
   CVEs from 2007–2013 (`verified: false`, backported distro builds). Weight by
   `kev`, `epss` and `verified`, never by raw CVE count.
5. **Attacker infrastructure is in the data.** Modules like `darktrack-rat`,
   `remcos-pro-rat`, `orcus-rat` fingerprint C2 servers (~0.6% of the sample). They are not
   prospects. Exclude them, but they're interesting as threat intel (hosting providers
   that harbour C2).
6. **Honeypots** (`tags: honeypot`, 1.5%) advertise fake vulns. Exclude them.
7. **Maturity signals are rare and therefore informative**: `security.txt` on 55 of 30k
   HTTP hosts; WAF present on ~45% (mostly CDN-provided).
8. **Sector-revealing services**: `dicom` (medical imaging), `automated-tank-gauge`
   (fuel stations / ICS), `bacnet` (building automation), `hikvision`/`dahua` (cameras),
   `microsoft_exchange`, VPN appliances (`fortinet`, `sonicwall`, `checkpoint`). These
   give both **need** and **vertical** in one field.

## Ideas to test on the full file

- [ ] Random-sample across the whole file (not just the head) and redo coverage stats.
- [ ] Same IP seen on multiple ports → count the **attack surface per company**.
- [ ] `ssl.cert.subject.O` as the legal company name (enrichment, dedup).
- [ ] Cert SAN lists → more domains per company.
- [ ] `http.components` versions → outdated CMS/plugins (WordPress, jQuery).
- [ ] `cert_days_to_expiry` < 14 → a **timing** trigger ("your cert expires next week").
- [ ] Hosts where the org owns the ASN → in-house IT → buyer with budget.
- [ ] Diff across monthly files → *new* exposure = trigger event (needs 2+ files).
- [ ] Vertical classification from titles/cert O/domains (rules first, LLM for the long tail, measured).
