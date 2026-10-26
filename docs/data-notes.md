# Data notes (living document)

## Full file (2026-10-27)

- **17.6 GB zstd, 14,608,407 banners, 4,992,440 distinct IPs**, one crawl window
  2026-10-25 18:13 → 2026-10-26 13:06 UTC (~19 h). One unparseable line.
- Ingest: **206.6 s on 15 workers (~68k banners/s)** → 836 MB Parquet.
- Coverage: owner-chosen domain (cert CN / HTTP Host) on only 5.9% of banners; PTR 5.6%,
  other hostnames 3.9%; **84.5% have no domain at all** (IP-only).
- `vulns` on banners with KEV: 1.9%; exposure classes 2.75%; SSL 6.8%; HTTP 29.5%.
- Countries: US 5.5M, **SG 4.5M** (CDN/Incapsula edge), CN 0.8M, GB, DE, JP.
- Exposed services (banners): camera 123k, remote access 73k, file share 51k,
  database 45k, **DICOM medical imaging 41k**, **ICS 37k (28k fuel-tank gauges)**,
  network admin 11k, devops 10k, edge appliances 9.7k.
- Attacker C2 fingerprints: ~66k banners (darktrack, remcos, orcus, nuclear, poison-ivy RATs).

### Full-file corrections to the head-sample findings
- **Honeypots are only partly tagged.** A ~1k-host AWS cluster claims every Oracle
  WebLogic KEV on random high ports; 60–78% tagged honeypot, the rest identical.
  Rule: one honeypot banner → drop the whole IP (90,476 IPs).
- **KEV ≠ actionable.** CVE-2023-44487 (HTTP/2 Rapid Reset, version-inferred on 169k
  nginx), CVE-2024-38475 and CVE-2021-40438 (Apache, version-inferred) account for most KEV hits.
  KEV CVEs seen on >20k banners are treated as ambient. Companies with a KEV: 38k → 6.5k.
- **Hosters, layer 3.** Co-tenancy: a domain naming machines whose cert/Host names belong
  to *other* companies is a hoster (sakura.ne.jp 140 tenants, nazwa.pl 3; mit.edu,
  walmart.com 0). Plus shared IPs (≥5 domains) are unattributable, plus a name/org
  keyword rule for VPS brands. ASN tenancy was tried and does **not** separate them
  (walmart.com lives on Google Cloud).
- Bug caught: `len(NULL)` made the score NULL for every company without an exposure.

### From reading the uniform random sample (`data/sample/READ_ME_50.md`)
- **Most of the file is noise to a salesperson.** Incapsula edge IPs answer on *every*
  port (that's why SG has 4.5M banners) and Google Cloud IPs on random high ports. Most
  `data` fields are empty. The useful signal is a thin layer on top.
- **Some modules flag victims, not attackers.** `ta14-353a` (US-CERT alert for the
  Sony-hack wiper implant, 11k banners) and `xiaongmai-backdoor` (XiongMai DVR
  backdoor, 4.6k) mean *this host is already compromised*. Now `is_compromised`.
  By contrast `njrat`/`blackshades` are attacker C2 and were slipping past the `-rat` hint.
- **Exposure classes I was missing** (now mapped): TeamViewer 44k, X11 68k, NoMachine,
  WebLogic 42k, SAP router, Oracle TNS, DB2, ClickHouse-native, Vault, Java RMI, git,
  iSCSI, PLC protocols (Omron, GE-SRTP, PLC5, Unitronics, Matrikon OPC), **Heidenhain CNC
  `lsv2`** (manufacturing), HandPunch biometric time clocks, PJL printers.
- **Exposed AI infrastructure**: ~3.5k Ollama (port 11434), 428 MCP, `ai` tag 2k.
  Small now, but a story no other submission will tell: a 2026 attack surface.
- **SaaS tenant subdomains** (`lindasellforcitycouncil.nationbuilder.com`, `*.azurewebsites.net`,
  `*.github.io`, `*.myshopify.com`): registrable domain = the platform. Added to the infra list.
- Nice examples of what good looks like: a Brazilian municipal health system's patient
  record app (`esus.*.wmsaude.com.br`, title "PEC") on EOL nginx; an oncology SaaS
  (`digitaloncology`) behind CloudFront; honeypots imitating a Juniper login page.
- The raw `data` banner carries versions Shodan didn't turn into CVEs (e.g. MikroTik
  Winbox package versions 6.48.4). Possible extra signal: parse versions ourselves.

---

## Head-of-file first pass (download still in progress)

First pass from the head of the file (100k–300k records). Superseded where the
section above disagrees.

- **Shodan banner export**: one line = one service observed on one IP:port at one time.
- ~7x zstd expansion; avg ~7 KB/record (raw `data` banner + parsed HTML dominate).

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
