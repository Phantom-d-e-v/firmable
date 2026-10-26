-- Company rollup + v0 score. Run via pipeline/build_companies.py.
-- v0 = transparent hand-set weights with reason codes; to be revisited once the
-- full file has been read and the hand-labelled eval set exists (see eval/).
--
-- Input view: banners (one row per Shodan banner, from pipeline/extract.py)

create or replace table shared_ips as
-- One IP serving many tenants' domains (shared hosting, site builders): an exposed
-- service there belongs to the host, not to any one tenant, so it can't be attributed.
select ip from banners where company_domain is not null
group by ip having count(distinct company_domain) >= 5;

create or replace table hoster_domains as
-- Co-tenancy: a domain that names machines (hostname / PTR) whose owner-chosen names
-- (cert CN, HTTP Host) belong to *other* companies is a hosting provider.
-- Separates sakura.ne.jp (140 tenants) / nazwa.pl (3) from mit.edu / walmart.com (0).
with own as (select distinct ip, company_domain d from banners where domain_source in ('cert', 'http_host')),
     named as (select distinct ip, company_domain h from banners where domain_source in ('hostname', 'ptr'))
select h as company_domain, count(distinct ip) ips, count(distinct d) filter (where d <> h) tenants
from named left join own using (ip)
group by h
having count(distinct d) filter (where d <> h) >= 3 and count(distinct ip) >= 5;

create or replace table infra_domains as
-- Data-driven infrastructure detection: domains that are mostly reverse-DNS names,
-- or span many unrelated network owners, describe ISPs / hosters, not prospects.
select company_domain
from banners
where company_domain is not null
group by 1
having avg((domain_source = 'ptr')::int) > 0.5
    or count(distinct org) >= 10
    -- many IPs, but almost never named in a cert / Host header the owner chose:
    -- the name comes from the provider's own hostnames, i.e. it's a hoster.
    or (count(distinct ip) >= 5 and avg((domain_source in ('cert', 'http_host'))::int) < 0.2)
union
select company_domain from hoster_domains
union
-- VPS / hosting brands whose customer boxes carry only the provider's hostname.
-- Name-based, so it's explainable and cheap; misses are caught by the eval set.
select distinct company_domain from banners
where regexp_matches(company_domain, '(host|server|vps|hosting|cloud|datacenter|dedi|colo|bluehost|websitewelcome|name-servers|reg\.ru|beget)')
   or (domain_source in ('hostname', 'ptr')
       and regexp_matches(lower(org), '(hosting|server|vps|data ?cent|cloud|colocation|webhost)'));

create or replace table honeypot_ips as
-- Honeypots are only partly tagged: the untagged siblings on the same IP advertise
-- the same fake KEVs (e.g. a ~1k-host AWS cluster claiming every WebLogic CVE).
select distinct ip from banners where is_honeypot;

create or replace table persona_ips as
-- Multi-persona IPs: one address answering as ICS + medical + camera + backdoor is a
-- honeypot or a port-mirroring device, not a real network (only 2-4% are tagged as
-- honeypots). Four or more exposure classes on one IP; CDN edges excluded (handled below).
select ip from banners where exposure is not null and not is_cdn
group by ip having count(distinct exposure) >= 4;

create or replace table asn_owner as
-- Org-owned networks: 84% of banners carry no domain. When an ASN is not cloud/CDN, one
-- domain dominates its owner-chosen names, *and* that domain matches the network owner's
-- name (containment, acronym, or cert O), the ASN's unnamed IPs belong to that company.
-- The name check is what rejects "busiest tenant on Equinix" (lawyer.com) style errors.
with named as (
  select asn, company_domain d, count(*) n, mode(cert_subject_o) cert_o from banners
  where domain_source in ('cert','http_host') and company_domain is not null
    and company_domain not in (select company_domain from infra_domains)
  group by 1,2),
tot as (select asn, sum(n) total, arg_max(d, n) top_d, arg_max(cert_o, n) cert_o, max(n) top_n from named group by 1),
net as (select asn, mode(org) org, avg((is_cdn or is_cloud)::int) cloudy, count(distinct ip) ips from banners group by 1),
cand as (
  select t.*, n.org, n.ips,
         lower(split_part(t.top_d, '.', 1)) label,
         lower(regexp_replace(n.org, '[^A-Za-z ]', '', 'g')) org_norm
  from tot t join net n using (asn)
  where t.top_n >= 3 and t.top_n >= 0.8 * t.total and n.cloudy < 0.2)
select asn, top_d domain, org, ips, top_n, total from cand
where (len(label) >= 4 and contains(replace(org_norm, ' ', ''), label))                         -- "Adyen N.V." ~ adyen
   or label = list_aggregate(list_transform(list_filter(string_split(org_norm, ' '),
              lambda w: len(w) > 2 and w not in ('the', 'and', 'inc', 'llc', 'ltd', 'corp', 'gmbh')),
              lambda w: w[1]), 'string_agg', '')                                               -- acronym: MIT
   or jaro_winkler_similarity(lower(coalesce(cert_o, '')), lower(org)) > 0.9;                  -- cert O == network owner

create or replace table ambient_cves as
-- KEV CVEs inferred from ubiquitous version strings (e.g. CVE-2023-44487 HTTP/2 Rapid
-- Reset on every nginx) are background noise, not a reason to call someone.
select cve from (select unnest(kev_cves) cve from banners) group by 1 having count(*) > 20000;

create or replace table attributed as
-- Every banner we credit to a company, after all attribution and noise rules. Scoring
-- and the app's evidence both read this table, so they can never disagree.
with ambient as (select coalesce(list(cve), []) cves from ambient_cves)
    select banners.* replace (
        coalesce(banners.company_domain, asn_owner.domain) as company_domain,
        list_filter(kev_cves, lambda x: not list_contains(ambient.cves, x)) as kev_cves
    ), banners.company_domain is null as via_network
    from banners
    cross join ambient
    left join asn_owner on banners.company_domain is null and banners.asn = asn_owner.asn
    where coalesce(banners.company_domain, asn_owner.domain) is not null
      and coalesce(banners.company_domain, asn_owner.domain) not in (select company_domain from infra_domains)
      and ip not in (select ip from shared_ips)
      and ip not in (select ip from honeypot_ips)
      and ip not in (select ip from persona_ips)
      and not is_honeypot
      and not is_malware_infra;

create or replace table companies as
with b as (select * from attributed),
agg as (
    select
        company_domain,
        mode(org)                                   as org,
        mode(country)                               as country,
        mode(cert_subject_o)                        as cert_org,
        count(*)                                    as services,
        count(distinct ip)                          as ips,
        bool_and(is_cdn)                            as all_behind_cdn,
        list_distinct(flatten(list(kev_cves)))      as kev_cves,
        len(list_distinct(flatten(list(kev_cves)))) as kev_vulns,
        max(max_cvss)                               as max_cvss,
        max(max_epss)                               as max_epss,
        sum(n_vulns)                                as vulns,
        -- CDN edges accept every port, so protocol probes against them misfire
        -- (e.g. ca.gov "exposing" ICS via Incapsula): exposures there don't count.
        coalesce(list(distinct exposure) filter (where exposure is not null and exposure <> 'compromise' and not is_cdn), []) as exposures,
        coalesce(bool_or(is_compromised and not is_cdn), false) as compromised,
        bool_or(eol_product or eol_os)              as eol,
        bool_or(cert_expired)                       as cert_expired,
        min(cert_days_to_expiry) filter (where cert_days_to_expiry >= 0) as cert_days_left,
        count(*) filter (where via_network)         as services_via_network,
        bool_or(self_signed)                        as self_signed,
        bool_or(weak_tls)                           as weak_tls,
        bool_or(has_securitytxt)                    as has_securitytxt,
        bool_or(waf is not null)                    as has_waf,
        bool_or(http_status is not null and not has_hsts) as missing_hsts,
        list(distinct product) filter (where product is not null) as products,
        lower(company_domain || ' ' || coalesce(mode(cert_subject_o), '') || ' ' ||
              case when regexp_matches(lower(coalesce(mode(org), '')),
                   '(hosting|host|server|vps|cloud|data ?cent|colo|telecom|internet|broadband|communications|network|isp|online|digital|cable|mobile|wireless|fiber|amazon|google|microsoft|akamai|cloudflare|incapsula|fastly|ovh|hetzner|godaddy)')
                   then '' else coalesce(mode(org), '') end) as name_text,
        max(ts)                                     as last_seen
    from b
    group by 1
),
scored as (
    select *,
        -- Score components, one column each so eval/ can ablate them independently.
        -- NEED: is something exploitable / exposed right now?
        least(kev_vulns, 5) * 8                                          as s_kev,
        case when max_epss >= 0.5 then 10 else 0 end                     as s_epss,
        case when compromised then 25 else 0 end                         as s_compromised,
        coalesce(list_sum(list_transform(exposures, lambda e: case
            when e in ('ics', 'medical') then 10
            when e in ('remote_access', 'database', 'edge_appliance', 'app_server', 'devops') then 8
            when e in ('file_share', 'network_admin', 'physical_access') then 6
            when e in ('camera', 'printer') then 3
            else 0 end)), 0)                                             as s_exposure,
        case when eol then 6 else 0 end                                  as s_eol,
        (case when cert_expired or self_signed then 3 else 0 end)
          + (case when weak_tls then 3 else 0 end)
          + (case when missing_hsts then 1 else 0 end)                   as s_hygiene,
        -- TIMING: a deadline the rep can open with.
        case when cert_days_left <= 14 then 3 else 0 end                 as s_timing,
        -- MATURITY: already invested in security -> less likely to need us.
        -(case when has_securitytxt then 5 else 0 end)
          - (case when all_behind_cdn then 5 else 0 end)                 as s_maturity,
        -- FIT: vertical from rules, strongest evidence first:
        --   1. registry-controlled TLDs (.edu/.ac/.gov/.mil) can't be self-declared;
        --   2. multilingual keywords over the domain, the cert's O (chosen by the company) and
        --      the network owner's name (only when the owner isn't a hoster / telco);
        --   3. what's exposed (DICOM -> healthcare, PLCs -> industrial).
        case
            when regexp_matches(company_domain, '\.(edu|ac|k12\.[a-z]{2}\.us)(\.[a-z]{2})?$|\.(edu|ac)\.[a-z]{2}$') then 'education'
            when regexp_matches(company_domain, '\.(gov|gob|gouv|govt|mil|go\.[a-z]{2}|gv\.at|gc\.ca|nhs\.uk)(\.[a-z]{2})?$') then 'government'
            when regexp_matches(name_text, 'hospitals?([^i]|$)|hospice|clinic|klinik|clinica|krankenhaus|ziekenhuis|spital([^i]|$)|health|saude|salud|sant[eé]|medic|pharma|dental|zahn|oncolog|radiolog|patholog|physio|veterin') then 'healthcare'
            when regexp_matches(name_text, 'universi|college|school|schule|escola|escuela|academ|lyc[eé]e|gymnas|polytechn|institute of technology') then 'education'
            when regexp_matches(name_text, 'council|municip|ministr|government|gobierno|gouvernement|regierung|county of|city of|state of|police|polic[ií]a|gemeinde|stadtverwaltung|landkreis|comune|prefeitura|ayuntamiento|kommune|kgrz') then 'government'
            when regexp_matches(name_text, 'bank|banca|banco|banque|sparkasse|credit|kredit|cr[eé]dito|financ|insur|assur|versicher|seguros|capital|invest|securities|asset manag|wealth|payment|fintech') then 'finance'
            when regexp_matches(name_text, 'law ?firm|lawyer|legal|attorney|advoca|abogad|avocat|notar|anwalt|kanzlei|solicitor') then 'legal'
            when list_contains(exposures, 'medical') then 'healthcare'
            when list_contains(exposures, 'ics')
              or regexp_matches(name_text, 'manufactur|industri|steel|chemical|plast|automotive|motor company|engineering|machinery|maschinen') then 'industrial'
            else 'other'
        end                                                              as vertical,
        case when ips >= 50 then 'enterprise' when ips >= 5 then 'mid-market' else 'smb' end as segment
    from agg
)
select *,
    s_kev + s_epss + s_compromised + s_exposure + s_eol + s_hygiene + s_timing + s_maturity as score_v0,
    list_filter([
        case when compromised then 'Backdoor / compromise indicator detected on a host' end,
        case when kev_vulns > 0 then format('{} known-exploited CVEs (CISA KEV): {}', kev_vulns, array_to_string(kev_cves[1:3], ', ')) end,
        case when max_epss >= 0.5 then format('CVE with {:.0f}% exploit probability (EPSS)', max_epss * 100) end,
        case when len(exposures) > 0 then 'Exposed: ' || array_to_string(exposures, ', ') end,
        case when eol then 'End-of-life software' end,
        case when cert_expired then 'Expired TLS certificate' end,
        case when cert_days_left <= 14 then format('TLS certificate expires in {} days', cert_days_left) end,
        case when self_signed then 'Self-signed certificate' end,
        case when weak_tls then 'Supports TLS 1.0/1.1 or SSL' end,
        case when has_securitytxt then 'Has security.txt (mature security program)' end
    ], lambda x: x is not null) as reasons
from scored;
