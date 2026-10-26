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

create or replace table ambient_cves as
-- KEV CVEs inferred from ubiquitous version strings (e.g. CVE-2023-44487 HTTP/2 Rapid
-- Reset on every nginx) are background noise, not a reason to call someone.
select cve from (select unnest(kev_cves) cve from banners) group by 1 having count(*) > 20000;

create or replace table companies as
with ambient as (select coalesce(list(cve), []) cves from ambient_cves),
b as (
    select banners.* replace (
        list_filter(kev_cves, lambda x: not list_contains(ambient.cves, x)) as kev_cves
    )
    from banners, ambient
    where company_domain is not null
      and company_domain not in (select company_domain from infra_domains)
      and ip not in (select ip from shared_ips)
      and ip not in (select ip from honeypot_ips)
      and not is_honeypot
      and not is_malware_infra
),
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
        coalesce(list(distinct exposure) filter (where exposure is not null), []) as exposures,
        bool_or(is_compromised)                     as compromised,
        bool_or(eol_product or eol_os)              as eol,
        bool_or(cert_expired)                       as cert_expired,
        bool_or(self_signed)                        as self_signed,
        bool_or(weak_tls)                           as weak_tls,
        bool_or(has_securitytxt)                    as has_securitytxt,
        bool_or(waf is not null)                    as has_waf,
        bool_or(http_status is not null and not has_hsts) as missing_hsts,
        list(distinct product) filter (where product is not null) as products,
        max(ts)                                     as last_seen
    from b
    group by 1
)
select *,
    -- NEED: is something exploitable / exposed right now?
      least(kev_vulns, 5) * 8                         -- known-exploited CVEs
    + case when max_epss >= 0.5 then 10 else 0 end    -- likely to be exploited soon
    + case when compromised then 25 else 0 end
    + len(exposures) * 8                              -- RDP/DB/ICS/etc on the internet
    + case when eol then 6 else 0 end
    + case when cert_expired or self_signed then 3 else 0 end
    + case when weak_tls then 3 else 0 end
    + case when missing_hsts then 1 else 0 end
    -- MATURITY: already invested in security -> less likely to need us (or better fit for upsell)
    - case when has_securitytxt then 5 else 0 end
    - case when all_behind_cdn then 5 else 0 end
    as score_v0,
    list_filter([
        case when kev_vulns > 0 then format('{} known-exploited CVEs (CISA KEV): {}', kev_vulns, array_to_string(kev_cves[1:3], ', ')) end,
        case when max_epss >= 0.5 then format('CVE with {:.0f}% exploit probability (EPSS)', max_epss * 100) end,
        case when compromised then 'Shodan flags host as compromised' end,
        case when len(exposures) > 0 then 'Exposed: ' || array_to_string(exposures, ', ') end,
        case when eol then 'End-of-life software' end,
        case when cert_expired then 'Expired TLS certificate' end,
        case when self_signed then 'Self-signed certificate' end,
        case when weak_tls then 'Supports TLS 1.0/1.1 or SSL' end,
        case when has_securitytxt then 'Has security.txt (mature security program)' end
    ], lambda x: x is not null) as reasons
from agg;
