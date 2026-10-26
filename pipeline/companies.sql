-- Company rollup + v0 score. Run via pipeline/build_companies.py.
-- v0 = transparent hand-set weights with reason codes; to be revisited once the
-- full file has been read and the hand-labelled eval set exists (see eval/).
--
-- Input view: banners (one row per Shodan banner, from pipeline/extract.py)

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
    or (count(distinct ip) >= 5 and avg((domain_source in ('cert', 'http_host'))::int) < 0.2);

create or replace table companies as
with b as (
    select * from banners
    where company_domain is not null
      and company_domain not in (select company_domain from infra_domains)
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
        sum(n_kev)                                  as kev_vulns,
        list_distinct(flatten(list(kev_cves)))      as kev_cves,
        max(max_cvss)                               as max_cvss,
        max(max_epss)                               as max_epss,
        sum(n_vulns)                                as vulns,
        list(distinct exposure) filter (where exposure is not null) as exposures,
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
        case when kev_vulns > 0 then format('{} known-exploited CVEs (CISA KEV)', kev_vulns) end,
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
