from pipeline.extract import extract, is_ptr_like, registrable


def banner(**kw):
    base = {"_shodan": {"module": "http", "id": "x"}, "port": 80, "ip_str": "1.2.3.4",
            "hostnames": [], "domains": [], "location": {}, "timestamp": "2026-10-26T12:00:00"}
    base.update(kw)
    return base


def test_registrable_handles_multi_part_suffix_and_ips():
    assert registrable("www.shop.example.co.uk") == "example.co.uk"
    assert registrable("1.2.3.4") is None
    assert registrable(None) is None


def test_ptr_like_detects_isp_reverse_dns():
    assert is_ptr_like("1-2-3-4.static.isp.net", "1.2.3.4")
    assert is_ptr_like("dsl-pool-77.provider.de", "9.9.9.9")
    assert not is_ptr_like("vpn.acme-corp.com", "1.2.3.4")


def test_cert_cn_beats_ptr_hostname_for_company_domain():
    r = extract(banner(hostnames=["1-2-3-4.static.isp.net"],
                       ssl={"cert": {"subject": {"CN": "mail.acme-corp.com"}}}))
    assert r["company_domain"] == "acme-corp.com"
    assert r["domain_source"] == "cert"


def test_infra_domains_are_never_the_company():
    r = extract(banner(hostnames=["abc.googleusercontent.com"]))
    assert r["company_domain"] is None


def test_vuln_rollup_counts_kev_and_epss():
    r = extract(banner(vulns={
        "CVE-1": {"cvss": 9.8, "epss": 0.97, "kev": True, "verified": False},
        "CVE-2": {"cvss": 5.0, "epss": 0.01},
    }))
    assert (r["n_vulns"], r["n_kev"], r["max_cvss"], r["max_epss"]) == (2, 1, 9.8, 0.97)
    assert r["kev_cves"] == ["CVE-1"]


def test_exposure_from_module_and_port():
    assert extract(banner(_shodan={"module": "rdp"}, port=3389))["exposure"] == "remote_access"
    assert extract(banner(_shodan={"module": "auto"}, port=27017))["exposure"] == "database"
    assert extract(banner(fortinet={}))["exposure"] == "edge_appliance"


def test_malware_infra_and_honeypot_flags():
    assert extract(banner(_shodan={"module": "darktrack-rat"}))["is_malware_infra"]
    assert extract(banner(_shodan={"module": "njrat"}))["is_malware_infra"]
    assert extract(banner(tags=["honeypot"]))["is_honeypot"]


def test_backdoor_modules_mark_the_victim_compromised_not_malware_infra():
    r = extract(banner(_shodan={"module": "xiaongmai-backdoor"}))
    assert r["is_compromised"] and not r["is_malware_infra"]


def test_saas_tenant_subdomain_is_not_attributed_to_the_platform():
    r = extract(banner(ssl={"cert": {"subject": {"CN": "acme.myshopify.com"}}}))
    assert r["company_domain"] is None
