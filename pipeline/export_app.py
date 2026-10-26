"""Export the slim dataset the hosted app serves.

    python -m pipeline.export_app [--db data/companies.duckdb] [--out app/data]

companies.parquet: one row per company (score, components, reasons, fit).
evidence.parquet:  up to 25 banners per company, most interesting first: the proof a
                   rep can quote ("RDP on 203.0.113.7:3389, BlueKeep").
Both are small enough to ship inside the container image; the app loads them into an
in-memory DuckDB at startup, so there's no database to run.
"""
from __future__ import annotations

import argparse
from pathlib import Path

import duckdb

EVIDENCE_PER_COMPANY = 25


def export(db: Path, out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    con = duckdb.connect(str(db), read_only=True)
    con.execute(f"""
        copy (
            select company_domain, org, country, cert_org, vertical, segment, services, ips,
                   score_v0 as score, s_kev, s_epss, s_compromised, s_exposure, s_eol, s_hygiene, s_maturity,
                   kev_vulns, kev_cves, max_cvss, max_epss, exposures, compromised, eol,
                   cert_expired, cert_days_left, s_timing, services_via_network,
                   self_signed, weak_tls, has_securitytxt, has_waf, products, reasons, last_seen
            from companies
        ) to '{out}/companies.parquet' (format parquet, compression zstd)
    """)
    con.execute(f"""
        copy (
            select company_domain, ip, port, transport, module, product, version,
                   case when is_cdn then null else exposure end as exposure,
                   kev_cves, n_vulns, max_cvss, max_epss, is_compromised and not is_cdn as is_compromised,
                   eol_product or eol_os as eol, http_title, http_status, waf, cert_subject_o, cert_expired,
                   cert_days_to_expiry, weak_tls, self_signed, hostnames[1:3] as hostnames, via_network, ts
            from attributed
            qualify row_number() over (
                partition by company_domain
                order by (is_compromised and not is_cdn) desc, len(kev_cves) desc,
                         (exposure is not null and not is_cdn) desc, max_epss desc, n_vulns desc, ts desc
            ) <= {EVIDENCE_PER_COMPANY}
        ) to '{out}/evidence.parquet' (format parquet, compression zstd)
    """)
    for f in ("companies", "evidence"):
        n = duckdb.sql(f"select count(*) from '{out}/{f}.parquet'").fetchall()[0][0]
        size = (out / f"{f}.parquet").stat().st_size / 1e6
        print(f"{f}: {n:,} rows, {size:.1f} MB")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", type=Path, default=Path("data/companies.duckdb"))
    ap.add_argument("--out", type=Path, default=Path("app/data"))
    a = ap.parse_args()
    export(a.db, a.out)


if __name__ == "__main__":
    main()
