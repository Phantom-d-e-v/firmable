"""Sales intelligence API + UI.

    .venv/bin/uvicorn app.main:app --port 8000

Loads the exported Parquet (pipeline/export_app.py) into in-memory DuckDB at startup:
no database server, cold start ~1s, one container serves the whole thing.
"""
from __future__ import annotations

import csv
import io
import os
from pathlib import Path

import duckdb
from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse, StreamingResponse

DATA = Path(os.environ.get("APP_DATA", Path(__file__).parent / "data"))
STATIC = Path(__file__).parent / "static"

con = duckdb.connect()
con.execute(f"create table companies as select * from read_parquet('{DATA}/companies.parquet')")
con.execute(f"create table evidence as select * from read_parquet('{DATA}/evidence.parquet')")
con.execute("create index companies_domain on companies(company_domain)")

app = FastAPI(title="Breach Radar", docs_url="/api/docs")

SORTS = {"score": "score desc", "kev": "kev_vulns desc, score desc", "epss": "max_epss desc, score desc",
         "size": "ips desc, score desc", "recent": "last_seen desc"}
SIGNALS = {
    "compromised": "compromised",
    "kev": "kev_vulns > 0",
    "exposed": "len(exposures) > 0",
    "eol": "eol",
    "tls": "(cert_expired or self_signed or weak_tls)",
}


def _q():
    return con.cursor()  # cursors are cheap and safe per request


def _where(q, vertical, segment, country, signal, exposure, min_score):
    clauses, params = ["true"], []
    if q:
        clauses.append("(company_domain ilike ? or org ilike ? or cert_org ilike ?)")
        params += [f"%{q}%"] * 3
    for col, val in (("vertical", vertical), ("segment", segment), ("country", country)):
        if val:
            clauses.append(f"{col} = ?")
            params.append(val)
    if signal:
        if signal not in SIGNALS:
            raise HTTPException(400, f"signal must be one of {sorted(SIGNALS)}")
        clauses.append(SIGNALS[signal])
    if exposure:
        clauses.append("list_contains(exposures, ?)")
        params.append(exposure)
    if min_score is not None:
        clauses.append("score >= ?")
        params.append(min_score)
    return " and ".join(clauses), params


def _rows(cur) -> list[dict]:
    cols = [d[0] for d in cur.description]
    return [dict(zip(cols, r)) for r in cur.fetchall()]


LIST_COLS = ("company_domain, org, country, cert_org, vertical, segment, services, ips, score, "
             "kev_vulns, max_epss, exposures, compromised, eol, reasons")


@app.get("/api/companies")
def companies(q: str | None = None, vertical: str | None = None, segment: str | None = None,
              country: str | None = None, signal: str | None = None, exposure: str | None = None,
              min_score: int | None = None, sort: str = "score",
              limit: int = Query(50, le=200), offset: int = 0):
    where, params = _where(q, vertical, segment, country, signal, exposure, min_score)
    order = SORTS.get(sort, SORTS["score"])
    cur = _q()
    total = cur.execute(f"select count(*) from companies where {where}", params).fetchone()[0]
    cur.execute(f"select {LIST_COLS} from companies where {where} order by {order}, company_domain "
                f"limit {limit} offset {offset}", params)
    return {"total": total, "rows": _rows(cur)}


@app.get("/api/companies/{domain}")
def company(domain: str):
    cur = _q()
    cur.execute("select * from companies where company_domain = ?", [domain])
    rows = _rows(cur)
    if not rows:
        raise HTTPException(404, "unknown company")
    c = rows[0]
    rank = cur.execute("select count(*) + 1 from companies where score > ?", [c["score"]]).fetchone()[0]
    cur.execute("select * exclude (company_domain) from evidence where company_domain = ? "
                "order by is_compromised desc, len(kev_cves) desc, (exposure is not null) desc, max_epss desc",
                [domain])
    return {"company": c, "rank": rank, "evidence": _rows(cur)}


@app.get("/api/stats")
def stats():
    cur = _q()
    cur.execute("""select count(*) companies, count(*) filter (where score >= 20) hot,
        count(*) filter (where compromised) compromised, count(*) filter (where kev_vulns > 0) kev,
        count(*) filter (where len(exposures) > 0) exposed from companies""")
    totals = _rows(cur)[0]
    facets = {}
    for col in ("vertical", "segment", "country"):
        cur.execute(f"select {col} v, count(*) n from companies where score >= 20 group by 1 order by 2 desc limit 25")
        facets[col] = _rows(cur)
    cur.execute("select e v, count(*) n from (select unnest(exposures) e from companies) group by 1 order by 2 desc")
    facets["exposure"] = _rows(cur)
    return {"totals": totals, "facets": facets}


@app.get("/api/export.csv")
def export_csv(q: str | None = None, vertical: str | None = None, segment: str | None = None,
               country: str | None = None, signal: str | None = None, exposure: str | None = None,
               min_score: int | None = None, sort: str = "score", limit: int = Query(1000, le=5000)):
    where, params = _where(q, vertical, segment, country, signal, exposure, min_score)
    cur = _q()
    cur.execute(f"select company_domain, org, country, vertical, segment, score, kev_vulns, "
                f"array_to_string(exposures, '; ') exposures, array_to_string(reasons, ' | ') reasons "
                f"from companies where {where} order by {SORTS.get(sort, SORTS['score'])} limit {limit}", params)
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow([d[0] for d in cur.description])
    w.writerows(cur.fetchall())
    return StreamingResponse(iter([buf.getvalue()]), media_type="text/csv",
                             headers={"content-disposition": "attachment; filename=accounts.csv"})


@app.get("/healthz")
def healthz():
    return {"ok": True}


@app.get("/")
def index():
    return FileResponse(STATIC / "index.html")
