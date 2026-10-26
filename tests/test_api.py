"""API tests against a real uvicorn process serving the exported app data."""
import json
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
pytestmark = pytest.mark.skipif(not (ROOT / "app/data/companies.parquet").exists(),
                                reason="run pipeline.export_app first")


@pytest.fixture(scope="module")
def base():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    proc = subprocess.Popen([sys.executable, "-m", "uvicorn", "app.main:app", "--port", str(port)],
                            cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    url = f"http://127.0.0.1:{port}"
    for _ in range(100):
        try:
            urllib.request.urlopen(url + "/healthz")
            break
        except OSError:
            time.sleep(0.1)
    yield url
    proc.terminate()
    proc.wait()


def get(base, path):
    try:
        with urllib.request.urlopen(base + path) as r:
            body = r.read().decode()
            return r.status, (json.loads(body) if r.headers.get_content_type() == "application/json" else body)
    except urllib.error.HTTPError as e:
        return e.code, None


def test_list_is_sorted_by_score_and_paginates(base):
    _, page1 = get(base, "/api/companies?limit=20")
    _, page2 = get(base, "/api/companies?limit=20&offset=20")
    scores = [r["score"] for r in page1["rows"] + page2["rows"]]
    assert scores == sorted(scores, reverse=True)
    assert not {r["company_domain"] for r in page1["rows"]} & {r["company_domain"] for r in page2["rows"]}


def test_filters_narrow_and_hold(base):
    _, all_ = get(base, "/api/companies?limit=1")
    _, hc = get(base, "/api/companies?vertical=healthcare&signal=kev&limit=50")
    assert 0 < hc["total"] < all_["total"]
    assert all(r["vertical"] == "healthcare" and r["kev_vulns"] > 0 for r in hc["rows"])


def test_every_listed_reason_is_backed_by_a_score_component(base):
    _, top = get(base, "/api/companies?limit=50")
    for r in top["rows"]:
        if any("known-exploited" in t for t in r["reasons"]):
            assert r["kev_vulns"] > 0
        if any(t.startswith("Backdoor") for t in r["reasons"]):
            assert r["compromised"]


def test_detail_has_rank_and_evidence_for_the_same_company(base):
    _, top = get(base, "/api/companies?limit=1")
    domain = top["rows"][0]["company_domain"]
    status, d = get(base, f"/api/companies/{domain}")
    assert status == 200 and d["rank"] == 1 and d["company"]["company_domain"] == domain
    assert 0 < len(d["evidence"]) <= 25


def test_errors(base):
    assert get(base, "/api/companies/does-not-exist.example")[0] == 404
    assert get(base, "/api/companies?signal=bogus")[0] == 400
    assert get(base, "/api/companies?limit=100000")[0] == 422


def test_search_is_parameterised_not_injected(base):
    status, r = get(base, "/api/companies?q=%27%20or%201%3D1%20--")
    assert status == 200 and r["total"] == 0


def test_csv_export_respects_filters(base):
    status, body = get(base, "/api/export.csv?vertical=government&limit=5")
    lines = body.strip().splitlines()
    assert status == 200 and lines[0].startswith("company_domain,")
    assert 1 < len(lines) <= 6 and all(",government," in l for l in lines[1:])
