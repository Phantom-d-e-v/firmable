"""Tiny local labelling UI.

    .venv/bin/python -m eval.label_server   # then open http://127.0.0.1:8765

Shows one company at a time from eval/label_set.jsonl (shuffled, score hidden) and
appends your verdict to eval/labels.jsonl. Keys: 1 call · 2 maybe · 3 no · 4 not a company
(hoster / ISP / SaaS) · s skip. The last label for a domain wins, so you can relabel.
"""
from __future__ import annotations

import json
import random
from datetime import datetime, timezone
from pathlib import Path

import uvicorn
from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

HERE = Path(__file__).parent
SET, LABELS = HERE / "label_set.jsonl", HERE / "labels.jsonl"
VERDICTS = {"call", "maybe", "no", "not_company"}

app = FastAPI()


def _labelled() -> dict[str, dict]:
    if not LABELS.exists():
        return {}
    return {(r := json.loads(l))["company_domain"]: r for l in LABELS.open()}


@app.get("/next")
def next_item():
    done = _labelled()
    todo = [r for r in map(json.loads, SET.open()) if r["company_domain"] not in done]
    random.Random(len(done)).shuffle(todo)  # stratum order never leaks into labelling order
    total = sum(1 for _ in SET.open())
    if not todo:
        return {"done": True, "progress": [total, total]}
    item = {k: v for k, v in todo[0].items() if k != "stratum"}
    return {"done": False, "item": item, "progress": [len(done), total]}


class Label(BaseModel):
    company_domain: str
    verdict: str
    note: str = ""


@app.post("/label")
def label(l: Label):
    if l.verdict not in VERDICTS:
        return {"ok": False}
    with LABELS.open("a") as f:
        f.write(json.dumps({**l.model_dump(), "ts": datetime.now(timezone.utc).isoformat()}) + "\n")
    return {"ok": True}


PAGE = """<!doctype html><html><head><meta charset="utf-8"><title>Label accounts</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
:root{--bg:#fafaf9;--fg:#1c1917;--mut:#78716c;--card:#fff;--line:#e7e5e4;--acc:#0f766e}
@media (prefers-color-scheme:dark){:root{--bg:#1c1917;--fg:#f5f5f4;--mut:#a8a29e;--card:#292524;--line:#44403c;--acc:#2dd4bf}}
body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,sans-serif}
main{max-width:860px;margin:0 auto;padding:24px 16px}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:20px}
h1{font-size:22px;margin:0 0 4px} .mut{color:var(--mut)} dl{display:grid;grid-template-columns:130px 1fr;gap:6px 12px}
dt{color:var(--mut)} dd{margin:0;word-break:break-word} code{font-size:13px}
.btns{display:flex;gap:8px;flex-wrap:wrap;margin-top:16px} button{font:inherit;padding:8px 14px;border-radius:8px;
border:1px solid var(--line);background:var(--card);color:var(--fg);cursor:pointer} button:hover{border-color:var(--acc)}
input{width:100%;box-sizing:border-box;font:inherit;padding:8px;border-radius:8px;border:1px solid var(--line);background:var(--bg);color:var(--fg);margin-top:12px}
.q{margin:16px 0 0;font-weight:600}
</style></head><body><main>
<p class="mut" id="prog"></p><div class="card" id="card">loading…</div></main>
<script>
let cur=null;
const esc=s=>String(s??'').replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const list=v=>Array.isArray(v)?v.map(esc).join(' · '):esc(v);
async function load(){
  const r=await (await fetch('/next')).json();
  document.getElementById('prog').textContent=`${r.progress[0]} / ${r.progress[1]} labelled`;
  if(r.done){document.getElementById('card').innerHTML='<h1>All done 🎉</h1><p>Run <code>python -m eval.run</code>.</p>';return}
  cur=r.item; const i=cur;
  document.getElementById('card').innerHTML=`<h1><a href="https://${esc(i.company_domain)}" target="_blank" rel="noopener">${esc(i.company_domain)}</a></h1>
  <div class="mut">${esc(i.org)} · ${esc(i.country)} · ${esc(i.vertical)} · ${esc(i.segment)} · ${i.services} services on ${i.ips} IPs</div>
  <dl style="margin-top:16px">
   <dt>Signals</dt><dd>${list(i.reasons)||'—'}</dd><dt>Cert org</dt><dd>${esc(i.cert_org)||'—'}</dd>
   <dt>Page titles</dt><dd>${list(i.titles)||'—'}</dd><dt>Hostnames</dt><dd><code>${list(i.hostnames)||'—'}</code></dd>
   <dt>Ports</dt><dd>${list(i.ports)}</dd><dt>Products</dt><dd>${list(i.products)||'—'}</dd><dt>KEV CVEs</dt><dd>${list(i.kev_cves)||'—'}</dd></dl>
  <p class="q">Would a cybersecurity vendor's rep want to call this account this week?</p>
  <div class="btns"><button onclick="send('call')">1 · Call</button><button onclick="send('maybe')">2 · Maybe</button>
  <button onclick="send('no')">3 · No</button><button onclick="send('not_company')">4 · Not a company (hoster/ISP/SaaS)</button>
  <button onclick="load()">s · Skip</button></div><input id="note" placeholder="optional note (why?)">`;
}
async function send(v){await fetch('/label',{method:'POST',headers:{'content-type':'application/json'},
  body:JSON.stringify({company_domain:cur.company_domain,verdict:v,note:document.getElementById('note').value})});load()}
document.addEventListener('keydown',e=>{if(e.target.id==='note')return;
  ({'1':()=>send('call'),'2':()=>send('maybe'),'3':()=>send('no'),'4':()=>send('not_company'),'s':load})[e.key]?.()});
load();
</script></body></html>"""


@app.get("/", response_class=HTMLResponse)
def index():
    return PAGE


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8765)
