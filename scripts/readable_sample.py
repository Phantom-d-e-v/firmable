"""Write a human-readable Markdown digest of N raw Shodan banners.

    python scripts/readable_sample.py data/sample/random_3k.jsonl data/sample/READ_ME_50.md --n 50

Stratified so the read covers the interesting cases, not 50 CDN edges: a few with
vulns, with exposures, with TLS, with HTTP, and plain random ones. Bulky fields
(full HTML, raw TCP, cert chain) are trimmed; everything else is kept verbatim.
"""
import argparse
import json
import random

DROP_HTTP = {"html", "components_hash", "dom_hash", "headers_hash", "html_hash", "robots_hash",
             "server_hash", "sitemap_hash", "title_hash", "securitytxt_hash", "favicon"}
DROP_SSL = {"chain", "chain_sha256", "acceptable_cas", "handshake_states", "tlsext", "dhparams"}


def slim(r: dict) -> dict:
    r = dict(r)
    r["data"] = r.get("data", "")[:800] + (" …[truncated]" if len(r.get("data", "")) > 800 else "")
    r.pop("tcp", None)
    r.pop("hash", None)
    if r.get("http"):
        r["http"] = {k: v for k, v in r["http"].items() if k not in DROP_HTTP}
        if isinstance(r["http"].get("robots"), str):
            r["http"]["robots"] = r["http"]["robots"][:300]
    if r.get("ssl"):
        r["ssl"] = {k: v for k, v in r["ssl"].items() if k not in DROP_SSL}
        cert = r["ssl"].get("cert") or {}
        r["ssl"]["cert"] = {k: cert.get(k) for k in ("subject", "issuer", "issued", "expires", "expired")}
    if r.get("vulns"):
        r["vulns"] = {c: {k: v.get(k) for k in ("cvss", "epss", "kev", "verified", "summary")}
                      for c, v in list(r["vulns"].items())[:8]}
    return r


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("src")
    ap.add_argument("dst")
    ap.add_argument("--n", type=int, default=50)
    a = ap.parse_args()
    recs = [json.loads(l) for l in open(a.src)]
    rnd = random.Random(7)
    buckets = {
        "has vulns": [r for r in recs if r.get("vulns")],
        "exposed service (non-HTTP module)": [r for r in recs if r["_shodan"]["module"] not in
                                               ("auto", "http", "https", "http-simple-new", "https-simple-new")],
        "TLS cert": [r for r in recs if r.get("ssl")],
        "HTTP": [r for r in recs if r.get("http")],
    }
    per = a.n // 5
    picked, seen = [], set()
    for name, pool in buckets.items():
        for r in rnd.sample(pool, min(per, len(pool))):
            if r["_shodan"]["id"] not in seen:
                seen.add(r["_shodan"]["id"]); picked.append((name, r))
    rest = [r for r in recs if r["_shodan"]["id"] not in seen]
    for r in rnd.sample(rest, a.n - len(picked)):
        picked.append(("pure random", r))

    with open(a.dst, "w") as f:
        f.write(f"# {len(picked)} Shodan banners to read by hand\n\n"
                f"Uniform random sample of the full file (`{a.src}`), stratified: {per} each with "
                "vulns / non-HTTP service / TLS / HTTP, rest pure random.\n"
                "For each one ask: *whose machine is this, and would a security vendor want to call them?*\n\n")
        for i, (why, r) in enumerate(picked, 1):
            sh = r["_shodan"]
            f.write(f"## {i}. {r.get('ip_str') or r.get('ipv6')}:{r['port']}/{r.get('transport')} "
                    f"· {sh.get('module')} · {r.get('org')} · {r.get('location', {}).get('country_code')}\n\n"
                    f"*picked as: {why}* · hostnames: {', '.join(r.get('hostnames') or []) or '-'} · "
                    f"tags: {', '.join(r.get('tags') or []) or '-'}\n\n"
                    f"```json\n{json.dumps(slim(r), indent=1, ensure_ascii=False)}\n```\n\n")
    print(f"wrote {len(picked)} records -> {a.dst}")


if __name__ == "__main__":
    main()
