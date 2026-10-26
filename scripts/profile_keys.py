"""Quick structural profile of a Shodan JSONL sample: key coverage, top values."""
import json, sys, collections

path = sys.argv[1]
top = collections.Counter()
nested = collections.defaultdict(collections.Counter)
vals = collections.defaultdict(collections.Counter)
n = 0
VAL_KEYS = ["port", "transport", "product", "os", "org", "isp", "tags", "cpe23"]
with open(path) as f:
    for line in f:
        r = json.loads(line); n += 1
        top.update(r.keys())
        for k, v in r.items():
            if isinstance(v, dict) and k not in ("vulns",):
                nested[k].update(v.keys())
        for k in VAL_KEYS:
            v = r.get(k)
            if isinstance(v, list):
                vals[k].update(map(str, v))
            elif v is not None:
                vals[k][str(v)] += 1
        vals["country"][r.get("location", {}).get("country_code")] += 1
        vals["module"][r.get("_shodan", {}).get("module")] += 1
        vals["has_vulns"][bool(r.get("vulns"))] += 1
        vals["has_domains"][bool(r.get("domains"))] += 1
        vals["has_ssl"][bool(r.get("ssl"))] += 1
        if r.get("ssl"):
            vals["ssl_expired"][r["ssl"].get("cert", {}).get("expired")] += 1
print(f"records: {n}")
print("\n== top-level key coverage ==")
for k, c in top.most_common(): print(f"{k:28s} {c/n:6.1%}")
for k in ("_shodan", "http", "ssl", "location", "opts"):
    print(f"\n== {k}.* keys ==")
    for kk, c in nested[k].most_common(40): print(f"  {kk:26s} {c/n:6.1%}")
for k, ctr in vals.items():
    print(f"\n== {k} (top 25 of {len(ctr)}) ==")
    for v, c in ctr.most_common(25): print(f"  {c:7d}  {v}")
