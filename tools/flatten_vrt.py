#!/usr/bin/env python3
"""Regenerate bugcrowd-vrt-lookup.csv from the upstream Bugcrowd VRT.

Pulls the VRT tree + the CVSS-v3 mapping from the official repo, joins them by id-path,
and writes a flat lookup CSV (priority | category | subcategory | variant | vrt_path |
id_path | cvss_v3) to the repo root.

Usage:  python3 tools/flatten_vrt.py            # downloads latest, writes ../bugcrowd-vrt-lookup.csv
        python3 tools/flatten_vrt.py tree.json cvss.json   # use local copies
"""
import csv, json, os, sys, urllib.request

BASE = "https://raw.githubusercontent.com/bugcrowd/vulnerability-rating-taxonomy/master"
TREE_URL = f"{BASE}/vulnerability-rating-taxonomy.json"
CVSS_URL = f"{BASE}/mappings/cvss_v3/cvss_v3.json"

def load(src, url):
    if src and os.path.exists(src):
        return json.load(open(src))
    with urllib.request.urlopen(url, timeout=30) as r:
        return json.loads(r.read())

tree = load(sys.argv[1] if len(sys.argv) > 1 else None, TREE_URL)
cvss = load(sys.argv[2] if len(sys.argv) > 2 else None, CVSS_URL)

cvss_by_idpath = {}
def walk_cvss(nodes, path):
    for n in nodes:
        p = path + [n["id"]]
        if "cvss_v3" in n:
            cvss_by_idpath["/".join(p)] = n["cvss_v3"]
        for c in n.get("children", []) or []:
            walk_cvss([c], p)
walk_cvss(cvss["content"], [])

rows = []
def walk(nodes, names, ids):
    for n in nodes:
        nm, idp = names + [n["name"]], ids + [n["id"]]
        pr, kids = n.get("priority"), n.get("children")
        if not kids or pr is not None:
            rows.append({
                "priority": f"P{pr}" if isinstance(pr, int) else (pr or "varies"),
                "category": nm[0] if nm else "",
                "subcategory": nm[1] if len(nm) > 1 else "",
                "variant": nm[2] if len(nm) > 2 else "",
                "vrt_path": " > ".join(nm),
                "id_path": "/".join(idp),
                "cvss_v3": cvss_by_idpath.get("/".join(idp), ""),
            })
        if kids:
            walk(kids, nm, idp)
walk(tree["content"], [], [])

out = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "bugcrowd-vrt-lookup.csv")
with open(out, "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=["priority","category","subcategory","variant","vrt_path","id_path","cvss_v3"])
    w.writeheader(); w.writerows(rows)
print(f"WROTE {out}  ({len(rows)} leaves)  release={tree['metadata']['release_date'][:10]}")
