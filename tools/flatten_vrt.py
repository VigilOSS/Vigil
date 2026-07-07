#!/usr/bin/env python3
"""Regenerate agent/references/reporting/bugcrowd-vrt.tsv from the upstream Bugcrowd VRT.

Pulls the VRT tree + the CVSS-v3 mapping from a *pinned* tagged release of the official
repo, joins them by id-path, and writes a lean, grep-friendly 3-column TSV:

    priority <TAB> vrt_path <TAB> cvss_v3

The old lookup also carried category/subcategory/variant/id_path columns; those are dropped
here because every one of them is derivable from vrt_path (the " > "-joined name chain).

Design guarantees:
  * Deterministic  -- same pinned tag in => byte-identical TSV out. No wall-clock
    timestamps are written, so re-running never produces a spurious diff.
  * Self-describing -- the upstream tag + release date are stamped into a "#"-comment
    header line at the very top of the TSV, so the version can never silently drift from
    a separate prose file. Consumers strip it with `grep -v '^#'`.
  * Zero quoting    -- fields are tab-joined directly (no csv quoting). A run-time assert
    guarantees no field contains a tab/newline, so the TSV stays trivially grep/cut-able.

Usage:
    python3 tools/flatten_vrt.py                      # download the pinned tag, write the TSV
    python3 tools/flatten_vrt.py tree.json cvss.json  # use local JSON copies (still stamped VRT_TAG)

To upgrade the taxonomy: bump the single VRT_TAG constant below to a newer tag
(see https://github.com/bugcrowd/vulnerability-rating-taxonomy/tags) and re-run.
"""
import json, os, sys, urllib.request

# --- Pin upstream to a tagged release (NOT `master`) so the lookup is reproducible. ---
# --- Bump this one constant + re-run to upgrade. ---
VRT_TAG = "v1.19"

BASE = f"https://raw.githubusercontent.com/bugcrowd/vulnerability-rating-taxonomy/{VRT_TAG}"
TREE_URL = f"{BASE}/vulnerability-rating-taxonomy.json"
CVSS_URL = f"{BASE}/mappings/cvss_v3/cvss_v3.json"

OUT = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "agent", "references", "reporting", "bugcrowd-vrt.tsv",
)


def load(src, url):
    if src and os.path.exists(src):
        with open(src) as f:
            return json.load(f)
    with urllib.request.urlopen(url, timeout=30) as r:
        return json.loads(r.read())


def main():
    tree = load(sys.argv[1] if len(sys.argv) > 1 else None, TREE_URL)
    cvss = load(sys.argv[2] if len(sys.argv) > 2 else None, CVSS_URL)

    # cvss_v3 vectors are keyed by id-path in a parallel tree; index them first.
    cvss_by_idpath = {}

    def walk_cvss(nodes, path):
        for n in nodes:
            p = path + [n["id"]]
            if "cvss_v3" in n:
                cvss_by_idpath["/".join(p)] = n["cvss_v3"]
            for c in n.get("children", []) or []:
                walk_cvss([c], p)

    walk_cvss(cvss["content"], [])

    # Flatten the VRT: a leaf is any node with no children, or any node that carries its
    # own priority (some interior nodes are directly selectable).
    rows = []

    def walk(nodes, names, ids):
        for n in nodes:
            nm, idp = names + [n["name"]], ids + [n["id"]]
            pr, kids = n.get("priority"), n.get("children")
            if not kids or pr is not None:
                priority = f"P{pr}" if isinstance(pr, int) else (pr or "varies")
                vrt_path = " > ".join(nm)
                cvss_v3 = cvss_by_idpath.get("/".join(idp), "")
                for field in (priority, vrt_path, cvss_v3):
                    assert "\t" not in field and "\n" not in field, f"tab/newline in field: {field!r}"
                rows.append((priority, vrt_path, cvss_v3))
            if kids:
                walk(kids, nm, idp)

    walk(tree["content"], [], [])

    release = tree["metadata"]["release_date"][:10]
    header_comment = (
        f"# bugcrowd-vrt.tsv | source: bugcrowd/vulnerability-rating-taxonomy@{VRT_TAG} "
        f"(release {release}, {len(rows)} leaves) | regen: tools/flatten_vrt.py"
    )
    lines = [header_comment, "priority\tvrt_path\tcvss_v3"]
    lines += ["\t".join(r) for r in rows]

    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", newline="\n") as f:
        f.write("\n".join(lines) + "\n")

    print(f"WROTE {OUT}  ({len(rows)} rows)  VRT {VRT_TAG}  release={release}")


if __name__ == "__main__":
    main()
