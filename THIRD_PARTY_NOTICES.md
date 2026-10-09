# Third-party notices

Vigil is licensed under Apache-2.0. Portions of the tracked reference material and pattern
taxonomy were adapted from the projects below under their respective licenses. Those licenses
apply to the upstream material, not to Vigil as a whole. Exact MIT license texts are retained
under `third_party/licenses/` and are included in Vigil source distributions and wheels.

The Bugcrowd Vulnerability Rating Taxonomy below is distributed under Apache-2.0. A copy of that
license is included as Vigil's root `LICENSE` file.

## Bugcrowd Vulnerability Rating Taxonomy

- Upstream: <https://github.com/bugcrowd/vulnerability-rating-taxonomy>
- Revision: v1.19 (released 2026-06-24)
- License: Apache-2.0; Copyright 2017 Bugcrowd, Inc.
- License text: `LICENSE`

`agent/references/reporting/bugcrowd-vrt.tsv` is a flattened representation of the v1.19 taxonomy.
`tools/flatten_vrt.py` is Vigil's project-authored converter for regenerating that representation.

## PayloadsAllTheThings

- Upstream: <https://github.com/swisskyrepo/PayloadsAllTheThings>
- Provenance-audit revision:
  [`3ac27901c711bdf3f5b65a7b1d1820a1f65bd09a`](https://github.com/swisskyrepo/PayloadsAllTheThings/commit/3ac27901c711bdf3f5b65a7b1d1820a1f65bd09a)
- License: MIT; Copyright (c) 2019 Swissky
- Retained text: `third_party/licenses/PayloadsAllTheThings-MIT.txt`

The `agent/references/payloads/` files whose frontmatter names PayloadsAllTheThings are adapted
operator references rather than verbatim mirrors. Selected `agent/references/gf-patterns/` files
also cite the corresponding upstream topic as supporting material. The original revision consulted
when each reference was authored was not recorded; the immutable commit above is the revision
against which provenance and license terms were audited for this release.

## Gf-Patterns

- Upstream: <https://github.com/1ndianl33t/Gf-Patterns>
- Revision:
  [`f686f06ae647726578920084c894100d702496cc`](https://github.com/1ndianl33t/Gf-Patterns/commit/f686f06ae647726578920084c894100d702496cc)
- License: MIT; Copyright (c) 2020 Shiv Chouhan (1ndianl33t)
- Retained text: `third_party/licenses/Gf-Patterns-MIT.txt`

This is the revision fetched by the runtime build and the audit anchor for the upstream-derived
keys documented in `agent/references/gf-patterns/` and adapted in
`agent/scripts/assess/lib/classify_buckets.py`. Vigil's local overlays, weights, precision guards,
and additional buckets are project-authored modifications.

## rix4uni/gf-patterns

- Upstream: <https://github.com/rix4uni/gf-patterns>
- Provenance-audit revision:
  [`aa4db64656ac1fe22c8b5ad3cb2bad21ce848050`](https://github.com/rix4uni/gf-patterns/commit/aa4db64656ac1fe22c8b5ad3cb2bad21ce848050)
- License: MIT; Copyright (c) 2023 Bhagirath Saxena
- Retained text: `third_party/licenses/rix4uni-gf-patterns-MIT.txt`

Selected parameter and extension additions recorded in `agent/references/gf-patterns/DRIFT.md`
were informed by this pattern set. The original revision consulted during that comparison was not
recorded; the immutable commit above is the release audit anchor.

## gf

- Upstream: <https://github.com/tomnomnom/gf>
- Revision:
  [`dcd4c361f9f5ba302294ed38b8ce278e8ba69006`](https://github.com/tomnomnom/gf/commit/dcd4c361f9f5ba302294ed38b8ce278e8ba69006)
- License: MIT; Copyright (c) 2018 Tom Hudson
- Retained text: `third_party/licenses/gf-MIT.txt`

The runtime recipe builds this pinned revision of the `gf` executable. A distributed runtime image
must carry the applicable notices for this tool and every other installed component; the source
package notices do not by themselves approve or make a separately distributed image compliant.
