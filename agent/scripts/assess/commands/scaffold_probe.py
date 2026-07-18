"""vigil assess scaffold-probe — write a runnable probe skeleton + register it.

Phase 4 self-expanding "write-probe-script" capability. The agent authors a
single-file Python probe at runtime (see `agent/skills/write-probe-script/SKILL.md`),
runs it through `vigil assess kali exec -- python3 <script>`, validates it, and
persists it for reuse. This command is the thin scaffold that bootstraps step 1:
it writes a templated, immediately-runnable probe into the engagement's
``scripts/`` dir (the canonical home for agent-authored helpers — same place
`kali-exec` SKILL.md "Run a custom Python helper" points at) and pre-registers
the artifact via the existing ``POST /assessment/.../artifacts`` path so it is
linkable to a finding from the first second.

No new plumbing: the engagement dir resolves through ``load_config`` exactly like
every other command, and registration reuses ``AssessmentClient.post("artifacts",
...)`` — the same call ``vigil assess artifact register`` makes.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

from assess.lib.client import AssessError, AssessmentClient
from assess.lib.config import load_config


# Probe names become a filename and (effectively) a python module name when run,
# so keep them to a safe identifier-ish charset. This also stops a caller from
# escaping the scripts/ dir via ``../`` or absolute paths.
_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]*$")

# The kind we tag scaffolded probes with so they are filterable in the artifact
# index (``vigil assess artifact search --kind probe-script``).
_PROBE_KIND = "probe-script"


def register(subparsers: argparse._SubParsersAction) -> None:
    p = subparsers.add_parser(
        "scaffold-probe",
        help="Write a runnable probe skeleton into the engagement scripts/ dir and register it.",
        description=(
            "Bootstrap a single-file Python probe (write-probe-script capability). "
            "Writes scripts/<name>.py with the finding-return convention and an "
            "oob-mint hook commented in, then pre-registers it as an artifact so it "
            "is immediately linkable to a finding. Run it via "
            "`vigil assess kali exec -- python3 /engagements/$ENGAGEMENT_KEY/scripts/<name>.py`."
        ),
    )
    p.add_argument(
        "name",
        help="Probe name (becomes scripts/<name>.py). Allowed: letters, digits, '-', '_'.",
    )
    p.add_argument(
        "--finding",
        default="",
        help="Link the registered artifact to this finding slug (e.g. LFI-001).",
    )
    p.add_argument(
        "--purpose",
        default="",
        help="One-line description woven into the script docstring/header.",
    )
    p.add_argument(
        "--force",
        action="store_true",
        help="Overwrite scripts/<name>.py if it already exists.",
    )
    p.add_argument(
        "--no-register",
        dest="register_artifact",
        action="store_false",
        help="Skip artifact registration (write the file only).",
    )
    p.add_argument(
        "--json",
        dest="as_json",
        action="store_true",
        help="Emit the result (path, registered artifact row) as JSON.",
    )
    p.set_defaults(func=run, register_artifact=True)


def run(args: argparse.Namespace) -> None:
    name = args.name.strip()
    if not _NAME_RE.match(name):
        print(
            f"scaffold-probe: invalid name {name!r}; use letters, digits, '-', '_' "
            "(no slashes, no leading dot).",
            file=sys.stderr,
        )
        sys.exit(2)

    cfg = load_config(args.engagement_dir)
    scripts_dir = Path(cfg.engagement_dir) / "scripts"
    scripts_dir.mkdir(parents=True, exist_ok=True)
    script_path = scripts_dir / f"{name}.py"
    relative_path = f"scripts/{name}.py"

    if script_path.exists() and not args.force:
        print(
            f"scaffold-probe: {relative_path} already exists; pass --force to overwrite.",
            file=sys.stderr,
        )
        sys.exit(1)

    purpose = args.purpose.strip() or f"Bespoke probe '{name}' (fill in the hypothesis)."
    script_path.write_text(_render_template(name=name, purpose=purpose), encoding="utf-8")
    # Mark executable for parity with how operators run engagement-local scripts;
    # execution is always via `python3 <path>` so this is convenience, not a
    # dependency.
    try:
        script_path.chmod(0o755)
    except OSError:
        pass

    result: dict = {
        "name": name,
        "path": str(script_path),
        "relative_path": relative_path,
        "registered": False,
        "artifact": None,
    }

    if args.register_artifact:
        try:
            result["artifact"] = _register_artifact(cfg, relative_path, args.finding or None)
            result["registered"] = True
        except AssessError as exc:
            # Non-fatal: the file is written and runnable regardless. Surface the
            # failure so the agent can register manually with `artifact register`.
            print(
                f"warning: artifact registration failed: {exc}; "
                f"the script is written. Register it with "
                f"`vigil assess artifact register {relative_path} --kind {_PROBE_KIND}`.",
                file=sys.stderr,
            )

    if args.as_json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return

    print(f"wrote {relative_path}")
    if result["registered"]:
        row = result["artifact"] or {}
        present = "yes" if row.get("present") else "no"
        finding = row.get("related_finding_slug") or args.finding or "-"
        print(f"registered artifact id={row.get('id')} present={present} finding={finding}")
    print("next: edit the probe, then run it via")
    print(
        f"  vigil assess kali exec --technique <ENUM> --intent '<why>' "
        f"--probe-kind <kind> --phase <phase> --timeout <s> -- "
        f"python3 /engagements/{cfg.engagement_key}/{relative_path} --target <url>"
    )


def _register_artifact(cfg, relative_path: str, finding_slug: str | None) -> dict:
    """Pre-register the scaffolded probe via the existing artifacts POST path.

    Mirrors ``vigil assess artifact register``: same endpoint, same payload
    shape (``assess.commands.artifact._run_register``). The file is written
    before this call so the backend hashes real bytes (``present=yes``).
    """
    with AssessmentClient(cfg.base_url, cfg.engagement_key) as client:
        payload = {
            "path": relative_path,
            "kind": _PROBE_KIND,
            "related_finding_slug": finding_slug,
        }
        return client.post("artifacts", payload)


def _render_template(*, name: str, purpose: str) -> str:
    """Return a minimal-but-real runnable probe skeleton.

    The skeleton: parses ``--target`` (+ ``--out``), does one passive GET, and
    prints the finding-return JSON verdict on the LAST stdout line (the
    convention `write-probe-script` SKILL.md defines). The active-payload branch
    and the `vigil oob mint` blind-callback hook are present but commented so the
    file runs as-is yet shows the agent exactly where to extend it.
    """
    # NOTE: kept intentionally small. The template is a starting point the agent
    # edits — the SKILL.md worked example shows the differential/active shapes.
    return f'''#!/usr/bin/env python3
"""{purpose}

Probe: {name}
Run inside the runtime container via:
  vigil assess kali exec --technique <ENUM> --intent "<why>" \\
    --probe-kind <fingerprint|baseline|payload|exploit> --phase <phase> \\
    --timeout <seconds> [--destructive] -- \\
    python3 /engagements/$ENGAGEMENT_KEY/scripts/{name}.py \\
      --target <url> --out /engagements/$ENGAGEMENT_KEY/scans/{name}.json

Output contract (see agent/skills/write-probe-script/SKILL.md): the LAST stdout
line is a single JSON object {{"finding": bool, "summary": str, "evidence": {{...}}}}.
When finding is true that verdict seeds a finding record. Stdlib-only so the
probe replays on any runtime tier; `requests` is available if you genuinely need it.
"""
import argparse
import json
import os
import sys
import urllib.request


def fetch(url: str, *, timeout: int = 15) -> tuple[int, str]:
    """GET `url`, returning (status, first 4 KiB of body). Scoped target only."""
    req = urllib.request.Request(url, headers={{"User-Agent": "vigil-probe"}})
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 (scoped target)
        body = resp.read(4096).decode("utf-8", "replace")
        return resp.status, body


def main() -> int:
    ap = argparse.ArgumentParser(description="{purpose}")
    ap.add_argument("--target", required=True, help="Target URL the probe acts on.")
    ap.add_argument("--out", default="", help="Optional path to write the JSON verdict to.")
    # Active-payload knobs — uncomment + use when this is a payload/exploit probe:
    # ap.add_argument("--param", default="q", help="Injected parameter/slot name.")
    # ap.add_argument("--payload", default="", help="Crafted input under test.")
    # ap.add_argument("--marker", default="", help="Response marker that proves the hypothesis.")
    # Blind-callback hook — mint the host on the HOST first, pass it in here:
    #   vigil oob mint --client <name> --technique <t> --target-url <url> --param <p>
    #   (mint binds the nonce under the client's id; pass the EXACT host it prints —
    #    a bare <nonce>.oob... host never reaches `vigil oob poll`.)
    # ap.add_argument("--callback", default="", help="Exact minted http://<nonce>.<client-id>.oob.../ host from `vigil oob mint`.")
    args = ap.parse_args()

    # ---- IMPLEMENT: replace this passive baseline with the real probe logic. --
    status, body = fetch(args.target)
    # Example verdict logic — a real probe branches on response shape, diffs two
    # responses, times a blind callback, or chains primitives. Make `finding`
    # mean "the hypothesis held" and put the load-bearing facts in `evidence`.
    finding = False
    summary = f"baseline GET {{args.target}} -> {{status}} (no hypothesis tested yet)"
    evidence = {{"status": status, "body_prefix": body[:200]}}
    # ---------------------------------------------------------------------------

    result = {{"finding": finding, "summary": summary, "evidence": evidence}}
    if args.out:
        os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump(result, fh, indent=2)
    # Verdict MUST be the last stdout line.
    print(json.dumps(result, ensure_ascii=False))
    return 0 if finding else 1


if __name__ == "__main__":
    sys.exit(main())
'''
