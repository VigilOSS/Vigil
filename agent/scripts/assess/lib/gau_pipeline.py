"""Shared helpers for the cache-aware gau pipeline wrappers.

The three wrapper verbs (`gau-endpoints`, `gau-secrets`, `gau-js-endpoints`)
all need the same five primitives:

1. Resolve the engagement directory and `cases.db` from the engagement
   context, with `--db` and `--engagement-dir` overrides. Existing wrappers
   like `transition_phase.py` and `lib/coverage_checks.py` already use this
   pattern; collecting it here keeps the new commands consistent.
2. Resolve the canonical gau output path
   (`scans/gau-pipeline/<target_slug>/<cache_key_slug>/<basename>.txt`)
   and a sidecar meta file (same dir, `<basename>.meta.json`) so cache
   reuse can be audited without round-tripping through the backend.
   The on-disk namespacing means two targets — or the same target with
   different `--subs`/`--providers` — never share artifacts.
3. Decide whether the cached gau output is reusable (file present, sidecar
   says exit_code == 0, age within `--max-cache-age-hours`) and emit a
   loud, unmissable stderr message documenting the decision.
4. Run gau via `kali_exec()` when the cache miss; persist the sidecar meta
   on success so the next call can reuse it.
5. Provide a minimal LinkFinder-style endpoint extractor for `.js` bodies
   so `gau-js-endpoints` can recover routes hidden in minified bundles
   without a Dockerfile rebuild. The regex is the well-known LinkFinder
   set; we vendor it inline because the upstream project is a single
   ~300-line Python script that is awkward to install reproducibly inside
   the runtime image.

Keeping the shared logic in one library means a future bug fix to the
cache-decision rules lands once instead of three times.
"""
from __future__ import annotations

import hashlib
import json
import re
import sys
import time
from dataclasses import dataclass, asdict
from pathlib import Path
from shlex import quote
from typing import Any
from urllib.parse import urljoin, urlparse

from .config import Config


_DEFAULT_MAX_CACHE_AGE_HOURS = 24
_DEFAULT_GAU_OUTPUT_BASENAME = "gau_output"


def slug_target(target: str) -> str:
    """Filesystem-safe slug for a gau target.

    Strips scheme/port/path, lowercases the host, replaces non-alphanumeric
    runs with `-`, and appends a short sha256 suffix so two visually
    similar targets (`example.com`, `Example.com`) cannot collide on
    case-insensitive filesystems and so the slug always disambiguates
    regardless of how the operator spelled the target.
    """
    raw = (target or "").strip()
    parsed = urlparse(raw if "://" in raw else f"http://{raw}")
    host = (parsed.hostname or raw).lower()
    safe = re.sub(r"[^a-z0-9]+", "-", host).strip("-")
    if not safe:
        safe = "target"
    digest = hashlib.sha256(raw.lower().encode("utf-8")).hexdigest()[:8]
    return f"{safe[:48]}-{digest}"


def slug_cache_key(cache_key: str) -> str:
    """Short, deterministic slug for a `gau_cache_key()` value.

    Carries the `vN` version prefix verbatim so the on-disk layout makes
    the cache-key schema visible at a glance, plus a sha256 suffix so
    two different flag sets cannot land in the same directory. The full
    `cache_key` is stored in the sidecar meta for human auditability.
    """
    raw = (cache_key or "").strip()
    digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:10]
    version = raw.split("|", 1)[0] if "|" in raw else "v0"
    if not re.fullmatch(r"v[0-9]+", version):
        version = "v0"
    return f"{version}-{digest}"


@dataclass
class GauOutputPaths:
    """Canonical paths for a gau pipeline run inside an engagement.

    The layout is namespaced by `<target_slug>/<cache_key_slug>/` so two
    runs that target different hosts, or the same host with different
    corpus-affecting gau flags, write to disjoint directories. That
    means trufflehog never scans bodies from the wrong corpus and the
    cache-key invariant we enforce in metadata is also enforced by the
    filesystem layout.
    """

    engagement_dir: Path
    work_dir: Path     # /engagements/$KEY/scans/gau-pipeline/<target>/<key>/
    output_path: Path  # work_dir / <basename>.txt
    meta_path: Path    # work_dir / <basename>.meta.json
    bodies_dir: Path   # work_dir / bodies/
    target_slug: str
    cache_key_slug: str

    @property
    def _container_root(self) -> str:
        return (
            f"/engagements/{self.engagement_dir.name}/scans/gau-pipeline/"
            f"{self.target_slug}/{self.cache_key_slug}"
        )

    @property
    def container_output_path(self) -> str:
        """Path the container sees (the engagement dir is bind-mounted at /engagements/<key>/)."""
        return f"{self._container_root}/{self.output_path.name}"

    @property
    def container_work_dir(self) -> str:
        return self._container_root

    @property
    def container_bodies_dir(self) -> str:
        return f"{self._container_root}/bodies"


@dataclass
class GauCacheMeta:
    """Sidecar meta describing the most recent successful gau run.

    Persisted next to the output file as `<basename>.meta.json`. Caching
    decisions read this rather than the audit backend so the wrapper stays
    self-contained and decisions are reproducible offline.
    """

    target: str
    ran_at_epoch: float
    ran_at_iso: str
    exit_code: int
    line_count: int
    output_path: str
    gau_argv: list[str]
    # Canonical fingerprint of the corpus-affecting gau flags (currently
    # --subs and --providers). Performance flags (--threads, output path)
    # and post-collection filters do not change the URL set so they are
    # excluded — that way unrelated knobs do not invalidate the cache.
    # See `gau_cache_key()`.
    cache_key: str = ""


@dataclass
class GauCacheDecision:
    """Result of the cache check, with a human-readable message for stderr."""

    reused: bool
    reason: str
    meta: GauCacheMeta | None
    age_hours: float | None


def resolve_pipeline_paths(
    cfg: Config,
    *,
    target: str,
    cache_key: str,
    output_basename: str = _DEFAULT_GAU_OUTPUT_BASENAME,
) -> GauOutputPaths:
    """Build the canonical path set for the pipeline relative to the engagement dir.

    Layout: `<engagement>/scans/gau-pipeline/<target_slug>/<cache_key_slug>/`
    — one directory per (target, corpus-flag-set) pair, so runs never share
    `gau_output.txt`, intermediate artifacts, or `bodies/`. See
    :class:`GauOutputPaths` for why that separation matters.
    """
    eng_dir = Path(cfg.engagement_dir).resolve()
    target_slug = slug_target(target)
    cache_key_slug = slug_cache_key(cache_key)
    work_dir = eng_dir / "scans" / "gau-pipeline" / target_slug / cache_key_slug
    return GauOutputPaths(
        engagement_dir=eng_dir,
        work_dir=work_dir,
        output_path=work_dir / f"{output_basename}.txt",
        meta_path=work_dir / f"{output_basename}.meta.json",
        bodies_dir=work_dir / "bodies",
        target_slug=target_slug,
        cache_key_slug=cache_key_slug,
    )


def resolve_db_path(cfg: Config, override: str | None = None) -> Path:
    """Resolve cases.db from the engagement dir unless an explicit override is passed.

    The override exists so live testing and one-off operator workflows can
    point at a temp DB without touching the production work buffer. New
    callers should default to the auto-resolved path; older commands like
    `ingest-endpoints` still take a positional `db_path` for backward compat.
    """
    if override:
        return Path(override).expanduser().resolve()
    return Path(cfg.engagement_dir).resolve() / "cases.db"


def load_cache_meta(meta_path: Path) -> GauCacheMeta | None:
    """Read the sidecar meta JSON or return None on any read error.

    Read errors are intentionally swallowed and treated as a cache miss
    (safer to re-run gau than to assume stale meta is current). The caller
    surfaces the reason in the GauCacheDecision message.
    """
    if not meta_path.is_file():
        return None
    try:
        raw = json.loads(meta_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    try:
        return GauCacheMeta(
            target=str(raw["target"]),
            ran_at_epoch=float(raw["ran_at_epoch"]),
            ran_at_iso=str(raw["ran_at_iso"]),
            exit_code=int(raw["exit_code"]),
            line_count=int(raw["line_count"]),
            output_path=str(raw["output_path"]),
            gau_argv=list(raw.get("gau_argv") or []),
            cache_key=str(raw.get("cache_key") or ""),
        )
    except (KeyError, TypeError, ValueError):
        return None


def gau_cache_key(*, subs: bool, providers: str = "") -> str:
    """Build the canonical cache key for the corpus-affecting gau flags.

    Two runs with the same key produce the same URL set, so cache reuse is
    safe; runs with different keys produce different URL sets, so cache
    reuse would silently serve the wrong corpus. We deliberately exclude
    flags that do not change the URL set (output path, --threads, audit
    flags) so cache hits survive routine variation in those.

    Bump the leading version tag when adding a new corpus-affecting flag
    so older meta files (which lack the new field) automatically miss
    instead of falsely matching.
    """
    parts = [
        "v2",
        f"subs={1 if subs else 0}",
        f"providers={(providers or '').strip()}",
    ]
    return "|".join(parts)


def _format_cache_key_diff(cached: str, requested: str) -> str:
    """Produce a human-readable diff of two cache keys for the LLM/operator.

    The raw `cache_key` is a compact `key=value|key=value` blob — readable
    but easy to miss the actual delta. This helper reports each per-field
    change so the cache-miss reason names which gau flag changed instead
    of dumping both keys verbatim.
    """
    def _to_map(key: str) -> dict[str, str]:
        out: dict[str, str] = {}
        for part in key.split("|"):
            if "=" in part:
                k, _, v = part.partition("=")
                out[k] = v
        return out

    a = _to_map(cached)
    b = _to_map(requested)
    deltas: list[str] = []
    for field in sorted(set(a) | set(b)):
        if a.get(field) != b.get(field):
            deltas.append(f"{field}: cached={a.get(field, '<absent>')!r} requested={b.get(field, '<absent>')!r}")
    if not deltas:
        return f"cache-key changed (cached: {cached}; requested: {requested})"
    return "; ".join(deltas)


def write_cache_meta(meta_path: Path, meta: GauCacheMeta) -> None:
    """Persist sidecar meta atomically (write+rename) so a crash mid-write doesn't leave a half file."""
    meta_path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = meta_path.with_suffix(meta_path.suffix + ".tmp")
    tmp_path.write_text(json.dumps(asdict(meta), ensure_ascii=False, indent=2), encoding="utf-8")
    tmp_path.replace(meta_path)


def decide_cache_reuse(
    paths: GauOutputPaths,
    *,
    target: str,
    refresh: bool,
    max_age_hours: float,
    cache_key: str,
) -> GauCacheDecision:
    """Apply the cache reuse rules and return a documented decision.

    Rules (all must hold for reuse):
    - Operator did not pass `--refresh`
    - The output file exists and is non-empty
    - The sidecar meta file exists and is parseable
    - The cached run's exit_code was 0
    - The cached run's target matches (so a different host doesn't get
      served a stale corpus)
    - The cached run's `cache_key` matches the current one (so a
      different flag set — e.g. `--subs` toggled or `--providers`
      changed — does not silently serve a corpus that does not match
      what the operator asked for)
    - The output file's age is within `max_age_hours`

    Each failed condition becomes the human-readable `reason` so the
    operator/LLM can see exactly why a fresh run was triggered.
    """
    if refresh:
        return GauCacheDecision(False, "operator passed --refresh", None, None)
    if not paths.output_path.is_file():
        return GauCacheDecision(False, f"no cached output at {paths.output_path}", None, None)
    if paths.output_path.stat().st_size == 0:
        return GauCacheDecision(False, "cached output is empty", None, None)

    meta = load_cache_meta(paths.meta_path)
    if meta is None:
        return GauCacheDecision(
            False,
            f"sidecar meta {paths.meta_path.name} missing or unreadable; cannot verify cached run",
            None,
            None,
        )
    if meta.exit_code != 0:
        return GauCacheDecision(
            False, f"cached gau run exited {meta.exit_code} (non-zero)", meta, None
        )
    if meta.target != target:
        return GauCacheDecision(
            False,
            f"cached output was for target '{meta.target}', not '{target}'",
            meta,
            None,
        )
    if not meta.cache_key:
        # Older meta written before the cache_key was added. Treat as a miss
        # so the next run regenerates the meta with the fingerprint, rather
        # than guessing the cached run matched the current flag set.
        return GauCacheDecision(
            False,
            "cached meta is missing the flag-set fingerprint (cache_key); "
            "regenerating",
            meta,
            None,
        )
    if meta.cache_key != cache_key:
        return GauCacheDecision(
            False,
            f"cached run used different gau flags ({_format_cache_key_diff(meta.cache_key, cache_key)})",
            meta,
            None,
        )
    age_seconds = time.time() - meta.ran_at_epoch
    age_hours = age_seconds / 3600.0
    if age_hours > max_age_hours:
        return GauCacheDecision(
            False,
            f"cached output is {age_hours:.1f}h old (cap {max_age_hours:.1f}h)",
            meta,
            age_hours,
        )
    return GauCacheDecision(
        True,
        f"reusing cached gau output: {meta.line_count} URLs, {age_hours:.1f}h old",
        meta,
        age_hours,
    )


def announce_cache_decision(decision: GauCacheDecision, *, target: str) -> None:
    """Print an unmissable stderr message documenting the cache decision.

    Both human operators (reading stderr) and the LLM (parsing the JSON
    summary on stdout) need to see the decision; this surface covers the
    human/log channel. The JSON summary returned by each wrapper carries
    the same `cache_reused` field so the LLM does not have to scrape
    stderr.
    """
    if decision.reused:
        print(
            f"[gau-pipeline] REUSING cached gau output for '{target}': {decision.reason}. "
            f"Pass --refresh to force a fresh gau run.",
            file=sys.stderr,
        )
    else:
        print(
            f"[gau-pipeline] RUNNING fresh gau for '{target}': {decision.reason}.",
            file=sys.stderr,
        )


# LinkFinder-derived endpoint regex. Captures five families of endpoint
# strings commonly minified into JS bundles: full URLs, absolute paths,
# relative endpoints with extensions, REST-shaped endpoints, and bare file
# names with web extensions. Operates on raw minified source; heavily
# obfuscated bundles (string concatenation, base64 wrappers) need a
# separate pass.
_LINKFINDER_REGEX = re.compile(
    r"""
        (?:"|')                                 # opening quote
        (
            ((?:[a-zA-Z]{1,10}://|//)           # scheme:// or //
                [^"'/]{1,}\.                    # domain head
                [a-zA-Z]{2,}[^"']{0,})          # TLD + path
            |
            ((?:/|\.\./|\./)                    # /,../,./
                [^"'><,;|*()(%$^/\\\[\]]
                [^"'><,;|()]{1,})
            |
            ([a-zA-Z0-9_\-/]{1,}/               # relative endpoint with /
                [a-zA-Z0-9_\-/.]{1,}            # resource segment (dot allowed for /v1.2/bar.json)
                \.(?:[a-zA-Z]{1,4}|action)
                (?:[\?|#][^"|']{0,}|))
            |
            ([a-zA-Z0-9_\-/]{1,}/               # REST-shape: at least two segments
                [a-zA-Z0-9_\-/]{3,}
                (?:[\?|#][^"|']{0,}|))
            |
            ([a-zA-Z0-9_\-]{1,}                 # bare filename + web ext
                \.(?:php|asp|aspx|jsp|json|action|html|js|txt|xml)
                (?:[\?|#][^"|']{0,}|))
        )
        (?:"|')                                 # closing quote
    """,
    re.VERBOSE,
)


# Extensions that LinkFinder commonly false-positives on (CSS classes that
# look like paths, image references in CSS-in-JS, fingerprinted asset
# bundles). Drop them post-extraction so the operator's work buffer does not
# inherit a wave of static-asset noise.
_LINKFINDER_DROP_EXTENSIONS: frozenset[str] = frozenset({
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".css", ".map", ".mp3", ".mp4", ".webm", ".pdf",
})


def extract_js_endpoints(js_text: str) -> list[str]:
    """Return deduplicated endpoint strings extracted from a JS body.

    The extractor preserves order of first appearance so reviewers can
    correlate output to the source bundle. Drops obvious static-asset
    noise via `_LINKFINDER_DROP_EXTENSIONS`. The caller is responsible
    for resolving relative endpoints against a host before ingestion.
    """
    seen: set[str] = set()
    endpoints: list[str] = []
    for match in _LINKFINDER_REGEX.finditer(js_text):
        endpoint = match.group(1)
        if not endpoint:
            continue
        endpoint = endpoint.strip()
        if not endpoint or endpoint in seen:
            continue
        # Strip query/fragment for the extension drop check; the original
        # endpoint string is preserved for the caller to ingest.
        bare = endpoint.split("?", 1)[0].split("#", 1)[0].lower()
        ext = ""
        last_dot = bare.rfind(".")
        if last_dot != -1:
            ext = bare[last_dot:]
        if ext in _LINKFINDER_DROP_EXTENSIONS:
            continue
        seen.add(endpoint)
        endpoints.append(endpoint)
    return endpoints


def resolve_js_endpoint(endpoint: str, *, base_url: str) -> str | None:
    """Resolve a LinkFinder-extracted endpoint to an absolute URL or None.

    Resolution rules:
    - Already-absolute URL (scheme present): returned as-is
    - Protocol-relative (`//host/path`): inherit base scheme
    - Absolute path (`/path`): join with base origin
    - Anything else (bare filenames like `users.json`, REST-shape like
      `api/v2/users`, or `./relative`): join with the base URL's directory
      so the resolution is unambiguous

    Returns None when the resulting URL has no host (e.g., `/static/foo`
    extracted from a JS file with no usable base — pathological but
    possible).
    """
    base = base_url.strip()
    if not base:
        return None
    parsed_base = urlparse(base)
    if not parsed_base.scheme or not parsed_base.netloc:
        return None
    raw = endpoint.strip()
    if raw.startswith(("http://", "https://")):
        return raw
    if raw.startswith("//"):
        return f"{parsed_base.scheme}:{raw}"
    if raw.startswith("/"):
        return f"{parsed_base.scheme}://{parsed_base.netloc}{raw}"
    # Relative path: resolve against the base URL's directory.
    resolved = urljoin(base, raw)
    parsed_resolved = urlparse(resolved)
    if not parsed_resolved.netloc:
        return None
    return resolved


def count_lines(path: Path) -> int:
    """Count newline-terminated lines, tolerant of files without a trailing newline."""
    if not path.is_file():
        return 0
    count = 0
    with path.open("rb") as fh:
        for _ in fh:
            count += 1
    return count


def build_uro_command(paths: GauOutputPaths, *, source_path: Path, dest_path: Path) -> list[str]:
    """Build the in-container uro dedup argv for a source→dest URL file pair.

    Pure (no exec) so the argv shape is unit-testable. ``source_path`` and
    ``dest_path`` must live under ``paths.work_dir`` so their basenames resolve
    against ``paths.container_work_dir`` (the bind-mounted same directory the
    container sees). The values are ``shlex.quote``-d because they ride a
    ``bash -lc`` string.
    """
    container_src = f"{paths.container_work_dir}/{source_path.name}"
    container_dst = f"{paths.container_work_dir}/{dest_path.name}"
    return ["bash", "-lc", f"uro -i {quote(container_src)} -o {quote(container_dst)}"]


def run_uro_dedup(
    paths: GauOutputPaths,
    *,
    cfg: Config,
    phase: str,
    timeout: int,
    target: str,
    source_path: Path,
    dest_path: Path,
) -> int:
    """Structurally dedupe a URL file with uro inside the runtime container.

    uro collapses near-duplicate URLs — same path with different parameter
    VALUES, cache-busted asset variants (`app.js?v=1` vs `app.js?v=2`),
    incremental id paths — to one representative, so the downstream body-fetch /
    ingest works a smaller, non-redundant set. This is the single source for the
    uro stage so all three gau pipelines (`gau-secrets`, `gau-endpoints`,
    `gau-js-endpoints`) dedupe identically.

    Returns the deduped line count; raises :class:`AssessError` on a non-zero uro
    exit so the caller can decide whether to abort (gau-secrets, whose body-fetch
    needs the trimmed list) or fall back to the undeduped file (gau-endpoints /
    gau-js-endpoints, where ingest/classification dedupe again downstream).

    The ``kali`` import is function-level so this module stays import-light (it is
    a pure pipeline lib elsewhere) and so a unit test can monkeypatch
    ``assess.lib.kali.kali_exec``.
    """
    from .client import AssessError
    from .kali import kali_exec

    cmd = build_uro_command(paths, source_path=source_path, dest_path=dest_path)
    result = kali_exec(
        cmd,
        technique="RECON",
        intent=f"uro structural dedup for {target}",
        probe_kind="fingerprint",
        phase=phase,
        timeout=int(timeout),
        tool_name="uro",
        config=cfg,
    )
    if int(getattr(result, "return_code", 0) or 0) != 0:
        raise AssessError(
            f"uro exited {getattr(result, 'return_code', '?')}; "
            f"see {getattr(result, 'stderr_path', '?')}"
        )
    return count_lines(dest_path)


def add_engagement_flags(parser, *, allow_db_override: bool = True) -> None:
    """Attach the standard --db and --max-cache-age-hours flags.

    `--engagement-dir` is hoisted at the root parser by `assess.cli` so it
    lands on every subcommand automatically — we do not re-declare it
    here. `--db` exists for live-testing scenarios where the operator
    wants to seat results into a temp DB instead of the engagement's
    production cases.db.
    """
    if allow_db_override:
        parser.add_argument(
            "--db",
            dest="db_override",
            default=None,
            help=(
                "Override path to cases.db. Defaults to "
                "<engagement_dir>/cases.db when omitted. Use a temp path "
                "for live testing so the production work buffer is not "
                "polluted."
            ),
        )
    parser.add_argument(
        "--max-cache-age-hours",
        dest="max_cache_age_hours",
        type=float,
        default=_DEFAULT_MAX_CACHE_AGE_HOURS,
        help=(
            f"Reuse cached gau output as long as it is younger than this "
            f"many hours and the cached run exited 0 (default "
            f"{_DEFAULT_MAX_CACHE_AGE_HOURS}h). Increase for stable targets "
            f"with rare new URLs; decrease when actively iterating."
        ),
    )
    parser.add_argument(
        "--refresh",
        dest="refresh",
        action="store_true",
        help="Force a fresh gau run even when cached output is otherwise valid.",
    )


def add_common_audit_defaults(parser, *, default_phase: str = "recon") -> None:
    """Defaults for the audit flags forwarded to inner kali_exec calls.

    Each pipeline wrapper invokes multiple kali tools (gau, httpx, trufflehog).
    The audit flags must be uniform across those calls so the operator can
    correlate runs. We default `phase` to `recon` because the gau pipeline
    is recon-class work; specialists running it during a different phase
    can override.
    """
    parser.add_argument(
        "--phase",
        dest="phase",
        default=default_phase,
        help=f"Phase tag for inner kali_exec calls (default: {default_phase}).",
    )
    parser.add_argument(
        "--timeout",
        dest="timeout",
        type=int,
        default=900,
        help="Wall-clock budget for each inner kali invocation (default 900s).",
    )


def utcnow_iso() -> str:
    """ISO timestamp for sidecar meta (UTC, second resolution).

    Lives here rather than reaching into kali_output._utcnow_iso so the
    pipeline lib has no implicit dependency on the kali audit module.
    """
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def emit_pipeline_summary(payload: dict[str, Any]) -> None:
    """Print the wrapper's structured JSON summary on stdout.

    Wrappers always end with this so the LLM gets a stable, parseable
    summary even when individual inner steps printed their own kali
    summaries earlier in the pipeline.
    """
    print(json.dumps(payload, ensure_ascii=False, indent=2))
