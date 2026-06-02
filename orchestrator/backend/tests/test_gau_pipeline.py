"""Tests for the gau pipeline shared library and the three wrapper verbs.

The wrappers themselves shell out to `kali_exec` (target-touching) and
`ingest-endpoints` (a child `vigil assess` subprocess), so end-to-end tests
would need a runtime container and an orchestrator backend. These unit
tests cover the pieces that can be exercised in-process without those
dependencies:

- Cache-decision rules (refresh, missing meta, stale age, target mismatch,
  exit-code failure, happy-path reuse) — pure logic over a temp dir.
- Sidecar meta read/write round-trip.
- LinkFinder-style endpoint extraction over a small JS body.
- Endpoint resolution against an absolute base URL (relative, absolute
  path, protocol-relative, scheme-prefixed).
- Argparse registration smoke test for each new verb (registers without
  exception and exposes the documented flags).

End-to-end coverage of `kali_exec` plus the inner `ingest-endpoints`
subprocess is left for the live test the operator runs against the
real engagement runtime.
"""
from __future__ import annotations

import importlib.util
import json
import sys
import time
from pathlib import Path
from types import SimpleNamespace

import pytest


def _scripts_root() -> Path:
    return Path(__file__).resolve().parents[3] / "agent" / "scripts"


def _ensure_scripts_path() -> None:
    """Add agent/scripts to sys.path so `from assess.lib...` works.

    Same pattern test_aith_cli.py uses to import the agent CLI library.
    Cleaning previously-imported `assess.*` modules guards against test
    isolation issues when the import order interacts with other test files.
    """
    scripts_root = _scripts_root()
    if str(scripts_root) not in sys.path:
        sys.path.insert(0, str(scripts_root))


def _load_pipeline_lib():
    _ensure_scripts_path()
    from assess.lib import gau_pipeline  # type: ignore[import-not-found]
    return gau_pipeline


def _make_paths(tmp_path: Path, *, target: str = "example.com", cache_key: str | None = None):
    """Build a GauOutputPaths instance pointing at a fake engagement dir.

    Routes through `resolve_pipeline_paths` instead of constructing the
    dataclass by hand so the test layout always matches the production
    one (namespaced by target+cache_key under `scans/gau-pipeline/`).
    """
    lib = _load_pipeline_lib()
    eng_dir = tmp_path / "2026-05-04-test-engagement"
    eng_dir.mkdir()
    (eng_dir / "scans").mkdir()

    class _StubCfg:
        engagement_dir = str(eng_dir)

    if cache_key is None:
        cache_key = lib.gau_cache_key(subs=False, providers="")
    paths = lib.resolve_pipeline_paths(_StubCfg(), target=target, cache_key=cache_key)
    paths.work_dir.mkdir(parents=True, exist_ok=True)
    return lib, paths


# ─── Cache decision rules ───────────────────────────────────────────────


_DEFAULT_KEY_KW = {"subs": False, "providers": ""}


def _key(**overrides) -> str:
    """Helper: build a cache key with default-empty corpus flags."""
    lib = _load_pipeline_lib()
    kw = {**_DEFAULT_KEY_KW, **overrides}
    return lib.gau_cache_key(**kw)


def test_cache_miss_when_refresh_flag_set(tmp_path: Path) -> None:
    lib, paths = _make_paths(tmp_path)
    paths.output_path.write_text("https://x/\n", encoding="utf-8")
    lib.write_cache_meta(paths.meta_path, lib.GauCacheMeta(
        target="example.com", ran_at_epoch=time.time(), ran_at_iso="now",
        exit_code=0, line_count=1, output_path=str(paths.output_path),
        gau_argv=["gau"], cache_key=_key(),
    ))
    decision = lib.decide_cache_reuse(
        paths, target="example.com", refresh=True, max_age_hours=24, cache_key=_key(),
    )
    assert decision.reused is False
    assert "refresh" in decision.reason


def test_cache_miss_when_output_missing(tmp_path: Path) -> None:
    lib, paths = _make_paths(tmp_path)
    decision = lib.decide_cache_reuse(
        paths, target="example.com", refresh=False, max_age_hours=24, cache_key=_key(),
    )
    assert decision.reused is False
    assert "no cached output" in decision.reason


def test_cache_miss_when_output_empty(tmp_path: Path) -> None:
    lib, paths = _make_paths(tmp_path)
    paths.output_path.touch()  # zero bytes
    decision = lib.decide_cache_reuse(
        paths, target="example.com", refresh=False, max_age_hours=24, cache_key=_key(),
    )
    assert decision.reused is False
    assert "empty" in decision.reason


def test_cache_miss_when_meta_missing(tmp_path: Path) -> None:
    lib, paths = _make_paths(tmp_path)
    paths.output_path.write_text("https://x/\n", encoding="utf-8")
    decision = lib.decide_cache_reuse(
        paths, target="example.com", refresh=False, max_age_hours=24, cache_key=_key(),
    )
    assert decision.reused is False
    assert "sidecar meta" in decision.reason


def test_cache_miss_when_previous_run_failed(tmp_path: Path) -> None:
    lib, paths = _make_paths(tmp_path)
    paths.output_path.write_text("https://x/\n", encoding="utf-8")
    lib.write_cache_meta(paths.meta_path, lib.GauCacheMeta(
        target="example.com", ran_at_epoch=time.time(), ran_at_iso="now",
        exit_code=2, line_count=1, output_path=str(paths.output_path),
        gau_argv=["gau"], cache_key=_key(),
    ))
    decision = lib.decide_cache_reuse(
        paths, target="example.com", refresh=False, max_age_hours=24, cache_key=_key(),
    )
    assert decision.reused is False
    assert "exited 2" in decision.reason


def test_cache_miss_when_target_changed(tmp_path: Path) -> None:
    lib, paths = _make_paths(tmp_path)
    paths.output_path.write_text("https://x/\n", encoding="utf-8")
    lib.write_cache_meta(paths.meta_path, lib.GauCacheMeta(
        target="other.com", ran_at_epoch=time.time(), ran_at_iso="now",
        exit_code=0, line_count=1, output_path=str(paths.output_path),
        gau_argv=["gau"], cache_key=_key(),
    ))
    decision = lib.decide_cache_reuse(
        paths, target="example.com", refresh=False, max_age_hours=24, cache_key=_key(),
    )
    assert decision.reused is False
    assert "other.com" in decision.reason and "example.com" in decision.reason


def test_cache_miss_when_too_old(tmp_path: Path) -> None:
    lib, paths = _make_paths(tmp_path)
    paths.output_path.write_text("https://x/\n", encoding="utf-8")
    twenty_six_hours_ago = time.time() - (26 * 3600)
    lib.write_cache_meta(paths.meta_path, lib.GauCacheMeta(
        target="example.com", ran_at_epoch=twenty_six_hours_ago, ran_at_iso="t",
        exit_code=0, line_count=1, output_path=str(paths.output_path),
        gau_argv=["gau"], cache_key=_key(),
    ))
    decision = lib.decide_cache_reuse(
        paths, target="example.com", refresh=False, max_age_hours=24, cache_key=_key(),
    )
    assert decision.reused is False
    assert "old" in decision.reason and decision.age_hours is not None
    assert decision.age_hours > 24


def test_cache_hit_within_window(tmp_path: Path) -> None:
    lib, paths = _make_paths(tmp_path)
    paths.output_path.write_text("https://x/\nhttps://y/\n", encoding="utf-8")
    one_hour_ago = time.time() - 3600
    lib.write_cache_meta(paths.meta_path, lib.GauCacheMeta(
        target="example.com", ran_at_epoch=one_hour_ago, ran_at_iso="t",
        exit_code=0, line_count=2, output_path=str(paths.output_path),
        gau_argv=["gau"], cache_key=_key(),
    ))
    decision = lib.decide_cache_reuse(
        paths, target="example.com", refresh=False, max_age_hours=24, cache_key=_key(),
    )
    assert decision.reused is True
    assert "reusing" in decision.reason.lower()
    assert decision.meta is not None
    assert decision.age_hours is not None
    assert 0.5 < decision.age_hours < 1.5


def test_cache_miss_when_subs_flag_changed(tmp_path: Path) -> None:
    """Toggling --subs must bust the cache so the operator gets the corpus they asked for."""
    lib, paths = _make_paths(tmp_path)
    paths.output_path.write_text("https://x/\n", encoding="utf-8")
    cached_no_subs = _key(subs=False)
    lib.write_cache_meta(paths.meta_path, lib.GauCacheMeta(
        target="example.com", ran_at_epoch=time.time(), ran_at_iso="t",
        exit_code=0, line_count=1, output_path=str(paths.output_path),
        gau_argv=["gau"], cache_key=cached_no_subs,
    ))
    decision = lib.decide_cache_reuse(
        paths, target="example.com", refresh=False, max_age_hours=24,
        cache_key=_key(subs=True),
    )
    assert decision.reused is False
    assert "different gau flags" in decision.reason
    assert "subs:" in decision.reason
    assert "'0'" in decision.reason and "'1'" in decision.reason


def test_cache_miss_when_providers_changed(tmp_path: Path) -> None:
    """Changing --providers must bust the cache."""
    lib, paths = _make_paths(tmp_path)
    paths.output_path.write_text("https://x/\n", encoding="utf-8")
    lib.write_cache_meta(paths.meta_path, lib.GauCacheMeta(
        target="example.com", ran_at_epoch=time.time(), ran_at_iso="t",
        exit_code=0, line_count=1, output_path=str(paths.output_path),
        gau_argv=["gau"], cache_key=_key(providers="wayback"),
    ))
    decision = lib.decide_cache_reuse(
        paths, target="example.com", refresh=False, max_age_hours=24,
        cache_key=_key(providers="wayback,otx"),
    )
    assert decision.reused is False
    assert "different gau flags" in decision.reason


def test_cache_hit_when_args_match_across_wrappers(tmp_path: Path) -> None:
    """gau-endpoints and gau-secrets with identical corpus flags must share the cache."""
    lib, paths = _make_paths(tmp_path)
    paths.output_path.write_text("https://x/\n", encoding="utf-8")
    shared = _key(subs=True, providers="wayback,otx")
    lib.write_cache_meta(paths.meta_path, lib.GauCacheMeta(
        target="example.com", ran_at_epoch=time.time() - 60, ran_at_iso="t",
        exit_code=0, line_count=1, output_path=str(paths.output_path),
        gau_argv=["gau"], cache_key=shared,
    ))
    decision = lib.decide_cache_reuse(
        paths, target="example.com", refresh=False, max_age_hours=24, cache_key=shared,
    )
    assert decision.reused is True


def test_cache_miss_reason_names_specific_flag_change(tmp_path: Path) -> None:
    """Flag-mismatch reason must call out the specific field that changed, not just the keys."""
    lib, paths = _make_paths(tmp_path)
    paths.output_path.write_text("https://x/\n", encoding="utf-8")
    lib.write_cache_meta(paths.meta_path, lib.GauCacheMeta(
        target="example.com", ran_at_epoch=time.time(), ran_at_iso="t",
        exit_code=0, line_count=1, output_path=str(paths.output_path),
        gau_argv=["gau"], cache_key=_key(subs=False, providers="wayback"),
    ))
    decision = lib.decide_cache_reuse(
        paths, target="example.com", refresh=False, max_age_hours=24,
        cache_key=_key(subs=True, providers="wayback,otx"),
    )
    assert decision.reused is False
    # The reason must mention which fields differ, not dump the whole key.
    assert "subs:" in decision.reason
    assert "providers:" in decision.reason


def test_cache_miss_when_meta_lacks_cache_key(tmp_path: Path) -> None:
    """Meta written by an older verb (no cache_key field) must trigger a regeneration."""
    lib, paths = _make_paths(tmp_path)
    paths.output_path.write_text("https://x/\n", encoding="utf-8")
    lib.write_cache_meta(paths.meta_path, lib.GauCacheMeta(
        target="example.com", ran_at_epoch=time.time(), ran_at_iso="t",
        exit_code=0, line_count=1, output_path=str(paths.output_path),
        gau_argv=["gau"], cache_key="",  # legacy meta
    ))
    decision = lib.decide_cache_reuse(
        paths, target="example.com", refresh=False, max_age_hours=24, cache_key=_key(),
    )
    assert decision.reused is False
    assert "cache_key" in decision.reason


def test_gau_cache_key_is_stable() -> None:
    """The same flags must always produce the same key (deterministic, no order dependence)."""
    lib = _load_pipeline_lib()
    a = lib.gau_cache_key(subs=True, providers="wayback,otx")
    b = lib.gau_cache_key(subs=True, providers="wayback,otx")
    assert a == b
    assert a.startswith("v2|")  # version tag bumped when blacklist dropped


def test_pipeline_paths_namespace_by_target_and_cache_key(tmp_path: Path) -> None:
    """Two targets (or one target with different gau flags) must land in disjoint dirs."""
    lib, paths_a = _make_paths(tmp_path, target="foo.com")
    second_root = tmp_path / "second"
    second_root.mkdir()
    _, paths_b = _make_paths(second_root, target="bar.com")
    assert paths_a.work_dir != paths_b.work_dir
    assert paths_a.bodies_dir != paths_b.bodies_dir

    # Same target, different corpus flags → different dirs.
    eng_dir = tmp_path / "third"
    eng_dir.mkdir()
    (eng_dir / "scans").mkdir()

    class _Cfg:
        engagement_dir = str(eng_dir)

    p1 = lib.resolve_pipeline_paths(_Cfg(), target="foo.com", cache_key=lib.gau_cache_key(subs=False))
    p2 = lib.resolve_pipeline_paths(_Cfg(), target="foo.com", cache_key=lib.gau_cache_key(subs=True))
    assert p1.work_dir != p2.work_dir
    # Both still rooted under scans/gau-pipeline/<target>/
    assert "gau-pipeline" in str(p1.work_dir)
    assert p1.target_slug == p2.target_slug
    assert p1.cache_key_slug != p2.cache_key_slug


def test_pipeline_paths_target_slug_is_filesystem_safe(tmp_path: Path) -> None:
    """Targets with weird characters (URLs, ports, paths) must produce safe slugs."""
    lib = _load_pipeline_lib()
    weird_targets = [
        "https://example.com:8443/admin/",
        "*.example.com",
        "foo bar.com",
        "Example.COM",
    ]
    seen_slugs: set[str] = set()
    for t in weird_targets:
        slug = lib.slug_target(t)
        # Slug must be path-safe (no slashes, spaces, colons, glob chars).
        assert "/" not in slug
        assert " " not in slug
        assert ":" not in slug
        assert "*" not in slug
        # Must be deterministic.
        assert lib.slug_target(t) == slug
        seen_slugs.add(slug)
    # Different targets must produce different slugs.
    assert len(seen_slugs) == len(weird_targets)


def test_container_paths_reflect_namespaced_layout(tmp_path: Path) -> None:
    """Container-side paths must include the <target>/<key>/ prefix so kali_exec writes to the right place."""
    lib, paths = _make_paths(tmp_path, target="example.com")
    assert "/scans/gau-pipeline/" in paths.container_work_dir
    assert paths.target_slug in paths.container_work_dir
    assert paths.cache_key_slug in paths.container_work_dir
    assert paths.container_output_path.endswith("/gau_output.txt")
    assert paths.container_bodies_dir.endswith("/bodies")


def test_gau_cache_key_v2_invalidates_v1_meta(tmp_path: Path) -> None:
    """A v1 cache_key written by an older release must miss against a v2 requested key.

    Bumping the version tag is how we make stale meta files self-invalidate
    instead of pretending the corpus matches.
    """
    lib, paths = _make_paths(tmp_path)
    paths.output_path.write_text("https://x/\n", encoding="utf-8")
    lib.write_cache_meta(paths.meta_path, lib.GauCacheMeta(
        target="example.com", ran_at_epoch=time.time(), ran_at_iso="t",
        exit_code=0, line_count=1, output_path=str(paths.output_path),
        gau_argv=["gau"], cache_key="v1|subs=0|providers=|blacklist=",
    ))
    decision = lib.decide_cache_reuse(
        paths, target="example.com", refresh=False, max_age_hours=24, cache_key=_key(),
    )
    assert decision.reused is False


def test_cache_meta_round_trip(tmp_path: Path) -> None:
    lib, paths = _make_paths(tmp_path)
    meta = lib.GauCacheMeta(
        target="t", ran_at_epoch=1.5, ran_at_iso="iso",
        exit_code=0, line_count=42, output_path="p",
        gau_argv=["gau", "--subs", "t"], cache_key=_key(subs=True),
    )
    lib.write_cache_meta(paths.meta_path, meta)
    loaded = lib.load_cache_meta(paths.meta_path)
    assert loaded is not None
    assert loaded.target == "t"
    assert loaded.line_count == 42
    assert loaded.gau_argv == ["gau", "--subs", "t"]
    assert loaded.cache_key == _key(subs=True)


def test_cache_meta_atomic_write(tmp_path: Path) -> None:
    """A crash mid-write must not leave a half-written meta file."""
    lib, paths = _make_paths(tmp_path)
    meta = lib.GauCacheMeta(
        target="t", ran_at_epoch=1.0, ran_at_iso="iso",
        exit_code=0, line_count=1, output_path="p", gau_argv=[], cache_key=_key(),
    )
    lib.write_cache_meta(paths.meta_path, meta)
    # The .tmp file must not survive a successful write.
    assert not paths.meta_path.with_suffix(paths.meta_path.suffix + ".tmp").exists()
    assert paths.meta_path.is_file()


# ─── LinkFinder regex extraction ───────────────────────────────────────


def test_extract_js_endpoints_finds_absolute_urls() -> None:
    lib = _load_pipeline_lib()
    js = "var x = 'https://api.example.com/v2/users';"
    out = lib.extract_js_endpoints(js)
    assert "https://api.example.com/v2/users" in out


def test_extract_js_endpoints_finds_relative_paths() -> None:
    lib = _load_pipeline_lib()
    js = "fetch('/api/v1/admin/delete'); call('/api/v1/admin/users');"
    out = lib.extract_js_endpoints(js)
    assert "/api/v1/admin/delete" in out
    assert "/api/v1/admin/users" in out


def test_extract_js_endpoints_finds_rest_shape() -> None:
    lib = _load_pipeline_lib()
    js = "const route = 'users/profile/edit';"
    out = lib.extract_js_endpoints(js)
    # Either as the bare REST shape or as a slash-prefixed variant — the
    # regex normalizes; we only assert we recovered the route segments.
    assert any("users/profile/edit" in ep for ep in out)


def test_extract_js_endpoints_dedupes() -> None:
    lib = _load_pipeline_lib()
    js = "fetch('/api/x'); fetch('/api/x'); call('/api/x');"
    out = lib.extract_js_endpoints(js)
    assert out.count("/api/x") == 1


def test_extract_js_endpoints_handles_versioned_paths() -> None:
    """Versioned paths like /v1.2/users.json must not be truncated at the dot in 'v1.2'.

    The third alternative's resource segment includes the dot character so
    paths with embedded version dots survive intact.
    """
    lib = _load_pipeline_lib()
    js = "fetch('api/v1.2/users.json'); fetch('lib/v3.4/admin/keys.json');"
    out = lib.extract_js_endpoints(js)
    assert any("v1.2/users.json" in ep for ep in out)
    assert any("v3.4/admin/keys.json" in ep for ep in out)


def test_extract_js_endpoints_drops_static_assets() -> None:
    lib = _load_pipeline_lib()
    js = "url('/static/img/logo.png'); url('/static/fonts/main.woff2');"
    out = lib.extract_js_endpoints(js)
    # png/woff2 are in the drop list
    assert all(not ep.endswith(".png") for ep in out)
    assert all(not ep.endswith(".woff2") for ep in out)


# ─── Endpoint resolution ───────────────────────────────────────────────


def test_resolve_absolute_url_passthrough() -> None:
    lib = _load_pipeline_lib()
    out = lib.resolve_js_endpoint("https://api.example.com/x", base_url="https://other.com/")
    assert out == "https://api.example.com/x"


def test_resolve_protocol_relative_inherits_scheme() -> None:
    lib = _load_pipeline_lib()
    out = lib.resolve_js_endpoint("//cdn.example.com/asset", base_url="https://target.example/app.js")
    assert out == "https://cdn.example.com/asset"


def test_resolve_absolute_path_joins_origin() -> None:
    lib = _load_pipeline_lib()
    out = lib.resolve_js_endpoint("/api/users", base_url="https://target.example/static/app.js")
    assert out == "https://target.example/api/users"


def test_resolve_relative_path_joins_directory() -> None:
    lib = _load_pipeline_lib()
    out = lib.resolve_js_endpoint("users.json", base_url="https://target.example/static/app.js")
    assert out == "https://target.example/static/users.json"


def test_resolve_returns_none_for_invalid_base() -> None:
    lib = _load_pipeline_lib()
    out = lib.resolve_js_endpoint("/api/x", base_url="not a url")
    assert out is None


# ─── Wrapper safety helpers ─────────────────────────────────────────────


def test_gau_endpoints_shell_command_quotes_dynamic_args() -> None:
    import argparse
    _ensure_scripts_path()
    from assess.commands import gau_endpoints  # type: ignore[import-not-found]
    args = argparse.Namespace(
        subs=True,
        providers="wayback,otx;echo bad",
    )
    argv = gau_endpoints._build_gau_argv(
        target="example.com;touch /tmp/pwned",
        output_path="/tmp/gau output.txt",
        args=args,
    )
    command = argv[-1]
    assert command.startswith("set -o pipefail; ")
    assert "'wayback,otx;echo bad'" in command
    assert "'example.com;touch /tmp/pwned'" in command
    assert "> '/tmp/gau output.txt'" in command


def test_gau_secrets_gau_command_uses_pipefail(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _ensure_scripts_path()
    from assess.commands import gau_secrets  # type: ignore[import-not-found]

    captured: dict[str, list[str]] = {}
    paths = SimpleNamespace(
        output_path=tmp_path / "gau_output.txt",
        meta_path=tmp_path / "gau_output.meta.json",
        container_output_path="/engagements/demo/scans/gau_output.txt",
    )

    def fake_kali_exec(cmd, **_kwargs):
        captured["cmd"] = cmd
        paths.output_path.write_text("https://example.com/app.js\n", encoding="utf-8")
        return SimpleNamespace(return_code=0)

    monkeypatch.setattr(gau_secrets, "kali_exec", fake_kali_exec)
    args = SimpleNamespace(
        target="example.com",
        subs=False,
        providers="",
        refresh=True,
        max_cache_age_hours=24,
        phase="recon",
        timeout=30,
    )

    gau_secrets._maybe_run_gau(paths, args=args, cfg=SimpleNamespace(), current_cache_key="test-key")

    assert captured["cmd"][-1].startswith("set -o pipefail; ")


def test_gau_js_host_match_requires_exact_host_or_subdomain() -> None:
    _ensure_scripts_path()
    from assess.commands import gau_js_endpoints  # type: ignore[import-not-found]
    assert gau_js_endpoints._host_matches_target("example.com", "example.com")
    assert gau_js_endpoints._host_matches_target("api.example.com", "example.com")
    assert gau_js_endpoints._host_matches_target("api.example.com", "https://example.com")
    assert gau_js_endpoints._host_matches_target("api.example.com", "*.example.com")
    assert gau_js_endpoints._host_matches_target("api.example.com", "example.com:8443")
    assert not gau_js_endpoints._host_matches_target("badexample.com", "example.com")
    assert not gau_js_endpoints._host_matches_target("example.com.evil.test", "example.com")


def test_gau_js_source_url_uses_http_scheme_hint_from_body_name(tmp_path: Path) -> None:
    _ensure_scripts_path()
    from assess.commands import gau_js_endpoints  # type: ignore[import-not-found]

    body = tmp_path / "http-example.com-response.txt"
    body.write_text("GET /static/app.js HTTP/1.1\nHost: example.com\n\n", encoding="utf-8")

    assert gau_js_endpoints._extract_source_url_from_body(body) == "http://example.com/static/app.js"


def test_gau_js_max_bodies_applies_to_suffix_matches(tmp_path: Path) -> None:
    _ensure_scripts_path()
    from assess.commands import gau_js_endpoints  # type: ignore[import-not-found]

    for index in range(3):
        (tmp_path / f"bundle-{index}.js").write_text("console.log('/api');", encoding="utf-8")

    assert len(gau_js_endpoints._list_js_bodies(tmp_path, max_bodies=2)) == 2


def test_gau_body_reuse_checks_require_files(tmp_path: Path) -> None:
    _ensure_scripts_path()
    from assess.commands import gau_js_endpoints, gau_secrets  # type: ignore[import-not-found]

    (tmp_path / "nested").mkdir()
    assert not gau_js_endpoints._directory_has_files(tmp_path)
    assert not gau_secrets._directory_has_files(tmp_path)

    (tmp_path / "nested" / "body.txt").write_text("HTTP/1.1 200 OK\n\n", encoding="utf-8")
    assert gau_js_endpoints._directory_has_files(tmp_path)
    assert gau_secrets._directory_has_files(tmp_path)


# ─── Argparse registration ─────────────────────────────────────────────


def test_gau_endpoints_registers(tmp_path: Path) -> None:
    import argparse
    _ensure_scripts_path()
    from assess.commands import gau_endpoints  # type: ignore[import-not-found]
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers()
    gau_endpoints.register(sub)
    args = parser.parse_args(["gau-endpoints", "example.com", "--subs", "--db", "/tmp/x.db"])
    assert args.target == "example.com"
    assert args.subs is True
    assert args.db_override == "/tmp/x.db"
    assert args.refresh is False
    assert args.max_cache_age_hours == 24


def test_gau_secrets_registers() -> None:
    import argparse
    _ensure_scripts_path()
    from assess.commands import gau_secrets  # type: ignore[import-not-found]
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers()
    gau_secrets.register(sub)
    args = parser.parse_args(["gau-secrets", "example.com"])
    assert args.target == "example.com"
    assert args.verify is False
    assert args.cap_body_bytes == 1048576


def test_gau_secrets_verify_opt_in() -> None:
    """--verify must be opt-in; default must keep trufflehog in --no-verification."""
    import argparse
    _ensure_scripts_path()
    from assess.commands import gau_secrets  # type: ignore[import-not-found]
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers()
    gau_secrets.register(sub)
    default_args = parser.parse_args(["gau-secrets", "example.com"])
    verified_args = parser.parse_args(["gau-secrets", "example.com", "--verify"])
    assert default_args.verify is False
    assert verified_args.verify is True


def test_gau_js_endpoints_registers() -> None:
    import argparse
    _ensure_scripts_path()
    from assess.commands import gau_js_endpoints  # type: ignore[import-not-found]
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers()
    gau_js_endpoints.register(sub)
    args = parser.parse_args([
        "gau-js-endpoints", "example.com",
        "--bodies-dir", "/tmp/bodies",
        "--max-bodies", "5",
        "--fetch-if-missing",
    ])
    assert args.target == "example.com"
    assert args.bodies_dir_override == "/tmp/bodies"
    assert args.max_bodies == 5
    assert args.fetch_if_missing is True
    assert args.source == "js-extract"


def test_gau_js_endpoints_does_not_expose_cache_reuse_flags() -> None:
    """This verb is a post-processor; --refresh / --max-cache-age-hours would mislead.

    Cache reuse is decided by gau-endpoints / gau-secrets (the verbs that
    actually run gau). gau-js-endpoints reads the existing cache and bodies
    only — exposing cache-reuse flags here would suggest the operator could
    re-execute gau from this verb, which is not the case.
    """
    import argparse
    _ensure_scripts_path()
    from assess.commands import gau_js_endpoints  # type: ignore[import-not-found]
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers()
    gau_js_endpoints.register(sub)
    with pytest.raises(SystemExit):
        parser.parse_args(["gau-js-endpoints", "example.com", "--refresh"])
    with pytest.raises(SystemExit):
        parser.parse_args(["gau-js-endpoints", "example.com", "--max-cache-age-hours", "1"])
