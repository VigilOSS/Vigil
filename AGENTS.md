# Repository instructions

This file guides development of Vigil. Engagement prompts under `agent/` are separate
runtime instructions; do not treat this maintainer guide as an engagement prompt.

Read [CODE-MAP.md](CODE-MAP.md) before changing a contract or subsystem boundary.
Use [CONTRIBUTING.md](CONTRIBUTING.md) for setup, [README.md](README.md) for installation
and runtime usage, and [maintainer recipes](docs/maintainer-guide.md) for the applicable
extension, freshness, or report-template procedure.

## Code quality

- Inspect the owning implementation, contracts, and tests before adding functionality.
  Extend the existing path; keep each value and decision in its canonical owner.
- Preserve precision, deep coverage, and trustworthy state. Do not narrow detection or
  classification coverage for convenience; use pinned regressions to establish correctness.
- For behavior changes, run the smallest regression before production edits and confirm
  it fails for the intended behavior, then make it pass and run the impacted suite.
- Keep changes cohesive: update registrations, generated artifacts, schemas, and callers
  together. Match surrounding idioms; remove obsolete code and unnecessary abstractions.
- Use Acme and reserved `example.com` / `.example` domains in fixtures and examples.
  Never commit personal identities, employer/customer material, real engagement data,
  credentials, local-machine paths, or private benchmark content.
- Report what changed, why, validation results, and remaining limitations. Explain both
  the operator-visible effect and the concrete mechanism when a breakdown is requested.

## Version control and maintainer identity

Use Jujutsu in colocated checkouts (`.jj/` alongside `.git/`). Initialize a fresh clone
once with `jj git init --colocate`; use `jj` for commits, bookmarks, conflict resolution,
and pushes. Keep Git for read-only inspection, and preserve unrelated working-copy changes.

Maintainer clones must run `python3 tools/check_public_commit_identity.py --install` to
install identity hooks and configure Git/jj as Vigil OSS Maintainers <vigil.oss@proton.me>.

The installer also configures a clone-local jj push guard. Run the revision identity check
before publishing; CI checks canonical history while allowing contributor fork/PR identities.

```bash
python3 tools/check_public_commit_identity.py --config
python3 tools/check_public_commit_identity.py --revision main --revision v1.0.0
```

## Operator data and security boundaries

Credentials, tokens, cookies, authorization headers, proxy URLs, raw argv, and evidence
render verbatim in engagement views and exports. Do not add masking or lossy projections.
[ADR 0019](docs/adr/0019-vigil-does-not-defend-against-its-own-operator.md) governs this boundary;
it does not authorize committing operator data to the public repository or weakening
exploit approval, tool-policy gates, proof integrity, or untrusted-target-text containment.
[ADR 0018](docs/adr/0018-target-derived-text-is-untrusted-data.md) governs containment and safe rendering.

## Contracts and documentation

- Keep durable payloads and lifecycle truth in executable helpers and backend models.
  Prompts point at `vigil assess contract` instead of duplicating schemas.
- Update CODE-MAP.md when an entrypoint, contract owner, registration, API family, or
  generation relationship changes. Do not churn it for internal implementation details.
- Read the relevant [maintainer recipe](docs/maintainer-guide.md) before adding or renaming
  a skill, reference, assess verb, oracle, language/index catalogue, or eval case.
- Use content digests for install-managed freshness, never mtimes. Keep declared image
  and build input sets synchronized with consumers; see the maintainer freshness recipe.
- Keep CLI rename/removal notes in CHANGELOG.md and update every live caller and contract.
  Preserve historical audit records as records of what actually ran.

## Prompt system flow

Edit canonical prompt sources, never generated wrappers:

- `agent/operator-core.md`, its code overlay, and the blue core own operator workflows.
- `agent/agents/*.md`, `agent/shared-constraints*.md`, and `agent/rules/*.md` own role-specific,
  cross-role, and always-active guidance respectively.
- Generated `agent/AGENTS*.md`, `agent/CLAUDE.md`, and client wrapper trees come from the renderer.

Before deleting apparently duplicated instructions, determine which roles load each copy
and search for references to its heading. Specialists do not load operator cores; deleting
an operator rule cannot be justified by a specialist-only copy, or vice versa.

For finding, lifecycle, or dispatch changes, review the applicable operator core, role
prompt, shared constraints, owning CLI/backend helpers, and tests together. Propagate new
prompt primitives to every applicable role and apply the
[prompt-authoring standards](docs/prompt-authoring-standards.md).

```bash
(cd agent && ./scripts/render-operator-prompts.sh repo)
# Also regenerate blue wrappers when blue/shared blue prompt sources change:
(cd agent && ./scripts/render-operator-prompts.sh repo --type blue)
```

Review generated diffs directly. Do not add tests that pin Markdown wording or headings;
test executable contracts and structural invariants instead.

## Tests & verification

`.github/workflows/ci.yml` owns the blocking gates. Use the backend venv for all four pytest
scopes. Never run bare pytest from the repository root: duplicate test basenames collide.
Absolute suite paths are required because `uv --directory` changes the working directory.

```bash
VIGIL_REPO=$(jj root)
uv run --directory orchestrator/backend --extra dev pytest
uv run --directory orchestrator/backend --extra dev pytest "$VIGIL_REPO/tests" --ignore="$VIGIL_REPO/tests/eval"
uv run --directory orchestrator/backend --extra dev pytest "$VIGIL_REPO/agent/scripts/assess/tests"
uv run --directory orchestrator/backend --extra dev pytest "$VIGIL_REPO/tests/eval"
uvx ruff check .
uvx --with-editable . mypy src/vigil_cli
(cd orchestrator/frontend && npm ci && npm test && npm run build)
(cd orchestrator/report && npm ci && npm test && npm run build)
(cd agent && ./scripts/render-operator-prompts.sh check)
(cd agent && ./scripts/render-operator-prompts.sh check --type blue)
uv run --directory orchestrator/backend python scripts/generate_agent_schemas.py --check
```

Regenerate schemas with the same generator without `--check` when request models or agent
schema overlays change. Backend pytest defaults to parallel workers; use `-n 0` for debugging.
Integration tests are excluded by default and require a prepared live runtime before opting
in with `-m integration`. Run the complete blocking matrix before publishing; report skips
and failures explicitly. See the maintainer guide for runner details and the report boundary.
