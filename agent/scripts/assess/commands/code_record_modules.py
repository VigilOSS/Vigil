"""vigil assess code-record modules — POST module definitions for a code repository."""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

from assess.lib.client import AssessmentClient, AssessError
from assess.lib.config import load_config


def _derive_module_key(name: str) -> str:
    """Slugify a module name into a valid module_key."""
    key = name.strip().lower()
    key = re.sub(r"[^a-z0-9]+", "_", key)
    return key.strip("_") or "unknown"


# Generic names like 'auth_module_1', 'module_2', 'unknown_module' indicate the
# agent emitting modules did not pick meaningful identifiers. Reject these at
# the CLI so the backend never accumulates undescriptive rows that
# code-architect / report-writer cannot map to a real subsystem.
_GENERIC_MODULE_PATTERNS = (
    re.compile(r"^module_\d+$"),
    re.compile(r"^[a-z]+_module_\d+$"),
    re.compile(r"^unknown(?:_module)?$"),
    re.compile(r"^undefined(?:_module)?$"),
)


def _is_generic_label(value: str) -> bool:
    candidate = (value or "").strip().lower()
    if not candidate:
        return True
    return any(pattern.match(candidate) for pattern in _GENERIC_MODULE_PATTERNS)


def _check_auto_derived_key_collisions(modules: list[dict], existing_modules: list[dict]) -> None:
    existing_by_key = {
        str(module.get("module_key", "")): str(module.get("name", "")).strip()
        for module in existing_modules
        if module.get("module_key")
    }
    auto_derived_by_key: dict[str, str] = {}
    for mod in modules:
        if mod.get("_auto_derived_module_key") is not True:
            continue
        module_key = str(mod["module_key"])
        module_name = str(mod.get("name", "")).strip()
        previous_name = auto_derived_by_key.get(module_key)
        if previous_name is not None and previous_name != module_name:
            print(
                f"Auto-derived module_key collision for '{module_key}': "
                f"'{previous_name}' and '{module_name}'. Provide explicit module_key values.",
                file=sys.stderr,
            )
            sys.exit(1)
        existing_name = existing_by_key.get(module_key)
        if existing_name is not None and existing_name != module_name:
            print(
                f"Auto-derived module_key '{module_key}' for '{module_name}' collides with existing module "
                f"'{existing_name}'. Provide an explicit module_key.",
                file=sys.stderr,
            )
            sys.exit(1)
        auto_derived_by_key[module_key] = module_name


def _require_modules_receipt(
    response: object, *, repo_id: int, modules: list[dict]
) -> list[dict]:
    valid_rows = isinstance(response, list) and len(response) == len(modules)
    rows = response if isinstance(response, list) else []
    returned_keys: list[str] = []
    if valid_rows:
        for row in rows:
            if not isinstance(row, dict):
                valid_rows = False
                break
            row_id = row.get("id")
            row_repo_id = row.get("repo_id")
            module_key = row.get("module_key")
            if (
                not isinstance(row_id, int)
                or isinstance(row_id, bool)
                or row_id < 1
                or not isinstance(row_repo_id, int)
                or isinstance(row_repo_id, bool)
                or row_repo_id != repo_id
                or not isinstance(module_key, str)
                or not module_key
            ):
                valid_rows = False
                break
            returned_keys.append(module_key)
    expected_keys = [str(module["module_key"]) for module in modules]
    if not valid_rows or sorted(returned_keys) != sorted(expected_keys):
        raise AssessError(
            "record code modules: backend response did not identify the canonical "
            "module id/repo/key rows for every requested module; the write may have "
            "committed, so inspect `vigil assess code list-modules` and do not retry "
            "automatically"
        )
    return rows


def register(subparsers) -> None:
    p = subparsers.add_parser("modules", help="Record module definitions for a code repository")
    p.add_argument("repo_id", help="Repository ID")
    p.add_argument("modules_json", help="Path to JSON file with array of module objects")
    p.set_defaults(func=run)


def run(args) -> None:
    json_path = Path(args.modules_json)
    if not json_path.is_file():
        print(f"Modules JSON file not found: {args.modules_json}", file=sys.stderr)
        sys.exit(1)

    modules = json.loads(json_path.read_text(encoding="utf-8"))
    if not isinstance(modules, list):
        print("Modules file must contain a JSON array", file=sys.stderr)
        sys.exit(1)

    if not modules:
        print("No modules to submit.", file=sys.stderr)
        sys.exit(0)

    # Validate and normalize required fields
    for i, mod in enumerate(modules):
        if not isinstance(mod, dict):
            print(f"Item {i} is not a JSON object", file=sys.stderr)
            sys.exit(1)
        if 'module_key' not in mod:
            name = mod.get('name', '')
            if not name:
                print(f"Item {i} missing both 'module_key' and 'name'", file=sys.stderr)
                sys.exit(1)
            mod['module_key'] = _derive_module_key(name)
            mod['_auto_derived_module_key'] = True
            print(f"Auto-derived module_key '{mod['module_key']}' from name '{name}'", file=sys.stderr)

        # Reject generic auto-pattern labels: 'auth_module_1', 'module_2',
        # 'unknown_module'. These come from agents that did not pick
        # meaningful identifiers and end up unmappable downstream.
        for label_field in ("module_key", "name"):
            value = mod.get(label_field, "")
            if isinstance(value, str) and _is_generic_label(value):
                print(
                    f"Item {i} {label_field}='{value}' is a generic auto-pattern "
                    "(e.g. 'module_N', '*_module_N', 'unknown_module'). "
                    "Pick a meaningful identifier reflecting the actual subsystem "
                    "(auth_login, payment_settlement, ws_subscription, etc.) — "
                    "the report and code-architect downstream depend on it.",
                    file=sys.stderr,
                )
                sys.exit(1)

    repo_id = int(args.repo_id)

    cfg = load_config(args.engagement_dir)
    with AssessmentClient(cfg.base_url, cfg.engagement_key) as client:
        existing_modules = client.get(f"code/modules?repo_id={repo_id}")
        if not isinstance(existing_modules, list):
            print(f"Unexpected response while fetching existing modules: {type(existing_modules)}", file=sys.stderr)
            sys.exit(1)
        _check_auto_derived_key_collisions(modules, existing_modules)

        for mod in modules:
            mod.pop('_auto_derived_module_key', None)

        payload = {
            'repo_id': repo_id,
            'modules': modules,
        }
        result = _require_modules_receipt(
            client.post('code/modules', payload),
            repo_id=repo_id,
            modules=modules,
        )

    print("=== Code Modules Summary ===")
    print(f"Modules created: {len(result)}")
    for mod in result:
        print(f"  [{mod['id']}] {mod['module_key']}: {mod.get('name', '?')}")
