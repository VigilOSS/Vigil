from __future__ import annotations

import errno
import hashlib
import json
import os
import re
import secrets
import threading
from collections.abc import Callable, Iterable
from dataclasses import asdict, dataclass, replace
from pathlib import Path
from typing import TextIO, cast

from .config import config_path

try:
    import fcntl as _fcntl
except ImportError:  # Windows
    _fcntl = None  # type: ignore[assignment]

try:
    import msvcrt as _msvcrt
except ImportError:  # POSIX
    _msvcrt = None  # type: ignore[assignment]

RELAY_METADATA_FILENAME = "relay-routing.json"
# Spelling this record shipped under before the relay-slot rename. Installs that
# allocated a route then still own it, so every read falls back to this name and
# leaves the spelling alone; only an allocation or reconcile writes the new one.
LEGACY_RELAY_METADATA_FILENAME = "tenant-routing.json"
# Where releases before the record followed the runtime data directory kept it,
# whatever that directory was. Reads fall back here so an install that allocated
# then is never mistaken for an unrouted one, and `vigil install` moves the
# record into :func:`oob_state_dir`.
_INSTALL_ROOT_OOB_STATE_PATH = Path(".runtime-data/oob")
# Filename stems of the routing records THIS module writes, in both spellings,
# covering their ``.lock`` and temporary siblings. They are bookkeeping, not
# evidence of a live channel: an interrupted pin leaves a lock file behind with
# nothing ever having been routed through it.
_ROUTING_RECORD_STEMS = (
    Path(RELAY_METADATA_FILENAME).stem,
    Path(LEGACY_RELAY_METADATA_FILENAME).stem,
)
ROUTING_VERSION = 1
PORT_BLOCK_START = 20_000
PORT_BLOCK_SIZE = 2
PORT_SLOT_COUNT = 20_000
LEGACY_DNS_REMOTE_PORT = 53
LEGACY_REVERSE_REMOTE_PORT = 8443
OOB_ALLOCATION_REGISTRY_FILENAME = "oob-allocations.json"

# A cross-device move, or a filesystem without hard links, copies instead.
_NO_HARD_LINK_ERRNOS = frozenset({errno.EXDEV, errno.EPERM, errno.ENOTSUP, errno.EOPNOTSUPP})

_THREAD_LOCKS: dict[str, threading.Lock] = {}
_THREAD_LOCKS_GUARD = threading.Lock()
_DNS_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


@dataclass(frozen=True, slots=True)
class OobRelayRoute:
    version: int
    install_id: str
    slot_name: str
    slot_prefix: str
    base_domain: str
    oob_domain: str
    allocation_slot: int
    dns_remote_port: int
    reverse_remote_port: int
    legacy: bool
    metadata_path: Path

    @property
    def port_range(self) -> tuple[int, int]:
        return (self.dns_remote_port, self.reverse_remote_port)

    def serializable(self) -> dict[str, object]:
        payload = asdict(self)
        payload.pop("metadata_path")
        return payload


def sanitize_slot_prefix(value: str) -> str:
    raw = str(value).strip()
    if not raw or raw in {".", ".."} or "/" in raw or "\\" in raw:
        raise SystemExit(f"Invalid OOB relay slot identity {value!r}: expected a slot name, not a path.")
    clean = re.sub(r"[^a-z0-9]+", "-", raw.lower()).strip("-")
    if not clean:
        raise SystemExit(f"Invalid OOB relay slot identity {value!r}: no DNS-safe characters remain.")
    return clean[:40].rstrip("-")


def normalize_base_domain(value: str) -> str:
    """Validate one literal DNS base domain before it reaches FRP/Caddy output."""
    domain = str(value).strip().rstrip(".").lower()
    labels = domain.split(".") if domain else []
    if (
        len(labels) < 2
        or len(domain) > 253
        or any(not _DNS_LABEL_RE.fullmatch(label) for label in labels)
    ):
        raise SystemExit(
            f"Invalid OOB base domain {value!r}: expected a literal DNS name "
            "with RFC-compatible labels (no wildcard, whitespace, or underscore)."
        )
    return domain


def _default_identity() -> str:
    return secrets.token_hex(16)


def _default_slot_candidates(identity: str) -> Iterable[int]:
    seed = hashlib.sha256(identity.encode("utf-8")).digest()
    start = int.from_bytes(seed[:8], "big") % PORT_SLOT_COUNT
    for offset in range(PORT_SLOT_COUNT):
        yield (start + offset) % PORT_SLOT_COUNT


def oob_state_dir(
    install_root: Path,
    *,
    preserve_install_path: bool = False,
    canonical_install_root: Path | None = None,
) -> Path:
    """The one directory everything an OOB session writes lives in.

    That is the container's ``/data/oob`` (rendered ``frpc.toml``, its log, the
    interactsh watch log, the runtime route marker, one file per registered
    client) and, host-side, the routing record plus the poll channel cache kept
    beside them. Its host side is the runtime data directory, relocatable
    through VIGIL_RUNTIME_DATA_DIR or the install `.env`, so it is derived from
    runtime's own resolver instead of a second copy of that precedence.

    `vigil install` passes its pinned directory as ``.`` and the path it stands
    for as ``canonical_install_root``. The workspace registers its runtime state
    as an absolute path under that root, which is re-anchored at ``.`` so the
    install never reaches it again through a path that could have been swapped.
    """
    # Imported here because `runtime` pulls in the Docker helpers that the rest
    # of this filesystem-only module never needs.
    from .runtime import _resolve_runtime_data_dir

    root = install_root.expanduser()
    if not preserve_install_path:
        root = root.resolve()
    data_dir = _resolve_runtime_data_dir(root)
    if canonical_install_root is not None:
        canonical = _install_identity_path(
            canonical_install_root, preserve_install_path=preserve_install_path
        )
        if data_dir.is_relative_to(canonical):
            data_dir = root / data_dir.relative_to(canonical)
    return data_dir / "oob"


def _metadata_path(
    install_root: Path,
    *,
    preserve_install_path: bool = False,
    canonical_install_root: Path | None = None,
) -> Path:
    state_dir = oob_state_dir(
        install_root,
        preserve_install_path=preserve_install_path,
        canonical_install_root=canonical_install_root,
    )
    _require_contained(state_dir, state_dir.parent, "the runtime data directory")
    return state_dir / RELAY_METADATA_FILENAME


def _install_root_state_dir(install_root: Path, *, preserve_install_path: bool) -> Path:
    root = install_root.expanduser()
    resolved_root = root.resolve()
    if not preserve_install_path:
        root = resolved_root
    state_dir = root / _INSTALL_ROOT_OOB_STATE_PATH
    _require_contained(state_dir, resolved_root, "install root")
    return state_dir


def _require_contained(state_dir: Path, anchor: Path, anchor_name: str) -> None:
    if not state_dir.resolve(strict=False).is_relative_to(anchor.resolve(strict=False)):
        raise SystemExit(
            f"Invalid OOB metadata path {state_dir}: escapes {anchor_name} through a symlink."
        )


def _thread_lock(path: Path) -> threading.Lock:
    key = str(path.expanduser().resolve())
    with _THREAD_LOCKS_GUARD:
        return _THREAD_LOCKS.setdefault(key, threading.Lock())


class _FileLock:
    def __init__(self, path: Path) -> None:
        self.path = path
        self._handle: TextIO | None = None
        self._thread_lock = _thread_lock(path)

    def __enter__(self) -> _FileLock:
        self._thread_lock.acquire()
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
            fd = os.open(self.path, flags, 0o600)
            handle = os.fdopen(fd, "a+", encoding="utf-8")
            self._handle = handle
            _lock_file(handle)
        except BaseException:
            if self._handle is not None:
                self._handle.close()
                self._handle = None
            self._thread_lock.release()
            raise
        return self

    def __exit__(self, *_exc: object) -> None:
        assert self._handle is not None
        try:
            _unlock_file(self._handle)
            self._handle.close()
        finally:
            self._thread_lock.release()


def _lock_file(handle: TextIO) -> None:
    if _fcntl is not None:
        _fcntl.flock(handle.fileno(), _fcntl.LOCK_EX)
        return
    if _msvcrt is None:
        raise RuntimeError("No supported file-locking backend is available.")
    handle.seek(0, os.SEEK_END)
    if handle.tell() == 0:
        handle.write("\0")
        handle.flush()
    handle.seek(0)
    _msvcrt.locking(handle.fileno(), _msvcrt.LK_LOCK, 1)


def _unlock_file(handle: TextIO) -> None:
    if _fcntl is not None:
        _fcntl.flock(handle.fileno(), _fcntl.LOCK_UN)
        return
    if _msvcrt is None:
        raise RuntimeError("No supported file-locking backend is available.")
    handle.seek(0)
    _msvcrt.locking(handle.fileno(), _msvcrt.LK_UNLCK, 1)


def _read_json(path: Path, *, default: dict[str, object] | None = None) -> dict[str, object]:
    """Parse ``path``; a missing file is ``default``, or FileNotFoundError without one."""
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        if default is None:
            raise
        return dict(default)
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"Invalid OOB routing metadata at {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise SystemExit(f"Invalid OOB routing metadata at {path}: expected a JSON object.")
    return payload


def _atomic_write_json_real(path: Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.{threading.get_ident()}.tmp")
    try:
        with temporary.open("x", encoding="utf-8") as handle:
            os.chmod(temporary, 0o600)
            json.dump(payload, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        _fsync_directory(path.parent)
    finally:
        temporary.unlink(missing_ok=True)


def _fsync_directory(path: Path) -> None:
    """Persist a rename where directory handles support fsync (not Windows)."""
    try:
        directory_fd = os.open(path, os.O_RDONLY)
    except OSError as exc:
        if isinstance(exc, PermissionError) or exc.errno in {
            errno.EACCES,
            errno.EINVAL,
            errno.ENOTSUP,
        }:
            return
        raise
    try:
        try:
            os.fsync(directory_fd)
        except OSError as exc:
            if exc.errno not in {errno.EACCES, errno.EINVAL, errno.ENOTSUP}:
                raise
    finally:
        os.close(directory_fd)


def _route_from_payload(path: Path, payload: dict[str, object]) -> OobRelayRoute:
    try:
        route = OobRelayRoute(
            version=_payload_int(payload, "version"),
            install_id=str(payload["install_id"]),
            slot_name=str(_payload_field(payload, "slot_name", "tenant_name")),
            slot_prefix=str(_payload_field(payload, "slot_prefix", "tenant_prefix")),
            base_domain=normalize_base_domain(str(payload["base_domain"])),
            oob_domain=str(payload["oob_domain"]).strip().rstrip(".").lower(),
            allocation_slot=_payload_int(payload, "allocation_slot"),
            dns_remote_port=_payload_int(payload, "dns_remote_port"),
            reverse_remote_port=_payload_int(payload, "reverse_remote_port"),
            legacy=_payload_bool(payload, "legacy"),
            metadata_path=path,
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise SystemExit(f"Invalid OOB routing metadata at {path}: missing or malformed fields.") from exc
    _validate_route(route)
    return route


def _payload_field(payload: dict[str, object], key: str, legacy_key: str) -> object:
    """Read one record field under its current name or its pre-rename name.

    Records written before the relay-slot rename spell these keys ``tenant_*``.
    Surfacing them under the current names keeps an existing install's route
    loadable without rewriting a file the caller only meant to read.
    """
    if key in payload:
        return payload[key]
    return payload[legacy_key]


def _payload_int(payload: dict[str, object], key: str) -> int:
    value = payload[key]
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        raise ValueError(key)
    return int(value)


def _payload_bool(payload: dict[str, object], key: str) -> bool:
    value = payload[key]
    if not isinstance(value, bool):
        raise ValueError(key)
    return value


def _validate_route(route: OobRelayRoute) -> None:
    if route.version != ROUTING_VERSION or not route.install_id:
        raise SystemExit(f"Invalid OOB routing metadata at {route.metadata_path}: unsupported identity/version.")
    clean = sanitize_slot_prefix(route.slot_name)
    normalized_oob_domain = normalize_base_domain(route.oob_domain)
    if route.legacy:
        valid = (
            route.slot_prefix == "legacy"
            and normalized_oob_domain == route.base_domain
            and route.allocation_slot == -1
            and route.dns_remote_port == LEGACY_DNS_REMOTE_PORT
            and route.reverse_remote_port == LEGACY_REVERSE_REMOTE_PORT
        )
    else:
        digest = hashlib.sha256(route.install_id.encode("utf-8")).hexdigest()[:16]
        expected_prefix = f"{clean}-{digest}"
        expected_dns = PORT_BLOCK_START + route.allocation_slot * PORT_BLOCK_SIZE
        valid = (
            0 <= route.allocation_slot < PORT_SLOT_COUNT
            and route.slot_prefix == expected_prefix
            and normalized_oob_domain == f"{expected_prefix}.{route.base_domain}"
            and route.dns_remote_port == expected_dns
            and route.reverse_remote_port == expected_dns + 1
        )
    if not valid:
        raise SystemExit(
            f"Invalid OOB routing metadata at {route.metadata_path}: routing metadata is inconsistent; "
            "refusing to change callback correlation or relay routing silently."
        )


def _first_record(directory: Path) -> OobRelayRoute | None:
    for name in (RELAY_METADATA_FILENAME, LEGACY_RELAY_METADATA_FILENAME):
        path = directory / name
        if path.is_symlink():
            raise SystemExit(f"Invalid OOB routing metadata at {path}: symlink files are not allowed.")
        try:
            return _route_from_payload(path, _read_json(path))
        except FileNotFoundError:
            continue
    return None


def load_relay_route(
    install_root: Path,
    *,
    preserve_install_path: bool = False,
    canonical_install_root: Path | None = None,
    registry_path: Path | None = None,
) -> OobRelayRoute | None:
    """This install's routing record: the state directory's, else the install root's.

    The install root's location is read first. `vigil install` links a record
    into the state directory before unlinking it there, so a reader that finds
    the install root's copy gone always finds the state directory's next.
    """
    state_dir = _metadata_path(
        install_root,
        preserve_install_path=preserve_install_path,
        canonical_install_root=canonical_install_root,
    ).parent
    root_state_dir = install_root.expanduser() / _INSTALL_ROOT_OOB_STATE_PATH
    fallback = None
    if root_state_dir.resolve(strict=False) != state_dir.resolve(strict=False):
        fallback = _first_record(
            _install_root_state_dir(install_root, preserve_install_path=preserve_install_path)
        )
    route = _first_record(state_dir) or fallback
    if route is None:
        return None
    if fallback is not None and fallback.install_id != route.install_id:
        raise SystemExit(
            f"OOB routing records at {route.metadata_path} and {fallback.metadata_path} belong to "
            "different installs: the runtime data directory holds another install's relay slot. "
            "Give each install its own VIGIL_RUNTIME_DATA_DIR, set in that install's `.env`."
        )
    if not route.legacy:
        prior = _read_allocations(_resolved_registry_path(registry_path)).get(route.install_id)
        if prior is not None:
            _registered_root(
                route,
                prior,
                _install_identity_path(
                    canonical_install_root or install_root,
                    preserve_install_path=preserve_install_path,
                ),
                preserve_install_path=preserve_install_path,
            )
    return route


def _move_record_into_state_dir(
    route: OobRelayRoute,
    install_root: Path,
    *,
    preserve_install_path: bool,
    canonical_install_root: Path | None,
    registry_path: Path | None,
) -> OobRelayRoute:
    """Move a record found only beside the install root to :func:`oob_state_dir`.

    The record is the slot's identity, so it moves unchanged: same bytes on one
    filesystem, the same JSON across two. The registry row it pairs with names
    the install root, never this path, so the move leaves it as it is. Linking
    before unlinking keeps the record visible to :func:`load_relay_route`, which
    takes no lock, at every step.
    """
    state_dir = _metadata_path(
        install_root,
        preserve_install_path=preserve_install_path,
        canonical_install_root=canonical_install_root,
    ).parent
    if route.metadata_path.parent == state_dir:
        return route
    with _FileLock((state_dir / RELAY_METADATA_FILENAME).with_suffix(".lock")):
        current = load_relay_route(
            install_root,
            preserve_install_path=preserve_install_path,
            canonical_install_root=canonical_install_root,
            registry_path=registry_path,
        )
        if current is None or current.metadata_path.parent == state_dir:
            return current or route
        source = current.metadata_path
        destination = state_dir / source.name
        try:
            os.link(source, destination)
        except OSError as exc:
            if exc.errno not in _NO_HARD_LINK_ERRNOS:
                raise
            _atomic_write_json_real(destination, _read_json(source))
        source.unlink()
        _fsync_directory(state_dir)
        _fsync_directory(source.parent)
        return replace(current, metadata_path=destination)


def legacy_relay_route(
    install_root: Path,
    *,
    base_domain: str,
    preserve_install_path: bool = False,
    canonical_install_root: Path | None = None,
) -> OobRelayRoute:
    path = _metadata_path(
        install_root,
        preserve_install_path=preserve_install_path,
        canonical_install_root=canonical_install_root,
    )
    domain = normalize_base_domain(base_domain)
    route = OobRelayRoute(
        version=ROUTING_VERSION,
        install_id="legacy-single-tenant",
        slot_name="legacy",
        slot_prefix="legacy",
        base_domain=domain,
        oob_domain=domain,
        allocation_slot=-1,
        dns_remote_port=LEGACY_DNS_REMOTE_PORT,
        reverse_remote_port=LEGACY_REVERSE_REMOTE_PORT,
        legacy=True,
        metadata_path=path,
    )
    _validate_route(route)
    return route


def _resolved_registry_path(registry_path: Path | None) -> Path:
    return (
        registry_path or config_path().with_name(OOB_ALLOCATION_REGISTRY_FILENAME)
    ).expanduser().resolve()


def _allocation_row(route: OobRelayRoute, install_root: Path) -> dict[str, object]:
    return {
        "install_root": str(install_root),
        "slot_prefix": route.slot_prefix,
        "oob_domain": route.oob_domain,
        "allocation_slot": route.allocation_slot,
        "dns_remote_port": route.dns_remote_port,
        "reverse_remote_port": route.reverse_remote_port,
    }


def _validated_allocations(
    registry_path: Path, registry: dict[str, object]
) -> dict[str, dict[str, object]]:
    if registry.get("version") != ROUTING_VERSION:
        raise SystemExit(
            f"Invalid OOB allocation registry at {registry_path}: unsupported version."
        )
    raw = registry.get("allocations")
    if not isinstance(raw, dict):
        raise SystemExit(
            f"Invalid OOB allocation registry at {registry_path}: allocations must be an object."
        )
    allocations: dict[str, dict[str, object]] = {}
    used_slots: dict[int, str] = {}
    used_domains: dict[str, str] = {}
    for install_id, value in raw.items():
        if not isinstance(install_id, str) or not install_id or not isinstance(value, dict):
            raise SystemExit(
                f"Invalid OOB allocation registry at {registry_path}: malformed allocation row."
            )
        try:
            install_root = str(value["install_root"]).strip()
            slot_prefix = str(_payload_field(value, "slot_prefix", "tenant_prefix")).strip()
            domain = normalize_base_domain(str(value["oob_domain"]))
            slot_value = value["allocation_slot"]
            dns_value = value["dns_remote_port"]
            reverse_value = value["reverse_remote_port"]
            if any(isinstance(item, bool) for item in (slot_value, dns_value, reverse_value)):
                raise ValueError("boolean numeric field")
            slot = int(slot_value)
            dns_port = int(dns_value)
            reverse_port = int(reverse_value)
        except (KeyError, TypeError, ValueError) as exc:
            raise SystemExit(
                f"Invalid OOB allocation registry at {registry_path}: malformed allocation for {install_id!r}."
            ) from exc
        expected_dns = PORT_BLOCK_START + slot * PORT_BLOCK_SIZE
        if (
            not install_root
            or not slot_prefix
            or not 0 <= slot < PORT_SLOT_COUNT
            or dns_port != expected_dns
            or reverse_port != expected_dns + 1
            or not domain.startswith(f"{slot_prefix}.")
        ):
            raise SystemExit(
                f"Invalid OOB allocation registry at {registry_path}: inconsistent allocation for {install_id!r}."
            )
        if slot in used_slots or domain in used_domains:
            raise SystemExit(
                f"Invalid OOB allocation registry at {registry_path}: duplicate slot domain or FRP block."
            )
        used_slots[slot] = install_id
        used_domains[domain] = install_id
        allocations[install_id] = {
            "install_root": install_root,
            "slot_prefix": slot_prefix,
            "oob_domain": domain,
            "allocation_slot": slot,
            "dns_remote_port": dns_port,
            "reverse_remote_port": reverse_port,
        }
    return allocations


def _reconcile_existing_route_locked(
    route: OobRelayRoute,
    install_root: Path,
    registry_path: Path,
    *,
    atomic_writer: Callable[[Path, dict[str, object]], None] = _atomic_write_json_real,
    preserve_install_path: bool = False,
) -> OobRelayRoute:
    if route.legacy:
        return route
    allocations = _read_allocations(registry_path)
    expected = _allocation_row(route, install_root)
    prior = allocations.get(route.install_id)
    if prior is not None:
        if _registered_root(
            route, prior, install_root, preserve_install_path=preserve_install_path
        ) != install_root:
            prior = {**prior, "install_root": str(install_root)}
        if any(prior.get(key) != expected[key] for key in expected if key != "install_root"):
            raise SystemExit(
                f"OOB allocation registry at {registry_path} disagrees with persisted relay routing; "
                "refusing to change correlation or FRP ownership silently."
            )
        if prior == expected:
            return route
    else:
        for owner, row in allocations.items():
            if (
                row["allocation_slot"] == route.allocation_slot
                or row["oob_domain"] == route.oob_domain
            ):
                raise SystemExit(
                    f"OOB allocation registry at {registry_path} assigns this slot's domain or FRP block "
                    f"to {owner!r}; refusing a collision."
                )
    allocations[route.install_id] = expected
    atomic_writer(
        registry_path,
        {"version": ROUTING_VERSION, "allocations": allocations},
    )
    return route


def _read_allocations(registry_path: Path) -> dict[str, dict[str, object]]:
    registry = _read_json(
        registry_path,
        default={"version": ROUTING_VERSION, "allocations": {}},
    )
    return _validated_allocations(registry_path, registry)


def _registered_root(
    route: OobRelayRoute,
    prior: dict[str, object],
    install_root: Path,
    *,
    preserve_install_path: bool,
) -> Path:
    """The root ``prior`` registers ``route`` to, unless another live install owns it.

    A registered root that no longer exists is this install, moved.
    """
    prior_root = _install_identity_path(
        Path(str(prior["install_root"])),
        preserve_install_path=preserve_install_path,
    )
    if prior_root != install_root and prior_root.exists():
        raise SystemExit(
            f"OOB install identity {route.install_id!r} at {route.metadata_path} is already registered "
            f"to another install root ({prior_root}); refusing a copied relay route. Installs that "
            "share a VIGIL_RUNTIME_DATA_DIR share its oob/ directory; give each install its own."
        )
    return prior_root


def _install_identity_path(
    install_root: Path, *, preserve_install_path: bool
) -> Path:
    expanded = install_root.expanduser()
    if preserve_install_path:
        return Path(os.path.abspath(expanded))
    return expanded.resolve()


def reconcile_relay_route_registry(
    route: OobRelayRoute,
    install_root: Path,
    *,
    registry_path: Path | None = None,
    preserve_install_path: bool = False,
) -> OobRelayRoute:
    install_root = _install_identity_path(
        install_root, preserve_install_path=preserve_install_path
    )
    resolved_registry = _resolved_registry_path(registry_path)
    lock_path = resolved_registry.with_suffix(resolved_registry.suffix + ".lock")
    with _FileLock(lock_path):
        return _reconcile_existing_route_locked(
            route,
            install_root,
            resolved_registry,
            preserve_install_path=preserve_install_path,
        )


def _oob_state_directories(
    install_root: Path, *, canonical_install_root: Path | None
) -> tuple[Path, ...]:
    """Every directory an OOB session could have written this install's state to.

    Missing either would read a live install as never-configured and move its
    ports out from under running callbacks: :func:`oob_state_dir` is where
    `vigil oob start` writes, and an install root's `.runtime-data/oob` holds
    whatever it wrote while the runtime data directory was `.runtime-data`.
    """
    root = install_root.expanduser()
    directories = [
        oob_state_dir(
            root,
            preserve_install_path=True,
            canonical_install_root=canonical_install_root,
        )
    ]
    if root / _INSTALL_ROOT_OOB_STATE_PATH not in directories:
        directories.append(root / _INSTALL_ROOT_OOB_STATE_PATH)
    return tuple(directories)


def has_pre_routing_oob_state(
    install_root: Path, *, canonical_install_root: Path | None = None
) -> bool:
    """True when this root was already running OOB before it had a relay route.

    The legacy 53/8443 route exists for exactly one population: installs whose
    callbacks are already live on the shared domain and whose correlation would
    break if their ports moved. `vigil oob start` is the only thing that puts an
    install in that population — with no routing record it resolves the shared
    route through :func:`legacy_relay_route` (see `oob.oob_options`) — and it
    cannot run without leaving its rendered `frpc.toml`, logs, per-client files
    and runtime route marker behind. That state is therefore the discriminator,
    and it is absent from a root that has never had OOB configured or started.

    Deliberately NOT evidence: a root merely being old. An install stamp,
    `.runtime-data/logs` or an engagement directory proves a previous install or
    engagement, never a live OOB channel; treating them as legacy is what
    stranded every deferred-configuration install on the contended shared ports.
    An entry in the allocation registry is not evidence either — a registry row
    is only ever written for an allocated slot, so it proves the opposite.
    """
    for directory in _oob_state_directories(
        install_root, canonical_install_root=canonical_install_root
    ):
        if not directory.is_dir():
            continue
        try:
            entries = list(directory.iterdir())
        except OSError:
            # The directory exists but will not be read. With no way to prove it
            # empty, keep the route this install may be using.
            return True
        if any(
            not entry.name.lstrip(".").startswith(_ROUTING_RECORD_STEMS)
            for entry in entries
        ):
            return True
    return False


def initialize_relay_route(
    install_root: Path,
    *,
    slot_name: str | None = None,
    base_domain: str,
    registry_path: Path | None = None,
    canonical_install_root: Path | None = None,
    preserve_install_path: bool = False,
) -> OobRelayRoute:
    existing = load_relay_route(
        install_root,
        preserve_install_path=preserve_install_path,
        canonical_install_root=canonical_install_root,
        registry_path=registry_path,
    )
    registry_install_root = _install_identity_path(
        canonical_install_root or install_root,
        preserve_install_path=preserve_install_path,
    )
    if existing is not None:
        existing = _move_record_into_state_dir(
            existing,
            install_root,
            preserve_install_path=preserve_install_path,
            canonical_install_root=canonical_install_root,
            registry_path=registry_path,
        )
        return reconcile_relay_route_registry(
            existing,
            registry_install_root,
            registry_path=registry_path,
            preserve_install_path=preserve_install_path,
        )
    if not has_pre_routing_oob_state(
        install_root, canonical_install_root=canonical_install_root
    ):
        return allocate_relay_route(
            install_root,
            slot_name=slot_name or registry_install_root.name,
            base_domain=base_domain,
            registry_path=registry_path,
            canonical_install_root=registry_install_root,
            preserve_install_path=preserve_install_path,
        )
    route = legacy_relay_route(
        install_root,
        base_domain=base_domain,
        preserve_install_path=preserve_install_path,
        canonical_install_root=canonical_install_root,
    )
    path = route.metadata_path
    with _FileLock(path.with_suffix(".lock")):
        existing = load_relay_route(
            install_root,
            preserve_install_path=preserve_install_path,
            canonical_install_root=canonical_install_root,
            registry_path=registry_path,
        )
        if existing is not None:
            return existing
        _atomic_write_json_real(path, route.serializable())
    return route


def allocate_relay_route(
    install_root: Path,
    *,
    slot_name: str,
    base_domain: str = "oob.invalid",
    registry_path: Path | None = None,
    identity_factory: Callable[[], str] = _default_identity,
    slot_candidates: Callable[[str], Iterable[int]] = _default_slot_candidates,
    atomic_writer: Callable[[Path, dict[str, object]], None] = _atomic_write_json_real,
    canonical_install_root: Path | None = None,
    preserve_install_path: bool = False,
) -> OobRelayRoute:
    clean = sanitize_slot_prefix(slot_name)
    filesystem_install_root = install_root.expanduser()
    registry_install_root = _install_identity_path(
        canonical_install_root or filesystem_install_root,
        preserve_install_path=preserve_install_path,
    )
    if not preserve_install_path:
        filesystem_install_root = filesystem_install_root.resolve()
    metadata_path = _metadata_path(
        filesystem_install_root,
        preserve_install_path=preserve_install_path,
        canonical_install_root=canonical_install_root,
    )
    registry_path = _resolved_registry_path(registry_path)
    lock_path = registry_path.with_suffix(registry_path.suffix + ".lock")
    with _FileLock(lock_path):
        existing = load_relay_route(
            filesystem_install_root,
            preserve_install_path=preserve_install_path,
            canonical_install_root=canonical_install_root,
            registry_path=registry_path,
        )
        if existing is not None:
            return _reconcile_existing_route_locked(
                existing,
                registry_install_root,
                registry_path,
                atomic_writer=atomic_writer,
                preserve_install_path=preserve_install_path,
            )
        allocations = _read_allocations(registry_path)
        install_id = str(identity_factory()).strip()
        if not install_id:
            raise SystemExit("Invalid OOB install identity: identity factory returned an empty value.")
        prior_identity = allocations.get(install_id)
        if prior_identity is not None:
            raise SystemExit(
                "OOB install identity collision: the generated identity is already allocated to "
                f"{prior_identity!r}; refusing to overwrite another relay route."
            )
        used_slots = {
            cast(int, row["allocation_slot"])
            for row in allocations.values()
        }
        try:
            slot = next(candidate for candidate in slot_candidates(install_id) if candidate not in used_slots)
        except StopIteration as exc:
            raise SystemExit("OOB relay slot allocation exhausted: no free FRP port block remains.") from exc
        if not 0 <= slot < PORT_SLOT_COUNT:
            raise SystemExit(f"OOB relay slot allocator returned invalid slot {slot}.")
        digest = hashlib.sha256(install_id.encode("utf-8")).hexdigest()[:16]
        prefix = f"{clean}-{digest}"
        domain = normalize_base_domain(base_domain)
        oob_domain = f"{prefix}.{domain}"
        if any(
            isinstance(row, dict) and row.get("oob_domain") == oob_domain
            for row in allocations.values()
        ):
            raise SystemExit(
                f"OOB relay slot domain collision for {oob_domain!r}; generate a new install identity."
            )
        dns_port = PORT_BLOCK_START + slot * PORT_BLOCK_SIZE
        route = OobRelayRoute(
            version=ROUTING_VERSION,
            install_id=install_id,
            slot_name=slot_name.strip(),
            slot_prefix=prefix,
            base_domain=domain,
            oob_domain=oob_domain,
            allocation_slot=slot,
            dns_remote_port=dns_port,
            reverse_remote_port=dns_port + 1,
            legacy=False,
            metadata_path=metadata_path,
        )
        _validate_route(route)
        original_registry = {"version": ROUTING_VERSION, "allocations": dict(allocations)}
        allocations[install_id] = _allocation_row(route, registry_install_root)
        updated_registry = {"version": ROUTING_VERSION, "allocations": allocations}
        atomic_writer(registry_path, updated_registry)
        try:
            atomic_writer(metadata_path, route.serializable())
        except BaseException:
            _atomic_write_json_real(registry_path, original_registry)
            raise
        return route


def render_edge_routing(route: OobRelayRoute, *, frp_http_vhost_port: int = 8080) -> dict[str, str]:
    """Render deployment inputs; callers apply them explicitly outside this CLI."""
    callback_hosts = (
        route.oob_domain,
        f"*.{route.oob_domain}",
        f"*.*.{route.oob_domain}",
    )
    caddy = (
        f"{', '.join(callback_hosts)} {{\n"
        "    tls {\n"
        "        on_demand\n"
        "    }\n"
        f"    reverse_proxy 127.0.0.1:{int(frp_http_vhost_port)} {{\n"
        "        header_up Host {host}\n"
        "    }\n"
        "}\n\n"
        f"{', '.join(f'http://{host}' for host in callback_hosts)} {{\n"
        f"    reverse_proxy 127.0.0.1:{int(frp_http_vhost_port)} {{\n"
        "        header_up Host {host}\n"
        "    }\n"
        "}\n"
    )
    dns = (
        f"{route.oob_domain}:53 {{\n"
        "    errors\n"
        f"    forward . 127.0.0.1:{route.dns_remote_port} {{\n"
        "        prefer_udp\n"
        "    }\n"
        "}\n"
    )
    routing_json = json.dumps(
        {
            "slot_prefix": route.slot_prefix,
            "domain": route.oob_domain,
            "dns_upstream": f"127.0.0.1:{route.dns_remote_port}",
            "reverse_tcp_port": route.reverse_remote_port,
            "frp_http_vhost_port": int(frp_http_vhost_port),
        },
        indent=2,
        sort_keys=True,
    ) + "\n"
    return {"caddy": caddy, "dns": dns, "routing_json": routing_json}
