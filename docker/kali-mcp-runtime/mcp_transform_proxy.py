#!/usr/bin/env python3
from __future__ import annotations

import argparse
import importlib.util
import ipaddress
import json
import logging
import os
import random
import re
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any


UPSTREAM_CLIENT_PATH = Path(
    os.environ.get("KALI_MCP_CLIENT_PATH", "/usr/share/mcp-kali-server/client.py")
)
IPV4_CANDIDATE_RE = re.compile(r"(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d)")
RULES_PATH = Path(os.environ.get("MCP_TRANSFORM_RULES_PATH", "/config/mcp-transform-rules.json"))


def load_upstream():
    spec = importlib.util.spec_from_file_location("kali_upstream_client", UPSTREAM_CLIENT_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load upstream client from {UPSTREAM_CLIENT_PATH}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


upstream = load_upstream()
logger = logging.getLogger("mcp_transform_proxy")


def env_string(primary: str, fallback: str, default: str) -> str:
    return os.environ.get(primary) or os.environ.get(fallback, default)


@dataclass(frozen=True)
class ReplaceRule:
    find: str
    replace: str


@dataclass(frozen=True)
class TransformConfig:
    outbound_rules: tuple[ReplaceRule, ...]
    inbound_rules: tuple[ReplaceRule, ...]
    public_ip_aliasing_enabled: bool
    public_ip_map_path: Path


def load_transform_config(path: Path) -> TransformConfig:
    if not path.exists():
        raise RuntimeError(f"Transform rules file not found: {path}")

    try:
        raw = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"Unable to load transform rules file {path}: {exc}") from exc

    if not isinstance(raw, dict):
        raise RuntimeError(f"Transform rules file must contain a JSON object: {path}")

    def parse_rules(key: str) -> tuple[ReplaceRule, ...]:
        value = raw.get(key, [])
        if value is None:
            return ()
        if not isinstance(value, list):
            raise RuntimeError(f"Transform rules field '{key}' must be a list in {path}")

        rules: list[ReplaceRule] = []
        for idx, item in enumerate(value):
            if not isinstance(item, dict):
                raise RuntimeError(f"Transform rule {key}[{idx}] must be an object in {path}")
            find = item.get("find")
            replace = item.get("replace")
            if not isinstance(find, str) or not find:
                raise RuntimeError(f"Transform rule {key}[{idx}].find must be a non-empty string")
            if not isinstance(replace, str):
                raise RuntimeError(f"Transform rule {key}[{idx}].replace must be a string")
            rules.append(ReplaceRule(find=find, replace=replace))
        return tuple(rules)

    public_ip_aliases = raw.get("public_ip_aliases", {})
    if public_ip_aliases is None:
        public_ip_aliases = {}
    if not isinstance(public_ip_aliases, dict):
        raise RuntimeError(f"Transform rules field 'public_ip_aliases' must be an object in {path}")

    enabled = public_ip_aliases.get("enabled", True)
    if not isinstance(enabled, bool):
        raise RuntimeError(f"Transform rules field 'public_ip_aliases.enabled' must be a boolean in {path}")

    map_path_value = public_ip_aliases.get("map_path", "/data/mcp-public-ip-map.json")
    if not isinstance(map_path_value, str) or not map_path_value:
        raise RuntimeError(f"Transform rules field 'public_ip_aliases.map_path' must be a non-empty string in {path}")

    return TransformConfig(
        outbound_rules=parse_rules("outbound"),
        inbound_rules=parse_rules("inbound"),
        public_ip_aliasing_enabled=enabled,
        public_ip_map_path=Path(map_path_value),
    )


def is_public_ipv4(candidate: str) -> bool:
    try:
        address = ipaddress.ip_address(candidate)
    except ValueError:
        return False
    return address.version == 4 and address.is_global


def replace_string(value: str, source: str, target: str) -> str:
    if not source:
        return value
    return value.replace(source, target)


def apply_rules(value: str, rules: tuple[ReplaceRule, ...]) -> str:
    transformed = value
    for rule in rules:
        transformed = replace_string(transformed, rule.find, rule.replace)
    return transformed


def transform_strings(value: Any, transformer) -> Any:
    if isinstance(value, str):
        return transformer(value)
    if isinstance(value, list):
        return [transform_strings(item, transformer) for item in value]
    if isinstance(value, tuple):
        return tuple(transform_strings(item, transformer) for item in value)
    if isinstance(value, dict):
        return {key: transform_strings(item, transformer) for key, item in value.items()}
    return value


class PublicIpAliasMap:
    def __init__(self, path: Path):
        self.path = path
        self._lock = threading.Lock()
        self._mappings = self._load()

    def _load(self) -> dict[str, str]:
        if not self.path.exists():
            return {}
        try:
            data = json.loads(self.path.read_text())
        except (OSError, json.JSONDecodeError):
            logger.warning("Failed to load IP alias map from %s, starting fresh", self.path)
            return {}
        if not isinstance(data, dict):
            logger.warning("Ignoring malformed IP alias map in %s", self.path)
            return {}
        mappings: dict[str, str] = {}
        for public_ip, private_ip in data.items():
            if isinstance(public_ip, str) and isinstance(private_ip, str):
                if is_public_ipv4(public_ip) and self._is_private_ipv4(private_ip):
                    mappings[public_ip] = private_ip
        return mappings

    def _save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp_path = self.path.with_suffix(f"{self.path.suffix}.tmp")
        tmp_path.write_text(json.dumps(self._mappings, indent=2, sort_keys=True) + "\n")
        tmp_path.replace(self.path)

    def _is_private_ipv4(self, candidate: str) -> bool:
        try:
            address = ipaddress.ip_address(candidate)
        except ValueError:
            return False
        return address.version == 4 and address.is_private

    def _generate_private_ip(self) -> str:
        assigned = set(self._mappings.values())
        while True:
            choice = random.choice(
                (
                    f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}",
                    f"172.{random.randint(16, 31)}.{random.randint(0, 255)}.{random.randint(1, 254)}",
                    f"192.168.{random.randint(0, 255)}.{random.randint(1, 254)}",
                )
            )
            if choice not in assigned:
                return choice

    def alias_for(self, public_ip: str) -> str:
        with self._lock:
            existing = self._mappings.get(public_ip)
            if existing:
                return existing
            private_ip = self._generate_private_ip()
            self._mappings[public_ip] = private_ip
            self._save()
            logger.info("Mapped public IP %s to private IP %s", public_ip, private_ip)
            return private_ip

    def remap_text(self, value: str) -> str:
        def replace_match(match: re.Match[str]) -> str:
            candidate = match.group(0)
            if not is_public_ipv4(candidate):
                return candidate
            return self.alias_for(candidate)

        return IPV4_CANDIDATE_RE.sub(replace_match, value)


CONFIG = load_transform_config(RULES_PATH)
PUBLIC_IP_ALIAS_MAP = (
    PublicIpAliasMap(CONFIG.public_ip_map_path) if CONFIG.public_ip_aliasing_enabled else None
)


class TransformingKaliToolsClient(upstream.KaliToolsClient):
    def transform_outbound(self, payload: Any) -> Any:
        transformed = transform_strings(
            payload,
            lambda text: apply_rules(text, CONFIG.outbound_rules),
        )
        if transformed != payload:
            logger.info("Transformed outbound payload")
        return transformed

    def transform_inbound(self, payload: Any) -> Any:
        transformed = transform_strings(
            payload,
            lambda text: (
                PUBLIC_IP_ALIAS_MAP.remap_text(apply_rules(text, CONFIG.inbound_rules))
                if PUBLIC_IP_ALIAS_MAP is not None
                else apply_rules(text, CONFIG.inbound_rules)
            ),
        )
        if transformed != payload:
            logger.info("Transformed inbound payload")
        return transformed

    def safe_get(self, endpoint: str, params=None):
        transformed_params = self.transform_outbound(params or {})
        response = super().safe_get(endpoint, transformed_params)
        return self.transform_inbound(response)

    def safe_post(self, endpoint: str, json_data):
        transformed_payload = self.transform_outbound(json_data)
        response = super().safe_post(endpoint, transformed_payload)
        return self.transform_inbound(response)


def parse_args():
    parser = argparse.ArgumentParser(description="Run the MCP Kali transform proxy")
    parser.add_argument(
        "--server",
        type=str,
        default=upstream.DEFAULT_KALI_SERVER,
        help=f"Kali API server URL (default: {upstream.DEFAULT_KALI_SERVER})",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=upstream.DEFAULT_REQUEST_TIMEOUT,
        help=f"Request timeout in seconds (default: {upstream.DEFAULT_REQUEST_TIMEOUT})",
    )
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    return parser.parse_args()


def main():
    args = parse_args()
    if args.debug:
        logger.setLevel(logging.DEBUG)
        upstream.logger.setLevel(logging.DEBUG)

    kali_client = TransformingKaliToolsClient(args.server, args.timeout)
    health = kali_client.check_health()
    if "error" in health:
        upstream.logger.warning(
            "Unable to connect to Kali API server at %s: %s",
            args.server,
            health["error"],
        )
    else:
        upstream.logger.info("Successfully connected to Kali API server at %s", args.server)
        upstream.logger.info("Server health status: %s", health.get("status"))

    mcp = upstream.setup_mcp_server(kali_client)
    upstream.logger.info("Starting MCP Kali transform proxy")
    mcp.run()


if __name__ == "__main__":
    main()
