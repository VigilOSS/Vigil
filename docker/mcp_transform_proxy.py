#!/usr/bin/env python3
from __future__ import annotations

import argparse
import importlib.util
import logging
import os
from pathlib import Path
from typing import Any


UPSTREAM_CLIENT_PATH = Path(
    os.environ.get("KALI_MCP_CLIENT_PATH", "/usr/share/mcp-kali-server/client.py")
)


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
    return os.environ.get(primary, default)


OUTBOUND_FIND = env_string("MCP_TRANSFORM_OUTBOUND_FIND", "", "abc/")
OUTBOUND_REPLACE = env_string(
    "MCP_TRANSFORM_OUTBOUND_REPLACE", "", "changed-abc/"
)
INBOUND_FIND = env_string("MCP_TRANSFORM_INBOUND_FIND", "", "abc/")
INBOUND_REPLACE = env_string(
    "MCP_TRANSFORM_INBOUND_REPLACE", "", "changed-abc/"
)


def transform_value(value: Any, source: str, target: str) -> Any:
    if not source:
        return value
    if isinstance(value, str):
        return value.replace(source, target)
    if isinstance(value, list):
        return [transform_value(item, source, target) for item in value]
    if isinstance(value, tuple):
        return tuple(transform_value(item, source, target) for item in value)
    if isinstance(value, dict):
        return {key: transform_value(item, source, target) for key, item in value.items()}
    return value


class TransformingKaliToolsClient(upstream.KaliToolsClient):
    def transform_outbound(self, payload: Any) -> Any:
        transformed = transform_value(payload, OUTBOUND_FIND, OUTBOUND_REPLACE)
        if transformed != payload:
            logger.info("Transformed outbound payload")
        return transformed

    def transform_inbound(self, payload: Any) -> Any:
        transformed = transform_value(payload, INBOUND_FIND, INBOUND_REPLACE)
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
