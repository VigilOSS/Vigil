from __future__ import annotations

import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path


def load_proxy_module(stub_client_path: Path, map_path: Path):
    os.environ["KALI_MCP_CLIENT_PATH"] = str(stub_client_path)
    os.environ["MCP_TRANSFORM_PUBLIC_IP_MAP_PATH"] = str(map_path)

    spec = importlib.util.spec_from_file_location(
        "test_mcp_transform_proxy_module",
        Path(__file__).resolve().parents[1] / "docker/kali-mcp-runtime/mcp_transform_proxy.py",
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("Unable to load mcp_transform_proxy.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class McpTransformProxyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.tmp_path = Path(self.temp_dir.name)
        self.stub_client_path = self.tmp_path / "stub_client.py"
        self.map_path = self.tmp_path / "ip-map.json"
        self.stub_client_path.write_text(
            "\n".join(
                [
                    "import logging",
                    "DEFAULT_KALI_SERVER = 'http://localhost:5000'",
                    "DEFAULT_REQUEST_TIMEOUT = 30",
                    "logger = logging.getLogger('stub_kali_client')",
                    "class KaliToolsClient:",
                    "    def __init__(self, server, timeout):",
                    "        self.server = server",
                    "        self.timeout = timeout",
                    "    def safe_get(self, endpoint, params=None):",
                    "        return {'endpoint': endpoint, 'params': params}",
                    "    def safe_post(self, endpoint, json_data):",
                    "        return {'endpoint': endpoint, 'json': json_data}",
                    "    def check_health(self):",
                    "        return {'status': 'ok'}",
                    "def setup_mcp_server(client):",
                    "    class DummyServer:",
                    "        def run(self):",
                    "            return None",
                    "    return DummyServer()",
                ]
            )
            + "\n"
        )

    def test_public_ips_are_stably_mapped_to_private_ips(self) -> None:
        module = load_proxy_module(self.stub_client_path, self.map_path)
        module.random.seed(7)

        client = module.TransformingKaliToolsClient("http://localhost:5000", 30)
        first = client.transform_inbound(
            {
                "stdout": "dig result 52.12.12.11 and 52.12.12.11",
                "stderr": "",
            }
        )
        self.assertNotIn("52.12.12.11", first["stdout"])
        mapped_ip = first["stdout"].split()[-1]
        self.assertTrue(module.ipaddress.ip_address(mapped_ip).is_private)

        second = client.transform_inbound({"stdout": "repeat 52.12.12.11", "stderr": ""})
        self.assertIn(mapped_ip, second["stdout"])

        third = client.transform_inbound(
            {"stdout": "new 8.8.8.8 private 192.168.1.20 loopback 127.0.0.1", "stderr": ""}
        )
        self.assertNotIn("8.8.8.8", third["stdout"])
        self.assertIn("192.168.1.20", third["stdout"])
        self.assertIn("127.0.0.1", third["stdout"])

        stored_map = json.loads(self.map_path.read_text())
        self.assertEqual(stored_map["52.12.12.11"], mapped_ip)
        self.assertIn("8.8.8.8", stored_map)
        self.assertNotEqual(stored_map["8.8.8.8"], mapped_ip)


if __name__ == "__main__":
    unittest.main()
