#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import subprocess
import traceback
from pathlib import Path
from typing import Any, Dict


UPSTREAM_SERVER_PATH = Path("/usr/share/mcp-kali-server/server.py")


def load_upstream():
    spec = importlib.util.spec_from_file_location("kali_upstream_server", UPSTREAM_SERVER_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load upstream server from {UPSTREAM_SERVER_PATH}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


upstream = load_upstream()


class PatchedCommandExecutor(upstream.CommandExecutor):
    def execute(self) -> Dict[str, Any]:
        upstream.logger.info("Executing command: %s", self.command)

        if not isinstance(self.command, (str, list)):
            raise ValueError(
                f"CommandExecutor expects a string or list, but got {type(self.command).__name__}"
            )

        use_shell = isinstance(self.command, str)

        try:
            self.process = subprocess.Popen(
                self.command,
                shell=use_shell,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
            )

            self.stdout_thread = upstream.threading.Thread(target=self._read_stdout, daemon=True)
            self.stderr_thread = upstream.threading.Thread(target=self._read_stderr, daemon=True)
            self.stdout_thread.start()
            self.stderr_thread.start()

            try:
                self.return_code = self.process.wait(timeout=self.timeout)
                self.stdout_thread.join()
                self.stderr_thread.join()
            except subprocess.TimeoutExpired:
                self.timed_out = True
                upstream.logger.warning(
                    "Command timed out after %s seconds. Terminating process.",
                    self.timeout,
                )
                self.process.terminate()
                try:
                    self.process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    upstream.logger.warning("Process not responding to termination. Killing.")
                    self.process.kill()
                self.return_code = -1

            success = (
                True
                if self.timed_out and (self.stdout_data or self.stderr_data)
                else (self.return_code == 0)
            )

            return {
                "stdout": self.stdout_data,
                "stderr": self.stderr_data,
                "return_code": self.return_code,
                "success": success,
                "timed_out": self.timed_out,
                "partial_results": self.timed_out and (self.stdout_data or self.stderr_data),
            }
        except Exception as exc:
            upstream.logger.error("Error executing command: %s", exc)
            upstream.logger.error(traceback.format_exc())
            return {
                "stdout": self.stdout_data,
                "stderr": f"Error executing command: {exc}\n{self.stderr_data}",
                "return_code": -1,
                "success": False,
                "timed_out": False,
                "partial_results": bool(self.stdout_data or self.stderr_data),
            }


def execute_command(command):
    executor = PatchedCommandExecutor(command)
    return executor.execute()


upstream.CommandExecutor = PatchedCommandExecutor
upstream.execute_command = execute_command


def main() -> None:
    args = upstream.parse_args()

    if args.debug:
        upstream.DEBUG_MODE = True
        upstream.os.environ["DEBUG_MODE"] = "1"
        upstream.logger.setLevel(upstream.logging.DEBUG)

    if args.port != upstream.API_PORT:
        upstream.API_PORT = args.port

    upstream.logger.info(
        "Starting Kali Linux Tools API Server on %s:%s",
        args.ip,
        upstream.API_PORT,
    )
    upstream.app.run(host=args.ip, port=upstream.API_PORT, debug=upstream.DEBUG_MODE)


if __name__ == "__main__":
    main()
