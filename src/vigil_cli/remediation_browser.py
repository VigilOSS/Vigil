"""Direct local browser tools for trusted remediation UI rehearsals."""
from __future__ import annotations

import asyncio
import importlib.util
import inspect
import json
import os
import subprocess
import sys
import uuid
from pathlib import Path


class BrowseSession:
    def __init__(self, output: Path, cdp: str = "") -> None:
        if cdp:
            raise SystemExit(
                "browse 0.11.1 stop closes externally attached Chrome; use managed local "
                "browse without browser_cdp_url, or select the Stagehand SDK driver"
            )
        self.output = output
        self.target = ["--local"]
        # browse appends this name to macOS's long temporary Unix socket path.
        self.session = "vigil-" + uuid.uuid4().hex[:16]
        self.commands: list[dict] = []

    async def command(self, *arguments: str) -> str:
        target_flags = {"--remote", "--local", "--cdp", "--auto-connect", "--session", "-s"}
        if any(argument.split("=", 1)[0] in target_flags for argument in arguments):
            raise SystemExit("browser target and session are configured by the rehearsal runner")
        # Explicit targeting prevents an ambient Browserbase key selecting a remote browser.
        target = [] if arguments == ("stop",) else self.target
        argv = ["browse", *arguments, *target, "--session", self.session]
        env = dict(os.environ, BROWSE_LOAD_DOTENV="0")
        try:
            process = await asyncio.to_thread(subprocess.run, argv, cwd=self.output, env=env,
                                              capture_output=True, text=True, timeout=120)
        except (OSError, subprocess.TimeoutExpired) as exc:
            self.commands.append({"argv": argv, "error": str(exc)})
            self._save()
            raise
        self.commands.append({"argv": argv, "returncode": process.returncode,
                              "stdout": process.stdout, "stderr": process.stderr})
        self._save()
        if process.returncode:
            raise SystemExit(f"browse command failed ({process.returncode}): {process.stderr}")
        return process.stdout

    def _save(self) -> None:
        (self.output / "commands.json").write_text(json.dumps(self.commands, indent=2) + "\n", encoding="utf-8")


async def execute(script: Path, output: Path, config: dict[str, object]) -> dict:
    browser = BrowseSession(output, str(config.get("browser_cdp_url") or ""))
    try:
        spec = importlib.util.spec_from_file_location("vigil_remediation_browse_script", script)
        if spec is None or spec.loader is None:
            raise SystemExit(f"cannot load browser script: {script}")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        run = getattr(module, "run", None)
        if not inspect.iscoroutinefunction(run):
            raise SystemExit("browse script must expose async def run(browser, output_dir)")
        result = await run(browser, output)
        if not isinstance(result, dict):
            raise SystemExit("browse script must return a JSON object")
        if not any(command.get("argv", [None, None])[1] != "stop" for command in browser.commands):
            raise SystemExit("browse script must execute a UI command")
        if any(command.get("returncode") != 0 for command in browser.commands):
            raise SystemExit("rehearsal contains failed browser commands")
        return result
    finally:
        if browser.commands:
            original_error = sys.exc_info()[1]
            try:
                await browser.command("stop")
            except BaseException as cleanup_error:
                if original_error is None:
                    raise
                original_error.add_note(f"browse session cleanup failed: {cleanup_error}")
