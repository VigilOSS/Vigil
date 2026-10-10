#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = [
#     "psutil==7.2.2",
#     "tree-sitter==0.26.0",
#     "tree-sitter-java==0.23.5",
#     "tree-sitter-c==0.24.2",
#     "tree-sitter-cpp==0.23.4",
#     "tree-sitter-python==0.25.0",
#     "tree-sitter-javascript==0.25.0",
#     "tree-sitter-typescript==0.23.2",
#     "tree-sitter-go==0.25.0",
#     "tree-sitter-ruby==0.23.1",
#     "tree-sitter-php==0.24.1",
#     "tree-sitter-c-sharp==0.23.5",
# ]
# ///
"""Vigil — assessment CLI entry point."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
# Raw script execution and uv's isolated script environment need the CLI
# snapshot shipped with these assets, not an unrelated installed distribution.
_application = Path(__file__).resolve().parents[2]
_cli = _application / ("cli" if (_application / "cli/vigil_cli").is_dir() else "src")
sys.path.insert(0, str(_cli))
from assess.cli import main  # noqa: E402 — import after matched CLI bootstrap

main()
