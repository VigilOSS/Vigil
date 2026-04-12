#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = [
#     "tree-sitter>=0.24,<1",
#     "tree-sitter-java>=0.23,<1",
#     "tree-sitter-c>=0.23,<1",
#     "tree-sitter-cpp>=0.23,<1",
#     "tree-sitter-python>=0.23,<1",
#     "tree-sitter-javascript>=0.23,<1",
#     "tree-sitter-typescript>=0.23,<1",
# ]
# ///
"""AI Threat Hunting — assessment CLI entry point."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from assess.cli import main

main()
