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
# ]
# ///
"""Vigil — assessment CLI entry point."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from assess.cli import main

main()
