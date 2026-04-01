#!/usr/bin/env python3
"""AI Threat Hunting — assessment CLI entry point."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from assess.cli import main

main()
