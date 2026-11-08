#!/usr/bin/env python3
"""CLI: generate deps-inventory.json for a checked-out repository."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from depinv.generate import main

if __name__ == "__main__":
    raise SystemExit(main())
