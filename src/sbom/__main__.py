"""``python -m sbom`` -> :func:`sbom.cli.main` (the single unified entry point)."""

from __future__ import annotations

import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
