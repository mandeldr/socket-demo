"""Allows the package to be run with `python -m scanner`."""

import sys

from scanner.cli import main

if __name__ == "__main__":
    sys.exit(main())
