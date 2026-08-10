"""Command line entry point.

Keeps argument handling separate from the work: this module parses argv,
validates inputs, and hands off. It deliberately contains no parsing,
resolution or HTTP logic.
"""

import argparse
import sys
from pathlib import Path

from scanner.parsers import parse_requirements_txt

# Exit codes. Chosen to match the convention CI tools use (and Socket's own
# `socket ci`): 0 means "ran and passed", non-zero means something a build
# should react to.
EXIT_OK = 0
EXIT_VULNERABILITIES_FOUND = 1
EXIT_USAGE_ERROR = 2
EXIT_SCAN_ERROR = 3


def build_parser() -> argparse.ArgumentParser:
    """Define the command line interface.

    Split out from main() so tests can inspect the parser without running it.
    """
    parser = argparse.ArgumentParser(
        prog="scanner",
        description=(
            "Scan a dependency manifest for known vulnerabilities. "
            "Resolves transitive dependencies and reports findings from "
            "public advisory databases."
        ),
    )
    parser.add_argument(
        "manifest",
        type=Path,
        help="path to a manifest file (requirements.txt or package.json)",
    )
    parser.add_argument(
        "--format",
        choices=("console", "json", "both"),
        default="console",
        help="output format (default: console)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        metavar="PATH",
        help="write the JSON report to this file",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """Run the scanner.

    Returns an exit code rather than calling sys.exit() directly, so that
    tests can call main() and assert on the result.
    """
    args = build_parser().parse_args(argv)

    # argparse handles missing/invalid arguments itself (and exits 2).
    # What it cannot check is whether the file actually exists, so do that
    # here and fail with a readable message instead of a traceback.
    if not args.manifest.exists():
        print(f"error: no such file: {args.manifest}", file=sys.stderr)
        return EXIT_USAGE_ERROR

    if not args.manifest.is_file():
        print(f"error: not a file: {args.manifest}", file=sys.stderr)
        return EXIT_USAGE_ERROR

    result = parse_requirements_txt(args.manifest)

    print(f"{args.manifest}: {len(result.dependencies)} dependencies")
    for dependency in result.dependencies:
        version = dependency.key.version or "(unpinned)"
        print(f"  {dependency.key.name} {version}")

    if result.skipped:
        print(f"\nskipped {len(result.skipped)} lines:")
        for skipped in result.skipped:
            print(f"  line {skipped.line_number}: {skipped.reason.value}")

    # TODO(stage 2): query OSV for these packages and report vulnerabilities.
    return EXIT_OK
