"""Command line entry point.

Keeps argument handling separate from the work: this module parses argv,
validates inputs, and hands off. It deliberately contains no parsing,
resolution or HTTP logic.
"""

import argparse
import json
import sys
from pathlib import Path

from scanner.console import render
from scanner.github import GHSAClient
from scanner.osv import OSVClient
from scanner.parsers import parse_requirements_txt
from scanner.pypi import PyPIClient
from scanner.report import build
from scanner.resolver import resolve
from scanner.sources import merge

# Exit codes. Chosen to match the convention CI tools use (and Socket's own
# `socket ci`): 0 means "ran and passed", non-zero means something a build
# should react to.
EXIT_OK = 0
EXIT_VULNERABILITIES_FOUND = 1
EXIT_USAGE_ERROR = 2
EXIT_SCAN_ERROR = 3


def note(message: str) -> None:
    """Progress, on stderr so it never mixes into the report on stdout."""
    print(message, file=sys.stderr, flush=True)


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
        help="path to a requirements.txt manifest",
    )
    parser.add_argument(
        "--format",
        choices=("console", "json"),
        default="console",
        help="output format (default: console)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        metavar="PATH",
        help="write the JSON report to this file",
    )
    parser.add_argument(
        "--ignore",
        action="append",
        default=[],
        metavar="ID",
        help="suppress an advisory by CVE or GHSA id (repeatable)",
    )
    parser.add_argument(
        "--stale-after",
        type=int,
        metavar="DAYS",
        help="flag packages with no release in this many days",
    )
    parser.add_argument(
        "--min-severity",
        choices=("CRITICAL", "HIGH", "MEDIUM", "LOW"),
        help="only list findings at least this serious (unknown severities are always shown)",
    )
    parser.add_argument(
        "--show-skipped",
        action="store_true",
        help="list the manifest lines that were not scanned",
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

    # Everything below reports progress on stderr, so that stdout carries only
    # the report and `scanner --format json | jq` works.
    parsed = parse_requirements_txt(args.manifest)
    note("resolving...")
    graph = resolve(parsed.dependencies, PyPIClient().fetch)

    packages = [node.key for node in graph.nodes.values() if not node.failed]
    note(f"checking {len(packages)} packages against OSV...")
    osv = OSVClient().query(packages)

    # GitHub is only asked about the findings OSV left incomplete, so this is
    # usually a handful of requests rather than one per package.
    github = GHSAClient().fill_gaps(osv.findings)

    report = build(
        manifest=args.manifest,
        graph=graph,
        findings=merge([osv, github]),
        source_errors={"osv": osv.error, "github": github.error},
        parsed=parsed,
        ignore=args.ignore,
        stale_after_days=args.stale_after,
        min_severity=args.min_severity,
    )

    if args.format == "json":
        print(json.dumps(report, indent=2))
    else:
        print(render(report, show_skipped=args.show_skipped))

    if args.output:
        args.output.write_text(json.dumps(report, indent=2) + "\n")
        note(f"wrote {args.output}")

    # Non-zero so a CI job fails on a vulnerable dependency, which is the whole
    # point of running this in a pipeline. Counted from the summary rather than
    # the printed findings: --min-severity decides what is shown, and a display
    # flag that could turn a failing build green would be a way to silence CI.
    return EXIT_VULNERABILITIES_FOUND if report["summary"]["total_vulnerabilities"] else EXIT_OK
