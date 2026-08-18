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
from scanner.graph import DependencyGraph
from scanner.manifests import ManifestError, package_lock, requirements_txt, yarn_lock
from scanner.models import ParseResult
from scanner.osv import OSVClient
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

# Filenames that mean JavaScript. Any of them is accepted, since they sit in
# one directory and each names the others.
PACKAGE_LOCK = "package-lock.json"
YARN_LOCK = "yarn.lock"
JAVASCRIPT_MANIFESTS = ("package.json", PACKAGE_LOCK, YARN_LOCK)

SUPPORTED = "requirements.txt, package.json (with package-lock.json or yarn.lock)"

# Manifests other tools write, named so that pointing at one gets an answer
# about that format instead of a complaint about requirements file syntax.
# The value is the command that produces something this can read, where one
# exists; None means the whole ecosystem is unsupported.
OTHER_FORMATS = {
    "poetry.lock": "poetry export -f requirements.txt --output requirements.txt",
    "Pipfile.lock": "pipenv requirements > requirements.txt",
    "pnpm-lock.yaml": None,
    "bun.lockb": None,
    "shrinkwrap.yaml": None,
    "go.mod": None,
    "go.sum": None,
    "Gemfile.lock": None,
    "Cargo.lock": None,
    "composer.lock": None,
}


def note(message: str) -> None:
    """Progress, on stderr so it never mixes into the report on stdout."""
    print(message, file=sys.stderr, flush=True)


def _why_unreadable(name: str) -> str | None:
    """Why this filename cannot be scanned, or None when it can be.

    Recognising manifests positively, and refusing everything else, is the
    point of this function. The requirements.txt reader is permissive by
    design - a bare `flask` with no version is a legal requirement - so if an
    unrecognised file reached it, an entire manifest of some other format
    would parse as nothing and be reported as a clean scan.

    A pip requirements file has no fixed name: `requirements.txt`,
    `requirements-dev.txt` and `constraints.txt` are all conventions. So any
    `.txt` is accepted, and the check is on everything that is not one.
    """
    if name in JAVASCRIPT_MANIFESTS or name.endswith(".txt"):
        return None

    if name in OTHER_FORMATS:
        message = f"{name} is not a format this reads. Supported: {SUPPORTED}"
        export = OTHER_FORMATS[name]
        return f"{message}\n  to scan this project, run: {export}" if export else message

    return f"{name} is not a manifest this recognises. Supported: {SUPPORTED}"


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
        help="path to requirements.txt, or to package.json (its lock file is read from alongside)",
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


def _read(manifest: Path) -> tuple[ParseResult, DependencyGraph]:
    """Turn a manifest into what it asked for and what that installs.

    The two ecosystems reach the same pair of answers by different routes, and
    the difference is left visible rather than hidden behind one call: a
    requirements.txt names ranges that still have to be resolved against PyPI,
    while a lock file names versions somebody already committed. Pretending
    they are the same shape would obscure the reason npm needs no resolver.
    """
    # The fork. Everything below this function works on a graph and never
    # learns which ecosystem produced it.
    if manifest.name in JAVASCRIPT_MANIFESTS:
        # A lock file already names versions, so this returns a finished graph.
        return _read_javascript(manifest)

    # requirements.txt names ranges, so parsing is only half the job - the
    # resolver has to turn them into versions by walking PyPI.
    parsed = requirements_txt.parse(manifest)
    note("resolving...")
    return parsed, resolve(parsed.dependencies, PyPIClient().fetch)


def _read_javascript(manifest: Path) -> tuple[ParseResult, DependencyGraph]:
    """Read a package.json with whichever lock file sits beside it.

    npm's lock wins when both are present, which is what npm itself does. A
    project with neither falls through to the npm reader, so the error names
    `npm install --package-lock-only`; a yarn user has to translate that.
    """
    directory = manifest.parent

    pointed_at_yarn = manifest.name == YARN_LOCK
    yarn_is_the_only_lock = (directory / YARN_LOCK).exists() and not (
        directory / PACKAGE_LOCK
    ).exists()

    if pointed_at_yarn or yarn_is_the_only_lock:
        return yarn_lock.parse(manifest)
    return package_lock.parse(manifest)


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

    # Refuse anything we do not recognise, rather than letting it reach the
    # requirements reader and be reported as a clean scan of nothing.
    unreadable = _why_unreadable(args.manifest.name)
    if unreadable:
        print(f"error: {unreadable}", file=sys.stderr)
        return EXIT_USAGE_ERROR

    # Everything below reports progress on stderr, so that stdout carries only
    # the report and `scanner --format json | jq` works.
    try:
        parsed, graph = _read(args.manifest)
    except ManifestError as error:
        print(f"error: {error}", file=sys.stderr)
        return EXIT_USAGE_ERROR

    if args.stale_after is not None and args.manifest.name in JAVASCRIPT_MANIFESTS:
        # The flag would otherwise report nothing stale, which reads as "none
        # found" rather than "never looked".
        note("note: a lock file carries no release dates, so --stale-after finds nothing")

    # Failed lookups have no version, and OSV matches exact versions only.
    packages = [node.key for node in graph.nodes.values() if not node.failed]
    note(f"checking {len(packages)} packages against OSV...")
    # This is the slow line: one request per package, sequentially.
    osv = OSVClient().query(packages)

    # GitHub is only asked about findings OSV left incomplete, so this is
    # usually a handful of requests rather than one per package.
    github = GHSAClient().fill_gaps(osv.findings)

    report = build(
        manifest=args.manifest,
        graph=graph,
        # merge folds both sources into one list per package and collapses the
        # duplicate records, so the report never sees two copies of one CVE.
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
        try:
            args.output.write_text(json.dumps(report, indent=2) + "\n")
        except OSError as error:
            # Not a traceback, and not exit 1: that is the code for "vulnerable
            # dependency found", so a failed write here would fail a clean
            # build and blame the dependencies.
            print(f"error: could not write {args.output}: {error}", file=sys.stderr)
            return EXIT_USAGE_ERROR
        note(f"wrote {args.output}")

    # Non-zero so a CI job fails on a vulnerable dependency, which is the whole
    # point of running this in a pipeline. Counted from the summary rather than
    # the printed findings: --min-severity decides what is shown, and a display
    # flag that could turn a failing build green would be a way to silence CI.
    return EXIT_VULNERABILITIES_FOUND if report["summary"]["total_vulnerabilities"] else EXIT_OK
