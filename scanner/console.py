"""Rendering a finished report as text.

Everything here reads from the report dictionary and nothing else. It cannot
show a number the JSON does not also carry, which is the point: two formatters
written against the same source cannot drift apart.

Findings go in a table because there are often a lot of them - a manifest with
an old django in it produces nearly fifty - and a table shows one per line
instead of four.
"""

import io

from rich.box import SIMPLE
from rich.console import Console
from rich.table import Table
from rich.text import Text


def render(report: dict, show_skipped: bool = False, width: int | None = None) -> str:
    """The console version, built from the same data the JSON carries."""
    # markup=False so a summary containing square brackets is printed rather
    # than read as styling. record=True is what lets us hand back a string.
    console = Console(file=io.StringIO(), record=True, width=width, markup=False)

    console.print(report["manifest"])
    for line in _header(report["summary"]):
        console.print(line)

    _print_findings(console, report)
    skipped = _skipped_lines(report) if show_skipped else []
    _print_section(console, "skipped:", skipped)
    _print_section(
        console, f"unmaintained {len(report['unmaintained'])}:", _unmaintained_lines(report)
    )
    _print_section(
        console, f"could not resolve {len(report['unresolved'])}:", _unresolved_lines(report)
    )

    for name, why in report["sources"]["failed"].items():
        console.print(f"\n{name} did not finish: {why}")

    return console.export_text().rstrip() + "\n"


def _header(summary: dict) -> list[str]:
    """What the manifest asked for, and what came back.

    Clauses that would read as zero are left out, so the line stays about what
    actually happened.
    """
    manifest = f"{summary['requirements']} requirements"
    # A manifest can name the same package twice. Saying so is the only way a
    # reader gets from the line count to the package count.
    requested = summary["packages_requested"]
    if requested and requested != summary["requirements"]:
        manifest += f" ({requested} package{'' if requested == 1 else 's'})"
    if summary["skipped"]:
        manifest += f", {summary['skipped']} lines skipped"

    resolved = (
        f"{summary['total_packages']} packages resolved "
        f"({summary['direct']} direct, {summary['transitive']} transitive)"
    )
    if summary["unresolved"]:
        resolved += f", {summary['unresolved']} unresolved"

    return [manifest, resolved]


def _print_findings(console: Console, report: dict) -> None:
    """The headline counts, then a table per vulnerable package."""
    summary = report["summary"]
    ignored = ""
    if report["ignored"]["count"]:
        ignored = f" ({report['ignored']['count']} ignored)"

    if not report["findings"]:
        console.print(f"\nno known vulnerabilities{ignored}")
        return

    console.print(
        f"\n{summary['vulnerable_packages']} vulnerable "
        f"({summary['vulnerable_percent']}% of packages), "
        f"{summary['total_vulnerabilities']} findings{ignored}"
    )
    console.print("  " + "  ".join(f"{level} {n}" for level, n in summary["by_severity"].items()))
    if summary["min_severity"]:
        console.print(
            f"  showing {summary['min_severity']} and above; {summary['hidden_by_severity']} hidden"
        )

    for finding in report["findings"]:
        console.print()
        console.print(_title(finding))
        console.print(_table(finding))


def _title(finding: dict) -> str:
    """Which package, how it got here, and what to do about it."""
    how = "direct" if finding["direct"] else "via " + " -> ".join(finding["path"][:-1])
    fix = (
        f", to at least {finding['upgrade_to']}"
        if finding["upgrade_to"]
        else " (no version clears every finding)"
    )
    return f"{finding['package']} {finding['version']}  ({how})\n  {finding['remediation']}{fix}"


def _table(finding: dict) -> Table:
    """One row per vulnerability. Only the summary column wraps."""
    table = Table(box=SIMPLE, show_edge=False, pad_edge=False, expand=True)
    table.add_column("severity", style="bold", no_wrap=True)
    table.add_column("advisory", no_wrap=True)
    table.add_column("fixed in", no_wrap=True)
    table.add_column("summary", ratio=1)

    for vulnerability in finding["vulnerabilities"]:
        table.add_row(
            vulnerability["severity"],
            # The advisory page as a link on the identifier: terminals that
            # support it make this clickable, and the plain text stays the id.
            Text(vulnerability["cve"] or vulnerability["id"], style=f"link {vulnerability['url']}"),
            ", ".join(vulnerability["fixed_versions"]) or "no fix published",
            vulnerability["summary"],
        )
    return table


def _print_section(console: Console, heading: str, lines: list[str]) -> None:
    """A heading and its indented lines, or nothing when there are none."""
    if not lines:
        return
    console.print(f"\n{heading}")
    for line in lines:
        console.print(f"  {line}")


def _skipped_lines(report: dict) -> list[str]:
    """Parts of the manifest the scan did not read, with the reason.

    The line number is dropped when there is not one. A requirements.txt entry
    lives on a line worth naming; a package.json dependency is a key in an
    object, and `line 0` would be noise dressed up as a location.
    """
    return [
        f"line {x['line']}: {x['content']}  ({x['reason']})"
        if x["line"]
        else f"{x['content']}  ({x['reason']})"
        for x in report["skipped"]
    ]


def _unmaintained_lines(report: dict) -> list[str]:
    """Packages with no recent release, worst first."""
    return [
        f"{x['package']}: no release in {x['days_since_release']} days"
        for x in report["unmaintained"]
    ]


def _unresolved_lines(report: dict) -> list[str]:
    """Packages the resolver could not settle on, with the reason."""
    return [f"{x['package']}: {x['reason']}" for x in report["unresolved"]]
