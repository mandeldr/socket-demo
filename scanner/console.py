"""Rendering a finished report as text.

Everything here reads from the report dictionary and nothing else. It cannot
show a number the JSON does not also carry, which is the point: two formatters
written against the same source cannot drift apart.
"""


def render(report: dict, show_skipped: bool = False) -> str:
    """The console version, built from the same data the JSON carries."""
    summary = report["summary"]
    lines = [report["manifest"], *_header(summary), ""]

    if report["findings"]:
        counts = "  ".join(f"{level} {n}" for level, n in summary["by_severity"].items())
        lines.append(
            f"{summary['vulnerable_packages']} vulnerable "
            f"({summary['vulnerable_percent']}% of packages), "
            f"{summary['total_vulnerabilities']} findings{_ignored_note(report)}"
        )
        lines.append(f"  {counts}")
        if summary["min_severity"]:
            lines.append(
                f"  showing {summary['min_severity']} and above; "
                f"{summary['hidden_by_severity']} hidden"
            )
        for finding in report["findings"]:
            lines += _render_finding(finding)
    else:
        lines.append(f"no known vulnerabilities{_ignored_note(report)}")

    if report["skipped"] and show_skipped:
        lines.append("")
        lines.append("skipped:")
        lines += [
            f"  line {item['line']}: {item['content']}  ({item['reason']})"
            for item in report["skipped"]
        ]

    if report["unmaintained"]:
        lines.append("")
        lines.append(f"unmaintained {len(report['unmaintained'])}:")
        lines += [
            f"  {item['package']}: no release in {item['days_since_release']} days"
            for item in report["unmaintained"]
        ]

    if report["unresolved"]:
        lines.append("")
        lines.append(f"could not resolve {len(report['unresolved'])}:")
        lines += [f"  {item['package']}: {item['reason']}" for item in report["unresolved"]]

    for name, why in report["sources"]["failed"].items():
        lines.append("")
        lines.append(f"{name} did not finish: {why}")

    return "\n".join(lines)


def _header(summary: dict) -> list[str]:
    """What the manifest asked for, and what came back.

    Clauses that would read as zero are left out rather than printed, so the
    line stays about what actually happened.
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


def _ignored_note(report: dict) -> str:
    """Say when findings were suppressed, so a clean report can be trusted."""
    count = report["ignored"]["count"]
    return f" ({count} ignored)" if count else ""


def _upgrade_note(finding: dict) -> str:
    """What to upgrade to, or that nothing available fixes everything."""
    if finding["upgrade_to"]:
        return f", to at least {finding['upgrade_to']}"
    return " (no version clears every finding)"


def _render_finding(finding: dict) -> list[str]:
    how = "direct" if finding["direct"] else "via " + " -> ".join(finding["path"][:-1])
    lines = [
        "",
        f"{finding['package']} {finding['version']}  ({how})",
        f"  {finding['remediation']}{_upgrade_note(finding)}",
    ]
    for vulnerability in finding["vulnerabilities"]:
        fixed = ", ".join(vulnerability["fixed_versions"]) or "no fix published"
        lines.append(
            f"  [{vulnerability['severity']:8}] {vulnerability['cve'] or vulnerability['id']}"
            f"  fixed in {fixed}"
        )
        if vulnerability["summary"]:
            lines.append(f"{'':13}{vulnerability['summary']}")
        lines.append(f"{'':13}{vulnerability['url']}")
    return lines
