"""Turning a finished scan into plain data.

Everything worth saying about a scan ends up in one dictionary: it is what
`--format json` prints, and what console.py renders the human version from.
Building it once means the two cannot disagree.
"""

from datetime import datetime, timezone
from pathlib import Path

from packaging.version import InvalidVersion, Version

from scanner.graph import DependencyGraph, GraphNode
from scanner.models import PackageKey, ParseResult, Vulnerability
from scanner.sources import SEVERITY_ORDER, UNKNOWN_SEVERITY, cve_of


def build(
    manifest: Path,
    graph: DependencyGraph,
    findings: dict[PackageKey, list[Vulnerability]],
    source_errors: dict[str, str | None],
    parsed: ParseResult | None = None,
    generated_at: datetime | None = None,
    ignore: list[str] | None = None,
    stale_after_days: int | None = None,
    min_severity: str | None = None,
) -> dict:
    """Everything worth saying about one scan, as plain data."""
    now = generated_at or datetime.now(timezone.utc)
    resolved = [node for node in graph.nodes.values() if not node.failed]

    parsed = parsed or ParseResult()
    kept, ignored_count = _apply_ignore_list(findings, ignore or [])
    shown, hidden_count = _apply_severity_filter(kept, min_severity)

    return {
        "manifest": str(manifest),
        "generated_at": now.isoformat(),
        "summary": _summary(
            resolved,
            kept,
            parsed,
            len(graph.roots),
            len(graph.errors),
            hidden_count,
            min_severity,
        ),
        "findings": [
            # `kept` rather than `shown`: the severity filter decides what is
            # listed, but the upgrade target still has to clear everything the
            # user has not explicitly ignored.
            _finding(package, vulnerabilities, kept[package], graph)
            for package, vulnerabilities in _worst_first(shown)
        ],
        "ignored": {"count": ignored_count, "rules": sorted(ignore or [])},
        # What the scan did not read. A caller of the JSON must not be left
        # believing the whole manifest was covered.
        "skipped": [
            {"line": line.line_number, "content": line.content, "reason": line.reason.value}
            for line in parsed.skipped
        ],
        "unmaintained": _unmaintained(resolved, now, stale_after_days),
        "unresolved": [{"package": e.package, "reason": e.error} for e in graph.errors],
        "sources": {
            "queried": sorted(source_errors),
            "failed": {name: why for name, why in source_errors.items() if why},
        },
    }


def _apply_ignore_list(
    findings: dict[PackageKey, list[Vulnerability]], ignore: list[str]
) -> tuple[dict[PackageKey, list[Vulnerability]], int]:
    """Drop advisories the user has already decided about.

    Matching is on any identifier a record carries, so a rule can name either
    the CVE a person read in the output or the GHSA id a tool emitted.
    """
    if not ignore:
        return findings, 0

    rules = {rule.strip().upper() for rule in ignore}
    kept: dict[PackageKey, list[Vulnerability]] = {}
    dropped = 0

    for package, vulnerabilities in findings.items():
        remaining = [v for v in vulnerabilities if not _matches(v, rules)]
        dropped += len(vulnerabilities) - len(remaining)
        if remaining:
            kept[package] = remaining

    return kept, dropped


def _apply_severity_filter(
    findings: dict[PackageKey, list[Vulnerability]], min_severity: str | None
) -> tuple[dict[PackageKey, list[Vulnerability]], int]:
    """Show only what is at least this serious.

    UNKNOWN always survives. It sorts last, so a plain rank comparison would
    drop it, but unknown means we could not work the severity out rather than
    that it does not matter. Hiding those would be the tool covering up its own
    blind spot.
    """
    if not min_severity:
        return findings, 0

    threshold = SEVERITY_ORDER.index(min_severity.strip().upper())
    shown: dict[PackageKey, list[Vulnerability]] = {}
    hidden = 0

    for package, vulnerabilities in findings.items():
        keep = [
            v
            for v in vulnerabilities
            if v.severity == UNKNOWN_SEVERITY or _severity_rank(v) <= threshold
        ]
        hidden += len(vulnerabilities) - len(keep)
        if keep:
            shown[package] = keep

    return shown, hidden


def _matches(vulnerability: Vulnerability, rules: set[str]) -> bool:
    names = {vulnerability.id.upper()} | {alias.upper() for alias in vulnerability.aliases}
    return bool(names & rules)


def _summary(
    resolved: list[GraphNode],
    findings: dict,
    parsed: ParseResult,
    requested: int,
    unresolved: int,
    hidden: int,
    min_severity: str | None,
) -> dict:
    """The counts a reader wants before any detail.

    Manifest counts and package counts live together so that they reconcile:
    requirements minus unresolved is what a reader should see resolved.
    """
    severities: dict[str, int] = {}
    for vulnerabilities in findings.values():
        for vulnerability in vulnerabilities:
            severities[vulnerability.severity] = severities.get(vulnerability.severity, 0) + 1

    return {
        "requirements": len(parsed.dependencies),
        "packages_requested": requested,
        "skipped": len(parsed.skipped),
        "unresolved": unresolved,
        "total_packages": len(resolved),
        "direct": len([n for n in resolved if n.depth == 0]),
        "transitive": len([n for n in resolved if n.depth > 0]),
        "vulnerable_packages": len(findings),
        "vulnerable_percent": round(100 * len(findings) / len(resolved), 1) if resolved else 0.0,
        "total_vulnerabilities": sum(len(v) for v in findings.values()),
        "hidden_by_severity": hidden,
        "min_severity": min_severity.strip().upper() if min_severity else None,
        # Worst first, so the JSON and the console read the same way round.
        "by_severity": {
            level: severities[level] for level in SEVERITY_ORDER if level in severities
        },
    }


def _unmaintained(
    resolved: list[GraphNode], now: datetime, stale_after_days: int | None
) -> list[dict]:
    """Packages nobody has published a release for in a long time.

    Not a vulnerability, but the thing an attacker looks for: an abandoned
    package is one nobody is watching. Off unless a threshold is given, since
    what counts as abandoned depends on the project.
    """
    if stale_after_days is None:
        return []

    stale: list[dict] = []
    for node in resolved:
        if node.last_release is None:
            continue
        days = (now - node.last_release).days
        if days >= stale_after_days:
            stale.append({"package": node.key.name, "days_since_release": days})

    return sorted(stale, key=lambda item: -item["days_since_release"])


def _finding(
    package: PackageKey,
    vulnerabilities: list[Vulnerability],
    everything: list[Vulnerability],
    graph: DependencyGraph,
) -> dict:
    """One vulnerable package: what is wrong, and what to change.

    `vulnerabilities` is what gets listed; `everything` is every finding for
    this package that survived the ignore list, which is what the upgrade
    target has to clear.
    """
    return {
        "package": package.name,
        "version": package.version,
        "direct": graph.nodes[package].depth == 0,
        "path": [key.name for key in graph.path_to(package)],
        "remediation": _remediation(package, graph),
        "upgrade_to": _upgrade_target(package, everything),
        "vulnerabilities": [
            {
                "id": vulnerability.id,
                "cve": cve_of(vulnerability),
                "severity": vulnerability.severity,
                "summary": vulnerability.summary,
                "fixed_versions": vulnerability.fixed_versions,
                "url": vulnerability.url,
                "source": vulnerability.source.value,
            }
            for vulnerability in sorted(vulnerabilities, key=_order)
        ],
    }


def _upgrade_target(package: PackageKey, vulnerabilities: list[Vulnerability]) -> str | None:
    """The lowest version that clears every finding for this package.

    For each finding take the lowest published fix above the installed version,
    then take the highest of those: anything lower leaves some finding open.
    None when even one finding has no fix that helps.

    This assumes releases go up in a line. A project that backports a fix to an
    old branch after shipping a newer major - urllib3 does this with 1.26.x -
    can push the answer higher than strictly necessary. For a security tool
    that is the safe direction to be wrong in.
    """
    current = _version(package.version)
    if current is None:
        return None

    target = None
    for vulnerability in vulnerabilities:
        usable = [v for v in map(_version, vulnerability.fixed_versions) if v and v > current]
        if not usable:
            return None
        lowest = min(usable)
        if target is None or lowest > target:
            target = lowest

    return str(target) if target else None


def _version(raw: str | None) -> Version | None:
    """Compared as a version, not as text: 1.9.0 is above 1.26.19."""
    if not raw:
        return None
    try:
        return Version(raw)
    except InvalidVersion:
        return None


def _remediation(package: PackageKey, graph: DependencyGraph) -> str:
    """Which package to change, which is not always the vulnerable one.

    A transitive package is pinned by whatever required it, so editing the
    manifest to bump it has no effect. The dependents are what has to move.
    """
    if graph.nodes[package].depth == 0:
        return f"upgrade {package.name} in the manifest"

    dependents = sorted({key.name for key in graph.dependents_of(package)})
    if not dependents:
        return f"upgrade whatever requires {package.name}"

    verb = "requires" if len(dependents) == 1 else "require"
    return f"upgrade {', '.join(dependents)}, which {verb} {package.name}"


def _severity_rank(vulnerability: Vulnerability) -> int:
    """Position in SEVERITY_ORDER, so the worst sorts first."""
    return SEVERITY_ORDER.index(vulnerability.severity)


def _order(vulnerability: Vulnerability) -> tuple[int, str]:
    """Worst first, then by identifier so two runs print the same order.

    Without the second half the order follows whatever the services happened
    to return, and the output cannot be diffed between runs.
    """
    return (_severity_rank(vulnerability), cve_of(vulnerability) or vulnerability.id)


def _worst_first(findings: dict[PackageKey, list[Vulnerability]]) -> list[tuple]:
    """Packages ordered by their most serious vulnerability, then by name."""
    return sorted(
        findings.items(),
        key=lambda item: (min(_severity_rank(v) for v in item[1]), item[0].name),
    )
