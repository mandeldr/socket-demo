"""Builders shared by the report and console tests.

Both suites need the same fixtures - a graph, some findings, a parsed manifest -
so they live here rather than being duplicated or imported across test modules.
"""

from datetime import datetime, timezone
from pathlib import Path

from scanner.enums import Ecosystem, SkipReason, Source
from scanner.graph import DependencyGraph
from scanner.models import Dependency, PackageKey, ParseResult, SkippedLine, Vulnerability
from scanner.report import build

NOW = datetime(2026, 8, 11, tzinfo=timezone.utc)


def key(name: str, version: str = "1.0") -> PackageKey:
    return PackageKey(name, version, Ecosystem.PYTHON)


def vulnerability(
    identifier: str = "GHSA-x",
    cve: str = "CVE-2025-1",
    severity: str = "HIGH",
    fixes: list[str] | None = None,
    summary: str = "something is wrong",
) -> Vulnerability:
    return Vulnerability(
        id=identifier,
        aliases={cve},
        fixed_versions=fixes if fixes is not None else ["2.0.0"],
        source=Source.OSV,
        severity=severity,
        summary=summary,
        url=f"https://osv.dev/vulnerability/{identifier}",
    )


def graph_with(*names: str, last_release: dict | None = None) -> DependencyGraph:
    """A flat graph of direct packages, optionally with release dates."""
    graph = DependencyGraph()
    for name in names:
        graph.add_node(key(name), depth=0, last_release=(last_release or {}).get(name))
    return graph


def skipped_lines() -> list[SkippedLine]:
    return [
        SkippedLine(4, "-e .", SkipReason.EDITABLE),
        SkippedLine(9, "--index-url https://example.com", SkipReason.PIP_OPTION),
    ]


def mixed_findings() -> dict:
    """One finding at each severity, for testing the filter."""
    return {
        key("critical-pkg"): [vulnerability("A", "CVE-1", severity="CRITICAL")],
        key("high-pkg"): [vulnerability("B", "CVE-2", severity="HIGH")],
        key("medium-pkg"): [vulnerability("C", "CVE-3", severity="MEDIUM")],
        key("low-pkg"): [vulnerability("D", "CVE-4", severity="LOW")],
    }


def report_for(
    graph: DependencyGraph,
    findings: dict,
    requirements: int = 0,
    skipped: list[SkippedLine] | None = None,
    **kwargs,
) -> dict:
    """Build a report, with the manifest facts spelled out as counts.

    `build` takes the ParseResult the parser actually produces; tests care about
    the counts, so this makes one up from them.
    """
    parsed = ParseResult(
        dependencies=[Dependency(f"req{i}", raw_spec="") for i in range(requirements)],
        skipped=skipped or [],
    )
    return build(
        manifest=Path("requirements.txt"),
        graph=graph,
        findings=findings,
        source_errors=kwargs.pop("source_errors", {"osv": None, "github": None}),
        parsed=parsed,
        generated_at=kwargs.pop("generated_at", NOW),
        **kwargs,
    )
