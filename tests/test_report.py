"""Tests for the report.

The report is built once as a dictionary and the console text is rendered from
it, so every test here checks both: if something is worth printing it has to be
in the JSON too.
"""

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from scanner.enums import EcoSystem, SkipReason, Source
from scanner.graph import DependencyGraph, ResolutionError
from scanner.models import PackageKey, SkippedLine, Vulnerability
from scanner.report import build, render

NOW = datetime(2026, 8, 11, tzinfo=timezone.utc)


def key(name: str, version: str = "1.0") -> PackageKey:
    return PackageKey(name, version, EcoSystem.PYTHON)


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


def report_for(graph, findings, **kwargs) -> dict:
    defaults = {
        "manifest": Path("requirements.txt"),
        "source_errors": {"osv": None, "github": None},
        "generated_at": NOW,
    }
    return build(graph=graph, findings=findings, **{**defaults, **kwargs})


# --- the summary the rubric asks for --------------------------------------


def test_the_summary_counts_packages_and_what_share_are_vulnerable() -> None:
    graph = graph_with("flask", "click", "jinja2", "urllib3")
    report = report_for(graph, {key("flask"): [vulnerability()]})

    summary = report["summary"]
    assert summary["total_packages"] == 4
    assert summary["vulnerable_packages"] == 1
    assert summary["vulnerable_percent"] == 25.0
    assert summary["total_vulnerabilities"] == 1


def test_the_summary_counts_each_severity() -> None:
    graph = graph_with("flask")
    findings = {
        key("flask"): [
            vulnerability("A", "CVE-1", severity="CRITICAL"),
            vulnerability("B", "CVE-2", severity="HIGH"),
            vulnerability("C", "CVE-3", severity="HIGH"),
        ]
    }
    assert report_for(graph, findings)["summary"]["by_severity"] == {"CRITICAL": 1, "HIGH": 2}


def test_severities_are_counted_worst_first() -> None:
    graph = graph_with("flask")
    findings = {
        key("flask"): [
            vulnerability("A", "CVE-1", severity="LOW"),
            vulnerability("B", "CVE-2", severity="CRITICAL"),
        ]
    }
    assert list(report_for(graph, findings)["summary"]["by_severity"]) == ["CRITICAL", "LOW"]


# --- an ignore list, so known findings can be silenced ---------------------


def test_an_ignored_advisory_is_left_out_of_the_findings() -> None:
    graph = graph_with("flask")
    findings = {key("flask"): [vulnerability("GHSA-x", "CVE-2025-1")]}

    report = report_for(graph, findings, ignore=["CVE-2025-1"])

    assert report["findings"] == []
    assert report["summary"]["vulnerable_packages"] == 0


def test_a_package_keeps_the_findings_that_were_not_ignored() -> None:
    graph = graph_with("flask")
    findings = {
        key("flask"): [
            vulnerability("GHSA-x", "CVE-2025-1"),
            vulnerability("GHSA-y", "CVE-2025-2"),
        ]
    }

    report = report_for(graph, findings, ignore=["CVE-2025-1"])

    (finding,) = report["findings"]
    assert [v["cve"] for v in finding["vulnerabilities"]] == ["CVE-2025-2"]


def test_an_advisory_can_be_ignored_by_its_ghsa_id_too() -> None:
    """A user reading the console output sees the CVE, but the id also works."""
    graph = graph_with("flask")
    findings = {key("flask"): [vulnerability("GHSA-x", "CVE-2025-1")]}

    assert report_for(graph, findings, ignore=["GHSA-x"])["findings"] == []


def test_what_was_ignored_is_recorded_so_the_report_stays_honest() -> None:
    """Silently dropping findings would make a clean report untrustworthy."""
    graph = graph_with("flask")
    findings = {key("flask"): [vulnerability("GHSA-x", "CVE-2025-1")]}

    report = report_for(graph, findings, ignore=["CVE-2025-1"])

    assert report["ignored"]["count"] == 1
    assert report["ignored"]["rules"] == ["CVE-2025-1"]


def test_the_console_says_when_findings_were_ignored() -> None:
    graph = graph_with("flask")
    findings = {key("flask"): [vulnerability("GHSA-x", "CVE-2025-1")]}

    text = render(report_for(graph, findings, ignore=["CVE-2025-1"]))

    assert "1 ignored" in text


def test_ignoring_nothing_says_nothing() -> None:
    graph = graph_with("flask")
    text = render(report_for(graph, {key("flask"): [vulnerability()]}))
    assert "ignored" not in text


# --- unmaintained packages ------------------------------------------------


def test_a_package_with_no_recent_release_is_flagged() -> None:
    graph = graph_with("abandoned", last_release={"abandoned": NOW - timedelta(days=900)})

    report = report_for(graph, {}, stale_after_days=365)

    assert report["unmaintained"] == [{"package": "abandoned", "days_since_release": 900}]


def test_a_recently_released_package_is_not_flagged() -> None:
    graph = graph_with("healthy", last_release={"healthy": NOW - timedelta(days=10)})
    assert report_for(graph, {}, stale_after_days=365)["unmaintained"] == []


def test_a_package_with_no_known_release_date_is_not_guessed_at() -> None:
    """No date is not the same as no releases."""
    graph = graph_with("mystery")
    assert report_for(graph, {}, stale_after_days=365)["unmaintained"] == []


def test_the_threshold_is_configurable() -> None:
    graph = graph_with("quiet", last_release={"quiet": NOW - timedelta(days=100)})

    assert report_for(graph, {}, stale_after_days=365)["unmaintained"] == []
    assert len(report_for(graph, {}, stale_after_days=90)["unmaintained"]) == 1


def test_unmaintained_packages_are_listed_worst_first() -> None:
    graph = graph_with(
        "old",
        "older",
        last_release={"old": NOW - timedelta(days=400), "older": NOW - timedelta(days=800)},
    )

    report = report_for(graph, {}, stale_after_days=365)

    assert [p["package"] for p in report["unmaintained"]] == ["older", "old"]


def test_the_console_lists_unmaintained_packages() -> None:
    graph = graph_with("abandoned", last_release={"abandoned": NOW - timedelta(days=900)})

    text = render(report_for(graph, {}, stale_after_days=365))

    assert "abandoned" in text
    assert "900 days" in text


def test_staleness_is_off_unless_asked_for() -> None:
    graph = graph_with("abandoned", last_release={"abandoned": NOW - timedelta(days=9000)})
    assert report_for(graph, {})["unmaintained"] == []


# --- everything the console shows is in the json --------------------------


def test_the_report_is_json_serialisable() -> None:
    graph = graph_with("flask")
    graph.errors.append(ResolutionError("ghost", "no such package on PyPI"))
    report = report_for(
        graph,
        {key("flask"): [vulnerability()]},
        ignore=["CVE-9999-1"],
        stale_after_days=365,
    )

    assert json.loads(json.dumps(report)) == report


@pytest.mark.parametrize(
    "field", ["manifest", "generated_at", "summary", "findings", "unresolved", "sources"]
)
def test_the_report_carries_every_section(field: str) -> None:
    assert field in report_for(graph_with("flask"), {})


def test_a_finding_carries_everything_the_rubric_asks_for() -> None:
    graph = DependencyGraph()
    graph.add_node(key("boto3"), depth=0)
    graph.add_node(key("urllib3", "1.26.20"), depth=1, parent=key("boto3"))
    graph.add_edge(key("boto3"), key("urllib3", "1.26.20"))

    report = report_for(graph, {key("urllib3", "1.26.20"): [vulnerability(fixes=["2.6.0"])]})

    (finding,) = report["findings"]
    assert finding["package"] == "urllib3"
    assert finding["version"] == "1.26.20"
    assert finding["path"] == ["boto3", "urllib3"]
    assert finding["direct"] is False
    assert "boto3" in finding["remediation"]

    (found,) = finding["vulnerabilities"]
    assert found["severity"] == "HIGH"
    assert found["cve"] == "CVE-2025-1"
    assert found["summary"] == "something is wrong"
    assert found["fixed_versions"] == ["2.6.0"]
    assert found["url"].startswith("https://")


def test_a_transitive_finding_names_the_package_to_actually_upgrade() -> None:
    """Bumping urllib3 in the manifest does nothing when botocore pins it."""
    graph = DependencyGraph()
    graph.add_node(key("boto3"), depth=0)
    graph.add_node(key("botocore"), depth=1, parent=key("boto3"))
    graph.add_node(key("urllib3"), depth=2, parent=key("botocore"))
    graph.add_edge(key("botocore"), key("urllib3"))

    report = report_for(graph, {key("urllib3"): [vulnerability()]})

    assert report["findings"][0]["remediation"] == "upgrade botocore, which requires urllib3"


def test_one_dependent_reads_as_singular_and_two_as_plural() -> None:
    graph = DependencyGraph()
    graph.add_node(key("flask"), depth=0)
    graph.add_node(key("requests"), depth=0)
    graph.add_node(key("urllib3"), depth=1, parent=key("flask"))
    graph.add_edge(key("flask"), key("urllib3"))
    graph.add_edge(key("requests"), key("urllib3"))

    report = report_for(graph, {key("urllib3"): [vulnerability()]})

    assert "which require urllib3" in report["findings"][0]["remediation"]


def test_a_vulnerability_with_no_fix_says_so() -> None:
    graph = graph_with("flask")
    text = render(report_for(graph, {key("flask"): [vulnerability(fixes=[])]}))
    assert "no fix published" in text


def test_a_clean_scan_says_so_in_one_line() -> None:
    text = render(report_for(graph_with("flask", "click"), {}))
    assert "no known vulnerabilities" in text
    assert "2 packages" in text


def test_a_failed_source_is_named_in_both_formats() -> None:
    graph = graph_with("flask")
    report = report_for(
        graph, {}, source_errors={"osv": None, "github": "GitHub rate limit reached"}
    )

    assert report["sources"]["failed"] == {"github": "GitHub rate limit reached"}
    assert "GitHub rate limit reached" in render(report)


def test_packages_are_ordered_by_their_worst_vulnerability() -> None:
    graph = graph_with("mild", "severe")
    findings = {
        key("mild"): [vulnerability("A", "CVE-1", severity="LOW")],
        key("severe"): [vulnerability("B", "CVE-2", severity="CRITICAL")],
    }

    report = report_for(graph, findings)

    assert [f["package"] for f in report["findings"]] == ["severe", "mild"]


def test_vulnerabilities_of_equal_severity_are_ordered_predictably() -> None:
    """Otherwise two runs of the same scan print the findings in different
    orders, which makes the output impossible to diff."""
    graph = graph_with("django")
    findings = {
        key("django"): [
            vulnerability("GHSA-c", "CVE-2024-9999", severity="HIGH"),
            vulnerability("GHSA-a", "CVE-2024-1111", severity="HIGH"),
            vulnerability("GHSA-b", "CVE-2024-5555", severity="HIGH"),
        ]
    }

    (finding,) = report_for(graph, findings)["findings"]

    assert [v["cve"] for v in finding["vulnerabilities"]] == [
        "CVE-2024-1111",
        "CVE-2024-5555",
        "CVE-2024-9999",
    ]


# --- what version to upgrade to -------------------------------------------


def test_the_upgrade_target_clears_every_finding() -> None:
    """Each finding needs a fix above the current version; the answer is the
    highest of those, which is the lowest version that clears them all."""
    graph = graph_with("urllib3")
    findings = {
        key("urllib3", "1.0"): [
            vulnerability("A", "CVE-1", fixes=["2.6.0"]),
            vulnerability("B", "CVE-2", fixes=["2.7.0"]),
            vulnerability("C", "CVE-3", fixes=["2.5.0"]),
        ]
    }

    (finding,) = report_for(graph, findings)["findings"]

    assert finding["upgrade_to"] == "2.7.0"


def test_a_fix_below_the_current_version_is_not_a_fix() -> None:
    """urllib3 backports to 1.26.x, so a fix list can contain a version older
    than what is installed."""
    graph = DependencyGraph()
    graph.add_node(key("urllib3", "2.2.1"), depth=0)
    findings = {key("urllib3", "2.2.1"): [vulnerability("A", "CVE-1", fixes=["1.26.19", "2.2.2"])]}

    (finding,) = report_for(graph, findings)["findings"]

    assert finding["upgrade_to"] == "2.2.2"


def test_versions_are_compared_numerically_not_as_strings() -> None:
    """Sorted as text, 1.26.19 comes before 1.9.0."""
    graph = DependencyGraph()
    graph.add_node(key("thing", "1.0.0"), depth=0)
    findings = {key("thing", "1.0.0"): [vulnerability("A", "CVE-1", fixes=["1.9.0", "1.26.19"])]}

    (finding,) = report_for(graph, findings)["findings"]

    assert finding["upgrade_to"] == "1.9.0"


def test_a_finding_with_no_published_fix_means_no_target() -> None:
    """One unfixable finding means no version clears everything."""
    graph = graph_with("thing")
    findings = {
        key("thing", "1.0"): [
            vulnerability("A", "CVE-1", fixes=["2.0.0"]),
            vulnerability("B", "CVE-2", fixes=[]),
        ]
    }

    assert report_for(graph, findings)["findings"][0]["upgrade_to"] is None


def test_a_fix_that_does_not_help_means_no_target() -> None:
    """Every fix is already below the installed version."""
    graph = DependencyGraph()
    graph.add_node(key("thing", "5.0.0"), depth=0)
    findings = {key("thing", "5.0.0"): [vulnerability("A", "CVE-1", fixes=["1.0.0"])]}

    assert report_for(graph, findings)["findings"][0]["upgrade_to"] is None


def test_an_unreadable_version_is_skipped_rather_than_crashing() -> None:
    graph = DependencyGraph()
    graph.add_node(key("thing", "1.0.0"), depth=0)
    findings = {
        key("thing", "1.0.0"): [vulnerability("A", "CVE-1", fixes=["not a version", "2.0"])]
    }

    assert report_for(graph, findings)["findings"][0]["upgrade_to"] == "2.0"


def test_a_package_with_no_version_has_no_target() -> None:
    graph = DependencyGraph()
    graph.add_node(PackageKey("thing", None, EcoSystem.PYTHON), depth=0)
    findings = {PackageKey("thing", None, EcoSystem.PYTHON): [vulnerability(fixes=["2.0"])]}

    assert report_for(graph, findings)["findings"][0]["upgrade_to"] is None


def test_the_console_names_the_version_to_upgrade_to() -> None:
    graph = graph_with("flask")
    text = render(report_for(graph, {key("flask", "1.0"): [vulnerability(fixes=["3.1.3"])]}))
    assert "to at least 3.1.3" in text


def test_the_console_says_when_nothing_clears_it() -> None:
    graph = graph_with("flask")
    text = render(report_for(graph, {key("flask", "1.0"): [vulnerability(fixes=[])]}))
    assert "no version clears every finding" in text


# --- what the scan did not look at ----------------------------------------


def skipped_lines() -> list[SkippedLine]:
    return [
        SkippedLine(4, "-e .", SkipReason.EDITABLE),
        SkippedLine(9, "--index-url https://example.com", SkipReason.PIP_OPTION),
    ]


def test_skipped_lines_are_recorded_so_the_scan_is_honest() -> None:
    """A consumer of the JSON must not believe the whole manifest was read."""
    report = report_for(graph_with("flask"), {}, skipped=skipped_lines())

    assert report["skipped"] == [
        {"line": 4, "content": "-e .", "reason": "editable install"},
        {"line": 9, "content": "--index-url https://example.com", "reason": "pip option"},
    ]


def test_the_reason_reads_as_english_not_as_an_enum() -> None:
    report = report_for(graph_with("flask"), {}, skipped=skipped_lines())
    assert report["skipped"][0]["reason"] == "editable install"


def test_the_summary_counts_skipped_lines() -> None:
    report = report_for(graph_with("flask"), {}, skipped=skipped_lines())
    assert report["summary"]["skipped"] == 2


def test_nothing_skipped_is_an_empty_list_not_a_missing_key() -> None:
    report = report_for(graph_with("flask"), {})
    assert report["skipped"] == []
    assert report["summary"]["skipped"] == 0


def test_the_console_says_how_many_lines_were_skipped() -> None:
    text = render(report_for(graph_with("flask"), {}, skipped=skipped_lines()))
    assert "2 lines skipped" in text


def test_the_console_does_not_list_every_skipped_line_by_default() -> None:
    """Twelve lines of skip detail would drown the report."""
    text = render(report_for(graph_with("flask"), {}, skipped=skipped_lines()))
    assert "--index-url" not in text


def test_the_skipped_lines_can_be_shown_on_request() -> None:
    report = report_for(graph_with("flask"), {}, skipped=skipped_lines())
    text = render(report, show_skipped=True)
    assert "line 4: -e ." in text
    assert "editable install" in text


# --- the header, where every count has to reconcile ------------------------


def test_the_header_reconciles_the_manifest_against_what_resolved() -> None:
    """16 requirements, 12 skipped, 11 resolved and 4 failed have to add up
    for a reader without doing arithmetic across two output streams."""
    graph = DependencyGraph()
    graph.add_node(key("flask"), depth=0)
    graph.add_node(key("click"), depth=1, parent=key("flask"))
    graph.errors.append(ResolutionError("ghost", "no such package on PyPI"))

    text = render(report_for(graph, {}, requirements=3, skipped=skipped_lines()))

    assert "3 requirements, 2 lines skipped" in text
    assert "2 packages resolved (1 direct, 1 transitive), 1 unresolved" in text


def test_the_header_leaves_out_clauses_that_are_zero() -> None:
    graph = graph_with("flask")
    text = render(report_for(graph, {}, requirements=1))

    assert "1 requirements" in text
    assert "skipped" not in text
    assert "unresolved" not in text


def test_the_requirement_count_is_in_the_summary() -> None:
    report = report_for(graph_with("flask"), {}, requirements=16)
    assert report["summary"]["requirements"] == 16


def test_the_unresolved_count_is_in_the_summary() -> None:
    graph = graph_with("flask")
    graph.errors.append(ResolutionError("ghost", "no such package on PyPI"))
    assert report_for(graph, {})["summary"]["unresolved"] == 1


def test_the_manifest_path_appears_once() -> None:
    text = render(report_for(graph_with("flask"), {}, requirements=1))
    assert text.count("requirements.txt") == 1


# --- showing only what matters --------------------------------------------


def mixed_findings() -> dict:
    return {
        key("critical-pkg"): [vulnerability("A", "CVE-1", severity="CRITICAL")],
        key("high-pkg"): [vulnerability("B", "CVE-2", severity="HIGH")],
        key("medium-pkg"): [vulnerability("C", "CVE-3", severity="MEDIUM")],
        key("low-pkg"): [vulnerability("D", "CVE-4", severity="LOW")],
    }


def test_findings_below_the_threshold_are_not_listed() -> None:
    graph = graph_with("critical-pkg", "high-pkg", "medium-pkg", "low-pkg")

    report = report_for(graph, mixed_findings(), min_severity="HIGH")

    assert [f["package"] for f in report["findings"]] == ["critical-pkg", "high-pkg"]


def test_the_summary_still_counts_everything() -> None:
    """The filter changes what is shown, never what was found."""
    graph = graph_with("critical-pkg", "high-pkg", "medium-pkg", "low-pkg")

    report = report_for(graph, mixed_findings(), min_severity="HIGH")

    assert report["summary"]["total_vulnerabilities"] == 4
    assert report["summary"]["vulnerable_packages"] == 4
    assert report["summary"]["by_severity"] == {"CRITICAL": 1, "HIGH": 1, "MEDIUM": 1, "LOW": 1}


def test_how_many_were_hidden_is_reported() -> None:
    graph = graph_with("critical-pkg", "high-pkg", "medium-pkg", "low-pkg")
    report = report_for(graph, mixed_findings(), min_severity="HIGH")
    assert report["summary"]["hidden_by_severity"] == 2


def test_unknown_severity_is_never_hidden() -> None:
    """Unknown means we could not tell, not that it does not matter. Hiding it
    would be the tool concealing its own blind spot."""
    graph = graph_with("mystery")
    findings = {key("mystery"): [vulnerability("A", "CVE-1", severity="UNKNOWN")]}

    report = report_for(graph, findings, min_severity="CRITICAL")

    assert [f["package"] for f in report["findings"]] == ["mystery"]


def test_no_threshold_hides_nothing() -> None:
    graph = graph_with("critical-pkg", "high-pkg", "medium-pkg", "low-pkg")
    report = report_for(graph, mixed_findings())
    assert len(report["findings"]) == 4
    assert report["summary"]["hidden_by_severity"] == 0


def test_a_package_whose_findings_are_all_hidden_drops_out() -> None:
    graph = graph_with("low-pkg")
    findings = {key("low-pkg"): [vulnerability("D", "CVE-4", severity="LOW")]}

    assert report_for(graph, findings, min_severity="HIGH")["findings"] == []


def test_the_console_says_what_is_hidden() -> None:
    graph = graph_with("critical-pkg", "high-pkg", "medium-pkg", "low-pkg")
    text = render(report_for(graph, mixed_findings(), min_severity="HIGH"))
    assert "showing HIGH and above" in text
    assert "2 hidden" in text


def test_the_console_says_nothing_when_no_threshold_is_set() -> None:
    graph = graph_with("high-pkg")
    findings = {key("high-pkg"): [vulnerability("B", "CVE-2", severity="HIGH")]}
    assert "hidden" not in render(report_for(graph, findings))


def test_the_upgrade_target_ignores_the_display_filter() -> None:
    """--min-severity decides what is shown, not what a user has to fix.
    Recommending a version that only clears the visible findings would leave
    them with the hidden ones still open."""
    graph = DependencyGraph()
    graph.add_node(key("django", "5.0.1"), depth=0)
    findings = {
        key("django", "5.0.1"): [
            vulnerability("A", "CVE-1", severity="HIGH", fixes=["5.1.14"]),
            vulnerability("B", "CVE-2", severity="LOW", fixes=["5.2.16"]),
        ]
    }

    report = report_for(graph, findings, min_severity="HIGH")

    (finding,) = report["findings"]
    assert [v["cve"] for v in finding["vulnerabilities"]] == ["CVE-1"]  # LOW is hidden
    assert finding["upgrade_to"] == "5.2.16"  # but it still has to be fixed


def test_an_ignored_finding_does_not_affect_the_upgrade_target() -> None:
    """Ignoring is a decision about the finding itself, not about the display."""
    graph = DependencyGraph()
    graph.add_node(key("django", "5.0.1"), depth=0)
    findings = {
        key("django", "5.0.1"): [
            vulnerability("A", "CVE-1", severity="HIGH", fixes=["5.1.14"]),
            vulnerability("B", "CVE-2", severity="LOW", fixes=["5.2.16"]),
        ]
    }

    report = report_for(graph, findings, ignore=["CVE-2"])

    assert report["findings"][0]["upgrade_to"] == "5.1.14"
