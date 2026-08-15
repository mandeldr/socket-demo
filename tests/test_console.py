"""Tests for the console rendering.

Every test builds a real report and renders it, so nothing here can assert
on something the JSON does not also carry.
"""

from datetime import timedelta

from scanner.console import render
from scanner.enums import SkipReason
from scanner.graph import DependencyGraph, ResolutionError
from scanner.models import SkippedLine
from tests.helpers import (
    NOW,
    graph_with,
    key,
    mixed_findings,
    report_for,
    skipped_lines,
    vulnerability,
)


def test_the_console_says_when_findings_were_ignored() -> None:
    graph = graph_with("flask")
    findings = {key("flask"): [vulnerability("GHSA-x", "CVE-2025-1")]}

    text = render(report_for(graph, findings, ignore=["CVE-2025-1"]))

    assert "1 ignored" in text


def test_ignoring_nothing_says_nothing() -> None:
    graph = graph_with("flask")
    text = render(report_for(graph, {key("flask"): [vulnerability()]}))
    assert "ignored" not in text


def test_the_console_lists_unmaintained_packages() -> None:
    graph = graph_with("abandoned", last_release={"abandoned": NOW - timedelta(days=900)})

    text = render(report_for(graph, {}, stale_after_days=365))

    assert "abandoned" in text
    assert "900 days" in text


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


def test_the_console_names_the_version_to_upgrade_to() -> None:
    graph = graph_with("flask")
    text = render(report_for(graph, {key("flask", "1.0"): [vulnerability(fixes=["3.1.3"])]}))
    assert "to at least 3.1.3" in text


def test_the_console_says_when_nothing_clears_it() -> None:
    graph = graph_with("flask")
    text = render(report_for(graph, {key("flask", "1.0"): [vulnerability(fixes=[])]}))
    assert "no version clears every finding" in text


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


def test_the_manifest_path_appears_once() -> None:
    text = render(report_for(graph_with("flask"), {}, requirements=1))
    assert text.count("requirements.txt") == 1


def test_the_console_says_what_is_hidden() -> None:
    graph = graph_with("critical-pkg", "high-pkg", "medium-pkg", "low-pkg")
    text = render(report_for(graph, mixed_findings(), min_severity="HIGH"))
    assert "showing HIGH and above" in text
    assert "2 hidden" in text


def test_the_console_says_nothing_when_no_threshold_is_set() -> None:
    graph = graph_with("high-pkg")
    findings = {key("high-pkg"): [vulnerability("B", "CVE-2", severity="HIGH")]}
    assert "hidden" not in render(report_for(graph, findings))


def test_the_header_shows_unique_packages_when_a_manifest_repeats_one() -> None:
    """requirements.txt lists flask and requests twice, so 12 lines are 10
    packages. Without this the reader cannot get from 12 to 10."""
    graph = DependencyGraph()
    graph.roots.append(key("flask"))
    graph.add_node(key("flask"), depth=0)

    text = render(report_for(graph, {}, requirements=3))

    assert "3 requirements (1 package)" in text


def test_the_header_stays_quiet_when_nothing_repeats() -> None:
    graph = DependencyGraph()
    graph.roots.extend([key("flask"), key("click")])
    graph.add_node(key("flask"), depth=0)
    graph.add_node(key("click"), depth=0)

    text = render(report_for(graph, {}, requirements=2))

    assert "2 requirements" in text
    assert "packages)" not in text


def test_a_skipped_entry_with_no_line_number_does_not_print_one() -> None:
    """A requirements.txt line has a number worth printing. A package.json
    dependency is a key in an object, so `line 0` would be noise pretending to
    be a location."""
    report = report_for(
        graph_with("flask"),
        {},
        skipped=[SkippedLine(None, "local-lib@file:./local-lib", SkipReason.LOCAL_PATH)],
    )

    output = render(report, show_skipped=True)

    assert "local-lib@file:./local-lib  (local path reference)" in output
    assert "line 0" not in output


def test_a_skipped_line_from_a_text_manifest_still_prints_its_number() -> None:
    report = report_for(
        graph_with("flask"), {}, skipped=[SkippedLine(4, "-e .", SkipReason.EDITABLE)]
    )

    assert "line 4: -e .  (editable install)" in render(report, show_skipped=True)
