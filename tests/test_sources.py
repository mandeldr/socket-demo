"""Tests for the vocabulary the two sources share."""

import pytest

from scanner.enums import Ecosystem, Source
from scanner.models import PackageKey, Vulnerability
from scanner.sources import QueryResult, cve_of, dedupe, merge, normalize_severity


def key(name: str, version: str = "1.0") -> PackageKey:
    return PackageKey(name, version, Ecosystem.PYTHON)


def vulnerability(
    identifier: str,
    cve: str | None = None,
    severity: str = "UNKNOWN",
    fixes: list[str] | None = None,
    source: Source = Source.OSV,
) -> Vulnerability:
    return Vulnerability(
        id=identifier,
        aliases={cve} if cve else set(),
        fixed_versions=fixes or [],
        source=source,
        severity=severity,
    )


# --- one vocabulary for severity ------------------------------------------


@pytest.mark.parametrize(
    ("given", "expected"),
    [
        ("MODERATE", "MEDIUM"),  # OSV's word
        ("medium", "MEDIUM"),  # GitHub's word for the same thing
        ("HIGH", "HIGH"),
        ("high", "HIGH"),
        ("critical", "CRITICAL"),
        ("low", "LOW"),
        (None, "UNKNOWN"),
        ("", "UNKNOWN"),
        ("CVSS:3.1/AV:N/AC:H", "UNKNOWN"),  # a vector is not a bucket
        ("something new", "UNKNOWN"),
    ],
)
def test_both_services_are_mapped_onto_one_scale(given, expected) -> None:
    assert normalize_severity(given) == expected


# --- what makes two records the same problem ------------------------------


def test_the_cve_is_what_identifies_a_finding() -> None:
    assert cve_of(vulnerability("GHSA-x", cve="CVE-2025-1")) == "CVE-2025-1"


def test_a_record_with_no_cve_has_none() -> None:
    assert cve_of(vulnerability("GHSA-x")) is None


def test_records_sharing_a_cve_collapse_to_one() -> None:
    found = dedupe(
        [
            vulnerability("GHSA-x", cve="CVE-2025-1"),
            vulnerability("PYSEC-1", cve="CVE-2025-1"),
        ]
    )
    assert len(found) == 1


def test_records_with_different_cves_stay_separate() -> None:
    found = dedupe(
        [
            vulnerability("GHSA-x", cve="CVE-2025-1"),
            vulnerability("GHSA-y", cve="CVE-2025-2"),
        ]
    )
    assert len(found) == 2


def test_records_without_cves_fall_back_to_their_own_ids() -> None:
    found = dedupe([vulnerability("GHSA-x"), vulnerability("GHSA-y")])
    assert len(found) == 2


def test_the_copy_carrying_a_severity_wins() -> None:
    (kept,) = dedupe(
        [
            vulnerability("PYSEC-1", cve="CVE-2025-1"),
            vulnerability("GHSA-x", cve="CVE-2025-1", severity="HIGH"),
        ]
    )
    assert kept.severity == "HIGH"


def test_the_copy_carrying_a_fix_wins_when_both_have_a_severity() -> None:
    (kept,) = dedupe(
        [
            vulnerability("PYSEC-1", cve="CVE-2025-1", severity="HIGH"),
            vulnerability("GHSA-x", cve="CVE-2025-1", severity="HIGH", fixes=["2.5.0"]),
        ]
    )
    assert kept.fixed_versions == ["2.5.0"]


def test_a_richer_record_does_not_lose_to_a_later_thinner_one() -> None:
    """Order should not decide it."""
    (kept,) = dedupe(
        [
            vulnerability("GHSA-x", cve="CVE-2025-1", severity="HIGH", fixes=["2.5.0"]),
            vulnerability("PYSEC-1", cve="CVE-2025-1"),
        ]
    )
    assert kept.severity == "HIGH"


# --- folding the sources together -----------------------------------------


def test_the_same_cve_from_both_services_becomes_one_finding() -> None:
    package = key("urllib3", "1.26.20")
    osv = QueryResult({package: [vulnerability("PYSEC-1", cve="CVE-2025-1")]})
    github = QueryResult(
        {
            package: [
                vulnerability("GHSA-x", cve="CVE-2025-1", severity="HIGH", source=Source.GITHUB)
            ]
        }
    )

    merged = merge([osv, github])

    assert len(merged[package]) == 1
    assert merged[package][0].severity == "HIGH"


def test_findings_only_one_source_has_are_kept() -> None:
    package = key("flask", "3.0.0")
    osv = QueryResult({package: [vulnerability("PYSEC-1", cve="CVE-1")]})
    github = QueryResult({package: [vulnerability("GHSA-2", cve="CVE-2")]})

    assert len(merge([osv, github])[package]) == 2


def test_a_source_that_failed_still_contributes_what_it_got() -> None:
    """Half an answer is worth keeping, as long as the caller knows it is half."""
    package = key("flask", "3.0.0")
    partial = QueryResult(
        {package: [vulnerability("GHSA-1", cve="CVE-1")]},
        error="GitHub rate limit reached",
    )

    assert len(merge([partial])[package]) == 1
    assert not partial.ok


def test_merging_nothing_gives_nothing() -> None:
    assert merge([]) == {}
    assert merge([QueryResult(), QueryResult()]) == {}


def test_a_result_is_ok_only_when_there_is_no_error() -> None:
    assert QueryResult().ok
    assert not QueryResult(error="boom").ok


# --- keeping the most useful copy, not just the most severe ----------------


def test_a_record_with_a_fix_is_not_beaten_by_one_without() -> None:
    """OSV often carries a fix with no severity word; GitHub carries a severity
    with at most one patched version, and sometimes none for our package.
    Ranking severity above the fix loses the only actionable part of a finding -
    the user is told how bad it is and not what to upgrade to."""
    with_fix = Vulnerability(
        id="GHSA-x",
        aliases={"CVE-1"},
        fixed_versions=["2.5.0"],
        source=Source.OSV,
        severity="UNKNOWN",
    )
    with_severity = Vulnerability(
        id="GHSA-x",
        aliases={"CVE-1"},
        fixed_versions=[],
        source=Source.GITHUB,
        severity="HIGH",
    )

    (kept,) = dedupe([with_fix, with_severity])

    assert kept.fixed_versions == ["2.5.0"]


def test_a_record_with_both_beats_one_with_either() -> None:
    partial = Vulnerability(
        id="GHSA-x",
        aliases={"CVE-1"},
        fixed_versions=["2.5.0"],
        source=Source.OSV,
        severity="UNKNOWN",
    )
    complete = Vulnerability(
        id="GHSA-x",
        aliases={"CVE-1"},
        fixed_versions=["2.5.0"],
        source=Source.GITHUB,
        severity="HIGH",
    )

    (kept,) = dedupe([partial, complete])

    assert kept.severity == "HIGH"
    assert kept.fixed_versions == ["2.5.0"]


def test_merging_two_sources_keeps_the_fix_and_the_severity() -> None:
    """What the two sources are for: neither alone answers both questions."""
    osv = QueryResult(
        {
            key("pkg"): [
                Vulnerability(
                    id="GHSA-x",
                    aliases={"CVE-1"},
                    fixed_versions=["2.5.0"],
                    source=Source.OSV,
                    severity="UNKNOWN",
                )
            ]
        }
    )
    github = QueryResult(
        {
            key("pkg"): [
                Vulnerability(
                    id="GHSA-x",
                    aliases={"CVE-1"},
                    fixed_versions=[],
                    source=Source.GITHUB,
                    severity="HIGH",
                )
            ]
        }
    )

    (found,) = merge([osv, github])[key("pkg")]

    assert found.fixed_versions == ["2.5.0"]
