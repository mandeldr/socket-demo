"""Tests for the command line entry point.

main() returns an exit code instead of calling sys.exit(), so these call it
directly. The PyPI client is swapped for a fake, which also makes these the
only tests that exercise parse -> resolve -> print end to end.
"""

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from packaging.requirements import Requirement

from scanner.cli import EXIT_OK, EXIT_USAGE_ERROR, EXIT_VULNERABILITIES_FOUND, build_parser, main
from scanner.enums import Source
from scanner.models import Vulnerability
from scanner.resolver import FetchResult
from scanner.sources import QueryResult

INDEX = {
    "flask": ["click>=8.0"],
    "click": [],
}


class FakeClient:
    """Stands in for PyPIClient. Serves INDEX and knows nothing else."""

    def fetch(self, name: str, spec) -> FetchResult:
        if name not in INDEX:
            return FetchResult(error="no such package on PyPI")
        return FetchResult(
            "1.0",
            [Requirement(r) for r in INDEX[name]],
            last_release=datetime.now(timezone.utc) - timedelta(days=900),
        )


class SilentOSV:
    """Answers "nothing known" for every package, without a network call."""

    def query(self, packages) -> QueryResult:
        return QueryResult()


class SilentGitHub:
    def fill_gaps(self, findings) -> QueryResult:
        return QueryResult()


@pytest.fixture
def offline(monkeypatch: pytest.MonkeyPatch) -> None:
    """No network anywhere: PyPI, OSV and GitHub are all stubbed."""
    monkeypatch.setattr("scanner.cli.PyPIClient", FakeClient)
    monkeypatch.setattr("scanner.cli.OSVClient", SilentOSV)
    monkeypatch.setattr("scanner.cli.GHSAClient", SilentGitHub)


def manifest(tmp_path: Path, contents: str) -> Path:
    path = tmp_path / "requirements.txt"
    path.write_text(contents)
    return path


def test_a_missing_file_is_a_usage_error(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["does-not-exist.txt"]) == EXIT_USAGE_ERROR
    assert "no such file" in capsys.readouterr().err


def test_a_directory_is_a_usage_error(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main([str(tmp_path)]) == EXIT_USAGE_ERROR
    assert "not a file" in capsys.readouterr().err


def test_an_unknown_format_is_rejected() -> None:
    """argparse exits 2 itself rather than returning."""
    with pytest.raises(SystemExit) as exit_info:
        build_parser().parse_args(["requirements.txt", "--format", "yaml"])
    assert exit_info.value.code == 2


def test_the_defaults_are_console_and_the_resolver_depth() -> None:
    args = build_parser().parse_args(["requirements.txt"])
    assert args.format == "console"
    assert args.output is None


def test_a_scan_reports_direct_and_transitive_counts(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], offline: None
) -> None:
    path = manifest(tmp_path, "flask==1.0\n")

    assert main([str(path)]) == EXIT_OK

    captured = capsys.readouterr()
    assert "1 requirements" in captured.out
    assert "2 packages resolved (1 direct, 1 transitive)" in captured.out  # click is transitive
    assert "no known vulnerabilities" in captured.out


def test_skipped_lines_are_counted(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], offline: None
) -> None:
    path = manifest(tmp_path, "flask==1.0\n-e .\n--index-url https://example.com\n")

    main([str(path)])

    assert "2 lines skipped" in capsys.readouterr().out


def test_a_package_that_cannot_be_resolved_is_named_with_its_reason(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], offline: None
) -> None:
    path = manifest(tmp_path, "flask==1.0\nnot-a-real-package==1.0\n")

    assert main([str(path)]) == EXIT_OK

    out = capsys.readouterr().out
    assert "could not resolve 1:" in out
    assert "not-a-real-package: no such package on PyPI" in out


def test_the_counts_exclude_packages_that_failed_to_resolve(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], offline: None
) -> None:
    """direct + transitive must equal the total, and match the list printed.

    A failed direct dependency is still a root, so counting roots reported it
    as direct while the listing below left it out.
    """
    path = manifest(tmp_path, "flask==1.0\nnot-a-real-package==1.0\n")

    main([str(path)])

    out = capsys.readouterr().out
    assert "2 packages resolved (1 direct, 1 transitive)" in out


def test_an_empty_manifest_scans_cleanly(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], offline: None
) -> None:
    path = manifest(tmp_path, "# nothing here\n\n")

    assert main([str(path)]) == EXIT_OK
    assert "0 packages" in capsys.readouterr().out


# --- output that other tools can consume -----------------------------------


def test_json_output_is_the_only_thing_on_stdout(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], offline: None
) -> None:
    """`scanner --format json | jq` has to work, so progress goes to stderr."""
    path = manifest(tmp_path, "flask==1.0\n")

    main([str(path), "--format", "json"])

    captured = capsys.readouterr()
    report = json.loads(captured.out)
    assert report["summary"]["total_packages"] == 2
    assert "resolving" in captured.err


def test_progress_is_reported_on_stderr(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], offline: None
) -> None:
    path = manifest(tmp_path, "flask==1.0\n")

    main([str(path)])

    err = capsys.readouterr().err
    assert "resolving" in err
    assert "checking 2 packages" in err


def test_the_json_file_written_with_output_is_the_same_report(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], offline: None
) -> None:
    path = manifest(tmp_path, "flask==1.0\n")
    destination = tmp_path / "report.json"

    main([str(path), "--format", "json", "--output", str(destination)])

    assert json.loads(destination.read_text()) == json.loads(capsys.readouterr().out)


# --- the optional extras ---------------------------------------------------


def test_ignored_rules_are_recorded_in_the_report(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], offline: None
) -> None:
    path = manifest(tmp_path, "flask==1.0\n")

    main([str(path), "--format", "json", "--ignore", "CVE-2025-1", "--ignore", "GHSA-x"])

    report = json.loads(capsys.readouterr().out)
    assert report["ignored"]["rules"] == ["CVE-2025-1", "GHSA-x"]


def test_stale_packages_are_flagged_when_a_threshold_is_given(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], offline: None
) -> None:
    """FakeClient reports every package as last published long ago."""
    path = manifest(tmp_path, "flask==1.0\n")

    main([str(path), "--format", "json", "--stale-after", "365"])

    report = json.loads(capsys.readouterr().out)
    assert {item["package"] for item in report["unmaintained"]} == {"flask", "click"}


def test_nothing_is_flagged_as_stale_without_the_flag(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], offline: None
) -> None:
    path = manifest(tmp_path, "flask==1.0\n")

    main([str(path), "--format", "json"])

    assert json.loads(capsys.readouterr().out)["unmaintained"] == []


def test_a_vulnerable_scan_exits_non_zero(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, offline: None
) -> None:
    """So a CI job fails on a vulnerable dependency."""

    class FindsSomething:
        def query(self, packages) -> QueryResult:
            return QueryResult({packages[0]: [_finding_for_test()]})

    monkeypatch.setattr("scanner.cli.OSVClient", FindsSomething)
    path = manifest(tmp_path, "flask==1.0\n")

    assert main([str(path)]) == EXIT_VULNERABILITIES_FOUND


def _finding_for_test() -> Vulnerability:
    return Vulnerability(
        id="GHSA-x",
        aliases={"CVE-2025-1"},
        fixed_versions=["2.0"],
        source=Source.OSV,
        severity="HIGH",
        summary="bad",
        url="https://example.com",
    )


def test_hiding_findings_does_not_weaken_the_exit_code(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, offline: None
) -> None:
    """--min-severity is a display choice. If it could turn a failing build
    green, anyone could silence CI by passing a flag."""

    class FindsHigh:
        def query(self, packages) -> QueryResult:
            return QueryResult({packages[0]: [_finding_for_test()]})

    monkeypatch.setattr("scanner.cli.OSVClient", FindsHigh)
    path = manifest(tmp_path, "flask==1.0\n")

    assert main([str(path), "--min-severity", "CRITICAL"]) == EXIT_VULNERABILITIES_FOUND


def test_ignoring_a_finding_does_clear_the_exit_code(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, offline: None
) -> None:
    """Unlike hiding, ignoring is a decision that the finding does not count."""

    class FindsHigh:
        def query(self, packages) -> QueryResult:
            return QueryResult({packages[0]: [_finding_for_test()]})

    monkeypatch.setattr("scanner.cli.OSVClient", FindsHigh)
    path = manifest(tmp_path, "flask==1.0\n")

    assert main([str(path), "--ignore", "CVE-2025-1"]) == EXIT_OK
