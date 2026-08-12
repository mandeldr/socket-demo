"""Tests for the command line entry point.

main() returns an exit code instead of calling sys.exit(), so these call it
directly. The PyPI client is swapped for a fake, which also makes these the
only tests that exercise parse -> resolve -> print end to end.
"""

from pathlib import Path

import pytest
from packaging.requirements import Requirement

from scanner.cli import EXIT_OK, EXIT_USAGE_ERROR, build_parser, main
from scanner.resolver import DEFAULT_MAX_DEPTH, FetchResult

INDEX = {
    "flask": ["click>=8.0"],
    "click": [],
}


class FakeClient:
    """Stands in for PyPIClient. Serves INDEX and knows nothing else."""

    def fetch(self, name: str, spec) -> FetchResult:
        if name not in INDEX:
            return FetchResult(error="no such package on PyPI")
        return FetchResult("1.0", [Requirement(r) for r in INDEX[name]])


@pytest.fixture
def offline(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("scanner.cli.PyPIClient", FakeClient)


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
    assert args.max_depth == DEFAULT_MAX_DEPTH
    assert args.output is None


def test_max_depth_is_read_as_a_number() -> None:
    assert build_parser().parse_args(["requirements.txt", "--max-depth", "2"]).max_depth == 2


def test_a_scan_reports_direct_and_transitive_counts(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], offline: None
) -> None:
    path = manifest(tmp_path, "flask==1.0\n")

    assert main([str(path)]) == EXIT_OK

    out = capsys.readouterr().out
    assert "1 direct dependencies" in out
    assert "2 packages (1 direct, 1 transitive)" in out
    assert "click" in out  # pulled in transitively, not listed in the manifest


def test_skipped_lines_are_counted(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], offline: None
) -> None:
    path = manifest(tmp_path, "flask==1.0\n-e .\n--index-url https://example.com\n")

    main([str(path)])

    assert "(2 lines skipped)" in capsys.readouterr().out


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
    assert "2 packages (1 direct, 1 transitive)" in out


def test_max_depth_stops_the_walk(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], offline: None
) -> None:
    """At depth 0 the direct dependency resolves but its children are not followed."""
    path = manifest(tmp_path, "flask==1.0\n")

    main([str(path), "--max-depth", "0"])

    out = capsys.readouterr().out
    assert "1 packages (1 direct, 0 transitive)" in out
    assert "click" not in out


def test_an_empty_manifest_scans_cleanly(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], offline: None
) -> None:
    path = manifest(tmp_path, "# nothing here\n\n")

    assert main([str(path)]) == EXIT_OK
    assert "0 packages" in capsys.readouterr().out
