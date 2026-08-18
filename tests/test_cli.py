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
from scanner.resolver import PackageMetadata
from scanner.sources import QueryResult

INDEX = {
    "flask": ["click>=8.0"],
    "click": [],
}


class FakeClient:
    """Stands in for PyPIClient. Serves INDEX and knows nothing else."""

    def fetch(self, name: str, spec, extras=frozenset()) -> PackageMetadata:
        if name not in INDEX:
            return PackageMetadata(error="no such package on PyPI")
        return PackageMetadata(
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


# --- choosing a reader -----------------------------------------------------


def npm_project(tmp_path: Path, dependencies: dict, lock_packages: dict) -> Path:
    (tmp_path / "package.json").write_text(
        json.dumps({"name": "x", "version": "1.0.0", "dependencies": dependencies})
    )
    (tmp_path / "package-lock.json").write_text(
        json.dumps(
            {
                "lockfileVersion": 3,
                "packages": {"": {"dependencies": dependencies}, **lock_packages},
            }
        )
    )
    return tmp_path / "package.json"


def test_a_package_json_is_read_as_javascript(
    tmp_path: Path, offline: None, capsys: pytest.CaptureFixture[str]
) -> None:
    """No PyPI lookup happens: the lock already decided every version, so the
    fake client is never asked and would not know these packages anyway."""
    path = npm_project(
        tmp_path,
        {"a": "^1"},
        {
            "node_modules/a": {"version": "1.2.3", "dependencies": {"b": "^2"}},
            "node_modules/b": {"version": "2.0.0"},
        },
    )

    assert main([str(path), "--format", "json"]) == EXIT_OK

    report = json.loads(capsys.readouterr().out)
    assert report["summary"]["total_packages"] == 2
    assert report["summary"]["direct"] == 1
    assert report["summary"]["transitive"] == 1


def test_a_lock_file_can_be_given_instead(
    tmp_path: Path, offline: None, capsys: pytest.CaptureFixture[str]
) -> None:
    npm_project(tmp_path, {"a": "^1"}, {"node_modules/a": {"version": "1.2.3"}})

    assert main([str(tmp_path / "package-lock.json"), "--format", "json"]) == EXIT_OK

    assert json.loads(capsys.readouterr().out)["summary"]["total_packages"] == 1


def test_a_requirements_file_is_still_read_as_python(
    tmp_path: Path, offline: None, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main([str(manifest(tmp_path, "flask\n")), "--format", "json"]) == EXIT_OK

    report = json.loads(capsys.readouterr().out)
    assert report["summary"]["total_packages"] == 2  # flask -> click


def test_an_unreadable_manifest_is_a_usage_error(
    tmp_path: Path, offline: None, capsys: pytest.CaptureFixture[str]
) -> None:
    """A package.json with no lock beside it. The message has to carry the fix."""
    path = tmp_path / "package.json"
    path.write_text('{"name": "x", "dependencies": {"a": "^1"}}')

    assert main([str(path)]) == EXIT_USAGE_ERROR

    assert "npm install --package-lock-only" in capsys.readouterr().err


def test_an_unsupported_lock_file_says_what_is_supported(
    tmp_path: Path, offline: None, capsys: pytest.CaptureFixture[str]
) -> None:
    """pnpm is common enough that falling through to "not a requirements file"
    would be a confusing way to say no."""
    path = tmp_path / "pnpm-lock.yaml"
    path.write_text("lockfileVersion: '9.0'\n")

    assert main([str(path)]) == EXIT_USAGE_ERROR

    error = capsys.readouterr().err
    assert "pnpm-lock.yaml" in error
    assert "package-lock.json" in error


# --- formats that must never be read as a requirements file ----------------
#
# The requirements reader accepts a bare name with no version, so an entire
# manifest of some other format parses as either nothing or as garbage. Both
# end in exit 0 and "no known vulnerabilities", which is a scanner reporting
# clean on a project it never looked at.


@pytest.mark.parametrize(
    ("filename", "contents"),
    [
        ("poetry.lock", '[[package]]\nname = "flask"\nversion = "3.0.0"\n'),
        ("Pipfile.lock", '{"default": {"flask": {"version": "==3.0.0"}}}'),
        ("go.mod", "module example.com/x\n\ngo 1.22\n\nrequire (\n\tx/y v1.2.3\n)\n"),
        ("Gemfile.lock", "GEM\n  specs:\n    rails (7.0.4)\n\nDEPENDENCIES\n  rails\n"),
        ("Cargo.lock", '[[package]]\nname = "serde"\nversion = "1.0"\n'),
    ],
)
def test_another_ecosystems_manifest_is_refused_not_scanned_as_empty(
    tmp_path: Path,
    offline: None,
    capsys: pytest.CaptureFixture[str],
    filename: str,
    contents: str,
) -> None:
    path = tmp_path / filename
    path.write_text(contents)

    assert main([str(path)]) == EXIT_USAGE_ERROR

    captured = capsys.readouterr()
    assert filename in captured.err
    # The dangerous output, which is what this test exists to prevent.
    assert "no known vulnerabilities" not in captured.out


def test_a_poetry_lock_names_the_export_command(
    tmp_path: Path, offline: None, capsys: pytest.CaptureFixture[str]
) -> None:
    """Every other error in the tool names the next thing to type."""
    path = tmp_path / "poetry.lock"
    path.write_text('[[package]]\nname = "flask"\n')

    main([str(path)])

    assert "poetry export" in capsys.readouterr().err


def test_an_unrecognised_filename_is_refused_rather_than_guessed_at(
    tmp_path: Path, offline: None, capsys: pytest.CaptureFixture[str]
) -> None:
    """The catch-all. A format nobody has thought of yet must not be read as
    Python just because it is not on a list."""
    path = tmp_path / "deps.yaml"
    path.write_text("dependencies:\n  - flask\n")

    assert main([str(path)]) == EXIT_USAGE_ERROR
    assert "deps.yaml" in capsys.readouterr().err


@pytest.mark.parametrize(
    "filename", ["requirements.txt", "requirements-dev.txt", "constraints.txt", "prod.txt"]
)
def test_any_txt_file_is_read_as_requirements(
    tmp_path: Path, offline: None, capsys: pytest.CaptureFixture[str], filename: str
) -> None:
    """pip has no fixed name for these, so the extension is what we go on.
    Refusing an unusually named requirements file would be worse than reading
    one, because the tool would be turning away work it can actually do."""
    path = tmp_path / filename
    path.write_text("flask==1.0\n")

    assert main([str(path), "--format", "json"]) == EXIT_OK
    assert json.loads(capsys.readouterr().out)["summary"]["total_packages"] == 2


def test_stale_after_says_a_lock_file_carries_no_dates(
    tmp_path: Path, offline: None, capsys: pytest.CaptureFixture[str]
) -> None:
    """The flag would otherwise report zero stale packages, which reads as
    "none found" when it means "never looked"."""
    path = npm_project(tmp_path, {"a": "^1"}, {"node_modules/a": {"version": "1.2.3"}})

    assert main([str(path), "--stale-after", "365", "--format", "json"]) == EXIT_OK

    assert "no release dates" in capsys.readouterr().err


def yarn_project(tmp_path: Path, dependencies: dict, lock: str) -> Path:
    (tmp_path / "package.json").write_text(
        json.dumps({"name": "x", "version": "1.0.0", "dependencies": dependencies})
    )
    (tmp_path / "yarn.lock").write_text(lock)
    return tmp_path / "package.json"


def test_a_package_json_with_a_yarn_lock_is_read(
    tmp_path: Path, offline: None, capsys: pytest.CaptureFixture[str]
) -> None:
    path = yarn_project(tmp_path, {"ms": "2.0.0"}, 'ms@2.0.0:\n  version "2.0.0"\n')

    assert main([str(path), "--format", "json"]) == EXIT_OK

    assert json.loads(capsys.readouterr().out)["summary"]["total_packages"] == 1


def test_a_yarn_lock_can_be_given_instead(
    tmp_path: Path, offline: None, capsys: pytest.CaptureFixture[str]
) -> None:
    yarn_project(tmp_path, {"ms": "2.0.0"}, 'ms@2.0.0:\n  version "2.0.0"\n')

    assert main([str(tmp_path / "yarn.lock"), "--format", "json"]) == EXIT_OK

    assert json.loads(capsys.readouterr().out)["summary"]["total_packages"] == 1


def test_npms_lock_wins_when_a_project_has_both(
    tmp_path: Path, offline: None, capsys: pytest.CaptureFixture[str]
) -> None:
    """Which is what npm itself does. The two locks here disagree on purpose,
    so the count says which one was read."""
    yarn_project(tmp_path, {"ms": "2.0.0"}, 'ms@2.0.0:\n  version "2.0.0"\n')
    (tmp_path / "package-lock.json").write_text(
        json.dumps(
            {
                "lockfileVersion": 3,
                "packages": {
                    "": {"dependencies": {"ms": "2.0.0"}},
                    "node_modules/ms": {"version": "2.0.0", "dependencies": {"extra": "1"}},
                    "node_modules/extra": {"version": "1.0.0"},
                },
            }
        )
    )

    assert main([str(tmp_path / "package.json"), "--format", "json"]) == EXIT_OK

    assert json.loads(capsys.readouterr().out)["summary"]["total_packages"] == 2


def test_an_unwritable_output_path_is_a_usage_error(
    tmp_path: Path, offline: None, capsys: pytest.CaptureFixture[str]
) -> None:
    """An unguarded write here exits 1, which is the code for "vulnerable
    dependency found" - so a CI job fails a clean project and blames the
    dependencies. Every other error path returns 2."""
    manifest_path = manifest(tmp_path, "")

    code = main([str(manifest_path), "--output", str(tmp_path / "missing" / "out.json")])

    assert code == EXIT_USAGE_ERROR
    assert "could not write" in capsys.readouterr().err


def test_the_report_is_still_printed_when_the_output_file_fails(
    tmp_path: Path, offline: None, capsys: pytest.CaptureFixture[str]
) -> None:
    """The scan succeeded; only the copy failed."""
    manifest_path = manifest(tmp_path, "flask\n")

    main([str(manifest_path), "--format", "json", "--output", str(tmp_path / "no" / "x.json")])

    captured = capsys.readouterr()
    assert json.loads(captured.out)["summary"]["total_packages"] == 2
