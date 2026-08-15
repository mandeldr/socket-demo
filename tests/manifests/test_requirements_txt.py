"""Tests for manifest parsing.

Written before the implementation: these describe what the parser is supposed
to do with every line shape that shows up in a real requirements file.
"""

from pathlib import Path

import pytest

from scanner.enums import SkipReason
from scanner.manifests import requirements_txt


def write(tmp_path: Path, content: str, name: str = "requirements.txt") -> Path:
    path = tmp_path / name
    path.write_text(content)
    return path


def names(result) -> list[str]:
    return [d.name for d in result.dependencies]


# the basics


def test_empty_file_yields_nothing(tmp_path: Path) -> None:
    result = requirements_txt.parse(write(tmp_path, ""))
    assert result.dependencies == []
    assert result.skipped == []


def test_blank_lines_and_comments_are_ignored(tmp_path: Path) -> None:
    result = requirements_txt.parse(write(tmp_path, "# a comment\n\n   \n# another\n"))
    assert result.dependencies == []
    assert result.skipped == []  # comments are not "skipped lines", they are noise


def test_single_pinned_requirement(tmp_path: Path) -> None:
    result = requirements_txt.parse(write(tmp_path, "flask==3.0.0\n"))
    (dep,) = result.dependencies
    assert dep.name == "flask"


def test_raw_spec_is_preserved(tmp_path: Path) -> None:
    """The original constraint is kept even when we cannot pin a version."""
    result = requirements_txt.parse(write(tmp_path, "pandas>=2.0.0,<3.0.0\n"))
    (dep,) = result.dependencies
    assert "2.0.0" in dep.raw_spec
    assert "3.0.0" in dep.raw_spec


# versions


def test_range_has_no_pinned_version(tmp_path: Path) -> None:
    result = requirements_txt.parse(write(tmp_path, "pandas>=2.0.0,<3.0.0\n"))
    (dep,) = result.dependencies


def test_unpinned_package_has_no_version(tmp_path: Path) -> None:
    """`pyyaml` with no specifier cannot be queried until it is resolved."""
    result = requirements_txt.parse(write(tmp_path, "pyyaml\n"))
    (dep,) = result.dependencies
    assert dep.name == "pyyaml"


def test_compatible_release_operator_is_not_a_pin(tmp_path: Path) -> None:
    result = requirements_txt.parse(write(tmp_path, "click~=8.1.7\n"))
    (dep,) = result.dependencies


# names


def test_names_are_canonicalized(tmp_path: Path) -> None:
    content = "Flask==3.0.0\nzope.interface==6.1\nmy_package==1.0.0\n"
    result = requirements_txt.parse(write(tmp_path, content))
    assert names(result) == ["flask", "zope-interface", "my-package"]


def test_extras_are_stripped_from_the_name(tmp_path: Path) -> None:
    result = requirements_txt.parse(write(tmp_path, "requests[security]==2.31.0\n"))
    (dep,) = result.dependencies
    assert dep.name == "requests"


def test_multiple_extras(tmp_path: Path) -> None:
    result = requirements_txt.parse(write(tmp_path, "celery[redis,auth]==5.3.6\n"))
    (dep,) = result.dependencies
    assert dep.name == "celery"


# whitespace, comments, continuations


def test_leading_and_trailing_whitespace(tmp_path: Path) -> None:
    result = requirements_txt.parse(write(tmp_path, "   flask==3.0.0   \n"))
    (dep,) = result.dependencies
    assert dep.name == "flask"


def test_trailing_comment_is_removed(tmp_path: Path) -> None:
    content = "cryptography==42.0.1  # pinned for FIPS\n"
    result = requirements_txt.parse(write(tmp_path, content))
    (dep,) = result.dependencies


def test_spaces_around_operator(tmp_path: Path) -> None:
    result = requirements_txt.parse(write(tmp_path, "packaging  ==  23.2\n"))
    (dep,) = result.dependencies
    assert dep.name == "packaging"


# environment markers


def test_markers_are_kept_not_evaluated(tmp_path: Path) -> None:
    """A scanner should over-report rather than miss something.

    We include requirements whose marker does not apply to the current
    interpreter, because the manifest may well be installed elsewhere.
    """
    content = 'pywin32==306 ; sys_platform == "win32"\n'
    result = requirements_txt.parse(write(tmp_path, content))
    (dep,) = result.dependencies
    assert dep.name == "pywin32"


# lines that are not requirements


@pytest.mark.parametrize(
    ("line", "reason"),
    [
        ("--index-url https://pypi.org/simple", SkipReason.PIP_OPTION),
        ("--extra-index-url https://example.com/s", SkipReason.PIP_OPTION),
        ("--find-links ./wheels", SkipReason.PIP_OPTION),
        ("-c constraints.txt", SkipReason.PIP_OPTION),
        ("-r base.txt", SkipReason.PIP_OPTION),
        ("-e .", SkipReason.EDITABLE),
        ("-e ./local-package", SkipReason.EDITABLE),
        ("-e git+https://github.com/psf/requests.git#egg=requests", SkipReason.EDITABLE),
        ("git+https://github.com/pallets/flask.git@3.0.0#egg=flask", SkipReason.VCS),
        ("https://example.com/pkg-1.0.0-py3-none-any.whl", SkipReason.DIRECT_URL),
        ("file:///opt/wheels/internal-1.0.0.whl", SkipReason.DIRECT_URL),
    ],
)
def test_non_requirement_lines_are_skipped_with_a_reason(
    tmp_path: Path, line: str, reason: SkipReason
) -> None:
    result = requirements_txt.parse(write(tmp_path, line + "\n"))
    assert result.dependencies == []
    (skipped,) = result.skipped
    assert skipped.reason is reason
    assert skipped.content == line


def test_skipped_lines_record_their_line_number(tmp_path: Path) -> None:
    content = "flask==3.0.0\n-e .\n"
    result = requirements_txt.parse(write(tmp_path, content))
    (skipped,) = result.skipped
    assert skipped.line_number == 2


def test_unparseable_line_is_skipped_not_fatal(tmp_path: Path) -> None:
    content = "flask==3.0.0\n=====\ndjango==5.0.1\n"
    result = requirements_txt.parse(write(tmp_path, content))
    assert names(result) == ["flask", "django"]
    (skipped,) = result.skipped
    assert skipped.reason is SkipReason.INVALID


def test_a_hash_inside_a_url_is_not_treated_as_a_comment(tmp_path: Path) -> None:
    """`#egg=` fragments must survive comment stripping."""
    line = "git+https://github.com/pallets/flask.git@3.0.0#egg=flask"
    result = requirements_txt.parse(write(tmp_path, line + "\n"))
    (skipped,) = result.skipped
    assert skipped.content == line  # not truncated at the '#'


# the fixtures on disk

FIXTURES = Path(__file__).parent.parent / "fixtures"


def test_clean_fixture_parses_without_skips() -> None:
    result = requirements_txt.parse(FIXTURES / "requirements.txt")
    assert result.dependencies
    assert result.skipped == []


def test_hostile_fixture_does_not_crash() -> None:
    result = requirements_txt.parse(FIXTURES / "hostile.txt")
    assert result.dependencies  # some lines are real requirements
    assert result.skipped  # and plenty are not


# --- line continuations ----------------------------------------------------


def test_a_backslash_continuation_is_one_requirement(tmp_path: Path) -> None:
    """pip-compile and `pip freeze --require-hashes` write every pin this way,
    so a scanner that cannot read them cannot read the most careful manifests."""
    manifest = tmp_path / "requirements.txt"
    manifest.write_text(
        "flask==3.0.0 \\\n"
        "    --hash=sha256:cfadcdb638b609361d29ec22360d6070a77d7463dcb3ab08d2c2f2 \\\n"
        "    --hash=sha256:99c2b1b0f9f0e37e5e8b9b1b1e0fb4d5b8e6c8e0d0e1f2a3b4c5d6\n"
    )

    result = requirements_txt.parse(manifest)

    assert [d.name for d in result.dependencies] == ["flask"]
    assert result.skipped == []


def test_a_continued_line_is_reported_at_its_first_line(tmp_path: Path) -> None:
    manifest = tmp_path / "requirements.txt"
    manifest.write_text("flask==3.0.0\n!!!broken!!! \\\n    keeps going\n")

    result = requirements_txt.parse(manifest)

    (skipped,) = result.skipped
    assert skipped.line_number == 2


def test_several_continued_requirements_in_a_row(tmp_path: Path) -> None:
    manifest = tmp_path / "requirements.txt"
    manifest.write_text(
        "flask==3.0.0 \\\n    --hash=sha256:aaa\nrequests==2.31.0 \\\n    --hash=sha256:bbb\n"
    )

    result = requirements_txt.parse(manifest)

    assert [d.name for d in result.dependencies] == ["flask", "requests"]


def test_a_trailing_backslash_at_the_end_of_the_file(tmp_path: Path) -> None:
    """Malformed, but it should not take the scan down."""
    manifest = tmp_path / "requirements.txt"
    manifest.write_text("flask==3.0.0 \\\n")

    assert [d.name for d in requirements_txt.parse(manifest).dependencies] == ["flask"]


def test_a_backslash_inside_a_line_is_not_a_continuation(tmp_path: Path) -> None:
    manifest = tmp_path / "requirements.txt"
    manifest.write_text("flask==3.0.0\nrequests==2.31.0\n")

    assert len(requirements_txt.parse(manifest).dependencies) == 2


def test_a_continuation_still_has_its_comment_stripped(tmp_path: Path) -> None:
    manifest = tmp_path / "requirements.txt"
    manifest.write_text("flask==3.0.0 \\\n    --hash=sha256:aaa  # pinned by security\n")

    result = requirements_txt.parse(manifest)

    assert [d.name for d in result.dependencies] == ["flask"]


def test_per_requirement_options_are_stripped(tmp_path: Path) -> None:
    """`--hash` and friends belong to the requirement but are not part of it."""
    manifest = tmp_path / "requirements.txt"
    manifest.write_text("flask==3.0.0 --hash=sha256:aaa --hash=sha256:bbb\n")

    assert [d.name for d in requirements_txt.parse(manifest).dependencies] == ["flask"]


def test_a_line_that_is_only_a_pip_option_is_still_skipped(tmp_path: Path) -> None:
    """Stripping options must not turn `--index-url ...` into an empty line."""
    manifest = tmp_path / "requirements.txt"
    manifest.write_text("--index-url https://example.com/simple\n")

    result = requirements_txt.parse(manifest)

    assert result.dependencies == []
    assert [s.reason for s in result.skipped] == [SkipReason.PIP_OPTION]


def test_a_marker_survives_option_stripping(tmp_path: Path) -> None:
    manifest = tmp_path / "requirements.txt"
    manifest.write_text('tomli==2.0.1 ; python_version < "3.11" --hash=sha256:aaa\n')

    assert [d.name for d in requirements_txt.parse(manifest).dependencies] == ["tomli"]


# --- extras ----------------------------------------------------------------


def test_a_requested_extra_is_kept(tmp_path: Path) -> None:
    """`celery[redis]` installs redis. Dropping the extra makes it invisible."""
    manifest = tmp_path / "requirements.txt"
    manifest.write_text("celery[redis]==5.3.6\n")

    (dep,) = requirements_txt.parse(manifest).dependencies

    assert dep.name == "celery"
    assert dep.extras == frozenset({"redis"})


def test_several_extras_are_all_kept(tmp_path: Path) -> None:
    manifest = tmp_path / "requirements.txt"
    manifest.write_text("celery[redis,auth]==5.3.6\n")

    (dep,) = requirements_txt.parse(manifest).dependencies

    assert dep.extras == frozenset({"redis", "auth"})


def test_no_extras_is_an_empty_set(tmp_path: Path) -> None:
    manifest = tmp_path / "requirements.txt"
    manifest.write_text("celery==5.3.6\n")

    assert requirements_txt.parse(manifest).dependencies[0].extras == frozenset()
