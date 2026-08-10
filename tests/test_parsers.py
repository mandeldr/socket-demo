"""Tests for manifest parsing.

Written before the implementation: these describe what the parser is supposed
to do with every line shape that shows up in a real requirements file.
"""

from pathlib import Path

import pytest

from scanner.models import EcoSystem, SkipReason
from scanner.parsers import parse_requirements_txt


def write(tmp_path: Path, content: str, name: str = "requirements.txt") -> Path:
    path = tmp_path / name
    path.write_text(content)
    return path


def names(result) -> list[str]:
    return [d.key.name for d in result.dependencies]


# the basics


def test_empty_file_yields_nothing(tmp_path: Path) -> None:
    result = parse_requirements_txt(write(tmp_path, ""))
    assert result.dependencies == []
    assert result.skipped == []


def test_blank_lines_and_comments_are_ignored(tmp_path: Path) -> None:
    result = parse_requirements_txt(
        write(tmp_path, "# a comment\n\n   \n# another\n")
    )
    assert result.dependencies == []
    assert result.skipped == []  # comments are not "skipped lines", they are noise


def test_single_pinned_requirement(tmp_path: Path) -> None:
    result = parse_requirements_txt(write(tmp_path, "flask==3.0.0\n"))
    (dep,) = result.dependencies
    assert dep.key.name == "flask"
    assert dep.key.version == "3.0.0"
    assert dep.key.eco_system is EcoSystem.PYTHON


def test_every_manifest_entry_is_direct_at_depth_zero(tmp_path: Path) -> None:
    result = parse_requirements_txt(write(tmp_path, "flask==3.0.0\n"))
    (dep,) = result.dependencies
    assert dep.is_direct is True
    assert dep.depth == 0
    assert dep.parent is None


def test_raw_spec_is_preserved(tmp_path: Path) -> None:
    """The original constraint is kept even when we cannot pin a version."""
    result = parse_requirements_txt(write(tmp_path, "pandas>=2.0.0,<3.0.0\n"))
    (dep,) = result.dependencies
    assert "2.0.0" in dep.raw_spec
    assert "3.0.0" in dep.raw_spec


# versions


def test_range_has_no_pinned_version(tmp_path: Path) -> None:
    result = parse_requirements_txt(write(tmp_path, "pandas>=2.0.0,<3.0.0\n"))
    (dep,) = result.dependencies
    assert dep.key.version is None


def test_unpinned_package_has_no_version(tmp_path: Path) -> None:
    """`pyyaml` with no specifier cannot be queried until it is resolved."""
    result = parse_requirements_txt(write(tmp_path, "pyyaml\n"))
    (dep,) = result.dependencies
    assert dep.key.name == "pyyaml"
    assert dep.key.version is None


def test_compatible_release_operator_is_not_a_pin(tmp_path: Path) -> None:
    result = parse_requirements_txt(write(tmp_path, "click~=8.1.7\n"))
    (dep,) = result.dependencies
    assert dep.key.version is None


# names


def test_names_are_canonicalized(tmp_path: Path) -> None:
    content = "Flask==3.0.0\nzope.interface==6.1\nmy_package==1.0.0\n"
    result = parse_requirements_txt(write(tmp_path, content))
    assert names(result) == ["flask", "zope-interface", "my-package"]


def test_extras_are_stripped_from_the_name(tmp_path: Path) -> None:
    result = parse_requirements_txt(write(tmp_path, "requests[security]==2.31.0\n"))
    (dep,) = result.dependencies
    assert dep.key.name == "requests"


def test_multiple_extras(tmp_path: Path) -> None:
    result = parse_requirements_txt(write(tmp_path, "celery[redis,auth]==5.3.6\n"))
    (dep,) = result.dependencies
    assert dep.key.name == "celery"
    assert dep.key.version == "5.3.6"


# whitespace, comments, continuations


def test_leading_and_trailing_whitespace(tmp_path: Path) -> None:
    result = parse_requirements_txt(write(tmp_path, "   flask==3.0.0   \n"))
    (dep,) = result.dependencies
    assert dep.key.name == "flask"


def test_trailing_comment_is_removed(tmp_path: Path) -> None:
    content = "cryptography==42.0.1  # pinned for FIPS\n"
    result = parse_requirements_txt(write(tmp_path, content))
    (dep,) = result.dependencies
    assert dep.key.version == "42.0.1"


def test_spaces_around_operator(tmp_path: Path) -> None:
    result = parse_requirements_txt(write(tmp_path, "packaging  ==  23.2\n"))
    (dep,) = result.dependencies
    assert dep.key.name == "packaging"
    assert dep.key.version == "23.2"



# environment markers


def test_markers_are_kept_not_evaluated(tmp_path: Path) -> None:
    """A scanner should over-report rather than miss something.

    We include requirements whose marker does not apply to the current
    interpreter, because the manifest may well be installed elsewhere.
    """
    content = 'pywin32==306 ; sys_platform == "win32"\n'
    result = parse_requirements_txt(write(tmp_path, content))
    (dep,) = result.dependencies
    assert dep.key.name == "pywin32"


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
    result = parse_requirements_txt(write(tmp_path, line + "\n"))
    assert result.dependencies == []
    (skipped,) = result.skipped
    assert skipped.reason is reason
    assert skipped.content == line


def test_skipped_lines_record_their_line_number(tmp_path: Path) -> None:
    content = "flask==3.0.0\n-e .\n"
    result = parse_requirements_txt(write(tmp_path, content))
    (skipped,) = result.skipped
    assert skipped.line_number == 2


def test_unparseable_line_is_skipped_not_fatal(tmp_path: Path) -> None:
    content = "flask==3.0.0\n=====\ndjango==5.0.1\n"
    result = parse_requirements_txt(write(tmp_path, content))
    assert names(result) == ["flask", "django"]
    (skipped,) = result.skipped
    assert skipped.reason is SkipReason.INVALID


def test_a_hash_inside_a_url_is_not_treated_as_a_comment(tmp_path: Path) -> None:
    """`#egg=` fragments must survive comment stripping."""
    line = "git+https://github.com/pallets/flask.git@3.0.0#egg=flask"
    result = parse_requirements_txt(write(tmp_path, line + "\n"))
    (skipped,) = result.skipped
    assert skipped.content == line  # not truncated at the '#'






# the fixtures on disk

FIXTURES = Path(__file__).parent / "fixtures"


def test_clean_fixture_parses_without_skips() -> None:
    result = parse_requirements_txt(FIXTURES / "requirements.txt")
    assert result.dependencies
    assert result.skipped == []


def test_hostile_fixture_does_not_crash() -> None:
    result = parse_requirements_txt(FIXTURES / "hostile.txt")
    assert result.dependencies  # some lines are real requirements
    assert result.skipped  # and plenty are not
