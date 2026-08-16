"""Tests for the PyPI metadata client.

The client takes a session, so these run against a fake one rather than the
network. Same idea as passing `fetch` into the resolver.
"""

import pytest
from packaging.specifiers import SpecifierSet

from scanner.pypi import NOT_ON_PYPI, PyPIClient


class FakeResponse:
    def __init__(self, payload: dict | None, status_code: int = 200) -> None:
        self.status_code = status_code
        self._payload = payload

    def json(self) -> dict:
        if self._payload is None:
            raise ValueError("no json")
        return self._payload


class FakeSession:
    """Serves canned payloads and counts requests."""

    def __init__(self, pages: dict[str, FakeResponse]) -> None:
        self.pages = pages
        self.calls: list[str] = []

    def get(self, url: str, timeout: float = 0) -> FakeResponse:
        self.calls.append(url)
        return self.pages.get(url, FakeResponse(None, status_code=404))


def package_page(version: str, requires: list[str] | None, releases: list[str]) -> FakeResponse:
    return FakeResponse(
        {
            "info": {"version": version, "requires_dist": requires},
            "releases": dict.fromkeys(releases, []),
        }
    )


def client_for(pages: dict[str, FakeResponse]) -> tuple[PyPIClient, FakeSession]:
    session = FakeSession(pages)
    return PyPIClient(session=session), session


def test_returns_the_latest_version_and_its_requirements() -> None:
    client, _ = client_for(
        {
            "https://pypi.org/pypi/flask/json": package_page(
                "3.0.0", ["Werkzeug>=3.0.0", "Jinja2>=3.1.2"], ["2.0.0", "3.0.0"]
            )
        }
    )
    result = client.fetch("flask", SpecifierSet())
    assert result.ok
    assert result.version == "3.0.0"
    assert [r.name for r in result.requirements] == ["Werkzeug", "Jinja2"]


def test_requires_dist_of_none_means_no_dependencies() -> None:
    """Packages with no dependencies omit the field entirely (e.g. certifi)."""
    client, _ = client_for(
        {"https://pypi.org/pypi/certifi/json": package_page("2024.2.2", None, ["2024.2.2"])}
    )
    result = client.fetch("certifi", SpecifierSet())
    assert result.version == "2024.2.2"
    assert result.requirements == []


def test_unknown_package_says_it_does_not_exist() -> None:
    client, _ = client_for({})
    result = client.fetch("does-not-exist", SpecifierSet())
    assert not result.ok
    assert result.error == NOT_ON_PYPI


def test_a_pinned_version_is_used_directly() -> None:
    client, session = client_for(
        {
            "https://pypi.org/pypi/flask/json": package_page(
                "3.0.0", [], ["2.0.0", "2.3.0", "3.0.0"]
            ),
            "https://pypi.org/pypi/flask/2.3.0/json": package_page("2.3.0", ["click>=8.0"], []),
        }
    )
    result = client.fetch("flask", SpecifierSet("==2.3.0"))
    assert result.version == "2.3.0"
    assert [r.name for r in result.requirements] == ["click"]


def test_a_range_picks_the_highest_matching_release() -> None:
    client, _ = client_for(
        {
            "https://pypi.org/pypi/flask/json": package_page(
                "3.0.0", [], ["1.0.0", "2.0.0", "2.3.0", "3.0.0"]
            ),
            "https://pypi.org/pypi/flask/2.3.0/json": package_page("2.3.0", [], []),
        }
    )
    result = client.fetch("flask", SpecifierSet(">=2.0,<3.0"))
    assert result.version == "2.3.0"


def test_no_release_satisfies_the_constraint() -> None:
    """The package exists; the pin does not. Different problem, different message."""
    client, _ = client_for(
        {"https://pypi.org/pypi/flask/json": package_page("3.0.0", [], ["3.0.0"])}
    )
    result = client.fetch("flask", SpecifierSet("<2.0"))
    assert not result.ok
    assert result.error == "no release satisfies <2.0 (latest is 3.0.0)"
    assert result.error != NOT_ON_PYPI


def test_the_latest_release_is_not_refetched() -> None:
    """If the constraint allows the latest, its metadata is already in hand."""
    client, session = client_for(
        {"https://pypi.org/pypi/flask/json": package_page("3.0.0", [], ["2.0.0", "3.0.0"])}
    )
    client.fetch("flask", SpecifierSet(">=2.0"))
    assert session.calls == ["https://pypi.org/pypi/flask/json"]


def test_a_package_is_only_requested_once() -> None:
    """Diamond dependencies ask for the same package repeatedly."""
    client, session = client_for(
        {"https://pypi.org/pypi/flask/json": package_page("3.0.0", [], ["3.0.0"])}
    )
    client.fetch("flask", SpecifierSet())
    client.fetch("flask", SpecifierSet())
    client.fetch("flask", SpecifierSet())
    assert session.calls.count("https://pypi.org/pypi/flask/json") == 1


def test_names_are_canonicalized_before_lookup() -> None:
    """PEP 503: `Zope.Interface` and `zope-interface` are one project, so the
    request has to go to the canonical URL. Asserting on the return value alone
    is not enough - fetch always returns a PackageMetadata, even for a 404, so
    such a test passes with canonicalization deleted."""
    client, session = client_for(
        {"https://pypi.org/pypi/zope-interface/json": package_page("6.1", [], ["6.1"])}
    )

    result = client.fetch("Zope.Interface", SpecifierSet())

    assert session.calls == ["https://pypi.org/pypi/zope-interface/json"]
    assert result.ok
    assert result.version == "6.1"


def test_a_network_error_returns_none_rather_than_raising() -> None:
    class ExplodingSession:
        def get(self, url: str, timeout: float = 0):
            raise OSError("connection reset")

    client = PyPIClient(session=ExplodingSession())
    result = client.fetch("flask", SpecifierSet())
    assert not result.ok
    assert "could not reach PyPI" in (result.error or "")


def test_malformed_json_is_reported_as_such() -> None:
    client, _ = client_for({"https://pypi.org/pypi/flask/json": FakeResponse(None, 200)})
    result = client.fetch("flask", SpecifierSet())
    assert result.error == "PyPI returned invalid JSON"


def test_an_unparseable_requirement_is_skipped() -> None:
    """One bad entry in requires_dist should not lose the rest."""
    client, _ = client_for(
        {
            "https://pypi.org/pypi/flask/json": package_page(
                "3.0.0", ["click>=8.0", "!!!broken!!!", "jinja2>=3.0"], ["3.0.0"]
            )
        }
    )
    result = client.fetch("flask", SpecifierSet())
    assert [r.name for r in result.requirements] == ["click", "jinja2"]


@pytest.mark.parametrize("status", [500, 502, 503])
def test_a_server_error_names_the_status(status: int) -> None:
    client, _ = client_for(
        {"https://pypi.org/pypi/flask/json": FakeResponse({}, status_code=status)}
    )
    result = client.fetch("flask", SpecifierSet())
    assert result.error == f"PyPI returned HTTP {status}"


def test_optional_extras_are_not_required_dependencies() -> None:
    """`pip install pandas` does not install its test suite."""
    client, _ = client_for(
        {
            "https://pypi.org/pypi/pandas/json": package_page(
                "2.3.3",
                [
                    "numpy>=1.22.4",
                    "python-dateutil>=2.8.2",
                    'pytest>=7.3.2; extra == "test"',
                    'sphinx; extra == "docs"',
                    "hypothesis>=6.46.1; extra == 'test'",
                ],
                ["2.3.3"],
            )
        }
    )
    result = client.fetch("pandas", SpecifierSet())
    assert [r.name for r in result.requirements] == ["numpy", "python-dateutil"]


def test_platform_markers_are_kept() -> None:
    """Unlike extras, these describe where it installs, not whether."""
    client, _ = client_for(
        {
            "https://pypi.org/pypi/thing/json": package_page(
                "1.0",
                ['pywin32; sys_platform == "win32"', 'tomli; python_version < "3.11"'],
                ["1.0"],
            )
        }
    )
    result = client.fetch("thing", SpecifierSet())
    assert [r.name for r in result.requirements] == ["pywin32", "tomli"]


# --- when the project last published anything ------------------------------


def dated_page(version: str, uploads: dict[str, list[str]]) -> FakeResponse:
    """A package page whose releases carry upload times."""
    return FakeResponse(
        {
            "info": {"version": version, "requires_dist": []},
            "releases": {
                release: [{"upload_time_iso_8601": when} for when in times]
                for release, times in uploads.items()
            },
        }
    )


def test_the_newest_upload_time_is_the_last_release() -> None:
    """Not the resolved version's date: the question is when anyone last
    published, which is what tells you a project is abandoned."""
    client, _ = client_for(
        {
            "https://pypi.org/pypi/flask/json": dated_page(
                "3.0.0",
                {
                    "1.0.0": ["2019-01-01T00:00:00.000000Z"],
                    "3.0.0": ["2024-06-15T12:00:00.000000Z", "2024-06-15T12:05:00.000000Z"],
                },
            )
        }
    )

    result = client.fetch("flask", SpecifierSet())

    assert result.last_release is not None
    assert result.last_release.year == 2024
    assert result.last_release.month == 6


def test_a_page_with_no_upload_times_has_no_date() -> None:
    client, _ = client_for(
        {"https://pypi.org/pypi/flask/json": package_page("3.0.0", [], ["3.0.0"])}
    )
    assert client.fetch("flask", SpecifierSet()).last_release is None


def test_an_unreadable_date_is_skipped_rather_than_crashing() -> None:
    client, _ = client_for(
        {
            "https://pypi.org/pypi/flask/json": dated_page(
                "3.0.0", {"3.0.0": ["not a date", "2024-06-15T12:00:00.000000Z"]}
            )
        }
    )
    result = client.fetch("flask", SpecifierSet())
    assert result.last_release is not None
    assert result.last_release.year == 2024


def test_a_release_with_no_files_is_skipped() -> None:
    """Yanked releases can have an empty file list."""
    client, _ = client_for({"https://pypi.org/pypi/flask/json": dated_page("3.0.0", {"3.0.0": []})})
    assert client.fetch("flask", SpecifierSet()).last_release is None


def test_an_impossible_pin_names_the_version_that_does_exist() -> None:
    """The customer thinks the scanner is wrong; really they pinned a version
    that was never published. Saying which one exists answers that directly."""
    client, _ = client_for(
        {"https://pypi.org/pypi/urllib3/json": package_page("2.7.0", [], ["2.6.0", "2.7.0"])}
    )

    result = client.fetch("urllib3", SpecifierSet("==3.0.0"))

    assert result.error == "no release satisfies ==3.0.0 (latest is 2.7.0)"


def test_a_missing_package_still_says_it_does_not_exist() -> None:
    """A package that is not on PyPI has no latest version to name."""
    client, _ = client_for({})
    assert client.fetch("nope", SpecifierSet("==1.0")).error == NOT_ON_PYPI


# --- prereleases -----------------------------------------------------------


def test_the_latest_being_a_prerelease_does_not_make_it_the_answer() -> None:
    """PyPI reports the newest upload, which is sometimes an rc. pip will not
    install it for `flask>=2.0`, so neither should we - reporting CVEs against
    a version the user does not have is worse than reporting nothing."""
    client, _ = client_for(
        {
            "https://pypi.org/pypi/flask/json": package_page(
                "3.0.0rc1", [], ["2.0", "2.3.0", "3.0.0rc1"]
            ),
            "https://pypi.org/pypi/flask/2.3.0/json": package_page("2.3.0", [], []),
        }
    )

    result = client.fetch("flask", SpecifierSet(">=2.0"))

    assert result.version == "2.3.0"


def test_a_prerelease_is_not_picked_out_of_the_release_list_either() -> None:
    """The other path: the latest does not satisfy, so we search the releases."""
    client, _ = client_for(
        {
            "https://pypi.org/pypi/flask/json": package_page("1.0", [], ["1.0", "2.0", "3.0.0rc1"]),
            "https://pypi.org/pypi/flask/2.0/json": package_page("2.0", [], []),
        }
    )

    assert client.fetch("flask", SpecifierSet(">=2.0")).version == "2.0"


def test_a_pin_on_a_prerelease_still_resolves() -> None:
    """PEP 440: asking for one explicitly is consent."""
    client, _ = client_for(
        {
            "https://pypi.org/pypi/flask/json": package_page("2.3.0", [], ["2.3.0", "3.0.0rc1"]),
            "https://pypi.org/pypi/flask/3.0.0rc1/json": package_page("3.0.0rc1", [], []),
        }
    )

    assert client.fetch("flask", SpecifierSet("==3.0.0rc1")).version == "3.0.0rc1"


def test_a_project_with_only_prereleases_still_resolves() -> None:
    """Nothing else to offer, so offering it beats saying no release satisfies."""
    client, _ = client_for(
        {
            "https://pypi.org/pypi/new-thing/json": package_page("1.0.0b1", [], ["1.0.0b1"]),
            "https://pypi.org/pypi/new-thing/1.0.0b1/json": package_page("1.0.0b1", [], []),
        }
    )

    assert client.fetch("new-thing", SpecifierSet(">=0")).version == "1.0.0b1"


# --- extras -----------------------------------------------------------------


def extras_page() -> FakeResponse:
    """A package whose requires_dist mixes plain, extra-guarded and platform."""
    return package_page(
        "5.3.6",
        [
            "billiard>=4.2.0",
            'redis>=4.5.2 ; extra == "redis"',
            'pyopenssl ; extra == "auth"',
            'pywin32 ; sys_platform == "win32"',
        ],
        ["5.3.6"],
    )


def test_an_extra_is_not_installed_unless_it_is_asked_for() -> None:
    client, _ = client_for({"https://pypi.org/pypi/celery/json": extras_page()})

    result = client.fetch("celery", SpecifierSet())

    assert [r.name for r in result.requirements] == ["billiard", "pywin32"]


def test_asking_for_an_extra_includes_its_requirements() -> None:
    client, _ = client_for({"https://pypi.org/pypi/celery/json": extras_page()})

    result = client.fetch("celery", SpecifierSet(), extras=frozenset({"redis"}))

    assert [r.name for r in result.requirements] == ["billiard", "redis", "pywin32"]


def test_asking_for_two_extras_includes_both() -> None:
    client, _ = client_for({"https://pypi.org/pypi/celery/json": extras_page()})

    result = client.fetch("celery", SpecifierSet(), extras=frozenset({"redis", "auth"}))

    assert {r.name for r in result.requirements} == {"billiard", "redis", "pyopenssl", "pywin32"}


def test_an_extra_that_does_not_exist_adds_nothing() -> None:
    client, _ = client_for({"https://pypi.org/pypi/celery/json": extras_page()})

    result = client.fetch("celery", SpecifierSet(), extras=frozenset({"nonsense"}))

    assert [r.name for r in result.requirements] == ["billiard", "pywin32"]


def test_platform_markers_are_kept_whether_or_not_extras_are_asked_for() -> None:
    """Those describe where a package installs, not whether it was opted into."""
    client, _ = client_for({"https://pypi.org/pypi/celery/json": extras_page()})

    for extras in (frozenset(), frozenset({"redis"})):
        result = client.fetch("celery", SpecifierSet(), extras=extras)
        assert "pywin32" in [r.name for r in result.requirements]


def test_a_json_body_of_null_is_an_error_not_a_success() -> None:
    """A 200 whose body is literally `null` used to produce PackageMetadata
    with no error and no version - and `.ok` reads the error, so the resolver
    recorded it as a successful lookup of a versionless package."""

    class NullBody:
        def get(self, url, timeout=0):
            class R:
                status_code = 200

                def json(self):
                    return None

            return R()

    result = PyPIClient(session=NullBody()).fetch("flask", SpecifierSet())

    assert not result.ok
    assert result.version is None
