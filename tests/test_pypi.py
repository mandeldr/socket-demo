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
    assert result.error == "no release satisfies <2.0"
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
    client, session = client_for(
        {"https://pypi.org/pypi/zope-interface/json": package_page("6.1", [], ["6.1"])}
    )
    assert client.fetch("Zope.Interface", SpecifierSet()) is not None


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
