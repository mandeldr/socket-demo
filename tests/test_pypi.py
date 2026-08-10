"""Tests for the PyPI metadata client.

The client takes a session, so these run against a fake one rather than the
network. Same idea as passing `fetch` into the resolver.
"""

import pytest
from packaging.specifiers import SpecifierSet

from scanner.pypi import PyPIClient


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
    assert result is not None
    version, requirements = result
    assert version == "3.0.0"
    assert [r.name for r in requirements] == ["Werkzeug", "Jinja2"]


def test_requires_dist_of_none_means_no_dependencies() -> None:
    """Packages with no dependencies omit the field entirely (e.g. certifi)."""
    client, _ = client_for(
        {"https://pypi.org/pypi/certifi/json": package_page("2024.2.2", None, ["2024.2.2"])}
    )
    result = client.fetch("certifi", SpecifierSet())
    assert result == ("2024.2.2", [])


def test_unknown_package_returns_none() -> None:
    client, _ = client_for({})
    assert client.fetch("does-not-exist", SpecifierSet()) is None


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
    assert result is not None
    version, requirements = result
    assert version == "2.3.0"
    assert [r.name for r in requirements] == ["click"]


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
    assert result is not None
    assert result[0] == "2.3.0"


def test_no_release_satisfies_the_constraint() -> None:
    client, _ = client_for(
        {"https://pypi.org/pypi/flask/json": package_page("3.0.0", [], ["3.0.0"])}
    )
    assert client.fetch("flask", SpecifierSet("<2.0")) is None


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
    assert client.fetch("flask", SpecifierSet()) is None


def test_malformed_json_returns_none() -> None:
    client, _ = client_for({"https://pypi.org/pypi/flask/json": FakeResponse(None, 200)})
    assert client.fetch("flask", SpecifierSet()) is None


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
    assert result is not None
    assert [r.name for r in result[1]] == ["click", "jinja2"]


@pytest.mark.parametrize("status", [500, 502, 503])
def test_a_server_error_returns_none(status: int) -> None:
    client, _ = client_for(
        {"https://pypi.org/pypi/flask/json": FakeResponse({}, status_code=status)}
    )
    assert client.fetch("flask", SpecifierSet()) is None
