"""Tests for the GitHub advisory client.

The advisories under tests/fixtures/osv/ghsa-urllib3.json are real responses
captured from the live API.
"""

import json
from pathlib import Path

import pytest

from scanner.enums import EcoSystem, Source
from scanner.github import GHSAClient, _is_complete, _patched_version, _vulnerability
from scanner.models import PackageKey, Vulnerability

FIXTURES = Path(__file__).parent / "fixtures" / "osv"
ADVISORIES = json.loads((FIXTURES / "ghsa-urllib3.json").read_text())
ADVISORY = next(a for a in ADVISORIES if a["ghsa_id"] == "GHSA-pq67-6m6q-mj2v")


def key(name: str, version: str = "1.0") -> PackageKey:
    return PackageKey(name, version, EcoSystem.PYTHON)


def gap(
    cve: str | None = "CVE-2025-50181",
    severity: str = "UNKNOWN",
    fixed_versions: list[str] | None = None,
    aliases: set[str] | None = None,
) -> Vulnerability:
    """A finding OSV could not fully describe."""
    return Vulnerability(
        id="PYSEC-2026-1999",
        aliases=aliases if aliases is not None else ({cve} if cve else set()),
        fixed_versions=fixed_versions or [],
        source=Source.OSV,
        severity=severity,
    )


class FakeResponse:
    def __init__(self, payload, status_code: int = 200, headers: dict | None = None) -> None:
        self.status_code = status_code
        self.headers = headers or {}
        self._payload = payload

    def json(self):
        if self._payload is None:
            raise ValueError("no json")
        return self._payload


class FakeSession:
    def __init__(self, payload=None, status_code: int = 200, headers: dict | None = None) -> None:
        self.payload = payload if payload is not None else [ADVISORY]
        self.status_code = status_code
        self.response_headers = headers or {}
        self.calls: list[dict] = []

    def get(self, url, params=None, headers=None, timeout=0):
        self.calls.append({"params": params or {}, "headers": headers or {}})
        return FakeResponse(self.payload, self.status_code, self.response_headers)


def client_for(**kwargs) -> tuple[GHSAClient, FakeSession]:
    session = FakeSession(**kwargs)
    return GHSAClient(session=session, token="test-token"), session


# --- deciding what is worth asking about ----------------------------------


def test_a_finding_with_a_severity_and_a_fix_is_left_alone() -> None:
    """OSV already answered; there is nothing for GitHub to add."""
    client, session = client_for()

    complete = gap(severity="HIGH", fixed_versions=["2.5.0"])
    result = client.enrich({key("urllib3"): [complete]})

    assert session.calls == []
    assert result.findings == {}


def test_a_finding_missing_its_severity_is_looked_up() -> None:
    client, session = client_for()

    client.enrich({key("urllib3"): [gap(fixed_versions=["2.5.0"])]})

    assert len(session.calls) == 1
    assert session.calls[0]["params"] == {"cve_id": "CVE-2025-50181"}


def test_a_finding_missing_its_fix_is_looked_up() -> None:
    client, session = client_for()

    client.enrich({key("urllib3"): [gap(severity="HIGH")]})

    assert len(session.calls) == 1


def test_a_finding_with_no_cve_cannot_be_looked_up() -> None:
    """There is nothing to key the request on."""
    client, session = client_for()

    result = client.enrich({key("urllib3"): [gap(aliases=set())]})

    assert session.calls == []
    assert result.findings == {}


def test_an_unknown_cve_returns_nothing_without_failing() -> None:
    client, _ = client_for(payload=[])

    result = client.enrich({key("urllib3"): [gap()]})

    assert result.ok
    assert result.findings == {}


@pytest.mark.parametrize(
    ("severity", "fixes", "complete"),
    [
        ("HIGH", ["2.5.0"], True),
        ("UNKNOWN", ["2.5.0"], False),
        ("HIGH", [], False),
        ("UNKNOWN", [], False),
    ],
)
def test_completeness_needs_both_a_severity_and_a_fix(severity, fixes, complete) -> None:
    assert _is_complete(gap(severity=severity, fixed_versions=fixes)) is complete


# --- turning an advisory into the model -----------------------------------


def test_a_real_advisory_becomes_a_vulnerability() -> None:
    client, _ = client_for()

    result = client.enrich({key("urllib3"): [gap()]})

    (vulnerability,) = result.findings[key("urllib3")]
    assert vulnerability.id == "GHSA-pq67-6m6q-mj2v"
    assert vulnerability.severity == "MEDIUM"  # GitHub writes it as "medium"
    assert vulnerability.fixed_versions == ["2.5.0"]
    assert "CVE-2025-50181" in vulnerability.aliases
    assert vulnerability.source is Source.GITHUB
    assert vulnerability.url == "https://github.com/advisories/GHSA-pq67-6m6q-mj2v"


def test_the_fix_is_the_one_for_this_package() -> None:
    """One advisory can cover several packages and patch them separately."""
    advisory = {
        "vulnerabilities": [
            {"package": {"name": "other"}, "first_patched_version": "9.9.9"},
            {"package": {"name": "urllib3"}, "first_patched_version": "2.5.0"},
        ]
    }
    assert _patched_version(advisory, "urllib3") == "2.5.0"


def test_a_package_the_advisory_does_not_cover_has_no_fix() -> None:
    advisory = {"vulnerabilities": [{"package": {"name": "other"}, "first_patched_version": "9.9"}]}
    assert _patched_version(advisory, "urllib3") is None


def test_an_advisory_with_no_published_fix() -> None:
    advisory = {"vulnerabilities": [{"package": {"name": "urllib3"}}]}
    assert _patched_version(advisory, "urllib3") is None


def test_the_graphql_shape_of_a_patched_version_is_also_accepted() -> None:
    """REST answers with a string; GraphQL wraps it in an object."""
    advisory = {
        "vulnerabilities": [
            {"package": {"name": "urllib3"}, "first_patched_version": {"identifier": "2.5.0"}}
        ]
    }
    assert _patched_version(advisory, "urllib3") == "2.5.0"


def test_a_sparse_advisory_does_not_crash() -> None:
    vulnerability = _vulnerability({"ghsa_id": "GHSA-bare"}, "urllib3")
    assert vulnerability.severity == "UNKNOWN"
    assert vulnerability.fixed_versions == []


# --- authentication and failure -------------------------------------------


def test_a_token_is_sent_when_there_is_one() -> None:
    client, session = client_for()
    client.enrich({key("urllib3"): [gap()]})
    assert session.calls[0]["headers"]["Authorization"] == "Bearer test-token"


def test_a_token_is_read_from_the_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GITHUB_TOKEN", "from-env")
    session = FakeSession()
    GHSAClient(session=session).enrich({key("urllib3"): [gap()]})
    assert session.calls[0]["headers"]["Authorization"] == "Bearer from-env"


def test_no_token_means_no_authorization_header(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    session = FakeSession()
    GHSAClient(session=session).enrich({key("urllib3"): [gap()]})
    assert "Authorization" not in session.calls[0]["headers"]


def test_being_rate_limited_says_how_to_fix_it(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    session = FakeSession(payload=[], status_code=403, headers={"X-RateLimit-Remaining": "0"})

    result = GHSAClient(session=session).enrich({key("urllib3"): [gap()]})

    assert not result.ok
    assert "GITHUB_TOKEN" in (result.error or "")


def test_a_rate_limited_token_says_so_differently() -> None:
    client, _ = client_for(payload=[], status_code=403, headers={"X-RateLimit-Remaining": "0"})
    result = client.enrich({key("urllib3"): [gap()]})
    assert result.error == "GitHub rate limit reached (5000/hour)"


def test_a_plain_403_is_not_reported_as_a_rate_limit() -> None:
    client, _ = client_for(payload=[], status_code=403)
    result = client.enrich({key("urllib3"): [gap()]})
    assert result.error == "GitHub returned HTTP 403"


def test_an_unreachable_source_reports_why_instead_of_raising() -> None:
    class ExplodingSession:
        def get(self, *args, **kwargs):
            raise OSError("connection reset")

    result = GHSAClient(session=ExplodingSession()).enrich({key("urllib3"): [gap()]})

    assert "could not reach GitHub" in (result.error or "")


def test_what_was_filled_in_before_a_failure_is_kept() -> None:
    class FailsOnSecond:
        def __init__(self):
            self.calls = 0

        def get(self, url, params=None, headers=None, timeout=0):
            self.calls += 1
            if self.calls == 1:
                return FakeResponse([ADVISORY])
            return FakeResponse([], status_code=503)

    result = GHSAClient(session=FailsOnSecond(), token="t").enrich(
        {key("urllib3"): [gap()], key("flask"): [gap("CVE-2020-1")]}
    )

    assert not result.ok
    assert key("urllib3") in result.findings


def test_a_cve_is_only_looked_up_once() -> None:
    """One CVE can be a gap on several packages, and on one package at two
    versions. GitHub is the rate limited source, so repeats cost the most here."""
    client, session = client_for()

    client.enrich(
        {
            key("urllib3", "1.26.20"): [gap()],
            key("urllib3", "2.2.1"): [gap()],
            key("requests", "2.31.0"): [gap(), gap()],
        }
    )

    assert len(session.calls) == 1


def test_a_cve_with_no_advisory_is_not_asked_about_again() -> None:
    """A miss is an answer worth remembering too."""
    client, session = client_for(payload=[])

    client.enrich({key("a"): [gap()], key("b"): [gap()]})

    assert len(session.calls) == 1


def test_a_failed_lookup_is_not_cached() -> None:
    """A rate limit says nothing about whether the CVE has an advisory."""
    session = FakeSession(payload=[], status_code=503)
    client = GHSAClient(session=session, token="t")

    client.enrich({key("a"): [gap()]})

    assert client._cache == {}
