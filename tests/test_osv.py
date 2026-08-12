"""Tests for the OSV client.

The record under tests/fixtures/osv is a real response captured from the live
API, so these run against the shape OSV actually returns.
"""

import json
from pathlib import Path

from scanner.enums import EcoSystem, Source
from scanner.models import PackageKey
from scanner.osv import OSVClient, _fixed_versions, _severity, _vulnerability

FIXTURES = Path(__file__).parent / "fixtures" / "osv"
RECORD = json.loads((FIXTURES / "vuln-GHSA-pq67-6m6q-mj2v.json").read_text())


def key(name: str, version: str | None = "1.0") -> PackageKey:
    return PackageKey(name, version, EcoSystem.PYTHON)


class FakeResponse:
    def __init__(self, payload, status_code: int = 200) -> None:
        self.status_code = status_code
        self._payload = payload

    def json(self):
        if self._payload is None:
            raise ValueError("no json")
        return self._payload


class FakeSession:
    """Answers with one canned payload per call, and records the bodies sent."""

    def __init__(self, *responses: FakeResponse) -> None:
        self.responses = list(responses)
        self.bodies: list[dict] = []

    def post(self, url, json=None, timeout=0):
        self.bodies.append(json or {})
        if not self.responses:
            return FakeResponse({"vulns": []})
        return self.responses.pop(0)


def answering(*payloads) -> tuple[OSVClient, FakeSession]:
    session = FakeSession(*[FakeResponse(p) for p in payloads])
    return OSVClient(session=session), session


# --- turning a record into the model --------------------------------------


def test_a_real_record_becomes_a_vulnerability() -> None:
    client, _ = answering({"vulns": [RECORD]})

    result = client.query([key("urllib3", "1.26.20")])

    (vulnerability,) = result.findings[key("urllib3", "1.26.20")]
    assert vulnerability.id == "GHSA-pq67-6m6q-mj2v"
    assert vulnerability.severity == "MEDIUM"  # OSV writes it as MODERATE
    assert vulnerability.fixed_versions == ["2.5.0"]
    assert "CVE-2025-50181" in vulnerability.aliases
    assert vulnerability.source is Source.OSV
    assert vulnerability.url == "https://osv.dev/vulnerability/GHSA-pq67-6m6q-mj2v"
    assert "redirects are not disabled" in vulnerability.summary


def test_severity_comes_from_the_word_not_the_cvss_vector() -> None:
    assert _severity(RECORD) == "MEDIUM"
    assert RECORD["severity"][0]["score"].startswith("CVSS:3.1/")


def test_a_record_with_only_a_vector_is_left_for_github_to_answer() -> None:
    """A vector is not a bucket the summary can count."""
    record = dict(RECORD)
    record.pop("database_specific")
    assert _severity(record) == "UNKNOWN"


def test_fixed_versions_are_read_from_the_events_list() -> None:
    assert _fixed_versions(RECORD) == ["2.5.0"]


def test_a_range_with_no_fix_reports_nothing() -> None:
    """No `fixed` event means no patched release exists yet."""
    record = {"affected": [{"ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}]}]}
    assert _fixed_versions(record) == []


def test_git_ranges_are_skipped() -> None:
    """Their versions are commit hashes; "upgrade to f05b1329" is not advice."""
    record = {
        "affected": [
            {"ranges": [{"type": "GIT", "events": [{"fixed": "f05b1329126d5be6de501"}]}]},
            {"ranges": [{"type": "ECOSYSTEM", "events": [{"fixed": "2.5.0"}]}]},
        ]
    }
    assert _fixed_versions(record) == ["2.5.0"]


def test_several_maintained_branches_give_several_fixes() -> None:
    record = {
        "affected": [
            {"ranges": [{"type": "ECOSYSTEM", "events": [{"fixed": "1.26.19"}]}]},
            {"ranges": [{"type": "ECOSYSTEM", "events": [{"fixed": "2.2.2"}]}]},
        ]
    }
    assert _fixed_versions(record) == ["1.26.19", "2.2.2"]


# --- querying -------------------------------------------------------------


def test_one_request_per_package() -> None:
    """The cost of a scan is the package count, not the vulnerability count."""
    client, session = answering({"vulns": []}, {"vulns": []}, {"vulns": []})

    client.query([key("a", "1.0"), key("b", "2.0"), key("c", "3.0")])

    assert len(session.bodies) == 3


def test_the_package_and_version_are_both_sent() -> None:
    client, session = answering({"vulns": []})

    client.query([key("flask", "3.0.0")])

    assert session.bodies[0] == {
        "package": {"name": "flask", "ecosystem": "PyPI"},
        "version": "3.0.0",
    }


def test_a_package_with_no_version_is_not_asked_about() -> None:
    """OSV matches an exact version, so a package that never resolved cannot be queried."""
    client, session = answering()

    client.query([key("mystery", None)])

    assert session.bodies == []


def test_a_clean_package_gets_no_entry() -> None:
    client, _ = answering({"vulns": []})

    result = client.query([key("certifi", "2026.7.22")])

    assert result.ok
    assert result.findings == {}


def test_the_same_cve_from_two_databases_becomes_one_finding() -> None:
    """OSV republishes both GitHub's write-up and PyPA's."""
    pysec = dict(RECORD, id="PYSEC-2026-1999")
    client, _ = answering({"vulns": [RECORD, pysec]})

    result = client.query([key("urllib3", "1.26.20")])

    assert len(result.findings[key("urllib3", "1.26.20")]) == 1


# --- failure --------------------------------------------------------------


def test_an_unreachable_source_reports_why_instead_of_raising() -> None:
    class ExplodingSession:
        def post(self, *args, **kwargs):
            raise OSError("connection reset")

    result = OSVClient(session=ExplodingSession()).query([key("flask", "3.0.0")])

    assert not result.ok
    assert "could not reach OSV" in (result.error or "")


def test_a_server_error_names_the_status() -> None:
    session = FakeSession(FakeResponse({}, status_code=503))
    result = OSVClient(session=session).query([key("flask", "3.0.0")])
    assert result.error == "OSV returned HTTP 503"


def test_malformed_json_is_reported_as_such() -> None:
    session = FakeSession(FakeResponse(None))
    result = OSVClient(session=session).query([key("flask", "3.0.0")])
    assert result.error == "OSV returned invalid JSON"


def test_what_was_found_before_a_failure_is_kept() -> None:
    """Half an answer beats none, as long as it is reported as half."""
    session = FakeSession(FakeResponse({"vulns": [RECORD]}), FakeResponse({}, status_code=503))

    result = OSVClient(session=session).query([key("urllib3", "1.26.20"), key("flask", "3.0.0")])

    assert not result.ok
    assert key("urllib3", "1.26.20") in result.findings


def test_the_vulnerability_model_survives_a_sparse_record() -> None:
    """Only `id` is guaranteed; everything else should degrade, not crash."""
    vulnerability = _vulnerability({"id": "GHSA-bare"})

    assert vulnerability.id == "GHSA-bare"
    assert vulnerability.severity == "UNKNOWN"
    assert vulnerability.fixed_versions == []
    assert vulnerability.aliases == set()
