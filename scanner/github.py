"""Filling the gaps OSV leaves, from GitHub Security Advisories.

GitHub is not a second search. Across the packages this was tested on it found
no CVE that OSV had not already found, which is unsurprising since OSV
republishes GitHub's advisories.

What it does have is better metadata: a severity word and a patched version on
every record, where OSV sometimes carries only a CVSS vector. So it is asked
about the few findings OSV could not fully describe - roughly one in thirty -
and asked by CVE, which returns exactly the advisory wanted.
"""

import os
from collections.abc import Iterator

from packaging.utils import canonicalize_name

from scanner.enums import Source
from scanner.http import DEFAULT_TIMEOUT, make_session
from scanner.models import PackageKey, Vulnerability
from scanner.sources import (
    UNKNOWN_SEVERITY,
    QueryResult,
    cve_of,
    normalize_severity,
)

ADVISORIES_URL = "https://api.github.com/advisories"


class GHSAClient:
    """Looks up individual advisories by CVE."""

    def __init__(
        self,
        session=None,
        timeout: float = DEFAULT_TIMEOUT,
        token: str | None = None,
    ) -> None:
        self.session = session or make_session()
        self.timeout = timeout
        # Unauthenticated is 60 requests an hour, shared with everything else
        # using GitHub's core API. A token raises it to 5000.
        self.token = token or os.environ.get("GITHUB_TOKEN")
        # One CVE can be a gap on several packages at once, and on the same
        # package resolved at two versions. Remembering what has been looked up
        # matters more here than anywhere else, because this is the source with
        # a request budget to spend.
        self._cache: dict[str, dict | None] = {}

    def fill_gaps(self, findings: dict[PackageKey, list[Vulnerability]]) -> QueryResult:
        """Look up whatever OSV could not fully describe.

        Returns only the records it filled in. Merging those back over the
        originals is the caller's job, which keeps this from having to know how
        two copies of one advisory get reconciled.
        """
        filled: dict[PackageKey, list[Vulnerability]] = {}

        for package, cve in _gaps(findings):
            advisory, error = self._advisory(cve)
            if error:
                return QueryResult(filled, error=error)
            if advisory:
                filled.setdefault(package, []).append(_vulnerability(advisory, package.name))

        return QueryResult(filled)

    def _advisory(self, cve: str) -> tuple[dict | None, str | None]:
        """The advisory for one CVE. Returns (advisory, error)."""
        if cve in self._cache:
            return self._cache[cve], None

        headers = {"Accept": "application/vnd.github+json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"

        try:
            response = self.session.get(
                ADVISORIES_URL,
                params={"cve_id": cve},
                headers=headers,
                timeout=self.timeout,
            )
            if response.status_code != 200:
                # Not cached: a rate limit or a server error says nothing about
                # whether this CVE has an advisory.
                return None, _error_for(response, bool(self.token))
            advisories = response.json()
            self._cache[cve] = advisories[0] if advisories else None
            return self._cache[cve], None
        except ValueError:
            return None, "GitHub returned invalid JSON"
        except OSError as exc:
            return None, f"could not reach GitHub ({type(exc).__name__})"


def _gaps(findings: dict[PackageKey, list[Vulnerability]]) -> Iterator[tuple[PackageKey, str]]:
    """The findings worth asking GitHub about, as (package, cve) pairs.

    Worth asking means two things: OSV left something out, and there is a CVE
    to look the advisory up by. A finding with neither problem is skipped, and
    a finding with no CVE cannot be looked up at all.
    """
    for package, vulnerabilities in findings.items():
        for vulnerability in vulnerabilities:
            cve = cve_of(vulnerability)
            if cve and not _is_complete(vulnerability):
                yield package, cve


def _is_complete(vulnerability: Vulnerability) -> bool:
    """Whether OSV already said enough that GitHub has nothing to add."""
    return vulnerability.severity != UNKNOWN_SEVERITY and bool(vulnerability.fixed_versions)


def _error_for(response, has_token: bool) -> str:
    """Why the request failed, in terms someone can act on."""
    rate_limited = str(response.headers.get("X-RateLimit-Remaining", "")) == "0"
    if response.status_code == 403 and rate_limited:
        if has_token:
            return "GitHub rate limit reached (5000/hour)"
        return "GitHub rate limit reached (60/hour without a token; set GITHUB_TOKEN)"
    return f"GitHub returned HTTP {response.status_code}"


def _vulnerability(advisory: dict, package_name: str) -> Vulnerability:
    """Turn one advisory into the model the report uses."""
    patched = _patched_version(advisory, package_name)
    aliases = {i["value"] for i in advisory.get("identifiers") or [] if i.get("value")}
    if advisory.get("cve_id"):
        aliases.add(advisory["cve_id"])

    return Vulnerability(
        id=advisory.get("ghsa_id", ""),
        aliases=aliases,
        fixed_versions=[patched] if patched else [],
        source=Source.GITHUB,
        severity=normalize_severity(advisory.get("severity")),
        summary=advisory.get("summary") or "",
        url=advisory.get("html_url") or "",
    )


def _patched_version(advisory: dict, package_name: str) -> str | None:
    """The fix for this package specifically.

    One advisory can cover several packages and patch them at different
    versions, so the entry matching the package being enriched is the one that
    matters.
    """
    for entry in advisory.get("vulnerabilities") or []:
        name = canonicalize_name((entry.get("package") or {}).get("name") or "")
        if name == package_name:
            return entry.get("first_patched_version") or None
    return None
