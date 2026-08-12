"""PyPI metadata lookups, with retries and caching.

Provides the `fetch` callable the resolver walks the dependency tree with.
"""

import logging

from packaging.requirements import InvalidRequirement, Requirement
from packaging.specifiers import SpecifierSet
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

from scanner.http import DEFAULT_TIMEOUT, make_session
from scanner.resolver import FetchResult

BASE_URL = "https://pypi.org/pypi"
NOT_ON_PYPI = "no such package on PyPI"

log = logging.getLogger(__name__)


class PyPIClient:
    """Looks up package metadata, remembering what it has already seen."""

    def __init__(self, session=None, timeout: float = DEFAULT_TIMEOUT) -> None:
        self.session = session or make_session()
        self.timeout = timeout
        self._cache: dict[str, tuple[dict | None, str | None]] = {}

    def fetch(self, name: str, spec: SpecifierSet) -> FetchResult:
        """Return the version satisfying `spec` and that version's requirements."""
        name = canonicalize_name(name)

        page, error = self._get(f"{BASE_URL}/{name}/json")
        if error or page is None:
            return FetchResult(error=error)

        latest = page["info"]["version"]
        if spec.contains(latest, prereleases=True):
            return FetchResult(latest, _requirements(page))

        version = _best_match(page.get("releases", {}), spec)
        if version is None:
            return FetchResult(error=f"no release satisfies {spec}")

        pinned, error = self._get(f"{BASE_URL}/{name}/{version}/json")
        if error or pinned is None:
            return FetchResult(error=f"metadata for {version} unavailable ({error})")
        return FetchResult(version, _requirements(pinned))

    def _get(self, url: str) -> tuple[dict | None, str | None]:
        """Fetch and decode a URL. Returns (payload, error); exactly one is set."""
        if url in self._cache:
            return self._cache[url]

        result: tuple[dict | None, str | None]
        try:
            response = self.session.get(url, timeout=self.timeout)
            if response.status_code == 404:
                result = (None, NOT_ON_PYPI)
            elif response.status_code != 200:
                result = (None, f"PyPI returned HTTP {response.status_code}")
            else:
                result = (response.json(), None)
        except ValueError:
            result = (None, "PyPI returned invalid JSON")
        except OSError as exc:
            result = (None, f"could not reach PyPI ({type(exc).__name__})")

        if result[1]:
            log.debug("%s: %s", url, result[1])
        self._cache[url] = result
        return result


def _requirements(page: dict) -> list[Requirement]:
    """Parse requires_dist, which is null for packages with no dependencies.

    Optional dependencies are skipped. A requirement guarded by an `extra`
    marker is only installed when the user asks for it: `pip install pandas`
    pulls in 6 packages, `pip install pandas[test]` pulls in far more. Treating
    them as required would report a dependency tree nobody actually has.

    Other markers (python_version, sys_platform) are kept, because the manifest
    may well be installed on a different interpreter or OS than this one.
    """
    parsed = []
    for entry in page["info"].get("requires_dist") or []:
        try:
            requirement = Requirement(entry)
        except InvalidRequirement:
            log.debug("skipping unparseable requirement %r", entry)
            continue

        if requirement.marker and "extra" in str(requirement.marker):
            continue

        parsed.append(requirement)
    return parsed


def _best_match(releases: dict[str, object], spec: SpecifierSet) -> str | None:
    """The highest released version satisfying the constraint."""
    versions = []
    for raw in releases:
        try:
            versions.append(Version(raw))
        except InvalidVersion:
            continue
    matching = list(spec.filter(versions, prereleases=True))
    return str(max(matching)) if matching else None
