"""PyPI metadata lookups, with retries and caching.

Provides the `fetch` callable the resolver walks the dependency tree with.
"""

import logging

import requests
from packaging.requirements import InvalidRequirement, Requirement
from packaging.specifiers import SpecifierSet
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version
from requests.adapters import HTTPAdapter
from urllib3.util import Retry

BASE_URL = "https://pypi.org/pypi"
DEFAULT_TIMEOUT = 10.0

log = logging.getLogger(__name__)


def make_session(retries: int = 3, backoff: float = 0.5) -> requests.Session:
    """A session that retries transient failures with exponential backoff.

    urllib3 waits backoff * 2 ** (attempt - 1) seconds between tries, and
    honours a Retry-After header when the server sends one. Only the statuses
    below are retried; a 404 is an answer, not a failure.
    """
    retry = Retry(
        total=retries,
        backoff_factor=backoff,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=("GET",),
    )
    session = requests.Session()
    session.mount("https://", HTTPAdapter(max_retries=retry))
    return session


class PyPIClient:
    """Looks up package metadata, remembering what it has already seen."""

    def __init__(self, session=None, timeout: float = DEFAULT_TIMEOUT) -> None:
        self.session = session or make_session()
        self.timeout = timeout
        self._cache: dict[str, dict | None] = {}

    def fetch(self, name: str, spec: SpecifierSet) -> tuple[str, list[Requirement]] | None:
        """Return the version satisfying `spec` and its requirements.

        None means the package could not be looked up, either because it does
        not exist or because PyPI could not be reached.
        """
        name = canonicalize_name(name)
        page = self._get(f"{BASE_URL}/{name}/json")
        if page is None:
            return None

        latest = page["info"]["version"]
        if spec.contains(latest, prereleases=True):
            return latest, _requirements(page)

        version = _best_match(page.get("releases", {}), spec)
        if version is None:
            log.debug("no release of %s satisfies %s", name, spec)
            return None

        pinned = self._get(f"{BASE_URL}/{name}/{version}/json")
        if pinned is None:
            return None
        return version, _requirements(pinned)

    def _get(self, url: str) -> dict | None:
        """Fetch and decode a URL, or None if that is not possible."""
        if url in self._cache:
            return self._cache[url]

        payload = None
        try:
            response = self.session.get(url, timeout=self.timeout)
            if response.status_code == 200:
                payload = response.json()
            else:
                log.debug("%s returned %s", url, response.status_code)
        except (OSError, ValueError) as exc:
            # OSError covers requests' network errors; ValueError covers bad JSON
            log.debug("%s failed: %s", url, exc)

        self._cache[url] = payload
        return payload


def _requirements(page: dict) -> list[Requirement]:
    """Parse requires_dist, which is null for packages with no dependencies."""
    parsed = []
    for entry in page["info"].get("requires_dist") or []:
        try:
            parsed.append(Requirement(entry))
        except InvalidRequirement:
            log.debug("skipping unparseable requirement %r", entry)
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
