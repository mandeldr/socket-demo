"""PyPI metadata lookups, with retries and caching.

Provides the `fetch` callable the resolver walks the dependency tree with.
"""

from datetime import datetime

from packaging.requirements import InvalidRequirement, Requirement
from packaging.specifiers import SpecifierSet
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

from scanner.http import DEFAULT_TIMEOUT, make_session
from scanner.resolver import PackageMetadata

BASE_URL = "https://pypi.org/pypi"
NOT_ON_PYPI = "no such package on PyPI"


class PyPIClient:
    """Looks up package metadata, remembering what it has already seen."""

    def __init__(self, session=None, timeout: float = DEFAULT_TIMEOUT) -> None:
        self.session = session or make_session()
        self.timeout = timeout
        self._cache: dict[str, tuple[dict | None, str | None]] = {}

    def fetch(
        self, name: str, spec: SpecifierSet, extras: frozenset[str] = frozenset()
    ) -> PackageMetadata:
        """Return the version satisfying `spec` and that version's requirements."""
        name = canonicalize_name(name)

        # Request one: the project page. Lists every release, and describes
        # the latest one in detail.
        page, error = self._get(f"{BASE_URL}/{name}/json")
        if error or page is None:
            return PackageMetadata(error=error)

        published = _last_release(page)
        latest = page["info"]["version"]

        # Pick the version. Every candidate goes through the same selection,
        # including `latest` - SpecifierSet.contains() matches prereleases
        # where filter() does not, so testing latest separately would answer
        # differently for an rc.
        version = _best_match(page.get("releases", {}), spec)
        if version is None:
            # This is the Exercise 01 message: the pin names a release that
            # does not exist.
            return PackageMetadata(error=f"no release satisfies {spec} (latest is {latest})")

        # Short-circuit: the page in hand already describes the latest release,
        # so if that is what we picked, we are done in one request.
        if version == latest:
            return PackageMetadata(latest, _requirements(page, extras), last_release=published)

        # Request two, only for a pin below latest: that version's own metadata,
        # because requirements change between releases.
        pinned, error = self._get(f"{BASE_URL}/{name}/{version}/json")
        if error or pinned is None:
            return PackageMetadata(error=f"metadata for {version} unavailable ({error})")
        return PackageMetadata(version, _requirements(pinned, extras), last_release=published)

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
                payload = response.json()
                # A 200 carrying `null` or a list is not a package page. Without
                # this the caller gets no payload and no error, and `ok` reads
                # the error - so a failed lookup is recorded as a success.
                if isinstance(payload, dict):
                    result = (payload, None)
                else:
                    result = (None, "PyPI returned an unexpected payload")
        except ValueError:
            result = (None, "PyPI returned invalid JSON")
        except OSError as exc:
            result = (None, f"could not reach PyPI ({type(exc).__name__})")

        self._cache[url] = result
        return result


def _is_installed(requirement: Requirement, extras: frozenset[str]) -> bool:
    """Whether this requirement is installed, given the extras asked for.

    An `extra == "redis"` marker means "only when redis was requested", so it
    is a condition to evaluate. Environment markers - sys_platform,
    python_version - are left alone: they say *where* a package installs, not
    whether it was opted into, and this manifest may be installed elsewhere.
    """
    marker = requirement.marker
    # No marker, or a marker that says nothing about extras: it always installs.
    if marker is None or "extra" not in str(marker):
        return True

    # Try the marker once per extra. The "" entry asks "would this install with
    # no extras at all?", which covers a marker combining `extra` with
    # something else, like `extra == "x" or python_version < "3.9"`.
    return any(marker.evaluate({"extra": extra}) for extra in ("", *extras))


def _last_release(page: dict) -> datetime | None:
    """When anything was last published for this project.

    The newest upload across *every* release, not the date of the version we
    resolved to. An old pin of a healthy project is a different problem from a
    project nobody has touched in years, and only the second one is staleness.
    """
    newest = None
    # releases is {version: [file, file, ...]}, so this is a nested scan of
    # every uploaded file. It runs a few thousand times on a small scan and
    # costs well under a millisecond - the network dwarfs it.
    for files in (page.get("releases") or {}).values():
        for entry in files or []:
            when = _parse_time(entry.get("upload_time_iso_8601"))
            if when and (newest is None or when > newest):
                newest = when
    return newest


def _parse_time(raw: str | None) -> datetime | None:
    """An upload timestamp, or None if PyPI wrote something unreadable."""
    if not raw:
        return None
    try:
        # PyPI writes a trailing Z, which fromisoformat did not accept until 3.11.
        return datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return None


def _requirements(page: dict, extras: frozenset[str] = frozenset()) -> list[Requirement]:
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
            continue

        if not _is_installed(requirement, extras):
            continue

        parsed.append(requirement)
    return parsed


def _best_match(releases: dict[str, object], spec: SpecifierSet) -> str | None:
    """The highest released version satisfying the constraint, or None."""
    versions = []
    for raw in releases:
        try:
            versions.append(Version(raw))
        except InvalidVersion:
            # PyPI carries some genuinely unparseable old version strings.
            continue
    # filter() leaves prereleases out unless the specifier asks for one, and
    # falls back to them when a project has never shipped a stable release.
    # That matches pip. Picking an rc the user does not have would mean
    # reporting vulnerabilities they do not have.
    matching = list(spec.filter(versions))
    # max() on Version objects compares by version, not alphabetically.
    return str(max(matching)) if matching else None
