"""Vulnerability lookups against OSV.dev.

One request per package, which returns the complete records rather than a list
of ids to go and fetch. That makes the cost of a scan the number of packages,
not the number of vulnerabilities they turn out to have - a manifest full of
old pins costs the same as a clean one.

OSV aggregates several databases, so the same CVE usually comes back twice.
`dedupe` collapses them.
"""

from scanner.enums import Source
from scanner.http import DEFAULT_TIMEOUT, make_session
from scanner.models import PackageKey, Vulnerability
from scanner.sources import UNKNOWN_SEVERITY, QueryResult, dedupe, normalize_severity

QUERY_URL = "https://api.osv.dev/v1/query"


class OSVClient:
    """Asks OSV what is known about each package."""

    def __init__(self, session=None, timeout: float = DEFAULT_TIMEOUT) -> None:
        # The query is a POST, but it is a pure lookup with no side effect, so
        # replaying it after a transient failure is safe.
        self.session = session or make_session(methods=("GET", "POST"))
        self.timeout = timeout

    def query(self, packages: list[PackageKey]) -> QueryResult:
        """Find the known vulnerabilities affecting each package."""
        findings: dict[PackageKey, list[Vulnerability]] = {}

        for package in packages:
            # OSV matches an exact version, so a package that never resolved to
            # one cannot be asked about.
            if not package.version:
                continue

            records, error = self._records(package)
            if error:
                # Keep what was found before the failure and say it is partial.
                return QueryResult(findings, error=error)
            if records:
                findings[package] = dedupe([_vulnerability(r) for r in records])

        return QueryResult(findings)

    def _records(self, package: PackageKey) -> tuple[list[dict] | None, str | None]:
        """Every advisory OSV holds for one package. Returns (records, error)."""
        body = {
            "package": {"name": package.name, "ecosystem": package.eco_system.value},
            "version": package.version,
        }
        try:
            response = self.session.post(QUERY_URL, json=body, timeout=self.timeout)
            if response.status_code != 200:
                return None, f"OSV returned HTTP {response.status_code}"
            return response.json().get("vulns") or [], None
        except ValueError:
            return None, "OSV returned invalid JSON"
        except OSError as exc:
            return None, f"could not reach OSV ({type(exc).__name__})"


def _vulnerability(record: dict) -> Vulnerability:
    """Turn one OSV record into the model the report uses.

    The advisory link is built from the id rather than dug out of `references`,
    because that list mixes commits, release notes and NVD pages, while the OSV
    page for an id always exists.
    """
    return Vulnerability(
        id=record["id"],
        aliases=set(record.get("aliases") or []),
        fixed_versions=_fixed_versions(record),
        source=Source.OSV,
        severity=_severity(record),
        summary=_description(record),
        url=f"https://osv.dev/vulnerability/{record['id']}",
    )


def _description(record: dict) -> str:
    """One line saying what is wrong.

    PyPA records often carry no `summary` at all, only the long `details`
    markdown, and a finding with no description is not much use to a reader.
    OSV also returns the odd summary with a stray space on the end.
    """
    summary = (record.get("summary") or "").strip()
    if summary:
        return summary

    details = (record.get("details") or "").strip()
    return details.split("\n\n")[0].strip()


def _fixed_versions(record: dict) -> list[str]:
    """The releases that carry the fix.

    OSV describes an affected range as a flat list of events: `introduced`
    opens a range and `fixed` closes it. A range with no `fixed` event means no
    patched release exists, and returning nothing says that honestly.

    Git ranges are skipped because their versions are commit hashes, and
    telling someone to upgrade to a commit sha is not useful advice.
    """
    versions: list[str] = []
    for affected in record.get("affected") or []:
        for entry in affected.get("ranges") or []:
            if entry.get("type") == "GIT":
                continue
            for event in entry.get("events") or []:
                if "fixed" in event and event["fixed"] not in versions:
                    versions.append(event["fixed"])
    return versions


def _severity(record: dict) -> str:
    """A severity worth printing.

    Two fields carry one and they hold different things. `database_specific`
    has the word the publishing database assigned, which is what a person wants
    to read. The other holds CVSS vector strings, which are precise but are not
    a bucket a summary can count, so a record with only those is left unknown
    and GitHub is asked to fill it in.
    """
    specific = record.get("database_specific") or {}
    if specific.get("severity"):
        return normalize_severity(specific["severity"])
    return UNKNOWN_SEVERITY
