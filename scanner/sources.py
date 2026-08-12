"""What every vulnerability source has in common.

Two services answer the same question in different words, so this module holds
the vocabulary they are translated into: one result type, one severity scale,
and the rule for deciding that two records describe the same problem.

The clients themselves live in osv.py and github.py. Nothing here imports them,
so the dependency only runs one way.
"""

from dataclasses import dataclass, field

from scanner.models import PackageKey, Vulnerability

UNKNOWN_SEVERITY = "UNKNOWN"

# OSV says MODERATE where GitHub says medium. Left alone that is two buckets in
# the summary for one level of seriousness.
SEVERITY_WORDS = {
    "CRITICAL": "CRITICAL",
    "HIGH": "HIGH",
    "MODERATE": "MEDIUM",
    "MEDIUM": "MEDIUM",
    "LOW": "LOW",
}


@dataclass
class QueryResult:
    """What a source reported, and why it stopped if it did.

    Both are allowed at once. A source that is rate limited halfway through has
    still told us something true, and throwing it away would be worse than
    keeping it and saying the answer is incomplete.
    """

    findings: dict[PackageKey, list[Vulnerability]] = field(default_factory=dict)
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.error is None


def normalize_severity(value: str | None) -> str:
    """One vocabulary for both services."""
    return SEVERITY_WORDS.get(str(value or "").strip().upper(), UNKNOWN_SEVERITY)


def cve_of(vulnerability: Vulnerability) -> str | None:
    """The CVE this record describes, if it has one.

    A CVE is the identifier both services agree on, so it is what tells us two
    records are the same problem.
    """
    cves = sorted(a for a in vulnerability.aliases if a.startswith("CVE-"))
    return cves[0] if cves else None


def dedupe(vulnerabilities: list[Vulnerability]) -> list[Vulnerability]:
    """Collapse records describing the same problem, keeping the fullest one.

    One CVE usually arrives more than once: OSV publishes GitHub's write-up and
    PyPA's, and GitHub is asked directly on top of that. Keyed on the CVE they
    become one finding.
    """
    kept: dict[str, Vulnerability] = {}
    for vulnerability in vulnerabilities:
        key = cve_of(vulnerability) or vulnerability.id
        if key not in kept or _completeness(vulnerability) > _completeness(kept[key]):
            kept[key] = vulnerability
    return list(kept.values())


def _completeness(vulnerability: Vulnerability) -> tuple[bool, bool]:
    """How much of a record is filled in, for choosing between copies.

    PyPA records often omit the severity where GitHub has it. Whichever copy
    answers more of the user's questions wins.
    """
    return (
        vulnerability.severity != UNKNOWN_SEVERITY,
        bool(vulnerability.fixed_versions),
    )


def merge(results: list[QueryResult]) -> dict[PackageKey, list[Vulnerability]]:
    """Fold every source into one list of findings per package.

    A source that failed still contributes whatever it managed to return; the
    caller reports which ones did not finish.
    """
    combined: dict[PackageKey, list[Vulnerability]] = {}
    for result in results:
        for package, vulnerabilities in result.findings.items():
            combined.setdefault(package, []).extend(vulnerabilities)
    return {package: dedupe(found) for package, found in combined.items()}
