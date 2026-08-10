from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path

from packaging.utils import canonicalize_name


class EcoSystem(Enum):
    PYTHON = "PyPI"
    NPM = "npm"


class Source(Enum):
    GITHUB = "ghsa"
    OSV = "osv"


class SkipReason(Enum):
    PIP_OPTION = "pip option"
    EDITABLE = "editable install"
    VCS = "version control reference"
    DIRECT_URL = "direct URL"
    MISSING_INCLUDE = "included file not found"
    INVALID = "could not be parsed"


@dataclass(frozen=True)  # so it's hashable and usable in a set
class PackageKey:
    name: str
    # None when the manifest does not pin an exact version (a range, or no
    # specifier at all). Such a package cannot be queried against an advisory
    # database until resolution picks a concrete version for it.
    version: str | None
    eco_system: EcoSystem

    def __post_init__(self) -> None:
        """Normalize the package name so equivalent spellings compare equal.

        PyPI treats `zope.interface`, `zope-interface` and `zope_interface` as
        the same project (PEP 503), so we canonicalize on construction to avoid
        counting one package more than once.
        """
        # 1. PEP 503 canonical form: lowercase, runs of -_. collapsed to a single -
        normalized_name = canonicalize_name(self.name.strip())

        # 2. Bypass the frozen dataclass restriction during initialization only
        object.__setattr__(self, "name", normalized_name)


@dataclass
class Dependency:
    key: PackageKey
    raw_spec: str
    is_direct: bool
    depth: int
    parent: PackageKey | None


@dataclass
class SkippedLine:
    line_number: int
    content: str
    reason: SkipReason
    source: Path | None = None


@dataclass
class ParseResult:
    dependencies: list[Dependency] = field(default_factory=list)
    skipped: list[SkippedLine] = field(default_factory=list)


@dataclass
class Vulnerability:
    id: str
    aliases: set[str]
    fixed_versions: list[str]
    source: Source
    severity: str = ""
    summary: str = ""
    url: str = ""


@dataclass
class Finding:
    package: PackageKey
    vulnerability: Vulnerability
    path: list[PackageKey]
    is_direct: bool


@dataclass
class GraphNode:
    key: PackageKey
    children: list[PackageKey]
    depth: int
    unresolved: bool  # metadata missing or package not found


@dataclass
class ResolutionError:
    error: str


@dataclass
class DependencyGraph:
    nodes: dict[PackageKey, GraphNode]
    roots: list[PackageKey]
    cycles: list[list[PackageKey]]
    errors: list[ResolutionError]


@dataclass
class ScanStats:
    total_dependencies: int
    direct_count: int
    transitive_count: int
    vulnerable_count: int
    vulnerable_pct: float
    by_severity: dict[str, int]


@dataclass
class ScanError:
    error: str


@dataclass
class ScanReport:
    manifest_path: str
    ecosystem: EcoSystem
    generated_at: datetime
    stats: ScanStats
    findings: list[Finding]
    cycles: list[list[PackageKey]]
    errors: list[ScanError]
    sources_queried: list[Source]
    sources_failed: list[Source]
