from dataclasses import dataclass, field
from pathlib import Path

from packaging.utils import canonicalize_name

from scanner.enums import EcoSystem, SkipReason, Source


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
        # PEP 503 canonical form: lowercase, runs of -_. collapsed to a single -
        normalized_name = canonicalize_name(self.name.strip())

        # Bypass the frozen dataclass restriction during initialization only
        object.__setattr__(self, "name", normalized_name)


@dataclass
class Dependency:
    """A requirement as the manifest wrote it, before anything is resolved."""

    key: PackageKey
    raw_spec: str
    # Optional feature sets the manifest opted into: `celery[redis]` installs
    # redis, so dropping this makes a real dependency invisible.
    extras: frozenset[str] = frozenset()


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
