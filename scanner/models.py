"""The things a scan is made of.

A package moves through three of these: a `Dependency` is what the manifest
asked for, a `PackageKey` is what that resolved to, and a `Vulnerability` is
what an advisory database said about it.
"""

from dataclasses import dataclass, field

from packaging.utils import canonicalize_name

from scanner.enums import Ecosystem, SkipReason, Source


def canonical_name(name: str, ecosystem: Ecosystem) -> str:
    """Normalize a package name the way its own registry does.

    PyPI folds `.`, `-` and `_` together (PEP 503), so `zope.interface` and
    `zope_interface` are one project. npm folds nothing: `lodash.merge` and
    `lodash-merge` are two different names and only the first one exists.
    Applying PyPI's rule to npm makes the advisory lookup come back empty,
    with no error to notice.
    """
    name = name.strip()
    if ecosystem is Ecosystem.PYTHON:
        return str(canonicalize_name(name))

    # npm treats names case insensitively and rejects new ones with capitals,
    # so lowercasing is the whole rule. `@Babel/Core` is `@babel/core`.
    return name.lower()


@dataclass(frozen=True)  # frozen so it can key the graph and live in a set
class PackageKey:
    """One identified package: which project, which version, which registry."""

    name: str
    # None when nothing has pinned an exact version yet. OSV matches exact
    # versions only, so a package still holding None cannot be queried.
    version: str | None
    ecosystem: Ecosystem

    def __post_init__(self) -> None:
        """Normalize the name on construction, so two spellings cannot become two nodes."""
        # object.__setattr__ because the dataclass is frozen.
        object.__setattr__(self, "name", canonical_name(self.name, self.ecosystem))


@dataclass
class Dependency:
    """A requirement as the manifest wrote it, before anything is resolved."""

    # Left as spelled. The name becomes a lookup key in PackageKey, which
    # canonicalizes; here it is only counted and displayed.
    name: str
    raw_spec: str
    # `celery[redis]` installs redis. Dropping the extras hides that package.
    extras: frozenset[str] = frozenset()


@dataclass
class SkippedLine:
    """Something in a manifest that did not turn into a requirement."""

    # None for formats with no line to point at. A package.json dependency is
    # a key in an object, so "line 0" would be a location that does not exist.
    line_number: int | None
    content: str
    reason: SkipReason


@dataclass
class ParseResult:
    """Everything one manifest yielded: what it asked for, and what was skipped."""

    dependencies: list[Dependency] = field(default_factory=list)
    skipped: list[SkippedLine] = field(default_factory=list)


@dataclass
class Vulnerability:
    """One advisory, as a source reported it.

    The same CVE arrives from OSV and GitHub under different ids, so `aliases`
    is what lets the two be recognised as one finding.
    """

    id: str
    aliases: set[str]
    fixed_versions: list[str]
    source: Source
    severity: str = ""
    summary: str = ""
    url: str = ""
