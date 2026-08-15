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

    The two rules are not interchangeable, and using the wrong one is silent.
    PyPI folds `.`, `-` and `_` together, so `zope.interface` and
    `zope_interface` are one project. npm does not: `lodash.merge` is a real
    package and `lodash-merge` is nothing at all, so collapsing them means
    asking an advisory database about a package that does not exist and being
    told, truthfully, that it has no vulnerabilities.
    """
    name = name.strip()
    if ecosystem is Ecosystem.PYTHON:
        # PEP 503 canonical form: lowercase, runs of -_. collapsed to a single -
        return str(canonicalize_name(name))

    # npm rejects new names containing capitals and treats existing ones
    # case insensitively, so lowercasing is the whole rule. Scopes come along
    # untouched: `@Babel/Core` is `@babel/core`.
    return name.lower()


@dataclass(frozen=True)  # so it's hashable and usable in a set
class PackageKey:
    """One identified package: which project, which version, which registry."""

    name: str
    # None when the manifest does not pin an exact version (a range, or no
    # specifier at all). Such a package cannot be queried against an advisory
    # database until resolution picks a concrete version for it.
    version: str | None
    ecosystem: Ecosystem

    def __post_init__(self) -> None:
        """Normalize the package name so equivalent spellings compare equal.

        Which spellings count as equivalent depends on the registry, so the
        rule lives in `canonical_name` and every comparison against this name
        has to use the same one.
        """
        # Bypass the frozen dataclass restriction during initialization only
        object.__setattr__(self, "name", canonical_name(self.name, self.ecosystem))


@dataclass
class Dependency:
    """A requirement as the manifest wrote it, before anything is resolved."""

    # Canonicalized, so `zope.interface` and `zope_interface` match whatever
    # a package's requires_dist happens to call it.
    name: str
    raw_spec: str
    # Optional feature sets the manifest opted into: `celery[redis]` installs
    # redis, so dropping this makes a real dependency invisible.
    extras: frozenset[str] = frozenset()


@dataclass
class SkippedLine:
    """Something in a manifest that did not turn into a requirement."""

    # None when the format has no lines to point at: a package.json dependency
    # is a key in an object, and reporting it as line 0 would be a location
    # that does not exist.
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

    `aliases` is what makes deduplication possible - the same CVE arrives from
    OSV and GitHub under different ids.
    """

    id: str
    aliases: set[str]
    fixed_versions: list[str]
    source: Source
    severity: str = ""
    summary: str = ""
    url: str = ""
