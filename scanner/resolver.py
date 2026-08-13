from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from typing import NamedTuple

from packaging.requirements import Requirement
from packaging.specifiers import SpecifierSet
from packaging.utils import canonicalize_name

from scanner.enums import EcoSystem
from scanner.graph import DependencyGraph, ResolutionError
from scanner.models import Dependency, PackageKey


@dataclass
class FetchResult:
    """What a metadata lookup produced, or why it did not.

    Carrying the reason rather than just None means the report can tell a user
    the difference between "that package does not exist" and "no release of it
    satisfies the version you pinned", which need different fixes.
    """

    version: str | None = None
    requirements: list[Requirement] = field(default_factory=list)
    error: str | None = None
    # When the project last published anything, which is what tells you it has
    # been abandoned. None when the registry did not say.
    last_release: datetime | None = None

    @property
    def ok(self) -> bool:
        return self.error is None


# Given a package name, the constraint on it, and any optional feature sets
# asked for, look up the version to use and what it requires.
Fetch = Callable[[str, SpecifierSet, frozenset[str]], FetchResult]


def _needs(metadata: FetchResult) -> list[tuple[str, SpecifierSet, frozenset[str]]]:
    """What a package requires, one entry per required package.

    A package can name the same requirement more than once under different
    markers - `foo>=1.0; python_version<"3.10"` beside `foo>=2.0` - and those
    are constraints on one package, not two. Extras are unioned for the same
    reason: `celery[redis]` and `celery[auth]` are one celery with both.
    """
    specs: dict[str, SpecifierSet] = {}
    extras: dict[str, frozenset[str]] = {}
    for requirement in metadata.requirements:
        name = canonicalize_name(requirement.name)
        specs[name] = specs.get(name, SpecifierSet()) & requirement.specifier
        extras[name] = extras.get(name, frozenset()) | frozenset(requirement.extras)
    return [(name, spec, extras[name]) for name, spec in specs.items()]


def _record(graph: DependencyGraph, parent: PackageKey | None, key: PackageKey) -> None:
    """Note how we arrived at a package.

    Every requester gets an edge, including ones that arrive after the package
    was resolved - that is what `dependents_of` reads to say which package a
    user actually has to upgrade.
    """
    if parent is None:
        if key not in graph.roots:
            graph.roots.append(key)
    else:
        graph.add_edge(parent, key)


class _Lookup(NamedTuple):
    """A package waiting to be looked up, and how we got to it.

    It carries a name and a constraint but no version, because the version is
    what the lookup is for. Once it has one it becomes a PackageKey.
    """

    name: str
    spec: SpecifierSet
    extras: frozenset[str]
    depth: int
    parent: PackageKey | None


def resolve(direct: list[Dependency], fetch: Fetch) -> DependencyGraph:
    """Walk the dependency tree breadth-first and build the graph.

    Breadth-first so `depth` is the shortest path to each package, which is the
    most useful answer to "why is this here".

    There is no depth limit. The walk is bounded by the graph itself - a
    package already resolved is never resolved again - so a limit would only
    mean looking at less of a tree that pip installs all of.

    A package is resolved once, against every constraint anything has placed on
    it. The manifest may pin `adlfs==2024.4.1` while a provider asks for
    `adlfs>=2023.10.0`; answering those separately gives two versions where pip
    installs one, so the constraints are combined before asking.
    """
    graph = DependencyGraph()
    queue = deque(
        # raw_spec carries the constraint from the manifest, so `flask==3.0.0`
        # resolves to 3.0.0 rather than whatever is currently latest
        _Lookup(dep.key.name, SpecifierSet(dep.raw_spec), dep.extras, 0, None)
        for dep in direct
    )

    # What has been asked of each package, and what we settled on.
    asked: dict[str, SpecifierSet] = {}
    wanted: dict[str, frozenset[str]] = {}
    chosen: dict[str, PackageKey] = {}

    while queue:
        name, spec, extras, depth, parent = queue.popleft()

        combined = asked.get(name, SpecifierSet()) & spec
        asked[name] = combined
        previous_extras = wanted.get(name, frozenset())
        all_extras = previous_extras | extras
        wanted[name] = all_extras

        settled = chosen.get(name)
        if settled is not None:
            # Already resolved. If the version still satisfies what is now
            # being asked, record the edge and move on; otherwise say the
            # constraints disagree rather than quietly carrying two versions.
            if settled.version and not combined.contains(settled.version):
                graph.errors.append(ResolutionError(name, f"conflicting constraints: {combined}"))
            _record(graph, parent, settled)
            continue

        if combined.is_unsatisfiable():
            key = PackageKey(name, None, EcoSystem.PYTHON)
            chosen[name] = key
            _record(graph, parent, key)
            graph.add_node(key, depth, parent=parent, failed=True)
            graph.errors.append(ResolutionError(name, f"conflicting constraints: {combined}"))
            continue

        metadata = fetch(name, combined, all_extras)
        key = PackageKey(name, metadata.version, EcoSystem.PYTHON)
        chosen[name] = key
        _record(graph, parent, key)

        graph.add_node(
            key,
            depth,
            parent=parent,
            failed=not metadata.ok,
            last_release=metadata.last_release,
        )
        if not metadata.ok:
            graph.errors.append(ResolutionError(name, metadata.error or "unknown error"))
            continue

        for required, constraint, wants in _needs(metadata):
            queue.append(_Lookup(required, constraint, wants, depth + 1, key))

    return graph
