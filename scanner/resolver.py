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


# Given a package name and the constraint on it, look up the version to use.
Fetch = Callable[[str, SpecifierSet], FetchResult]


def _requirements_by_name(requirements: list[Requirement]) -> dict[str, SpecifierSet]:
    """One constraint per package, however many times it is listed.

    A package can name the same requirement more than once under different
    markers - `foo>=1.0; python_version<"3.10"` beside `foo>=2.0` - and those
    are constraints on one package, not two.
    """
    combined: dict[str, SpecifierSet] = {}
    for requirement in requirements:
        name = canonicalize_name(requirement.name)
        combined[name] = combined.get(name, SpecifierSet()) & requirement.specifier
    return combined


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
        _Lookup(dep.key.name, SpecifierSet(dep.raw_spec), 0, None)
        for dep in direct
    )

    # What has been asked of each package, and what we settled on.
    asked: dict[str, SpecifierSet] = {}
    chosen: dict[str, PackageKey] = {}

    while queue:
        name, spec, depth, parent = queue.popleft()

        combined = asked.get(name, SpecifierSet()) & spec
        asked[name] = combined

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

        metadata = fetch(name, combined)
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

        for required, constraint in _requirements_by_name(metadata.requirements).items():
            queue.append(_Lookup(required, constraint, depth + 1, key))

    return graph
