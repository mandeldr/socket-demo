from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from typing import NamedTuple

from packaging.requirements import Requirement
from packaging.specifiers import SpecifierSet

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

DEFAULT_MAX_DEPTH = 5


class _Lookup(NamedTuple):
    """A package waiting to be looked up, and how we got to it.

    It carries a name and a constraint but no version, because the version is
    what the lookup is for. Once it has one it becomes a PackageKey.
    """

    name: str
    spec: SpecifierSet
    depth: int
    parent: PackageKey | None


def resolve(
    direct: list[Dependency],
    fetch: Fetch,
    max_depth: int = DEFAULT_MAX_DEPTH,
) -> DependencyGraph:
    """Walk the dependency tree breadth-first and build the graph.

    Breadth-first so `depth` is the shortest path to each package, which is the
    most useful answer to "why is this here".
    """
    graph = DependencyGraph()
    queue = deque(
        # raw_spec carries the constraint from the manifest, so `flask==3.0.0`
        # resolves to 3.0.0 rather than whatever is currently latest
        _Lookup(dep.key.name, SpecifierSet(dep.raw_spec), 0, None)
        for dep in direct
    )

    while queue:
        name, spec, depth, parent = queue.popleft()

        metadata = fetch(name, spec)
        key = PackageKey(name, metadata.version, EcoSystem.PYTHON)

        if parent is None:
            if key not in graph.roots:
                graph.roots.append(key)
        else:
            graph.add_edge(parent, key)

        # Already seen: a shared dependency, a duplicate, or a cycle coming
        # back around. Either way there is nothing left to expand.
        if key in graph.nodes:
            continue

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

        if depth < max_depth:
            for requirement in metadata.requirements:
                queue.append(_Lookup(requirement.name, requirement.specifier, depth + 1, key))

    return graph
