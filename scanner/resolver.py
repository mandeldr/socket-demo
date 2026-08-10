from collections import deque
from collections.abc import Callable
from typing import NamedTuple

from packaging.requirements import Requirement
from packaging.specifiers import SpecifierSet

from scanner.enums import EcoSystem
from scanner.graph import DependencyGraph, ResolutionError
from scanner.models import Dependency, PackageKey

# Given a package name and the constraint on it, return the version chosen and
# that version's own requirements. None means the package could not be found.
Fetch = Callable[[str, SpecifierSet], tuple[str, list[Requirement]] | None]

DEFAULT_MAX_DEPTH = 5


class _Pending(NamedTuple):
    """A package waiting to be looked up, and how we got to it."""

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
        _Pending(dep.key.name, SpecifierSet(dep.raw_spec), 0, None)
        for dep in direct
    )

    while queue:
        item = queue.popleft()

        found = fetch(item.name, item.spec)
        version, requirements = found if found else (None, [])
        key = PackageKey(item.name, version, EcoSystem.PYTHON)

        if item.parent is None:
            if key not in graph.roots:
                graph.roots.append(key)
        else:
            graph.add_edge(item.parent, key)

        # Already seen: a shared dependency, a duplicate, or a cycle coming
        # back around. Either way there is nothing left to expand.
        if key in graph.nodes:
            continue

        graph.add_node(key, item.depth, parent=item.parent, unresolved=found is None)
        if found is None:
            graph.errors.append(ResolutionError(item.name, "could not be found"))
            continue

        if item.depth < max_depth:
            for requirement in requirements:
                queue.append(
                    _Pending(requirement.name, requirement.specifier, item.depth + 1, key)
                )

    return graph
