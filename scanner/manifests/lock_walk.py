"""Turning a lock file into a graph.

A lock has already decided every version, so the walk is just "for each
requirement, go to the entry that answers it". npm and yarn differ in only two
places, and both are passed in as arguments.
"""

from collections import deque
from collections.abc import Callable

from scanner.graph import DependencyGraph
from scanner.models import PackageKey


def walk(
    roots: list[str],
    package_at: Callable[[str], PackageKey],
    required_by: Callable[[str], list[str]],
) -> DependencyGraph:
    """Walk a lock file breadth first, from its direct dependencies outward.

    A `location` identifies one entry, and each format identifies them its own
    way:

        npm    an install path. The same package sits at several, and the path
               decides which copy a given requirement sees.
        yarn   a `name@range` key, which is what an entry answers to.

    `package_at` turns a location into the package found there; `required_by`
    gives the locations that package's own requirements point at. Nothing in
    this function knows which format it is reading.

    Breadth first, so `depth` ends up the shortest route to each package.
    """
    graph = DependencyGraph()
    queue: deque[tuple[str, int, PackageKey | None]] = deque(
        (location, 0, None) for location in roots
    )
    seen: set[str] = set()

    while queue:
        location, depth, parent = queue.popleft()
        package = package_at(location)

        # Above the visited check: a package reached a second time still gains
        # a requester, and dependents_of is what names the package to upgrade.
        graph.link(parent, package)

        if location in seen:
            continue
        seen.add(location)

        # One package can sit at two locations - installed twice at the same
        # version, or answering two ranges. add_node replaces, and this walk is
        # breadth first, so the entry already there came by a shorter route.
        if package not in graph.nodes:
            graph.add_node(package, depth, parent=parent)

        for target in required_by(location):
            queue.append((target, depth + 1, package))

    return graph
