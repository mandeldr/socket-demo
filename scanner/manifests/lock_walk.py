"""Turning a lock file into a graph.

Both JavaScript lock formats need the same walk, because a lock has already
decided every version - following it is just "for each requirement, go to the
entry that answers it". Only two things differ between npm and yarn, and they
are the arguments this takes.
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

    A `location` is whatever the format uses to identify one entry, and the two
    formats identify them differently:

        npm    an install path, because the same package sits at several and
               the path decides which copy a requirement sees
        yarn   a `name@range` key, because that is what an entry answers to

    `package_at` turns a location into the package found there, and
    `required_by` gives the locations that one's own requirements point at.
    Nothing else in this walk knows which format it is reading.

    Breadth first so `depth` ends up the shortest route to each package, which
    is the most useful answer to "why is this here".
    """
    graph = DependencyGraph()
    queue: deque[tuple[str, int, PackageKey | None]] = deque(
        (location, 0, None) for location in roots
    )
    seen: set[str] = set()

    while queue:
        location, depth, parent = queue.popleft()
        package = package_at(location)

        # Before the visited check, so every requester gets an edge and not
        # just the first one to arrive.
        graph.link(parent, package)

        if location in seen:
            continue
        seen.add(location)

        # One package can sit at two locations - installed twice at the same
        # version, or answering two ranges. The graph is keyed by package and
        # add_node replaces, so keep whatever is already there: this walk is
        # breadth first, so it arrived by a shorter route.
        if package not in graph.nodes:
            graph.add_node(package, depth, parent=parent)

        for target in required_by(location):
            queue.append((target, depth + 1, package))

    return graph
