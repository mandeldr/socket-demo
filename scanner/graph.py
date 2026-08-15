"""The dependency graph produced by resolution.

An adjacency list: every node holds the keys of the packages it requires.
"""

from dataclasses import dataclass, field
from datetime import datetime

from scanner.models import PackageKey


@dataclass
class GraphNode:
    """One package in the resolved tree, and how we got to it."""

    key: PackageKey
    depth: int
    children: list[PackageKey] = field(default_factory=list)
    # How this package was first reached. Because the walk is breadth-first,
    # the first route found is the shortest one, so following parent links
    # gives the most direct explanation of why a package is present.
    # None for a direct dependency: it came from the manifest.
    parent: PackageKey | None = None
    failed: bool = False  # the lookup did not produce a version
    # When the newest release was published, for spotting packages nobody has
    # touched in years. None when the registry did not say.
    last_release: datetime | None = None


@dataclass
class ResolutionError:
    """A package the walk could not settle on, and why."""

    package: str
    error: str


@dataclass
class DependencyGraph:
    """Every package a manifest installs, and what asked for each one.

    `nodes` is keyed by package, so it doubles as the set of things already
    resolved - which is what stops the walk revisiting a cycle.
    """

    nodes: dict[PackageKey, GraphNode] = field(default_factory=dict)
    roots: list[PackageKey] = field(default_factory=list)
    errors: list[ResolutionError] = field(default_factory=list)

    def add_node(
        self,
        key: PackageKey,
        depth: int,
        parent: PackageKey | None = None,
        failed: bool = False,
        last_release: datetime | None = None,
    ) -> None:
        """Add a package to the graph, replacing any earlier entry for it."""
        self.nodes[key] = GraphNode(
            key, depth, parent=parent, failed=failed, last_release=last_release
        )

    def add_edge(self, parent: PackageKey, child: PackageKey) -> None:
        """Record that `parent` requires `child`.

        Does nothing if the parent is not in the graph yet. The walk always
        adds a package before recording what it requires, so that cannot
        happen from `resolve` - but a hand-built graph should not raise.
        """
        node = self.nodes.get(parent)
        if node and child not in node.children:
            node.children.append(child)

    def link(self, parent: PackageKey | None, child: PackageKey) -> None:
        """Record how we arrived at a package.

        A package with no parent came from the manifest and is a root;
        anything else was required by something. Every walk in the project
        needs this, and every one of them called it before checking whether
        the package had been seen - because a package reached a second time
        still gains a requester, and that list is what `dependents_of` reads
        to name the package a user actually has to upgrade.
        """
        if parent is None:
            if child not in self.roots:
                self.roots.append(child)
        else:
            self.add_edge(parent, child)

    def dependents_of(self, key: PackageKey) -> list[PackageKey]:
        """Which packages pull this one in. Answers "why do I have this?".

        Sorted and unique: cryptography has forty-three dependents in a real
        Airflow tree, and a caller wanting to name them should not have to
        deduplicate first.
        """
        found = {n.key for n in self.nodes.values() if key in n.children}
        return sorted(found, key=lambda k: (k.name, k.version or ""))

    def path_to(self, key: PackageKey) -> list[PackageKey]:
        """The chain from a direct dependency down to this package.

        Returns [boto3, botocore, urllib3] for a package pulled in two levels
        deep, or just [flask] for something listed in the manifest.
        """
        chain: list[PackageKey] = []
        current: PackageKey | None = key
        while current is not None:
            chain.append(current)
            node = self.nodes.get(current)
            current = node.parent if node else None
        return list(reversed(chain))
