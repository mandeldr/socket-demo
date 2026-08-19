"""The dependency graph produced by resolution.

An adjacency list: every node holds the keys of the packages it requires.

Two walks build this - resolver.py for Python, manifests/lock_walk.py for
JavaScript - and report.py reads it. It is a data structure, not a step in the
pipeline, which is why it lives in its own module.
"""

from dataclasses import dataclass, field
from datetime import datetime

from scanner.models import PackageKey


@dataclass
class GraphNode:
    """One package in the resolved tree, and how we got to it."""

    key: PackageKey
    # Hops from the manifest. 0 means the manifest asked for it directly.
    depth: int
    # What this package requires. Written by add_edge.
    children: list[PackageKey] = field(default_factory=list)
    # The first route we found here. Both walks are breadth first, so first
    # found is the shortest, and following parent links back gives the most
    # direct explanation of why this package is installed.
    # None means it came from the manifest, so there is nothing above it.
    parent: PackageKey | None = None
    failed: bool = False  # the lookup did not produce a version
    # Newest release date for the whole project, for --stale-after.
    # None when the registry did not say, or for lock files, which carry no dates.
    last_release: datetime | None = None


@dataclass
class ResolutionError:
    """Something the walk has to say about a package, and what it was.

    Two different things end up in this list and they mean opposite things. A
    package with no version was never scanned. A package that settled and then
    met a constraint disagreeing with the choice *was* scanned, at
    `settled_version`. Reporting both as "could not resolve" claims the tool
    failed on a package whose vulnerabilities it is listing on the same page.
    """

    package: str
    error: str
    # The version already chosen when the conflict was found. None means
    # nothing was chosen, so there is genuinely nothing to scan.
    settled_version: str | None = None


@dataclass
class DependencyGraph:
    """Every package a manifest installs, and what asked for each one.

    Each walk keeps its own visited set - the resolver by name, the lock walk
    by install location - because what counts as "already seen" differs. This
    dict is what they both write into, and what the report reads.
    """

    # Every package that installs, keyed by name+version+ecosystem.
    nodes: dict[PackageKey, GraphNode] = field(default_factory=dict)
    # What the manifest asked for directly. Drives the "N direct" count.
    roots: list[PackageKey] = field(default_factory=list)
    # Packages we could not settle on, and why. Printed under "could not resolve".
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

        Does nothing if the parent is not in the graph yet. Both walks add a
        package before recording what it requires, so that cannot happen in
        practice - but a hand-built graph should not raise.
        """
        node = self.nodes.get(parent)
        # The `not in` keeps children unique: one package can require another
        # through two different requirement fields.
        if node and child not in node.children:
            node.children.append(child)

    def link(self, parent: PackageKey | None, child: PackageKey) -> None:
        """Record how we arrived at a package: as a root, or as somebody's child.

        Both walks call this *before* checking whether they have seen the
        package already. A package reached a second time still gains a
        requester, and that list is what `dependents_of` reads to name the
        package a user actually has to upgrade.
        """
        if parent is None:
            # No parent means the manifest asked for it, so it is a root.
            if child not in self.roots:
                self.roots.append(child)
        else:
            self.add_edge(parent, child)

    def dependents_of(self, key: PackageKey) -> list[PackageKey]:
        """Everything that requires this package. Answers "what do I upgrade?".

        Report uses this for the remediation line, which is why the edges have
        to be complete - see `link` above.
        """
        # A scan of every node's children. O(nodes), called once per finding,
        # which is nothing next to the network time.
        found = {n.key for n in self.nodes.values() if key in n.children}
        # Sorted and deduplicated so the caller can print it directly.
        return sorted(found, key=lambda k: (k.name, k.version or ""))

    def path_to(self, key: PackageKey) -> list[PackageKey]:
        """The chain from a direct dependency down to this package.

        Answers "why do I have this?" - [boto3, botocore, urllib3] for
        something two levels deep, or just [flask] for a direct dependency.
        """
        chain: list[PackageKey] = []
        current: PackageKey | None = key
        # Walk parent links upward until we reach a root (parent is None).
        while current is not None:
            chain.append(current)
            node = self.nodes.get(current)
            current = node.parent if node else None
        # Built leaf-first, so flip it to read manifest-first.
        return list(reversed(chain))
