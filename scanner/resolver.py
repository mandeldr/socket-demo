"""Working out the full set of packages a manifest installs.

The manifest names a handful; those need others, which need others again. This
walks that outward from the manifest, asking a registry what each package
resolves to and what it in turn requires, until nothing new is left to look up.
"""

from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from typing import NamedTuple

from packaging.requirements import Requirement
from packaging.specifiers import SpecifierSet
from packaging.utils import canonicalize_name

from scanner.enums import Ecosystem
from scanner.graph import DependencyGraph, ResolutionError
from scanner.models import Dependency, PackageKey


@dataclass
class PackageMetadata:
    """What a registry knows about one package, or why we could not find out.

    Carrying the reason as text is what lets the report distinguish "that
    package does not exist" from "no release satisfies the version you
    pinned". Those need different fixes, and the second one is how the
    Exercise 01 manifest fails.
    """

    version: str | None = None  # the release we settled on
    requirements: list[Requirement] = field(default_factory=list)  # what it needs
    error: str | None = None  # set instead of version when the lookup failed
    # Newest release across the whole project, for --stale-after.
    last_release: datetime | None = None

    @property
    def ok(self) -> bool:
        return self.error is None


# Given a package name, the constraint on it, and any optional feature sets
# asked for, look up the version to use and what it requires.
Fetch = Callable[[str, SpecifierSet, frozenset[str]], PackageMetadata]


def _required_packages(metadata: PackageMetadata) -> list[tuple[str, SpecifierSet, frozenset[str]]]:
    """Collapse one package's requires_dist into one entry per required package.

    A package can name the same requirement twice under different markers -
    `foo<2; python_version<"3.9"` beside `foo>=2` - and those are two
    constraints on one package, not two packages. Extras get unioned for the
    same reason: `celery[redis]` and `celery[auth]` are one celery with both.
    """
    specs: dict[str, SpecifierSet] = {}
    extras: dict[str, frozenset[str]] = {}

    # `marker is not None` sorts False before True, so unconditional
    # requirements are folded in first. Without that, the order they happen to
    # sit in requires_dist would change the answer.
    for requirement in sorted(metadata.requirements, key=lambda r: r.marker is not None):
        name = canonicalize_name(requirement.name)
        specs[name] = _narrowed(specs.get(name, SpecifierSet()), requirement)
        extras[name] = extras.get(name, frozenset()) | frozenset(requirement.extras)

    return [(name, spec, extras[name]) for name, spec in specs.items()]


def _narrowed(so_far: SpecifierSet, requirement: Requirement) -> SpecifierSet:
    """Fold one more requirement into what is already asked of a package.

    A marker-guarded requirement only applies in some environments, and we
    walk a superset of environments instead of resolving for this machine. So
    a guarded constraint is taken only while the result stays satisfiable:
    `foo<2; python_version<"3.9"` beside `foo>=2` is not a conflict pip would
    ever see, and reporting one would be inventing a problem.

    NOTE: this guard only applies *within* one package's requires_dist. Two
    different packages contributing mutually exclusive marker branches still
    get intersected in the main loop below, which can produce a spurious
    conflict. Known limitation.
    """
    combined = so_far & requirement.specifier
    # Guarded and now impossible: drop it and keep what we had.
    if requirement.marker is not None and combined.is_unsatisfiable():
        return so_far
    # Unconditional constraints are allowed to become unsatisfiable - that is
    # a real conflict, and the caller reports it.
    return combined


def _queue_requirements(
    queue: deque,
    metadata: PackageMetadata,
    depth: int,
    requester: PackageKey,
) -> None:
    """Line up everything this package needs, to be looked up in turn."""
    for name, constraint, extras in _required_packages(metadata):
        queue.append(_Lookup(name, constraint, extras, depth + 1, requester))


class _Lookup(NamedTuple):
    """One queue entry: a package waiting to be looked up, and how we got to it.

    Carries a name and a constraint but no version - the version is what the
    lookup is *for*. Once it has one it becomes a PackageKey.
    """

    name: str
    spec: SpecifierSet  # what this particular requester asked for
    extras: frozenset[str]
    depth: int  # hops from the manifest
    parent: PackageKey | None  # None for a direct dependency


def resolve(direct: list[Dependency], fetch: Fetch) -> DependencyGraph:
    """Walk the dependency tree breadth-first and build the graph.

    Breadth-first so `depth` is the shortest path to each package, which is the
    most useful answer to "why is this here".

    There is no depth limit. The walk is bounded by `resolved` below - a
    package settled once is not settled again - so a limit would only mean
    looking at less of a tree that pip installs all of. The one exception is
    a package whose extras grow later, which is looked up again for the extra
    requirements alone.

    A package is resolved once, against every constraint anything has placed on
    it. The manifest may pin `adlfs==2024.4.1` while a provider asks for
    `adlfs>=2023.10.0`; answering those separately gives two versions where pip
    installs one, so the constraints are combined before asking.

    This looks like `manifests.walk` and deliberately is not shared with it.
    The shapes match; the invariants are opposite. This walk is keyed by
    package name and exists to collapse a name to one version, where a lock
    file walk is keyed by install location and must keep the several versions
    npm installs. This one also unifies constraints, asks a registry over the
    network, and records the packages it could not settle. Merging them would
    mean one function with switches for behaviour only one caller wants. They
    share the graph, not the loop.
    """
    graph = DependencyGraph()
    # Every direct dependency goes in at depth 0 *before* the loop starts.
    # That is why a package that is both a manifest pin and a transitive
    # requirement always settles as direct - it is popped first.
    queue = deque(
        # raw_spec carries the manifest's own constraint, so `flask==3.0.0`
        # resolves to 3.0.0 and not to whatever is latest today.
        _Lookup(dep.name, SpecifierSet(dep.raw_spec), dep.extras, 0, None)
        for dep in direct
    )

    # The three pieces of state the walk carries, all keyed by package name:
    constraints: dict[str, SpecifierSet] = {}  # everything asked of it so far
    requested_extras: dict[str, frozenset[str]] = {}  # every extra asked for
    resolved: dict[str, PackageKey] = {}  # what we settled on; also the visited set

    while queue:
        name, spec, extras, depth, parent = queue.popleft()
        # Canonicalize here rather than trusting the caller: these dicts are
        # keyed by name, and `Flask` and `flask` have to hit the same entry.
        name = canonicalize_name(name)

        # Fold this request into everything already asked of the package. `&`
        # intersects the specifier sets, so `==2.2.1` and `<3,>=1.21.1` become
        # `<3,==2.2.1,>=1.21.1`. This is what makes one lookup serve every
        # requester instead of one lookup each.
        constraint = constraints[name] = constraints.get(name, SpecifierSet()) & spec
        asked_before = requested_extras.get(name, frozenset())
        all_extras = requested_extras[name] = asked_before | extras

        # --- case 1: we have already settled this package ------------------
        settled = resolved.get(name)
        if settled is not None:
            # Still record the edge. This is what keeps dependents_of complete.
            graph.link(parent, settled)

            if settled.version and not constraint.contains(settled.version):
                # Something now wants a version we already ruled out. We do not
                # backtrack, so say so instead of quietly carrying two versions.
                graph.errors.append(ResolutionError(name, f"conflicting constraints: {constraint}"))

            if all_extras > asked_before:
                # A newly requested extra adds requirements without changing the
                # version, so the answer grows instead of being redone. `>` is a
                # strict superset test: only re-fetch if the set actually grew.
                _queue_requirements(queue, fetch(name, constraint, all_extras), depth, settled)
            continue

        # --- case 2: the constraints already rule out every version --------
        if constraint.is_unsatisfiable():
            # `<=0.7.1` beside `==1.5.0`. No point asking PyPI. Record the
            # package with version=None so the report can still name it.
            key = PackageKey(name, None, Ecosystem.PYTHON)
            resolved[name] = key  # mark it settled so we do not retry
            graph.link(parent, key)
            graph.add_node(key, depth, parent=parent, failed=True)
            graph.errors.append(ResolutionError(name, f"conflicting constraints: {constraint}"))
            continue

        # --- case 3: a package we have not seen before ---------------------
        # The only branch that touches the network.
        metadata = fetch(name, constraint, all_extras)
        key = PackageKey(name, metadata.version, Ecosystem.PYTHON)
        resolved[name] = key
        graph.link(parent, key)
        graph.add_node(
            key,
            depth,
            parent=parent,
            failed=not metadata.ok,
            last_release=metadata.last_release,
        )

        if metadata.ok:
            # Queue what it needs, one depth deeper, with this package as parent.
            _queue_requirements(queue, metadata, depth, key)
        else:
            # A failed lookup is recorded and the walk continues - one missing
            # package must not stop the rest of the scan.
            graph.errors.append(ResolutionError(name, metadata.error or "unknown error"))

    # The loop ends when the queue drains. `resolved` is what bounds it: every
    # package is fetched at most once, so there is no need for a depth limit.
    return graph
