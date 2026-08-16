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
Fetch = Callable[[str, SpecifierSet, frozenset[str]], PackageMetadata]


def _required_packages(metadata: PackageMetadata) -> list[tuple[str, SpecifierSet, frozenset[str]]]:
    """What a package requires, one entry per required package.

    A package can name the same requirement more than once under different
    markers - `foo<2; python_version<"3.9"` beside `foo>=2` - and those are
    constraints on one package, not two. Extras are unioned for the same
    reason: `celery[redis]` and `celery[auth]` are one celery with both.

    Unconditional requirements are folded in first, so the order they happen to
    appear in `requires_dist` cannot change the answer.
    """
    specs: dict[str, SpecifierSet] = {}
    extras: dict[str, frozenset[str]] = {}

    for requirement in sorted(metadata.requirements, key=lambda r: r.marker is not None):
        name = canonicalize_name(requirement.name)
        specs[name] = _narrowed(specs.get(name, SpecifierSet()), requirement)
        extras[name] = extras.get(name, frozenset()) | frozenset(requirement.extras)

    return [(name, spec, extras[name]) for name, spec in specs.items()]


def _narrowed(so_far: SpecifierSet, requirement: Requirement) -> SpecifierSet:
    """Fold one more requirement into what is already asked of a package.

    A marker-guarded requirement applies in some environments and not others,
    and this walks a superset of environments rather than resolving for one.
    So its constraint is taken only while the result stays satisfiable:
    `foo<2; python_version<"3.9"` beside `foo>=2` is not a conflict pip would
    ever see, and reporting one would be inventing a problem rather than
    finding it.

    Two unconditional requirements that disagree are a real conflict and are
    left to become unsatisfiable, which is what the caller reports.
    """
    combined = so_far & requirement.specifier
    if requirement.marker is not None and combined.is_unsatisfiable():
        return so_far
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
    """A package waiting to be looked up, and how we got to it.

    It carries a name and a constraint but no version, because the version is
    what the lookup is for. Once it has one it becomes a PackageKey.

    A NamedTuple rather than a plain tuple so the five values are named and
    type-checked; the loop unpacks it positionally.
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
    queue = deque(
        # raw_spec carries the constraint from the manifest, so `flask==3.0.0`
        # resolves to 3.0.0 rather than whatever is currently latest
        _Lookup(dep.name, SpecifierSet(dep.raw_spec), dep.extras, 0, None)
        for dep in direct
    )

    # Everything asked of each package so far, and what we settled on. A
    # package is looked up once, against all of it.
    constraints: dict[str, SpecifierSet] = {}
    requested_extras: dict[str, frozenset[str]] = {}
    resolved: dict[str, PackageKey] = {}

    while queue:
        name, spec, extras, depth, parent = queue.popleft()
        # Canonicalized here rather than trusted from the caller: these dicts
        # are keyed by name, and `Flask` and `flask` are one package.
        name = canonicalize_name(name)

        # Fold this request into everything already asked of the package, so it
        # is looked up once against all of it rather than once per requester.
        constraint = constraints[name] = constraints.get(name, SpecifierSet()) & spec
        asked_before = requested_extras.get(name, frozenset())
        all_extras = requested_extras[name] = asked_before | extras

        settled = resolved.get(name)
        if settled is not None:
            graph.link(parent, settled)

            if settled.version and not constraint.contains(settled.version):
                # Something now wants a version we have already ruled out. Say
                # so, rather than quietly carrying the package twice.
                graph.errors.append(ResolutionError(name, f"conflicting constraints: {constraint}"))

            if all_extras > asked_before:
                # A newly requested extra adds requirements without changing
                # the version, so the answer grows instead of being redone.
                _queue_requirements(queue, fetch(name, constraint, all_extras), depth, settled)
            continue

        if constraint.is_unsatisfiable():
            # No version can satisfy all of it - `<=0.7.1` beside `==1.5.0`.
            # Record the package so the report can name it, and move on.
            key = PackageKey(name, None, Ecosystem.PYTHON)
            resolved[name] = key
            graph.link(parent, key)
            graph.add_node(key, depth, parent=parent, failed=True)
            graph.errors.append(ResolutionError(name, f"conflicting constraints: {constraint}"))
            continue

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
            _queue_requirements(queue, metadata, depth, key)
        else:
            graph.errors.append(ResolutionError(name, metadata.error or "unknown error"))

    return graph
