"""Readers that turn a manifest file into what it installs.

One module per format, each with a single `parse` function. What they return
differs, and deliberately so: a requirements.txt names ranges that still have
to be resolved against a registry, while a lock file names versions somebody
already committed, so it can hand back a finished graph.
"""

import json
from collections import deque
from collections.abc import Callable
from pathlib import Path

from scanner.enums import SkipReason
from scanner.graph import DependencyGraph
from scanner.models import Dependency, PackageKey, ParseResult, SkippedLine

MANIFEST = "package.json"

# A specifier naming somewhere on disk rather than a release on a registry.
# `portal:` is yarn's; the rest are shared.
LOCAL_PREFIXES = ("file:", "link:", "workspace:", "portal:")

# What a project's own package.json counts as asking for. The two lists differ
# by one field, and that difference is real rather than an oversight: npm 7 and
# later install a peerDependency declared at the root, and neither yarn 1 nor
# berry does. Locking the same manifest with all three puts react in npm's file
# and in neither yarn one.
#
# So they are kept here, next to each other, because the only way to notice a
# difference living in two modules is to go looking for it.
NPM_PROJECT_FIELDS = (
    "dependencies",
    "devDependencies",
    "optionalDependencies",
    "peerDependencies",
)
YARN_PROJECT_FIELDS = ("dependencies", "devDependencies", "optionalDependencies")


class ManifestError(Exception):
    """A manifest that could not be read at all.

    Raised only when there is nothing to scan - a missing lock file, JSON that
    does not parse, a format we do not support. A file we can read but that
    contains an awkward line is read anyway, and the line is recorded in
    `ParseResult.skipped` instead, so a scan is never quietly narrowed.

    The message is written for the person running the tool, and names the
    command that fixes the problem wherever there is one.
    """


def read_json(path: Path, missing: str | None = None) -> dict:
    """Read one JSON manifest, or say why it could not be read.

    Both lock readers start from the same package.json, so the rules for
    reading it live here rather than in each of them.

    utf-8-sig rather than utf-8: a byte order mark is invisible in an editor
    and makes a plain read reject the whole file over three bytes nobody can
    see.
    """
    try:
        text = path.read_text(encoding="utf-8-sig")
    except OSError:
        raise ManifestError(missing or f"no such file: {path}") from None

    try:
        loaded = json.loads(text)
    except ValueError as exc:
        raise ManifestError(f"{path.name} is not valid JSON: {exc}") from None

    if not isinstance(loaded, dict):
        raise ManifestError(f"{path.name} is not a JSON object")
    return loaded


def requested(manifest: dict, fields: tuple[str, ...]) -> ParseResult:
    """What a package.json asked for, before any lock decided versions.

    `fields` differs between the two readers because npm and yarn disagree on
    whether a project's own peerDependencies count as something it asked for.
    """
    result = ParseResult()

    for field in fields:
        for name, spec in (manifest.get(field) or {}).items():
            if spec.startswith(LOCAL_PREFIXES):
                # Somewhere on disk, so there is no release to look up. Recorded
                # rather than dropped, so the report can say what it did not read.
                result.skipped.append(SkippedLine(0, f"{name}@{spec}", SkipReason.LOCAL_PATH))
            else:
                result.dependencies.append(Dependency(name=name, raw_spec=spec))

    return result


def walk(
    roots: list[str],
    package_at: Callable[[str], PackageKey],
    required_by: Callable[[str], list[str]],
) -> DependencyGraph:
    """Turn a lock file into a graph, breadth first from the direct dependencies.

    Both lock formats need the same walk, because a lock has already decided
    every version - following it is just "for each requirement, go to the entry
    that answers it". Only two things differ, and they are the arguments: how a
    location in the file names a package, and where that location's own
    requirements point.

    A `location` is whatever the format uses to identify one entry: an install
    path for npm, since the same package sits at several; a `name@range` key
    for yarn, since that is what an entry answers to.

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
