"""Reading a package.json and its lock file into the packages they install.

Nothing here resolves anything. npm already worked out which release satisfies
every range and wrote the answer into the lock file, so this reads that answer
rather than asking a registry for it - the same reason the Python side reads
PyPI metadata instead of building sdists.

Three things make it more than a loop over the file:

- a package can be installed more than once at different versions, so a lock
  path rather than a name identifies a node;
- an entry can be installed under a name that is not its own, so the name has
  to come from the entry rather than from where it sits;
- a monorepo's own packages live outside node_modules and are listed twice,
  so they have to be found separately and their links followed.
"""

import json
from collections import deque
from pathlib import Path

from scanner.enums import EcoSystem, SkipReason
from scanner.graph import DependencyGraph
from scanner.manifests import ManifestError
from scanner.models import Dependency, PackageKey, ParseResult, SkippedLine

MANIFEST = "package.json"
LOCK = "package-lock.json"

# What to tell someone whose lock file is missing or too old. It is the whole
# fix, and it needs no network.
REGENERATE = "run `npm install --package-lock-only` to generate one"

# What an installed package can pull in. Its devDependencies are absent on
# purpose: yours are installed on your machine, a library's are not installed
# on anyone's.
INSTALLED_PACKAGE_FIELDS = ("dependencies", "optionalDependencies", "peerDependencies")

# What the project itself pulls in, which is everything plus its own dev tools.
PROJECT_FIELDS = INSTALLED_PACKAGE_FIELDS + ("devDependencies",)

# A specifier naming somewhere on disk rather than a release on the registry.
LOCAL_PREFIXES = ("file:", "link:", "workspace:")


def parse(path: Path) -> tuple[ParseResult, DependencyGraph]:
    """Read a package.json and its lock file.

    Returns what the manifest asked for, and the tree the lock says that
    installs. Two values rather than one because a lock file genuinely gives
    more than a requirements.txt does: it answers the resolution question as
    well as the "what did you ask for" one.
    """
    directory = path.parent

    manifest = _load(directory / MANIFEST)
    lock = _load(directory / LOCK, missing=f"{MANIFEST} has no {LOCK} beside it; {REGENERATE}")

    return _requested(manifest), _installed(_entries(lock))


def _load(path: Path, missing: str | None = None) -> dict:
    """Read one JSON file, or say why it could not be read.

    utf-8-sig rather than utf-8: a byte order mark is invisible in an editor
    and makes a plain read refuse the whole file over three bytes nobody can
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


def _entries(lock: dict) -> dict:
    """The lock's package map, or an explanation of why there is not one.

    npm 6 wrote an entirely different shape, keyed by name with the tree nested
    inside itself. Read as a modern lock it simply has no packages, so without
    this the answer would be a confident zero rather than a refusal.
    """
    if "packages" in lock:
        return lock["packages"]

    version = lock.get("lockfileVersion")
    if version == 1 or "dependencies" in lock:
        raise ManifestError(
            f"{LOCK} is lockfileVersion 1, written by npm 6; {REGENERATE} with npm 7 or newer"
        )
    raise ManifestError(f"{LOCK} lists no packages")


def _requested(manifest: dict) -> ParseResult:
    """What package.json asked for, before the lock decided any versions."""
    result = ParseResult()

    for field in PROJECT_FIELDS:
        for name, spec in (manifest.get(field) or {}).items():
            if spec.startswith(LOCAL_PREFIXES):
                # Somewhere on disk, so there is no release to look up. Recorded
                # rather than dropped, so the report can say what it did not read.
                result.skipped.append(SkippedLine(0, f"{name}@{spec}", SkipReason.LOCAL_PATH))
            else:
                result.dependencies.append(Dependency(name=name, raw_spec=spec))

    return result


def _installed(entries: dict) -> DependencyGraph:
    """Walk the lock into a graph, breadth first from the direct dependencies.

    Breadth first for the same reason as the Python resolver: depth becomes the
    shortest route to a package, which is the most useful answer to "why is
    this here".
    """
    graph = DependencyGraph()
    packages = {
        path: _key(path, entry) for path, entry in entries.items() if _is_package(path, entry)
    }

    # Direct dependencies are what the root asked for, plus every workspace
    # package. A workspace package is code the project ships rather than
    # something it pulled in, and `npm ls` lists them alongside the root's own
    # dependencies for that reason.
    direct = _paths_required_by("", entries, packages, PROJECT_FIELDS)
    direct += [path for path in _workspace_packages(entries) if path in packages]

    queue: deque[tuple[str, int, PackageKey | None]] = deque((path, 0, None) for path in direct)

    seen: set[str] = set()
    while queue:
        path, depth, parent = queue.popleft()
        key = packages[path]

        # Before the visited check, so every requester gets an edge and not
        # just the first one to arrive. That list is what `dependents_of`
        # reads to name the package a user actually has to upgrade.
        _record(graph, key, parent)

        if path in seen:
            continue
        seen.add(path)
        graph.add_node(key, depth, parent=parent)

        fields = PROJECT_FIELDS if _is_workspace(path) else INSTALLED_PACKAGE_FIELDS
        for target in _paths_required_by(path, entries, packages, fields):
            queue.append((target, depth + 1, key))

    return graph


def _workspace_packages(entries: dict) -> list[str]:
    """The project's own packages: real directories, not installs.

    A monorepo lists each of these twice - once as the directory holding the
    code, and once as a link under node_modules so its siblings can import it.
    This finds the first kind, which is the one with the dependencies on it.
    """
    return [path for path in entries if path and "node_modules/" not in path]


def _is_workspace(install_path: str) -> bool:
    """Whether this entry is the project's own code rather than a dependency.

    It decides which requirement fields apply: a workspace package's
    devDependencies are installed, exactly like the root's.
    """
    return "node_modules/" not in install_path


def _paths_required_by(
    requirer: str, entries: dict, packages: dict[str, PackageKey], fields: tuple[str, ...]
) -> list[str]:
    """Where to find each package this one requires.

    A requirement that resolves to nothing installed is dropped rather than
    reported: an optional peer dependency nobody supplied is the ordinary
    reason, and it is not a fault in the manifest.
    """
    found = []
    for name in _required_by(entries[requirer], fields):
        path = _copy_visible_to(requirer, name, entries)
        if path and path in packages:
            found.append(path)
    return found


def _record(graph: DependencyGraph, key: PackageKey, parent: PackageKey | None) -> None:
    """Note how we arrived at a package: an edge, or a place in the roots."""
    if parent is None:
        if key not in graph.roots:
            graph.roots.append(key)
    else:
        graph.add_edge(parent, key)


def _is_package(install_path: str, entry: dict) -> bool:
    """Whether this entry is a release that can be looked up.

    The root entry describes the project, and a link entry names a directory;
    neither is something an advisory database has ever heard of.
    """
    return bool(install_path) and not entry.get("link") and bool(entry.get("version"))


def _key(install_path: str, entry: dict) -> PackageKey:
    return PackageKey(_package_name(install_path, entry), entry["version"], EcoSystem.NPM)


def _package_name(install_path: str, entry: dict) -> str:
    """The name the registry knows this package by.

    An entry carries `name` when that differs from where it was installed:
    `"utils": "npm:lodash@4.17.15"` puts lodash in node_modules/utils. Reading
    the name off the path would ask OSV about `utils`, which has no advisories,
    so a package with six of them comes back clean. The path is a location; the
    field is the identity.
    """
    if entry.get("name"):
        return str(entry["name"])
    return install_path.rsplit("node_modules/", 1)[-1]


def _required_by(entry: dict, fields: tuple[str, ...]) -> list[str]:
    """The packages one entry pulls in, across the fields that apply to it."""
    return [name for field in fields for name in (entry.get(field) or {})]


def _copy_visible_to(requirer: str, name: str, entries: dict) -> str | None:
    """Which copy of `name` the package at `requirer` actually sees.

    Node looks in the requirer's own node_modules first, then its parent's, and
    so on out to the project root, so a copy nested deep shadows the one above
    it. That is how one project installs `ms` at three versions at once, and
    why a lock path rather than a package name identifies a node here.

        node_modules/send  needs  ms
          node_modules/send/node_modules/ms   <- found, 2.0.0
          node_modules/ms                        (2.1.3, not used by send)
    """
    prefix = requirer
    while True:
        candidate = f"{prefix}/node_modules/{name}" if prefix else f"node_modules/{name}"
        if candidate in entries:
            return _follow_link(candidate, entries)
        if not prefix:
            return None
        prefix = prefix.rsplit("/node_modules/", 1)[0] if "/node_modules/" in prefix else ""


def _follow_link(install_path: str, entries: dict) -> str:
    """Where a link entry actually points.

    A workspace package appears under node_modules as `{"link": true,
    "resolved": "packages/api"}` - a signpost to the directory holding the
    code. Stopping at the signpost loses every edge into a sibling package.
    """
    entry = entries[install_path]
    target = entry.get("resolved")
    if entry.get("link") and target in entries:
        return str(target)
    return install_path
