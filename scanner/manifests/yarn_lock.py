"""Reading a package.json and its yarn.lock into the packages they install.

Yarn is the simpler of the two lock formats. It is flat - no nesting, so no
walking up a directory tree - and every entry is keyed by the requirement that
produced it. `express` needing `debug "2.6.9"` is answered by looking up the
key `debug@2.6.9`, which means resolving an edge is a dictionary lookup and no
version comparison happens anywhere in this file.

The cost is two readers. Yarn 1 wrote a format that looks like YAML and is not,
and berry writes real YAML with a different shape again. They are normalized
into one map of `name@range` -> entry, after which the walk is shared.
"""

from pathlib import Path
from typing import NamedTuple

import yaml

from scanner.enums import Ecosystem
from scanner.graph import DependencyGraph
from scanner.manifests import ManifestError, package_json
from scanner.manifests.lock_walk import walk
from scanner.manifests.package_json import YARN_FIELDS as PROJECT_FIELDS
from scanner.manifests.package_json import requested
from scanner.models import PackageKey, ParseResult

LOCK = "yarn.lock"

REGENERATE = "run `yarn install` to generate one"

# Berry writes ranges with a protocol - `npm:^1.0.0` where yarn 1 writes
# `^1.0.0`. Dropping it is what lets one lookup serve both formats and the
# ranges written in package.json.
NPM_PROTOCOL = "npm:"

# Berry's file header. It parses as an entry and is not a package.
METADATA_KEY = "__metadata"

# What an installed package pulls in, in either format. peerDependencies is
# absent on purpose: yarn does not install a dependency's peers the way npm 7
# and later do, so following them here would report packages yarn never put on
# disk. Both readers use this list, so the same project scans the same whether
# yarn 1 or berry wrote the lock.
REQUIRE_FIELDS = ("dependencies", "optionalDependencies")


class _Entry(NamedTuple):
    """One resolution: what it turned out to be, and what it needs."""

    name: str
    version: str
    # Requirement name -> range, exactly as the lock wrote it.
    requires: dict[str, str]


def parse(path: Path) -> tuple[ParseResult, DependencyGraph]:
    """Read a package.json and the yarn.lock beside it."""
    directory = path.parent

    manifest = package_json.load(directory / package_json.NAME)
    entries = _entries(_read_lock(directory / LOCK))

    return requested(manifest, PROJECT_FIELDS), _installed(manifest, entries)


def _read_lock(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8-sig")
    except OSError:
        raise ManifestError(f"{package_json.NAME} has no {LOCK} beside it; {REGENERATE}") from None


def _entries(text: str) -> dict[str, _Entry]:
    """The lock as one map, keyed by the requirement each entry answers."""
    raw = _berry_entries(text) if _is_berry(text) else _v1_entries(text)

    entries: dict[str, _Entry] = {}
    for descriptor, (version, requires) in raw.items():
        name, spec = _split_descriptor(descriptor)
        entries[_descriptor(name, spec)] = _Entry(_registry_name(name, spec), version, requires)
    return entries


def _is_berry(text: str) -> bool:
    """Berry announces itself with a __metadata block; yarn 1 never has one.

    Matched as a line of its own rather than anywhere in the file, so a package
    or URL that happens to contain the word does not switch the reader.
    """
    return any(line.startswith(METADATA_KEY) for line in text.splitlines())


def _berry_entries(text: str) -> dict[str, tuple[str, dict[str, str]]]:
    """Berry writes real YAML, so this is a load and a reshape."""
    try:
        loaded = yaml.safe_load(text) or {}
    except yaml.YAMLError as exc:
        raise ManifestError(f"{LOCK} is not valid YAML: {exc}") from None

    entries = {}
    for descriptors, body in loaded.items():
        if descriptors == METADATA_KEY or not isinstance(body, dict):
            continue
        version = body.get("version")
        if version is None:
            continue
        requires = {
            name: spec for field in REQUIRE_FIELDS for name, spec in (body.get(field) or {}).items()
        }
        # One key can carry several descriptors, comma separated, as in v1.
        for descriptor in descriptors.split(", "):
            entries[descriptor.strip().strip('"')] = (str(version), requires)
    return entries


def _v1_entries(text: str) -> dict[str, tuple[str, dict[str, str]]]:
    """Read a yarn 1 lock, which looks like YAML and is not.

    A YAML parser fails on the first `dependencies:` block, because the entries
    under it are `name "range"` pairs with no colon. The format is small enough
    to read directly: entries start in column zero, their fields are indented
    two, and a dependency list is indented four.

    Both PyPI yarn.lock libraries were measured against this and leave a comma
    separated key joined, so a lookup for either range finds nothing. That is
    roughly one edge in twelve on a real lock, silently unresolved, which is
    why this is twenty lines rather than a dependency.
    """
    entries: dict[str, tuple[str, dict[str, str]]] = {}
    descriptors: list[str] = []
    version = ""
    requires: dict[str, str] = {}
    in_requires = False

    def flush() -> None:
        for descriptor in descriptors:
            if version:
                entries[descriptor] = (version, dict(requires))

    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip())

        if indent == 0:
            flush()
            descriptors = [d.strip().strip('"') for d in line.rstrip(":").split(", ")]
            version, requires, in_requires = "", {}, False
        elif indent == 2:
            field, _, value = line.partition(" ")
            in_requires = field.rstrip(":") in REQUIRE_FIELDS
            if field.rstrip(":") == "version":
                version = value.strip().strip('"')
        elif in_requires:
            name, _, spec = line.partition(" ")
            requires[name.strip('"').rstrip(":")] = spec.strip().strip('"')

    flush()
    return entries


def _split_descriptor(descriptor: str) -> tuple[str, str]:
    """`express@4.17.1` -> ("express", "4.17.1").

    Split on the first `@` after position zero, so a scope survives:
    `@babel/core@^7.0.0` is one name and one range, not three pieces. Splitting
    on the last `@` instead would read an alias backwards.
    """
    at = descriptor.find("@", 1)
    if at == -1:
        return descriptor, ""
    return descriptor[:at], descriptor[at + 1 :]


def _descriptor(name: str, spec: str) -> str:
    """How a requirement is looked up, in either format."""
    return f"{name}@{_without_protocol(spec)}"


def _without_protocol(spec: str) -> str:
    return spec[len(NPM_PROTOCOL) :] if spec.startswith(NPM_PROTOCOL) else spec


def _registry_name(name: str, spec: str) -> str:
    """The name the registry knows this package by.

    Yarn has no `name` field the way npm's lock does. An alias is written into
    the range instead - `"utils": "npm:lodash@4.17.15"` - so the real name is
    everything between the protocol and the version.
    """
    if spec.startswith(NPM_PROTOCOL):
        aliased = spec[len(NPM_PROTOCOL) :]
        at = aliased.find("@", 1)
        if at != -1:
            return aliased[:at]
    return name


def _installed(manifest: dict, entries: dict[str, _Entry]) -> DependencyGraph:
    """Walk the lock into a graph.

    A location here is a `name@range` key, because that is what an entry
    answers to - and one entry often answers several.
    """

    def package_at(lookup: str) -> PackageKey:
        entry = entries[lookup]
        return PackageKey(entry.name, entry.version, Ecosystem.NPM)

    def required_by(lookup: str) -> list[str]:
        return _lookups_for(entries[lookup].requires, entries)

    return walk(_lookups_for(_direct(manifest), entries), package_at, required_by)


def _direct(manifest: dict) -> dict[str, str]:
    """Everything package.json asks for, as one name -> range map."""
    return {
        name: spec for field in PROJECT_FIELDS for name, spec in (manifest.get(field) or {}).items()
    }


def _lookups_for(requires: dict[str, str], entries: dict[str, _Entry]) -> list[str]:
    """The lookup key for each requirement that the lock actually answers.

    A requirement with no entry is dropped rather than reported: an optional
    dependency yarn chose not to install is the ordinary reason.
    """
    keys = [_descriptor(name, spec) for name, spec in requires.items()]
    return [key for key in keys if key in entries]
