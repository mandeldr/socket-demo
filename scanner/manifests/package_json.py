"""Reading the package.json that both JavaScript lock formats start from.

npm and yarn write completely different lock files, but they answer the same
manifest, so what it means lives here once rather than in each reader.
"""

import json
from pathlib import Path

from scanner.enums import SkipReason
from scanner.manifests import ManifestError
from scanner.models import Dependency, ParseResult, SkippedLine

NAME = "package.json"

# A specifier naming somewhere on disk rather than a release on a registry.
# `portal:` is yarn's; the rest are shared.
LOCAL_PREFIXES = ("file:", "link:", "workspace:", "portal:")

# What a project's own package.json counts as asking for. The two lists differ
# by one field, and that difference is real rather than an oversight: npm 7 and
# later install a peerDependency declared at the root, and neither yarn 1 nor
# berry does. Locking the same manifest with all three puts react in npm's file
# and in neither yarn one.
#
# So they are kept next to each other, because the only way to notice a
# difference living in two modules is to go looking for it.
NPM_FIELDS = ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies")
YARN_FIELDS = ("dependencies", "devDependencies", "optionalDependencies")


def load(path: Path, missing: str | None = None) -> dict:
    """Read one JSON file of the pair, or say why it could not be read.

    Used for the lock file as well as the manifest: both are JSON, and both
    fail in the same four ways.

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
    """What the manifest asked for, before any lock decided versions.

    `fields` is passed in rather than assumed because npm and yarn disagree on
    whether a project's own peerDependencies count - see NPM_FIELDS above.
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
