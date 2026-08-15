"""Readers that turn a manifest file into what it installs.

One module per format, each with a single `parse` function. What they return
differs, and deliberately so: a requirements.txt names ranges that still have
to be resolved against a registry, while a lock file names versions somebody
already committed, so it can hand back a finished graph.
"""

import json
from pathlib import Path


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
