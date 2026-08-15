"""Readers that turn a manifest file into what it installs.

One module per format, each with a single `parse` function. What they return
differs, and deliberately so: a requirements.txt names ranges that still have
to be resolved against a registry, while a lock file names versions somebody
already committed, so it can hand back a finished graph.

`package_json` and `lock_walk` hold what the two JavaScript readers share.
"""


class ManifestError(Exception):
    """A manifest that could not be read at all.

    Raised only when there is nothing to scan - a missing lock file, JSON that
    does not parse, a format we do not support. A file we can read but that
    contains an awkward line is read anyway, and the line is recorded in
    `ParseResult.skipped` instead, so a scan is never quietly narrowed.

    The message is written for the person running the tool, and names the
    command that fixes the problem wherever there is one.
    """
