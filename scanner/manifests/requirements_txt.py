"""Reading a requirements.txt into the requirements it asks for.

Lines that are not requirements - pip options, editable installs, VCS and URL
references - are recorded with a reason rather than dropped, so the report can
say what it did not read.
"""

import re
from collections.abc import Iterator
from itertools import takewhile
from pathlib import Path

from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import canonicalize_name

from scanner.enums import SkipReason
from scanner.models import Dependency, ParseResult, SkippedLine

# pip's own comment pattern (pip/_internal/req/req_file.py): "#" starts a
# comment at the beginning of a line or after whitespace. A URL fragment like
# #egg=name has no whitespace before it, so it survives.
COMMENT_RE = re.compile(r"(^|\s+)#.*$")


def parse(path: Path) -> ParseResult:
    """Parse a pip requirements file into direct dependencies.

    Three passes over each line: join continuations, decide whether it is a
    requirement at all, then let `packaging` read it.
    """
    result = ParseResult()

    for number, line in _logical_lines(Path(path).read_text()):
        # First: is this even a requirement? Options, VCS URLs and local paths
        # are recorded with a reason so the report can say what it did not read.
        reason = _skip_reason(line)
        if reason:
            result.skipped.append(SkippedLine(number, line, reason))
            continue

        # Second: hand the grammar to packaging rather than parsing it here.
        try:
            req = Requirement(line)
        except InvalidRequirement:
            result.skipped.append(SkippedLine(number, line, SkipReason.INVALID))
            continue

        result.dependencies.append(
            Dependency(
                name=canonicalize_name(req.name),
                raw_spec=str(req.specifier),
                extras=frozenset(req.extras),
            )
        )

    return result


def _logical_lines(text: str) -> Iterator[tuple[int, str]]:
    """Yield (line number, content) for each requirement in the file.

    A line ending in a backslash continues onto the next one. That is how
    `pip-compile` and `pip freeze --require-hashes` write every pin - the
    requirement on one line, its hashes indented below - so reading them
    separately would turn the most carefully pinned manifests into junk.

    The number reported is the line the requirement *started* on, since that
    is where a reader would go to fix it.
    """
    joined: list[str] = []  # parts of a requirement split across lines
    start = 0  # line number the current requirement began on

    for number, raw in enumerate(text.splitlines(), start=1):
        content = COMMENT_RE.sub("", raw).strip()
        # Empty `joined` means this line starts a new requirement.
        if not joined:
            start = number

        # Trailing backslash: hold this piece and keep reading.
        if content.endswith("\\"):
            joined.append(content[:-1].strip())
            continue

        joined.append(content)
        line = _without_options(" ".join(part for part in joined if part))
        joined = []  # reset for the next requirement
        if line:  # skips blank lines and comment-only lines
            yield start, line

    # A file ending on a backslash is malformed, but what came before it is
    # still a requirement worth reading.
    if joined:
        line = _without_options(" ".join(part for part in joined if part))
        if line:
            yield start, line


def _without_options(line: str) -> str:
    """Drop the per-requirement options pip allows after a specifier.

    `flask==3.0.0 --hash=sha256:...` is one requirement with a hash attached,
    and only the first half is something `packaging` can read.
    """
    # A line that is *only* an option is left whole, so _skip_reason can
    # recognise it and report it as a pip option.
    if line.startswith("-"):
        return line

    # Keep tokens up to the first `--`, which is where the options begin.
    tokens = line.split()
    kept = takewhile(lambda token: not token.startswith("--"), tokens)
    return " ".join(kept)


def _skip_reason(line: str) -> SkipReason | None:
    """Identify lines that are not requirement specifiers. None means "read it".

    Order matters: `-e` has to be tested before the general `-` case, or every
    editable install would be reported as a plain pip option.
    """
    if line.startswith(("-e", "--editable")):
        return SkipReason.EDITABLE
    if line.startswith("-"):
        return SkipReason.PIP_OPTION
    if line.startswith(("git+", "hg+", "svn+", "bzr+")):
        return SkipReason.VCS
    if line.startswith(("./", "../", "/", ".\\", "..\\")):
        # A path on disk, not a release on an index. Named for what it is, so
        # the report does not blame the manifest for syntax we simply skip.
        return SkipReason.LOCAL_PATH
    # Checked last: a VCS line also contains `://`, and VCS is the better name.
    if "://" in line:
        return SkipReason.DIRECT_URL
    return None
