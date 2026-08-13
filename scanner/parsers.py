import re
from collections.abc import Iterator
from itertools import takewhile
from pathlib import Path

from packaging.requirements import InvalidRequirement, Requirement

from scanner.enums import EcoSystem, SkipReason
from scanner.models import Dependency, PackageKey, ParseResult, SkippedLine

# pip's own comment pattern (pip/_internal/req/req_file.py): "#" starts a
# comment at the beginning of a line or after whitespace. A URL fragment like
# #egg=name has no whitespace before it, so it survives.
COMMENT_RE = re.compile(r"(^|\s+)#.*$")


def parse_requirements_txt(path: Path) -> ParseResult:
    """Parse a pip requirements file into direct dependencies.

    Lines that are not requirements are recorded with a reason rather than
    dropped, so the report can say what it did not read.
    """
    result = ParseResult()

    for number, line in _logical_lines(Path(path).read_text()):
        reason = _skip_reason(line)
        if reason:
            result.skipped.append(SkippedLine(number, line, reason))
            continue

        try:
            req = Requirement(line)
        except InvalidRequirement:
            result.skipped.append(SkippedLine(number, line, SkipReason.INVALID))
            continue

        result.dependencies.append(
            Dependency(
                key=PackageKey(req.name, _pinned_version(req), EcoSystem.PYTHON),
                raw_spec=str(req.specifier),
                extras=frozenset(req.extras),
            )
        )

    return result


def _logical_lines(text: str) -> Iterator[tuple[int, str]]:
    """Yield (line number, content) for each requirement in the file.

    A line ending in a backslash continues onto the next one, which is how
    `pip-compile` and `pip freeze --require-hashes` write every pin: the
    requirement on one line and its hashes on the following ones. Reading those
    separately turns the most carefully pinned manifests into nothing but
    unparseable lines.

    The number reported is the line the requirement started on, since that is
    where a reader would go to fix it.
    """
    joined: list[str] = []
    start = 0

    for number, raw in enumerate(text.splitlines(), start=1):
        content = COMMENT_RE.sub("", raw).strip()
        if not joined:
            start = number

        if content.endswith("\\"):
            joined.append(content[:-1].strip())
            continue

        joined.append(content)
        line = _without_options(" ".join(part for part in joined if part))
        joined = []
        if line:
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
    but only the first half is a requirement `packaging` can read. A line that
    is nothing but an option is left alone so it can be reported as one.
    """
    if line.startswith("-"):
        return line

    tokens = line.split()
    kept = takewhile(lambda token: not token.startswith("--"), tokens)
    return " ".join(kept)


def _skip_reason(line: str) -> SkipReason | None:
    """Identify lines that are not requirement specifiers."""
    if line.startswith(("-e", "--editable")):
        return SkipReason.EDITABLE
    if line.startswith("-"):
        return SkipReason.PIP_OPTION
    if line.startswith(("git+", "hg+", "svn+", "bzr+")):
        return SkipReason.VCS
    if "://" in line:
        return SkipReason.DIRECT_URL
    return None


def _pinned_version(req: Requirement) -> str | None:
    """Return the exact version, or None if the requirement is a range."""
    return next((s.version for s in req.specifier if s.operator == "=="), None)
