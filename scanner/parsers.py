import re
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

    for number, raw in enumerate(Path(path).read_text().splitlines(), start=1):
        line = COMMENT_RE.sub("", raw).strip()
        if not line:
            continue

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
                is_direct=True,
                depth=0,
                parent=None,
            )
        )

    return result


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
