"""Check our resolution against a real resolver.

Every other test asserts that the code does what the code was written to do.
These compare the answer against `uv pip compile`, which implements the same
standards independently - the check that was missing when this resolver quietly
reported a package at two versions.

Needs the network and a few seconds, so it is deselected by default:

    pytest -m network
"""

import shutil
import subprocess
from pathlib import Path

import pytest
from packaging.utils import canonicalize_name

from scanner.manifests import requirements_txt
from scanner.pypi import PyPIClient
from scanner.resolver import resolve

pytestmark = pytest.mark.network

FIXTURE = Path(__file__).parent / "fixtures" / "requirements.txt"


def what_uv_would_install(manifest: Path) -> dict[str, str]:
    """The pinned set `uv pip compile` produces, as {name: version}."""
    result = subprocess.run(
        # No -o: uv writes to stdout by default. Passing `-o -` also writes a
        # file literally named `-` into the working directory, which is how one
        # got committed to this repo.
        ["uv", "pip", "compile", str(manifest), "--no-annotate", "--no-header"],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        pytest.skip(f"uv could not resolve the fixture: {result.stderr.strip()[:200]}")

    pinned: dict[str, str] = {}
    for line in result.stdout.splitlines():
        line = line.split("#")[0].strip()
        if "==" in line:
            name, _, version = line.partition("==")
            pinned[str(canonicalize_name(name.strip()))] = version.strip()
    return pinned


def what_we_resolve(manifest: Path) -> dict[str, set[str | None]]:
    graph = resolve(requirements_txt.parse(manifest).dependencies, PyPIClient().fetch)
    resolved: dict[str, set[str | None]] = {}
    for node in graph.nodes.values():
        if not node.failed:
            resolved.setdefault(node.key.name, set()).add(node.key.version)
    return resolved


@pytest.fixture(scope="module")
def comparison() -> tuple[dict, dict]:
    if shutil.which("uv") is None:
        pytest.skip("uv is not installed")
    return what_uv_would_install(FIXTURE), what_we_resolve(FIXTURE)


def test_we_miss_nothing_uv_would_install(comparison) -> None:
    """The number that matters most: a package we never resolved is a package
    whose vulnerabilities we never looked for."""
    uv, ours = comparison

    assert sorted(set(uv) - set(ours)) == []


def test_no_package_is_resolved_at_two_versions(comparison) -> None:
    """The regression this file exists for. Left unchecked it reached 434 of
    805 packages on a real manifest, none of which the test suite noticed."""
    _, ours = comparison

    doubled = {name: sorted(v) for name, v in ours.items() if len(v) > 1}

    assert doubled == {}


def test_the_versions_we_pick_are_the_ones_uv_picks(comparison) -> None:
    """Where we do not backtrack our answer can differ, so this allows a small
    number of mismatches rather than none - but not a growing number."""
    uv, ours = comparison

    differing = {
        name: (sorted(versions)[0], uv[name])
        for name, versions in ours.items()
        if name in uv and versions != {uv[name]}
    }

    assert len(differing) <= 1, f"resolution drifted from uv: {differing}"


def test_we_are_a_superset_for_a_reason(comparison) -> None:
    """Anything extra should be a marker-guarded package uv dropped for this
    interpreter - we keep those deliberately, since a manifest scanned on a Mac
    may be installed on Windows."""
    uv, ours = comparison

    extra = sorted(set(ours) - set(uv))

    assert extra == ["colorama", "importlib-metadata", "typing-extensions", "zipp"]
