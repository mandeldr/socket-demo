"""Check our reading of a lock file against npm's own.

Every test under tests/manifests asserts that the code does what the code was
written to do. These ask npm instead. `npm ls --all --json --package-lock-only`
reads the same lock file and reports the tree it describes, so any package it
lists and we do not is a package whose vulnerabilities we would never look for.

That check is what was missing when the Python resolver quietly reported one
package at two versions, and it is why this exists before there is anything to
demo.

Unlike test_against_pip.py this needs **no network** - `--package-lock-only`
reads the file and nothing else - so it runs in the ordinary suite rather than
behind the `network` marker. It needs npm on PATH, and skips without it.
"""

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from scanner.manifests import package_lock
from scanner.manifests.package_lock import _is_package, _package_name

FIXTURES = Path(__file__).parent / "fixtures" / "npm"

# Lock files where every package is installed under its own name, so npm's
# names and ours are directly comparable. `hostile` is excluded on purpose and
# gets its own test below.
COMPARABLE = ["nested", "monorepo", "nodegoat"]


def what_npm_installs(project: Path) -> set[str]:
    """The tree npm reads out of the lock, as {name@version}."""
    result = subprocess.run(
        ["npm", "ls", "--all", "--json", "--package-lock-only"],
        cwd=project,
        capture_output=True,
        text=True,
    )
    # npm exits non-zero when the tree has any complaint in it - an unmet
    # optional peer is enough - but still writes the tree, which is what we
    # are comparing against.
    if not result.stdout:
        pytest.skip(f"npm ls produced nothing: {result.stderr.strip()[:200]}")

    installed: set[str] = set()

    def descend(node: dict) -> None:
        for name, child in (node.get("dependencies") or {}).items():
            if child.get("version"):
                installed.add(f"{name}@{child['version']}")
            descend(child)

    descend(json.loads(result.stdout))
    return installed


def what_we_read(project: Path) -> set[str]:
    _, graph = package_lock.parse(project / "package.json")
    return {f"{key.name}@{key.version}" for key in graph.nodes}


@pytest.fixture(scope="module", params=COMPARABLE)
def comparison(request) -> tuple[set[str], set[str], Path]:
    if shutil.which("npm") is None:
        pytest.skip("npm is not installed")
    project = FIXTURES / request.param
    return what_npm_installs(project), what_we_read(project), project


def test_we_miss_nothing_npm_installs(comparison) -> None:
    """The number that matters most: a package we never read is a package whose
    vulnerabilities we never look for."""
    npm, ours, _ = comparison

    assert sorted(npm - ours) == []


def test_we_report_nothing_npm_does_not_install(comparison) -> None:
    """The other direction. An extra package is a finding against something the
    user does not have, which is worse than a miss because it looks like work."""
    npm, ours, _ = comparison

    assert sorted(ours - npm) == []


def test_every_edge_lands_on_a_package_we_read(comparison) -> None:
    """A dangling edge means `path_to` and `dependents_of` are answering with a
    package that is not in the graph, which is how remediation advice starts
    naming things that do not exist."""
    _, _, project = comparison
    _, graph = package_lock.parse(project / "package.json")

    dangling = [
        (node.key.name, child.name)
        for node in graph.nodes.values()
        for child in node.children
        if child not in graph.nodes
    ]

    assert dangling == []


def test_every_package_in_the_lock_is_reachable_from_a_direct_dependency(comparison) -> None:
    """The graph is built by walking out from the roots, so a package nothing
    leads to is never added - it would be in the file, absent from the scan,
    and counted in neither. Compared against the lock rather than against the
    graph, because the graph cannot disagree with how it was built.
    """
    _, _, project = comparison
    entries = json.loads((project / "package-lock.json").read_text())["packages"]

    in_the_lock = {
        f"{_package_name(path, entry)}@{entry['version']}"
        for path, entry in entries.items()
        if _is_package(path, entry)
    }

    assert sorted(in_the_lock - what_we_read(project)) == []


def test_the_direct_count_matches_the_manifest() -> None:
    """NodeGoat names 16 dependencies and 20 devDependencies. Both are things
    the project asked for, so both are direct - getting this wrong strands the
    dev subtree and reports it as a smaller scan rather than as a fault."""
    project = FIXTURES / "nodegoat"
    manifest = json.loads((project / "package.json").read_text())

    parsed, graph = package_lock.parse(project / "package.json")

    declared = len(manifest["dependencies"]) + len(manifest["devDependencies"])
    assert declared == 36
    assert len(parsed.dependencies) == declared
    assert len(graph.roots) == declared


def test_a_real_project_resolves_at_scale() -> None:
    """1,390 lock entries collapsing to 1,073 packages, nested twelve deep."""
    _, graph = package_lock.parse(FIXTURES / "nodegoat" / "package.json")

    assert len(graph.nodes) == 1073
    assert max(node.depth for node in graph.nodes.values()) == 12


def test_an_alias_is_where_we_deliberately_differ_from_npm() -> None:
    """`npm ls` reports an aliased dependency under the name it was declared as,
    because it is describing the tree on disk. We report the name the registry
    knows, because we are about to ask an advisory database about it - and
    `utils` has no advisories while `lodash@4.17.11` has several.

    Both are right for their own purpose, which is why the set comparisons above
    skip this fixture rather than pretending it should match.
    """
    if shutil.which("npm") is None:
        pytest.skip("npm is not installed")
    project = FIXTURES / "hostile"

    npm = what_npm_installs(project)
    ours = what_we_read(project)

    assert "utils@4.17.11" in npm
    assert "lodash@4.17.11" in ours
    # Every difference is an alias, and nothing is missing for any other reason.
    assert npm - ours == {"utils@4.17.11", "debug-from-git@4.3.4"}
    assert ours - npm == {"lodash@4.17.11", "debug@4.3.4"}
