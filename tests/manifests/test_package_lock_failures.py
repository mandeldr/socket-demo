"""What happens when the files are wrong, missing, or merely nasty.

Two rules here. A file we cannot read at all raises ManifestError carrying the
reason and, where there is one, the command that fixes it - never a traceback.
A file we can read but that contains something awkward is read anyway, and the
awkward part is reported rather than dropped.

The fixture under tests/fixtures/npm/hostile is the JS counterpart of
hostile.txt: everything real manifests do that should not take a scan down.
"""

import json
from pathlib import Path

import pytest

from scanner.manifests import ManifestError, package_lock

FIXTURES = Path(__file__).parent.parent / "fixtures" / "npm"


def project(directory: Path, manifest: str, lock: str | None) -> Path:
    """Write the pair as raw text, so a test can write something invalid."""
    (directory / "package.json").write_text(manifest)
    if lock is not None:
        (directory / "package-lock.json").write_text(lock)
    return directory / "package.json"


def names_in(graph) -> set[str]:
    return {f"{node.key.name}@{node.key.version}" for node in graph.nodes.values()}


VALID_LOCK = json.dumps(
    {
        "lockfileVersion": 3,
        "packages": {
            "": {"dependencies": {"a": "^1"}},
            "node_modules/a": {"version": "1.0.0"},
        },
    }
)


# --- files we cannot read --------------------------------------------------


def test_a_missing_lock_file_names_the_command_that_makes_one(tmp_path: Path) -> None:
    """The one thing a user needs is the next thing to type."""
    manifest = project(tmp_path, '{"name": "x", "dependencies": {"a": "^1"}}', None)

    with pytest.raises(ManifestError) as raised:
        package_lock.parse(manifest)

    assert "npm install --package-lock-only" in str(raised.value)


def test_a_missing_package_json_is_reported(tmp_path: Path) -> None:
    (tmp_path / "package-lock.json").write_text(VALID_LOCK)

    with pytest.raises(ManifestError) as raised:
        package_lock.parse(tmp_path / "package-lock.json")

    assert "package.json" in str(raised.value)


def test_invalid_json_says_which_file_and_where(tmp_path: Path) -> None:
    """A trailing comma is the usual cause, and npm rejects it too."""
    manifest = project(tmp_path, '{"name": "x", "dependencies": {"a": "^1",},}', VALID_LOCK)

    with pytest.raises(ManifestError) as raised:
        package_lock.parse(manifest)

    message = str(raised.value)
    assert "package.json" in message
    assert "line 1" in message


def test_a_lock_that_is_not_an_object_is_reported(tmp_path: Path) -> None:
    """Valid JSON, wrong shape - which would otherwise be a TypeError."""
    manifest = project(tmp_path, '{"name": "x"}', '[{"name": "x"}]')

    with pytest.raises(ManifestError) as raised:
        package_lock.parse(manifest)

    assert "package-lock.json" in str(raised.value)


def test_lockfile_version_1_is_named_rather_than_guessed_at(tmp_path: Path) -> None:
    """npm 6 wrote a different shape entirely. Reading it as a v3 file finds no
    packages, so without this the answer is a confident zero."""
    v1 = json.dumps({"lockfileVersion": 1, "dependencies": {"a": {"version": "1.0.0"}}})
    manifest = project(tmp_path, '{"name": "x"}', v1)

    with pytest.raises(ManifestError) as raised:
        package_lock.parse(manifest)

    message = str(raised.value)
    assert "lockfileVersion 1" in message
    assert "npm install --package-lock-only" in message


def test_a_lock_with_no_packages_at_all_is_reported(tmp_path: Path) -> None:
    manifest = project(tmp_path, '{"name": "x"}', '{"name": "x", "version": "1.0.0"}')

    with pytest.raises(ManifestError):
        package_lock.parse(manifest)


# --- files we can read, awkwardly ------------------------------------------


def test_a_byte_order_mark_is_read_not_rejected(tmp_path: Path) -> None:
    """Windows editors write one. It is invisible on screen and makes a plain
    json.load refuse the entire file."""
    (tmp_path / "package.json").write_bytes(
        b"\xef\xbb\xbf" + b'{"name": "x", "dependencies": {"a": "^1"}}'
    )
    (tmp_path / "package-lock.json").write_bytes(b"\xef\xbb\xbf" + VALID_LOCK.encode())

    parsed, graph = package_lock.parse(tmp_path / "package.json")

    assert len(parsed.dependencies) == 1
    assert names_in(graph) == {"a@1.0.0"}


def test_a_project_with_no_dependencies_scans_nothing_without_failing(tmp_path: Path) -> None:
    empty = json.dumps({"lockfileVersion": 3, "packages": {"": {}}})
    manifest = project(tmp_path, '{"name": "x", "version": "1.0.0"}', empty)

    parsed, graph = package_lock.parse(manifest)

    assert parsed.dependencies == []
    assert graph.nodes == {}


def test_a_null_dependencies_field_is_treated_as_empty(tmp_path: Path) -> None:
    manifest = project(tmp_path, '{"name": "x", "dependencies": null}', VALID_LOCK)

    parsed, _ = package_lock.parse(manifest)

    assert parsed.dependencies == []


# --- shapes that could loop forever ----------------------------------------


def test_a_dependency_cycle_terminates(tmp_path: Path) -> None:
    """npm allows a to require b requiring a. The visited set is what ends the
    walk, exactly as it does in the Python resolver - there is no depth limit
    here either."""
    lock = json.dumps(
        {
            "lockfileVersion": 3,
            "packages": {
                "": {"dependencies": {"a": "1"}},
                "node_modules/a": {"version": "1.0.0", "dependencies": {"b": "1"}},
                "node_modules/b": {"version": "1.0.0", "dependencies": {"a": "1"}},
            },
        }
    )
    manifest = project(tmp_path, '{"name": "x", "dependencies": {"a": "1"}}', lock)

    _, graph = package_lock.parse(manifest)

    assert names_in(graph) == {"a@1.0.0", "b@1.0.0"}


def test_a_package_that_requires_itself_terminates(tmp_path: Path) -> None:
    lock = json.dumps(
        {
            "lockfileVersion": 3,
            "packages": {
                "": {"dependencies": {"a": "1"}},
                "node_modules/a": {"version": "1.0.0", "dependencies": {"a": "1"}},
            },
        }
    )
    manifest = project(tmp_path, '{"name": "x", "dependencies": {"a": "1"}}', lock)

    _, graph = package_lock.parse(manifest)

    assert names_in(graph) == {"a@1.0.0"}


def test_a_cycle_still_records_both_directions(tmp_path: Path) -> None:
    """Terminating must not mean losing the edge that closed the loop, or
    `dependents_of` names the wrong package to upgrade."""
    lock = json.dumps(
        {
            "lockfileVersion": 3,
            "packages": {
                "": {"dependencies": {"a": "1"}},
                "node_modules/a": {"version": "1.0.0", "dependencies": {"b": "1"}},
                "node_modules/b": {"version": "1.0.0", "dependencies": {"a": "1"}},
            },
        }
    )
    manifest = project(tmp_path, '{"name": "x", "dependencies": {"a": "1"}}', lock)

    _, graph = package_lock.parse(manifest)
    a = next(k for k in graph.nodes if k.name == "a")
    b = next(k for k in graph.nodes if k.name == "b")

    assert graph.nodes[a].children == [b]
    assert graph.nodes[b].children == [a]


# --- requirements that resolve to nothing ----------------------------------


def test_an_uninstalled_optional_peer_is_not_an_error(tmp_path: Path) -> None:
    """A peer marked optional that nobody supplied is the ordinary case, not a
    broken manifest."""
    lock = json.dumps(
        {
            "lockfileVersion": 3,
            "packages": {
                "": {"dependencies": {"a": "1"}},
                "node_modules/a": {"version": "1.0.0", "peerDependencies": {"react": "^18"}},
            },
        }
    )
    manifest = project(tmp_path, '{"name": "x", "dependencies": {"a": "1"}}', lock)

    _, graph = package_lock.parse(manifest)

    assert names_in(graph) == {"a@1.0.0"}
    assert graph.errors == []


def test_a_requirement_with_no_lock_entry_is_skipped(tmp_path: Path) -> None:
    lock = json.dumps(
        {
            "lockfileVersion": 3,
            "packages": {
                "": {"dependencies": {"a": "1"}},
                "node_modules/a": {"version": "1.0.0", "dependencies": {"ghost": "1"}},
            },
        }
    )
    manifest = project(tmp_path, '{"name": "x", "dependencies": {"a": "1"}}', lock)

    _, graph = package_lock.parse(manifest)
    a = next(k for k in graph.nodes if k.name == "a")

    assert graph.nodes[a].children == []


# --- the hostile fixture ---------------------------------------------------


def hostile():
    return package_lock.parse(FIXTURES / "hostile" / "package.json")


def test_the_hostile_manifest_is_read() -> None:
    """Alias, local path, git reference and an optional peer in one file."""
    _, graph = hostile()

    assert len(graph.nodes) == 5


def test_a_git_dependency_uses_its_registry_name_and_version() -> None:
    """`debug-from-git` is a git URL in package.json; the lock records what it
    resolved to, and `debug` is the name OSV answers about."""
    _, graph = hostile()

    assert "debug@4.3.4" in names_in(graph)
    assert not any(k.name == "debug-from-git" for k in graph.nodes)


def test_two_copies_of_one_package_under_different_names() -> None:
    """`lodash` directly and `utils` aliased to an older lodash."""
    _, graph = hostile()

    assert {k.version for k in graph.nodes if k.name == "lodash"} == {"4.17.11", "4.17.15"}


def test_the_local_path_dependency_is_skipped() -> None:
    parsed, _ = hostile()

    assert [s.content for s in parsed.skipped] == ["local-lib@file:./local-lib"]


def test_the_uninstalled_optional_peer_leaves_no_error() -> None:
    """react is declared optional and npm did not install it."""
    _, graph = hostile()

    assert not any(k.name == "react" for k in graph.nodes)
    assert graph.errors == []


# --- when the two files disagree -------------------------------------------


def test_the_graph_follows_the_lock_and_the_count_follows_the_manifest(tmp_path: Path) -> None:
    """A package.json edited without re-running npm install says one thing and
    the lock says another. The lock is what is installed, so it decides what
    gets scanned; package.json is what was asked for, so it decides the count.
    Reporting both is how the mismatch becomes visible rather than silent.
    """
    lock = json.dumps(
        {
            "lockfileVersion": 3,
            "packages": {
                "": {"dependencies": {"a": "^1"}},
                "node_modules/a": {"version": "1.0.0"},
            },
        }
    )
    manifest = project(tmp_path, '{"name": "x", "dependencies": {"a": "^1", "b": "^2"}}', lock)

    parsed, graph = package_lock.parse(manifest)

    assert len(parsed.dependencies) == 2  # package.json asked for two
    assert names_in(graph) == {"a@1.0.0"}  # the lock installed one
