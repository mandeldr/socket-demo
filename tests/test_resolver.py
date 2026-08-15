"""Tests for transitive dependency resolution.

The resolver takes a `fetch` callable so the graph logic can be tested without
touching the network. `fake_index` below builds one from a plain dict.
"""

from datetime import datetime, timezone

from packaging.requirements import Requirement
from packaging.version import Version

from scanner.enums import EcoSystem
from scanner.models import Dependency, PackageKey
from scanner.resolver import FetchResult, resolve


def key(name: str, version: str | None = "1.0") -> PackageKey:
    return PackageKey(name, version, EcoSystem.PYTHON)


def direct(*names: str) -> list[Dependency]:
    return [Dependency(n, raw_spec="==1.0") for n in names]


def versioned_index(index: dict[str, list[str]], versions: dict[str, list[str]]):
    """A fake PyPI that honours the constraint it is given.

    `fake_index` always answers "1.0"; this one picks the highest available
    version matching the spec, which is what makes constraint unification
    observable.
    """

    def fetch(name: str, spec, _extras=frozenset()) -> FetchResult:
        if name not in index:
            return FetchResult(error="no such package on PyPI")
        available = [Version(v) for v in versions.get(name, ["1.0"])]
        matching = list(spec.filter(available))
        if not matching:
            return FetchResult(error=f"no release satisfies {spec}")
        return FetchResult(str(max(matching)), [Requirement(r) for r in index[name]])

    return fetch


def fake_index(index: dict[str, list[str]]):
    """Build a fetch function from {package: [requirement strings]}."""

    def fetch(name: str, _spec, _extras=frozenset()) -> FetchResult:
        if name not in index:
            return FetchResult(error="no such package on PyPI")
        return FetchResult("1.0", [Requirement(r) for r in index[name]])

    return fetch


def names(graph) -> set[str]:
    return {k.name for k in graph.nodes}


def test_no_dependencies_gives_an_empty_graph() -> None:
    graph = resolve([], fake_index({}))
    assert graph.nodes == {}
    assert graph.roots == []


def test_a_leaf_dependency_is_a_single_node() -> None:
    graph = resolve(direct("flask"), fake_index({"flask": []}))
    assert names(graph) == {"flask"}
    assert graph.roots == [key("flask", "1.0")]
    assert graph.nodes[key("flask")].depth == 0


def test_a_child_is_resolved() -> None:
    graph = resolve(
        direct("flask"),
        fake_index({"flask": ["werkzeug==1.0"], "werkzeug": []}),
    )
    assert names(graph) == {"flask", "werkzeug"}
    assert graph.nodes[key("werkzeug")].depth == 1
    assert graph.nodes[key("flask")].children == [key("werkzeug")]


def test_a_chain_is_walked_to_the_end() -> None:
    graph = resolve(
        direct("a"),
        fake_index({"a": ["b==1.0"], "b": ["c==1.0"], "c": []}),
    )
    assert names(graph) == {"a", "b", "c"}
    assert graph.nodes[key("c")].depth == 2


def test_a_shared_dependency_is_visited_once() -> None:
    """The diamond: a -> b, a -> c, and both b and c depend on d."""
    graph = resolve(
        direct("a"),
        fake_index({"a": ["b==1.0", "c==1.0"], "b": ["d==1.0"], "c": ["d==1.0"], "d": []}),
    )
    assert names(graph) == {"a", "b", "c", "d"}
    assert len(graph.nodes) == 4  # d is not duplicated


def test_both_parents_of_a_shared_dependency_keep_the_edge() -> None:
    graph = resolve(
        direct("a"),
        fake_index({"a": ["b==1.0", "c==1.0"], "b": ["d==1.0"], "c": ["d==1.0"], "d": []}),
    )
    assert key("d") in graph.nodes[key("b")].children
    assert key("d") in graph.nodes[key("c")].children


def test_depth_is_the_shortest_path() -> None:
    """`d` is reachable at depth 1 and at depth 2; breadth-first finds 1 first."""
    graph = resolve(
        direct("a"),
        fake_index({"a": ["b==1.0", "d==1.0"], "b": ["c==1.0"], "c": ["d==1.0"], "d": []}),
    )
    assert graph.nodes[key("d")].depth == 1


def test_a_cycle_terminates() -> None:
    """The visited check is what stops this, not explicit cycle detection."""
    graph = resolve(
        direct("a"),
        fake_index({"a": ["b==1.0"], "b": ["a==1.0"]}),
    )
    assert names(graph) == {"a", "b"}


def test_a_self_referencing_package_terminates() -> None:
    graph = resolve(direct("a"), fake_index({"a": ["a==1.0"]}))
    assert names(graph) == {"a"}


def test_an_unknown_package_is_recorded_not_fatal() -> None:
    graph = resolve(
        direct("a"),
        fake_index({"a": ["ghost==1.0"], "b": []}),
    )
    # no version: we never got far enough to learn one
    assert graph.nodes[key("ghost", None)].failed is True
    assert graph.errors


def test_one_unknown_package_does_not_stop_the_others() -> None:
    graph = resolve(
        direct("a", "b"),
        fake_index({"b": []}),  # `a` is missing entirely
    )
    assert key("b") in graph.nodes
    assert graph.nodes[key("a", None)].failed is True


def test_duplicate_direct_dependencies_collapse() -> None:
    """`Flask` and `FLASK` canonicalize to one key."""
    deps = direct("Flask", "FLASK")
    graph = resolve(deps, fake_index({"flask": []}))
    assert len(graph.nodes) == 1
    assert graph.roots == [key("flask", "1.0")]


def test_dependents_of_answers_why_do_i_have_this() -> None:
    graph = resolve(
        direct("a"),
        fake_index({"a": ["b==1.0", "c==1.0"], "b": ["d==1.0"], "c": ["d==1.0"], "d": []}),
    )
    assert set(graph.dependents_of(key("d"))) == {key("b"), key("c")}


def test_direct_dependencies_are_the_roots() -> None:
    graph = resolve(
        direct("a", "b"),
        fake_index({"a": ["c==1.0"], "b": [], "c": []}),
    )
    assert set(graph.roots) == {key("a"), key("b")}
    assert key("c") not in graph.roots


def test_a_pinned_direct_dependency_keeps_its_version() -> None:
    """The manifest said flask==2.0.0, so latest is the wrong answer."""
    seen: list[str] = []

    def fetch(name: str, spec, _extras=frozenset()) -> FetchResult:
        seen.append(str(spec))
        return FetchResult("2.0.0", [])

    deps = [Dependency("flask", raw_spec="==2.0.0")]
    resolve(deps, fetch)
    assert seen == ["==2.0.0"]


def test_a_direct_dependency_has_no_parent() -> None:
    graph = resolve(direct("flask"), fake_index({"flask": []}))
    assert graph.nodes[key("flask")].parent is None


def test_a_transitive_dependency_records_how_it_was_reached() -> None:
    graph = resolve(
        direct("a"),
        fake_index({"a": ["b==1.0"], "b": ["c==1.0"], "c": []}),
    )
    assert graph.nodes[key("c")].parent == key("b")


def test_path_to_explains_why_a_package_is_present() -> None:
    graph = resolve(
        direct("a"),
        fake_index({"a": ["b==1.0"], "b": ["c==1.0"], "c": []}),
    )
    assert graph.path_to(key("c")) == [key("a"), key("b"), key("c")]


def test_path_to_a_direct_dependency_is_just_itself() -> None:
    graph = resolve(direct("flask"), fake_index({"flask": []}))
    assert graph.path_to(key("flask")) == [key("flask")]


def test_parent_is_the_shortest_route() -> None:
    """`d` is reachable via b (depth 2) and directly (depth 1)."""
    graph = resolve(
        direct("a"),
        fake_index({"a": ["b==1.0", "d==1.0"], "b": ["d==1.0"], "d": []}),
    )
    assert graph.nodes[key("d")].parent == key("a")
    assert graph.path_to(key("d")) == [key("a"), key("d")]


def test_the_last_release_date_reaches_the_graph() -> None:
    """The report needs it to spot packages nobody has touched in years."""
    published = datetime(2019, 1, 1, tzinfo=timezone.utc)

    def fetch(name: str, _spec, _extras=frozenset()) -> FetchResult:
        return FetchResult("1.0", [], last_release=published)

    graph = resolve(direct("abandoned"), fetch)

    assert graph.nodes[key("abandoned", "1.0")].last_release == published


# --- one version per package ----------------------------------------------


def test_a_pinned_package_is_not_also_resolved_from_a_range() -> None:
    """The bug this fixes: the manifest pins adlfs==2024.4.1 and a provider
    asks for adlfs>=2023.10.0. Resolved separately that is two versions; pip
    installs one."""
    index = {"a": ["adlfs>=2023.10.0"], "adlfs": []}
    versions = {"adlfs": ["2024.4.1", "2026.8.0"], "a": ["1.0"]}

    graph = resolve(
        [
            Dependency("a", raw_spec="==1.0"),
            Dependency("adlfs", raw_spec="==2024.4.1"),
        ],
        versioned_index(index, versions),
    )

    adlfs = [n for n in graph.nodes.values() if n.key.name == "adlfs"]
    assert [n.key.version for n in adlfs] == ["2024.4.1"]


def test_a_later_constraint_narrows_what_is_already_chosen() -> None:
    """Constraints seen before resolving are combined, so the answer satisfies
    all of them."""
    index = {"a": ["shared>=2.0", "shared<3.0"], "shared": []}
    versions = {"shared": ["1.0", "2.5", "3.5"], "a": ["1.0"]}

    graph = resolve(direct("a"), versioned_index(index, versions))

    shared = [n for n in graph.nodes.values() if n.key.name == "shared"]
    assert [n.key.version for n in shared] == ["2.5"]


def test_a_constraint_arriving_after_resolution_is_reported_not_applied() -> None:
    """We resolve on first sight and do not backtrack. If something later asks
    for a version we have already ruled out, the honest answer is to say the
    constraints disagree rather than to silently carry two versions."""
    index = {"a": ["shared>=2.0"], "b": ["shared<3.0"], "shared": []}
    versions = {"shared": ["1.0", "2.5", "3.5"], "a": ["1.0"], "b": ["1.0"]}

    graph = resolve(direct("a", "b"), versioned_index(index, versions))

    shared = [n for n in graph.nodes.values() if n.key.name == "shared"]
    assert len(shared) == 1, "still one node, not two versions"
    assert any(e.package == "shared" and "conflict" in e.error for e in graph.errors)


def test_every_requester_still_gets_an_edge() -> None:
    """Deduplicating the node must not lose who asked for it - that is what
    the remediation advice is built from."""
    index = {"a": ["shared>=1.0"], "b": ["shared>=1.0"], "shared": []}
    versions = {"shared": ["2.0"], "a": ["1.0"], "b": ["1.0"]}

    graph = resolve(direct("a", "b"), versioned_index(index, versions))

    dependents = graph.dependents_of(key("shared", "2.0"))
    assert sorted(k.name for k in dependents) == ["a", "b"]


def test_constraints_that_cannot_all_be_met_are_reported() -> None:
    """Better to name the conflict than to quietly carry two versions."""
    index = {"a": ["shared>=3.0"], "b": ["shared<2.0"], "shared": []}
    versions = {"shared": ["1.0", "3.5"], "a": ["1.0"], "b": ["1.0"]}

    graph = resolve(direct("a", "b"), versioned_index(index, versions))

    assert any("shared" == e.package for e in graph.errors)
    assert any("conflict" in e.error for e in graph.errors)


def test_a_package_appears_once_however_many_things_need_it() -> None:
    index = {f"p{i}": ["shared>=1.0"] for i in range(5)} | {"shared": []}
    versions = {"shared": ["2.0"], **{f"p{i}": ["1.0"] for i in range(5)}}

    graph = resolve(direct(*[f"p{i}" for i in range(5)]), versioned_index(index, versions))

    assert len([n for n in graph.nodes.values() if n.key.name == "shared"]) == 1


# --- extras through the walk ------------------------------------------------


def extras_index():
    """A fake PyPI where celery's redis requirement is behind an extra."""

    def fetch(name: str, spec, extras=frozenset()) -> FetchResult:
        table = {
            "celery": ["billiard>=4.2.0"] + (["redis>=4.5.2"] if "redis" in extras else []),
            "billiard": [],
            "redis": [],
            "app": [],
        }
        if name not in table:
            return FetchResult(error="no such package on PyPI")
        return FetchResult("1.0", [Requirement(r) for r in table[name]])

    return fetch


def test_a_requested_extra_pulls_in_its_dependency() -> None:
    graph = resolve(
        [Dependency("celery", raw_spec="==1.0", extras=frozenset({"redis"}))],
        extras_index(),
    )

    assert "redis" in {n.key.name for n in graph.nodes.values()}


def test_without_the_extra_that_dependency_is_absent() -> None:
    graph = resolve([Dependency("celery", raw_spec="==1.0")], extras_index())

    assert "redis" not in {n.key.name for n in graph.nodes.values()}


def test_an_extra_requested_transitively_is_honoured() -> None:
    """A package can ask for another package's extras too."""

    def fetch(name: str, spec, extras=frozenset()) -> FetchResult:
        table = {
            "app": ["celery[redis]>=1.0"],
            "celery": (["redis>=4.5.2"] if "redis" in extras else []),
            "redis": [],
        }
        if name not in table:
            return FetchResult(error="no such package on PyPI")
        return FetchResult("1.0", [Requirement(r) for r in table[name]])

    graph = resolve(direct("app"), fetch)

    assert "redis" in {n.key.name for n in graph.nodes.values()}


def test_extras_do_not_change_the_resolved_version() -> None:
    """`celery` and `celery[redis]` are one installed package, not two."""
    graph = resolve(
        [Dependency("celery", raw_spec="==1.0", extras=frozenset({"redis"}))],
        extras_index(),
    )

    celery = [n for n in graph.nodes.values() if n.key.name == "celery"]
    assert len(celery) == 1


def test_an_extra_asked_for_after_the_package_is_resolved_still_counts() -> None:
    """One package wants plain celery, another wants celery[redis]. Whichever
    arrives first, redis is installed - so both have to be honoured."""

    def fetch(name: str, spec, extras=frozenset()) -> FetchResult:
        table = {
            "a": ["celery"],
            "b": ["celery[redis]"],
            "celery": ["redis"] if "redis" in extras else [],
            "redis": [],
        }
        if name not in table:
            return FetchResult(error="no such package on PyPI")
        return FetchResult("1.0", [Requirement(r) for r in table[name]])

    graph = resolve(direct("a", "b"), fetch)

    assert "redis" in {n.key.name for n in graph.nodes.values()}


def test_the_extra_is_honoured_whichever_order_it_arrives_in() -> None:
    """The mirror case: the extra is seen first, the plain request second."""

    def fetch(name: str, spec, extras=frozenset()) -> FetchResult:
        table = {
            "a": ["celery[redis]"],
            "b": ["celery"],
            "celery": ["redis"] if "redis" in extras else [],
            "redis": [],
        }
        if name not in table:
            return FetchResult(error="no such package on PyPI")
        return FetchResult("1.0", [Requirement(r) for r in table[name]])

    graph = resolve(direct("a", "b"), fetch)

    assert "redis" in {n.key.name for n in graph.nodes.values()}
