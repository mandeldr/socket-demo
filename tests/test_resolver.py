"""Tests for transitive dependency resolution.

The resolver takes a `fetch` callable so the graph logic can be tested without
touching the network. `fake_index` below builds one from a plain dict.
"""

from datetime import datetime, timezone

from packaging.requirements import Requirement

from scanner.enums import EcoSystem
from scanner.models import Dependency, PackageKey
from scanner.resolver import FetchResult, resolve


def key(name: str, version: str | None = "1.0") -> PackageKey:
    return PackageKey(name, version, EcoSystem.PYTHON)


def direct(*names: str) -> list[Dependency]:
    return [
        Dependency(key(n), raw_spec="==1.0", is_direct=True, depth=0, parent=None) for n in names
    ]


def fake_index(index: dict[str, list[str]]):
    """Build a fetch function from {package: [requirement strings]}."""

    def fetch(name: str, _spec) -> FetchResult:
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
    assert graph.roots == [key("flask")]
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


def test_depth_limit_stops_the_walk() -> None:
    index = {"a": ["b==1.0"], "b": ["c==1.0"], "c": ["d==1.0"], "d": []}
    graph = resolve(direct("a"), fake_index(index), max_depth=2)
    assert names(graph) == {"a", "b", "c"}  # d is beyond the limit


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
    assert graph.roots == [key("flask")]


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

    def fetch(name: str, spec) -> FetchResult:
        seen.append(str(spec))
        return FetchResult("2.0.0", [])

    deps = [
        Dependency(key("flask", "2.0.0"), raw_spec="==2.0.0", is_direct=True, depth=0, parent=None)
    ]
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

    def fetch(name: str, _spec) -> FetchResult:
        return FetchResult("1.0", [], last_release=published)

    graph = resolve(direct("abandoned"), fetch)

    assert graph.nodes[key("abandoned", "1.0")].last_release == published


# --- the depth limit -------------------------------------------------------


def test_a_package_cut_off_by_the_depth_limit_is_marked() -> None:
    """Otherwise a subtree we never looked at is indistinguishable from a leaf,
    and the scan reports clean about packages it never examined."""
    graph = resolve(direct("a"), fake_index({"a": ["b"], "b": ["c"], "c": []}), max_depth=1)

    assert graph.nodes[key("b", "1.0")].truncated is True
    assert graph.nodes[key("a", "1.0")].truncated is False


def test_a_genuine_leaf_at_the_depth_limit_is_not_marked() -> None:
    """Nothing was cut off - it really has no requirements."""
    graph = resolve(direct("a"), fake_index({"a": ["b"], "b": []}), max_depth=1)

    assert graph.nodes[key("b", "1.0")].truncated is False


def test_nothing_is_marked_when_the_tree_fits() -> None:
    graph = resolve(direct("a"), fake_index({"a": ["b"], "b": ["c"], "c": []}), max_depth=5)

    assert not any(node.truncated for node in graph.nodes.values())


def test_a_failed_package_is_not_also_called_truncated() -> None:
    graph = resolve(direct("ghost"), fake_index({}), max_depth=0)

    assert graph.nodes[key("ghost", None)].truncated is False
