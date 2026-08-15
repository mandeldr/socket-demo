"""Tests for the dependency graph.

The graph answers two questions the report depends on: "what pulled this in"
(path_to) and "who else needs it" (dependents_of).
"""

from scanner.enums import Ecosystem
from scanner.graph import DependencyGraph
from scanner.models import PackageKey


def key(name: str, version: str = "1.0") -> PackageKey:
    return PackageKey(name, version, Ecosystem.PYTHON)


def graph_with(*names: str) -> DependencyGraph:
    """A graph holding the named packages, all at depth 0 with no edges."""
    graph = DependencyGraph()
    for name in names:
        graph.add_node(key(name), depth=0)
    return graph


def test_a_direct_dependency_has_no_parent() -> None:
    graph = graph_with("flask")
    assert graph.nodes[key("flask")].parent is None


def test_path_to_a_direct_dependency_is_just_itself() -> None:
    graph = graph_with("flask")
    assert graph.path_to(key("flask")) == [key("flask")]


def test_path_to_follows_parent_links_back_to_the_manifest() -> None:
    """The chain a user needs to see: boto3 is why urllib3 is installed."""
    graph = DependencyGraph()
    graph.add_node(key("boto3"), depth=0)
    graph.add_node(key("botocore"), depth=1, parent=key("boto3"))
    graph.add_node(key("urllib3"), depth=2, parent=key("botocore"))

    assert graph.path_to(key("urllib3")) == [key("boto3"), key("botocore"), key("urllib3")]


def test_path_to_an_unknown_package_is_just_that_package() -> None:
    """Nothing to walk, but callers should get a usable list rather than an error."""
    assert DependencyGraph().path_to(key("ghost")) == [key("ghost")]


def test_dependents_of_finds_every_package_that_requires_it() -> None:
    graph = graph_with("flask", "requests", "urllib3")
    graph.add_edge(key("flask"), key("urllib3"))
    graph.add_edge(key("requests"), key("urllib3"))

    assert graph.dependents_of(key("urllib3")) == [key("flask"), key("requests")]


def test_dependents_of_a_package_nothing_requires_is_empty() -> None:
    graph = graph_with("flask")
    assert graph.dependents_of(key("flask")) == []


def test_the_same_edge_is_not_recorded_twice() -> None:
    """A package can list the same requirement under several markers."""
    graph = graph_with("flask", "click")
    graph.add_edge(key("flask"), key("click"))
    graph.add_edge(key("flask"), key("click"))

    assert graph.nodes[key("flask")].children == [key("click")]


def test_an_edge_from_a_package_we_never_added_is_ignored() -> None:
    graph = graph_with("click")
    graph.add_edge(key("not-in-the-graph"), key("click"))

    assert graph.dependents_of(key("click")) == []


def test_a_shared_dependency_has_many_dependents_but_one_path() -> None:
    """The diamond case: two parents, but parent is the first route found."""
    graph = DependencyGraph()
    graph.add_node(key("flask"), depth=0)
    graph.add_node(key("requests"), depth=0)
    graph.add_node(key("urllib3"), depth=1, parent=key("flask"))
    graph.add_edge(key("flask"), key("urllib3"))
    graph.add_edge(key("requests"), key("urllib3"))

    assert graph.dependents_of(key("urllib3")) == [key("flask"), key("requests")]
    assert graph.path_to(key("urllib3")) == [key("flask"), key("urllib3")]


def test_versions_are_part_of_identity() -> None:
    """Two versions of one package are two nodes, not one."""
    graph = DependencyGraph()
    graph.add_node(key("urllib3", "1.26.0"), depth=1)
    graph.add_node(key("urllib3", "2.0.0"), depth=1)

    assert len(graph.nodes) == 2


def test_a_package_that_failed_to_resolve_is_marked() -> None:
    graph = DependencyGraph()
    graph.add_node(key("ghost"), depth=0, failed=True)

    assert graph.nodes[key("ghost")].failed
