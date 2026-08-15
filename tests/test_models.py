"""Tests for the core data models.

The interesting behaviour here is name canonicalization on PackageKey, and that
each registry gets its own rule. PyPI treats `zope.interface`, `zope-interface`
and `zope_interface` as one project, so equivalent spellings must compare (and
hash) equal. npm does not: `lodash.merge` and `lodash-merge` are two names, and
only one of them is a real package.
"""

import pytest

from scanner.enums import EcoSystem
from scanner.models import PackageKey, canonical_name


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("flask", "flask"),  # already canonical
        ("Flask", "flask"),  # uppercase
        ("  Flask  ", "flask"),  # surrounding whitespace
        ("zope.interface", "zope-interface"),  # dot separator
        ("my_pkg", "my-pkg"),  # underscore separator
        ("Foo--Bar", "foo-bar"),  # repeated separator collapses
        ("a.._.b", "a-b"),  # mixed run of separators collapses
    ],
)
def test_package_name_is_canonicalized(raw: str, expected: str) -> None:
    assert PackageKey(raw, "1.0", EcoSystem.PYTHON).name == expected


def test_equivalent_spellings_are_equal() -> None:
    a = PackageKey("zope.interface", "5.0", EcoSystem.PYTHON)
    b = PackageKey("zope_interface", "5.0", EcoSystem.PYTHON)
    assert a == b


def test_equivalent_spellings_deduplicate_in_a_set() -> None:
    """The whole point of canonicalizing: no double counting."""
    keys = {
        PackageKey("zope.interface", "5.0", EcoSystem.PYTHON),
        PackageKey("zope-interface", "5.0", EcoSystem.PYTHON),
        PackageKey("zope_interface", "5.0", EcoSystem.PYTHON),
    }
    assert len(keys) == 1


def test_version_is_not_canonicalized() -> None:
    """Only the name is normalized; the version string is left alone."""
    assert PackageKey("flask", "3.0.0", EcoSystem.PYTHON).version == "3.0.0"


def test_different_versions_are_different_keys() -> None:
    a = PackageKey("flask", "3.0.0", EcoSystem.PYTHON)
    b = PackageKey("flask", "2.3.0", EcoSystem.PYTHON)
    assert a != b
    assert len({a, b}) == 2


def test_same_name_different_ecosystem_are_different_keys() -> None:
    """`requests` on PyPI is not `requests` on npm."""
    a = PackageKey("requests", "1.0", EcoSystem.PYTHON)
    b = PackageKey("requests", "1.0", EcoSystem.NPM)
    assert a != b


def test_ecosystem_values_are_spelled_the_way_osv_expects() -> None:
    """Not cosmetic: OSV matches these exactly, and the wrong case silently
    returns no vulnerabilities rather than an error."""
    assert EcoSystem.PYTHON.value == "PyPI"
    assert EcoSystem.NPM.value == "npm"


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("lodash", "lodash"),  # already canonical
        ("Lodash", "lodash"),  # npm is case insensitive
        ("  lodash  ", "lodash"),  # surrounding whitespace
        ("lodash.merge", "lodash.merge"),  # a dot is part of the name
        ("string_decoder", "string_decoder"),  # so is an underscore
        ("@babel/core", "@babel/core"),  # scope and slash survive
        ("@Babel/Core", "@babel/core"),  # including when lowercased
    ],
)
def test_npm_names_are_only_lowercased(raw: str, expected: str) -> None:
    """Applying PEP 503 here would turn `lodash.merge` into `lodash-merge`,
    which is not a package - so OSV answers with nothing and a vulnerable
    dependency reports clean."""
    assert PackageKey(raw, "1.0", EcoSystem.NPM).name == expected


def test_npm_separators_are_not_interchangeable() -> None:
    """The inverse of the PyPI rule, and the reason the two need separate ones."""
    dotted = PackageKey("lodash.merge", "4.6.0", EcoSystem.NPM)
    dashed = PackageKey("lodash-merge", "4.6.0", EcoSystem.NPM)
    assert dotted != dashed
    assert len({dotted, dashed}) == 2


def test_canonical_name_applies_the_rule_for_the_registry_named() -> None:
    """The same spelling, normalized two ways, because two registries disagree."""
    assert canonical_name("lodash.merge", EcoSystem.PYTHON) == "lodash-merge"
    assert canonical_name("lodash.merge", EcoSystem.NPM) == "lodash.merge"
