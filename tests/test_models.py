"""Tests for the core data models.

The interesting behaviour here is PEP 503 name canonicalization on PackageKey:
PyPI treats `zope.interface`, `zope-interface` and `zope_interface` as the same
project, so equivalent spellings must compare (and hash) equal.
"""

import pytest

from scanner.enums import EcoSystem
from scanner.models import PackageKey


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
