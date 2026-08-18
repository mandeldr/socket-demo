"""The fixed string vocabularies, kept in one place.

Two of these carry values other systems see on the wire. One is only ever read
by a person.
"""

from enum import Enum


class Ecosystem(Enum):
    """Package registries we can scan.

    The values are what OSV expects in a query body, capitalisation included,
    so `.value` goes straight over the wire. GitHub spells Python `pip`; that
    translation lives in github.py so this promise stays true.
    """

    PYTHON = "PyPI"
    NPM = "npm"


class Source(Enum):
    """Where a vulnerability record came from."""

    GITHUB = "github"
    OSV = "osv"


class SkipReason(Enum):
    """Why a manifest line did not become a dependency.

    The values are printed straight into the report, so they read as English
    rather than as enum names.
    """

    PIP_OPTION = "pip option"
    EDITABLE = "editable install"
    VCS = "version control reference"
    DIRECT_URL = "direct URL"
    LOCAL_PATH = "local path reference"
    INVALID = "could not be parsed"
