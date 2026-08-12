from enum import Enum


class EcoSystem(Enum):
    """Package registries we can scan.

    The values are the identifiers OSV expects, so `PyPI` is spelled exactly
    that way. Keeping them here means the string exists in one place.
    """

    PYTHON = "PyPI"
    NPM = "npm"


class Source(Enum):
    """Where a vulnerability record came from."""

    GITHUB = "ghsa"
    OSV = "osv"


class SkipReason(Enum):
    """Why a manifest line did not become a dependency."""

    PIP_OPTION = "pip option"
    EDITABLE = "editable install"
    VCS = "version control reference"
    DIRECT_URL = "direct URL"
    INVALID = "could not be parsed"
