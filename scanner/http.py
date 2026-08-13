"""Shared HTTP setup.

Every network client in the pipeline talks to a different service - PyPI for
package metadata, OSV and GitHub for advisories - but they all want the same
behaviour underneath: retry transient failures, back off between attempts, and
never hang forever. That setup lives here so the clients only hold the part
that is actually specific to their service.
"""

import requests
from requests.adapters import HTTPAdapter
from urllib3.util import Retry

DEFAULT_TIMEOUT = 10.0

# Retried because they mean "try again later", not "your request was wrong".
# 429 is rate limiting; the 5xx range is the server having a bad time.
TRANSIENT_STATUSES = (429, 500, 502, 503, 504)


def make_session(
    retries: int = 3,
    backoff: float = 0.5,
    methods: tuple[str, ...] = ("GET",),
) -> requests.Session:
    """A session that retries transient failures with exponential backoff.

    urllib3 waits backoff * 2 ** (attempt - 1) seconds between tries, and
    honours a Retry-After header when the server sends one. A 404 is an answer,
    not a failure, so it is not retried.

    `methods` defaults to GET only, because retrying a POST can repeat a side
    effect the server already applied. A caller whose POST only asks a question
    and changes nothing - OSV's lookup endpoint - can safely opt in.
    """
    retry = Retry(
        total=retries,
        backoff_factor=backoff,
        status_forcelist=TRANSIENT_STATUSES,
        allowed_methods=methods,
    )
    session = requests.Session()
    session.mount("https://", HTTPAdapter(max_retries=retry))
    return session
