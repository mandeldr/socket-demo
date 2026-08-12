"""Tests for the shared session factory.

No network here: the retry policy is inspected on the mounted adapter, since
that is what urllib3 will act on at request time.
"""

from scanner.http import make_session


def retry_policy(session):
    """The Retry object requests will use for https requests."""
    return session.get_adapter("https://example.com").max_retries


def test_transient_failures_are_retried() -> None:
    """429 means slow down, 5xx means the server is unwell. Both are worth another try."""
    policy = retry_policy(make_session())
    assert policy.total == 3
    assert set(policy.status_forcelist) == {429, 500, 502, 503, 504}


def test_a_404_is_not_retried() -> None:
    """A missing package is an answer. Retrying it just wastes time."""
    assert 404 not in retry_policy(make_session()).status_forcelist


def test_backoff_is_exponential() -> None:
    """urllib3 waits backoff * 2 ** (attempt - 1), so 0.5 gives 0.5s, 1s, 2s."""
    assert retry_policy(make_session()).backoff_factor == 0.5


def test_retries_and_backoff_are_configurable() -> None:
    policy = retry_policy(make_session(retries=5, backoff=0.1))
    assert policy.total == 5
    assert policy.backoff_factor == 0.1


def test_only_get_is_retried_by_default() -> None:
    """Retrying a POST can repeat a side effect the server already applied."""
    assert set(retry_policy(make_session()).allowed_methods) == {"GET"}


def test_a_caller_can_opt_into_retrying_post() -> None:
    """For a pure query like OSV's batch lookup, replaying a POST is safe."""
    policy = retry_policy(make_session(methods=("GET", "POST")))
    assert set(policy.allowed_methods) == {"GET", "POST"}


def test_the_adapter_is_mounted_for_https() -> None:
    session = make_session()
    assert session.get_adapter("https://pypi.org/pypi/flask/json") is not None
