"""Shared fixtures."""

import pytest

from hardly import session as _sess


@pytest.fixture(autouse=True)
def _close_live_sessions():
    """Sessions are process-global; never let one test's session leak into the next."""
    for sid in list(_sess._sessions):
        _sess.close_session(sid)
    yield
    for sid in list(_sess._sessions):
        _sess.close_session(sid)


@pytest.fixture
def allow_private_hosts(monkeypatch):
    """Opt in to loopback/private targets (the synthetic ``hardly.local_site``); never autouse."""
    monkeypatch.setenv("HARDLY_ALLOW_PRIVATE_HOSTS", "1")


@pytest.fixture
def no_private_opt_in(monkeypatch):
    """Make sure the outbound guard is at its default, whatever the invoking shell exported."""
    monkeypatch.delenv("HARDLY_ALLOW_PRIVATE_HOSTS", raising=False)


def pytest_collection_modifyitems(items):
    """Browser / live tests drive the loopback synthetic site: opt in per test, never globally."""
    for item in items:
        if item.get_closest_marker("browser") or item.get_closest_marker("live"):
            item.fixturenames.append("allow_private_hosts")
