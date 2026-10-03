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
