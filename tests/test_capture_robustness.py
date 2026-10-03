"""Error classes for redirect loops / http status / invalid urls; policy bypass refusals."""

import pytest

from hardly.core import recipe_policy
from hardly.core.capture_errors import classify_capture_error


@pytest.mark.parametrize(
    "msg,cls",
    [
        ("net::ERR_TOO_MANY_REDIRECTS at https://x/", "redirect_loop"),
        ("net::ERR_TOO_MANY_RETRIES at https://x/", "redirect_loop"),
        ("net::ERR_HTTP_RESPONSE_CODE_FAILURE at https://x/", "http_status"),
        ("Cannot navigate to invalid URL", "invalid_url"),
    ],
)
def test_error_classes(msg, cls):
    out = classify_capture_error(msg)
    assert out["class"] == cls


def test_policy_refuses_password_evaluate():
    r = recipe_policy.check_step({"op": "evaluate", "expression": "document.querySelector('input[type=password]').value='x'"})
    assert r is not None


def test_redirect_diag_registered():
    from hardly import capabilities

    assert "hardly_redirect_diag" in capabilities.TOOLS
