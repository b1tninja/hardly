import pytest

from hardly.core.capture_errors import classify_capture_error, with_error_class


@pytest.mark.parametrize(
    "msg,cls,retry",
    [
        ("net::ERR_TUNNEL_CONNECTION_FAILED at https://x", "environment_blocked", False),
        ("CONNECT tunnel failed, response 403", "environment_blocked", False),
        ("x-deny-reason: host_not_allowed", "environment_blocked", False),
        ("net::ERR_TOO_MANY_RETRIES at x", "transient", True),
        ("net::ERR_CONNECTION_RESET", "transient", True),
        ("Navigation is interrupted by another navigation to y", "transient", True),
        ("net::ERR_HTTP2_PROTOCOL_ERROR", "transient", True),
        ("net::ERR_CERT_AUTHORITY_INVALID", "cert", False),
        ("net::ERR_NAME_NOT_RESOLVED at http://nope.invalid", "dns", False),
        ("Timeout 30000ms exceeded.", "timeout", True),
        ("net::ERR_CONNECTION_REFUSED", "refused", False),
        ("something odd", "unknown", False),
        ("", "unknown", False),
    ],
)
def test_classify(msg, cls, retry):
    out = classify_capture_error(msg)
    assert out["class"] == cls and out["retryable"] is retry and out["advice"]


def test_transient_list_shared():
    from hardly.capture import _TRANSIENT_NAV
    from hardly.core.capture_errors import TRANSIENT_NAV

    assert _TRANSIENT_NAV is TRANSIENT_NAV


def test_with_error_class():
    d = with_error_class({"error": "net::ERR_NAME_NOT_RESOLVED"})
    assert d["error_class"] == "dns" and d["error_advice"]
    assert "error_class" not in with_error_class({"status": "ok"})
