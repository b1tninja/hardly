"""Body preview coverage report."""

from pathlib import Path

from hardly import session as sess
from hardly.index import query as q

FIX = Path(__file__).parent / "fixtures" / "sample.har"


def test_body_coverage_on_sample(tmp_path, monkeypatch):
    monkeypatch.setenv("HARDLY_RUNTIME_DIR", str(tmp_path))
    info = sess.open_har(str(FIX), force=True)
    conn = sess.require_conn(info["session_id"])
    cov = q.body_coverage(conn, exclude_noise=False)
    assert cov["entries"] >= 1
    assert cov["with_preview"] >= 1
    assert 0.0 <= cov["preview_ratio"] <= 1.0
