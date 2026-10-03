"""Secret query values never reach entry / curl / stub / params / probe output."""

import json

from hardly import session as sess
from hardly.core.curl import entry_to_curl
from hardly.core.params import param_variance
from hardly.core.stub import client_stub
from hardly.index import query as q

URL = "https://api.example.com/items?page=2&api_key=APIKEYSECRET1&sid=SIDSECRET2&access_token=TOKSECRET3&code=AUTHCODE4"


def _open(tmp_path, monkeypatch):
    entry = {
        "startedDateTime": "2026-01-01T00:00:01.000Z", "time": 5,
        "request": {"method": "GET", "url": URL, "httpVersion": "HTTP/1.1", "headers": [],
                    "queryString": [{"name": "page", "value": "2"}], "cookies": [], "headersSize": -1, "bodySize": 0},
        "response": {"status": 200, "statusText": "OK", "httpVersion": "HTTP/1.1",
                     "headers": [{"name": "Content-Type", "value": "application/json"}], "cookies": [],
                     "redirectURL": "", "headersSize": -1, "bodySize": 2,
                     "content": {"size": 2, "mimeType": "application/json", "text": "{}"}},
    }
    path = tmp_path / "q.har"
    path.write_text(json.dumps({"log": {"version": "1.2", "creator": {"name": "t", "version": "1"}, "entries": [entry]}}))
    monkeypatch.setenv("HARDLY_RUNTIME_DIR", str(tmp_path / "cache"))
    info = sess.open_har(str(path), force=True)
    return sess.require_conn(info["session_id"])


def test_secret_query_values_are_redacted_everywhere(tmp_path, monkeypatch):
    conn = _open(tmp_path, monkeypatch)
    outputs = {
        "entry": json.dumps(q.get_entry(conn, 0), default=str),
        "curl": json.dumps(entry_to_curl(conn, 0), default=str),
        "stub": json.dumps(client_stub(conn, entry_ids=[0]), default=str),
        "params": json.dumps(param_variance(conn, method="GET", host="api.example.com", path_template="/items"), default=str),
        "endpoints": json.dumps(q.list_endpoints(conn), default=str),
    }
    for name, blob in outputs.items():
        for secret in ("APIKEYSECRET1", "SIDSECRET2", "TOKSECRET3", "AUTHCODE4"):
            assert secret not in blob, (name, secret)
    assert "page=2" in outputs["curl"] and "api_key=" in outputs["curl"]  # names and benign values stay
