"""HAR body sidecar merge (Playwright size=-1 backfill)."""

import json
from pathlib import Path

from hardly.core.har_bodies import interesting_mime, merge_bodies_into_har, shape_body


def test_interesting_mime():
    assert interesting_mime("text/html; charset=utf-8")
    assert interesting_mime("application/json")
    assert interesting_mime("application/javascript")
    assert interesting_mime(None)
    assert not interesting_mime("image/png")
    assert not interesting_mime("application/octet-stream")


def test_shape_body_truncates():
    assert len(shape_body("x" * 100, max_chars=10)) == 10


def test_merge_fills_empty_entries(tmp_path: Path):
    har = {
        "log": {
            "version": "1.2",
            "creator": {"name": "t", "version": "0"},
            "entries": [
                {
                    "request": {
                        "method": "POST",
                        "url": "https://portal.example.com/Search/GridResults",
                    },
                    "response": {
                        "status": 200,
                        "content": {"size": -1, "mimeType": "application/json"},
                    },
                },
                {
                    "request": {
                        "method": "GET",
                        "url": "https://portal.example.com/search",
                    },
                    "response": {
                        "status": 200,
                        "content": {
                            "size": 5,
                            "mimeType": "text/html",
                            "text": "<ok/>",
                        },
                    },
                },
            ],
        }
    }
    path = tmp_path / "cap.har"
    path.write_text(json.dumps(har), encoding="utf-8")
    stats = merge_bodies_into_har(
        path,
        [
            {
                "method": "POST",
                "url": "https://portal.example.com/Search/GridResults",
                "status": 200,
                "mime": "application/json",
                "text": '{"data":[]}',
            },
            {
                "method": "GET",
                "url": "https://portal.example.com/search",
                "status": 200,
                "mime": "text/html",
                "text": "<ignored/>",
            },
        ],
    )
    assert stats["filled"] == 1
    assert stats["skipped"] == 1
    data = json.loads(path.read_text(encoding="utf-8"))
    content = data["log"]["entries"][0]["response"]["content"]
    assert content["text"] == '{"data":[]}'
    assert content["size"] > 0
    assert data["log"]["entries"][1]["response"]["content"]["text"] == "<ok/>"
