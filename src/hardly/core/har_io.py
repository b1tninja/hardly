"""Streaming JSON readers for HAR files, with a read buffer sized for large bodies.

``ijson`` copies a string value that spans many read buffers once per buffer, so one 50 MB response
body read with its default 64 KiB buffer takes minutes (quadratic); with 4 MiB the same file
takes about two seconds and a file of many small entries is as fast as before.
"""

from __future__ import annotations

from typing import Any

import ijson

#: Read buffer for every HAR stream (bytes).
BUF_SIZE = 4 << 20


def ijson_items(f: Any, prefix: str, **kw: Any):
    kw.setdefault("buf_size", BUF_SIZE)
    return ijson.items(f, prefix, **kw)


def ijson_parse(f: Any, **kw: Any):
    kw.setdefault("buf_size", BUF_SIZE)
    return ijson.parse(f, **kw)
