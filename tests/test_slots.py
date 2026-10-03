"""Cross-process capture slot limiter."""

import os
import subprocess
import sys
import time

import pytest

pytest.importorskip("fcntl")

from hardly.core import slots  # noqa: E402

SRC = os.path.join(os.path.dirname(__file__), "..", "src")

HOLDER = """
import sys, time
from hardly.core.slots import capture_slot
with capture_slot(timeout_s=30) as info:
    print("HELD", info["slot"], flush=True)
    time.sleep(float(sys.argv[1]))
"""


def _env(tmp_path, n):
    env = dict(os.environ)
    env["HARDLY_RUNTIME_DIR"] = str(tmp_path)
    env["HARDLY_CAPTURE_SLOTS"] = str(n)
    env["PYTHONPATH"] = SRC
    return env


def _spawn(tmp_path, n, secs):
    p = subprocess.Popen(
        [sys.executable, "-c", HOLDER, str(secs)],
        env=_env(tmp_path, n),
        stdout=subprocess.PIPE,
        text=True,
    )
    assert p.stdout.readline().startswith("HELD")
    return p


def test_unlimited(monkeypatch, tmp_path):
    monkeypatch.setenv("HARDLY_RUNTIME_DIR", str(tmp_path))
    monkeypatch.setenv("HARDLY_CAPTURE_SLOTS", "0")
    with slots.capture_slot() as a, slots.capture_slot() as b:
        assert a["slot"] == b["slot"] == -1
    assert slots.slot_status()["unlimited"] is True


def test_limit_across_processes_and_timeout_message(monkeypatch, tmp_path):
    monkeypatch.setenv("HARDLY_RUNTIME_DIR", str(tmp_path))
    monkeypatch.setenv("HARDLY_CAPTURE_SLOTS", "2")
    h1, h2 = _spawn(tmp_path, 2, 20), _spawn(tmp_path, 2, 20)
    try:
        assert slots.slot_status()["in_use"] == 2
        with pytest.raises(
            slots.SlotTimeoutError, match=r"waited \d+s for a capture slot; 2 running"
        ):
            with slots.capture_slot(timeout_s=0.5):
                pass
    finally:
        h1.kill()
        h2.kill()
        h1.wait()
        h2.wait()
    # killed holders release their locks
    with slots.capture_slot(timeout_s=5) as info:
        assert info["slot"] in (0, 1)


def test_queue_depth_observable(monkeypatch, tmp_path):
    monkeypatch.setenv("HARDLY_RUNTIME_DIR", str(tmp_path))
    monkeypatch.setenv("HARDLY_CAPTURE_SLOTS", "1")
    holder = _spawn(tmp_path, 1, 20)
    waiters = [
        subprocess.Popen(
            [sys.executable, "-c", HOLDER, "0"],
            env=_env(tmp_path, 1),
            stdout=subprocess.PIPE,
            text=True,
        )
        for _ in range(2)
    ]
    try:
        deadline = time.time() + 10
        while time.time() < deadline and slots.slot_status()["waiting"] < 2:
            time.sleep(0.1)
        st = slots.slot_status()
        assert st["slots"] == 1 and st["in_use"] == 1 and st["waiting"] == 2
    finally:
        holder.kill()
        holder.wait()
        for w in waiters:
            w.wait(timeout=30)
    assert slots.slot_status()["waiting"] == 0


def test_stale_marker_ignored(monkeypatch, tmp_path):
    monkeypatch.setenv("HARDLY_RUNTIME_DIR", str(tmp_path))
    monkeypatch.setenv("HARDLY_CAPTURE_SLOTS", "1")
    dead = subprocess.Popen([sys.executable, "-c", "pass"])
    dead.wait()
    d = slots.slots_dir()
    (d / f"wait-{dead.pid}-abc.marker").write_text(f"{dead.pid}\n")
    (d / "wait-junk-x.marker").write_text("garbage")
    assert slots.slot_status()["waiting"] == 0
    assert not list(d.glob("wait-*.marker"))
    with slots.capture_slot() as info:
        assert info["queue_depth"] == 0 and info["waited_s"] >= 0
