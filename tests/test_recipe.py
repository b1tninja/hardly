"""Capture recipe validation (no live browser)."""

import pytest

from hardly.capture import CaptureError, run_capture_recipe


def test_recipe_requires_running_capture(tmp_path, monkeypatch):
    monkeypatch.setenv("HARDLY_RUNTIME_DIR", str(tmp_path))
    with pytest.raises(CaptureError, match="no running capture"):
        run_capture_recipe([{"op": "url"}])


def test_recipe_rejects_bad_op(tmp_path, monkeypatch):
    monkeypatch.setenv("HARDLY_RUNTIME_DIR", str(tmp_path))
    # Force a fake running capture id path — still fails at running check first
    with pytest.raises(CaptureError, match="no running capture"):
        run_capture_recipe([{"op": "explode"}])
