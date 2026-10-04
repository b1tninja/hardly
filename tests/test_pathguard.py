"""Write-path guard: allowlist, symlinks, special files, always-denied locations, every writer."""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from types import SimpleNamespace

import pytest

from hardly import server
from hardly import session as sess
from hardly.core import pathguard
from hardly.core.pathguard import PathNotAllowed, guard_write

FIX = str(Path(__file__).parent / "fixtures" / "sample.har")


@pytest.fixture
def jail(tmp_path, monkeypatch):
    """cwd, temp dir and home are three separate dirs; ``other`` is outside every allowed root."""
    ns = SimpleNamespace(
        cwd=tmp_path / "cwd", tmp=tmp_path / "tmp", home=tmp_path / "home", other=tmp_path / "other"
    )
    for d in (ns.cwd, ns.tmp, ns.home, ns.other, ns.home / ".ssh"):
        d.mkdir()
    monkeypatch.chdir(ns.cwd)
    monkeypatch.setattr(tempfile, "tempdir", str(ns.tmp))
    monkeypatch.setenv("HOME", str(ns.home))
    monkeypatch.setenv("USERPROFILE", str(ns.home))
    monkeypatch.setenv("HARDLY_WORKSPACE", str(tmp_path / "no-workspace"))
    monkeypatch.delenv("HARDLY_WRITE_DIRS", raising=False)
    return ns


def test_allowed_roots_cwd_and_temp(jail):
    assert guard_write(jail.cwd / "a" / "b.json") == jail.cwd / "a" / "b.json"
    guard_write(jail.tmp / "x.har")
    guard_write("relative.har")


def test_outside_allowlist_refused_with_actionable_hint(jail):
    with pytest.raises(PathNotAllowed) as ei:
        guard_write(jail.other / "x.har")
    assert ei.value.code == "path_not_allowed"
    assert "HARDLY_WRITE_DIRS" in ei.value.hint and str(jail.cwd) in ei.value.hint


def test_write_dirs_env_adds_roots_and_star_disables(jail, monkeypatch):
    monkeypatch.setenv("HARDLY_WRITE_DIRS", os.pathsep.join(["", str(jail.other)]))
    guard_write(jail.other / "ok.har")
    monkeypatch.setenv("HARDLY_WRITE_DIRS", "*")
    guard_write(jail.other / "ok.har")


def test_dotdot_and_symlink_escape_refused(jail):
    with pytest.raises(PathNotAllowed):
        guard_write(jail.cwd / ".." / "other" / "x")
    link = jail.cwd / "out"
    try:
        link.symlink_to(jail.other, target_is_directory=True)
    except OSError:
        pytest.skip("symlinks unavailable")
    with pytest.raises(PathNotAllowed):
        guard_write(link / "x.har")
    file_link = jail.cwd / "f.har"
    file_link.symlink_to(jail.home / ".ssh" / "authorized_keys")
    with pytest.raises(PathNotAllowed):
        guard_write(file_link)


@pytest.mark.parametrize(
    "rel",
    [".ssh/authorized_keys", ".ssh", ".gnupg/x", ".aws/credentials", ".kube/config", ".config/gcloud/x.json",
     ".bashrc", ".zshrc", ".profile", ".bash_profile", ".netrc", ".config/fish/config.fish"],
)
def test_credential_locations_denied_even_inside_allowed_dirs(jail, monkeypatch, rel):
    monkeypatch.chdir(jail.home)  # home is the cwd: inside an allowed root
    with pytest.raises(PathNotAllowed, match="not writable"):
        guard_write(jail.home / rel)
    monkeypatch.setenv("HARDLY_WRITE_DIRS", "*")  # ... and with the allowlist off
    with pytest.raises(PathNotAllowed):
        guard_write(jail.home / rel)
    guard_write(jail.home / "notes.txt")


def test_git_internals_denied(jail):
    with pytest.raises(PathNotAllowed):
        guard_write(jail.cwd / "repo" / ".git" / "hooks" / "pre-commit")


@pytest.mark.skipif(os.name == "nt", reason="posix device files")
def test_special_files_denied_even_without_allowlist(jail, monkeypatch):
    monkeypatch.setenv("HARDLY_WRITE_DIRS", "*")
    with pytest.raises(PathNotAllowed, match="special file"):
        guard_write("/dev/null")
    fifo = jail.cwd / "pipe"
    os.mkfifo(fifo)
    with pytest.raises(PathNotAllowed, match="special file"):
        guard_write(fifo)


def test_filesystem_root_cwd_does_not_open_everything(jail, monkeypatch):
    monkeypatch.chdir(Path(jail.cwd.anchor))
    assert Path(jail.cwd.anchor) not in pathguard.allowed_roots()
    with pytest.raises(PathNotAllowed):
        guard_write(jail.other / "x")


# ------------------------------------------------------------------ every writer is guarded


def _err(text: str) -> dict:
    out = json.loads(text)
    assert out.get("code") == "path_not_allowed", out
    assert "HARDLY_WRITE_DIRS" in out["hint"]
    return out


def _sid():
    return sess.open_har(FIX, force=True)["session_id"]


@pytest.mark.parametrize("fmt", ["openapi", "postman", "api_markdown", "site_brief", "report", "client_python", "plan_steps"])
def test_write_export_all_formats_guarded(jail, fmt):
    sid = _sid()
    for bad in (jail.other / "x.out", jail.home / ".ssh" / "x.out"):
        _err(server.hardly_write_export(session_id=sid, format=fmt, output_path=str(bad)))
        assert not bad.exists()
    ok = json.loads(server.hardly_write_export(session_id=sid, format=fmt, output_path=str(jail.cwd / f"{fmt}.out")))
    assert "error" not in ok, ok


def test_write_session_copy_har_and_index_guarded(jail):
    sid = _sid()
    for fmt in ("har", "index"):
        _err(server.hardly_write_session_copy(session_id=sid, output_path=str(jail.other / "c"), format=fmt))
        out = json.loads(server.hardly_write_session_copy(session_id=sid, output_path=str(jail.cwd / f"c.{fmt}"), format=fmt))
        assert out.get("saved_to"), out


def test_session_open_output_path_guarded(jail):
    with pytest.raises(PathNotAllowed):
        sess.open_session(FIX, output_path=jail.other / "i.sqlite")
    assert not (jail.other / "i.sqlite").exists()
    with sess.open_session(FIX, output_path=jail.cwd / "i.sqlite", force=True) as s:
        assert s.saved_to is not None


def test_har_tools_guarded(jail):
    _err(server.hardly_write_har_scrubbed(har_path=FIX, output_path=str(jail.other / "s.har")))
    _err(server.hardly_write_har_pruned(har_path=FIX, output_path=str(jail.other / "p.har")))
    _err(server.hardly_write_har_merged(har_paths=[FIX], output_path=str(jail.other / "m.har")))
    _err(server.hardly_write_har_split(har_path=FIX, output_dir=str(jail.other / "parts")))
    assert not (jail.other / "parts").exists()
    out = json.loads(server.hardly_write_har_split(har_path=FIX, output_dir=str(jail.cwd / "parts")))
    assert "error" not in out, out


def test_catalog_write_guarded(jail):
    target = {"id": "t1", "endpoints": [{"role": "api", "url": "https://example.com/api"}]}
    _err(server.hardly_write_catalog_record(catalog_path=str(jail.other / "c.json"), target=target, create=True))
    assert not (jail.other / "c.json").exists()
    out = json.loads(server.hardly_write_catalog_record(catalog_path=str(jail.cwd / "c.json"), target=target, create=True))
    assert out["action"] == "created"


def test_screenshot_and_capture_output_paths_guarded(jail):
    _err(server.hardly_write_screenshot(output_path=str(jail.other / "s.png")))
    _err(server.hardly_browser_start(url="https://example.com/", har_output_path=str(jail.other / "c.har")))
    _err(server.hardly_browser_start(url="https://example.com/", har_output_path=str(jail.cwd / "c.har"),
                                     profile=str(jail.other / "profile")))


def test_cli_output_flags_guarded(jail, capsys):
    from hardly import cli

    for argv in (
        ["session", "open", FIX, "-o", str(jail.other / "i.sqlite")],
        ["write", "har-scrubbed", FIX, "-o", str(jail.other / "s.har")],
    ):
        with pytest.raises(SystemExit) as ei:
            cli.main(argv)
        assert ei.value.code == 1
        assert json.loads(capsys.readouterr().out)["code"] == "path_not_allowed"
    from hardly.core import catalog as C

    p = jail.cwd / "c.json"
    C.save(C.Catalog(name="n"), p)
    with pytest.raises(PathNotAllowed):
        cli.cmd_catalog_export(SimpleNamespace(catalog_path=str(p), format="json", output=str(jail.other / "e.json")))


def test_ephemeral_and_atomic_temp_files_stay_inside_allowed_dirs(jail):
    from hardly.ephemeral import new_ephemeral_har

    p = new_ephemeral_har("x")
    try:
        assert pathguard.guard_write(p) == p  # the OS temp dir is an allowed root
    finally:
        p.unlink(missing_ok=True)
    sid = _sid()
    out = jail.cwd / "idx.sqlite"
    json.loads(server.hardly_write_session_copy(session_id=sid, output_path=str(out), format="index"))
    assert sorted(x.name for x in jail.cwd.iterdir()) == ["idx.sqlite"]  # temp siblings cleaned up
