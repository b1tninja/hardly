"""Operating modes: archive / headless / interactive."""

from hardly.core.modes import (
    MODE_ARCHIVE,
    MODE_HEADLESS,
    MODE_INTERACTIVE,
    list_modes,
    mode_playbook,
    pick_mode,
)


def test_list_modes_has_three():
    catalog = list_modes()
    ids = {m["id"] for m in catalog["modes"]}
    assert ids == {MODE_ARCHIVE, MODE_HEADLESS, MODE_INTERACTIVE}
    assert len(catalog["summary"]) == 3
    assert "archive" in catalog["summary"][0]


def test_pick_har_is_archive():
    result = pick_mode(har_path="D:/code/captures/portal.har")
    assert result["mode"] == MODE_ARCHIVE
    assert result["playbook"]["calls"][0]["tool"] == "hardly_session_open"


def test_pick_url_is_headless():
    result = pick_mode(url="https://portal.example.com/search")
    assert result["mode"] == MODE_HEADLESS
    tools = {c["tool"] for c in result["playbook"]["calls"]}
    assert "hardly_browser_capture_discover" in tools


def test_pick_interactive_goal():
    result = pick_mode(goal="ask the user to click through captcha")
    assert result["mode"] == MODE_INTERACTIVE
    assert result["playbook"]["ask_user"]
    assert result["playbook"]["needs_user"] is True


def test_mode_playbook_aliases():
    assert mode_playbook("file")["mode"] == MODE_ARCHIVE
    assert mode_playbook("offline")["mode"] == MODE_ARCHIVE
    assert mode_playbook("discover")["mode"] == MODE_HEADLESS
    assert mode_playbook("human")["mode"] == MODE_INTERACTIVE


def test_cli_modes():
    from hardly import cli

    parser = cli.build_parser()
    assert "modes" in parser._subparsers._group_actions[0].choices
