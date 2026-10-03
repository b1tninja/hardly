"""Packaging metadata consistency (offline; no build needed)."""

from __future__ import annotations

import importlib
import json
import re
import sys
from pathlib import Path

import pytest

import hardly

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover
    tomllib = pytest.importorskip("tomli")

ROOT = Path(__file__).resolve().parents[1]


def _pyproject() -> dict:
    return tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))


def test_version_matches_dunder():
    assert _pyproject()["project"]["version"] == hardly.__version__


def test_server_json_version_and_name():
    data = json.loads((ROOT / "server.json").read_text(encoding="utf-8"))
    version = _pyproject()["project"]["version"]
    assert data["version"] == version
    assert [p["version"] for p in data["packages"]] == [version]
    assert data["packages"][0]["identifier"] == _pyproject()["project"]["name"]
    assert data["name"] == "io.github.b1tninja/hardly"


def test_readme_has_mcp_name():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "mcp-name: io.github.b1tninja/hardly" in readme


def test_changelog_has_unreleased():
    text = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    assert "## [Unreleased]" in text


def test_entry_points_importable():
    scripts = _pyproject()["project"]["scripts"]
    assert "hardly" in scripts
    for target in scripts.values():
        mod, _, attr = target.partition(":")
        assert callable(getattr(importlib.import_module(mod), attr))


def test_runtime_data_is_packaged():
    force = _pyproject()["tool"]["hatch"]["build"]["targets"]["wheel"]["force-include"]
    assert force["docs"] == "hardly/_data/docs"
    assert force["skills"] == "hardly/_data/skills"
    assert (ROOT / "docs" / "README.md").is_file()
    assert (ROOT / "skills" / "hardly" / "SKILL.md").is_file()


def test_metadata_basics():
    proj = _pyproject()["project"]
    assert re.match(r"^>=3\.\d+$", proj["requires-python"])
    assert (ROOT / proj["readme"]).is_file()
    assert {"capture", "dev"} <= set(proj["optional-dependencies"])
    assert "Changelog" in proj["urls"]


def test_workflows_are_valid_yaml():
    yaml = pytest.importorskip("yaml")
    files = sorted((ROOT / ".github" / "workflows").glob("*.yml"))
    assert files
    for f in files:
        doc = yaml.safe_load(f.read_text(encoding="utf-8"))
        assert "jobs" in doc, f.name
        assert "permissions" in doc, f"{f.name}: set top-level permissions"


def test_release_notes_extraction():
    sys.path.insert(0, str(ROOT / "scripts"))
    import release_notes

    text = "# C\n\n## [Unreleased]\n\n- next\n\n## [1.2.3] - 2030-01-01\n\n- shipped\n\n## [1.2.2]\n\n- old\n"
    assert release_notes.extract(text, "1.2.3").strip() == "- shipped"
    assert release_notes.extract(text, "9.9.9").strip() == "- next"
