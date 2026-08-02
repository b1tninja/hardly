"""Unit tests for core helpers."""

from pathlib import Path

from hardly.core.filters import is_noise
from hardly.core.redact import redact_body_text, redact_header_value
from hardly.core.schema_infer import infer_schema
from hardly.core.urls import path_template
from hardly.session import resolve_path


def test_path_template_numeric_and_uuid():
    assert path_template("/users/42/2fa/google/validate") == "/users/{id}/2fa/google/validate"
    assert (
        path_template("/orgs/a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11")
        == "/orgs/{uuid}"
    )


def test_noise_static_and_options():
    assert is_noise(method="GET", url="https://cdn.example.com/app.js")
    assert is_noise(method="OPTIONS", url="https://api.example.com/x")
    assert is_noise(method="GET", url="https://www.google-analytics.com/g/collect")
    assert not is_noise(method="POST", url="https://api.example.com/login")


def test_redact_password_and_auth_header():
    assert redact_header_value("Authorization", "Bearer secret") == "***REDACTED***"
    body = redact_body_text('{"email":"a@b.c","password":"s3cret"}')
    assert "s3cret" not in (body["text"] or "")
    assert "password" in (body["text"] or "")


def test_schema_infer_object():
    schema = infer_schema(
        [
            {"id": 1, "name": "a"},
            {"id": 2, "name": "b", "extra": True},
        ]
    )
    assert schema["type"] == "object"
    assert "id" in schema["required"]
    assert schema["properties"]["extra"].get("optional") is True


def test_resolve_path_mapping(tmp_path, monkeypatch):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    monkeypatch.setenv("HARDLY_WORKSPACE", str(workspace))
    monkeypatch.setenv("HARDLY_PATH_MAP", rf"D:\code={workspace}")
    mapped = resolve_path(r"D:\code\payhoa\app.payhoa.com.har")
    assert mapped == Path(workspace) / "payhoa" / "app.payhoa.com.har"
