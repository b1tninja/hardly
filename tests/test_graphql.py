"""GraphQL operation detection."""

from hardly.core.graphql import _parse_graphql


def test_parse_named_and_anonymous_operations():
    named = _parse_graphql(
        '{"query":"query GetUser { user { id } }","operationName":"GetUser"}',
        "application/json",
    )
    assert named is not None
    assert named["operation_type"] == "query"
    assert named["operation_name"] == "GetUser"

    anon = _parse_graphql(
        '{"query":"mutation { createUser(name:\\"x\\") { id } }"}',
        "application/json",
    )
    assert anon is not None
    assert anon["operation_type"] == "mutation"


def test_parse_shorthand_selection_set():
    parsed = _parse_graphql(
        '{\n  "query": "{ __typename country(code:\\"US\\"){ name } }"\n}',
        "application/json",
    )
    assert parsed is not None
    assert parsed["operation_type"] == "query"
    assert parsed["operation_name"] is None
