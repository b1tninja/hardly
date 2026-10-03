"""Parse and normalize Playwright AI aria refs."""

from hardly.core.aria_refs import normalize_aria_ref, parse_aria_refs

SAMPLE = """
- banner:
  - heading "Portal" [level=1] [ref=e1]
- main:
  - textbox "Name" [ref=e12]
  - button "Search" [ref=e15] [cursor=pointer]
  - link "Next" [ref=e20]:
    - /url: /page/2
"""


def test_parse_aria_refs():
    refs = parse_aria_refs(SAMPLE)
    by_ref = {r["ref"]: r for r in refs}
    assert by_ref["e12"]["role"] == "textbox"
    assert by_ref["e12"]["name"] == "Name"
    assert by_ref["e15"]["role"] == "button"
    assert by_ref["e15"]["name"] == "Search"
    assert by_ref["e20"]["role"] == "link"


def test_normalize_aria_ref():
    assert normalize_aria_ref("e12") == "e12"
    assert normalize_aria_ref("ref=e12") == "e12"
    assert normalize_aria_ref("[ref=e12]") == "e12"
    assert normalize_aria_ref("") == ""
