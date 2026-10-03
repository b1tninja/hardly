from hardly.core.html_forms import extract_html_structure
from hardly.core.search_nav import find_search_entry, rank_search_links, score_link

LANDING = """<html><body><form action="/q"><input name="x"></form>
<a href="/about">About</a><a href="/login">Sign in</a>
<a href="/svc/widget-search">Widget Search</a>
<a href="/svc/gadget-lookup">Gadget Lookup</a>
<a href="/pay">Pay now</a><a href="/forms/a.pdf">Search forms</a></body></html>"""


def test_score_filters_noise_and_is_generic():
    assert score_link("Sign in", "/login")[0] == 0
    assert score_link("Widget Search", "/w")[0] > 0
    assert score_link("Gadgets", "/g", ("gadget",))[1] == ["gadget"]


def test_keywords_reorder_candidates():
    links = extract_html_structure(LANDING, base_url="https://c.example/")["links"]
    top = rank_search_links(links, keywords=("gadget",))
    assert top[0]["text"] == "Gadget Lookup"
    assert top[0]["click"]["css"] == 'a:has-text("Gadget Lookup")'
    assert not any(r["text"] in ("Sign in", "Pay now") for r in top)


def test_find_search_entry_on_sample():
    from hardly import session as sess

    r = sess.open_har("tests/fixtures/sample.har")
    out = find_search_entry(sess.require_conn(r["session_id"]), keywords=["doc"])
    assert "candidates" in out and out["pages_scanned"] >= 0
