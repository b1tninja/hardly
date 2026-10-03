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


def test_js_actions_are_candidates():
    html = """<a href="javascript:__doPostBack('ctl00$nav$lnkFind','')">Find a Widget</a>
    <a href="#" onclick="go()">Gadget Search</a>
    <input type="submit" id="btnGo" value="Lookup">
    <button id="b2">Sign in</button><button>Cancel</button>"""
    s = extract_html_structure(html)
    kinds = {a["kind"] for a in s["actions"]}
    assert {"postback", "js_link", "button"} <= kinds
    from hardly.core.search_nav import actions_as_links

    top = rank_search_links(actions_as_links(s["actions"]), keywords=("gadget",))
    assert top[0]["text"] == "Gadget Search" and top[0]["kind"] == "js_link"
    texts = [r["text"] for r in top]
    assert "Find a Widget" in texts and "Lookup" in texts and "Sign in" not in texts


def test_search_form_reached_skips_login_and_site_search():
    from hardly.core.search_nav import search_form_reached

    site = extract_html_structure('<form action="/f"><input type="search" name="q"></form>')
    assert search_form_reached(site) is None  # header search box is not the goal
    login = extract_html_structure(
        '<form><input name="u"><input type="password" name="p"></form>'
    )
    assert search_form_reached(login) is None
    real = extract_html_structure(
        '<form action="/r"><input name="name"><select name="cat"><option>a</option></select></form>'
    )
    hit = search_form_reached(real)
    assert hit and set(hit["fields"]) == {"name", "cat"}
    single = extract_html_structure('<form><input type="text" name="parcel_id"></form>')
    assert search_form_reached(single)["fields"] == ["parcel_id"]  # one specific field counts


def test_gateway_words_use_link_text_only():
    from hardly.core.search_nav import score_link

    assert score_link("Online services", "/x")[0] > 0
    assert score_link("About us", "/portal/about")[0] == 0  # path alone is not a gateway
