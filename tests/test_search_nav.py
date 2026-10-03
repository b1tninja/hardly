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


def test_goal_detector_ignores_utility_forms_seen_on_real_sites():
    from hardly.core.search_nav import search_form_reached as reached

    def s(html):
        return extract_html_structure(html)

    # sf.gov: header search with nameless inputs
    assert reached(s('<form action="/search"><input type="text"><input type="text"></form>')) is None
    # newsletter (single email field)
    assert reached(s('<form action="/subscribe" method="post"><input type="email" name="email"><input type="submit"></form>')) is None
    # language selector only
    assert reached(s('<form method="post"><select name="lang_dropdown_select"><option>en</option></select></form>')) is None
    # feedback / report-a-problem with honeypot
    assert reached(s('<form action="/contact/govuk/problem_reports"><input name="giraffe"><textarea name="what_wrong"></textarea></form>')) is None
    # site search boxes by name
    for name in ("keys", "cdsSearchText", "search_term", "q"):
        assert reached(s(f'<form action="/find"><input type="text" name="{name}"><input type="submit"></form>')) is None, name
    # a specific one-field lookup counts, and a keyword can rescue a generic name
    assert reached(s('<form action="/x"><input type="text" name="entity_name"><input type="submit"></form>'))
    assert reached(s('<form action="/x"><input type="text" name="q"><input type="submit"></form>'), keywords=["q"]) is not None
    # specific one-field lookup rejected when keywords are given and do not match
    assert reached(s('<form action="/x"><input type="text" name="entity_name"><input type="submit"></form>'), keywords=["parcel"]) is None


def test_hidden_mobile_triggers_are_not_candidates():
    from hardly.core.search_nav import actions_as_links

    acts = [
        {"kind": "button", "tag": "button", "id": "mobile-trigger-search", "name": "", "text": "View Search", "xpath": ""},
        {"kind": "button", "tag": "button", "id": "go", "name": "", "text": "Search records", "xpath": ""},
    ]
    assert [a["css"] for a in actions_as_links(acts)] == ["#go"]


def test_generic_keywords_cannot_vouch_for_site_search():
    from hardly.core.search_nav import search_form_reached as reached

    box = extract_html_structure('<form action="/x"><input type="text" name="search"><input type="submit"></form>')
    assert reached(box, keywords=["search", "records"]) is None
    assert reached(box, keywords=["search", "parcel"]) is None       # name does not mention parcel
    spec = extract_html_structure('<form action="/x"><input type="text" name="parcel_search"><input type="submit"></form>')
    assert reached(spec, keywords=["parcel"]) is not None


def test_feedback_links_are_never_candidates():
    from hardly.core.search_nav import score_link

    for text in ("Did you find what you needed?", "Was this page helpful?", "Take our survey", "Give us feedback"):
        assert score_link(text, "/x", ("permit",))[0] == 0, text
    assert score_link("Find a permit", "/x", ("permit",))[0] > 0


def test_keyword_vouches_by_field_name_not_action_url():
    from hardly.core.search_nav import search_form_reached as reached

    form = '<form action="/lookup/permits"><input type="text" name="keys"><input type="submit"></form>'
    assert reached(extract_html_structure(form), keywords=["permit"]) is None      # action only
    named = '<form action="/lookup"><input type="text" name="permit_number"><input type="submit"></form>'
    assert reached(extract_html_structure(named), keywords=["permit"]) is not None


def test_one_box_search_accepted_only_after_deliberate_navigation():
    from hardly.core.search_nav import has_search_term, search_form_reached as reached

    box = extract_html_structure('<form action="/x"><input type="text" name="query"><input type="submit"></form>')
    assert reached(box) is None
    assert reached(box, allow_site_search=True) is not None          # we followed "Search Online Catalog" to get here
    newsletter = extract_html_structure('<form action="/subscribe"><input type="email" name="email"></form>')
    assert reached(newsletter, allow_site_search=True) is None       # utility forms stay rejected
    assert has_search_term("Search Online Catalog") and not has_search_term("Tanks - fire permit application")


def test_site_search_with_scope_selector_is_not_a_lookup():
    from hardly.core.search_nav import search_form_reached as reached

    scoped = extract_html_structure(
        '<form action="/results"><select name="search_type"><option>all</option></select>'
        '<input type="text" name="q"><input type="submit"></form>'
    )
    assert reached(scoped) is None
    assert reached(scoped, allow_site_search=True) is not None  # deliberately navigated here
    real = extract_html_structure(
        '<form action="/results"><select name="county"><option>a</option></select>'
        '<input type="text" name="owner_name"><input type="submit"></form>'
    )
    assert reached(real) is not None
