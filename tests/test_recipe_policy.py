"""Recipe guard and headless find_click gate stop."""

from hardly.capture import _find_click, _run_inprocess_recipe
from hardly.core.recipe_policy import check_step


def test_allows_ordinary_steps():
    for step in (
        {"op": "goto", "url": "https://x.example/challenge"},
        {"op": "click", "css": "a.next"},
        {"op": "fill", "css": "#q", "value": "abc"},
        {"op": "evaluate", "js": "document.title"},
        {"op": "wait", "ms": 10},
    ):
        assert check_step(step) == (True, ""), step


def test_refuses_captcha_targets():
    for step in (
        {"op": "click", "css": ".g-recaptcha"},
        {"op": "click", "selector": "iframe[src*=hcaptcha]"},
        {"op": "click", "text": "Verify you are human (Turnstile)"},
        {"op": "press", "ref": "e12-captcha"},
        {"op": "fill", "css": "#h-captcha-response", "value": "x"},
        {"op": "click", "css": "#challenge-form button"},
        {"op": "fetch", "url": "https://x.example/captcha/verify"},
    ):
        ok, why = check_step(step)
        assert not ok and why.startswith("policy:"), step


def test_refuses_gate_js():
    for js in ("grecaptcha.execute('k')", "turnstile.render('#x')", "hcaptcha.execute()"):
        ok, why = check_step({"op": "evaluate", "js": js})
        assert not ok and why.startswith("policy:")


def test_password_fill_needs_allow_login():
    step = {"op": "fill", "css": "input[type=password]", "value": "pw"}
    ok, why = check_step(step)
    assert not ok and "allow_login" in why
    assert check_step({**step, "allow_login": True}) == (True, "")
    assert not check_step({"op": "fill", "css": "#password", "value": "x"})[0]


def test_reason_never_echoes_values():
    ok, why = check_step({"op": "fill", "css": "#password", "value": "SECRETPASSWORD"})
    assert not ok and "SECRETPASSWORD" not in why


class _Page:
    def __init__(self, html, url="https://x.example/"):
        self._html = html
        self.url = url
        self.clicked = []

    def content(self):
        return self._html

    def wait_for_load_state(self, *a, **k):
        pass

    def wait_for_timeout(self, *a, **k):
        pass

    def locator(self, css):
        return _Locator(self, css)


class _Locator:
    """Inspecting the page is fine; clicking through a gate is not."""

    def __init__(self, page, css):
        self.page, self.css = page, css

    @property
    def first(self):
        return self

    def count(self):
        return 1

    def wait_for(self, *a, **k):
        pass

    def click(self, *a, **k):
        self.page.clicked.append(self.css)
        raise AssertionError("must not click through a gate")


def test_inprocess_runner_refuses_step():
    page = _Page("<html></html>")
    out = _run_inprocess_recipe(page, [{"op": "click", "css": ".g-recaptcha"}])
    assert out["ok"] is False
    step = out["steps"][0]
    assert step["ok"] is False and step["error"].startswith("policy:")
    assert page.clicked == []


def test_find_click_stops_on_gate():
    html = ("<html><body>" + "<p>x</p>" * 40 + '<div class="g-recaptcha" data-sitekey="K"></div>'
            '<script src="https://www.google.com/recaptcha/api.js"></script>'
            '<a href="/search">Search records</a></body></html>')
    page = _Page(html)
    out = _find_click(page, {"keywords": ["records"]})
    assert out["reached"] is False and "captcha" in out["blocked"]
    assert page.clicked == []


def test_find_click_stops_on_login_page():
    html = "<html><body>" + "<p>x</p>" * 40 + '<form><input type="password" name="p"></form></body></html>'
    out = _find_click(_Page(html), {"keywords": ["x"]})
    assert out["reached"] is False and out["blocked"] == ["login"]
