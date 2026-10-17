from hardly.core.htmlsafe import defuse_html


def test_well_formed_markup_is_untouched():
    html = '<div class="a"><a href="/x?a=1&b=2">x</a><input value="<b>"></div> a < b'
    assert defuse_html(html) == html


def test_unterminated_tag_starts_become_text():
    run = "<a href=" * 300
    assert defuse_html(run + "<b>") == "&lt;a href=" * 300 + "<b>"
    assert defuse_html("text " + run).startswith("text &lt;a href=&lt;")
    assert defuse_html("<a href=<a href=<b>") == "<a href=<a href=<b>"  # few: left as written


def test_pathological_run_is_linear():
    import time

    t0 = time.perf_counter()
    out = defuse_html("<a href=" * 100_000)
    assert time.perf_counter() - t0 < 2
    assert "<" not in out
