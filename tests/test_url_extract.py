"""URL extraction from the kind of text a person actually pastes."""

from scam_cemetery.url_extract import extract_urls, refang


def test_text_around_the_link():
    text = "hey can you check https://phish.example/login?id=1 thanks"
    assert extract_urls(text) == ["https://phish.example/login?id=1"]


def test_no_scheme():
    assert extract_urls("see example.com/login before you pay") == ["https://example.com/login"]


def test_bare_domain():
    assert extract_urls("example.com") == ["https://example.com"]


def test_multiple_links_keep_order_and_drop_duplicates():
    text = "first https://a.example/x then b.example/y and again https://a.example/x"
    assert extract_urls(text) == [
        "https://a.example/x",
        "https://b.example/y",
    ]


def test_no_link_at_all():
    assert extract_urls("hello, just chatting, nothing to look up") == []
    assert extract_urls("") == []
    assert extract_urls("   ") == []


def test_defanged_hxxp_and_bracket_dot():
    text = "do not open hxxp://phish[.]example/login"
    assert refang(text) == "do not open http://phish.example/login"
    assert extract_urls(text) == ["http://phish.example/login"]


def test_defanged_hxxps_dot_word_and_colon():
    assert extract_urls("hxxps://bad[.]example[.]com/a") == ["https://bad.example.com/a"]
    assert extract_urls("hxxp[:]//evil[.]com/a") == ["http://evil.com/a"]
    assert extract_urls("see login[.]example/reset") == ["https://login.example/reset"]
    assert extract_urls("evil(dot)example/a") == ["https://evil.example/a"]


def test_email_and_filename_are_not_links():
    assert extract_urls("mail me at ada@example.com") == []
    assert extract_urls("the notes are in report.txt") == []


def test_trailing_punctuation_and_parentheses():
    assert extract_urls("See https://example.com.") == ["https://example.com"]
    assert extract_urls("(https://example.com/a)") == ["https://example.com/a"]
    assert extract_urls("check (hxxp://bad[.]example/login.) please") == [
        "http://bad.example/login"
    ]
    assert extract_urls("https://en.wikipedia.org/wiki/Foo_(bar)") == [
        "https://en.wikipedia.org/wiki/Foo_(bar)"
    ]
    assert extract_urls("https://en.wikipedia.org/wiki/Foo_(bar).") == [
        "https://en.wikipedia.org/wiki/Foo_(bar)"
    ]


def test_userinfo_is_dropped_so_it_is_not_stored():
    assert extract_urls("https://user:secret@example.com/a") == ["https://example.com/a"]


def test_a_bad_url_is_skipped_and_the_other_link_remains():
    text = "https://example.com:abc/a and also https://ok.example/x"
    assert extract_urls(text) == ["https://ok.example/x"]
    assert extract_urls("https://example.com:99999/a") == []
    assert extract_urls("http://[::1") == []


def test_bare_domain_keeps_its_query_string():
    assert extract_urls("example.com?token=abc") == ["https://example.com?token=abc"]
    assert extract_urls("see example.com/path?q=1 thanks") == ["https://example.com/path?q=1"]
