import pytest

from veritas.core.netpolicy import classify_address, path_ambiguity, path_matches, pattern_problem


@pytest.mark.parametrize(
    ("addr", "allowed"),
    [
        ("127.0.0.1", True),
        ("10.1.2.3", True),
        ("172.30.0.4", True),
        ("192.168.1.10", True),
        ("::1", True),
        ("fd00::5", True),
        ("::ffff:172.30.0.5", True),
        ("169.254.169.254", False),
        ("fe80::1", False),
        ("8.8.8.8", False),
        ("172.32.0.1", False),
        ("100.64.0.1", False),
        ("0.0.0.0", False),
        ("::ffff:8.8.8.8", False),
        ("2001:db8::1", False),
        ("example.com", False),
    ],
)
def test_classify_address(addr, allowed):
    assert classify_address(addr)[0] is allowed


@pytest.mark.parametrize(
    ("pattern", "path", "expected"),
    [
        ("/api/**", "/api", True),
        ("/api/**", "/api/", True),
        ("/api/**", "/api/notes/7", True),
        ("/api/**", "/apix", False),
        ("/api/*", "/api/notes", True),
        ("/api/*", "/api/notes/7", False),
        ("/api/notes/*", "/api/notes/", True),
        ("/", "/", True),
        ("/", "/x", False),
        ("/search", "/search", True),
        ("/search", "/search2", False),
        ("/**/delete", "/api/notes/7/delete", True),
        ("/static/*.css", "/static/site.css", True),
    ],
)
def test_path_matches(pattern, path, expected):
    assert path_matches(pattern, path) is expected


@pytest.mark.parametrize("pattern", ["api", "/a?b", "/a/../b", "/a**", "/a\\b"])
def test_bad_patterns_are_reported(pattern):
    assert pattern_problem(pattern) is not None


@pytest.mark.parametrize("path", ["/api/../admin", "/api/%2e%2e/admin", "/api%2Fadmin", "/a//b", "/a\\b", "/./x", "x"])
def test_ambiguous_paths_are_refused(path):
    assert path_ambiguity(path) is not None


def test_plain_path_is_not_ambiguous():
    assert path_ambiguity("/api/notes/7") is None
