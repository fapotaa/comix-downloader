"""Offline unit tests (no network, no browser)."""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import comix  # noqa: E402


def test_build_query_matches_axios():
    q = comix.build_query({
        "order": {"created_at": "desc"},
        "content_rating": ["safe", "suggestive"],
        "page": 1, "limit": 10, "_": "abc-_x",
    })
    assert q == ("order%5Bcreated_at%5D=desc&content_rating%5B%5D=safe&content_rating%5B%5D=suggestive"
                 "&page=1&limit=10&_=abc-_x")


def test_build_query_spaces_and_specials():
    assert comix.build_query({"keyword": "murim psychopath!"}) == "keyword=murim+psychopath%21"


@pytest.mark.parametrize("inp,expected", [
    ("comix.io", "https://comix.io"),
    ("https://comix.io/", "https://comix.io"),
    ("https://www.comix.io/title/eqy5m-x", "https://www.comix.io"),
    ("http://127.0.0.1:8080", "http://127.0.0.1:8080"),
])
def test_normalize_origin(inp, expected):
    assert comix.normalize_origin(inp) == expected


def test_set_origin_changes_global():
    old = comix.ORIGIN
    try:
        assert comix.set_origin("new-comix.net") == "https://new-comix.net"
        assert comix.ORIGIN == "https://new-comix.net"
    finally:
        comix.ORIGIN = old


@pytest.mark.parametrize("inp,expected", [
    ("eqy5m", ("eqy5m", None)),
    ("https://comix.to/title/eqy5m-murim-psychopath", ("eqy5m", None)),
    ("https://any-other-domain.io/title/eqy5m-murim-psychopath/9593389-chapter-27", ("eqy5m", 9593389)),
    ("murim psychopath", (None, None)),
    ("naruto", (None, None)),
])
def test_parse_target(inp, expected):
    assert comix.parse_target(inp) == expected


def test_parse_selection():
    nums = [0, 1, 2, 3, 4, 5, 5.5, 6, 10]
    assert comix.parse_selection("1-3,5.5", nums) == {1, 2, 3, 5.5}
    assert comix.parse_selection("latest", nums) == {10}
    assert comix.parse_selection("last2", nums) == {6, 10}
    assert comix.parse_selection("8-", nums) == {10}
    assert comix.parse_selection("all", nums) == set(nums)


def test_fmt_num():
    assert comix.fmt_num(7) == "007"
    assert comix.fmt_num(27.5) == "027.5"


def test_pick_one_per_number_prefers_group():
    chs = [
        {"id": 1, "number": 5, "group": {"name": "Asura Scans"}, "votes": 0},
        {"id": 2, "number": 5, "group": {"name": "UToon"}, "votes": 9},
        {"id": 3, "number": 6, "group": {"name": "UToon"}, "votes": 0},
    ]
    assert [c["id"] for c in comix.pick_one_per_number(chs, "asura")] == [1, 3]
    assert [c["id"] for c in comix.pick_one_per_number(chs, None)] == [2, 3]
