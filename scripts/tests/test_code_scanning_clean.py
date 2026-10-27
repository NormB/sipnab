# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: The sipnab contributors

"""scripts/code-scanning-clean.py: reading what `gh api --paginate` prints.

`--paginate` writes each page's JSON array straight after the previous one,
`[...][...]`, with nothing between. The script must turn that into one list
without reading the text of an alert as a page boundary, and must still refuse
an answer that is not JSON.
"""

import json

from conftest import load

scan = load("code-scanning-clean")


def alert(number, message):
    return {"number": number, "state": "open", "rule": {"id": "osv/x"},
            "most_recent_instance": {"message": {"text": message}}}


def test_an_alert_whose_text_holds_brackets_reads_as_one_page():
    page = [alert(1, "affected versions: [6.7.0][6.16.1)")]
    assert scan.merge_pages(json.dumps(page)) == page


def test_two_pages_back_to_back_merge_into_one_list():
    first = [alert(1, "a")]
    second = [alert(2, "b"), alert(3, "c")]
    out = json.dumps(first) + json.dumps(second)
    assert scan.merge_pages(out) == first + second


def test_pages_with_brackets_in_their_text_merge_in_order():
    first = [alert(1, "ranges [1.0][2.0)")]
    second = [alert(2, "list ][ end")]
    out = json.dumps(first) + json.dumps(second)
    assert scan.merge_pages(out) == first + second


def test_whitespace_between_pages_is_allowed():
    first, second = [alert(1, "a")], [alert(2, "b")]
    out = json.dumps(first, indent=2) + "\n" + json.dumps(second) + "\n"
    assert scan.merge_pages(out) == first + second


def test_an_empty_list_reads_as_no_alerts():
    assert scan.merge_pages("[]") == []


def test_an_answer_that_is_not_json_is_refused():
    assert scan.merge_pages("<html>502 Bad Gateway</html>") is None


def test_a_page_that_is_not_a_list_is_refused():
    assert scan.merge_pages('{"message": "Not Found"}') is None


def test_trailing_text_after_the_pages_is_refused():
    assert scan.merge_pages(json.dumps([alert(1, "a")]) + " oops") is None


def test_nothing_at_all_is_refused():
    assert scan.merge_pages("") is None
