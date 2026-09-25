"""Quoting a value into a sipnab filter expression.

The filter language's strings take `\\'` for a quote and keep every other
backslash sequence verbatim, so regex syntax survives (src/sip/dsl.rs,
`scan_quoted_string`). A value holding a backslash therefore cannot be
compared for equality at all: `\\\\` reaches the comparison as two
characters. Quoting it anyway would filter on a different value than the
one asked for, so it is refused.
"""

import importlib.util
import pathlib
import sys

import pytest

CLIENTS = pathlib.Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("sipnab_dsl", CLIENTS / "sipnab_dsl.py")
dsl = importlib.util.module_from_spec(spec)
sys.modules["sipnab_dsl"] = dsl
spec.loader.exec_module(dsl)


def test_a_plain_value_is_single_quoted():
    assert dsl.quote("busy-3a2b1c@192.0.2.30") == "'busy-3a2b1c@192.0.2.30'"


def test_a_single_quote_inside_is_escaped():
    assert dsl.quote("o'brien") == "'o\\'brien'"


def test_a_double_quote_inside_needs_no_escape():
    assert dsl.quote('say "hi"') == "'say \"hi\"'"


def test_a_value_holding_a_backslash_is_refused():
    with pytest.raises(ValueError, match="backslash"):
        dsl.quote("a\\b")
