"""Quote a value into a sipnab filter expression.

sipnab's filter strings take `\\'` for a single quote and keep every other
backslash sequence verbatim, so regex syntax survives into `=~`
(src/sip/dsl.rs, `scan_quoted_string`). The same rule means a backslash in a
value compared with `==` reaches the comparison doubled, so such a value
cannot be matched exactly and is refused rather than quietly filtered on
something else. Standard library only.
"""


def quote(value: str) -> str:
    """`value` as a single-quoted filter string, or ValueError."""
    if "\\" in value:
        raise ValueError(
            f"{value!r} holds a backslash, which a sipnab filter string cannot "
            "compare exactly"
        )
    return "'" + value.replace("'", "\\'") + "'"
