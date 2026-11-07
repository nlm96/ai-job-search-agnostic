"""Replace identity tokens in LaTeX source with escaped real values.

Escaping was checked empirically against the shipped templates (moderncv
with lualatex, cover.cls with xelatex):

* ordinary text, ``\\email{}``, ``\\name{}``, hyperref ``pdftitle`` and the
  first argument of a ``\\href`` nested in another command all accept the
  standard text escapes ``\\& \\% \\$ \\# \\_ \\{ \\}``; hyperref turns ``\\_``
  and ``\\%`` back into ``_`` and ``%`` in link targets;
* only ``~`` differs: in a URL argument ``\\~`` yields ``~``, while in text
  it is an accent, so text gets ``\\textasciitilde{}`` instead.
"""

from __future__ import annotations

import re

from privacy.identity import TOKEN_RE, TOKENS

FIELD_OF = {token: field for field, token in TOKENS.items()}

_TEXT_ESCAPES = {
    "\\": r"\textbackslash{}", "&": r"\&", "%": r"\%", "$": r"\$",
    "#": r"\#", "_": r"\_", "{": r"\{", "}": r"\}",
    "~": r"\textasciitilde{}", "^": r"\textasciicircum{}",
}
_URL_ESCAPES = dict(_TEXT_ESCAPES, **{"~": r"\~"})

_URL_COMMANDS = re.compile(r"\\(?:href|url)\s*\{")


class SubstitutionError(Exception):
    """Messages name tokens and fields, never values."""


def escape(value: str, url: bool = False) -> str:
    table = _URL_ESCAPES if url else _TEXT_ESCAPES
    return "".join(table.get(c, c) for c in value)


def url_spans(source: str) -> list[tuple[int, int]]:
    """Spans of the first argument of every \\href and \\url."""
    spans = []
    for m in _URL_COMMANDS.finditer(source):
        start = m.end()
        depth, i = 1, start
        while i < len(source) and depth:
            c = source[i]
            if c == "\\":
                i += 2
                continue
            depth += {"{": 1, "}": -1}.get(c, 0)
            i += 1
        if depth:
            raise SubstitutionError("unbalanced braces after \\href or \\url")
        spans.append((start, i - 1))
    return spans


def tokens_in(source: str) -> set[str]:
    return set(TOKEN_RE.findall(source))


def substitute(source: str, identity: dict) -> tuple[str, set[str]]:
    """Return the source with every token replaced, and the tokens used."""
    found = tokens_in(source)
    unknown = sorted(found - set(FIELD_OF))
    if unknown:
        raise SubstitutionError(f"unknown tokens: {', '.join(unknown)}")
    missing = sorted(t for t in found if not identity.get(FIELD_OF[t]))
    if missing:
        raise SubstitutionError(
            "tokens used but their identity field is empty: "
            + ", ".join(f"{t} ({FIELD_OF[t]})" for t in missing))
    spans = url_spans(source)

    def repl(m: re.Match) -> str:
        in_url = any(a <= m.start() < b for a, b in spans)
        return escape(identity[FIELD_OF[m.group(0)]], url=in_url)

    return TOKEN_RE.sub(repl, source), found
