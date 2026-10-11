"""Translation of IAM wildcard patterns into Z3 regular expressions.

Two matching modes exist in IAM:

* plain globs (Action, StringLike): `*` matches any run of characters,
  `?` exactly one, anywhere in the string;
* ARN globs (Resource, ArnLike): the ARN is matched segment by segment,
  so a `*` in the first five colon-separated segments cannot swallow a
  colon. The sixth segment (the resource part) may itself contain
  colons, so wildcards there match anything.

Both encodings are exact; nothing here approximates.

The request's resource is not one string variable but six, one per ARN
segment (see ArnVar). Z3's regex reasoning is far faster on short
independent segments than on one long string under intersected and
complemented regexes: the fuzzer found queries that took 30 seconds and
timed out in the single-string encoding, and they take milliseconds this
way. Every AWS resource is a six-segment ARN, so nothing is lost.
"""

from __future__ import annotations

from functools import lru_cache

import z3

_RE = z3.ReSort(z3.StringSort())
ANY_CHAR = z3.AllChar(_RE)
NON_COLON = z3.Intersect(ANY_CHAR, z3.Complement(z3.Re(":")))
PRINTABLE = z3.Star(z3.Range(" ", "~"))

WILDCARDS = frozenset("*?")
_BACKSLASH = chr(92)


def sval(text: str) -> z3.SeqRef:
    """A Z3 string literal for arbitrary text.

    z3.StringVal interprets backslash-u{hex} escape sequences in its argument, so a
    policy that literally contains one would be silently misread. Escaping
    every backslash first makes the literal exact.
    """
    # ${*} and ${?} reach here as private-use markers (see variables.py): they are literal characters.
    text = text.replace("\ue000", "*").replace("\ue001", "?")
    return z3.StringVal(text.replace(_BACKSLASH, _BACKSLASH + "u{5c}"))


def literal_re(text: str) -> z3.ReRef:
    return z3.Re(sval(text))


def has_wildcard(pattern: str) -> bool:
    return any(c in WILDCARDS for c in pattern)


def _concat(parts: list[z3.ReRef]) -> z3.ReRef:
    if not parts:
        return z3.Re("")
    if len(parts) == 1:
        return parts[0]
    return z3.Concat(*parts)


def _glob(pattern: str, char: z3.ReRef) -> z3.ReRef:
    parts: list[z3.ReRef] = []
    chars: list[str] = []
    for c in pattern:
        if c in WILDCARDS:
            if chars:
                parts.append(literal_re("".join(chars)))
                chars = []
            parts.append(z3.Star(char) if c == "*" else char)
        else:
            chars.append(c)
    if chars:
        parts.append(literal_re("".join(chars)))
    return _concat(parts)


@lru_cache(maxsize=4096)
def glob(pattern: str) -> z3.ReRef:
    """Plain glob: `*` and `?` match any character, including colons."""
    return _glob(pattern, ANY_CHAR)


@lru_cache(maxsize=4096)
def arn_glob(pattern: str) -> z3.ReRef:
    """ARN glob: wildcards in the first five segments stay inside their segment.

    A pattern that is not a six-segment ARN (most commonly a bare "*")
    falls back to a plain glob.
    """
    segments = pattern.split(":", 5)
    if len(segments) < 6:
        return glob(pattern)
    regexes = [_glob(seg, NON_COLON) for seg in segments[:5]] + [_glob(segments[5], ANY_CHAR)]
    parts: list[z3.ReRef] = []
    for i, r in enumerate(regexes):
        if i:
            parts.append(z3.Re(":"))
        parts.append(r)
    return _concat(parts)


def matches_any(var: z3.SeqRef, patterns: tuple[str, ...], arn: bool) -> z3.BoolRef:
    """`var` matches at least one pattern. Wildcard-free patterns become plain equalities."""
    terms = []
    for p in patterns:
        if not has_wildcard(p):
            terms.append(var == sval(p))
        else:
            terms.append(z3.InRe(var, arn_glob(p) if arn else glob(p)))
    return z3.Or(terms) if len(terms) > 1 else terms[0]


class ArnVar:
    """A symbolic resource ARN: six segment variables, the first five colon-free."""

    def __init__(self, name: str):
        self.segments = [z3.String(f"{name}_{i}") for i in range(6)]
        colon = sval(":")
        pieces: list[z3.SeqRef] = []
        for i, seg in enumerate(self.segments):
            if i:
                pieces.append(colon)
            pieces.append(seg)
        self.full = z3.Concat(*pieces)
        self.well_formed = [z3.Not(z3.Contains(seg, colon)) for seg in self.segments[:5]]

    def matches(self, pattern: str) -> z3.BoolRef:
        parts = pattern.split(":", 5)
        if len(parts) < 6:
            # Not ARN-shaped (most often a bare "*"): match the whole string.
            return z3.InRe(self.full, glob(pattern)) if has_wildcard(pattern) else self.full == sval(pattern)
        terms = [
            z3.InRe(seg, glob(part)) if has_wildcard(part) else seg == sval(part)
            for seg, part in zip(self.segments, parts)
            if part != "*"  # well_formed already confines each segment
        ]
        if not terms:
            return z3.BoolVal(True)
        return z3.And(terms) if len(terms) > 1 else terms[0]

    def matches_any(self, patterns: tuple[str, ...]) -> z3.BoolRef:
        terms = [self.matches(p) for p in patterns]
        if not terms:
            return z3.BoolVal(False)
        return z3.Or(terms) if len(terms) > 1 else terms[0]
