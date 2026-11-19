"""
Text as a reader sees it, for guards that match patterns against it (GHSA-v3m4).

A guard that matches a phrase, a secret or an identifier against text as sent
misses it when an invisible character sits inside: U+200B ZERO WIDTH SPACE,
U+00AD SOFT HYPHEN, U+FEFF and the other Unicode Default_Ignorable_Code_Point
characters draw nothing, so a model reads the phrase and a person or a script
recovers the secret by removing them. Nothing shows either for a control
character that is not Unicode White_Space (U+001C to U+001F and U+0085
NEXT LINE included, which Python's str.isspace() counts as whitespace), a
format character (Cf), a nonspacing mark (Mn: a combining dot above on an
i shows as an i, and joiners such as U+2D7F show nothing), a lone
surrogate, or a code point this Python does not know (Cn), which a newer
Unicode may make a format character (U+13439 to U+1343F on Python 3.10 and
3.11), so the reading does not depend on the Python version. Some
characters draw a blank as wide as a space (U+2800 BRAILLE PATTERN BLANK,
the Hangul fillers, U+1D159 MUSICAL SYMBOL NULL NOTEHEAD). Fullwidth and
other compatibility forms (NFKC) are read as the plain characters.

Each character is read on its own. The distinct characters of a text are
read once for all its readings (and the most common ones are kept between
calls), and each reading is one pass over the text, so the cost is linear in
the length of the text. NFKC of
a whole string is not: CPython takes seconds for 100,000 characters that each
expand to many (U+FDFA). Read one at a time, a letter does not compose with a
combining mark after it; no composed character is ASCII, so this never hides
an ASCII match that NFKC of the whole string would show. A compatibility
form is taken only when it is a space or holds other ASCII, and is no longer
than the character's UTF-8 encoding, so no copy has more characters than the
text has bytes, and a guard reads no copy more slowly than ASCII text of the
same size.

- ``reading_copies``: the text as written; then with the invisible
  characters removed (they joined a word or a secret); then with each run of
  them read as one space (they separated words); then as it shows, the
  blanks read as spaces and the rest removed; and, when the text holds
  Unicode tag characters (U+E0020 to U+E007E, an invisible copy of ASCII that
  some models read), the same three readings with those read as the ASCII
  they encode.
- ``marked_copies`` and ``read_through``: for a phrase, the text with each
  invisible character written as U+200B (and tag characters as ASCII, in a
  second copy), and the phrase pattern rewritten so that U+200B may sit
  between two letters of a word, wherever the pattern allows whitespace, and
  after any character a ``.`` matches. A phrase that uses invisible
  characters inside words and between them at once is still found, as in
  SecurityGateway (#644).

- ``decoded_json``: for a guard given JSON, the strings and keys it holds,
  which may write any character as an escape.

What a guard returns about a match comes from these copies; nothing here
changes the text it was given.
"""

import functools
import json
import re
import unicodedata
from typing import Any, Dict, List, Optional, Tuple

# Unicode Default_Ignorable_Code_Point, as SecurityGateway reads it (#644).
IGNORABLE_RANGES = (
    "\u00ad\u034f\u061c\u115f\u1160\u17b4\u17b5\u180b-\u180f"
    "\u200b-\u200f\u202a-\u202e\u2060-\u206f\u3164\ufe00-\ufe0f"
    "\ufeff\uffa0\ufff0-\ufff8"
    "\U0001bca0-\U0001bca3\U0001d173-\U0001d17a\U000e0000-\U000e0fff"
)
_DEFAULT_IGNORABLE = re.compile(f"[{IGNORABLE_RANGES}]")
# Characters that draw a blank as wide as a space.
_BLANKS = frozenset("\u115f\u1160\u3164\uffa0\u2800")
# U+1D159 MUSICAL SYMBOL NULL NOTEHEAD draws a blank too.
_BLANKS = _BLANKS | frozenset(map(chr, (0x1D159,)))
# Unicode White_Space, which a reader sees as a space. Not U+0085 NEXT LINE,
# which most text draws as nothing, and not U+001C to U+001F, which Python's
# str.isspace() counts but Unicode does not.
_WHITE_SPACE = frozenset(map(chr, (
    *range(0x09, 0x0E), 0x20, 0xA0, 0x1680, *range(0x2000, 0x200B), 0x2028, 0x2029, 0x202F, 0x205F, 0x3000,
)))
# Categories a reader sees nothing for: controls, format characters,
# nonspacing marks, lone surrogates and code points this Python does not know.
_UNSEEN_CATEGORIES = frozenset(("Cc", "Cf", "Cn", "Cs", "Mn"))
# What ``marked_copies`` writes for every character a reader does not see.
MARK = "\u200b"
_MARK_RUN = re.compile(MARK + "+")
_SEPARATOR = {"+": rf"(?:\s|{MARK})+", "*": rf"(?:\s|{MARK})*", "": rf"(?:\s|{MARK})"}
# Any one character a reader sees, with what does not show after it.
_ANY_SEEN = rf"(?:[^{MARK}]{MARK}*)"
# ASCII control characters that are not White_Space: the only ASCII a reader
# does not see.
_ASCII_INVISIBLE = re.compile(r"[\x00-\x08\x0e-\x1f\x7f]")
_TAG = re.compile("[\U000e0020-\U000e007e]")
_TAG_OFFSET = 0xE0000


def _invisible(char: str) -> bool:
    """Whether a reader sees no letter or digit for *char*. White_Space is
    seen as space."""
    if char in _WHITE_SPACE:
        return False
    return (
        unicodedata.category(char) in _UNSEEN_CATEGORIES
        or char in _BLANKS
        or _DEFAULT_IGNORABLE.match(char) is not None
    )


def _read_char(char: str) -> str:
    """*char* as ``marked_copies`` reads it. A compatibility form is taken
    when it is a space or holds an ASCII character other than a space (the
    guards' patterns are ASCII), and is no longer than the character's UTF-8
    encoding (U+FDFA is 18 characters, U+33C2 is "a.m.")."""
    if _invisible(char):
        return MARK
    if char.isascii() or unicodedata.is_normalized("NFKC", char):
        return char
    folded = unicodedata.normalize("NFKC", char)
    if len(folded) > len(char.encode("utf-8")):
        return char
    if folded.isspace() or any(c.isascii() and not c.isspace() for c in folded):
        return "".join(MARK if _invisible(c) else c for c in folded)
    return char


# ``_read_char`` kept for the most common characters between calls. A text
# with more distinct characters than the cache holds reads them uncached, as
# a cache that size would only turn over.
_CACHE_SIZE = 4096
_marked = functools.lru_cache(maxsize=_CACHE_SIZE)(_read_char)


# Tag characters, for ``str.translate``, as the ASCII they encode. What they
# give is printable ASCII, which no reading changes.
_TAG_TO_ASCII = {code: chr(code - _TAG_OFFSET) for code in range(0xE0020, 0xE007F)}


def _translations(text: str) -> Tuple[Dict[int, str], Dict[int, str]]:
    """For ``str.translate``, the distinct characters of *text* that a
    reading changes: as marked (``_read_char``) and as shown (a blank as a
    space, anything else that does not show removed). One pass over the
    distinct characters makes every reading; a character in neither stays as
    written in all of them (a blank, a tag character and U+200B itself are
    invisible, so they are in both)."""
    distinct = set(text)
    read = _marked if len(distinct) <= _CACHE_SIZE else _read_char
    marked: Dict[int, str] = {}
    shown: Dict[int, str] = {}
    for char in distinct:
        changed = read(char)
        if changed != char or changed == MARK:
            code = ord(char)
            marked[code] = changed
            shown[code] = " " if char in _BLANKS else changed.replace(MARK, "")
    return marked, shown


def _plain(text: str) -> bool:
    """Whether *text* is ASCII a reader sees in full."""
    return text.isascii() and not _ASCII_INVISIBLE.search(text)


def _marked_readings(text: str, marked: Dict[int, str]) -> Tuple[str, ...]:
    copies = [text.translate(marked)]
    if _TAG.search(text):
        copies.append(text.translate(_TAG_TO_ASCII).translate(marked))
    return tuple(dict.fromkeys(copies))


def _readings(text: str, marked: Dict[int, str], shown: Dict[int, str]) -> Tuple[str, ...]:
    copies = [text, *_seen_readings(text, marked, shown)]
    if _TAG.search(text):
        copies += _seen_readings(text.translate(_TAG_TO_ASCII), marked, shown)
    return tuple(dict.fromkeys(copies))


def marked_copies(text: str) -> Tuple[str, ...]:
    """*text* in NFKC, one character at a time, with each character a reader
    does not see written as U+200B; then, if it holds tag characters, the
    same with those read as ASCII. None for ASCII a reader sees in full,
    which the patterns as written have read."""
    if not isinstance(text, str) or _plain(text):
        return ()
    return _marked_readings(text, _translations(text)[0])


def reading_copies(text: str) -> Tuple[str, ...]:
    """``text`` as written, then read with the invisible characters removed,
    with each run of them read as one space, and as it shows; then, if it
    holds tag characters, the same three with those read as ASCII; each copy
    once."""
    if not isinstance(text, str) or _plain(text):
        return (text,)
    return _readings(text, *_translations(text))


def text_readings(text: str) -> Tuple[Tuple[str, ...], Tuple[str, ...]]:
    """``reading_copies`` and ``marked_copies`` of *text*, from one pass over
    its distinct characters."""
    if not isinstance(text, str) or _plain(text):
        return (text,), ()
    marked, shown = _translations(text)
    return _readings(text, marked, shown), _marked_readings(text, marked)


def _seen_readings(text: str, marked: Dict[int, str], shown: Dict[int, str]) -> Tuple[str, str, str]:
    """The three readings of *text*: invisible characters removed, each run
    of them read as one space, and as it shows (a blank as a space, anything
    else that does not show removed)."""
    as_marked = text.translate(marked)
    return as_marked.replace(MARK, ""), _MARK_RUN.sub(" ", as_marked), text.translate(shown)


_NOT_JSON = object()


def _escaped_json(text: str) -> Any:
    """*text* parsed, when it is JSON that writes an escape; else _NOT_JSON."""
    if not isinstance(text, str) or chr(92) not in text:
        return _NOT_JSON
    try:
        return json.loads(text)
    except (ValueError, RecursionError):
        return _NOT_JSON


def _dict_lines(item: Dict[str, Any], keyed: bool) -> Tuple[List[str], List[Any]]:
    """The lines a JSON object adds, and the values left to read: its keys,
    or with *keyed* each string value on its key's line."""
    if not keyed:
        return list(item), list(item.values())
    lines: List[str] = []
    rest: List[Any] = []
    for key, entry in item.items():
        if isinstance(entry, str):
            lines.append(f"{key}: {entry}")
        else:
            lines.append(key)
            rest.append(entry)
    return lines, rest


def _json_lines(value: Any, keyed: bool) -> str:
    found: List[str] = []
    pending = [value]
    while pending:
        item = pending.pop()
        if isinstance(item, str):
            found.append(item)
        elif isinstance(item, dict):
            lines, rest = _dict_lines(item, keyed)
            found.extend(lines)
            pending.extend(rest)
        elif isinstance(item, list):
            pending.extend(item)
    return "\n".join(reversed(found))


def decoded_json(text: str) -> Optional[str]:
    """The strings and keys *text* holds, one per line, when it is JSON that
    writes an escape; else None. A JSON string may write any character as an
    escape (a zero-width space, a tag character, a plain digit), which the
    text as sent does not show, so a guard given JSON reads these too."""
    value = _escaped_json(text)
    return None if value is _NOT_JSON else _json_lines(value, keyed=False)


def json_readings(text: str) -> Tuple[str, ...]:
    """``decoded_json`` of *text*, then the same with each string value on
    its key's line, as ``key: value``, for a guard that reads a value by the
    key it sits under; every key and string is in both. Parsed once; () when
    *text* is not JSON that writes an escape."""
    value = _escaped_json(text)
    if value is _NOT_JSON:
        return ()
    return _json_lines(value, keyed=False), _json_lines(value, keyed=True)


def read_through(pattern: str) -> str:
    """*pattern*, written for text as sent, rewritten for ``marked_copies``:
    U+200B may sit between two letters of a word, wherever the pattern
    allows whitespace (``\\s``, ``\\s+``, ``\\s*``), and after any character
    ``.`` matches, so ``.{0,40}`` counts only characters that show.
    Everything else is kept as written. For the guards' own phrase patterns,
    which hold letters, ``\\s``, ``.``, escapes, groups, classes and
    quantifiers.

    U+200B is not allowed after a word's last letter, where a separator or
    what follows takes it, and before a letter that may be absent (``n?``,
    ``[s]?``) it sits inside that letter's group, so no two parts match the
    same characters and a run of U+200B cannot make a match backtrack
    polynomially (#644)."""
    parts = []
    after_letter = False
    i = 0
    while i < len(pattern):
        char = pattern[i]
        if pattern.startswith("\\s", i):
            quantifier = pattern[i + 2:i + 3] if pattern[i + 2:i + 3] in ("+", "*") else ""
            parts.append(_SEPARATOR[quantifier])
            i += 2 + len(quantifier)
            after_letter = False
            continue
        if char == ".":
            parts.append(_ANY_SEEN)
            i += 1
            after_letter = False
            continue
        if char.isalpha() or char == "'" or char == "[":
            # A letter, or a class standing for one, of a word.
            end = pattern.index("]", i + 2) + 1 if char == "[" else i + 1
            atom = pattern[i:end]
            if not after_letter:
                parts.append(atom)
            elif pattern[end:end + 1] in ("?", "*", "+", "{"):
                parts.append(f"(?:{MARK}*{atom})")
            else:
                parts.append(MARK + "*" + atom)
            i = end
            after_letter = True
            continue
        if char == "\\":
            end = i + 2
        elif pattern.startswith("(?", i) and pattern[i + 2:i + 3] != ":":
            end = pattern.index(")", i) + 1
        else:
            end = i + 1
        parts.append(pattern[i:end])
        i = end
        after_letter = False
    return "".join(parts)
