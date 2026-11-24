"""
Security Gateway for QWED.
Handles Prompt Injection detection and PII redaction.

OWASP LLM01:2025 - Prompt Injection Defense (Multi-Layer)
"""
import re
import base64
import logging
import unicodedata
from functools import lru_cache
from typing import Tuple, Optional
from difflib import SequenceMatcher

logger = logging.getLogger(__name__)

# Unicode Default_Ignorable_Code_Point: these draw nothing, so a reader skips them.
_IGNORABLE_RANGES = (
    "\u00ad\u034f\u061c\u115f\u1160\u17b4\u17b5\u180b-\u180f"
    "\u200b-\u200f\u202a-\u202e\u2060-\u206f\u3164\ufe00-\ufe0f"
    "\ufeff\uffa0\ufff0-\ufff8"
    "\U0001bca0-\U0001bca3\U0001d173-\U0001d17a\U000e0000-\U000e0fff"
)
_IGNORABLE = f"[{_IGNORABLE_RANGES}]"
_TOO_LONG = "Input too long (max 10000 chars)"
# Every copy the phrase check reads writes each default-ignorable as this
# one (PR #672). Its searches then read through one character, not a
# class of ranges, and match exactly where they matched before: the
# copies keep every other character, each where it was.
_MARK = "\u200b"
_ANY_IGNORABLE = re.compile(_IGNORABLE)
# A letter or digit a reader sees, in such a copy: U+200B is not one. Nor
# is a Greek letter, for a phrase's edges: one glued to a phrase
# ("instruction" + final sigma, "rules" + sigma) does not hide it (PR #672).
# Any letter or digit, Greek too: what makes a word follow a phrase
# ("forget all" + theta + " values" goes on).
_ANY_LETTER_OR_DIGIT = r"[^\W_]"
_SEEN_IN_COPY = r"(?![\u0370-\u03ff\u1f00-\u1fff])[^\W_]"


# A character that ends a line (str.splitlines reads the same ones).
_LINE_BREAK = re.compile(r"[\n\r\x0b\x0c\x1c-\x1e\x85\u2028\u2029]")


def _collapse_ws(text: str) -> str:
    """Each run of whitespace becomes one space, or one newline where the
    run breaks a line, so a line's start can still be read as a
    sentence's (PR #672)."""
    return re.sub(r'\s+', lambda run: "\n" if _LINE_BREAK.search(run.group()) else " ", text).strip()


# Letters from other scripts that a reader takes for Latin ones (#646),
# read as the Latin letter in one more copy of the text. NFKC leaves them.
_LOOKALIKES = str.maketrans({
    # Cyrillic
    "\u0430": "a", "\u0435": "e", "\u043a": "k", "\u043c": "m", "\u043e": "o", "\u0440": "p",
    "\u0441": "c", "\u0443": "y", "\u0445": "x", "\u0456": "i", "\u0458": "j", "\u0455": "s",
    "\u0501": "d", "\u051b": "q", "\u051d": "w", "\u04cf": "l", "\u04bb": "h",
    "\u0410": "a", "\u0412": "b", "\u0415": "e", "\u041a": "k", "\u041c": "m", "\u041d": "h",
    "\u041e": "o", "\u0420": "p", "\u0421": "c", "\u0422": "t", "\u0425": "x", "\u0406": "i",
    "\u0408": "j", "\u0405": "s", "\u04ae": "y", "\u051a": "q", "\u051c": "w",
    # Greek
    "\u03b1": "a", "\u03bf": "o", "\u03b9": "i", "\u03ba": "k", "\u03bd": "v", "\u03c1": "p",
    "\u03c5": "u", "\u03c7": "x", "\u03b5": "e",
    "\u0391": "a", "\u0392": "b", "\u0395": "e", "\u0396": "z", "\u0397": "h", "\u0399": "i",
    "\u039a": "k", "\u039c": "m", "\u039d": "n", "\u039f": "o", "\u03a1": "p", "\u03a4": "t",
    "\u03a5": "y", "\u03a7": "x",
    # Greek letters that NFKC keeps and that look Latin (PR #672)
    "\u03c4": "t", "\u03f2": "c", "\u03f9": "c", "\u03c2": "s", "\u03f3": "j", "\u037f": "j",
    "\u03b7": "n", "\u03b3": "y", "\u03c9": "w", "\u03f5": "e", "\u03f1": "p",
    # Armenian
    "\u0585": "o", "\u057d": "u", "\u0570": "h", "\u0578": "n",
    # Latin letters outside ASCII that NFKC keeps
    "\u0131": "i", "\u0261": "g",
})


# The texts a screen read last, with what it found (PR #672): one request
# screens the same text in the policy check, the control plane and the
# translator. What is cached depends on the text alone.
_SCREENED = 64


@lru_cache(maxsize=_SCREENED)
def _phrase_copies(prompt: str) -> Optional[Tuple[str, ...]]:
    """The copies the phrase check reads: the original and its NFKC form,
    whitespace collapsed, and the text as the guards read it (GHSA-v3m4),
    with each character a reader does not see written as U+200B, which the
    patterns read through: controls (U+001F and U+0085 too), format
    characters such as U+FFF9 and U+13430, blanks such as U+2800, and
    nonspacing marks, each copy with every default-ignorable written as
    U+200B; then each of those with the look-alike letters of
    other scripts read as the Latin letters they look like (#646), as
    written and lowercased.
    ``None`` when a copy grows the text past the length bound. A copy the
    same as another is not read twice."""
    from qwed_new.guards.canonical_text import marked_copies

    collapsed = _collapse_ws(prompt)
    folded = unicodedata.normalize("NFKC", prompt)
    if len(folded) > 10000:
        return None
    folded = _collapse_ws(folded)
    marked = [_collapse_ws(copy) for copy in marked_copies(prompt)]
    if any(len(copy) > 10000 for copy in marked):
        return None
    copies = tuple(_ANY_IGNORABLE.sub(_MARK, copy) for copy in (collapsed, folded, *marked))
    read = [copy.translate(_LOOKALIKES) for copy in copies]
    # A capital look-alike can stand for the Latin letter its small form
    # looks like (capital nu for v): one more copy reads the lowercased
    # text, where it changes anything, under the same bound (PR #672).
    for copy in copies:
        lowered = copy.lower()
        looked = lowered.translate(_LOOKALIKES)
        if looked != lowered:
            if len(looked) > 10000:
                return None
            read.append(looked)
    return tuple(dict.fromkeys((*copies, *read)))


def _read_through_word(word: str) -> str:
    """``word`` with default-ignorables allowed between its letters only."""
    return (_MARK + "*").join(re.escape(char) for char in word)


# The endings the last word of a phrase may take.
_ENDING = "(?:" + "|".join(_read_through_word(e) for e in ("s", "es", "ed", "ing")) + ")?"

# What may stand between two words of a phrase (#646): whitespace and
# default-ignorables, with at most one dash, underscore or comma among
# them, or a dot with nothing after it ("ignore.previous"). A dot then a
# space ends a sentence, and a phrase does not run across one. No form
# holds a letter, and of the two that may start with an ignorable only
# one holds an apostrophe, so a failed word gives back at most one run of
# whitespace and ignorables.
# An apostrophe joins two words only with nothing a reader sees around it,
# as in a contraction ("what's", "let" + U+200B + "'s"); a quote after a
# space ("ignore 'instructions'") does not (PR #672).
_GAP = rf"(?:\s|{_MARK})"
_BETWEEN_WORDS = rf"(?:{_GAP}+(?:[-_,]{_GAP}*)?|[-_,]{_GAP}*|\.|{_MARK}*['\u2019]{_MARK}*)"
# The same for a copy that holds no ignorable, where reading through them
# can match nothing more and costs about twice as much.
_PLAIN_BETWEEN_WORDS = r"(?:\s+(?:[-_,]\s*)?|[-_,]\s*|\.|['\u2019])"
# The same without the underscore, for a phrase that an identifier such as
# a CSV header ("the_system_prompt") may hold as a name (PR #672).
_BETWEEN_WORDS_NOT_JOINED = rf"(?:{_GAP}+(?:[-,]{_GAP}*)?|[-,]{_GAP}*|\.|{_MARK}*['\u2019]{_MARK}*)"
_PLAIN_BETWEEN_WORDS_NOT_JOINED = r"(?:\s+(?:[-,]\s*)?|[-,]\s*|\.|['\u2019])"
_PLAIN_ENDING = "(?:s|es|ed|ing)?"
# Words a caller may put between an instruction verb and what it names:
# "ignore all the previous instructions", "forget what you were told above".
_MAX_QUALIFIERS = 4


def _one_of(words, read_through: bool = True) -> str:
    """One of ``words``, each read through ignorables unless
    ``read_through`` is false; longer words first."""
    word = _read_through_word if read_through else re.escape
    # Longer words first, then in order, so the pattern is the same in
    # every process whatever its hash seed (PR #672).
    ordered = sorted(set(words), key=lambda w: (-len(w), w))
    return "(?:" + "|".join(word(w) for w in ordered) + ")"


def _following(slot, between: str, read_through: bool) -> str:
    """The lookahead a last slot written ``("!re", pattern)``,
    ``("!", words)`` or ``("!",)`` puts after a phrase."""
    if slot[0] == "!re":
        follower = slot[1]
    elif len(slot) > 1:
        follower = _one_of(slot[1], read_through) + rf"(?!{_SEEN_IN_COPY})"
    else:
        follower = _ANY_LETTER_OR_DIGIT
    return rf"(?!{between}{follower})"


def _sentence_start(read_through: bool) -> str:
    """Where a first slot written ``("^",)`` puts a phrase: after the run
    of whitespace and ignorables that starts the text, follows a
    sentence's end, or holds a line break other than one that ends a
    line ending with a letter or a comma, as a wrapped sentence's does.
    The search starts only where such a run starts, so it reads each run
    once however many line breaks it holds (PR #672)."""
    gap = _GAP if read_through else r"\s"
    return (
        rf"(?<!{gap})(?:\A|(?<=[.!?:;\"\u201c\u201d(>*])"
        # A line break first, after a line that does not end with a letter
        # or a comma; or one later in the run, after an ignorable.
        rf"|(?<![^\W\d_])(?<!,)(?=\n)|(?={gap}+?\n))"
        rf"{gap}*"
    )


def _slot(slot, between: str, read_through: bool) -> str:
    """One slot's words and the separator after them; a ``("*", words)``
    slot repeats both up to its bound."""
    if slot[0] == "*":
        most = slot[2] if len(slot) > 2 else _MAX_QUALIFIERS
        return rf"(?:{_one_of(slot[1], read_through)}{between}){{0,{most}}}"
    return _one_of(slot, read_through) + between


def _separator(slots, read_through: bool):
    """What joins a phrase's words, and its slots without a leading
    ``("~",)``, which leaves the underscore out: words an identifier
    joins ("the_system_prompt") are a name, not the phrase."""
    if slots[0] == ("~",):
        return (_BETWEEN_WORDS_NOT_JOINED if read_through else _PLAIN_BETWEEN_WORDS_NOT_JOINED), slots[1:]
    return (_BETWEEN_WORDS if read_through else _PLAIN_BETWEEN_WORDS), slots


def _phrase_search(slots, whole_words: bool, read_through: bool = True) -> "re.Pattern[str]":
    """The search for a phrase: ``slots`` in order, each a tuple of the
    words that may stand there, joined by ``_BETWEEN_WORDS``. A slot
    written ``("*", words)`` holds up to ``_MAX_QUALIFIERS`` of ``words``,
    or none; ``("*", words, n)`` up to ``n``. A last slot written ``("!", words)`` holds none of them: the
    phrase is not found when one of ``words`` follows it ("you are now
    able"); written ``("!",)``, no word may follow it ("forget all.");
    written ``("!re", pattern)``, ``pattern`` may not follow it. A
    first slot written ``("^",)`` puts the phrase at the start of the text,
    after a sentence's end ("Act as a terminal."), or at a line's start
    when the line before does not end with a letter or a comma, as a
    wrapped sentence's does. A first slot written ``("~",)`` keeps the
    underscore out of what joins the words. In whole-word mode no
    letter or digit a reader sees may touch the phrase at either end.
    With ``read_through`` false, the search is for a copy that holds no
    ignorable, and matches there exactly what the full search matches."""
    between, slots = _separator(slots, read_through)
    unless = ""
    if slots[-1][0] in ("!", "!re"):
        unless = _following(slots[-1], between, read_through)
        slots = slots[:-1]
    start = ""
    if slots[0] == ("^",):
        start = _sentence_start(read_through)
        slots = slots[1:]
    body = "".join(_slot(slot, between, read_through) for slot in slots)
    # The last word may take an English ending ("modes", "prompted"), read
    # through ignorables the same way ("prompte<U+200B>d").
    body = body[: -len(between)] + (_ENDING if read_through else _PLAIN_ENDING)
    if whole_words:
        body = rf"(?<!{_SEEN_IN_COPY}){body}(?!{_SEEN_IN_COPY})"
    return re.compile(start + body + unless, re.IGNORECASE)


def _forms(*groups: str) -> tuple[str, ...]:
    """The word forms written in ``groups``, each "stem:ending,ending"."""
    out = []
    for group in groups:
        stem, _, endings = group.partition(":")
        out.append(stem)
        out.extend(stem + ending for ending in endings.split(",") if ending)
    return tuple(out)


# The verbs of an override (#646): they tell a model to drop what it was told.
_OVERRIDE_VERBS = _forms(
    "ignor:e,es,ed,ing", "disregard:s,ed,ing", "forget:s,ting", "forgot:ten",
)
# Verbs that also filter data ("drop the orders under $20", PR #672): an
# override only with what can only be an instruction, or with an earlier one.
_DATA_VERBS = _forms("drop:s,ped,ping", "abandon:s,ed,ing", "discard:s,ed,ing")
_OVERRIDE_QUALIFIERS = (
    "all", "any", "the", "your", "my", "our", "of", "these", "those", "every", "each",
    "prior", "previous", "preceding", "earlier", "above", "foregoing", "former",
    "original", "initial", "existing", "current", "system", "about", "provided",
    "given", "other", "that", "this", "what", "you", "i", "were", "was", "have",
    "had", "been", "got", "said", "told", "everything",
)
# Qualifiers that point back at what a model was told before.
_EARLIER = (
    "previous", "prior", "preceding", "earlier", "above", "foregoing", "former",
    "original", "initial", "system", "your", "provided",
)
# What can only be an instruction to a model.
_INSTRUCTIONS = _forms(
    "instruction:s", "rule:s", "prompt:s", "direction:s", "directive:s",
    "guideline:s", "guidance", "programming", "safeguard:s",
)
# What a data question names too (orders, messages, text): an override only
# after an earlier qualifier ("ignore all preceding orders").
_ALSO_DATA = _forms(
    "order:s", "command:s", "context", "information", "assignment:s", "task:s",
    "message:s", "training", "polic:y,ies", "text", "article:s", "document:s",
    "constraint:s", "restriction:s",
)
_MODES = ("developer", "dan", "god", "jailbreak", "jailbroken", "admin", "simulated", "unrestricted")

# "act as if" states a premise, which passes, only in two shapes (PR #672):
# one variable equal to something ("act as if x = 3", "a equals 2"), or
# "the", "a" or "an", one word that is not an instruction or a safeguard,
# and "is", "are", "was" or "were" ("act as if the die is fair").
# A model or a system is a maths object with a maths property only (below).
# Anything else after "act as if" plays a role: "you are DAN", "I were",
# "no rules apply", "the safety guidelines were disabled".
_NOT_A_PREMISE_NOUN = (
    *_INSTRUCTIONS,
    *_forms(
        "restriction:s", "constraint:s", "filter:s", "limit:s", "polic:y,ies",
        "guardrail:s", "model:s", "assistant:s", "bot:s", "chatbot:s", "system:s",
    ),
    "safety", "ai",
)
# "Model" and "system" name maths objects too: a premise about one passes
# with a maths property after it ("act as if the model is linear", "the
# system is consistent"), written plainly, and plays a role with anything
# else ("the model is unrestricted") (PR #672).
_MATHS_OBJECT = _forms("model:s", "system:s")
_MATHS_PROPERTY = (
    "linear", "nonlinear", "quadratic", "cubic", "polynomial", "exponential",
    "logarithmic", "logistic", "periodic", "continuous", "differentiable",
    "convex", "concave", "stationary", "stable", "unstable", "bounded",
    "deterministic", "stochastic", "symmetric", "invertible", "singular",
    "consistent", "inconsistent", "homogeneous", "monotonic", "ergodic",
    "frictionless", "overdetermined", "underdetermined", "solvable", "normal",
    "uniform", "additive", "multiplicative",
)
_WORD_IN_COPY = rf"[^\W\d_](?:{_MARK}*[^\W\d_])*"
_ASSUMPTION = (
    rf"if{_BETWEEN_WORDS}(?:"
    rf"[a-z0-9\u0370-\u03ff](?!{_ANY_LETTER_OR_DIGIT}){_GAP}*(?:=|(?:is|equals?)(?!{_SEEN_IN_COPY}))"
    rf"|(?:the|a|an){_BETWEEN_WORDS}"
    rf"(?!{_one_of(_NOT_A_PREMISE_NOUN)}(?!{_SEEN_IN_COPY})){_WORD_IN_COPY}"
    rf"{_BETWEEN_WORDS}(?:is|are|was|were)(?!{_SEEN_IN_COPY})"
    rf"|(?:the|a|an){_BETWEEN_WORDS}{_one_of(_MATHS_OBJECT, False)}{_BETWEEN_WORDS}"
    rf"(?:is|are|was|were){_BETWEEN_WORDS}{_one_of(_MATHS_PROPERTY, False)}(?!{_SEEN_IN_COPY})"
    rf")"
)
_ACT_AS = "act as"
_STORY_ROLES = ("dan", "evil", "rogue")

# A column of logged system prompts ("the system prompt column holds the
# text") is data, and so is an aggregate of them ("the system prompt token
# counts", "the system prompt's length"), unless the same sentence goes on
# to ask for the text ("the system prompt length and its text"), read up
# to 120 characters on (PR #672).
_PROMPT_COLUMN = _forms("column:s", "field:s")
_PROMPT_ATTRIBUTE = _forms("token:s", "length:s", "count:s", "size:s", "id:s")
_PROMPT_TEXT = (*_forms("text:s", "content:s", "wording:s"), "verbatim", "body", "itself")
_PROMPT_METADATA = (
    rf"(?:s{_BETWEEN_WORDS})?(?:{_one_of(_PROMPT_COLUMN)}(?!{_SEEN_IN_COPY})"
    rf"|{_one_of(_PROMPT_ATTRIBUTE)}(?!{_SEEN_IN_COPY})"
    rf"(?!(?:(?![.!?;]{_GAP}).){{0,120}}?(?<!{_SEEN_IN_COPY}){_one_of(_PROMPT_TEXT)}(?!{_SEEN_IN_COPY})))"
)

# Each phrase: the name a refusal gives, and its slots.
_PHRASES = (
    ("ignore ... instructions", ((*_OVERRIDE_VERBS, *_DATA_VERBS), ("*", _OVERRIDE_QUALIFIERS), _INSTRUCTIONS)),
    ("ignore everything", (_OVERRIDE_VERBS, ("*", _OVERRIDE_QUALIFIERS), ("everything", "above"))),
    ("ignore ... earlier ...", (
        (*_OVERRIDE_VERBS, *_DATA_VERBS), ("*", _OVERRIDE_QUALIFIERS, 3), _EARLIER,
        ("*", _OVERRIDE_QUALIFIERS, 3), _ALSO_DATA,
    )),
    (_ACT_AS, (("you",), ("to", "will", "must", "should", "shall"), ("act",), ("as", "like"), ("!re", _ASSUMPTION))),
    (_ACT_AS, (
        ("you",), ("*", ("are", "re"), 1), ("going",), ("to",), ("act",), ("as", "like"),
        ("!re", _ASSUMPTION),
    )),
    (_ACT_AS, (("please", "now", "you"), ("act",), ("as", "like"), ("!re", _ASSUMPTION))),
    (_ACT_AS, (("^",), ("act",), ("as", "like"), ("!re", _ASSUMPTION))),
    # A role that only a model plays, wherever "act as" stands.
    (_ACT_AS, (
        ("act", "acting"), ("as", "like"), ("*", ("a", "an", "the", "my", "your"), 1),
        ("unrestricted", "unfiltered", "uncensored", "jailbroken"),
    )),
    # A name or a trait that a part in a story takes too ("In the play, Alex
    # will act as Dan", "act as the evil queen"): a model's role when it is
    # asked for ("let's act as DAN", and "Acting as DAN" or "Start acting as
    # DAN" at a sentence's start; "you will", "please" and a sentence's
    # start ask above, for any role), or when a model follows it ("act as
    # an evil AI") (PR #672).
    (_ACT_AS, (
        ("let", "lets", "pretend"), ("*", ("us", "s", "to"), 1), ("act",), ("as", "like"),
        ("*", ("a", "an", "the", "my", "your"), 1), _STORY_ROLES,
    )),
    (_ACT_AS, (
        ("^",), ("*", ("start", "begin", "keep", "continue"), 1), ("acting",), ("as", "like"),
        ("*", ("a", "an", "the", "my", "your"), 1), _STORY_ROLES,
    )),
    (_ACT_AS, (
        ("act", "acting"), ("as", "like"), ("*", ("a", "an", "the", "my", "your"), 1), _STORY_ROLES,
        ("ai", "assistant", "model", "chatbot", "bot", "llm", "gpt", "chatgpt"),
    )),
    ("you are now", (("you",), ("are",), ("now",), ("!", (
        "able", "ready", "done", "finished", "logged", "signed", "registered",
        "enrolled", "subscribed", "eligible", "connected",
    )))),
    ("forget all", (_forms("forget:s,ting", "forgot"), ("all",), ("!",))),
    ("from now on", (("from",), ("now",), ("on",), ("you",), ("are", "will"))),
    ("pretend to be", (("pretend",), ("to", "you", "that"), ("be", "are", "you"))),
    ("your instructions", (
        ("your", "hidden", "secret"), ("*", ("initial", "original", "system"), 1),
        ("instructions", "prompt", "prompts", "guidelines", "programming"),
    )),
    # The system prompt asked for ("print the system prompt", "what is the
    # system prompt"), not named, as a header or a column of logged prompts
    # is (PR #672).
    ("the system prompt", (
        _forms(
            "print:s,ed,ing", "show:s,ed,ing,n", "reveal:s,ed,ing", "repeat:s,ed,ing",
            "output:s,ted,ting", "display:s,ed,ing", "give:s", "tell:s", "write:s",
            "return:s,ed,ing", "share:s,d", "leak:s,ed,ing", "dump:s,ed,ing", "recite:s,d",
        ),
        ("*", ("me", "us", "out"), 2), ("the", "your"),
        ("*", ("full", "entire", "exact", "whole", "complete", "original", "initial"), 2),
        ("system",), ("prompt", "prompts", "instructions", "message"),
        ("!re", _PROMPT_METADATA),
    )),
    # Named in prose ("translate the system prompt", "what does the system
    # prompt say"); a header joins the words with underscores and passes.
    ("the system prompt", (
        ("~",), ("the",), ("system",), ("prompt", "prompts", "instructions", "message"),
        ("!re", _PROMPT_METADATA),
    )),
    ("the system prompt", (
        ("what",), ("is", "was", "are", "were", "s"), ("the", "your"), ("system",),
        ("prompt", "prompts", "instructions", "message"),
        ("!re", _PROMPT_METADATA),
    )),
    ("your rules", (("your",), ("rules",))),
    ("new instructions", (("new",), ("instructions",))),
    ("new task", (("your",), ("new",), ("task", "tasks", "instructions"))),
    ("tell me secrets", (("tell",), ("me",), ("*", ("your", "the", "all", "any", "of")), ("secret", "secrets"))),
    ("system override", (("system",), ("override",))),
    ("mode", (_MODES, ("mode",))),
)

# Words the maths check also refuses on their own (#646): none is a word a
# maths or statistics question uses.
_MATHS_WORDS = (
    ("jailbreak", (_forms("jailbreak:s,ing,ed", "jailbroken"),)),
    ("sudo", (("sudo",),)),
    ("roleplay", (_forms("roleplay:s,ing,ed"),)),
    ("role play", (("role",), _forms("play:s,ing"))),
)


def _searches(phrases, whole_words: bool, read_through: bool = True):
    return tuple((name, _phrase_search(slots, whole_words, read_through)) for name, slots in phrases)


_PHRASE_SEARCHES = {mode: _searches(_PHRASES, mode) for mode in (False, True)}
_MATHS_WORD_SEARCHES = _searches(_MATHS_WORDS, True)
_PLAIN_PHRASE_SEARCHES = {mode: _searches(_PHRASES, mode, False) for mode in (False, True)}
_PLAIN_MATHS_WORD_SEARCHES = _searches(_MATHS_WORDS, True, False)



def _found(searches, copies: tuple[str, ...], plain=None) -> str | None:
    """The name of the first search that matches one of the copies, else
    None. Each search is one pass over a copy: no pattern holds ``.*``.
    A copy with no ignorable is read with ``plain``, the same searches
    without the reading through, where given."""
    reads_through = [plain is None or _MARK in text for text in copies]
    for index, (name, search) in enumerate(searches):
        for text, full in zip(copies, reads_through):
            if (search if full else plain[index][1]).search(text):
                return name
    return None


# Greek letters inside a Latin word, with Latin letters on both sides (PR
# #672): a Greek letter that only touches one, as in maths notation (the
# d of a differential, 2k times pi, omega t, mu g, sin theta), is not.
# The multiplication and division signs among the Latin-1 letters are
# not letters ("2 times pi r" written with the sign).
_LATIN_LETTER = "[A-Za-z\u00c0-\u00d6\u00d8-\u00f6\u00f8-\u024f]"
_GREEK_LETTER = "[\u0370-\u03ff\u1f00-\u1fff]"
_GREEK_IN_LATIN = re.compile(f"{_LATIN_LETTER}{_GREEK_LETTER}+{_LATIN_LETTER}")


def _seen_letters(text: str) -> str:
    """``text`` with what a reader does not see between letters removed:
    default-ignorables and nonspacing marks."""
    text = re.sub(_IGNORABLE, "", text)
    return "".join(char for char in text if unicodedata.category(char) != "Mn")


@lru_cache(maxsize=_SCREENED)
def _phrase_found(prompt: str, whole_words: bool) -> Optional[str]:
    """The name of the phrase ``prompt`` holds, ``_TOO_LONG`` when a copy
    of it passes the length bound, else None."""
    copies = _phrase_copies(prompt)
    if copies is None:
        return _TOO_LONG
    return _found(_PHRASE_SEARCHES[whole_words], copies, _PLAIN_PHRASE_SEARCHES[whole_words])


# Module-level PII Constants
PII_PATTERNS = {
    "EMAIL": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
    "PHONE": r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b", # Simple US format
    "SSN": r"\b\d{3}-\d{2}-\d{4}\b",
    "IP": r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"
}

def redact_pii(text: str) -> str:
    """
    Redacts PII from text using module-level patterns.
    Functions as a standalone utility.
    """
    if not isinstance(text, str):
        return str(text)
        
    redacted = text
    for p_type, pattern in PII_PATTERNS.items():
        redacted = re.sub(pattern, f"[{p_type}_REDACTED]", redacted)
    return redacted


class SecurityGateway:
    """
    Basic security middleware for LLM Security.
    1. Detects Prompt Injection attempts using heuristics.
    2. Redacts PII (Personally Identifiable Information) from logs/inputs.
    """
    
    def __init__(self):
        # Heuristic patterns for Prompt Injection
        # These are common "jailbreak" phrases.
        # The phrases the check refuses (#646), by name.
        self.injection_patterns = [name for name, _ in _PHRASES]
        
        
        # PII Patterns (Regex) are now module-level constants
        self.pii_patterns = PII_PATTERNS


    def detect_injection(self, prompt: str, whole_words: bool = False) -> Tuple[bool, Optional[str]]:
        """
        Checks for potential prompt injection attempts.
        Returns (is_safe, reason).

        Each phrase is a sequence of words, with set words allowed in each
        place (#646): an instruction verb, up to four qualifiers and what it
        names ("ignore all the prior instructions"), or a fixed phrase such
        as "developer mode". Its words may be joined by whitespace,
        invisible characters, a dash, an underscore, a comma, an apostrophe
        inside a contraction ("what's"), or a dot with
        no space after it; a phrase does not run across a sentence's end.

        With ``whole_words`` a phrase matches only where no letter or digit
        touches it, so "act as" is not found inside "Impact assessment"
        (#632). An underscore separates, as a space does, and the last word
        may still take an English ending ("prompts", "prompted", "modes"),
        so neither gets a phrase past the check. Every route reads whole
        words: the policy check, the maths check, and stats and fact text.

        The check reads the caller's text the way a model does, and folding
        can only add refusals. It reads the whitespace-collapsed original,
        its NFKC form and the text with each invisible character marked,
        each also with look-alike letters read as Latin, all held to the
        same 10,000-character bound, and each word lets default-ignorable
        characters follow any of its letters. An invisible character inside
        a word, as a separator, or both, hides nothing. The text the caller
        sent is left as it was.
        """
        # 1. Length Check (Prevent buffer overflow / context exhaustion)
        if len(prompt) > 10000:
            return False, _TOO_LONG

        # 2 and 3. Copies only: the caller's text is not changed. A fold
        # past the length bound is refused before any pattern runs. Then
        # every phrase, for all inputs, with no whitelist bypass.
        found = _phrase_found(prompt, whole_words)
        if found is _TOO_LONG:
            return False, _TOO_LONG
        if found is not None:
            return False, f"Potential Prompt Injection detected: '{found}'"

        return True, None

    def redact_pii(self, text: str) -> str:
        """
        Redacts PII from text.
        Wraps module-level function.
        """
        return redact_pii(text)


class EnhancedSecurityGateway:
    """
    Advanced multi-layer prompt injection defense.
    
    OWASP LLM01:2025 Compliance - Comprehensive protection against:
    - Base64-encoded injections
    - Unicode tricks and homoglyphs
    - Multi-language script mixing
    - Semantic similarity attacks
    - Length-based attacks
    
    Research-backed: 70% of attacks blocked by length limits alone.
    """
    
    def __init__(self, system_prompt: Optional[str] = None):
        # Wrap basic gateway for backward compatibility
        self.basic_gateway = SecurityGateway()
        
        # Enhanced parameters
        # The phrase check's bound (#646). A 2,000-character bound refused
        # ordinary questions and caught no measured attack the other layers
        # miss.
        self.max_input_length = 10000
        self.similarity_threshold = 0.6  # System prompt similarity detection
        
        # Store system prompt for similarity checks
        self.system_prompt = system_prompt or (
            "You are a mathematical expression translator for QWED. "
            "Convert natural language math queries to Python expressions."
        )
        
        # Additional injection keywords (beyond basic patterns)
        # Words the maths check refuses on their own (#646), by name.
        self.advanced_keywords = [name for name, _ in _MATHS_WORDS]
        
        # Block count for monitoring
        self.blocks_count = 0
    
    def detect_advanced_injection(self, prompt: str) -> Tuple[bool, Optional[str]]:
        """
        Multi-layer injection detection.
        
        Returns:
            (is_safe, reason) - True if safe, False with reason if blocked
        """
        # The length bound first (PR #672): it reads no character, so an
        # over-long text is refused before any layer scans it.
        if len(prompt) > self.max_input_length:
            self.blocks_count += 1
            logger.warning(f"Input exceeds {self.max_input_length} chars: {len(prompt)}")
            return False, (
                f"Input too long ({len(prompt)} chars). "
                f"Maximum {self.max_input_length} characters allowed."
            )

        # Zero-width characters next (PR #672): one pass that refuses on
        # its own, before the costly layers read a text of them. Every
        # layer only refuses, so the order changes no verdict.
        if self._contains_zero_width_chars(prompt):
            self.blocks_count += 1
            logger.warning("Zero-width characters detected")
            return False, "Input contains hidden zero-width characters"

        # Layer 1: Basic patterns (existing SecurityGateway)
        is_safe, reason = self.basic_gateway.detect_injection(prompt, whole_words=True)
        if not is_safe:
            self.blocks_count += 1
            logger.warning(f"Basic injection detected: {reason}")
            return False, reason
        
        # Layer 3: Base64/encoding detection
        is_safe, reason = self._check_base64_encoding(prompt)
        if not is_safe:
            self.blocks_count += 1
            logger.warning(f"Base64 injection detected: {reason}")
            return False, reason
        
        # Layer 4: Semantic similarity to system prompt. ratio() costs about
        # the product of the two lengths, so its upper bounds come first, as
        # in difflib.get_close_matches. An input much longer than the system
        # prompt cannot reach the threshold and skips ratio() (#645).
        matcher = SequenceMatcher(None, prompt.lower(), self.system_prompt.lower())
        threshold = self.similarity_threshold
        similarity = 0.0
        if matcher.real_quick_ratio() > threshold and matcher.quick_ratio() > threshold:
            similarity = matcher.ratio()
        if similarity > threshold:
            self.blocks_count += 1
            logger.warning(f"High similarity to system prompt: {similarity:.2%}")
            return False, (
                f"Input mimics system prompt structure (similarity: {similarity:.0%}). "
                "This may be a prompt injection attempt."
            )
        
        # Layer 5: Advanced keyword detection
        if self._contains_maths_words(prompt):
            self.blocks_count += 1
            return False, "Input contains suspicious keywords commonly used in prompt injections"
        
        # Layer 6: Multi-language script detection
        if self._contains_mixed_scripts(prompt):
            self.blocks_count += 1
            logger.warning("Mixed Unicode scripts detected")
            return False, "Input contains mixed-language scripts (potential evasion technique)"
        
        
        # All checks passed
        return True, None
    
    def _check_base64_encoding(self, text: str) -> Tuple[bool, Optional[str]]:
        """Detect Base64-encoded injection payloads."""
        # Look for Base64-like patterns (length divisible by 4, only valid chars)
        base64_pattern = r'[A-Za-z0-9+/]{20,}={0,2}'
        matches = re.findall(base64_pattern, text)
        
        pieces = []
        for match in matches:
            try:
                # Attempt to decode
                decoded = base64.b64decode(match, validate=True)
                # Not lowercased: a look-alike reads as a different Latin
                # letter in each case (capital nu is N, small nu is v), and
                # the phrase check reads case for itself (PR #672).
                pieces.append(decoded.decode('utf-8', errors='ignore'))
            except Exception:
                # Not valid Base64 or not decodable, continue
                pass

        # Every decoded piece read once, joined by ". ", which ends a
        # sentence: no phrase, exclusion or sentence start runs from one
        # piece into the next, so each is read as it would be alone, and
        # a text of many pieces costs one read (PR #672). The read is
        # outside the try, so an error in it is not taken for bad Base64.
        if pieces:
            joined = ". ".join(pieces)
            # Read one by one where the join passes the length bound, so two
            # pieces that fit alone are not refused for their sum (PR #672).
            readings = [joined] if _phrase_copies(joined) is not None else pieces
            if any(self._contains_injection_keywords(text) for text in readings):
                return False, "Base64-encoded injection payload detected"

        return True, None
    
    def _contains_injection_keywords(self, text: str) -> bool:
        """Whether ``text`` (decoded Base64) holds a phrase the check
        refuses, or a word the maths check refuses on its own, each as
        whole words (#646)."""
        copies = _phrase_copies(text)
        if copies is None:
            return True
        return (
            _found(_PHRASE_SEARCHES[True], copies, _PLAIN_PHRASE_SEARCHES[True]) is not None
            or _found(_MATHS_WORD_SEARCHES, copies, _PLAIN_MATHS_WORD_SEARCHES) is not None
        )

    def _contains_maths_words(self, text: str) -> bool:
        """Whether ``text`` holds a word the maths check refuses on its own
        (#646). The phrase check, layer 1, has read its phrases already."""
        copies = _phrase_copies(text)
        if copies is None:
            return True
        return _found(_MATHS_WORD_SEARCHES, copies, _PLAIN_MATHS_WORD_SEARCHES) is not None

    def _contains_mixed_scripts(self, text: str) -> bool:
        """
        Detect suspicious mixing of Unicode scripts.
        
        Attackers use Cyrillic, Arabic, or other scripts mixed with Latin
        to evade simple pattern matching.
        """
        if text.isascii():
            return False
        scripts = set()
        
        for char in text:
            # Cyrillic
            if '\u0400' <= char <= '\u04FF':
                scripts.add('cyrillic')
            # Arabic
            elif '\u0600' <= char <= '\u06FF':
                scripts.add('arabic')
            # Chinese/Japanese/Korean
            elif '\u4E00' <= char <= '\u9FFF':
                scripts.add('cjk')
            # Greek
            elif '\u0370' <= char <= '\u03FF':
                scripts.add('greek')
            # Latin (normal English)
            elif char.isalpha():
                scripts.add('latin')
        
        # Greek letters are mathematical symbols (theta, the zeta function,
        # TGF-beta, d theta, 2k pi), so a Greek letter that is not inside a
        # Latin word is not mixing (#646). One inside a Latin word ("instru"
        # + lunate sigma + "tions") is, as on main.
        if 'greek' in scripts and not _GREEK_IN_LATIN.search(_seen_letters(text)):
            scripts.discard('greek')

        # If more than one script, it's suspicious
        # Exception: allow CJK + Latin (common in multilingual queries)
        if len(scripts) > 1:
            # Allow latin + CJK combination
            if scripts == {'latin', 'cjk'}:
                return False
            return True
        
        return False
    
    def _contains_zero_width_chars(self, text: str) -> bool:
        """Detect zero-width characters used for obfuscation."""
        zero_width_chars = [
            '\u200B',  # Zero-width space
            '\u200C',  # Zero-width non-joiner
            '\u200D',  # Zero-width joiner
            '\uFEFF',  # Zero-width no-break space
        ]
        
        return any(char in text for char in zero_width_chars)
    
    def get_blocks_count(self) -> int:
        """Get total number of blocked attempts."""
        return self.blocks_count
    
    def redact_pii(self, text: str) -> str:
        """Delegate to basic gateway for PII redaction."""
        return self.basic_gateway.redact_pii(text)
