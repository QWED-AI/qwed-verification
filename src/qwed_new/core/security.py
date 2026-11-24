"""
Security Gateway for QWED.
Handles Prompt Injection detection and PII redaction.

OWASP LLM01:2025 - Prompt Injection Defense (Multi-Layer)
"""
import re
import base64
import logging
import unicodedata
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
# A letter or digit that a reader sees: a word character other than "_" and
# other than the default-ignorables, some of which (U+3164) count as letters.
_SEEN_LETTER_OR_DIGIT = rf"[^\W_{_IGNORABLE_RANGES}]"
_TOO_LONG = "Input too long (max 10000 chars)"


def _collapse_ws(text: str) -> str:
    """Tabs, newlines and repeated spaces become a single space."""
    return re.sub(r'\s+', ' ', text).strip()


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
    # Latin letters outside ASCII that NFKC keeps
    "\u0131": "i", "\u0261": "g",
})


def _phrase_copies(prompt: str) -> Optional[Tuple[str, ...]]:
    """The copies the phrase check reads: the original and its NFKC form,
    whitespace collapsed, and the text as the guards read it (GHSA-v3m4),
    with each character a reader does not see written as U+200B, which the
    patterns read through: controls (U+001F and U+0085 too), format
    characters such as U+FFF9 and U+13430, blanks such as U+2800, and
    nonspacing marks; then each of those with the look-alike letters of
    other scripts read as the Latin letters they look like (#646).
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
    copies = (collapsed, folded, *marked)
    return tuple(dict.fromkeys((*copies, *(copy.translate(_LOOKALIKES) for copy in copies))))


def _read_through_word(word: str) -> str:
    """``word`` with default-ignorables allowed between its letters only."""
    return (_IGNORABLE + "*").join(re.escape(char) for char in word)


# The endings the last word of a phrase may take.
_ENDING = "(?:" + "|".join(_read_through_word(e) for e in ("s", "es", "ed", "ing")) + ")?"

# What may stand between two words of a phrase (#646): whitespace and
# default-ignorables, with at most one dash, underscore or comma among
# them, or a dot with nothing after it ("ignore.previous"). A dot then a
# space ends a sentence, and a phrase does not run across one. The three
# forms start with different characters and none holds a letter, so a
# failed word gives back at most one run of whitespace and ignorables.
_GAP = rf"(?:\s|{_IGNORABLE})"
_BETWEEN_WORDS = rf"(?:{_GAP}+(?:[-_,]{_GAP}*)?|[-_,]{_GAP}*|\.)"
# Words a caller may put between an instruction verb and what it names:
# "ignore all the previous instructions", "forget what you were told above".
_MAX_QUALIFIERS = 4


def _one_of(words) -> str:
    """One of ``words``, each read through ignorables; longer words first."""
    return "(?:" + "|".join(_read_through_word(w) for w in sorted(set(words), key=len, reverse=True)) + ")"


def _phrase_search(slots, whole_words: bool) -> "re.Pattern[str]":
    """The search for a phrase: ``slots`` in order, each a tuple of the
    words that may stand there, joined by ``_BETWEEN_WORDS``. A slot
    written ``("*", words)`` holds up to ``_MAX_QUALIFIERS`` of ``words``,
    or none. A last slot written ``("!", words)`` holds none of them: the
    phrase is not found when one of ``words`` follows it ("you are now
    able"); written ``("!",)``, no word may follow it ("forget all."). A
    first slot written ``("^",)`` puts the phrase at the start of the text
    or after a sentence's end ("Act as a terminal."). In whole-word mode no
    letter or digit a reader sees may touch the phrase at either end."""
    unless = ""
    if slots[-1][0] == "!":
        if len(slots[-1]) > 1:
            follower = _one_of(slots[-1][1]) + rf"(?!{_SEEN_LETTER_OR_DIGIT})"
        else:
            follower = _SEEN_LETTER_OR_DIGIT
        unless = rf"(?!{_BETWEEN_WORDS}{follower})"
        slots = slots[:-1]
    start = ""
    if slots[0] == ("^",):
        start = rf"(?:\A|(?<=[.!?:;\"\u201c\u201d(>*]))(?:\s|{_IGNORABLE})*"
        slots = slots[1:]
    body = ""
    for slot in slots:
        if slot[0] == "*":
            body += rf"(?:{_one_of(slot[1])}{_BETWEEN_WORDS}){{0,{_MAX_QUALIFIERS}}}"
        else:
            body += _one_of(slot) + _BETWEEN_WORDS
    # The last word may take an English ending ("modes", "prompted"), read
    # through ignorables the same way ("prompte<U+200B>d").
    body = body[: -len(_BETWEEN_WORDS)] + _ENDING
    if whole_words:
        body = rf"(?<!{_SEEN_LETTER_OR_DIGIT}){body}(?!{_SEEN_LETTER_OR_DIGIT})"
    return re.compile(start + body + unless, re.IGNORECASE)


def _forms(*groups: str) -> tuple[str, ...]:
    """The word forms written in ``groups``, each "stem:ending,ending"."""
    out = []
    for group in groups:
        stem, _, endings = group.partition(":")
        out.append(stem)
        out.extend(stem + ending for ending in endings.split(",") if ending)
    return tuple(out)


# The instruction an override names (#646).
_OVERRIDE_VERBS = _forms(
    "ignor:e,es,ed,ing", "disregard:s,ed,ing", "forget:s,ting", "forgot:ten",
    "drop:s,ped,ping", "abandon:s,ed,ing", "discard:s,ed,ing",
)
_OVERRIDE_QUALIFIERS = (
    "all", "any", "the", "your", "my", "our", "of", "these", "those", "every", "each",
    "prior", "previous", "preceding", "earlier", "above", "foregoing", "former",
    "original", "initial", "existing", "current", "system", "about", "provided",
    "given", "other", "that", "this", "what", "you", "i", "were", "was", "have",
    "had", "been", "got", "said", "told", "everything",
)
_OVERRIDE_OBJECTS = _forms(
    "instruction:s", "rule:s", "prompt:s", "direction:s", "directive:s", "order:s",
    "command:s", "guideline:s", "guidance", "context", "everything", "above",
    "information", "assignment:s", "tasks", "message:s", "constraint:s",
    "restriction:s", "programming", "training", "polic:y,ies", "safeguard:s", "text",
    "article:s", "document:s",
)
_MODES = ("developer", "dan", "god", "jailbreak", "jailbroken", "admin", "simulated", "unrestricted")

# Each phrase: the name a refusal gives, and its slots.
_PHRASES = (
    ("ignore ... instructions", (_OVERRIDE_VERBS, ("*", _OVERRIDE_QUALIFIERS), _OVERRIDE_OBJECTS)),
    ("act as", (("you",), ("to", "will", "must", "should", "shall"), ("act",), ("as", "like"))),
    ("act as", (("going",), ("to",), ("act",), ("as", "like"))),
    ("act as", (("please", "now", "you"), ("act",), ("as", "like"))),
    ("act as", (("^",), ("act",), ("as", "like"), ("!", ("if", "though")))),
    ("you are now", (("you",), ("are",), ("now",), ("!", (
        "able", "ready", "done", "finished", "given", "at", "on", "back", "here", "there",
        "sure", "aware", "eligible", "logged", "signed", "connected", "registered",
    )))),
    ("forget all", (_forms("forget:s,ting", "forgot"), ("all",), ("!",))),
    ("from now on", (("from",), ("now",), ("on",), ("you",), ("are", "will"))),
    ("pretend to be", (("pretend",), ("to", "you", "that"), ("be", "are", "you"))),
    ("your instructions", (("your", "hidden", "secret"), (
        "instructions", "prompt", "prompts", "guidelines", "programming",
    ))),
    ("system prompt", (("system", "initial"), ("prompt", "prompts", "instructions"))),
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


def _searches(phrases, whole_words: bool):
    return tuple((name, _phrase_search(slots, whole_words)) for name, slots in phrases)


_PHRASE_SEARCHES = {mode: _searches(_PHRASES, mode) for mode in (False, True)}
_MATHS_WORD_SEARCHES = _searches(_MATHS_WORDS, True)



def _found(searches, copies: tuple[str, ...]) -> str | None:
    """The name of the first search that matches one of the copies, else
    None. Each search is one pass over a copy: no pattern holds ``.*``."""
    for name, search in searches:
        for text in copies:
            if search.search(text):
                return name
    return None


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
        invisible characters, a dash, an underscore, a comma, or a dot with
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

        # 2. Copies only. The caller's text is not changed. A fold past
        # the length bound is refused before any pattern runs.
        copies = _phrase_copies(prompt)
        if copies is None:
            return False, _TOO_LONG

        # 3. Heuristic Check. Runs for all inputs, with no whitelist bypass.
        found = _found(_PHRASE_SEARCHES[whole_words], copies)
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
        self.max_input_length = 2000  # Research-based: 70% attack prevention
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
        # Layer 1: Basic patterns (existing SecurityGateway)
        is_safe, reason = self.basic_gateway.detect_injection(prompt, whole_words=True)
        if not is_safe:
            self.blocks_count += 1
            logger.warning(f"Basic injection detected: {reason}")
            return False, reason
        
        # Layer 2: Stricter length check (70% effective per research)
        if len(prompt) > self.max_input_length:
            self.blocks_count += 1
            logger.warning(f"Input exceeds {self.max_input_length} chars: {len(prompt)}")
            return False, (
                f"Input too long ({len(prompt)} chars). "
                f"Maximum {self.max_input_length} characters allowed."
            )
        
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
        if self._contains_injection_keywords(prompt):
            self.blocks_count += 1
            return False, "Input contains suspicious keywords commonly used in prompt injections"
        
        # Layer 6: Multi-language script detection
        if self._contains_mixed_scripts(prompt):
            self.blocks_count += 1
            logger.warning("Mixed Unicode scripts detected")
            return False, "Input contains mixed-language scripts (potential evasion technique)"
        
        # Layer 7: Zero-width character detection
        if self._contains_zero_width_chars(prompt):
            self.blocks_count += 1
            logger.warning("Zero-width characters detected")
            return False, "Input contains hidden zero-width characters"
        
        # All checks passed
        return True, None
    
    def _check_base64_encoding(self, text: str) -> Tuple[bool, Optional[str]]:
        """Detect Base64-encoded injection payloads."""
        # Look for Base64-like patterns (length divisible by 4, only valid chars)
        base64_pattern = r'[A-Za-z0-9+/]{20,}={0,2}'
        matches = re.findall(base64_pattern, text)
        
        for match in matches:
            try:
                # Attempt to decode
                decoded = base64.b64decode(match, validate=True)
                decoded_text = decoded.decode('utf-8', errors='ignore').lower()
                
                # Check if decoded content contains injection keywords
                if self._contains_injection_keywords(decoded_text):
                    return False, "Base64-encoded injection payload detected"
                    
            except Exception:
                # Not valid Base64 or not decodable, continue
                pass
        
        return True, None
    
    def _contains_injection_keywords(self, text: str) -> bool:
        """Whether ``text`` holds a phrase the check refuses, or a word the
        maths check refuses on its own, each as whole words (#646)."""
        copies = _phrase_copies(text)
        if copies is None:
            return True
        return (
            _found(_PHRASE_SEARCHES[True], copies) is not None
            or _found(_MATHS_WORD_SEARCHES, copies) is not None
        )

    def _contains_mixed_scripts(self, text: str) -> bool:
        """
        Detect suspicious mixing of Unicode scripts.
        
        Attackers use Cyrillic, Arabic, or other scripts mixed with Latin
        to evade simple pattern matching.
        """
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
        # TGF-beta), so Greek beside Latin is not mixing (#646). A Greek
        # look-alike inside a Latin phrase is read as the Latin letter by
        # the phrase check.
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
