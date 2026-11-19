"""
Searches that do not repeat a failed attempt along a run (GHSA-v3m4).

``re`` tries a pattern at every position of the text. Some of the guards'
patterns start with a fixed part and then take a run of characters that the
part after the run cannot begin with: an email's local part before its
``@``, a token's first segment before its ``.``. An attempt that fails at the
first start of such a run fails at every later start inside it too, since
each later start reaches the same character after the run with no more
characters before it. So on a long run ``re`` repeats one failure at each
position, in time quadratic in its length, and the guards read several
copies of a text, which multiplies that.

``RunSearch`` finds the same matches, in the same order, as the pattern's
own ``search``, ``finditer`` and ``findall``, and after a failed attempt
goes on from the end of the run instead of the next position.
"""

import re
from typing import Iterator, List, Optional


class RunSearch:
    """*pattern*, every match of which starts where *start* matches and then
    takes a run of *run* characters. For a pattern given here the caller
    shows that:

    - *start* matches only run characters (or nothing), so a later start
      inside the run ends where an earlier one does;
    - what comes after the run cannot begin with a run character, or is the
      end of the text, so every start inside one run meets the same
      character after it;
    - a match needs no fewer run characters at a later start than at an
      earlier one (a minimum count, never a maximum).

    Then an attempt that fails at one start fails at every later start
    inside the same run, and the search skips to the run's end. *start* and
    *run* are read with the pattern's flags."""

    def __init__(self, pattern: "re.Pattern[str]", start: str, run: str):
        self.pattern = pattern
        self._start = re.compile(start, pattern.flags)
        self._run = re.compile(run, pattern.flags)

    def finditer(self, text: str) -> Iterator["re.Match[str]"]:
        """The pattern's matches in *text*, as ``pattern.finditer`` gives
        them (none of these patterns matches an empty string)."""
        position = 0
        while position <= len(text):
            begin = self._start.search(text, position)
            if begin is None:
                return
            at = begin.start()
            found = self.pattern.match(text, at)
            if found is not None:
                yield found
                position = max(found.end(), at + 1)
            else:
                position = max(self._run.match(text, begin.end()).end(), at + 1)

    def search(self, text: str) -> Optional["re.Match[str]"]:
        """The first match, as ``pattern.search`` gives it."""
        return next(self.finditer(text), None)

    def findall(self, text: str) -> List:
        """What ``pattern.findall`` gives: whole matches, or the group, or
        tuples of groups with "" for a group that took no part."""
        if self.pattern.groups == 0:
            return [found.group(0) for found in self.finditer(text)]
        if self.pattern.groups == 1:
            return [found.groups("")[0] for found in self.finditer(text)]
        return [found.groups("") for found in self.finditer(text)]
