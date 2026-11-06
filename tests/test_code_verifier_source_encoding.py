"""GHSA-pr6c-cqg8-6w5r: CodeVerifier.verify_code returned VERIFIED · ADMIT for
code whose coding declaration (PEP 263) makes Python decode different code
from the text that was checked. Under utf-7 or unicode_escape, what reads as
a comment decodes to new statements when the code runs from a file, an
import, or bytes passed to compile/exec.

Harmless placeholders (`id`); nothing is executed.
"""
import base64

import pytest

from qwed_new.core.code_verifier import CodeVerifier
from qwed_new.core.diagnostics import admission_decision

HIDDEN = "\nimport os\nos.system('id')\n"


def _utf7(text):
    # Each character on its own, so no part of it is readable as written.
    return "".join("+" + base64.b64encode(ch.encode("utf-16-be")).decode().rstrip("=") + "-" for ch in text)


def _escaped(text):
    return "".join("\\x%02x" % ord(ch) for ch in text)


def _verdict(code):
    result = CodeVerifier().verify_code(code, language="python")
    return result, admission_decision(result).value


REFUSED = {
    "utf7_hidden_statements": "# -*- coding: utf-7 -*-\nx = 1  #" + _utf7(HIDDEN) + "\n",
    "unicode_escape_hidden_statements": "# -*- coding: unicode_escape -*-\nx = 1  #" + _escaped(HIDDEN) + "\n",
    "declaration_after_a_shebang": "#!/usr/bin/env python\n# coding: utf-7\nx = 1  #" + _utf7(HIDDEN) + "\n",
    "other_declared_encoding": "# coding: latin-1\nprint('ok')\n",
    "unknown_declared_encoding": "# coding: no-such-codec\nprint('ok')\n",
}


@pytest.mark.parametrize("code", REFUSED.values(), ids=list(REFUSED))
def test_a_coding_declaration_other_than_utf8_is_refused(code):
    result, admission = _verdict(code)
    fields = result.developer_fields
    assert fields["is_safe"] is False, fields
    assert any(issue["type"] == "source_encoding" for issue in fields["issues"])
    assert admission == "BLOCKED"


ADMITTED = {
    "no_declaration": "print('ok')\n",
    "utf8_declaration": "# -*- coding: utf-8 -*-\nprint('café')\n",
    "utf8_declaration_after_a_shebang": "#!/usr/bin/env python\n# coding=utf-8\nprint('ok')\n",
    "utf8_spellings": "# coding: UTF8\nprint('ok')\n",
    "utf8_with_underscore": "# vim: set fileencoding=utf_8 :\nprint('ok')\n",
    # Only the first two lines can declare an encoding.
    "declaration_on_the_third_line": "x = 1\ny = 2\n# coding: utf-7\nprint(x + y)\n",
    "the_phrase_in_a_string": "label = 'coding: utf-7'\nprint(label)\n",
}


@pytest.mark.parametrize("code", ADMITTED.values(), ids=list(ADMITTED))
def test_utf8_and_undeclared_source_is_still_admitted(code):
    result, admission = _verdict(code)
    assert result.developer_fields["is_safe"] is True, result.developer_fields
    assert admission == "ADMIT"
