"""GHSA-jrxf-9jh4-86w7: CodeVerifier.verify_code returned VERIFIED · ADMIT for
code that runs a string as code through a standard-library module (timeit,
cProfile, profile, pdb, bdb, code, trace, doctest) and for code that reads,
extracts or lists files through modules missing from the file table
(tarfile, zipfile, gzip, bz2, lzma, codecs, linecache, fileinput, os.listdir,
glob, tempfile, sqlite3, shelve, dbm). Later also logging.config (fileConfig
evaluates a handler's args, dictConfig calls the dotted name under "()"),
idlelib, and the package data readers pkgutil.get_data and
importlib.resources, which read any file given "..".

Harmless placeholders; nothing is executed.
"""
import pytest

from qwed_new.core.code_verifier import CodeVerifier
from qwed_new.core.diagnostics import admission_decision


def _result(code):
    return CodeVerifier().verify_code(code, language="python")


def _assert_refused(code):
    result = _result(code)
    fields = result.developer_fields
    assert fields["is_safe"] is False, fields
    assert fields["critical_count"] >= 1
    assert admission_decision(result).value == "BLOCKED"


STRING_EXECUTION = [
    "import timeit\ntimeit.timeit(input(), number=1)",
    "import timeit\ntimeit.repeat(input())",
    "import timeit\ntimeit.Timer(input()).timeit()",
    "from timeit import timeit as t\nt(input())",
    "import cProfile\ncProfile.run(input())",
    "import cProfile\ncProfile.runctx(input(), {}, {})",
    "import profile\nprofile.run(input())",
    "import pdb\npdb.run(input())",
    "import bdb\nbdb.Bdb().run(source)",
    "import code\ncode.InteractiveInterpreter().runsource(input())",
    "import code\ncode.InteractiveConsole().push(input())",
    "from code import interact\ninteract()",
    "import trace\ntrace.Trace().run(input())",
    "import doctest\ndoctest.run_docstring_examples(f, {})",
    # fileConfig evaluates a handler's args; dictConfig calls the name under "()".
    "import logging.config\nlogging.config.fileConfig(source)",
    "from logging import config\nconfig.dictConfig(settings)",
    "from logging import config as lc\nlc.fileConfig(source)",
    "from logging.config import dictConfig\ndictConfig(settings)",
    "import logging\nlogging.config.dictConfig(settings)",
    "import logging as lg\nlg.config.fileConfig(source)",
    "from idlelib import pyshell",
]


@pytest.mark.parametrize("code", STRING_EXECUTION)
def test_modules_that_run_strings_as_code_are_refused(code):
    _assert_refused(code)


FILE_ACCESS = [
    "import tarfile\ntarfile.open(p).extractall()",
    "import zipfile\nzipfile.ZipFile(p).extractall()",
    "import gzip\ngzip.open('/etc/passwd').read()",
    "import bz2\nbz2.open(p).read()",
    "import lzma\nlzma.open(p).read()",
    "import codecs\ncodecs.open('/etc/passwd').read()",
    "import linecache\nlinecache.getline('/etc/passwd', 1)",
    "import fileinput\nfor line in fileinput.input(p):\n    pass",
    "import os\nos.listdir('/')",
    "import os\nos.scandir('/')",
    "import os\nos.walk('/')",
    "import os as o\no.stat('/etc/passwd')",
    "from os import listdir\nlistdir('/')",
    "import glob\nglob.glob('/etc/*')",
    "from glob import glob as g\ng('/etc/*')",
    "import tempfile\ntempfile.mkstemp()",
    "import sqlite3\nsqlite3.connect('x.db')",
    "import shelve\nshelve.open('x')",
    "import dbm\ndbm.open('x', 'c')",
    "import builtins\ndata = builtins.open('/etc/passwd').read()",
    # A package data name with ".." reads a file outside the package.
    "import pkgutil\npkgutil.get_data('json', '../os.py')",
    "import importlib.resources as r\nr.files('json').joinpath('../os.py').read_text()",
    "from importlib.resources import files\nfiles('json').joinpath('x').read_bytes()",
]


@pytest.mark.parametrize("code", FILE_ACCESS)
def test_file_reading_extracting_and_listing_are_refused(code):
    _assert_refused(code)


ADMITTED = [
    "import gzip\ndata = gzip.compress(b'abc')",
    "import bz2\nprint(bz2.compress(b'x'))",
    "import os\nprint(os.path.join('a', 'b'))",
    "import time\nstart = time.time()",
    "status_code = 200\nprint(status_code)",
    "class Response:\n    code = 1\n\nprint(Response.code)",
    "import statistics\nprint(statistics.mean([1, 2]))",
    "import logging\nlogging.basicConfig(level=logging.INFO)\nlogging.getLogger(__name__).info('ok')",
    "code = 'abc'\nprint(code.upper(), code.strip())",
    "config = {'a': 1}\nprint(config.get('a'))",
]


@pytest.mark.parametrize("code", ADMITTED)
def test_look_alikes_are_still_admitted(code):
    result = _result(code)
    assert result.developer_fields["is_safe"] is True, result.developer_fields
    assert admission_decision(result).value == "ADMIT"
