"""GHSA-qrp4-p44j-m484: CodeVerifier.verify_code returned VERIFIED · ADMIT for
code that gets a module by its name as a string from the import system (a
module's __loader__ or __spec__.loader, BuiltinImporter, sys.meta_path,
importlib.util.module_from_spec, the importlib bootstrap, _imp,
pkgutil.resolve_name, pydoc.locate, or sys.modules read other than by
subscript) and then calls on the module it returns.

Harmless placeholders (`id`); nothing is executed.
"""
import pytest

from qwed_new.core.code_verifier import CodeVerifier
from qwed_new.core.diagnostics import admission_decision


def _result(code):
    return CodeVerifier().verify_code(code, language="python")


MODULE_BY_NAME_ROUTES = [
    "__loader__.load_module('posix').system('id')",
    "__spec__.loader.load_module('posix').system('id')",
    "import os\nos.__loader__.load_module('posix').system('id')",
    "import json\njson.__spec__.loader.load_module('posix').system('id')",
    "loader = __loader__\nloader.load_module('posix')",
    "kind = type(__loader__)\nkind.load_module('posix').system('id')",
    "from importlib.machinery import BuiltinImporter as B\nB.load_module('posix').system('id')",
    "import importlib.machinery\nimportlib.machinery.BuiltinImporter.load_module('posix').system('id')",
    "import sys\nsys.meta_path[0].load_module('posix').system('id')",
    "import sys\ns = sys.meta_path[0].find_spec('posix')\ns.loader.create_module(s).system('id')",
    "import importlib.util as u\nu.module_from_spec(u.find_spec('posix')).system('id')",
    "from importlib.util import module_from_spec as m, find_spec as f\nm(f('posix')).system('id')",
    "import importlib._bootstrap as b\nb._gcd_import('posix').system('id')",
    "from importlib import _bootstrap\n_bootstrap._load(None)",
    "import importlib\nimportlib._bootstrap._builtin_from_name('posix').system('id')",
    "import _frozen_importlib\n_frozen_importlib.BuiltinImporter.load_module('posix').system('id')",
    "import _frozen_importlib as f\nf._load(None)",
    "import _imp, importlib.util as u\n_imp.create_builtin(u.find_spec('posix')).system('id')",
    "import _imp\n_imp.init_frozen('os').system('id')",
    "import pkgutil\npkgutil.get_loader('posix').load_module('posix')",
    "import pkgutil\npkgutil.resolve_name('os:system')('id')",
    "from pkgutil import resolve_name as r\nr('posix:system')('id')",
    "import pydoc\npydoc.locate('posix.system')('id')",
    "name = 'load_module'\nprint(name)",
    # The table of loaded modules, read other than as sys.modules[...].
    "import sys\nsys.modules.get('posix').system('id')",
    "import sys as s\ns.modules.get('posix').system('id')",
    "from sys import modules\nmodules.get('posix').system('id')",
    "from sys import modules as m\nm['posix'].system('id')",
    "from sys import *\nmodules.get('posix').system('id')",
    "import sys\ntable = sys.modules\ntable['posix'].system('id')",
    "import sys\nsys.modules.pop('posix').system('id')",
]


@pytest.mark.parametrize("code", MODULE_BY_NAME_ROUTES)
def test_module_by_name_routes_are_blocked(code):
    result = _result(code)
    fields = result.developer_fields
    assert fields["is_safe"] is False, fields
    assert fields["critical_count"] >= 1
    assert admission_decision(result).value == "BLOCKED"


# Third-party modules, importlib and pkgutil are not admitted at all
# (GHSA-9r7q); the look-alikes here are names, not imports of them.
ADMITTED = [
    "x = [1, 2, 3]\nprint(sum(x))",
    "class DataLoader:\n    pass\nloader = DataLoader()",
    "def load_module_config(path):\n    return path.upper()",
    "spec = {'json': True}\nprint(spec.get('json'))",
    "class Loader:\n    def load(self, path):\n        return path",
    "msg = 'module loaded from spec'\nprint(msg)",
    "iter_modules = ['a']\nprint([m for m in iter_modules][:1])",
    "bootstrap = True\nprint(bootstrap)",
    "import sys\nprint(sys.argv[1:], sys.version_info >= (3, 11))",
    "modules = ['a', 'b']\nprint(modules[0])",
    "class Package:\n    modules = []\nprint(Package().modules)",
]


@pytest.mark.parametrize("code", ADMITTED)
def test_names_that_only_resemble_the_import_system_are_admitted(code):
    result = _result(code)
    assert result.developer_fields["is_safe"] is True, result.developer_fields
    assert admission_decision(result).value == "ADMIT"
