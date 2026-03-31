import builtins
import importlib.util
import sys
from pathlib import Path


def test_observability_falls_back_without_prometheus(monkeypatch):
    module_path = Path(__file__).resolve().parents[1] / "src" / "qwed_new" / "core" / "observability.py"
    spec = importlib.util.spec_from_file_location("observability_no_prometheus", module_path)
    assert spec is not None
    assert spec.loader is not None

    real_import = builtins.__import__

    def fake_import(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "prometheus_client":
            raise ImportError("prometheus_client unavailable in test")
        return real_import(name, globals, locals, fromlist, level)

    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, spec.name, module)
    monkeypatch.setattr(builtins, "__import__", fake_import)
    spec.loader.exec_module(module)

    assert module.PROMETHEUS_AVAILABLE is False
    assert module.generate_latest() == b""
    assert module.get_prometheus_metrics() == b"# Prometheus client not installed\n"
    assert module.get_prometheus_content_type() == "text/plain"
