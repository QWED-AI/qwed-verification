import importlib.util
from pathlib import Path


def _load_script_module(module_name: str, relative_path: str):
    project_root = Path(__file__).resolve().parents[1]
    module_path = project_root / relative_path
    spec = importlib.util.spec_from_file_location(module_name, module_path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_benchmark_adversarial_safe_bool_eval_handles_logic():
    module = _load_script_module("benchmark_adversarial", "scripts/benchmark_adversarial.py")

    calculated, is_correct = module.verify_with_qwed("not(False or False)", "true")

    assert calculated == "true"
    assert is_correct is True
