"""Regression tests for controller-only module fallback schemas."""

import ast
import importlib.util
from pathlib import Path
import sys
import types

import pytest


REPOSITORY_ROOT = Path(__file__).resolve().parents[4]


class _FallbackReached(RuntimeError):
    """Raised when the test double reaches the explicit fail-closed path."""


def _closed_action_schema(path):
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    for node in tree.body:
        if (
            isinstance(node, ast.Assign)
            and any(
                isinstance(target, ast.Name) and target.id == "_EXPECTED_ARGS"
                for target in node.targets
            )
            and isinstance(node.value, ast.Call)
            and node.value.args
        ):
            return set(ast.literal_eval(node.value.args[0]))
    raise AssertionError(f"No closed action schema found in {path}")


def _load_module_stub(monkeypatch, name, path, captured):
    class CapturingAnsibleModule:
        def __init__(self, **kwargs):
            captured.update(kwargs)

        def fail_json(self, **kwargs):
            raise _FallbackReached(kwargs["msg"])

    ansible = types.ModuleType("ansible")
    module_utils = types.ModuleType("ansible.module_utils")
    basic = types.ModuleType("ansible.module_utils.basic")
    basic.AnsibleModule = CapturingAnsibleModule
    ansible.module_utils = module_utils
    module_utils.basic = basic
    monkeypatch.setitem(sys.modules, "ansible", ansible)
    monkeypatch.setitem(sys.modules, "ansible.module_utils", module_utils)
    monkeypatch.setitem(sys.modules, "ansible.module_utils.basic", basic)

    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize(
    ("stem", "expected_message"),
    (
        (
            "onepassword_approval",
            "onepassword_approval requires its controller action plugin",
        ),
        (
            "onepassword_ssh_key_import",
            "onepassword_ssh_key_import requires its controller action plugin",
        ),
    ),
)
def test_remote_fallback_accepts_the_closed_action_schema(
    monkeypatch, stem, expected_message
):
    captured = {}
    module = _load_module_stub(
        monkeypatch,
        f"test_{stem}_module",
        REPOSITORY_ROOT / "plugins" / "modules" / f"{stem}.py",
        captured,
    )

    with pytest.raises(_FallbackReached, match=expected_message):
        module.main()

    expected_args = _closed_action_schema(
        REPOSITORY_ROOT / "plugins" / "action" / f"{stem}.py"
    )
    assert set(captured["argument_spec"]) == expected_args
    assert captured["supports_check_mode"] is True
