from datetime import datetime, timezone

import pytest

from ansible.errors import AnsibleActionFail
from plugins.action import onepassword_approval as signer
from tests.unit.plugins.action.onepassword_approval_support import build_authority


def _arguments(tmp_path):
    authority = build_authority(tmp_path)
    signing_key = tmp_path / "signing-key"
    signing_key.write_bytes(b"test-only-key")
    signing_key.chmod(0o600)
    return {
        "approval_authority": authority,
        "binding": {"operation": "apply", "allow_create": True},
        "commit_shas": {"automation": "a" * 40, "foundational": "b" * 40},
        "execution_id_prefix": "WBX-1P-PASSWORD",
        "operation": "create-onepassword-secret",
        "signing_key_path": str(signing_key),
        "target": "host01.example.test",
        "validity_seconds": 600,
    }


def test_normalize_builds_short_lived_distinct_approval(tmp_path):
    now = datetime(2026, 8, 9, 22, 0, tzinfo=timezone.utc)
    first = signer._normalize_arguments(_arguments(tmp_path), now=now)
    second = signer._normalize_arguments(_arguments(tmp_path), now=now)
    assert first["approval"]["issued_at"] == "2026-08-09T22:00:00Z"
    assert first["approval"]["expires_at"] == "2026-08-09T22:10:00Z"
    assert first["approval"]["nonce"] != second["approval"]["nonce"]
    assert first["approval"]["execution_id"] != second["approval"]["execution_id"]


@pytest.mark.parametrize(
    "mutation",
    [
        lambda value: value.update(validity_seconds=901),
        lambda value: value.update(commit_shas={"automation": "short"}),
        lambda value: value.update(operation="invalid operation"),
        lambda value: value.update(target=""),
    ],
)
def test_normalize_rejects_invalid_contract(tmp_path, mutation):
    arguments = _arguments(tmp_path)
    mutation(arguments)
    with pytest.raises(AnsibleActionFail):
        signer._normalize_arguments(arguments)


def test_signing_key_must_be_owner_only(tmp_path):
    arguments = _arguments(tmp_path)
    signing_key = tmp_path / "signing-key"
    signing_key.chmod(0o640)
    with pytest.raises(AnsibleActionFail):
        signer._normalize_arguments(arguments)
