from datetime import datetime, timedelta, timezone
import hashlib
import os
import socket
import tempfile
from pathlib import Path

import pytest

from ansible.errors import AnsibleActionFail

from plugins.action import _onepassword_boundary as boundary


def _approval(tmp_path, operation="unlock", target="host01.example.test", binding=None):
    replay = tmp_path / "replay"
    replay.mkdir(mode=0o700)
    now = datetime.now(timezone.utc).replace(microsecond=0)
    approval = {
        "schema_version": 1,
        "execution_id": "exec-20260809-001",
        "commit_shas": {"foundational": "a" * 40},
        "nonce": "b" * 64,
        "issued_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "expires_at": (now + timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "replay_directory": str(replay),
    }
    contract = {"host": target} if binding is None else binding
    approval["confirmation"] = boundary.approval_confirmation(
        approval, operation, target, contract
    )
    return approval, contract, now


def test_trusted_executable_requires_exact_digest_and_safe_metadata(tmp_path):
    executable = tmp_path / "tool"
    executable.write_bytes(b"#!/bin/sh\nexit 0\n")
    executable.chmod(0o700)
    digest = hashlib.sha256(executable.read_bytes()).hexdigest()

    assert boundary.trusted_executable(str(executable), digest, "tool") == str(executable)

    with pytest.raises(AnsibleActionFail):
        boundary.trusted_executable(str(executable), "0" * 64, "tool")
    executable.chmod(0o722)
    with pytest.raises(AnsibleActionFail):
        boundary.trusted_executable(str(executable), digest, "tool")


def test_trusted_executable_rejects_mutable_parent_and_hard_link(tmp_path):
    mutable = tmp_path / "mutable"
    mutable.mkdir(mode=0o700)
    executable = mutable / "tool"
    executable.write_bytes(b"tool")
    executable.chmod(0o700)
    digest = hashlib.sha256(b"tool").hexdigest()
    hard_link = mutable / "tool.link"
    os.link(executable, hard_link)

    with pytest.raises(AnsibleActionFail):
        boundary.trusted_executable(str(executable), digest, "tool")

    hard_link.unlink()
    mutable.chmod(0o777)
    with pytest.raises(AnsibleActionFail):
        boundary.trusted_executable(str(executable), digest, "tool")


def test_agent_socket_resolves_official_style_alias_with_spaces(tmp_path):
    with tempfile.TemporaryDirectory(prefix="op socket ", dir="/private/tmp") as root:
        canonical_parent = Path(root)
        canonical_parent.chmod(0o700)
        socket_path = canonical_parent / "agent.sock"
        agent = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        agent.bind(str(socket_path))
        alias = tmp_path / "agent-alias.sock"
        alias.symlink_to(socket_path)
        try:
            assert boundary.trusted_agent_socket(str(alias)) == str(socket_path)
        finally:
            agent.close()


def test_approval_is_bound_and_can_be_claimed_exactly_once(tmp_path):
    approval, binding, now = _approval(tmp_path)
    normalized = boundary.normalize_approval(
        approval, "unlock", "host01.example.test", binding, now=now
    )

    assert boundary.claim_approval(normalized, now=now)
    with pytest.raises(AnsibleActionFail):
        boundary.normalize_approval(
            approval, "unlock", "host01.example.test", binding, now=now
        )
    with pytest.raises(AnsibleActionFail):
        boundary.claim_approval(normalized, now=now)


@pytest.mark.parametrize(
    ("operation", "target", "binding"),
    [
        ("create", "host01.example.test", {"host": "host01.example.test"}),
        ("unlock", "host02.example.test", {"host": "host01.example.test"}),
        ("unlock", "host01.example.test", {"host": "host02.example.test"}),
    ],
)
def test_approval_rejects_operation_target_and_binding_tampering(
    tmp_path, operation, target, binding
):
    approval, original_binding, now = _approval(tmp_path)
    with pytest.raises(AnsibleActionFail):
        boundary.normalize_approval(approval, operation, target, binding, now=now)


def test_approval_rejects_expiry_commit_tampering_and_insecure_replay_dir(tmp_path):
    approval, binding, now = _approval(tmp_path)
    with pytest.raises(AnsibleActionFail):
        boundary.normalize_approval(
            approval,
            "unlock",
            "host01.example.test",
            binding,
            now=now + timedelta(minutes=6),
        )

    tampered = dict(approval)
    tampered["commit_shas"] = {"foundational": "c" * 40}
    with pytest.raises(AnsibleActionFail):
        boundary.normalize_approval(
            tampered, "unlock", "host01.example.test", binding, now=now
        )

    replay = tmp_path / "replay"
    replay.chmod(0o755)
    with pytest.raises(AnsibleActionFail):
        boundary.normalize_approval(
            approval, "unlock", "host01.example.test", binding, now=now
        )
