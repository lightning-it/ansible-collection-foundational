from datetime import timedelta
import hashlib
import json
import os
from pathlib import Path
import socket
import tempfile

import pytest

from ansible.errors import AnsibleActionFail

from plugins.action import _onepassword_boundary as boundary
from tests.unit.plugins.action.onepassword_approval_support import (
    build_approval,
    build_authority,
    sign_approval,
)


def _approval(tmp_path, operation="unlock", target="host01.example.test", binding=None):
    authority = build_authority(tmp_path)
    contract = {"host": target} if binding is None else binding
    approval, replay, now = build_approval(
        tmp_path,
        authority,
        operation,
        target,
        contract,
        execution_id="exec-20260809-001",
        replay_name="replay",
    )
    return authority, approval, contract, replay, now


def test_trusted_executable_requires_exact_digest_and_safe_metadata(tmp_path):
    executable = tmp_path / "tool"
    executable.write_bytes(b"#!/bin/sh\nexit 0\n")
    executable.chmod(0o700)
    digest = hashlib.sha256(executable.read_bytes()).hexdigest()

    assert boundary.trusted_executable(str(executable), digest, "tool") == str(
        executable
    )

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


def test_asymmetric_approval_is_verified_and_claimed_exactly_once(tmp_path):
    authority, approval, binding, replay, now = _approval(tmp_path)
    normalized = boundary.normalize_approval(
        approval, authority, "unlock", "host01.example.test", binding, now=now
    )

    assert normalized["authority_fingerprint"] == authority["fingerprint"]
    assert boundary.claim_approval(normalized, now=now)
    assert len(list(replay.glob("*.used"))) == 1
    with pytest.raises(AnsibleActionFail):
        boundary.normalize_approval(
            approval,
            authority,
            "unlock",
            "host01.example.test",
            binding,
            now=now,
        )
    with pytest.raises(AnsibleActionFail):
        boundary.claim_approval(normalized, now=now)


def test_claim_rejects_replaced_replay_directory(tmp_path):
    authority, approval, binding, replay, now = _approval(tmp_path)
    normalized = boundary.normalize_approval(
        approval, authority, "unlock", "host01.example.test", binding, now=now
    )
    original = tmp_path / "original-replay"
    replay.rename(original)
    replay.mkdir(mode=0o700)

    with pytest.raises(AnsibleActionFail):
        boundary.claim_approval(normalized, now=now)


def test_publicly_forged_signature_is_rejected(tmp_path):
    authority, approval, binding, _replay, now = _approval(tmp_path)
    forged = dict(approval)
    forged["signature"] = (
        "-----BEGIN SSH SIGNATURE-----\n" + "0" * 64 + "\n-----END SSH SIGNATURE-----\n"
    )

    with pytest.raises(AnsibleActionFail):
        boundary.normalize_approval(
            forged,
            authority,
            "unlock",
            "host01.example.test",
            binding,
            now=now,
        )


@pytest.mark.parametrize(
    ("operation", "target", "binding"),
    [
        ("create", "host01.example.test", {"host": "host01.example.test"}),
        ("unlock", "host02.example.test", {"host": "host01.example.test"}),
        ("unlock", "host01.example.test", {"host": "host02.example.test"}),
    ],
)
def test_signature_rejects_operation_target_and_binding_mutation(
    tmp_path, operation, target, binding
):
    authority, approval, _original_binding, _replay, now = _approval(tmp_path)
    with pytest.raises(AnsibleActionFail):
        boundary.normalize_approval(
            approval, authority, operation, target, binding, now=now
        )


@pytest.mark.parametrize("changed_field", ["commit_shas", "issued_at", "expires_at"])
def test_signature_rejects_signed_envelope_mutation(tmp_path, changed_field):
    authority, approval, binding, _replay, now = _approval(tmp_path)
    tampered = dict(approval)
    if changed_field == "commit_shas":
        tampered[changed_field] = {"foundational": "c" * 40}
    elif changed_field == "issued_at":
        tampered[changed_field] = (now - timedelta(seconds=1)).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
    else:
        tampered[changed_field] = (now + timedelta(minutes=4)).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
    with pytest.raises(AnsibleActionFail):
        boundary.normalize_approval(
            tampered,
            authority,
            "unlock",
            "host01.example.test",
            binding,
            now=now,
        )


@pytest.mark.parametrize(
    ("target", "binding"),
    [
        ("host02.example.test", {"host": "host02.example.test"}),
        ("host01.example.test", {"host": "changed.example.test"}),
    ],
)
def test_claim_blocks_resigned_cross_target_and_cross_binding_replay(
    tmp_path, target, binding
):
    authority, approval, original_binding, _replay, now = _approval(tmp_path)
    normalized = boundary.normalize_approval(
        approval,
        authority,
        "unlock",
        "host01.example.test",
        original_binding,
        now=now,
    )
    boundary.claim_approval(normalized, now=now)
    resigned = sign_approval(approval, authority, "unlock", target, binding)

    with pytest.raises(AnsibleActionFail):
        boundary.normalize_approval(
            resigned, authority, "unlock", target, binding, now=now
        )


def test_claim_blocks_resigned_cross_directory_replay(tmp_path):
    authority, approval, original_binding, replay, now = _approval(tmp_path)
    normalized = boundary.normalize_approval(
        approval,
        authority,
        "unlock",
        "host01.example.test",
        original_binding,
        now=now,
    )
    boundary.claim_approval(normalized, now=now)
    alternative_replay = tmp_path / "alternative-replay"
    alternative_replay.mkdir(mode=0o700)
    changed = dict(approval)
    changed["replay_directory"] = str(alternative_replay)
    changed_binding = {"host": "host02.example.test"}
    resigned = sign_approval(
        changed,
        authority,
        "unlock",
        "host02.example.test",
        changed_binding,
    )
    replay_identity = {
        "schema_version": 1,
        "authority_identity": authority["identity"],
        "authority_namespace": authority["namespace"],
        "authority_fingerprint": authority["fingerprint"],
        "execution_id": resigned["execution_id"],
        "nonce": resigned["nonce"],
    }
    resigned_replay_digest = hashlib.sha256(
        json.dumps(
            replay_identity,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("ascii")
    ).hexdigest()

    assert resigned_replay_digest == normalized["replay_digest"]

    with pytest.raises(AnsibleActionFail, match="must exactly match"):
        boundary.normalize_approval(
            resigned,
            authority,
            "unlock",
            "host02.example.test",
            changed_binding,
            now=now,
        )

    assert (replay / (normalized["replay_digest"] + ".used")).is_file()
    assert not list(alternative_replay.glob("*.used"))


def test_approval_rejects_expiry_and_insecure_replay_directory(tmp_path):
    authority, approval, binding, replay, now = _approval(tmp_path)
    with pytest.raises(AnsibleActionFail):
        boundary.normalize_approval(
            approval,
            authority,
            "unlock",
            "host01.example.test",
            binding,
            now=now + timedelta(minutes=6),
        )

    replay.chmod(0o755)
    with pytest.raises(AnsibleActionFail):
        boundary.normalize_approval(
            approval,
            authority,
            "unlock",
            "host01.example.test",
            binding,
            now=now,
        )


@pytest.mark.parametrize(
    "mutation",
    [
        "authority_identity",
        "authority_fingerprint",
        "allowed_signers_digest",
        "verifier_digest",
        "replay_directory_alias",
    ],
)
def test_approval_authority_pins_fail_closed(tmp_path, mutation):
    authority = build_authority(tmp_path)
    changed = dict(authority)
    if mutation == "authority_identity":
        changed["identity"] = "attacker@example.test"
    elif mutation == "authority_fingerprint":
        changed["fingerprint"] = "SHA256:" + "A" * 43
    elif mutation == "allowed_signers_digest":
        changed["allowed_signers_sha256"] = "0" * 64
    elif mutation == "verifier_digest":
        changed["ssh_keygen_sha256"] = "0" * 64
    else:
        alias = tmp_path / "replay-alias"
        alias.symlink_to(authority["replay_directory"])
        changed["replay_directory"] = str(alias)

    with pytest.raises(AnsibleActionFail):
        boundary.normalize_approval_authority(changed)


def test_public_signing_api_rejects_injected_internal_authority_state(tmp_path):
    authority, approval, binding, _replay, _now = _approval(tmp_path)
    normalized_authority = boundary.normalize_approval_authority(authority)

    with pytest.raises(AnsibleActionFail):
        boundary.approval_signing_payload(
            approval,
            normalized_authority,
            "unlock",
            "host01.example.test",
            binding,
        )
