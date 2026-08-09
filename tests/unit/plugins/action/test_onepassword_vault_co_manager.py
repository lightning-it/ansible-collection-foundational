import pytest

from ansible.errors import AnsibleActionFail

from plugins.action import onepassword_vault_co_manager as plugin
from tests.unit.plugins.action.onepassword_approval_support import (
    build_approval,
    build_authority,
)


ACCOUNT_ID = "a" * 26
VAULT_ID = "v" * 26
OPERATOR_UUID = "o" * 26
USER_UUID = "u" * 26
USER_EMAIL = "custodian@example.com"
REQUIRED_PERMISSIONS = ["allow_viewing", "allow_editing", "allow_managing"]


def _arguments(**overrides):
    arguments = {
        "operation": "plan",
        "cli_path": "/usr/local/bin/op",
        "cli_sha256": "0" * 64,
        "cli_version": "2.38.1",
        "account_id": ACCOUNT_ID,
        "account_sign_in_address": "example.1password.com",
        "authorized_user_uuids": [OPERATOR_UUID],
        "vault_id": VAULT_ID,
        "user_uuid": USER_UUID,
        "user_email": USER_EMAIL,
        "allow_grant": False,
        "approval_authority": {},
        "approval": {},
    }
    arguments.update(overrides)
    return arguments


def _apply_arguments(tmp_path, **overrides):
    arguments = _arguments(operation="apply", allow_grant=True, **overrides)
    authority = build_authority(tmp_path)
    binding = {
        "operation": arguments["operation"],
        "allow_grant": arguments["allow_grant"],
        "account_id": arguments["account_id"],
        "account_sign_in_address": arguments["account_sign_in_address"],
        "authorized_user_uuids": arguments["authorized_user_uuids"],
        "cli_path": arguments["cli_path"],
        "cli_sha256": arguments["cli_sha256"],
        "cli_version": arguments["cli_version"],
        "required_permissions": REQUIRED_PERMISSIONS,
        "user_email": arguments["user_email"],
        "user_uuid": arguments["user_uuid"],
        "vault_id": arguments["vault_id"],
    }
    approval, replay, _unused_now = build_approval(
        tmp_path,
        authority,
        "grant-onepassword-vault-co-manager",
        "{0}:{1}".format(VAULT_ID, USER_UUID),
        binding,
        execution_id="vault-co-manager-001",
        replay_name="replay",
    )
    arguments["approval_authority"] = authority
    arguments["approval"] = approval
    return arguments, replay


class _FakeClient:
    def __init__(self, permissions=None, user_present=True, grant_effective=True):
        self.permissions = list(permissions or [])
        self.user_present = user_present
        self.grant_effective = grant_effective
        self.calls = []

    def _run(self, arguments, operation, discard_stdout=False):
        self.calls.append((list(arguments), operation, discard_stdout))
        assert arguments == ["--version"]
        return b"2.38.1\n"

    def metadata(self, arguments, operation):
        self.calls.append((list(arguments), operation, False))
        if arguments[0] == "whoami":
            return {
                "account_uuid": ACCOUNT_ID,
                "url": "https://example.1password.com",
                "user_uuid": OPERATOR_UUID,
            }
        if arguments[:2] == ["vault", "get"]:
            return {"id": VAULT_ID}
        if arguments[:2] == ["user", "get"]:
            return {
                "id": USER_UUID,
                "email": USER_EMAIL,
                "state": "ACTIVE",
            }
        if arguments[:3] == ["vault", "user", "list"]:
            if not self.user_present:
                return []
            return [
                {
                    "uuid": USER_UUID,
                    "email": USER_EMAIL,
                    "state": "ACTIVE",
                    "permissions": list(self.permissions),
                }
            ]
        raise AssertionError("unexpected metadata request")

    def discard(self, arguments, operation):
        self.calls.append((list(arguments), operation, True))
        assert arguments == [
            "vault",
            "user",
            "grant",
            "--account",
            ACCOUNT_ID,
            "--vault",
            VAULT_ID,
            "--user",
            USER_UUID,
            "--permissions",
            ",".join(REQUIRED_PERMISSIONS),
            "--no-input",
        ]
        if self.grant_effective:
            self.permissions = list(REQUIRED_PERMISSIONS)
            self.user_present = True


def test_plan_accepts_complete_co_manager_access():
    client = _FakeClient(permissions=REQUIRED_PERMISSIONS)
    result = plugin._OnePasswordVaultCoManagerStore(client).run(
        plugin._normalize_arguments(_arguments())
    )

    assert result == {
        "changed": False,
        "exists": True,
        "missing_permissions": [],
        "observed_permissions": sorted(REQUIRED_PERMISSIONS),
        "operator_user_uuid": OPERATOR_UUID,
        "planned": False,
        "required_permissions": REQUIRED_PERMISSIONS,
        "user_uuid": USER_UUID,
    }


def test_plan_reports_missing_permissions_without_mutation():
    client = _FakeClient(permissions=["allow_viewing"])
    result = plugin._OnePasswordVaultCoManagerStore(client).run(
        plugin._normalize_arguments(_arguments())
    )

    assert result["changed"] is True
    assert result["planned"] is True
    assert result["missing_permissions"] == ["allow_editing", "allow_managing"]
    assert not [call for call in client.calls if call[2] is True]


def test_apply_grants_complete_fixed_set_once_and_claims_approval(tmp_path):
    client = _FakeClient(permissions=["allow_viewing"])
    arguments, replay = _apply_arguments(tmp_path)
    result = plugin._OnePasswordVaultCoManagerStore(client).run(
        plugin._normalize_arguments(arguments)
    )

    assert result["changed"] is True
    assert result["missing_permissions"] == []
    assert result["observed_permissions"] == sorted(REQUIRED_PERMISSIONS)
    assert len([call for call in client.calls if call[2] is True]) == 1
    assert len(list(replay.glob("*.used"))) == 1


def test_apply_is_idempotent_and_does_not_consume_approval_for_noop(tmp_path):
    client = _FakeClient(permissions=REQUIRED_PERMISSIONS)
    arguments, replay = _apply_arguments(tmp_path)
    result = plugin._OnePasswordVaultCoManagerStore(client).run(
        plugin._normalize_arguments(arguments)
    )

    assert result["changed"] is False
    assert not [call for call in client.calls if call[2] is True]
    assert not list(replay.glob("*.used"))


def test_apply_rechecks_state_before_claim_and_avoids_raced_noop(tmp_path):
    class _ConvergingClient(_FakeClient):
        def __init__(self):
            super().__init__(permissions=["allow_viewing"])
            self.access_reads = 0

        def metadata(self, arguments, operation):
            response = super().metadata(arguments, operation)
            if arguments[:3] == ["vault", "user", "list"]:
                self.access_reads += 1
                if self.access_reads == 1:
                    self.permissions = list(REQUIRED_PERMISSIONS)
            return response

    client = _ConvergingClient()
    arguments, replay = _apply_arguments(tmp_path)
    result = plugin._OnePasswordVaultCoManagerStore(client).run(
        plugin._normalize_arguments(arguments)
    )

    assert result["changed"] is False
    assert result["missing_permissions"] == []
    assert client.access_reads == 2
    assert not [call for call in client.calls if call[2] is True]
    assert not list(replay.glob("*.used"))


def test_check_mode_reports_grant_without_claim_or_mutation(tmp_path):
    client = _FakeClient(permissions=[])
    arguments, replay = _apply_arguments(tmp_path)
    result = plugin._OnePasswordVaultCoManagerStore(client).run(
        plugin._normalize_arguments(arguments),
        check_mode=True,
    )

    assert result["changed"] is True
    assert result["planned"] is True
    assert not [call for call in client.calls if call[2] is True]
    assert not list(replay.glob("*.used"))


def test_apply_fails_when_post_grant_readback_is_incomplete(tmp_path):
    client = _FakeClient(permissions=[], grant_effective=False)
    arguments, _unused_replay = _apply_arguments(tmp_path)
    with pytest.raises(AnsibleActionFail):
        plugin._OnePasswordVaultCoManagerStore(client).run(
            plugin._normalize_arguments(arguments)
        )


@pytest.mark.parametrize(
    "overrides",
    [
        {"operation": "read"},
        {"allow_grant": True},
        {"user_uuid": "not-an-id"},
        {"user_email": "not-an-email"},
        {"authorized_user_uuids": []},
        {"cli_sha256": "wrong"},
    ],
)
def test_invalid_contracts_fail_before_cli_use(overrides):
    with pytest.raises(AnsibleActionFail):
        plugin._normalize_arguments(_arguments(**overrides))


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("account_sign_in_address", "changed.1password.com"),
        ("cli_path", "/opt/changed/op"),
        ("user_email", "changed@example.com"),
        ("user_uuid", "z" * 26),
        ("vault_id", "y" * 26),
    ],
)
def test_apply_signature_rejects_contract_mutation(tmp_path, field, value):
    arguments, _unused_replay = _apply_arguments(tmp_path)
    arguments[field] = value
    with pytest.raises(AnsibleActionFail):
        plugin._normalize_arguments(arguments)


def test_target_user_identity_mismatch_fails_closed():
    class _MismatchedClient(_FakeClient):
        def metadata(self, arguments, operation):
            response = super().metadata(arguments, operation)
            if arguments[:2] == ["user", "get"]:
                response["email"] = "different@example.com"
            return response

    with pytest.raises(AnsibleActionFail):
        plugin._OnePasswordVaultCoManagerStore(_MismatchedClient()).run(
            plugin._normalize_arguments(_arguments())
        )


def test_unauthorized_operator_fails_closed():
    with pytest.raises(AnsibleActionFail):
        plugin._OnePasswordVaultCoManagerStore(_FakeClient()).run(
            plugin._normalize_arguments(
                _arguments(authorized_user_uuids=["z" * 26])
            )
        )


def test_inactive_target_user_fails_closed():
    class _InactiveClient(_FakeClient):
        def metadata(self, arguments, operation):
            response = super().metadata(arguments, operation)
            if arguments[:2] == ["user", "get"]:
                response["state"] = "SUSPENDED"
            return response

    with pytest.raises(AnsibleActionFail):
        plugin._OnePasswordVaultCoManagerStore(_InactiveClient()).run(
            plugin._normalize_arguments(_arguments())
        )


def test_inactive_vault_user_access_fails_closed():
    class _InactiveAccessClient(_FakeClient):
        def metadata(self, arguments, operation):
            response = super().metadata(arguments, operation)
            if arguments[:3] == ["vault", "user", "list"] and response:
                response[0]["state"] = "SUSPENDED"
            return response

    with pytest.raises(AnsibleActionFail):
        plugin._OnePasswordVaultCoManagerStore(_InactiveAccessClient()).run(
            plugin._normalize_arguments(_arguments())
        )


def test_duplicate_or_invalid_permission_metadata_fails_closed():
    with pytest.raises(AnsibleActionFail):
        plugin._OnePasswordVaultCoManagerStore(
            _FakeClient(permissions=["allow_viewing", "allow_viewing"])
        ).run(plugin._normalize_arguments(_arguments()))
    with pytest.raises(AnsibleActionFail):
        plugin._OnePasswordVaultCoManagerStore(
            _FakeClient(permissions=[{"unexpected": "mapping"}])
        ).run(plugin._normalize_arguments(_arguments()))
