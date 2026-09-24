import pytest

from ansible.errors import AnsibleActionFail

from plugins.action import onepassword_secret_item as plugin
from tests.unit.plugins.action.onepassword_approval_support import (
    build_approval,
    build_authority,
)


ACCOUNT_ID = "A" * 26
VAULT_ID = "v" * 26
ITEM_ID = "i" * 26
ITEM_VERSION = 1
SUBJECT = "host01.example.test"
SECRET = "A" * 64
USER_UUID = "U" * 26


def _arguments(**overrides):
    arguments = {
        "operation": "plan",
        "cli_path": "/usr/local/bin/op",
        "cli_sha256": "0" * 64,
        "cli_version": "2.38.1",
        "account_id": ACCOUNT_ID,
        "account_sign_in_address": "example.1password.com",
        "authorized_user_uuids": [USER_UUID],
        "vault_id": VAULT_ID,
        "item_id": "",
        "item_version": 0,
        "item_title": "host01.example.test recovery",
        "field_id": "password",
        "category": "Password",
        "tags": ["breakglass", "recovery"],
        "subject": SUBJECT,
        "schema_version": 1,
        "password_recipe": "letters,digits,symbols,64",
        "password_length": 64,
        "allow_create": False,
        "approval_authority": {},
        "approval": {},
    }
    arguments.update(overrides)
    return arguments


def _apply_arguments(tmp_path, **overrides):
    arguments = _arguments(operation="apply", allow_create=True, **overrides)
    authority = build_authority(tmp_path)
    binding = {
        "operation": arguments["operation"],
        "allow_create": arguments["allow_create"],
        "account_id": arguments["account_id"],
        "account_sign_in_address": arguments["account_sign_in_address"],
        "authorized_user_uuids": arguments["authorized_user_uuids"],
        "category": arguments["category"],
        "cli_path": arguments["cli_path"],
        "cli_sha256": arguments["cli_sha256"],
        "cli_version": arguments["cli_version"],
        "field_id": arguments["field_id"],
        "item_id": arguments["item_id"],
        "item_title": arguments["item_title"],
        "item_version": arguments["item_version"],
        "password_length": arguments["password_length"],
        "password_recipe": arguments["password_recipe"],
        "schema_version": arguments["schema_version"],
        "subject": arguments["subject"],
        "tags": arguments["tags"],
        "vault_id": arguments["vault_id"],
    }
    approval, replay, _unused_now = build_approval(
        tmp_path,
        authority,
        "create-onepassword-secret",
        SUBJECT,
        binding,
        execution_id="secret-create-001",
        replay_name="replay",
    )
    arguments["approval_authority"] = authority
    arguments["approval"] = approval
    return arguments, replay


class _FakeClient:
    def __init__(self, exists=False):
        self.exists = exists
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
                "user_uuid": USER_UUID,
            }
        if arguments[:2] == ["vault", "get"]:
            return {"id": VAULT_ID}
        if arguments[:2] == ["item", "list"]:
            if not self.exists:
                return []
            return [
                {
                    "id": ITEM_ID,
                    "version": ITEM_VERSION,
                    "title": "host01.example.test recovery",
                    "category": "PASSWORD",
                    "tags": ["breakglass", "recovery"],
                }
            ]
        if arguments[:2] == ["item", "get"]:
            return [
                {"label": "subject", "value": SUBJECT},
                {"label": "schema_version", "value": "1"},
                {"label": "expected_length", "value": "64"},
            ]
        raise AssertionError("unexpected metadata request")

    def discard(self, arguments, operation):
        self.calls.append((list(arguments), operation, True))
        assert "--generate-password=letters,digits,symbols,64" in arguments
        assert "--generate-password" not in arguments
        assert SECRET not in repr(arguments)
        self.exists = True


def test_apply_generates_inside_onepassword_and_returns_only_item_metadata(tmp_path):
    client = _FakeClient(exists=False)
    store = plugin._OnePasswordSecretItemStore(client)
    arguments, replay = _apply_arguments(tmp_path)
    result = store.run(plugin._normalize_arguments(arguments))

    assert result == {
        "changed": True,
        "created": True,
        "exists": True,
        "item_id": ITEM_ID,
        "item_version": ITEM_VERSION,
        "operator_user_uuid": USER_UUID,
        "planned": False,
        "approval": result["approval"],
    }
    assert SECRET not in repr(result)
    creation_calls = [call for call in client.calls if call[1] == "item creation"]
    assert len(creation_calls) == 1
    assert creation_calls[0][2] is True
    assert len(list(replay.glob("*.used"))) == 1


def test_plan_validates_only_a_pinned_item_and_returns_no_secret():
    client = _FakeClient(exists=True)
    store = plugin._OnePasswordSecretItemStore(client)
    result = store.run(
        plugin._normalize_arguments(
            _arguments(
                operation="plan",
                item_id=ITEM_ID,
                item_version=ITEM_VERSION,
            )
        )
    )

    assert result["item_id"] == ITEM_ID
    assert result["changed"] is False
    assert "secret" not in result


def test_check_mode_apply_is_metadata_only_and_does_not_create(tmp_path):
    client = _FakeClient(exists=False)
    arguments, replay = _apply_arguments(tmp_path)
    result = plugin._OnePasswordSecretItemStore(client).run(
        plugin._normalize_arguments(arguments),
        check_mode=True,
    )

    assert result["planned"] is True
    assert result["created"] is False
    assert not [call for call in client.calls if call[1] == "item creation"]
    assert not list(replay.glob("*.used"))


def test_apply_rejects_a_preexisting_unpinned_item(tmp_path):
    client = _FakeClient(exists=True)
    arguments, unused_replay = _apply_arguments(tmp_path)
    with pytest.raises(AnsibleActionFail):
        plugin._OnePasswordSecretItemStore(client).run(
            plugin._normalize_arguments(arguments)
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("account_sign_in_address", "changed.1password.com"),
        ("cli_path", "/opt/changed/op"),
        ("item_title", "changed recovery title"),
        ("tags", ["breakglass", "changed"]),
    ],
)
def test_apply_signature_rejects_normalized_contract_mutation(tmp_path, field, value):
    arguments, _unused_replay = _apply_arguments(tmp_path)
    arguments[field] = value
    with pytest.raises(AnsibleActionFail):
        plugin._normalize_arguments(arguments)


@pytest.mark.parametrize(
    "overrides",
    [
        {"item_id": "not-an-id"},
        {"item_id": ITEM_ID},
        {"item_version": ITEM_VERSION},
        {"operation": "read"},
        {"tags": []},
        {"password_recipe": "letters,digits,64"},
        {"tags": ["recovery", "recovery"]},
        {"allow_create": True},
        {"authorized_user_uuids": []},
        {"cli_sha256": "wrong"},
    ],
)
def test_invalid_contracts_fail_before_cli_use(overrides):
    with pytest.raises(AnsibleActionFail):
        plugin._normalize_arguments(_arguments(**overrides))


def test_service_and_session_authentication_environment_is_rejected():
    with pytest.raises(AnsibleActionFail):
        plugin._OnePasswordCLI._minimal_environment(
            {"HOME": "/tmp/home", "OP_SERVICE_ACCOUNT_TOKEN": "test-token"}
        )
    with pytest.raises(AnsibleActionFail):
        plugin._OnePasswordCLI._minimal_environment(
            {"HOME": "/tmp/home", "OP_SESSION_test": "test-session"}
        )


def test_operator_user_uuid_must_be_allowlisted():
    client = _FakeClient(exists=True)
    config = plugin._normalize_arguments(
        _arguments(
            operation="plan",
            item_id=ITEM_ID,
            item_version=ITEM_VERSION,
            authorized_user_uuids=["Z" * 26],
        )
    )
    with pytest.raises(AnsibleActionFail):
        plugin._OnePasswordSecretItemStore(client).inspect(config)
