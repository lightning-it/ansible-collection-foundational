import pytest

from ansible.errors import AnsibleActionFail

from plugins.action import onepassword_secret_item as plugin


ACCOUNT_ID = "a" * 26
VAULT_ID = "v" * 26
ITEM_ID = "i" * 26
ITEM_VERSION = 1
SUBJECT = "host01.example.test"
SECRET = "A" * 64


def _arguments(**overrides):
    arguments = {
        "operation": "plan",
        "cli_path": "/usr/local/bin/op",
        "cli_version": "2.38.1",
        "account_id": ACCOUNT_ID,
        "account_sign_in_address": "example.1password.com",
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
        "confirmation": "",
    }
    arguments.update(overrides)
    return arguments


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
            return {"account_uuid": ACCOUNT_ID, "url": "https://example.1password.com"}
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

def test_apply_generates_inside_onepassword_and_returns_only_item_metadata():
    client = _FakeClient(exists=False)
    store = plugin._OnePasswordSecretItemStore(client)
    result = store.run(
        plugin._normalize_arguments(
            _arguments(
                operation="apply",
                allow_create=True,
                confirmation="CREATE-ONEPASSWORD-SECRET:" + SUBJECT,
            )
        )
    )

    assert result == {
        "changed": True,
        "created": True,
        "exists": True,
        "item_id": ITEM_ID,
        "item_version": ITEM_VERSION,
        "planned": False,
    }
    assert SECRET not in repr(result)
    creation_calls = [call for call in client.calls if call[1] == "item creation"]
    assert len(creation_calls) == 1
    assert creation_calls[0][2] is True


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


def test_check_mode_apply_is_metadata_only_and_does_not_create():
    client = _FakeClient(exists=False)
    result = plugin._OnePasswordSecretItemStore(client).run(
        plugin._normalize_arguments(
            _arguments(
                operation="apply",
                allow_create=True,
                confirmation="CREATE-ONEPASSWORD-SECRET:" + SUBJECT,
            )
        ),
        check_mode=True,
    )

    assert result["planned"] is True
    assert result["created"] is False
    assert not [call for call in client.calls if call[1] == "item creation"]


def test_apply_rejects_a_preexisting_unpinned_item():
    client = _FakeClient(exists=True)
    with pytest.raises(AnsibleActionFail):
        plugin._OnePasswordSecretItemStore(client).run(
            plugin._normalize_arguments(
                _arguments(
                    operation="apply",
                    allow_create=True,
                    confirmation="CREATE-ONEPASSWORD-SECRET:" + SUBJECT,
                )
            )
        )


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
        {"operation": "apply", "allow_create": True, "confirmation": "wrong"},
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
