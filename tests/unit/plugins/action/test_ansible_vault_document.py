import concurrent.futures
import math
import stat
import threading
from types import SimpleNamespace

import pytest
import yaml

from ansible.errors import AnsibleActionFail
from ansible.parsing.vault import VaultLib, VaultSecret
from ansible.utils.unsafe_proxy import AnsibleUnsafeText

from plugins.action import ansible_vault_document as plugin
from plugins.action import ansible_vault_secret_document as secret_plugin


TEST_VAULT_PASSWORD = b"unit-test-only-vault-password"
SECOND_VAULT_PASSWORD = b"unit-test-only-second-vault-password"
SECRET_SENTINEL = "unit-test-only-root-token-must-not-leak"


@pytest.fixture
def vault():
    return VaultLib([("unit-test", VaultSecret(TEST_VAULT_PASSWORD))])


def _document(token=SECRET_SENTINEL):
    return {
        "schema_version": 1,
        "subject": "service01.example.test",
        "bootstrap": {
            "initial_root_token": token,
            "key_shares": 5,
            "key_threshold": 3,
            "unseal_keys_b64": ["unit-test-only-share-a", "unit-test-only-share-b"],
        },
        "enabled": True,
        "optional": None,
        "weight": 1.25,
    }


def _store(vault):
    return plugin._new_document_store(vault)


def _write_encrypted(path, vault, document):
    path.write_bytes(vault.encrypt(yaml.safe_dump(document, sort_keys=True)))
    path.chmod(0o600)


def test_exact_document_is_created_once_and_rerun_is_unchanged(tmp_path, vault):
    path = tmp_path / "private" / "service.vault.yml"
    store = _store(vault)

    created = store.ensure_exact(str(path), _document())
    rerun = store.ensure_exact(str(path), _document())

    assert created == {
        "changed": True,
        "created": True,
        "exists": True,
        "path": str(path),
        "ciphertext_sha256": created["ciphertext_sha256"],
    }
    assert rerun == {
        "changed": False,
        "created": False,
        "exists": True,
        "path": str(path),
        "ciphertext_sha256": created["ciphertext_sha256"],
    }
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700
    assert yaml.safe_load(vault.decrypt(path.read_bytes())) == _document()
    assert SECRET_SENTINEL not in repr(created)


def test_explicit_vault_id_selects_exactly_one_loaded_identity(tmp_path):
    path = tmp_path / "private" / "selected.vault.yml"
    selected_secret = VaultSecret(SECOND_VAULT_PASSWORD)
    vault = VaultLib(
        [
            ("primary", VaultSecret(TEST_VAULT_PASSWORD)),
            ("secondary", selected_secret),
        ]
    )

    vault_secret, vault_id = plugin._select_vault_secret(vault, "secondary")
    result = _store(vault).ensure_exact(
        str(path),
        _document(),
        vault_secret=vault_secret,
        vault_id=vault_id,
    )

    assert result["created"] is True
    assert path.read_bytes().splitlines()[0] == b"$ANSIBLE_VAULT;1.2;AES256;secondary"
    selected_vault = VaultLib([("secondary", selected_secret)])
    assert yaml.safe_load(selected_vault.decrypt(path.read_bytes())) == _document()


def test_explicit_vault_id_must_match_one_loaded_identity():
    duplicate_vault = VaultLib(
        [
            ("duplicate", VaultSecret(TEST_VAULT_PASSWORD)),
            ("duplicate", VaultSecret(SECOND_VAULT_PASSWORD)),
        ]
    )

    with pytest.raises(AnsibleActionFail):
        plugin._select_vault_secret(duplicate_vault, "missing")
    with pytest.raises(AnsibleActionFail):
        plugin._select_vault_secret(duplicate_vault, "duplicate")


def test_ansible_unsafe_strings_are_normalized_to_exact_builtin_strings(
    tmp_path,
    vault,
):
    path = tmp_path / "private" / "unsafe.vault.yml"
    document = {
        AnsibleUnsafeText("schema_version"): 1,
        AnsibleUnsafeText("subject"): AnsibleUnsafeText("service01.example.test"),
        AnsibleUnsafeText("password"): AnsibleUnsafeText(SECRET_SENTINEL),
    }

    normalized = secret_plugin._normalize_document_mapping(document)
    created = _store(vault).ensure_exact(str(path), document)
    persisted = yaml.safe_load(vault.decrypt(path.read_bytes()))

    assert all(key.__class__ is str for key in normalized)
    assert all(value.__class__ in (int, str) for value in normalized.values())
    assert normalized["subject"].__class__ is str
    assert normalized["password"].__class__ is str
    assert persisted == {
        "schema_version": 1,
        "subject": "service01.example.test",
        "password": SECRET_SENTINEL,
    }
    assert created["created"] is True
    assert SECRET_SENTINEL not in repr(created)


def test_generic_cap_supports_large_exact_documents_on_create_read_and_race_paths(
    tmp_path,
    vault,
):
    path = tmp_path / "private" / "large.vault.yml"
    document = {
        "schema_version": 1,
        "luks_header_b64": "A" * ((1024 * 1024) + 8192),
    }
    store = _store(vault)

    created = store.ensure_exact(str(path), document)
    rerun = store.ensure_exact(str(path), document)
    race_digest = store._load_exact_race_winner(str(path), document)

    assert path.stat().st_size > 1024 * 1024
    assert created["created"] is True
    assert rerun["changed"] is False
    assert race_digest == created["ciphertext_sha256"]
    assert store._max_ciphertext_bytes == 128 * 1024 * 1024
    assert store._max_plaintext_bytes == 128 * 1024 * 1024
    with pytest.raises(AnsibleActionFail):
        secret_plugin._VaultSecretDocumentStore(vault).ensure_exact(str(path), document)


def test_generic_fixed_cap_rejects_oversize_ciphertext_before_path_creation(
    tmp_path,
    vault,
    monkeypatch,
):
    path = tmp_path / "absent" / "oversize.vault.yml"
    document = {"payload": "A" * (700 * 1024)}
    monkeypatch.setattr(plugin, "_MAX_DOCUMENT_BYTES", 1024 * 1024)
    store = plugin._new_document_store(vault)

    with pytest.raises(AnsibleActionFail):
        store.ensure_exact(str(path), document)

    assert store._max_ciphertext_bytes == 1024 * 1024
    assert not path.exists()
    assert not path.parent.exists()


def test_absent_check_mode_has_no_filesystem_serialization_or_vault_side_effects(
    tmp_path,
    vault,
    monkeypatch,
):
    path = tmp_path / "absent" / "service.vault.yml"
    store = _store(vault)

    def fail_if_called(*unused_args, **unused_kwargs):
        raise AssertionError("absent check mode must not serialize, encrypt, or publish")

    monkeypatch.setattr(store, "_serialize_document", fail_if_called)
    monkeypatch.setattr(store, "_exclusive_create", fail_if_called)
    monkeypatch.setattr(vault, "encrypt", fail_if_called)

    result = store.ensure_exact(str(path), _document(), check_mode=True)

    assert result == {
        "changed": True,
        "created": False,
        "exists": False,
        "path": str(path),
        "ciphertext_sha256": None,
    }
    assert not path.exists()
    assert not path.parent.exists()


def test_existing_document_is_type_exactly_validated_in_check_mode(tmp_path, vault):
    path = tmp_path / "service.vault.yml"
    _write_encrypted(path, vault, {"value": True})

    exact = _store(vault).ensure_exact(str(path), {"value": True}, check_mode=True)
    with pytest.raises(AnsibleActionFail):
        _store(vault).ensure_exact(str(path), {"value": 1}, check_mode=True)

    assert exact["changed"] is False
    assert exact["created"] is False
    assert exact["exists"] is True


def test_mismatched_existing_document_is_not_replaced_or_disclosed(tmp_path, vault):
    path = tmp_path / "service.vault.yml"
    requested_secret = "unit-test-only-requested-secret"
    existing_secret = "unit-test-only-existing-secret"
    _write_encrypted(path, vault, _document(existing_secret))
    original_ciphertext = path.read_bytes()

    with pytest.raises(AnsibleActionFail) as exception:
        _store(vault).ensure_exact(str(path), _document(requested_secret))

    assert path.read_bytes() == original_ciphertext
    assert requested_secret not in repr(exception.value)
    assert existing_secret not in repr(exception.value)


def test_duplicate_yaml_keys_in_existing_ciphertext_are_rejected(tmp_path, vault):
    path = tmp_path / "service.vault.yml"
    plaintext = "schema_version: 1\nsubject: first\nsubject: second\n"
    path.write_bytes(vault.encrypt(plaintext))
    path.chmod(0o600)

    with pytest.raises(AnsibleActionFail):
        _store(vault).ensure_exact(
            str(path),
            {"schema_version": 1, "subject": "second"},
        )


def test_malformed_decrypted_yaml_does_not_escape_through_exception_chaining(tmp_path, vault):
    path = tmp_path / "service.vault.yml"
    plaintext = "secret: {0}\nbroken: [\n".format(SECRET_SENTINEL)
    path.write_bytes(vault.encrypt(plaintext))
    path.chmod(0o600)

    with pytest.raises(AnsibleActionFail) as exception:
        _store(vault).ensure_exact(str(path), {"secret": SECRET_SENTINEL})

    assert SECRET_SENTINEL not in repr(exception.value)
    assert exception.value.__suppress_context__ is True


@pytest.mark.parametrize(
    "document",
    [
        {1: "non-string-key"},
        {"unsupported": ("tuple",)},
        {"unsupported": b"bytes"},
        {"number": math.nan},
        {"number": math.inf},
    ],
)
def test_non_json_safe_document_values_are_rejected(document, vault, tmp_path):
    with pytest.raises(AnsibleActionFail):
        _store(vault).ensure_exact(str(tmp_path / "service.vault.yml"), document)


def test_recursive_document_is_rejected(vault, tmp_path):
    document = {}
    document["recursive"] = document

    with pytest.raises(AnsibleActionFail):
        _store(vault).ensure_exact(str(tmp_path / "service.vault.yml"), document)


def test_concurrent_equal_writers_have_one_winner_and_no_staging_files(tmp_path, vault):
    path = tmp_path / "private" / "service.vault.yml"

    def persist(unused_index):
        return _store(vault).ensure_exact(str(path), _document())

    with concurrent.futures.ThreadPoolExecutor(max_workers=12) as executor:
        results = list(executor.map(persist, range(24)))

    assert sum(result["created"] for result in results) == 1
    assert sum(result["changed"] for result in results) == 1
    assert len({result["ciphertext_sha256"] for result in results}) == 1
    assert sorted(item.name for item in path.parent.iterdir()) == [path.name]


def test_concurrent_different_writers_accept_only_exact_race_winner(tmp_path, vault):
    path = tmp_path / "private" / "service.vault.yml"
    start = threading.Barrier(16)

    def persist(index):
        label = "alpha" if index % 2 == 0 else "beta"
        start.wait(timeout=5)
        try:
            result = _store(vault).ensure_exact(str(path), _document(label))
            return label, result, None
        except AnsibleActionFail as exc:
            return label, None, exc

    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as executor:
        outcomes = list(executor.map(persist, range(16)))

    persisted = yaml.safe_load(vault.decrypt(path.read_bytes()))
    winner = persisted["bootstrap"]["initial_root_token"]
    successes = [outcome for outcome in outcomes if outcome[1] is not None]
    failures = [outcome for outcome in outcomes if outcome[2] is not None]

    assert winner in ("alpha", "beta")
    assert sum(outcome[1]["created"] for outcome in successes) == 1
    assert all(outcome[0] == winner for outcome in successes)
    assert all(outcome[0] != winner for outcome in failures)
    assert sorted(item.name for item in path.parent.iterdir()) == [path.name]


def test_staging_file_and_result_never_contain_plaintext(tmp_path, vault):
    path = tmp_path / "private" / "service.vault.yml"
    staged = threading.Event()
    publish = threading.Event()

    class PausedPublicationStore(plugin._VaultDocumentStore):
        @staticmethod
        def _link_no_replace(parent_fd, temp_name, target_name):
            staged.set()
            assert publish.wait(timeout=5)
            plugin._VaultDocumentStore._link_no_replace(
                parent_fd,
                temp_name,
                target_name,
            )

    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(
            PausedPublicationStore(vault).ensure_exact,
            str(path),
            _document(),
        )
        assert staged.wait(timeout=5)
        staged_paths = list(path.parent.iterdir())
        assert len(staged_paths) == 1
        staged_ciphertext = staged_paths[0].read_bytes()
        assert staged_ciphertext.startswith(b"$ANSIBLE_VAULT;")
        assert SECRET_SENTINEL.encode("utf-8") not in staged_ciphertext
        publish.set()
        result = future.result(timeout=5)

    assert SECRET_SENTINEL not in repr(result)
    assert path.read_text(encoding="utf-8") not in repr(result)
    assert sorted(item.name for item in path.parent.iterdir()) == [path.name]


def test_argument_validation_rejects_password_relative_and_noncanonical_paths():
    with pytest.raises(AnsibleActionFail):
        plugin._normalize_arguments(
            {
                "path": "/secure/document.vault.yml",
                "document": {},
                "vault_password": "must-never-be-accepted",
            }
        )
    with pytest.raises(AnsibleActionFail):
        plugin._normalize_arguments(
            {
                "path": "/secure/document.vault.yml",
                "document": {},
                "max_ciphertext_bytes": 128 * 1024 * 1024,
            }
        )
    with pytest.raises(AnsibleActionFail):
        plugin._normalize_arguments({"path": "relative.vault.yml", "document": {}})
    with pytest.raises(AnsibleActionFail):
        plugin._normalize_arguments(
            {"path": "/secure/../document.vault.yml", "document": {}}
        )
    normalized = plugin._normalize_arguments(
        {
            "path": "/secure/document.vault.yml",
            "document": {},
            "vault_id": "production",
        }
    )
    assert normalized["vault_id"] == "production"


@pytest.mark.parametrize(
    "vault_id",
    (
        "",
        "ümlaut",
        "bad;identity",
        "bad identity",
        " leading",
        "trailing ",
        "bad\nidentity",
    ),
)
def test_invalid_vault_id_fails_before_path_creation(tmp_path, vault_id):
    path = tmp_path / "must-not-exist" / "document.vault.yml"

    with pytest.raises(AnsibleActionFail):
        plugin._normalize_arguments(
            {
                "path": str(path),
                "document": {},
                "vault_id": vault_id,
            }
        )

    assert not path.parent.exists()


def test_generated_ciphertext_is_validated_before_publication(
    tmp_path,
    vault,
    monkeypatch,
):
    path = tmp_path / "must-not-exist" / "document.vault.yml"
    monkeypatch.setattr(vault, "encrypt", lambda *args, **kwargs: b"not-vault-ciphertext")

    with pytest.raises(AnsibleActionFail):
        _store(vault).ensure_exact(str(path), _document())

    assert not path.parent.exists()


def test_task_no_log_is_required_and_failure_is_suppressed():
    task = SimpleNamespace(no_log=False)

    with pytest.raises(AnsibleActionFail) as exception:
        plugin._require_task_no_log(task)

    assert task.no_log is True
    assert SECRET_SENTINEL not in repr(exception.value)
    plugin._require_task_no_log(SimpleNamespace(no_log=True))
