import concurrent.futures
import stat

import pytest
import yaml

from ansible.errors import AnsibleActionFail
from ansible.parsing.vault import VaultLib, VaultSecret

from plugins.action import ansible_vault_secret_document as plugin


SUBJECT = "host01.example.test"
TEST_VAULT_PASSWORD = b"unit-test-only-vault-password"


@pytest.fixture
def vault():
    return VaultLib([("unit-test", VaultSecret(TEST_VAULT_PASSWORD))])


def _write_encrypted(path, vault, document):
    path.write_bytes(vault.encrypt(yaml.safe_dump(document, sort_keys=False)))
    path.chmod(0o600)


def _valid_document(subject=SUBJECT):
    return {
        "schema_version": 1,
        "subject": subject,
        "recovery_passphrase": "A" * 40,
    }


def _store(vault):
    return plugin._VaultSecretDocumentStore(vault)


def test_absent_document_is_created_once_and_rerun_is_unchanged(tmp_path, vault):
    path = tmp_path / "private" / "host.vault.yml"
    store = _store(vault)

    created = store.ensure(str(path), SUBJECT)
    rerun = store.ensure(str(path), SUBJECT)

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

    document = yaml.safe_load(vault.decrypt(path.read_bytes()))
    assert document["schema_version"] == 1
    assert document["subject"] == SUBJECT
    assert len(document["recovery_passphrase"]) == 64
    assert document["recovery_passphrase"].isalnum()
    assert document["recovery_passphrase"] not in repr(created)


def test_check_mode_absent_does_not_generate_encrypt_or_write(tmp_path, vault, monkeypatch):
    path = tmp_path / "missing" / "host.vault.yml"
    store = _store(vault)

    def fail_if_called(unused_sequence):
        raise AssertionError("random generation must not occur in check mode")

    monkeypatch.setattr(plugin.secrets, "choice", fail_if_called)
    result = store.ensure(str(path), SUBJECT, check_mode=True)

    assert result == {
        "changed": True,
        "created": False,
        "exists": False,
        "path": str(path),
        "ciphertext_sha256": None,
    }
    assert not path.exists()
    assert not path.parent.exists()


def test_check_mode_existing_document_is_validated(tmp_path, vault):
    path = tmp_path / "host.vault.yml"
    _write_encrypted(path, vault, _valid_document())

    result = _store(vault).ensure(str(path), SUBJECT, check_mode=True)

    assert result["changed"] is False
    assert result["created"] is False
    assert result["exists"] is True
    assert result["ciphertext_sha256"]


@pytest.mark.parametrize(
    "document",
    [
        {"schema_version": 1, "subject": SUBJECT},
        {
            "schema_version": 1,
            "subject": SUBJECT,
            "recovery_passphrase": "A" * 39,
        },
        {
            "schema_version": 1,
            "subject": SUBJECT,
            "recovery_passphrase": "A" * 40,
            "unexpected": True,
        },
        {
            "schema_version": 1,
            "subject": SUBJECT,
            "recovery_passphrase": ("A" * 40) + "\n",
        },
    ],
)
def test_incomplete_or_invalid_existing_document_is_rejected(tmp_path, vault, document):
    path = tmp_path / "host.vault.yml"
    _write_encrypted(path, vault, document)

    with pytest.raises(AnsibleActionFail):
        _store(vault).ensure(str(path), SUBJECT)


def test_corrupt_ciphertext_is_rejected(tmp_path, vault):
    path = tmp_path / "host.vault.yml"
    path.write_bytes(b"not Ansible Vault ciphertext")
    path.chmod(0o600)

    with pytest.raises(AnsibleActionFail):
        _store(vault).ensure(str(path), SUBJECT)


def test_wrong_subject_is_rejected_without_replacement(tmp_path, vault):
    path = tmp_path / "host.vault.yml"
    _write_encrypted(path, vault, _valid_document(subject="other.example.test"))
    original = path.read_bytes()

    with pytest.raises(AnsibleActionFail):
        _store(vault).ensure(str(path), SUBJECT)

    assert path.read_bytes() == original


def test_insecure_existing_file_mode_is_rejected(tmp_path, vault):
    path = tmp_path / "host.vault.yml"
    _write_encrypted(path, vault, _valid_document())
    path.chmod(0o640)

    with pytest.raises(AnsibleActionFail):
        _store(vault).ensure(str(path), SUBJECT)


def test_symlink_document_is_rejected(tmp_path, vault):
    target = tmp_path / "target.vault.yml"
    path = tmp_path / "host.vault.yml"
    _write_encrypted(target, vault, _valid_document())
    path.symlink_to(target)

    with pytest.raises(AnsibleActionFail):
        _store(vault).ensure(str(path), SUBJECT)


def test_concurrent_creation_has_one_winner_and_one_ciphertext(tmp_path, vault):
    path = tmp_path / "private" / "host.vault.yml"

    def create_document(unused_index):
        return _store(vault).ensure(str(path), SUBJECT)

    with concurrent.futures.ThreadPoolExecutor(max_workers=12) as executor:
        results = list(executor.map(create_document, range(24)))

    assert sum(result["created"] for result in results) == 1
    assert sum(result["changed"] for result in results) == 1
    assert all(result["exists"] for result in results)
    assert len({result["ciphertext_sha256"] for result in results}) == 1
    assert _store(vault).ensure(str(path), SUBJECT)["changed"] is False


def test_success_result_never_contains_secret_or_ciphertext(tmp_path, vault):
    path = tmp_path / "host.vault.yml"
    result = _store(vault).ensure(str(path), SUBJECT)
    document = yaml.safe_load(vault.decrypt(path.read_bytes()))

    assert set(result) == {
        "changed",
        "created",
        "exists",
        "path",
        "ciphertext_sha256",
    }
    assert document["recovery_passphrase"] not in repr(result)
    assert path.read_text(encoding="utf-8") not in repr(result)


def test_argument_validation_rejects_unsafe_values():
    with pytest.raises(AnsibleActionFail):
        plugin._normalize_arguments({"path": "/tmp/x", "subject": "host\nname"})
    with pytest.raises(AnsibleActionFail):
        plugin._normalize_arguments({"path": "/tmp/x", "subject": SUBJECT, "secret_length": 39})
    with pytest.raises(AnsibleActionFail):
        plugin._normalize_arguments(
            {"path": "/tmp/x", "subject": SUBJECT, "secret_field": "subject"}
        )
