"""Exercise real Vault encryption and the protected header reader."""

import base64
import hashlib
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from ansible.errors import AnsibleActionFail
from ansible.parsing.vault import VaultLib, VaultSecret
import yaml
from plugins.action import luks_header_escrow_read as READER


class HeaderReaderTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(dir=os.environ["HOME"])
        self.addCleanup(self.temporary.cleanup)
        self.path = Path(self.temporary.name) / "header.vault.yml"
        self.vault = VaultLib([("fixture", VaultSecret(b"synthetic-only-vault-key"))])
        raw = b"synthetic-only-header-bytes"
        self.document = dict(
            schema_version=1,
            subject="host01.example.test",
            luks_format="luks2",
            luks_uuid="11111111-2222-4333-8444-555555555555",
            luks_header_b64=base64.b64encode(raw).decode(),
            luks_header_raw_size_bytes=len(raw),
            luks_header_sha256_raw=hashlib.sha256(raw).hexdigest(),
        )
        self.path.write_bytes(self.vault.encrypt(yaml.safe_dump(self.document)))
        self.path.chmod(0o600)
        self.arguments = dict(
            path=str(self.path),
            subject=self.document["subject"],
            luks_uuid=self.document["luks_uuid"],
            ciphertext_sha256=hashlib.sha256(self.path.read_bytes()).hexdigest(),
        )

    def invoke(self, no_log=True, arguments=None, vault=None):
        action = READER.ActionModule.__new__(READER.ActionModule)
        action._task = SimpleNamespace(no_log=no_log, args=arguments or self.arguments)
        action._loader = SimpleNamespace(_vault=vault or self.vault)
        with patch.object(READER.ActionBase, "run", return_value={}):
            return action.run()

    def test_exact_encrypted_roundtrip_without_plaintext_files(self):
        before = set(Path(self.temporary.name).iterdir())
        result = self.invoke()
        self.assertEqual(result["document"], self.document)
        self.assertTrue(result["_ansible_no_log"])
        self.assertFalse(result["changed"])
        self.assertEqual(set(Path(self.temporary.name).iterdir()), before)

    def test_requires_no_log_before_read(self):
        with patch.object(
            READER._VaultDocumentStore,
            "_read_existing",
            side_effect=AssertionError("unexpected read"),
        ):
            with self.assertRaises(AnsibleActionFail):
                self.invoke(no_log=False)

    def test_wrong_identity_checksum_key_and_permissions_rejected(self):
        for field, value in [
            ("subject", "wrong.example.test"),
            ("luks_uuid", "22222222-2222-4333-8444-555555555555"),
            ("ciphertext_sha256", "0" * 64),
        ]:
            with self.subTest(field=field):
                with self.assertRaises(AnsibleActionFail):
                    self.invoke(arguments=dict(self.arguments, **{field: value}))
        wrong = VaultLib([("fixture", VaultSecret(b"synthetic-wrong-key"))])
        with self.assertRaises(AnsibleActionFail):
            self.invoke(vault=wrong)
        self.path.chmod(0o644)
        with self.assertRaises(AnsibleActionFail):
            self.invoke()

    def test_symlinks_and_hardlinks_rejected(self):
        link = Path(self.temporary.name) / "link"
        link.symlink_to(self.path)
        with self.assertRaises(AnsibleActionFail):
            self.invoke(arguments=dict(self.arguments, path=str(link)))
        os.link(self.path, Path(self.temporary.name) / "hardlink")
        with self.assertRaises(AnsibleActionFail):
            self.invoke()


if __name__ == "__main__":
    unittest.main()
