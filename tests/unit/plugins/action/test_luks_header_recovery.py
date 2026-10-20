"""Real regular-file cryptsetup tests; no production device or credentials."""

import base64
import copy
import hashlib
import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[4]
SPEC = importlib.util.spec_from_file_location(
    "header_recovery", ROOT / "plugins/module_utils/luks_header_recovery.py"
)
RECOVERY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RECOVERY)
SUBJECT = "host01.example.test"
UUID = "11111111-2222-4333-8444-555555555555"
PASSPHRASE = "synthetic-test-passphrase-" * 3


def envelope(raw=b"not-a-real-header"):
    return dict(
        schema_version=1,
        subject=SUBJECT,
        luks_format="luks2",
        luks_uuid=UUID,
        luks_header_b64=base64.b64encode(raw).decode(),
        luks_header_raw_size_bytes=len(raw),
        luks_header_sha256_raw=hashlib.sha256(raw).hexdigest(),
    )


class HeaderValidationTests(unittest.TestCase):
    def test_wrong_envelopes_rejected_before_writes(self):
        cases = [
            ("subject", "wrong.example.test"),
            ("luks_uuid", "22222222-2222-4333-8444-555555555555"),
            ("schema_version", True),
            ("luks_format", "luks1"),
            ("luks_header_raw_size_bytes", True),
            ("luks_header_raw_size_bytes", RECOVERY.MAX_HEADER + 1),
            ("luks_header_sha256_raw", "0" * 64),
            ("luks_header_b64", "@" * 24),
        ]
        with patch.object(
            RECOVERY.tempfile,
            "TemporaryDirectory",
            side_effect=AssertionError("unexpected write"),
        ):
            for field, value in cases:
                with self.subTest(field=field):
                    document = envelope()
                    document[field] = value
                    with self.assertRaises(ValueError):
                        RECOVERY.restore_drill(
                            document, SUBJECT, UUID, "a" * 32, "b" * 32, PASSPHRASE
                        )

    def test_witness_and_non_tmpfs_fail_before_writes(self):
        with self.assertRaises(ValueError):
            RECOVERY.witness_identity("a" * 32, "a" * 32)
        with patch.object(RECOVERY.Path, "read_text", return_value="c" * 32):
            with self.assertRaises(ValueError):
                RECOVERY.witness_identity("a" * 32, "b" * 32)
        with tempfile.TemporaryDirectory(dir=os.environ["HOME"]) as directory:
            with patch.object(
                RECOVERY.Path, "read_text", return_value="1 1 0:1 / / rw - ext4 disk rw"
            ):
                with self.assertRaises(ValueError):
                    RECOVERY.protected_tmpfs(directory)


class RealHeaderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture = tempfile.TemporaryDirectory(prefix="ltn292-source-", dir="/run")
        source, header = (
            Path(cls.fixture.name) / "source.img",
            Path(cls.fixture.name) / "header.luks",
        )
        with source.open("wb") as stream:
            stream.truncate(32 * 1024 * 1024)
        subprocess.run(
            [
                "/usr/sbin/cryptsetup",
                "luksFormat",
                "--type",
                "luks2",
                "--batch-mode",
                "--pbkdf",
                "pbkdf2",
                "--pbkdf-force-iterations",
                "1000",
                "--uuid",
                UUID,
                "--key-file=-",
                str(source),
            ],
            input=PASSPHRASE.encode(),
            capture_output=True,
            check=True,
        )
        subprocess.run(
            [
                "/usr/sbin/cryptsetup",
                "luksHeaderBackup",
                str(source),
                "--header-backup-file",
                str(header),
            ],
            capture_output=True,
            check=True,
        )
        cls.document = envelope(header.read_bytes())

    @classmethod
    def tearDownClass(cls):
        cls.fixture.cleanup()

    def identities(self):
        actual = Path("/etc/machine-id").read_text().strip()
        return ("a" if actual != "a" * 32 else "b") * 32, actual

    def test_real_restore_correct_wrong_key_idempotence_and_cleanup(self):
        before = set(Path("/run").glob("lit-luks-restore-*"))
        source_id, actual_id = self.identities()
        for unused in range(2):
            result = RECOVERY.restore_drill(
                self.document, SUBJECT, UUID, source_id, actual_id, PASSPHRASE
            )
            self.assertTrue(
                result["verified"]
                and result["wrong_key_rejected"]
                and result["scratch_removed"]
            )
            self.assertFalse(result["changed"])
        self.assertEqual(set(Path("/run").glob("lit-luks-restore-*")), before)

    def test_bad_key_and_malformed_real_header_clean_up(self):
        before = set(Path("/run").glob("lit-luks-restore-*"))
        source_id, actual_id = self.identities()
        with self.assertRaises(RuntimeError):
            RECOVERY.restore_drill(
                self.document, SUBJECT, UUID, source_id, actual_id, "wrong-" * 12
            )
        broken = copy.deepcopy(self.document)
        broken.update(envelope(b"\x00" * broken["luks_header_raw_size_bytes"]))
        with self.assertRaises(RuntimeError):
            RECOVERY.restore_drill(
                broken, SUBJECT, UUID, source_id, actual_id, PASSPHRASE
            )
        self.assertEqual(set(Path("/run").glob("lit-luks-restore-*")), before)

    def test_check_mode_does_not_restore(self):
        source_id, actual_id = self.identities()
        with patch.object(
            RECOVERY, "cryptsetup", side_effect=AssertionError("unexpected restore")
        ):
            result = RECOVERY.restore_drill(
                self.document,
                SUBJECT,
                UUID,
                source_id,
                actual_id,
                PASSPHRASE,
                check_mode=True,
            )
        self.assertEqual(
            result, {"changed": False, "verified": False, "check_mode": True}
        )


if __name__ == "__main__":
    unittest.main()
