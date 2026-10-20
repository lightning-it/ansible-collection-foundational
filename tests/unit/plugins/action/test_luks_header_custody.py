"""Provider transactions, exact readback, signature binding and failure boundaries."""

import copy
import hashlib
import json
import os
from pathlib import Path
import platform
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace

from ansible.errors import AnsibleActionFail
from plugins.module_utils import luks_header_custody as custody
from plugins.module_utils import luks_header_onepassword as native
from tests.unit.plugins.action import test_luks_header_escrow_read as reader_tests
from plugins.action import luks_header_custody_prepare as prepare_action
from plugins.action import luks_header_custody_package as package_action
from plugins.action import luks_header_escrow_read as reader_action
from tests.fixtures import luks_header_custody as https_fixture
from tests.unit.plugins.action.onepassword_approval_support import (
    build_authority,
    build_approval,
)


def package():
    ciphertext = "$ANSIBLE_VAULT;1.1;AES256\n" + "a" * 1024 + "\n"
    return {
        "manifest": {
            "schema_version": 1,
            "subject": "host01.example.test",
            "source_machine_id": "a" * 32,
            "luks_uuid": "11111111-2222-4333-8444-555555555555",
            "luks_header_sha256_raw": "b" * 64,
            "luks_header_raw_size_bytes": 16,
            "ciphertext_sha256": hashlib.sha256(ciphertext.encode()).hexdigest(),
            "owner": "infrastructure-team",
            "retention": "approved-retention-record",
            "key_retrieval_reference": "independent-key-object-reference",
        },
        "ciphertext": ciphertext,
    }


def config():
    return {
        "cli_path": "/usr/local/bin/op",
        "cli_sha256": "0" * 64,
        "cli_version": "2.38.1",
        "account_id": "A" * 26,
        "account_sign_in_address": "example.1password.com",
        "authorized_user_uuids": ["U" * 26],
        "vault_id": "v" * 26,
        "item_title": "host01 encrypted header",
        "item_id": "",
        "item_version": 0,
        "executor_uid": 501,
        "executor_node": "native.example.test",
    }


class FakeVault:
    def __init__(self):
        self.rows = {}
        self.writes = []
        self.fail_at = None

    def read(self, mount, path):
        return copy.deepcopy(self.rows.get(path))

    def create(self, mount, path, data):
        if path in self.rows or path == self.fail_at:
            raise ValueError("CAS rejected")
        self.rows[path] = {"data": copy.deepcopy(data), "version": 1}
        self.writes.append(path)


class FakeNative:
    def __init__(self, cfg, payload):
        self.cfg = cfg
        self.payload = payload
        self.tag_sha256 = custody.digest(payload)
        self.exists = False
        self.created = 0
        self.version = 1
        self.duplicate = False
        self.account = cfg["account_id"]
        self.user = "U" * 26
        self.category = "DOCUMENT"
        self.id = "i" * 26

    def run(self, argv, payload=b"", limit=1024 * 1024):
        if argv == ["--version"]:
            return b"2.38.1\n"
        if argv[:2] == ["document", "get"]:
            return self.payload
        raise AssertionError("unexpected command")

    def metadata(self, argv):
        if argv[0] == "whoami":
            return {
                "account_uuid": self.account,
                "user_uuid": self.user,
                "url": "https://example.1password.com",
            }
        if argv[:2] == ["vault", "get"]:
            return {"id": self.cfg["vault_id"]}
        if argv[:2] == ["item", "list"]:
            row = {
                "id": self.id,
                "title": self.cfg["item_title"],
                "version": self.version,
                "category": self.category,
                "tags": ["luks-header-custody", self.tag_sha256],
            }
            return [row] * (2 if self.duplicate else 1) if self.exists else []
        raise AssertionError("unexpected metadata")

    def metadata_create(self, argv, payload):
        self.created += 1
        self.exists = True
        self.payload = payload
        self.tag_sha256 = custody.digest(payload)
        return {"id": self.id}


class CustodyTests(unittest.TestCase):
    def test_both_providers_retrieve_from_only_independent_receipts(self):
        p, cfg = package(), config()
        raw = custody.validate_package(p)
        pins = {
            "package_sha256": custody.digest(raw),
            **{
                key: p["manifest"][key]
                for key in ("subject", "source_machine_id", "luks_uuid")
            },
        }
        vault = FakeVault()
        custody.vault_custody(vault, "kv", "headers", p, "apply")
        self.assertEqual(
            custody.vault_read_custody(vault, "kv", "headers", pins)["package"], p
        )
        cli = FakeNative(cfg, raw)
        cli.exists = True
        cfg.update(item_id=cli.id, item_version=cli.version)
        self.assertEqual(native.onepassword_read_custody(cli, cfg, pins)["package"], p)
        for key, value in [
            ("package_sha256", "0" * 64),
            ("subject", "wrong.example.test"),
            ("source_machine_id", "c" * 32),
        ]:
            wrong = dict(pins, **{key: value})
            with self.subTest(key=key), self.assertRaises(ValueError):
                native.onepassword_read_custody(cli, cfg, wrong)
            with self.subTest(key=key), self.assertRaises(ValueError):
                custody.vault_read_custody(vault, "kv", "headers", wrong)
        with self.assertRaises(ValueError):
            native.onepassword_read_custody(cli, config(), pins)

    def test_authenticated_package_export_and_password_free_import(self):
        fixture = reader_tests.HeaderReaderTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        action = prepare_action.ActionModule.__new__(prepare_action.ActionModule)
        args = dict(
            fixture.arguments,
            source_machine_id="a" * 32,
            owner="fixture-custodian",
            retention="fixture-lifetime",
            key_retrieval_reference="independent-fixture-reference",
        )
        action._task = SimpleNamespace(no_log=True, args=args, check_mode=False)
        action._loader = SimpleNamespace(_vault=fixture.vault)
        with patch.object(reader_action.ActionBase, "run", return_value={}):
            prepared = action.run()
        self.assertNotIn("synthetic-only-header-bytes", repr(prepared))
        dest = str(Path(fixture.temporary.name) / "handoff.json")
        params = {
            "operation": "export",
            "path": dest,
            "package": prepared["package"],
            "package_sha256": prepared["package_sha256"],
            "subject": args["subject"],
            "source_machine_id": args["source_machine_id"],
            "luks_uuid": args["luks_uuid"],
        }
        handoff = package_action.ActionModule.__new__(package_action.ActionModule)
        handoff._task = SimpleNamespace(no_log=True, args=params, check_mode=False)
        with patch.object(package_action.ActionBase, "run", return_value={}):
            self.assertTrue(handoff.run()["verified"])
            self.assertFalse(handoff.run()["changed"])
            handoff._task.args = {k: v for k, v in params.items() if k != "package"}
            handoff._task.args["operation"] = "read"
            self.assertEqual(handoff.run()["package"], prepared["package"])
            handoff._task.args["subject"] = "wrong.example.test"
            with self.assertRaises(AnsibleActionFail):
                handoff.run()
            handoff._task.args = dict(
                params, path=dest + ".wrong", subject="wrong.example.test"
            )
            with self.assertRaises(AnsibleActionFail):
                handoff.run()
            self.assertFalse(Path(dest + ".wrong").exists())
            handoff._task.args = dict(
                params, operation="materialize", path=dest + ".vault"
            )
            materialized = handoff.run()
            self.assertTrue(materialized["verified"])
            self.assertEqual(
                Path(dest + ".vault").read_bytes(), fixture.path.read_bytes()
            )
            self.assertFalse(handoff.run()["changed"])

    def test_real_https_vault_cas_readback_authorization_and_redirect(self):
        with tempfile.TemporaryDirectory(dir=os.environ["HOME"]) as directory:
            root = Path(directory)
            (root / "vault-password").write_bytes(os.urandom(48).hex().encode())
            https_fixture.initialize(root)
            self.addCleanup(lambda: https_fixture.stop(root))
            endpoint = json.loads((root / "endpoint.json").read_text())
            metadata = json.loads((root / "fixture.json").read_text())
            auth = dict(
                url=endpoint["url"],
                ca_cert=str(root / "ca.pem"),
                timeout=10,
                auth_method="token",
                token=metadata["token"],
            )
            client = custody.VaultHTTP(auth)
            p = package()
            result = custody.vault_custody(client, "fixture", "headers", p, "apply")
            self.assertTrue(result["verified"])
            self.assertFalse(
                custody.vault_custody(client, "fixture", "headers", p, "apply")[
                    "changed"
                ]
            )
            with self.assertRaises(ValueError):
                client.create(
                    "fixture", result["manifest_path"], {"attempt": "overwrite"}
                )
            with self.assertRaises(ValueError):
                custody.vault_custody(
                    custody.VaultHTTP(dict(auth, token="wrong")),
                    "fixture",
                    "headers",
                    p,
                )
            with self.assertRaises(ValueError):
                client.request("GET", "redirect")
            with self.assertRaises(ValueError):
                custody.VaultHTTP(
                    dict(auth, url=auth["url"].replace("https:", "http:"))
                )
            with self.assertRaises(ValueError):
                custody.VaultHTTP(dict(auth, auth_method="environment"))
            https_fixture.stop(root)

    def test_vault_deleted_history_is_not_an_absent_object(self):
        client = custody.VaultHTTP.__new__(custody.VaultHTTP)
        client.request = lambda method, path, **kw: (
            None if "/data/" in path else {"data": {"current_version": 2}}
        )
        with self.assertRaises(ValueError):
            client.read("kv", "headers")

    def test_package_rejects_wrong_schema_payload_and_plaintext(self):
        for key, value in [
            ("schema_version", True),
            ("source_machine_id", "wrong"),
            ("luks_uuid", "wrong"),
            ("ciphertext_sha256", "0" * 64),
            ("owner", ""),
            ("luks_header_raw_size_bytes", True),
        ]:
            p = package()
            p["manifest"][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                custody.validate_package(p)
        p = package()
        p["ciphertext"] = "unencrypted raw header"
        with self.assertRaises(ValueError):
            custody.validate_package(p)
        with self.assertRaises(ValueError):
            custody.decode_package(
                b'{"a":1,"a":2}', custody.validate_package(package())
            )

    def test_vault_create_readback_repeat_and_verify(self):
        client = FakeVault()
        p = package()
        plan = custody.vault_custody(client, "kv", "headers", p, "plan")
        self.assertFalse(plan["verified"])
        self.assertEqual(client.writes, [])
        result = custody.vault_custody(client, "kv", "headers", p, "apply")
        self.assertTrue(result["verified"])
        self.assertTrue(result["changed"])
        self.assertTrue(client.writes[-1].endswith("/manifest"))
        count = len(client.writes)
        repeated = custody.vault_custody(client, "kv", "headers", p, "apply")
        self.assertFalse(repeated["changed"])
        self.assertEqual(count, len(client.writes))
        self.assertTrue(custody.vault_custody(client, "kv", "headers", p)["verified"])

    def test_vault_partial_failure_does_not_publish_manifest_and_can_reconcile(self):
        client = FakeVault()
        p = package()
        root = "headers/" + custody.digest(custody.validate_package(p))
        client.fail_at = root + "/manifest"
        with self.assertRaises(ValueError):
            custody.vault_custody(client, "kv", "headers", p, "apply")
        self.assertNotIn(client.fail_at, client.rows)
        self.assertEqual(len(client.writes), 1)
        client.fail_at = None
        self.assertTrue(
            custody.vault_custody(client, "kv", "headers", p, "apply")["verified"]
        )

    def test_vault_conflicts_missing_copy_checkmode_and_traversal(self):
        client = FakeVault()
        p = package()
        with self.assertRaises(ValueError):
            custody.vault_custody(client, "kv", "headers", p)
        self.assertFalse(
            custody.vault_custody(client, "kv", "headers", p, "apply", True)["verified"]
        )
        self.assertFalse(client.writes)
        result = custody.vault_custody(client, "kv", "headers", p, "apply")
        client.rows[result["manifest_path"]]["data"]["package_sha256"] = "0" * 64
        before = copy.deepcopy(client.rows)
        with self.assertRaises(ValueError):
            custody.vault_custody(client, "kv", "headers", p, "apply")
        self.assertEqual(before, client.rows)
        for path in ("../header", "a//b", "/header", "a/./b"):
            with self.assertRaises(ValueError):
                custody.vault_custody(client, "kv", path, p, "apply")

    def test_vault_multichunk_full_reassembly(self):
        p = package()
        p["ciphertext"] += "a" * custody.CHUNK_SIZE * 2
        p["manifest"]["ciphertext_sha256"] = custody.digest(p["ciphertext"].encode())
        client = FakeVault()
        self.assertTrue(
            custody.vault_custody(client, "kv", "headers", p, "apply")["verified"]
        )
        self.assertGreater(len(client.writes), 2)
        self.assertNotIn(
            "ciphertext", repr(custody.vault_custody(client, "kv", "headers", p))
        )

    def test_native_missing_readonly_and_checkmode_never_create(self):
        cfg = config()
        cli = FakeNative(cfg, custody.validate_package(package()))
        self.assertFalse(
            native.onepassword_custody(cli, cfg, package(), "plan")["verified"]
        )
        self.assertFalse(
            native.onepassword_custody(cli, cfg, package(), "apply", True)["verified"]
        )
        with self.assertRaises(ValueError):
            native.onepassword_custody(cli, cfg, package())
        with self.assertRaises(ValueError):
            native.onepassword_custody(cli, cfg, package(), "apply")
        self.assertEqual(cli.created, 0)

    def test_native_signed_create_readback_repeat_and_replay(self):
        with tempfile.TemporaryDirectory(dir=os.environ["HOME"]) as directory:
            root = Path(directory)
            cfg, p = config(), package()
            raw = custody.validate_package(p)
            cli = FakeNative(cfg, raw)
            authority = build_authority(root)
            approval, replay, _ = build_approval(
                root,
                authority,
                "create-onepassword-header-document",
                p["manifest"]["subject"],
                {
                    "config": cfg,
                    "package_sha256": custody.digest(raw),
                    "allow_create": True,
                },
            )
            # The fixture binds the same canonical replay directory as the authority.
            authority["replay_directory"] = str(replay)
            from tests.unit.plugins.action.onepassword_approval_support import (
                sign_approval,
            )

            approval = sign_approval(
                approval,
                authority,
                "create-onepassword-header-document",
                p["manifest"]["subject"],
                {
                    "config": cfg,
                    "package_sha256": custody.digest(raw),
                    "allow_create": True,
                },
            )
            result = native.onepassword_custody(
                cli,
                cfg,
                p,
                "apply",
                allow_create=True,
                approval=approval,
                authority=authority,
            )
            self.assertTrue(result["verified"])
            self.assertEqual(cli.created, 1)
            self.assertFalse(
                native.onepassword_custody(cli, cfg, p, "apply")["changed"]
            )
            cli.exists = False
            with self.assertRaises(AnsibleActionFail):
                native.onepassword_custody(
                    cli,
                    cfg,
                    p,
                    "apply",
                    allow_create=True,
                    approval=approval,
                    authority=authority,
                )
            self.assertEqual(cli.created, 1)

    def test_native_identity_duplicate_revision_and_payload_rejected(self):
        cfg = config()
        raw = custody.validate_package(package())
        for field, value in [
            ("account", "X" * 26),
            ("user", "X" * 26),
            ("category", "PASSWORD"),
            ("duplicate", True),
        ]:
            cli = FakeNative(cfg, raw)
            cli.exists = True
            setattr(cli, field, value)
            with self.subTest(field=field), self.assertRaises(ValueError):
                native.onepassword_custody(
                    cli, cfg, package(), "apply", allow_create=True
                )
            self.assertEqual(cli.created, 0)
        cli = FakeNative(cfg, raw)
        cli.exists = True
        pinned = dict(cfg, item_id=cli.id, item_version=2)
        with self.assertRaises(ValueError):
            native.onepassword_custody(cli, pinned, package())
        cli.payload = b"wrong header"
        with self.assertRaises(ValueError):
            native.onepassword_custody(cli, cfg, package())

    def test_native_executor_and_token_fallback_rejected(self):
        cfg = config()
        with self.assertRaises(ValueError):
            native.NativeCLI(cfg)
        cfg.update(executor_uid=os.geteuid(), executor_node=platform.node())
        with patch.dict(os.environ, {"OP_SERVICE_ACCOUNT_TOKEN": "synthetic-only"}):
            with self.assertRaises(ValueError):
                native.NativeCLI(cfg)
        for key, value in [
            ("executor_uid", True),
            ("item_version", True),
            ("cli_sha256", "wrong"),
        ]:
            broken = config()
            broken[key] = value
            with self.assertRaises(ValueError):
                native.validate_config(broken)

    def test_native_streaming_actual_subprocess_and_output_bound(self):
        with tempfile.TemporaryDirectory(dir=os.environ["HOME"]) as directory:
            binary = Path(directory) / "fixture-cli"
            binary.write_text(
                "#!/usr/bin/python3\nimport sys\nsys.stdout.buffer.write(sys.stdin.buffer.read())\n"
            )
            binary.chmod(0o700)
            cfg = config()
            cfg.update(
                cli_path=str(binary),
                cli_sha256=custody.digest(binary.read_bytes()),
                executor_uid=os.geteuid(),
                executor_node=platform.node(),
            )
            cli = native.NativeCLI(cfg)
            self.assertEqual(
                cli.run([], payload=b"ciphertext-only"), b"ciphertext-only"
            )
            with self.assertRaises(ValueError):
                cli.run([], payload=b"x" * 2048, limit=1024)
            binary.write_text("#!/usr/bin/python3\nraise SystemExit(0)\n")
            with self.assertRaises(AnsibleActionFail):
                cli.run([])


if __name__ == "__main__":
    unittest.main()
