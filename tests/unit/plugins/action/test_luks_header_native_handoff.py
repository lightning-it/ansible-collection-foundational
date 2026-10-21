"""Native desktop exchange: source pins, readback, rejection and EE file custody."""

import copy
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from ansible.errors import AnsibleActionFail
from plugins.action import luks_header_native_handoff as action
from plugins.module_utils import luks_header_native_handoff as handoff
from plugins.module_utils import luks_header_custody as custody
from tests.unit.plugins.action.test_luks_header_custody import (
    config,
    package,
    FakeNative,
)


def request(operation="verify"):
    p = package()
    cfg = config()
    cfg.update(item_id="i" * 26, item_version=1)
    return {
        "schema_version": 1,
        "exchange": {
            "execution_id": "native-custody-test",
            "nonce": "b" * 64,
            "issued_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=10)).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            ),
        },
        "operation": operation,
        "provider_config": cfg,
        "package": {} if operation == "read" else p,
        "read_pins": {
            "package_sha256": custody.digest(custody.validate_package(p)),
            **{
                key: p["manifest"][key]
                for key in ("subject", "source_machine_id", "luks_uuid")
            },
        },
        "allow_create": False,
        "approval_authority": {},
        "approval": {},
    }


def execute(req):
    cli = FakeNative(req["provider_config"], custody.validate_package(package()))
    cli.exists = True
    result = handoff.execute_request(
        req, handoff.validate_request(req), lambda cfg: cli
    )
    assert cli.created == 0
    return result


class NativeExchangeTests(unittest.TestCase):
    def test_non_json_numeric_constants_are_rejected(self):
        with self.assertRaises(ValueError):
            handoff.decode(b'{"approval":{"invalid":NaN}}')

    @unittest.skipIf(
        os.geteuid() == 0, "The desktop provider intentionally rejects UID 0."
    )
    def test_isolated_native_process_with_pinned_cli_and_no_host_ansible(self):
        with tempfile.TemporaryDirectory(dir=os.environ["HOME"]) as directory:
            root = Path(directory)
            root.chmod(0o700)
            req = request("read")
            cfg = req["provider_config"]
            raw = custody.validate_package(package())
            binary = root / "op-fixture"
            rows = [
                {
                    "id": "i" * 26,
                    "version": 1,
                    "title": cfg["item_title"],
                    "category": "DOCUMENT",
                    "tags": ["luks-header-custody", custody.digest(raw)],
                }
            ]
            binary.write_text(
                "#!" + sys.executable + "\nimport json, sys\na=sys.argv[1:]\n"
                "if a == ['--version']: print('2.38.1')\n"
                "elif a[0] == 'whoami': print(json.dumps("
                + repr(
                    {
                        "account_uuid": cfg["account_id"],
                        "user_uuid": "U" * 26,
                        "url": "https://example.1password.com",
                    }
                )
                + "))\n"
                "elif a[:2] == ['vault','get']: print(json.dumps("
                + repr({"id": cfg["vault_id"]})
                + "))\n"
                "elif a[:2] == ['item','list']: print(json.dumps(" + repr(rows) + "))\n"
                "elif a[:2] == ['document','get']: sys.stdout.buffer.write("
                + repr(raw)
                + ")\n"
                "else: raise SystemExit(99)\n"
            )
            binary.chmod(0o700)
            cfg.update(
                cli_path=str(binary),
                cli_sha256=custody.digest(binary.read_bytes()),
                executor_uid=os.geteuid(),
                executor_node=platform.node(),
            )
            poison = root / "poison/ansible"
            poison.mkdir(parents=True)
            (poison / "__init__.py").write_text(
                "raise RuntimeError('UNTRUSTED_HOST_ANSIBLE')\n"
            )
            script = (
                Path(__file__).resolve().parents[4]
                / "scripts/luks-header-native-custody.py"
            )
            completed = subprocess.run(
                [
                    sys.executable,
                    "-I",
                    "-S",
                    str(script),
                    "--request-sha256",
                    handoff.validate_request(req),
                ],
                input=custody.canonical(req),
                capture_output=True,
                timeout=10,
                env=dict(os.environ, PYTHONPATH=str(poison.parent)),
            )
            self.assertEqual(completed.returncode, 0, "Isolated native adapter failed.")
            response = handoff.decode(completed.stdout)
            self.assertTrue(handoff.validate_response(req, response)["verified"])
            self.assertEqual(response["result"]["package"], package())

    def test_expired_exchange_and_cross_execution_response_are_rejected(self):
        req = request()
        response = execute(req)
        req["exchange"]["nonce"] = "c" * 64
        with self.assertRaises(ValueError):
            handoff.validate_response(req, response)
        req["exchange"]["issued_at"] = "2020-01-01T00:00:00Z"
        req["exchange"]["expires_at"] = "2020-01-01T00:10:00Z"
        with self.assertRaises(ValueError):
            handoff.validate_request(req)

    def test_existing_document_readback_repeat_is_unchanged(self):
        req = request()
        first = execute(req)
        self.assertTrue(first["result"]["verified"])
        self.assertFalse(first["result"]["changed"])
        self.assertEqual(first, execute(req))

    def test_independent_read_needs_no_local_header_or_vault(self):
        req = request("read")
        result = execute(req)
        self.assertEqual(req["package"], {})
        self.assertEqual(result["result"]["package"], package())
        self.assertEqual(handoff.validate_response(req, result)["item_id"], "i" * 26)

    def test_missing_document_plan_does_not_claim_verification(self):
        req = request("plan")
        req["provider_config"].update(item_id="", item_version=0)
        cli = FakeNative(req["provider_config"], custody.validate_package(package()))
        result = handoff.execute_request(
            req, handoff.validate_request(req), lambda cfg: cli
        )
        self.assertFalse(result["result"]["verified"])
        self.assertTrue(result["result"]["planned"])
        self.assertEqual(cli.created, 0)

    def test_wrong_request_digest_stops_before_native_provider(self):
        with self.assertRaises(ValueError), patch.object(handoff, "NativeCLI") as cli:
            handoff.execute_request(request(), "0" * 64, cli)
        cli.assert_not_called()

    def test_closed_request_and_identity_drift_stop_before_provider(self):
        cases = []
        req = request()
        req["vault_auth"] = {"token": "SECRET_CANARY"}
        cases.append(req)
        req = request()
        req["read_pins"]["source_machine_id"] = "b" * 32
        cases.append(req)
        req = request()
        req["package"]["ciphertext"] += "a"
        cases.append(req)
        req = request("read")
        req["package"] = package()
        cases.append(req)
        req = request("read")
        req["provider_config"].update(item_id="", item_version=0)
        cases.append(req)
        req = request()
        req["allow_create"] = True
        cases.append(req)
        req = request("apply")
        cases.append(req)
        for req in cases:
            with self.subTest(req=req["operation"]), self.assertRaises(ValueError):
                handoff.validate_request(req)

    def test_response_digest_document_version_and_ciphertext_are_bound(self):
        req = request("read")
        response = execute(req)
        cases = []
        bad = copy.deepcopy(response)
        bad["request_sha256"] = "0" * 64
        cases.append(bad)
        bad = copy.deepcopy(response)
        bad["result"]["item_version"] = 2
        cases.append(bad)
        bad = copy.deepcopy(response)
        bad["result"]["package"]["ciphertext"] += "a"
        cases.append(bad)
        bad = copy.deepcopy(response)
        bad["result"]["changed"] = True
        cases.append(bad)
        bad = copy.deepcopy(response)
        bad["result"]["verified"] = False
        cases.append(bad)
        for bad in cases:
            with self.assertRaises(ValueError):
                handoff.validate_response(req, bad)

    def test_duplicate_json_and_oversize_are_rejected(self):
        with self.assertRaises(ValueError):
            handoff.decode(b'{"schema_version":1,"schema_version":1}')
        with patch.object(handoff, "MAX_HANDOFF", 4), self.assertRaises(ValueError):
            handoff.decode(b"12345")

    def test_native_cli_fails_closed_without_isolation_or_on_invalid_input(self):
        script = (
            Path(__file__).resolve().parents[4]
            / "scripts/luks-header-native-custody.py"
        )
        for isolated in (False, True):
            completed = subprocess.run(
                [
                    sys.executable,
                    *(["-I", "-S"] if isolated else []),
                    str(script),
                    "--request-sha256",
                    "0" * 64,
                ],
                input=b'{"SECRET_CANARY":"DO_NOT_PRINT"}',
                capture_output=True,
                timeout=5,
            )
            self.assertEqual(completed.returncode, 1)
            self.assertEqual(completed.stdout, b"")
            self.assertNotIn(b"CANARY", completed.stderr)
            self.assertNotIn(b"Traceback", completed.stderr)


class NativeExchangeActionTests(unittest.TestCase):
    def test_mutable_parent_and_relative_paths_fail_before_export(self):
        self.root.chmod(0o777)
        with self.assertRaises(AnsibleActionFail):
            self.run_action()
        self.root.chmod(0o700)
        self.args["response_path"] = "relative-response.json"
        with self.assertRaises(AnsibleActionFail):
            self.run_action()
        self.assertFalse((self.root / "request.json").exists())

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(dir=os.environ["HOME"])
        self.root = Path(self.directory.name)
        self.root.chmod(0o700)
        self.req = request()
        self.args = {
            "operation": "prepare",
            "request": self.req,
            "request_path": str(self.root / "request.json"),
            "response_path": str(self.root / "response.json"),
        }

    def tearDown(self):
        self.directory.cleanup()

    def run_action(self, check=False, no_log=True):
        instance = action.ActionModule.__new__(action.ActionModule)
        instance._task = SimpleNamespace(
            args=self.args, no_log=no_log, check_mode=check
        )
        with patch("ansible.plugins.action.ActionBase.run", return_value={}):
            return instance.run(task_vars={})

    def test_prepare_consume_and_second_prepare_are_idempotent(self):
        self.assertTrue(self.run_action()["changed"])
        self.assertFalse(self.run_action()["changed"])
        self.assertEqual((self.root / "request.json").stat().st_mode & 0o777, 0o600)
        response = self.root / "response.json"
        response.write_bytes(custody.canonical(execute(self.req)))
        response.chmod(0o600)
        self.args["operation"] = "consume"
        result = self.run_action()
        self.assertTrue(result["verified"])
        self.assertFalse(result["changed"])

    def test_missing_response_check_mode_and_no_log_fail_closed(self):
        self.assertFalse((self.root / "request.json").exists())
        self.run_action(check=True)
        self.assertFalse((self.root / "request.json").exists())
        self.run_action()
        self.args["operation"] = "consume"
        for check, no_log in ((False, True), (True, True), (False, False)):
            with self.assertRaises(AnsibleActionFail):
                self.run_action(check, no_log)

    def test_existing_request_drift_and_unsafe_response_fail(self):
        self.run_action()
        self.args["request"] = copy.deepcopy(self.req)
        self.args["request"]["operation"] = "plan"
        with self.assertRaises(AnsibleActionFail):
            self.run_action()
        self.args["request"] = self.req
        self.args["operation"] = "consume"
        response = self.root / "response.json"
        response.write_text(json.dumps(execute(self.req)))
        response.chmod(0o666)
        with self.assertRaises(AnsibleActionFail):
            self.run_action()


if __name__ == "__main__":
    unittest.main()
