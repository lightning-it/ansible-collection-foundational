"""Real Ansible orchestration with isolated provider fixtures and a forbidden SSH transport."""

import json
import os
from pathlib import Path
import subprocess
import shutil
import tempfile
import unittest
import yaml

from plugins.module_utils import luks_header_custody as custody
from tests.fixtures import luks_header_custody as https_fixture
from tests.unit.plugins.action.test_luks_header_native_handoff import request, execute


class NativeRoleIntegrationTests(unittest.TestCase):
    def test_real_role_without_desktop_ssh_and_unchanged_repeat(self):
        with tempfile.TemporaryDirectory(dir=os.environ["HOME"]) as directory:
            root = Path(directory)
            root.chmod(0o700)
            (root / "vault-password").write_bytes(os.urandom(48).hex().encode())
            https_fixture.initialize(root)
            self.addCleanup(lambda: https_fixture.stop(root))
            endpoint = json.loads((root / "endpoint.json").read_text())
            fixture = json.loads((root / "fixture.json").read_text())
            req = request()
            req["provider_config"]["item_title"] = (
                "host01 encrypted header " + req["read_pins"]["package_sha256"]
            )
            for name, value in (
                ("package", req["package"]),
                ("request", req),
                ("response", execute(req)),
            ):
                path = root / (name + ".json")
                path.write_bytes(custody.canonical(value))
                path.chmod(0o600)
            source = Path(__file__).resolve().parents[4]
            collection_root = root / "collections/ansible_collections/lit"
            collection_root.mkdir(parents=True)
            shutil.copytree(
                source,
                collection_root / "foundational",
                ignore=shutil.ignore_patterns(
                    ".git", ".ansible", ".cache", "dist", "collections", "*.tar.gz"
                ),
            )
            connection = root / "connections"
            connection.mkdir(mode=0o700)
            (connection / "canary.py").write_text(
                "from ansible.plugins.connection import ConnectionBase\n"
                "class Connection(ConnectionBase):\n"
                " transport = 'canary'\n"
                " def _connect(self): raise RuntimeError('FORBIDDEN_MANAGED_CONNECTION')\n"
                " def exec_command(self, *a, **k): raise RuntimeError('FORBIDDEN_MANAGED_CONNECTION')\n"
                " def put_file(self, *a, **k): raise RuntimeError('FORBIDDEN_MANAGED_CONNECTION')\n"
                " def fetch_file(self, *a, **k): raise RuntimeError('FORBIDDEN_MANAGED_CONNECTION')\n"
                " def close(self): pass\n"
            )
            variables = {
                "luks_header_custody_cac_enabled": True,
                "luks_header_custody_cac_operation": "apply",
                "luks_header_custody_cac_allow_create": True,
                "luks_header_custody_cac_package_path": str(root / "package.json"),
                "luks_header_custody_cac_package_sha256": req["read_pins"][
                    "package_sha256"
                ],
                **{
                    "luks_header_custody_cac_" + key: req["package"]["manifest"][key]
                    for key in (
                        "subject",
                        "source_machine_id",
                        "luks_uuid",
                        "owner",
                        "retention",
                        "key_retrieval_reference",
                    )
                },
                "luks_header_custody_cac_onepassword_enabled": True,
                "luks_header_custody_cac_onepassword_transport": "native_handoff",
                "luks_header_custody_cac_onepassword": req["provider_config"],
                "luks_header_custody_cac_onepassword_title_prefix": "host01 encrypted header",
                "luks_header_custody_cac_onepassword_native_request_path": str(
                    root / "request.json"
                ),
                "luks_header_custody_cac_onepassword_native_response_path": str(
                    root / "response.json"
                ),
                "luks_header_custody_cac_onepassword_native_exchange": req["exchange"],
                "luks_header_custody_cac_vault": {
                    "mount": "fixture",
                    "prefix": "native-handoff",
                    "auth": {
                        "url": endpoint["url"],
                        "ca_cert": str(root / "ca.pem"),
                        "timeout": 10,
                        "auth_method": "token",
                        "token": fixture["token"],
                    },
                },
            }
            play = [
                {
                    "hosts": "source",
                    "gather_facts": False,
                    "vars": variables,
                    "roles": ["lit.foundational.luks_header_custody_cac"],
                    "post_tasks": [
                        {
                            "name": "Require both verified copies",
                            "ansible.builtin.assert": {
                                "that": [
                                    "luks_header_custody_cac_result.verified is sameas true",
                                    "luks_header_custody_cac_result.onepassword.verified is sameas true",
                                    "luks_header_custody_cac_result.vault.verified is sameas true",
                                ],
                                "quiet": True,
                            },
                        }
                    ],
                }
            ]
            (root / "play.yml").write_text(yaml.safe_dump(play))
            (root / "play.yml").chmod(0o600)
            (root / "inventory").write_text("source ansible_connection=canary\n")
            env = dict(
                os.environ,
                ANSIBLE_COLLECTIONS_PATH=str(root / "collections"),
                ANSIBLE_CONNECTION_PLUGINS=str(connection),
            )
            # The fixture uses its own HTTP token, not the Molecule scenario's
            # independently encrypted header or its Ansible Vault password.
            env.pop("ANSIBLE_VAULT_PASSWORD_FILE", None)
            for repeat in (False, True):
                completed = subprocess.run(
                    [
                        "ansible-playbook",
                        "-i",
                        str(root / "inventory"),
                        str(root / "play.yml"),
                    ],
                    env=env,
                    capture_output=True,
                    timeout=90,
                )
                combined = completed.stdout + completed.stderr
                self.assertTrue(
                    fixture["token"].encode() not in combined,
                    "Fixture credential leaked.",
                )
                self.assertTrue(
                    b"FORBIDDEN_MANAGED_CONNECTION" not in combined,
                    "Managed connection attempted.",
                )
                # Store only metadata/task statuses on failure, never fixture vars.
                if completed.returncode:
                    tasks = [
                        line.decode(errors="replace")
                        for line in completed.stdout.splitlines()
                        if line.startswith(
                            (b"TASK [", b"PLAY RECAP", b"source ", b"localhost ")
                        )
                    ]
                    raise AssertionError("Native role failed: " + repr(tasks))
                if repeat:
                    self.assertIn(b"changed=0", completed.stdout)


if __name__ == "__main__":
    unittest.main()
