"""Static safety tests for exact-byte LUKS recovery validation."""

from pathlib import Path
import unittest

import yaml


REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
LUKS_PASSPHRASE_TASKS = (
    REPOSITORY_ROOT
    / "roles"
    / "hetzner_rescue_validate"
    / "tasks"
    / "luks_passphrase.yml"
)


class HetznerRescueValidateLuksTests(unittest.TestCase):
    """Prevent terminal input semantics from corrupting the retained secret."""

    def test_passphrase_proof_uses_exact_stdin_bytes(self):
        tasks = yaml.safe_load(LUKS_PASSPHRASE_TASKS.read_text(encoding="utf-8"))
        proof = next(
            task
            for task in tasks
            if task.get("name")
            == "Prove the retained secret unlocks the installed LUKS root"
        )
        command = proof["ansible.builtin.command"]
        argv = command["argv"]

        self.assertEqual(argv.count("--key-file"), 1)
        self.assertEqual(argv[argv.index("--key-file") + 1], "-")
        self.assertIs(command["stdin_add_newline"], False)
        self.assertEqual(
            command["stdin"],
            "{{ hetzner_rescue_validate_luks_passphrase }}",
        )
        self.assertIs(proof["no_log"], True)


if __name__ == "__main__":
    unittest.main()
