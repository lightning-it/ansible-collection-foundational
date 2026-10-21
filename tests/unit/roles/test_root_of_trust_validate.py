"""Static safety tests for the root-of-trust role integration scenario."""

from pathlib import Path
import unittest

import yaml


REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
VERIFY = REPOSITORY_ROOT / "molecule" / "root-of-trust-validate-basic" / "verify.yml"
G2_ASSERT = REPOSITORY_ROOT / "roles" / "root_of_trust_validate" / "tasks" / "g2_assert.yml"


class RootOfTrustRoleSafetyTests(unittest.TestCase):
    """Keep rejected fixtures from being masked by their own test failures."""

    def test_negative_blocks_have_external_assertions(self):
        tasks = yaml.safe_load(VERIFY.read_text(encoding="utf-8"))[0]["tasks"]
        task_texts = [str(task) for task in tasks]
        rejected_facts: list[str] = []
        for index, task in enumerate(tasks):
            if "block" not in task or "rescue" not in task:
                continue
            self.assertNotIn(
                "ansible.builtin.fail",
                str(task["block"]),
                f"rescued negative block {index} contains a false-positive fail task",
            )
            rescue_text = str(task["rescue"])
            rejected_facts.extend(
                name
                for name in (
                    "root_of_trust_validate_partial_selection_rejected",
                    "root_of_trust_validate_wildcard_source_rejected",
                    "root_of_trust_validate_ipv6_source_rejected",
                    "root_of_trust_validate_disabled_firewall_rejected",
                    "root_of_trust_validate_in_process_rejected",
                    "root_of_trust_validate_cancelled_rejected",
                    "root_of_trust_validate_identity_ambiguity_rejected",
                )
                if name in rescue_text
            )

        self.assertEqual(len(rejected_facts), 7)
        for rejected_fact in rejected_facts:
            self.assertTrue(
                any(
                    "ansible.builtin.assert" in task_text
                    and rejected_fact in task_text
                    for task_text in task_texts
                ),
                f"{rejected_fact} has no assertion outside its rescued block",
            )

    def test_g2_uses_only_the_fail_closed_python_firewall_validator(self):
        text = G2_ASSERT.read_text(encoding="utf-8")
        self.assertIn("lit.foundational.root_of_trust_firewall_validate", text)
        self.assertNotIn("g2_validate_rule.yml", text)
        self.assertNotIn("g2_validate_protected_port.yml", text)
        self.assertIn("root_of_trust_validate_target.status == 'ready'", text)
        self.assertIn("not (root_of_trust_validate_target.cancelled | bool)", text)


if __name__ == "__main__":
    unittest.main()
