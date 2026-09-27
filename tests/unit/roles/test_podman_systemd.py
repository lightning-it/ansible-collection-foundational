"""Contract tests for the native Podman kube Quadlet controller."""

from pathlib import Path
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[3]
ROLE = ROOT / "roles" / "podman_systemd"


class PodmanSystemdContractTests(unittest.TestCase):
    def test_networks_default_to_no_override(self) -> None:
        defaults = yaml.safe_load(
            (ROLE / "defaults" / "main.yml").read_text(encoding="utf-8")
        )

        self.assertEqual(defaults["podman_systemd_networks"], [])

    def test_network_options_are_native_quadlet_entries(self) -> None:
        template = (ROLE / "templates" / "kube.quadlet.j2").read_text(
            encoding="utf-8"
        )

        self.assertIn("{% for network in podman_systemd_networks %}", template)
        self.assertIn("Network={{ network }}", template)
        self.assertNotIn("PodmanArgs=", template)
        self.assertNotIn("podman kube play", template)

    def test_network_values_are_bounded_to_single_line_strings(self) -> None:
        tasks = yaml.safe_load(
            (ROLE / "tasks" / "assert.yml").read_text(encoding="utf-8")
        )
        assertions = tasks[0]["ansible.builtin.assert"]["that"]
        rendered = "\n".join(assertions)

        self.assertIn("podman_systemd_networks is sequence", assertions)
        self.assertIn("podman_systemd_networks is not string", assertions)
        self.assertIn("select('string')", rendered)
        self.assertIn("select('search', '[\\r\\n]')", rendered)

    def test_changed_quadlet_restarts_a_running_service(self) -> None:
        tasks = (ROLE / "tasks" / "main.yml").read_text(encoding="utf-8")

        self.assertIn("podman_systemd_quadlet_render.changed", tasks)
        self.assertIn("podman_systemd_action in ['present', 'started']", tasks)
        self.assertIn("'restarted'", tasks)


if __name__ == "__main__":
    unittest.main()
