"""Unit tests for the fail-closed root-of-trust firewall validator."""

from copy import deepcopy
from pathlib import Path
import unittest

import yaml

from plugins.filter.root_of_trust import (
    AnsibleFilterError,
    root_of_trust_firewall_validate,
)


REPOSITORY_ROOT = Path(__file__).resolve().parents[4]
RESOURCES = (
    REPOSITORY_ROOT / "molecule" / "root-of-trust-validate-basic" / "resources"
)


def load_fixture():
    """Load the same policy that the role integration scenario consumes."""
    return yaml.safe_load(RESOURCES.read_text(encoding="utf-8"))


class RootOfTrustFirewallTests(unittest.TestCase):
    """Reject every policy shape outside the reviewed stateless allowlist."""

    def setUp(self):
        fixture = load_fixture()
        self.firewall = fixture["root_of_trust_validate_firewall"]
        self.target = fixture["root_of_trust_validate_target"]["public_ipv4"]
        self.controller = fixture["root_of_trust_validate_controller_ipv4_cidr"]

    def assert_rejected(self, firewall=None, controller=None):
        with self.assertRaises(AnsibleFilterError):
            root_of_trust_firewall_validate(
                self.firewall if firewall is None else firewall,
                self.target,
                self.controller if controller is None else controller,
            )

    def test_accepts_the_exact_active_policy(self):
        result = root_of_trust_firewall_validate(
            self.firewall, self.target, self.controller
        )
        self.assertEqual(
            result,
            {
                "bootstrap_rule_count": 8,
                "controller_ipv4_cidr": "198.51.100.7/32",
                "hardened_rule_count": 10,
                "output_rule_count": 1,
                "tang_source_count": 3,
                "validated": True,
            },
        )

    def test_rejects_disabled_provider_firewall(self):
        firewall = deepcopy(self.firewall)
        firewall["enabled"] = False
        self.assert_rejected(firewall)

    def test_rejects_disabled_ipv6_filter(self):
        firewall = deepcopy(self.firewall)
        firewall["filter_ipv6"] = False
        self.assert_rejected(firewall)

    def test_rejects_non_allow_all_output(self):
        firewall = deepcopy(self.firewall)
        firewall["hardened"]["output"][0]["action"] = "discard"
        self.assert_rejected(firewall)

    def test_rejects_broad_controller_source(self):
        self.assert_rejected(controller="128.0.0.0/1")

    def test_rejects_wrong_management_source(self):
        firewall = deepcopy(self.firewall)
        firewall["bootstrap"]["input"][0]["src_ip"] = "198.51.100.8/32"
        self.assert_rejected(firewall)

    def test_rejects_ipv6_input(self):
        firewall = deepcopy(self.firewall)
        firewall["bootstrap"]["input"][0]["ip_version"] = "ipv6"
        firewall["bootstrap"]["input"][0]["src_ip"] = "2001:db8::1/128"
        self.assert_rejected(firewall)

    def test_rejects_ipv6_wildcard(self):
        firewall = deepcopy(self.firewall)
        firewall["bootstrap"]["input"][0]["src_ip"] = "::/0"
        self.assert_rejected(firewall)

    def test_rejects_arbitrary_wildcard_tcp_accept(self):
        firewall = deepcopy(self.firewall)
        firewall["bootstrap"]["input"][6] = {
            "action": "accept",
            "ip_version": "ipv4",
            "name": "Unsafe wildcard TCP",
            "protocol": "tcp",
        }
        self.assert_rejected(firewall)

    def test_rejects_non_host_tang_source(self):
        firewall = deepcopy(self.firewall)
        firewall["hardened"]["input"][7]["src_ip"] = "192.0.2.0/24"
        self.assert_rejected(firewall)

    def test_rejects_hardened_ssh_22(self):
        firewall = deepcopy(self.firewall)
        firewall["hardened"]["input"][9]["src_ip"] = self.controller
        firewall["hardened"]["input"][9]["dst_port"] = "22"
        self.assert_rejected(firewall)

    def test_rejects_base_policy_drift_between_phases(self):
        firewall = deepcopy(self.firewall)
        firewall["hardened"]["input"][5]["src_port"] = "124"
        self.assert_rejected(firewall)

    def test_rejects_extra_rule_fields(self):
        firewall = deepcopy(self.firewall)
        firewall["bootstrap"]["input"][0]["state"] = "enabled"
        self.assert_rejected(firewall)


if __name__ == "__main__":
    unittest.main()
