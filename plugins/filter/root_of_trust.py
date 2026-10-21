"""Fail-closed filters for an infrastructure root-of-trust firewall plan."""

from __future__ import annotations

from ipaddress import IPv4Address, IPv4Network, ip_address, ip_network
from typing import Any

try:
    from ansible.errors import AnsibleFilterError
except ModuleNotFoundError:  # pragma: no cover - exercised without Ansible installed
    class AnsibleFilterError(Exception):
        """Fallback used only by direct Python validation tests."""


_RULE_KEYS = {
    "action",
    "dst_ip",
    "dst_port",
    "ip_version",
    "name",
    "protocol",
    "src_ip",
    "src_port",
    "tcp_flags",
}
_MANAGEMENT_KEYS = {
    "action",
    "dst_ip",
    "dst_port",
    "ip_version",
    "name",
    "protocol",
    "src_ip",
}
_TCP_RESPONSE_KEYS = {
    "action",
    "dst_ip",
    "dst_port",
    "ip_version",
    "name",
    "protocol",
    "tcp_flags",
}
_DNS_RESPONSE_KEYS = {
    "action",
    "dst_ip",
    "dst_port",
    "ip_version",
    "name",
    "protocol",
    "src_ip",
    "src_port",
}
_NTP_RESPONSE_KEYS = {
    "action",
    "dst_ip",
    "dst_port",
    "ip_version",
    "name",
    "protocol",
    "src_port",
}
_ICMP_KEYS = {"action", "ip_version", "name", "protocol"}
_WILDCARD_NETWORKS = {"0.0.0.0/0", "::/0"}


def _reject(reason: str) -> None:
    raise AnsibleFilterError(f"Unsafe root-of-trust firewall plan: {reason}.")


def _require_mapping(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        _reject(f"{label} must be a mapping")
    return value


def _require_exact_keys(value: dict[str, Any], keys: set[str], label: str) -> None:
    if set(value) != keys:
        _reject(f"{label} has an unexpected field set")


def _require_ipv4_address(value: Any, label: str) -> str:
    if not isinstance(value, str):
        _reject(f"{label} must be a canonical IPv4 address")
    try:
        address = ip_address(value)
    except ValueError:
        _reject(f"{label} must be a canonical IPv4 address")
    if not isinstance(address, IPv4Address) or str(address) != value:
        _reject(f"{label} must be a canonical IPv4 address")
    return value


def _require_ipv4_host_cidr(value: Any, label: str) -> str:
    if not isinstance(value, str):
        _reject(f"{label} must be a canonical IPv4 /32")
    try:
        network = ip_network(value, strict=True)
    except ValueError:
        _reject(f"{label} must be a canonical IPv4 /32")
    if (
        not isinstance(network, IPv4Network)
        or network.prefixlen != 32
        or str(network) != value
    ):
        _reject(f"{label} must be a canonical IPv4 /32")
    return value


def _port(value: Any) -> str:
    return str(value)


def _validate_output(rules: Any, phase: str) -> None:
    if not isinstance(rules, list) or len(rules) != 1:
        _reject(f"{phase} output must contain exactly one explicit rule")
    rule = _require_mapping(rules[0], f"{phase} output rule")
    _require_exact_keys(rule, {"action", "name"}, f"{phase} output rule")
    if rule.get("action") != "accept":
        _reject(f"{phase} output rule must explicitly accept output")
    if not isinstance(rule.get("name"), str) or not rule["name"].strip():
        _reject(f"{phase} output rule requires a non-empty name")


def _validate_common_rule(rule: Any, phase: str, index: int) -> dict[str, Any]:
    label = f"{phase} input rule {index + 1}"
    rule = _require_mapping(rule, label)
    if not set(rule).issubset(_RULE_KEYS):
        _reject(f"{label} contains unsupported fields")
    if any(value is None for value in rule.values()):
        _reject(f"{label} contains null fields")
    if any(isinstance(value, str) and not value.strip() for value in rule.values()):
        _reject(f"{label} contains empty fields")
    if any(str(value) in _WILDCARD_NETWORKS for value in rule.values()):
        _reject(f"{label} contains an unrestricted network")
    if rule.get("ip_version") != "ipv4":
        _reject(f"{label} must be IPv4; IPv6 input is not permitted")
    if rule.get("action") != "accept":
        _reject(f"{label} must be an explicit accept rule")
    if not isinstance(rule.get("name"), str) or not rule["name"].strip():
        _reject(f"{label} requires a non-empty name")
    return rule


def _semantic_signature(rule: dict[str, Any]) -> tuple[tuple[str, str], ...]:
    return tuple(sorted((key, str(value)) for key, value in rule.items() if key != "name"))


def _classify_input_rules(
    rules: Any,
    *,
    phase: str,
    target_ipv4: str,
    controller_ipv4_cidr: str,
) -> dict[str, Any]:
    if not isinstance(rules, list):
        _reject(f"{phase} input must be a list")

    management_ports: list[int] = []
    tcp_responses: list[dict[str, Any]] = []
    dns_sources: list[str] = []
    ntp_responses: list[dict[str, Any]] = []
    icmp_rules: list[dict[str, Any]] = []
    tang_sources: list[str] = []
    base_signatures: list[tuple[tuple[str, str], ...]] = []

    for index, candidate in enumerate(rules):
        rule = _validate_common_rule(candidate, phase, index)
        keys = set(rule)
        protocol = rule.get("protocol")
        destination_port = _port(rule.get("dst_port", ""))

        if keys == _MANAGEMENT_KEYS and protocol == "tcp":
            if rule["dst_ip"] != target_ipv4:
                _reject(f"{phase} TCP rule targets an unexpected IPv4 address")
            source = _require_ipv4_host_cidr(rule["src_ip"], f"{phase} TCP source")
            if destination_port in {"22", "1905", "2222"}:
                if source != controller_ipv4_cidr:
                    _reject(f"{phase} management source is not the approved controller")
                management_ports.append(int(destination_port))
                base_signatures.append(_semantic_signature(rule))
                continue
            if destination_port == "80":
                if phase != "hardened":
                    _reject("bootstrap input must not expose Tang")
                if source == controller_ipv4_cidr:
                    _reject("Tang source must not reuse the controller source")
                tang_sources.append(source)
                continue

        if keys == _TCP_RESPONSE_KEYS and protocol == "tcp":
            if (
                rule["dst_ip"] != target_ipv4
                or destination_port != "32768-65535"
                or str(rule["tcp_flags"]).lower() != "ack"
            ):
                _reject(f"{phase} TCP response rule has an unsafe shape")
            tcp_responses.append(rule)
            base_signatures.append(_semantic_signature(rule))
            continue

        if keys == _DNS_RESPONSE_KEYS and protocol == "udp":
            if (
                rule["dst_ip"] != target_ipv4
                or destination_port != "32768-65535"
                or _port(rule["src_port"]) != "53"
            ):
                _reject(f"{phase} DNS response rule has an unsafe shape")
            dns_sources.append(
                _require_ipv4_address(rule["src_ip"], f"{phase} DNS source")
            )
            base_signatures.append(_semantic_signature(rule))
            continue

        if keys == _NTP_RESPONSE_KEYS and protocol == "udp":
            if (
                rule["dst_ip"] != target_ipv4
                or destination_port != "32768-65535"
                or _port(rule["src_port"]) != "123"
            ):
                _reject(f"{phase} NTP response rule has an unsafe shape")
            ntp_responses.append(rule)
            base_signatures.append(_semantic_signature(rule))
            continue

        if keys == _ICMP_KEYS and protocol == "icmp":
            icmp_rules.append(rule)
            base_signatures.append(_semantic_signature(rule))
            continue

        _reject(f"{phase} input rule {index + 1} is not an approved semantic rule")

    expected_management = [22, 1905, 2222] if phase == "bootstrap" else [1905, 2222]
    if sorted(management_ports) != expected_management:
        _reject(f"{phase} management ports do not match the exact contract")
    if len(tcp_responses) != 1:
        _reject(f"{phase} requires exactly one TCP ACK response rule")
    if len(dns_sources) != 2 or len(set(dns_sources)) != 2:
        _reject(f"{phase} requires exactly two unique DNS response sources")
    if len(ntp_responses) != 1:
        _reject(f"{phase} requires exactly one NTP response rule")
    if len(icmp_rules) != 1:
        _reject(f"{phase} requires exactly one explicit wildcard ICMP rule")
    if phase == "bootstrap" and tang_sources:
        _reject("bootstrap input must not contain Tang sources")
    if phase == "hardened":
        if len(tang_sources) != 3 or len(set(tang_sources)) != 3:
            _reject("hardened input requires exactly three unique Tang /32 sources")
        forbidden_hosts = {controller_ipv4_cidr, f"{target_ipv4}/32"}
        if set(tang_sources) & forbidden_hosts:
            _reject("Tang sources must be separate consumer hosts")

    return {
        "management_ports": sorted(management_ports),
        "tang_sources": sorted(tang_sources),
        "base_signatures": sorted(base_signatures),
        "rule_count": len(rules),
    }


def root_of_trust_firewall_validate(
    firewall: Any,
    target_ipv4: Any,
    controller_ipv4_cidr: Any,
) -> dict[str, Any]:
    """Validate and summarize the exact fail-closed G2 firewall contract."""

    firewall = _require_mapping(firewall, "firewall")
    _require_exact_keys(
        firewall,
        {"allowlist_hos", "bootstrap", "enabled", "filter_ipv6", "hardened", "port"},
        "firewall",
    )
    target_ipv4 = _require_ipv4_address(target_ipv4, "target IPv4")
    controller_ipv4_cidr = _require_ipv4_host_cidr(
        controller_ipv4_cidr, "controller source"
    )
    if controller_ipv4_cidr == f"{target_ipv4}/32":
        _reject("controller source must be separate from the target")
    if firewall["enabled"] is not True:
        _reject("provider firewall must be enabled")
    if firewall["port"] != "main":
        _reject("provider firewall must protect the main interface")
    if firewall["filter_ipv6"] is not True:
        _reject("provider IPv6 filtering must be enabled")
    if firewall["allowlist_hos"] is not True:
        _reject("Hetzner services allowlisting must be enabled")

    phases: dict[str, dict[str, Any]] = {}
    for phase in ("bootstrap", "hardened"):
        declaration = _require_mapping(firewall[phase], f"{phase} phase")
        _require_exact_keys(declaration, {"input", "output"}, f"{phase} phase")
        _validate_output(declaration["output"], phase)
        phases[phase] = _classify_input_rules(
            declaration["input"],
            phase=phase,
            target_ipv4=target_ipv4,
            controller_ipv4_cidr=controller_ipv4_cidr,
        )

    if phases["bootstrap"]["rule_count"] != 8:
        _reject("bootstrap input must contain exactly eight rules")
    if phases["hardened"]["rule_count"] != 10:
        _reject("hardened input must contain exactly ten rules")

    bootstrap_without_ssh22 = [
        signature
        for signature in phases["bootstrap"]["base_signatures"]
        if ("dst_port", "22") not in signature
    ]
    if bootstrap_without_ssh22 != phases["hardened"]["base_signatures"]:
        _reject("hardened base policy must equal bootstrap with TCP 22 removed")

    return {
        "bootstrap_rule_count": phases["bootstrap"]["rule_count"],
        "controller_ipv4_cidr": controller_ipv4_cidr,
        "hardened_rule_count": phases["hardened"]["rule_count"],
        "output_rule_count": 1,
        "tang_source_count": len(phases["hardened"]["tang_sources"]),
        "validated": True,
    }


class FilterModule:
    """Expose the collection's root-of-trust filters to Ansible."""

    def filters(self) -> dict[str, Any]:
        return {"root_of_trust_firewall_validate": root_of_trust_firewall_validate}
