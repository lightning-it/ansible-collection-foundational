# Copyright: (c) 2026, Lightning IT
# SPDX-License-Identifier: MIT
"""Closed ciphertext-only exchange between an EE and its native desktop client."""

import json
from datetime import datetime, timezone
import re

from .luks_header_custody import (
    MAX_PACKAGE,
    canonical,
    digest,
    unique_object,
    validate_package,
    validate_read_pins,
    verify_download,
)
from .luks_header_onepassword import (
    NativeCLI,
    onepassword_custody,
    onepassword_read_custody,
    validate_config,
)

MAX_HANDOFF = MAX_PACKAGE + 1024 * 1024
REQUEST_FIELDS = {
    "exchange",
    "schema_version",
    "operation",
    "provider_config",
    "package",
    "read_pins",
    "allow_create",
    "approval_authority",
    "approval",
}


def decode(raw):
    if not isinstance(raw, bytes) or not 0 < len(raw) <= MAX_HANDOFF:
        raise ValueError("Invalid native handoff size.")

    def reject_constant(value):
        raise ValueError("Non-JSON numeric constant.")

    return json.loads(
        raw, object_pairs_hook=unique_object, parse_constant=reject_constant
    )


def validate_request(request):
    if (
        not isinstance(request, dict)
        or set(request) != REQUEST_FIELDS
        or type(request["schema_version"]) is not int
        or request["schema_version"] != 1
        or request["operation"] not in ("plan", "apply", "verify", "read")
        or type(request["allow_create"]) is not bool
        or not isinstance(request["approval_authority"], dict)
        or not isinstance(request["approval"], dict)
    ):
        raise ValueError("The closed native handoff contract is required.")
    exchange = request["exchange"]
    if (
        not isinstance(exchange, dict)
        or set(exchange) != {"execution_id", "nonce", "issued_at", "expires_at"}
        or not isinstance(exchange["execution_id"], str)
        or not re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", exchange["execution_id"]
        )
        or not isinstance(exchange["nonce"], str)
        or not re.fullmatch(r"[0-9a-f]{64}", exchange["nonce"])
    ):
        raise ValueError("An exact execution and unique native exchange are required.")
    issued, expires = (
        datetime.strptime(exchange[key], "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
        for key in ("issued_at", "expires_at")
    )
    now = datetime.now(timezone.utc)
    if (
        not 0 < (expires - issued).total_seconds() <= 900
        or (issued - now).total_seconds() > 60
        or now >= expires
    ):
        raise ValueError("Native exchange is expired or outside its bounded validity.")
    validate_config(request["provider_config"])
    validate_read_pins(request["read_pins"])
    if request["operation"] == "read":
        if request["package"] != {}:
            raise ValueError("Independent read must not receive a local package.")
        config = request["provider_config"]
        if not config["item_id"] or config["item_version"] <= 0:
            raise ValueError("Independent read requires retained Document pins.")
    else:
        raw = validate_package(request["package"])
        verify_download(raw, request["read_pins"])
    if request["operation"] != "apply" and (
        request["allow_create"] or request["approval"] or request["approval_authority"]
    ):
        raise ValueError("Read-only handoffs must not carry creation authority.")
    if request["operation"] == "apply" and (
        not request["allow_create"]
        or not request["approval"]
        or not request["approval_authority"]
    ):
        raise ValueError("Native apply requires explicit one-time creation authority.")
    raw = canonical(request)
    if len(raw) > MAX_HANDOFF:
        raise ValueError("Native request exceeded its bound.")
    return digest(raw)


def execute_request(request, expected_sha256, cli_factory=NativeCLI):
    """Run only the existing pinned provider, never an arbitrary command or Ansible."""
    request_sha256 = validate_request(request)
    if request_sha256 != expected_sha256:
        raise ValueError("Native request differs from the EE plan.")
    config = request["provider_config"]
    cli = cli_factory(config)
    if request["operation"] == "read":
        result = onepassword_read_custody(cli, config, request["read_pins"])
    else:
        result = onepassword_custody(
            cli,
            config,
            request["package"],
            operation=request["operation"],
            allow_create=request["allow_create"],
            approval=request["approval"],
            authority=request["approval_authority"],
        )
    response = {"schema_version": 1, "request_sha256": request_sha256, "result": result}
    validate_response(request, response)
    return response


def validate_response(request, response):
    """Check a trusted native execution result; a file alone is not execution proof."""
    expected = validate_request(request)
    if (
        not isinstance(response, dict)
        or set(response) != {"schema_version", "request_sha256", "result"}
        or type(response["schema_version"]) is not int
        or response["schema_version"] != 1
        or response["request_sha256"] != expected
    ):
        raise ValueError("Native response does not match the exact request.")
    result = response["result"]
    fields = {"changed", "verified", "package_sha256", "item_id", "item_version"}
    fields.add("package" if request["operation"] == "read" else "planned")
    if (
        not isinstance(result, dict)
        or set(result) != fields
        or type(result["changed"]) is not bool
        or type(result["verified"]) is not bool
        or result["package_sha256"] != request["read_pins"]["package_sha256"]
        or request["operation"] != "apply"
        and result["changed"]
        or request["operation"] != "plan"
        and result["verified"] is not True
    ):
        raise ValueError("Invalid native provider result.")
    if request["operation"] == "read":
        verify_download(validate_package(result["package"]), request["read_pins"])
    elif type(result["planned"]) is not bool or result["planned"] == result["verified"]:
        raise ValueError("Invalid native planning result.")
    if result["verified"]:
        if (
            not isinstance(result["item_id"], str)
            or not re.fullmatch(r"[a-z0-9]{26}", result["item_id"])
            or type(result["item_version"]) is not int
            or result["item_version"] <= 0
        ):
            raise ValueError("Missing native Document identity.")
        config = request["provider_config"]
        if config["item_id"] and (
            result["item_id"] != config["item_id"]
            or result["item_version"] != config["item_version"]
        ):
            raise ValueError("Native result changed retained Document pins.")
    elif (
        result["item_id"] is not None
        or result["item_version"] is not None
        or result["changed"]
    ):
        raise ValueError("An absent native copy must not have a successful receipt.")
    return result
