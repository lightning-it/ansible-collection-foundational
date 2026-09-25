import hashlib
import inspect
import os
from pathlib import Path
import socket
import stat
import sys
from types import SimpleNamespace

import pytest

from ansible.errors import AnsibleActionFail

from plugins.action import onepassword_ssh_secret_stdin as plugin
from tests.unit.plugins.action.onepassword_approval_support import (
    build_approval,
    build_authority,
)


ACCOUNT_ID = "A" * 26
VAULT_ID = "v" * 26
PASSWORD_ITEM_ID = "p" * 26
PASSWORD_ITEM_VERSION = 1
SSH_ITEM_ID = "i" * 26
SSH_ITEM_VERSION = 1
USER_UUID = "U" * 26
SUBJECT = "host01.example.test"
SECRET = b"S" * 64
PUBLIC_KEY = (
    "ssh-ed25519 "
    "AAAAC3NzaC1lZDI1NTE5AAAAIFNTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NTU1NT test"
)
HOST_PUBLIC_KEY = PUBLIC_KEY.split()[0] + " " + PUBLIC_KEY.split()[1]
SSH_FINGERPRINT = plugin._public_identity(PUBLIC_KEY)[1]
HOST_FINGERPRINT = plugin._public_identity(HOST_PUBLIC_KEY)[1]


def _digest(path, fallback):
    return hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else fallback


def _known_hosts_identity(arguments):
    path = os.path.realpath(arguments["known_hosts_path"])
    selected_line = Path(path).read_text(encoding="ascii").strip()
    _host_token, key_type, encoded_key = selected_line.split()[:3]
    fingerprint = plugin._public_identity("{0} {1}".format(key_type, encoded_key))[1]
    return {
        "path": path,
        "sha256": arguments["known_hosts_sha256"],
        "host_token": selected_line.split()[0],
        "key_type": key_type,
        "fingerprint": fingerprint,
        "selected_line_sha256": hashlib.sha256(
            (selected_line + "\n").encode("ascii")
        ).hexdigest(),
        "selected_line": selected_line,
    }


def _approval(tmp_path, arguments, authority):
    binding = {
        "onepassword": {
            "cli_path": arguments["cli_path"],
            "cli_sha256": arguments["cli_sha256"],
            "cli_version": arguments["cli_version"],
            "account_id": arguments["account_id"],
            "account_sign_in_address": arguments["account_sign_in_address"],
            "authorized_user_uuids": arguments["authorized_user_uuids"],
            "vault_id": arguments["vault_id"],
        },
        "password_item": {
            "operation": "plan",
            "allow_create": False,
            "item_id": arguments["password_item_id"],
            "item_version": arguments["password_item_version"],
            "item_title": arguments["password_item_title"],
            "field_id": arguments["password_field_id"],
            "category": "Password",
            "tags": arguments["password_tags"],
            "subject": arguments["subject"],
            "schema_version": arguments["schema_version"],
            "password_recipe": "letters,digits,symbols,{0}".format(
                arguments["password_length"]
            ),
            "password_length": arguments["password_length"],
        },
        "ssh_item": {
            "operation": "verify_agent",
            "allow_create": False,
            "item_id": arguments["ssh_item_id"],
            "item_version": arguments["ssh_item_version"],
            "item_title": arguments["ssh_item_title"],
            "category": "SSH Key",
            "tags": arguments["ssh_tags"],
            "subject": arguments["subject"],
            "schema_version": arguments["schema_version"],
            "key_type": "ed25519",
            "expected_fingerprint": arguments["ssh_expected_fingerprint"],
            "ssh_add_path": arguments["ssh_add_path"],
            "ssh_add_sha256": arguments["ssh_add_sha256"],
            "ssh_keygen_path": arguments["ssh_keygen_path"],
            "ssh_keygen_sha256": arguments["ssh_keygen_sha256"],
            "agent_socket_path": arguments["agent_socket_path"],
        },
        "controller_ssh": {
            "ssh_path": arguments["ssh_path"],
            "ssh_sha256": arguments["ssh_sha256"],
            "known_hosts_identity": _known_hosts_identity(arguments),
        },
        "destination": {
            "host": arguments["destination_host"],
            "user": arguments["destination_user"],
            "port": arguments["destination_port"],
            "host_fingerprint": arguments["destination_host_fingerprint"],
            "remote_command": arguments["remote_command"],
        },
    }
    approval, _unused_replay, _unused_now = build_approval(
        tmp_path,
        authority,
        "unlock-luks-over-ssh-stdin",
        arguments["destination_host"],
        binding,
        execution_id="luks-unlock-001",
        nonce="c" * 64,
        replay_name="replay",
    )
    return approval


def _arguments(tmp_path, **overrides):
    op_path = tmp_path / "op"
    ssh_path = tmp_path / "ssh"
    ssh_add_path = tmp_path / "ssh-add"
    ssh_keygen_path = tmp_path / "ssh-keygen"
    arguments = {
        "cli_path": str(op_path),
        "cli_sha256": _digest(op_path, "0" * 64),
        "cli_version": "2.38.1",
        "account_id": ACCOUNT_ID,
        "account_sign_in_address": "example.1password.com",
        "authorized_user_uuids": [USER_UUID],
        "vault_id": VAULT_ID,
        "password_item_id": PASSWORD_ITEM_ID,
        "password_item_version": PASSWORD_ITEM_VERSION,
        "password_item_title": SUBJECT + " LUKS recovery",
        "password_field_id": "password",
        "password_tags": ["breakglass", "recovery"],
        "password_length": 64,
        "ssh_item_id": SSH_ITEM_ID,
        "ssh_item_version": SSH_ITEM_VERSION,
        "ssh_item_title": SUBJECT + " Dropbear recovery",
        "ssh_tags": ["breakglass", "recovery"],
        "ssh_expected_fingerprint": SSH_FINGERPRINT,
        "subject": SUBJECT,
        "schema_version": 1,
        "ssh_path": str(ssh_path),
        "ssh_sha256": _digest(ssh_path, "1" * 64),
        "ssh_add_path": str(ssh_add_path),
        "ssh_add_sha256": _digest(ssh_add_path, "2" * 64),
        "ssh_keygen_path": str(ssh_keygen_path),
        "ssh_keygen_sha256": _digest(ssh_keygen_path, "3" * 64),
        "agent_socket_path": str(tmp_path / "agent.sock"),
        "known_hosts_path": str(tmp_path / "known_hosts"),
        "known_hosts_sha256": _digest(tmp_path / "known_hosts", "4" * 64),
        "destination_host": SUBJECT,
        "destination_user": "root",
        "destination_port": 2222,
        "destination_host_fingerprint": HOST_FINGERPRINT,
        "remote_command": "/bin/cryptroot-unlock",
    }
    explicit_approval = overrides.pop("approval", None)
    explicit_authority = overrides.pop("approval_authority", None)
    arguments.update(overrides)
    authority = (
        build_authority(tmp_path) if explicit_authority is None else explicit_authority
    )
    arguments["approval_authority"] = authority
    arguments["approval"] = (
        _approval(tmp_path, arguments, authority)
        if explicit_approval is None
        else explicit_approval
    )
    return arguments


def _write_executable(path, source):
    path.write_text("#!{0}\n{1}".format(sys.executable, source), encoding="utf-8")
    path.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)


def _write_valid_known_hosts(tmp_path):
    path = tmp_path / "known_hosts"
    path.write_text(
        "[{0}]:2222 {1}\n".format(SUBJECT, HOST_PUBLIC_KEY), encoding="ascii"
    )
    path.chmod(0o600)
    return path


def test_consumer_keeps_secret_out_of_result_and_process_arguments(
    tmp_path, monkeypatch
):
    marker = tmp_path / "ssh-success"
    op_path = tmp_path / "op"
    ssh_path = tmp_path / "ssh"
    _write_valid_known_hosts(tmp_path)
    _write_executable(
        op_path,
        "import os, sys\n"
        "args = sys.argv[1:]\n"
        "descriptor = int(args[args.index('--out-file') + 1].rsplit('/', 1)[1])\n"
        "os.write(descriptor, {0!r})\n".format(SECRET),
    )
    _write_executable(
        ssh_path,
        "import pathlib, sys\n"
        "value = sys.stdin.buffer.read()\n"
        "required = {0!r}\n"
        "if not required.issubset(set(sys.argv[1:])):\n"
        "    raise SystemExit(7)\n"
        "if sys.argv[-1] != '/bin/cryptroot-unlock':\n"
        "    raise SystemExit(8)\n"
        "if value != {1!r}:\n"
        "    raise SystemExit(9)\n"
        "pathlib.Path({2!r}).write_text('ok', encoding='utf-8')\n".format(
            {
                "-T",
                "BatchMode=yes",
                "CanonicalizeHostname=no",
                "ClearAllForwardings=yes",
                "EscapeChar=none",
                "ForwardAgent=no",
                "ForwardX11=no",
                "ForwardX11Trusted=no",
                "HostKeyAlgorithms=ssh-ed25519",
                "KbdInteractiveAuthentication=no",
                "PasswordAuthentication=no",
                "PermitLocalCommand=no",
                "ProxyCommand=none",
                "ProxyJump=none",
                "PubkeyAcceptedAlgorithms=ssh-ed25519",
                "RequestTTY=no",
                "StrictHostKeyChecking=yes",
                "UpdateHostKeys=no",
                "VerifyHostKeyDNS=no",
            },
            SECRET,
            str(marker),
        ),
    )
    agent_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    agent_socket.bind(str(tmp_path / "agent.sock"))
    config = plugin._normalize_arguments(_arguments(tmp_path))
    fake_client = SimpleNamespace(
        requested_binary=str(op_path),
        binary=str(op_path),
        binary_sha256=config["password"]["cli_sha256"],
        environment={"HOME": str(tmp_path), "PATH": os.environ["PATH"]},
    )
    monkeypatch.setattr(
        plugin,
        "_inspect_boundaries",
        lambda unused_config: (
            fake_client,
            {"public_key": PUBLIC_KEY, "fingerprint": SSH_FINGERPRINT},
            USER_UUID,
        ),
    )
    monkeypatch.setattr(plugin, "_disable_core_dumps", lambda: True)
    monkeypatch.setattr(
        plugin, "_revalidate_password_item", lambda client, config, operator: None
    )
    monkeypatch.setattr(
        plugin,
        "_revalidate_ssh_item",
        lambda client, config, public_identity, operator: None,
    )
    try:
        result = plugin._consume(config)
    finally:
        agent_socket.close()

    assert result["unlocked"] is True
    assert result["changed"] is True
    assert result["operator_user_uuid"] == USER_UUID
    assert result["core_dumps_disabled"] is True
    assert marker.read_text(encoding="utf-8") == "ok"
    assert SECRET.decode("ascii") not in repr(result)
    assert len(list((tmp_path / "replay").glob("*.used"))) == 1


def test_check_mode_never_claims_reads_or_connects(tmp_path, monkeypatch):
    ssh_path = tmp_path / "ssh"
    _write_executable(ssh_path, "raise SystemExit(99)\n")
    _write_valid_known_hosts(tmp_path)
    config = plugin._normalize_arguments(_arguments(tmp_path))
    monkeypatch.setattr(
        plugin,
        "_inspect_boundaries",
        lambda unused_config: (
            object(),
            {"public_key": PUBLIC_KEY, "fingerprint": SSH_FINGERPRINT},
            USER_UUID,
        ),
    )
    monkeypatch.setattr(
        plugin,
        "_read_secret_bytes",
        lambda *unused: pytest.fail("check mode read a secret"),
    )

    result = plugin._consume(config, check_mode=True)

    assert result["unlocked"] is False
    assert result["changed"] is False
    assert result["core_dumps_disabled"] is False
    assert not list((tmp_path / "replay").glob("*.used"))


def test_known_hosts_is_exactly_bound_to_host_port_ed25519_and_fingerprint(tmp_path):
    ssh_path = tmp_path / "ssh"
    _write_executable(ssh_path, "raise SystemExit(99)\n")
    known_hosts = _write_valid_known_hosts(tmp_path)
    config = plugin._normalize_arguments(_arguments(tmp_path))

    resolved_ssh, selected_pin = plugin._validate_controller_paths(config)
    assert resolved_ssh == str(ssh_path)
    assert selected_pin == known_hosts.read_text(encoding="ascii")

    invalid_rows = [
        known_hosts.read_text(encoding="ascii") * 2,
        "{0} {1}\n".format(SUBJECT, HOST_PUBLIC_KEY),
        "[{0}]:22 {1}\n".format(SUBJECT, HOST_PUBLIC_KEY),
        "* {0}\n".format(HOST_PUBLIC_KEY),
        "|1|hash|hash {0}\n".format(HOST_PUBLIC_KEY),
        "[{0}]:2222 ssh-rsa AAAA\n".format(SUBJECT),
    ]
    for row in invalid_rows:
        known_hosts.write_text(row, encoding="ascii")
        with pytest.raises(AnsibleActionFail):
            plugin._validate_controller_paths(config)


def test_known_hosts_wrong_fingerprint_and_hard_link_fail_closed(tmp_path):
    ssh_path = tmp_path / "ssh"
    _write_executable(ssh_path, "raise SystemExit(99)\n")
    known_hosts = _write_valid_known_hosts(tmp_path)
    with pytest.raises(AnsibleActionFail):
        plugin._normalize_arguments(
            _arguments(
                tmp_path,
                destination_host_fingerprint="SHA256:" + "A" * 43,
            )
        )

    config = plugin._normalize_arguments(_arguments(tmp_path))
    os.link(known_hosts, tmp_path / "known_hosts.link")
    with pytest.raises(AnsibleActionFail):
        plugin._validate_controller_paths(config)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("account_sign_in_address", "changed.1password.com"),
        ("agent_socket_path", "/tmp/changed-agent.sock"),
        ("password_item_title", "changed LUKS recovery"),
        ("ssh_tags", ["breakglass", "changed"]),
    ],
)
def test_unlock_signature_rejects_normalized_contract_mutation(tmp_path, field, value):
    _write_valid_known_hosts(tmp_path)
    arguments = _arguments(tmp_path)
    arguments[field] = value
    with pytest.raises(AnsibleActionFail):
        plugin._normalize_arguments(arguments)


def test_secret_reader_uses_mutable_readv_and_rejects_short_or_oversized_values(
    tmp_path,
):
    source = inspect.getsource(plugin._read_secret_bytes)
    assert "os.readv(" in source
    assert "os.read(" not in source
    op_path = tmp_path / "op"
    password_config = {
        "vault_id": VAULT_ID,
        "item_id": PASSWORD_ITEM_ID,
        "field_id": "password",
        "account_id": ACCOUNT_ID,
        "password_length": 64,
    }
    environment = {"HOME": str(tmp_path), "PATH": os.environ["PATH"]}
    for payload in (b"S" * 63, b"S" * 65, b"S" * 63 + b"\n"):
        _write_executable(
            op_path,
            "import os, sys\n"
            "args = sys.argv[1:]\n"
            "fd = int(args[args.index('--out-file') + 1].rsplit('/', 1)[1])\n"
            "os.write(fd, {0!r})\n".format(payload),
        )
        client = SimpleNamespace(
            requested_binary=str(op_path),
            binary=str(op_path),
            binary_sha256=hashlib.sha256(op_path.read_bytes()).hexdigest(),
            environment=environment,
        )
        with pytest.raises(AnsibleActionFail):
            plugin._read_secret_bytes(client, password_config)


def test_core_dump_boundary_sets_and_verifies_zero(monkeypatch):
    calls = []
    monkeypatch.setattr(
        plugin.resource,
        "getrlimit",
        lambda unused: (1024, 4096) if not calls else (0, 4096),
    )
    monkeypatch.setattr(
        plugin.resource, "setrlimit", lambda unused, value: calls.append(value)
    )

    assert plugin._disable_core_dumps() is True
    assert calls == [(0, 4096)]


def test_macos_agent_socket_path_is_quoted_without_shell_interpolation():
    path = (
        "/Users/operator/Library/Group Containers/2BUA8C4S2C.com.1password/t/agent.sock"
    )
    assert plugin._ssh_option_path(path) == '"{0}"'.format(path)


def test_ssh_identity_is_revalidated_after_secret_transport(monkeypatch):
    class _Store:
        @staticmethod
        def inspect(config):
            return {
                "exists": True,
                "item_id": config["item_id"],
                "item_version": config["item_version"],
                "operator_user_uuid": USER_UUID,
            }

        @staticmethod
        def public_metadata(config, item_id, item_version):
            return {"public_key": PUBLIC_KEY, "fingerprint": "SHA256:" + "B" * 43}

    monkeypatch.setattr(plugin, "_OnePasswordSSHKeyItemStore", lambda client: _Store())
    ssh_config = {"item_id": SSH_ITEM_ID, "item_version": SSH_ITEM_VERSION}

    with pytest.raises(AnsibleActionFail):
        plugin._revalidate_ssh_item(
            object(),
            ssh_config,
            {"public_key": PUBLIC_KEY, "fingerprint": SSH_FINGERPRINT},
            USER_UUID,
        )


@pytest.mark.parametrize(
    "overrides",
    [
        {"approval": {}},
        {"ssh_expected_fingerprint": "SHA256:wrong"},
        {"password_item_id": "not-an-id"},
        {"password_item_version": 0},
        {"ssh_item_version": 0},
        {"password_tags": []},
        {"destination_port": 0},
        {"remote_command": "cryptroot-unlock"},
        {"destination_user": "ubuntu"},
        {"destination_host": "other.example.test"},
        {"authorized_user_uuids": []},
        {"ssh_sha256": "wrong"},
    ],
)
def test_invalid_contracts_fail_before_any_secret_read(tmp_path, overrides):
    _write_valid_known_hosts(tmp_path)
    with pytest.raises(AnsibleActionFail):
        plugin._normalize_arguments(_arguments(tmp_path, **overrides))
