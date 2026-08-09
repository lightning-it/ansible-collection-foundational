# Copyright: (c) 2026, Lightning IT
# SPDX-License-Identifier: MIT

"""Send one pinned 1Password secret to one pinned SSH session over stdin."""

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import os
import re
import resource
import selectors
import subprocess
import tempfile
import time

from ansible.plugins.action import ActionBase

from .onepassword_secret_item import (
    _OnePasswordCLI,
    _OnePasswordSecretItemStore,
    _fail,
    _normalize_arguments as _normalize_password_arguments,
)
from .onepassword_ssh_key_item import (
    _OnePasswordSSHKeyItemStore,
    _normalize_arguments as _normalize_ssh_key_arguments,
    _public_identity,
    _write_controller_file,
)
from ._onepassword_boundary import (
    claim_approval,
    normalize_approval,
    normalize_sha256,
    safe_approval_metadata,
    trusted_agent_socket,
    trusted_executable,
    trusted_regular_file,
)


DOCUMENTATION = r"""
---
module: onepassword_ssh_secret_stdin
short_description: Stream one pinned 1Password secret into one pinned SSH session
version_added: "1.34.0"
description:
  - Validates exact Password and SSH Key items inside one exact 1Password account and vault.
  - Requires an externally pinned SSH-key fingerprint and an exact, protected SSH Agent socket.
  - Reads the Password value only inside the controller action and sends it directly to SSH standard input.
  - Never returns the secret to Ansible variables, facts, stdout, stderr, logs, or a plaintext file.
options:
  cli_path:
    type: path
    required: true
  cli_sha256:
    type: str
    required: true
  cli_version:
    type: str
    required: true
  account_id:
    type: str
    required: true
  account_sign_in_address:
    type: str
    required: true
  authorized_user_uuids:
    type: list
    elements: str
    required: true
  vault_id:
    type: str
    required: true
  password_item_id:
    type: str
    required: true
  password_item_version:
    type: int
    required: true
  password_item_title:
    type: str
    required: true
  password_field_id:
    type: str
    default: password
  password_tags:
    type: list
    elements: str
    required: true
  password_length:
    type: int
    required: true
  ssh_item_id:
    type: str
    required: true
  ssh_item_version:
    type: int
    required: true
  ssh_item_title:
    type: str
    required: true
  ssh_tags:
    type: list
    elements: str
    required: true
  ssh_expected_fingerprint:
    type: str
    required: true
  subject:
    type: str
    required: true
  schema_version:
    type: int
    default: 1
  ssh_path:
    type: path
    required: true
  ssh_sha256:
    type: str
    required: true
  ssh_add_path:
    type: path
    required: true
  ssh_add_sha256:
    type: str
    required: true
  ssh_keygen_path:
    type: path
    required: true
  ssh_keygen_sha256:
    type: str
    required: true
  agent_socket_path:
    type: path
    required: true
  known_hosts_path:
    type: path
    required: true
  destination_host:
    type: str
    required: true
  destination_user:
    type: str
    default: root
  destination_port:
    type: int
    required: true
  destination_host_fingerprint:
    type: str
    required: true
  remote_command:
    type: str
    choices: [/bin/cryptroot-unlock]
    required: true
  approval:
    type: dict
    required: true
notes:
  - The action supports only SSH public-key authentication through the exact approved Agent socket.
  - The destination user is always C(root), and C(subject) must equal C(destination_host).
  - The protected known-hosts file must contain exactly one Ed25519 key for the exact host and port, matching the
    independently pinned host fingerprint.
  - The action always disables PTY allocation, executes C(/bin/cryptroot-unlock) explicitly, sends the passphrase
    without a newline, and closes SSH standard input. Debian cryptroot-unlock uses EOF-delimited C(cat) input in its
    non-interactive path.
  - Check mode validates item identities, public fingerprints, files, and Agent availability but does not read the
    password or open an SSH connection.
  - This action does not reboot, create, edit, rotate, export, archive, or delete any 1Password item.
  - The controller worker soft core-dump limit is set to zero before reading. The trusted operating system, kernel,
    process memory, swap configuration, approved executable owners, and the 1Password/SSH child processes remain
    explicit trust boundaries.
author:
  - Lightning IT (@lightning-it)
"""

EXAMPLES = r"""
---
- name: Unlock one encrypted host without exposing the passphrase to Ansible
  lit.foundational.onepassword_ssh_secret_stdin:
    cli_path: /usr/local/bin/op
    cli_sha256: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    cli_version: 2.38.1
    account_id: aaaaaaaaaaaaaaaaaaaaaaaaaa
    account_sign_in_address: example.1password.com
    authorized_user_uuids: [uuuuuuuuuuuuuuuuuuuuuuuuuu]
    vault_id: vvvvvvvvvvvvvvvvvvvvvvvvvv
    password_item_id: pppppppppppppppppppppppppp
    password_item_version: 1
    password_item_title: host01.example.test LUKS recovery
    password_tags: [breakglass, recovery]
    password_length: 64
    ssh_item_id: iiiiiiiiiiiiiiiiiiiiiiiiii
    ssh_item_version: 1
    ssh_item_title: host01.example.test Dropbear recovery
    ssh_tags: [breakglass, recovery]
    ssh_expected_fingerprint: SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
    subject: host01.example.test
    ssh_path: /usr/bin/ssh
    ssh_sha256: bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
    ssh_add_path: /usr/bin/ssh-add
    ssh_add_sha256: cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
    ssh_keygen_path: /usr/bin/ssh-keygen
    ssh_keygen_sha256: dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd
    agent_socket_path: /absolute/path/to/1password/agent.sock
    known_hosts_path: /absolute/path/to/dropbear-known-hosts
    destination_host: host01.example.test
    destination_port: 2222
    destination_host_fingerprint: SHA256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB
    remote_command: /bin/cryptroot-unlock
    approval:
      schema_version: 1
      execution_id: unlock-20260809-001
      commit_shas:
        foundational: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
      nonce: cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
      issued_at: "2026-08-09T10:00:00Z"
      expires_at: "2026-08-09T10:05:00Z"
      replay_directory: /absolute/controller-only/approval-replay
      confirmation: APPROVE:unlock-20260809-001:<calculated-sha256>
"""

RETURN = r"""
unlocked:
  type: bool
  returned: always
  description: Whether the guarded SSH stdin operation completed successfully.
password_item_id:
  type: str
  returned: always
  description: Validated non-sensitive Password item ID.
password_item_version:
  type: int
  returned: always
  description: Validated non-sensitive Password item version.
ssh_item_id:
  type: str
  returned: always
  description: Validated non-sensitive SSH Key item ID.
ssh_item_version:
  type: int
  returned: always
  description: Validated non-sensitive SSH Key item version.
ssh_fingerprint:
  type: str
  returned: always
  description: Externally pinned and revalidated public-key fingerprint.
destination:
  type: str
  returned: always
  description: Non-sensitive SSH destination identity.
operator_user_uuid:
  type: str
  returned: always
  description: Allowlisted 1Password operator observed during validation.
core_dumps_disabled:
  type: bool
  returned: always
  description: Whether the controller worker soft core-dump limit was set to zero before secret retrieval.
"""


_EXPECTED_ARGS = frozenset(
    (
        "cli_path",
        "cli_sha256",
        "cli_version",
        "account_id",
        "account_sign_in_address",
        "authorized_user_uuids",
        "vault_id",
        "password_item_id",
        "password_item_version",
        "password_item_title",
        "password_field_id",
        "password_tags",
        "password_length",
        "ssh_item_id",
        "ssh_item_version",
        "ssh_item_title",
        "ssh_tags",
        "ssh_expected_fingerprint",
        "subject",
        "schema_version",
        "ssh_path",
        "ssh_sha256",
        "ssh_add_path",
        "ssh_add_sha256",
        "ssh_keygen_path",
        "ssh_keygen_sha256",
        "agent_socket_path",
        "known_hosts_path",
        "destination_host",
        "destination_user",
        "destination_port",
        "destination_host_fingerprint",
        "remote_command",
        "approval",
    )
)
_HOST_PATTERN = re.compile(
    r"[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?\Z", re.ASCII
)
_USER_PATTERN = re.compile(r"[a-z_][a-z0-9_-]{0,31}\Z", re.ASCII)
_FINGERPRINT_PATTERN = re.compile(r"SHA256:[A-Za-z0-9+/]{43}\Z", re.ASCII)
_PROCESS_TIMEOUT_SECONDS = 120
_MAX_SECRET_BYTES = 64


def _integer(value, name):
    if isinstance(value, bool):
        _fail("{0} must be an integer.".format(name))
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.isascii() and value.isdecimal():
        return int(value, 10)
    _fail("{0} must be an integer.".format(name))


def _normalize_arguments(args):
    unknown = set(args).difference(_EXPECTED_ARGS)
    if unknown:
        _fail("Unsupported arguments: {0}.".format(", ".join(sorted(unknown))))
    schema_version = _integer(args.get("schema_version", 1), "schema_version")
    password_length = _integer(args.get("password_length"), "password_length")
    destination_port = _integer(args.get("destination_port"), "destination_port")
    if schema_version != 1:
        _fail("schema_version must be exactly 1.")
    if password_length < 40 or password_length > _MAX_SECRET_BYTES:
        _fail("password_length must be between 40 and 64.")
    if destination_port < 1 or destination_port > 65535:
        _fail("destination_port must be between 1 and 65535.")
    destination_host = args.get("destination_host")
    destination_user = args.get("destination_user", "root")
    remote_command = args.get("remote_command")
    if not isinstance(destination_host, str) or not _HOST_PATTERN.fullmatch(destination_host):
        _fail("destination_host must be one exact host identity.")
    if not isinstance(destination_user, str) or not _USER_PATTERN.fullmatch(destination_user):
        _fail("destination_user must be one exact safe SSH user.")
    if destination_user != "root":
        _fail("destination_user must be exactly root.")
    if remote_command != "/bin/cryptroot-unlock":
        _fail("remote_command must be exactly /bin/cryptroot-unlock.")
    subject = args.get("subject")
    if subject != destination_host:
        _fail("subject and destination_host must be the same exact target identity.")
    destination_host_fingerprint = args.get("destination_host_fingerprint")
    if (
        not isinstance(destination_host_fingerprint, str)
        or not _FINGERPRINT_PATTERN.fullmatch(destination_host_fingerprint)
    ):
        _fail("destination_host_fingerprint must be one exact SHA-256 SSH fingerprint.")

    cli_sha256 = normalize_sha256(args.get("cli_sha256"), "cli_sha256")
    ssh_sha256 = normalize_sha256(args.get("ssh_sha256"), "ssh_sha256")
    ssh_add_sha256 = normalize_sha256(
        args.get("ssh_add_sha256"), "ssh_add_sha256"
    )
    ssh_keygen_sha256 = normalize_sha256(
        args.get("ssh_keygen_sha256"), "ssh_keygen_sha256"
    )

    common = {
        "cli_path": args.get("cli_path"),
        "cli_sha256": cli_sha256,
        "cli_version": args.get("cli_version"),
        "account_id": args.get("account_id"),
        "account_sign_in_address": args.get("account_sign_in_address"),
        "authorized_user_uuids": args.get("authorized_user_uuids"),
        "vault_id": args.get("vault_id"),
        "subject": subject,
        "schema_version": schema_version,
    }
    password = _normalize_password_arguments(
        dict(
            common,
            operation="plan",
            item_id=args.get("password_item_id"),
            item_version=args.get("password_item_version"),
            item_title=args.get("password_item_title"),
            field_id=args.get("password_field_id", "password"),
            category="Password",
            tags=args.get("password_tags"),
            password_recipe="letters,digits,symbols,{0}".format(password_length),
            password_length=password_length,
            allow_create=False,
            approval={},
        )
    )
    ssh_key = _normalize_ssh_key_arguments(
        dict(
            common,
            operation="verify_agent",
            item_id=args.get("ssh_item_id"),
            item_version=args.get("ssh_item_version"),
            item_title=args.get("ssh_item_title"),
            category="SSH Key",
            tags=args.get("ssh_tags"),
            key_type="ed25519",
            expected_fingerprint=args.get("ssh_expected_fingerprint"),
            allow_create=False,
            approval={},
            ssh_add_path=args.get("ssh_add_path"),
            ssh_add_sha256=ssh_add_sha256,
            ssh_keygen_path=args.get("ssh_keygen_path"),
            ssh_keygen_sha256=ssh_keygen_sha256,
            agent_socket_path=args.get("agent_socket_path"),
        )
    )
    config = {
        "password": password,
        "ssh_key": ssh_key,
        "ssh_path": args.get("ssh_path"),
        "ssh_sha256": ssh_sha256,
        "known_hosts_path": args.get("known_hosts_path"),
        "destination_host": destination_host,
        "destination_user": destination_user,
        "destination_port": destination_port,
        "destination_host_fingerprint": destination_host_fingerprint,
        "remote_command": remote_command,
    }
    config["approval"] = normalize_approval(
        args.get("approval"),
        operation="unlock-luks-over-ssh-stdin",
        target=destination_host,
        binding=_approval_binding(config),
    )
    return config


def _approval_binding(config):
    password = config["password"]
    ssh_key = config["ssh_key"]
    return {
        "account_id": password["account_id"],
        "authorized_user_uuids": password["authorized_user_uuids"],
        "cli_sha256": password["cli_sha256"],
        "destination_host": config["destination_host"],
        "destination_host_fingerprint": config["destination_host_fingerprint"],
        "destination_port": config["destination_port"],
        "destination_user": config["destination_user"],
        "password_item_id": password["item_id"],
        "password_item_version": password["item_version"],
        "remote_command": config["remote_command"],
        "ssh_add_sha256": ssh_key["ssh_add_sha256"],
        "ssh_expected_fingerprint": ssh_key["expected_fingerprint"],
        "ssh_item_id": ssh_key["item_id"],
        "ssh_item_version": ssh_key["item_version"],
        "ssh_keygen_sha256": ssh_key["ssh_keygen_sha256"],
        "ssh_sha256": config["ssh_sha256"],
        "subject": password["subject"],
        "vault_id": password["vault_id"],
    }


def _validate_controller_paths(config):
    ssh_path = trusted_executable(
        config["ssh_path"], config["ssh_sha256"], "ssh_path"
    )
    _unused_path, payload = trusted_regular_file(
        config["known_hosts_path"], "known_hosts_path"
    )
    try:
        rows = payload.decode("ascii", errors="strict").splitlines()
    except UnicodeDecodeError:
        _fail("known_hosts_path must contain ASCII OpenSSH host-key data.")
    entries = [
        row.strip()
        for row in rows
        if row.strip() and not row.lstrip().startswith("#")
    ]
    if len(entries) != 1:
        _fail("known_hosts_path must contain exactly one non-comment host-key entry.")
    fields = entries[0].split()
    if len(fields) not in (3, 4):
        _fail("known_hosts_path contains an invalid host-key entry.")
    host_token, key_type, encoded_key = fields[:3]
    if (
        host_token.startswith(("|", "@", "!"))
        or any(character in host_token for character in ("*", "?", ","))
    ):
        _fail("known_hosts_path may not use markers, hashes, patterns, or aliases.")
    expected_host_token = (
        config["destination_host"]
        if config["destination_port"] == 22
        else "[{0}]:{1}".format(
            config["destination_host"], config["destination_port"]
        )
    )
    if host_token != expected_host_token:
        _fail("known_hosts_path does not bind the exact destination host and port.")
    if key_type != "ssh-ed25519":
        _fail("known_hosts_path must pin exactly one Ed25519 host key.")
    _unused_public_key, fingerprint = _public_identity(
        "ssh-ed25519 {0}".format(encoded_key)
    )
    if fingerprint != config["destination_host_fingerprint"]:
        _fail("known_hosts_path does not match destination_host_fingerprint.")
    return ssh_path, "{0} {1} {2}\n".format(host_token, key_type, encoded_key)


def _inspect_boundaries(config):
    client = _OnePasswordCLI(
        config["password"]["cli_path"],
        config["password"]["cli_sha256"],
        config["password"]["account_id"],
    )
    password_observed = _OnePasswordSecretItemStore(client).inspect(config["password"])
    if (
        not password_observed["exists"]
        or password_observed["item_id"] != config["password"]["item_id"]
    ):
        _fail("The exact pinned Password item is absent.")
    ssh_store = _OnePasswordSSHKeyItemStore(client)
    ssh_observed = ssh_store.inspect(config["ssh_key"])
    if (
        not ssh_observed["exists"]
        or ssh_observed["item_id"] != config["ssh_key"]["item_id"]
    ):
        _fail("The exact pinned SSH Key item is absent.")
    public_identity = ssh_store.public_metadata(
        config["ssh_key"],
        ssh_observed["item_id"],
        ssh_observed["item_version"],
    )
    ssh_store.verify_agent(config["ssh_key"], public_identity)
    if password_observed["operator_user_uuid"] != ssh_observed["operator_user_uuid"]:
        _fail("Password and SSH boundaries were inspected by different operators.")
    return client, public_identity, password_observed["operator_user_uuid"]


def _read_secret_bytes(client, password_config):
    if not os.path.exists("/dev/fd"):
        _fail("The controller cannot provide the required inherited descriptor boundary.")
    read_descriptor, write_descriptor = os.pipe()
    secret = bytearray(password_config["password_length"])
    overflow = bytearray(1)
    producer = None
    selector = selectors.DefaultSelector()
    received = 0
    try:
        reference = "op://{0}/{1}/{2}".format(
            password_config["vault_id"],
            password_config["item_id"],
            password_config["field_id"],
        )
        client.binary = trusted_executable(
            client.requested_binary, client.binary_sha256, "cli_path"
        )
        try:
            producer = subprocess.Popen(
                [
                    client.binary,
                    "read",
                    "--account",
                    password_config["account_id"],
                    "--force",
                    "--no-newline",
                    "--out-file",
                    "/dev/fd/{0}".format(write_descriptor),
                    reference,
                ],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                env=client.environment,
                close_fds=True,
                pass_fds=(write_descriptor,),
            )
        except (OSError, subprocess.SubprocessError):
            _fail("1Password secret transport could not be started safely.")
        os.close(write_descriptor)
        write_descriptor = -1
        selector.register(read_descriptor, selectors.EVENT_READ)
        deadline = time.monotonic() + _PROCESS_TIMEOUT_SECONDS
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                _fail("1Password secret transport timed out and was terminated.")
            if not selector.select(remaining):
                _fail("1Password secret transport timed out and was terminated.")
            if received < len(secret):
                target = memoryview(secret)[received:]
                count = os.readv(read_descriptor, [target])
                target.release()
                if count == 0:
                    break
                received += count
                continue
            target = memoryview(overflow)
            count = os.readv(read_descriptor, [target])
            target.release()
            if count == 0:
                break
            _fail("1Password returned an oversized recovery-secret value.")
        remaining = max(0.001, deadline - time.monotonic())
        try:
            producer.wait(timeout=remaining)
        except subprocess.TimeoutExpired:
            _fail("1Password secret transport timed out and was terminated.")
        if producer.returncode != 0:
            _fail("1Password secret transport failed closed.")
        if received != password_config["password_length"]:
            _fail("1Password returned an unexpected recovery-secret length.")
        if any(value in secret for value in (0, 10, 13)):
            _fail("1Password returned an invalid recovery-secret value.")
        return secret
    except Exception:
        if producer is not None and producer.poll() is None:
            producer.kill()
            producer.wait()
        for index in range(len(secret)):
            secret[index] = 0
        overflow[0] = 0
        raise
    finally:
        selector.close()
        os.close(read_descriptor)
        if write_descriptor >= 0:
            os.close(write_descriptor)


def _revalidate_password_item(client, password_config, operator_user_uuid=None):
    observed = _OnePasswordSecretItemStore(client).inspect(password_config)
    if (
        observed["item_id"] != password_config["item_id"]
        or observed["item_version"] != password_config["item_version"]
    ):
        _fail("The pinned Password item changed while its value was transported.")
    if (
        operator_user_uuid is not None
        and observed["operator_user_uuid"] != operator_user_uuid
    ):
        _fail("The 1Password operator changed while the secret was transported.")


def _revalidate_ssh_item(
    client, ssh_config, public_identity, operator_user_uuid=None
):
    store = _OnePasswordSSHKeyItemStore(client)
    observed = store.inspect(ssh_config)
    if (
        observed["item_id"] != ssh_config["item_id"]
        or observed["item_version"] != ssh_config["item_version"]
    ):
        _fail("The pinned SSH Key item changed while the recovery secret was transported.")
    if (
        operator_user_uuid is not None
        and observed["operator_user_uuid"] != operator_user_uuid
    ):
        _fail("The 1Password operator changed while the secret was transported.")
    current_identity = store.public_metadata(
        ssh_config,
        observed["item_id"],
        observed["item_version"],
    )
    if current_identity != public_identity:
        _fail("The pinned SSH public identity changed before recovery consumption.")


def _ssh_option_path(value):
    if any(character in value for character in "\x00\r\n"):
        _fail("An SSH option path contains an invalid character.")
    return '"{0}"'.format(value.replace("\\", "\\\\").replace('"', '\\"'))


def _disable_core_dumps():
    try:
        _unused_soft, hard = resource.getrlimit(resource.RLIMIT_CORE)
        resource.setrlimit(resource.RLIMIT_CORE, (0, hard))
        soft_after, _unused_hard_after = resource.getrlimit(resource.RLIMIT_CORE)
    except (OSError, ValueError):
        _fail("The controller process core-dump boundary could not be disabled.")
    if soft_after != 0:
        _fail("The controller process core-dump boundary is not disabled.")
    return True


def _run_ssh(config, known_host_line, public_identity, secret):
    ssh_path = trusted_executable(
        config["ssh_path"], config["ssh_sha256"], "ssh_path"
    )
    agent_socket = trusted_agent_socket(config["ssh_key"]["agent_socket_path"])
    environment = {
        "HOME": os.environ.get("HOME", ""),
        "PATH": os.environ.get("PATH", ""),
        "SSH_AUTH_SOCK": agent_socket,
    }
    for name in ("LANG", "LC_ALL"):
        if os.environ.get(name):
            environment[name] = os.environ[name]
    if not environment["HOME"]:
        _fail("HOME is required for the approved 1Password SSH Agent.")
    temporary_root = tempfile.mkdtemp(prefix="lit-onepassword-ssh-")
    os.chmod(temporary_root, 0o700)
    public_key_path = os.path.join(temporary_root, "identity.pub")
    known_hosts_path = os.path.join(temporary_root, "known_hosts")
    try:
        _write_controller_file(
            public_key_path,
            (public_identity["public_key"] + "\n").encode("ascii"),
        )
        _write_controller_file(known_hosts_path, known_host_line.encode("ascii"))
        arguments = [
            ssh_path,
            "-F",
            "/dev/null",
            "-T",
            "-o",
            "BatchMode=yes",
            "-o",
            "CanonicalizeHostname=no",
            "-o",
            "ClearAllForwardings=yes",
            "-o",
            "ControlMaster=no",
            "-o",
            "ControlPath=none",
            "-o",
            "ControlPersist=no",
            "-o",
            "ConnectionAttempts=1",
            "-o",
            "ConnectTimeout=15",
            "-o",
            "EscapeChar=none",
            "-o",
            "ExitOnForwardFailure=yes",
            "-o",
            "ForwardAgent=no",
            "-o",
            "ForwardX11=no",
            "-o",
            "ForwardX11Trusted=no",
            "-o",
            "GlobalKnownHostsFile=/dev/null",
            "-o",
            "HostKeyAlgorithms=ssh-ed25519",
            "-o",
            "IdentityAgent={0}".format(_ssh_option_path(agent_socket)),
            "-o",
            "IdentitiesOnly=yes",
            "-i",
            public_key_path,
            "-o",
            "KbdInteractiveAuthentication=no",
            "-o",
            "NumberOfPasswordPrompts=0",
            "-o",
            "PasswordAuthentication=no",
            "-o",
            "PermitLocalCommand=no",
            "-o",
            "PreferredAuthentications=publickey",
            "-o",
            "ProxyCommand=none",
            "-o",
            "ProxyJump=none",
            "-o",
            "PubkeyAuthentication=yes",
            "-o",
            "PubkeyAcceptedAlgorithms=ssh-ed25519",
            "-o",
            "RequestTTY=no",
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            "UpdateHostKeys=no",
            "-o",
            "UserKnownHostsFile={0}".format(_ssh_option_path(known_hosts_path)),
            "-o",
            "VerifyHostKeyDNS=no",
            "-p",
            str(config["destination_port"]),
            "{0}@{1}".format(config["destination_user"], config["destination_host"]),
            config["remote_command"],
        ]
        try:
            consumer = subprocess.Popen(
                arguments,
                stdin=subprocess.PIPE,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                env=environment,
                close_fds=True,
                bufsize=0,
            )
        except (OSError, subprocess.SubprocessError):
            _fail("The pinned SSH recovery consumer could not be started safely.")
        view = None
        try:
            descriptor = consumer.stdin.fileno()
            view = memoryview(secret)
            offset = 0
            while offset < len(view):
                written = os.write(descriptor, view[offset:])
                if written <= 0:
                    raise BrokenPipeError
                offset += written
            consumer.stdin.close()
            consumer.wait(timeout=_PROCESS_TIMEOUT_SECONDS)
        except (BrokenPipeError, OSError):
            if consumer.poll() is None:
                consumer.kill()
                consumer.wait()
            _fail("The pinned SSH recovery consumer rejected the protected input.")
        except subprocess.TimeoutExpired:
            if consumer.poll() is None:
                consumer.kill()
                consumer.wait()
            _fail("The pinned SSH recovery consumer timed out and was terminated.")
        finally:
            if view is not None:
                view.release()
        if consumer.returncode != 0:
            _fail("The pinned SSH recovery consumer failed closed.")
    finally:
        for path in (known_hosts_path, public_key_path):
            if os.path.lexists(path):
                os.unlink(path)
        os.rmdir(temporary_root)


def _consume(config, check_mode=False):
    _ssh_path, known_host_line = _validate_controller_paths(config)
    client, public_identity, operator_user_uuid = _inspect_boundaries(config)
    result = {
        "changed": False,
        "unlocked": False,
        "password_item_id": config["password"]["item_id"],
        "password_item_version": config["password"]["item_version"],
        "ssh_item_id": config["ssh_key"]["item_id"],
        "ssh_item_version": config["ssh_key"]["item_version"],
        "ssh_fingerprint": public_identity["fingerprint"],
        "operator_user_uuid": operator_user_uuid,
        "approval": safe_approval_metadata(config["approval"]),
        "core_dumps_disabled": False,
        "destination": "{0}@{1}:{2}".format(
            config["destination_user"],
            config["destination_host"],
            config["destination_port"],
        ),
    }
    if check_mode:
        return result
    claim_approval(config["approval"])
    result["core_dumps_disabled"] = _disable_core_dumps()
    secret = _read_secret_bytes(client, config["password"])
    try:
        _revalidate_password_item(
            client, config["password"], operator_user_uuid
        )
        _revalidate_ssh_item(
            client, config["ssh_key"], public_identity, operator_user_uuid
        )
        _run_ssh(config, known_host_line, public_identity, secret)
    finally:
        for index in range(len(secret)):
            secret[index] = 0
    result.update({"changed": True, "unlocked": True})
    return result


class ActionModule(ActionBase):
    """Controller-only exact-item SSH secret-consumer action."""

    TRANSFERS_FILES = False
    _requires_connection = False
    _supports_check_mode = True
    _VALID_ARGS = _EXPECTED_ARGS

    def run(self, tmp=None, task_vars=None):
        if task_vars is None:
            task_vars = {}
        self._task.no_log = True
        super(ActionModule, self).run(tmp, task_vars)
        config = _normalize_arguments(dict(self._task.args))
        return _consume(config, check_mode=bool(self._task.check_mode))
