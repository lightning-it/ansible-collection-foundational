# Copyright: (c) 2026, Lightning IT
# SPDX-License-Identifier: MIT

"""Send one pinned 1Password secret to one pinned SSH session over stdin."""

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile

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
    _write_controller_file,
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
  cli_version:
    type: str
    required: true
  account_id:
    type: str
    required: true
  account_sign_in_address:
    type: str
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
  ssh_add_path:
    type: path
    required: true
  ssh_keygen_path:
    type: path
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
  remote_command:
    type: str
    choices: [/bin/cryptroot-unlock]
    required: true
  confirmation:
    type: str
    required: true
notes:
  - The action supports only SSH public-key authentication through the exact approved Agent socket.
  - The SSH host key must already be present in the exact protected known-hosts file.
  - The action always disables PTY allocation, executes C(/bin/cryptroot-unlock) explicitly, sends the passphrase
    without a newline, and closes SSH standard input. Debian cryptroot-unlock uses EOF-delimited C(cat) input in its
    non-interactive path.
  - Check mode validates item identities, public fingerprints, files, and Agent availability but does not read the
    password or open an SSH connection.
  - This action does not reboot, create, edit, rotate, export, archive, or delete any 1Password item.
author:
  - Lightning IT (@lightning-it)
"""

EXAMPLES = r"""
---
- name: Unlock one encrypted host without exposing the passphrase to Ansible
  lit.foundational.onepassword_ssh_secret_stdin:
    cli_path: /usr/local/bin/op
    cli_version: 2.38.1
    account_id: aaaaaaaaaaaaaaaaaaaaaaaaaa
    account_sign_in_address: example.1password.com
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
    ssh_add_path: /usr/bin/ssh-add
    ssh_keygen_path: /usr/bin/ssh-keygen
    agent_socket_path: /absolute/path/to/1password/agent.sock
    known_hosts_path: /absolute/path/to/dropbear-known-hosts
    destination_host: host01.example.test
    destination_port: 2222
    remote_command: /bin/cryptroot-unlock
    confirmation: UNLOCK:host01.example.test
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
"""


_EXPECTED_ARGS = frozenset(
    (
        "cli_path",
        "cli_version",
        "account_id",
        "account_sign_in_address",
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
        "ssh_add_path",
        "ssh_keygen_path",
        "agent_socket_path",
        "known_hosts_path",
        "destination_host",
        "destination_user",
        "destination_port",
        "remote_command",
        "confirmation",
    )
)
_HOST_PATTERN = re.compile(
    r"[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?\Z", re.ASCII
)
_USER_PATTERN = re.compile(r"[a-z_][a-z0-9_-]{0,31}\Z", re.ASCII)
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


def _canonical_path(value, name):
    if not isinstance(value, str) or not value or not os.path.isabs(value):
        _fail("{0} must be a non-empty absolute path.".format(name))
    if os.path.normpath(value) != value or any(character in value for character in "\x00\r\n"):
        _fail("{0} must be an exact normalized path.".format(name))
    try:
        resolved = Path(value).resolve(strict=True)
    except OSError:
        _fail("{0} does not resolve to an existing controller object.".format(name))
    if str(resolved) != value:
        _fail("{0} must be canonical and may not traverse a symbolic link.".format(name))
    return resolved


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
    if remote_command != "/bin/cryptroot-unlock":
        _fail("remote_command must be exactly /bin/cryptroot-unlock.")
    subject = args.get("subject")
    confirmation = args.get("confirmation")
    if confirmation != "UNLOCK:{0}".format(subject):
        _fail("confirmation must be the exact fresh UNLOCK:<subject> value.")

    common = {
        "cli_path": args.get("cli_path"),
        "cli_version": args.get("cli_version"),
        "account_id": args.get("account_id"),
        "account_sign_in_address": args.get("account_sign_in_address"),
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
            confirmation="",
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
            confirmation="",
            ssh_add_path=args.get("ssh_add_path"),
            ssh_keygen_path=args.get("ssh_keygen_path"),
            agent_socket_path=args.get("agent_socket_path"),
        )
    )
    return {
        "password": password,
        "ssh_key": ssh_key,
        "ssh_path": args.get("ssh_path"),
        "known_hosts_path": args.get("known_hosts_path"),
        "destination_host": destination_host,
        "destination_user": destination_user,
        "destination_port": destination_port,
        "remote_command": remote_command,
        "confirmation": confirmation,
    }


def _validate_controller_paths(config):
    ssh_path = _canonical_path(config["ssh_path"], "ssh_path")
    if not ssh_path.is_file() or not os.access(str(ssh_path), os.X_OK):
        _fail("ssh_path must be an executable regular file.")
    known_hosts_path = _canonical_path(config["known_hosts_path"], "known_hosts_path")
    status = os.lstat(str(known_hosts_path))
    if not stat.S_ISREG(status.st_mode):
        _fail("known_hosts_path must be a regular file.")
    if status.st_uid != os.getuid() or status.st_mode & 0o022:
        _fail("known_hosts_path must be controller-owned and not group/world-writable.")
    if status.st_nlink != 1:
        _fail("known_hosts_path must have exactly one filesystem link.")
    if status.st_size < 1 or status.st_size > 1048576:
        _fail("known_hosts_path must contain a bounded exact host-key pin set.")
    return str(ssh_path), str(known_hosts_path)


def _inspect_boundaries(config):
    client = _OnePasswordCLI(
        config["password"]["cli_path"],
        config["password"]["account_id"],
    )
    password_observed = _OnePasswordSecretItemStore(client).inspect(config["password"])
    if not password_observed["exists"] or password_observed["item_id"] != config["password"]["item_id"]:
        _fail("The exact pinned Password item is absent.")
    ssh_store = _OnePasswordSSHKeyItemStore(client)
    ssh_observed = ssh_store.inspect(config["ssh_key"])
    if not ssh_observed["exists"] or ssh_observed["item_id"] != config["ssh_key"]["item_id"]:
        _fail("The exact pinned SSH Key item is absent.")
    public_identity = ssh_store.public_metadata(
        config["ssh_key"],
        ssh_observed["item_id"],
        ssh_observed["item_version"],
    )
    ssh_store.verify_agent(config["ssh_key"], public_identity)
    return client, public_identity


def _read_secret_bytes(client, password_config):
    if not os.path.exists("/dev/fd"):
        _fail("The controller cannot provide the required inherited descriptor boundary.")
    read_descriptor, write_descriptor = os.pipe()
    secret = bytearray()
    try:
        reference = "op://{0}/{1}/{2}".format(
            password_config["vault_id"],
            password_config["item_id"],
            password_config["field_id"],
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
        try:
            producer.wait(timeout=_PROCESS_TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired:
            producer.kill()
            producer.wait()
            _fail("1Password secret transport timed out and was terminated.")
        if producer.returncode != 0:
            _fail("1Password secret transport failed closed.")
        while len(secret) <= _MAX_SECRET_BYTES:
            chunk = os.read(read_descriptor, _MAX_SECRET_BYTES + 1 - len(secret))
            if not chunk:
                break
            secret.extend(chunk)
        if len(secret) != password_config["password_length"]:
            _fail("1Password returned an unexpected recovery-secret length.")
        if any(value in secret for value in (0, 10, 13)):
            _fail("1Password returned an invalid recovery-secret value.")
        return secret
    except Exception:
        for index in range(len(secret)):
            secret[index] = 0
        raise
    finally:
        os.close(read_descriptor)
        if write_descriptor >= 0:
            os.close(write_descriptor)


def _revalidate_password_item(client, password_config):
    observed = _OnePasswordSecretItemStore(client).inspect(password_config)
    if (
        observed["item_id"] != password_config["item_id"]
        or observed["item_version"] != password_config["item_version"]
    ):
        _fail("The pinned Password item changed while its value was transported.")


def _revalidate_ssh_item(client, ssh_config, public_identity):
    store = _OnePasswordSSHKeyItemStore(client)
    observed = store.inspect(ssh_config)
    if (
        observed["item_id"] != ssh_config["item_id"]
        or observed["item_version"] != ssh_config["item_version"]
    ):
        _fail("The pinned SSH Key item changed while the recovery secret was transported.")
    current_identity = store.public_metadata(
        ssh_config,
        observed["item_id"],
        observed["item_version"],
    )
    if current_identity != public_identity:
        _fail("The pinned SSH public identity changed before recovery consumption.")


def _run_ssh(config, ssh_path, known_hosts_path, public_identity, secret):
    environment = {
        "HOME": os.environ.get("HOME", ""),
        "PATH": os.environ.get("PATH", ""),
        "SSH_AUTH_SOCK": config["ssh_key"]["agent_socket_path"],
    }
    for name in ("LANG", "LC_ALL"):
        if os.environ.get(name):
            environment[name] = os.environ[name]
    if not environment["HOME"]:
        _fail("HOME is required for the approved 1Password SSH Agent.")
    temporary_root = tempfile.mkdtemp(prefix="lit-onepassword-ssh-")
    os.chmod(temporary_root, 0o700)
    public_key_path = os.path.join(temporary_root, "identity.pub")
    try:
        _write_controller_file(
            public_key_path,
            (public_identity["public_key"] + "\n").encode("ascii"),
        )
        arguments = [
            ssh_path,
            "-F",
            "/dev/null",
            "-T",
            "-o",
            "BatchMode=yes",
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
            "GlobalKnownHostsFile=/dev/null",
            "-o",
            "IdentityAgent={0}".format(config["ssh_key"]["agent_socket_path"]),
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "IdentityFile={0}".format(public_key_path),
            "-o",
            "KbdInteractiveAuthentication=no",
            "-o",
            "NumberOfPasswordPrompts=0",
            "-o",
            "PasswordAuthentication=no",
            "-o",
            "PreferredAuthentications=publickey",
            "-o",
            "ProxyCommand=none",
            "-o",
            "ProxyJump=none",
            "-o",
            "PubkeyAuthentication=yes",
            "-o",
            "RequestTTY=no",
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            "UpdateHostKeys=no",
            "-o",
            "UserKnownHostsFile={0}".format(known_hosts_path),
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
        try:
            written = consumer.stdin.write(secret)
            if written != len(secret):
                consumer.kill()
                consumer.wait()
                _fail("The pinned SSH recovery consumer accepted incomplete protected input.")
            consumer.stdin.close()
            consumer.wait(timeout=_PROCESS_TIMEOUT_SECONDS)
        except (BrokenPipeError, OSError):
            consumer.kill()
            consumer.wait()
            _fail("The pinned SSH recovery consumer rejected the protected input.")
        except subprocess.TimeoutExpired:
            consumer.kill()
            consumer.wait()
            _fail("The pinned SSH recovery consumer timed out and was terminated.")
        if consumer.returncode != 0:
            _fail("The pinned SSH recovery consumer failed closed.")
    finally:
        if os.path.lexists(public_key_path):
            os.unlink(public_key_path)
        os.rmdir(temporary_root)


def _consume(config, check_mode=False):
    ssh_path, known_hosts_path = _validate_controller_paths(config)
    client, public_identity = _inspect_boundaries(config)
    result = {
        "changed": False,
        "unlocked": False,
        "password_item_id": config["password"]["item_id"],
        "password_item_version": config["password"]["item_version"],
        "ssh_item_id": config["ssh_key"]["item_id"],
        "ssh_item_version": config["ssh_key"]["item_version"],
        "ssh_fingerprint": public_identity["fingerprint"],
        "destination": "{0}@{1}:{2}".format(
            config["destination_user"],
            config["destination_host"],
            config["destination_port"],
        ),
    }
    if check_mode:
        return result
    secret = _read_secret_bytes(client, config["password"])
    try:
        _revalidate_password_item(client, config["password"])
        _revalidate_ssh_item(client, config["ssh_key"], public_identity)
        _run_ssh(config, ssh_path, known_hosts_path, public_identity, secret)
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
        super(ActionModule, self).run(tmp, task_vars)
        config = _normalize_arguments(dict(self._task.args))
        return _consume(config, check_mode=bool(self._task.check_mode))
