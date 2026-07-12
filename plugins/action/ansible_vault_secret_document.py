# Copyright: (c) 2026, Lightning IT
# SPDX-License-Identifier: MIT

"""Create one immutable, controller-local Ansible Vault secret document."""

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import errno
import hashlib
import os
import secrets
import stat
import string
import time

import yaml

from ansible.errors import AnsibleActionFail, AnsibleError
from ansible.parsing.vault import VaultLib
from ansible.plugins.action import ActionBase


DOCUMENTATION = r"""
---
module: ansible_vault_secret_document
short_description: Create an immutable local Ansible Vault secret document
version_added: "1.27.0"
description:
  - Creates one encrypted YAML document on the Ansible controller.
  - Uses the Vault identity already loaded by Ansible; no Vault password is accepted as an argument.
  - Existing documents are immutable and must decrypt and match the requested schema exactly.
options:
  path:
    description:
      - Controller-local path of the encrypted document.
    type: path
    required: true
  subject:
    description:
      - Identity that the encrypted document is bound to.
    type: str
    required: true
  schema_version:
    description:
      - Expected document schema version.
    type: int
    default: 1
  secret_field:
    description:
      - Name of the field containing the generated secret.
    type: str
    default: recovery_passphrase
  secret_length:
    description:
      - Length of a newly generated alphanumeric secret.
    type: int
    default: 64
notes:
  - This is an action plugin and only accesses the controller filesystem.
  - Check mode validates an existing document. For an absent document it reports that creation is needed without
    generating or encrypting a secret.
author:
  - Lightning IT
"""

EXAMPLES = r"""
---
- name: Ensure the encrypted recovery document exists
  lit.foundational.ansible_vault_secret_document:
    path: /secure/inventory/recovery/example.vault.yml
    subject: "{{ inventory_hostname }}"
"""

RETURN = r"""
created:
  description: Whether this invocation won the create-if-absent operation.
  returned: always
  type: bool
exists:
  description: Whether a valid encrypted document exists after this invocation.
  returned: always
  type: bool
path:
  description: Absolute controller-local document path.
  returned: always
  type: str
ciphertext_sha256:
  description: SHA-256 of the persisted ciphertext, or null for an absent document in check mode.
  returned: always
  type: str
"""


_ALPHANUMERIC = string.ascii_letters + string.digits
_EXPECTED_ARGS = frozenset(
    ("path", "subject", "schema_version", "secret_field", "secret_length")
)
_MAX_CIPHERTEXT_BYTES = 1024 * 1024
_RACE_RETRIES = 100
_RACE_RETRY_SECONDS = 0.01
_TEMP_CREATE_RETRIES = 100


class _UniqueKeySafeLoader(yaml.SafeLoader):
    """Safe YAML loader that rejects duplicate mapping keys."""


def _construct_unique_mapping(loader, node, deep=False):
    loader.flatten_mapping(node)
    mapping = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        try:
            duplicate = key in mapping
        except TypeError as exc:
            raise yaml.constructor.ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                "found an unhashable key",
                key_node.start_mark,
            ) from exc
        if duplicate:
            raise yaml.constructor.ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                "found a duplicate key",
                key_node.start_mark,
            )
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


_UniqueKeySafeLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)


class _TransientPublicationError(AnsibleActionFail):
    """An atomic hard-link publication is not fully settled yet."""


def _fail(message):
    raise AnsibleActionFail(message)


def _normalize_arguments(args):
    unknown = set(args).difference(_EXPECTED_ARGS)
    if unknown:
        _fail("Unsupported arguments: {0}.".format(", ".join(sorted(unknown))))

    path = args.get("path")
    if not isinstance(path, str) or not path.strip():
        _fail("path must be a non-empty string.")
    if "\x00" in path or "\r" in path or "\n" in path:
        _fail("path contains an invalid character.")
    path = os.path.abspath(os.path.expanduser(path))
    if path == os.path.sep or not os.path.basename(path):
        _fail("path must identify a file, not a directory.")

    subject = args.get("subject")
    if not isinstance(subject, str) or not subject:
        _fail("subject must be a non-empty string.")
    if "\r" in subject or "\n" in subject:
        _fail("subject must not contain a carriage return or newline.")

    schema_version = args.get("schema_version", 1)
    if isinstance(schema_version, bool) or not isinstance(schema_version, int):
        _fail("schema_version must be an integer.")
    if schema_version < 1:
        _fail("schema_version must be at least 1.")

    secret_field = args.get("secret_field", "recovery_passphrase")
    if not isinstance(secret_field, str) or not secret_field:
        _fail("secret_field must be a non-empty string.")
    if "\r" in secret_field or "\n" in secret_field:
        _fail("secret_field must not contain a carriage return or newline.")
    if secret_field in ("schema_version", "subject"):
        _fail("secret_field conflicts with a required schema field.")

    secret_length = args.get("secret_length", 64)
    if isinstance(secret_length, bool) or not isinstance(secret_length, int):
        _fail("secret_length must be an integer.")
    if secret_length < 40:
        _fail("secret_length must be at least 40.")

    return {
        "path": path,
        "subject": subject,
        "schema_version": schema_version,
        "secret_field": secret_field,
        "secret_length": secret_length,
    }


class _VaultSecretDocumentStore:
    """Filesystem and ciphertext implementation kept separate for unit testing."""

    def __init__(self, vault):
        self._vault = vault

    def ensure(
        self,
        path,
        subject,
        schema_version=1,
        secret_field="recovery_passphrase",
        secret_length=64,
        check_mode=False,
    ):
        validation_args = {
            "subject": subject,
            "schema_version": schema_version,
            "secret_field": secret_field,
        }
        try:
            ciphertext = self._read_existing(path)
        except _TransientPublicationError:
            digest = self._load_race_winner(path, **validation_args)
            return self._result(path, created=False, exists=True, digest=digest)
        if ciphertext is not None:
            digest = self._validate_ciphertext(
                ciphertext,
                **validation_args,
            )
            return self._result(path, created=False, exists=True, digest=digest)

        if check_mode:
            return self._result(path, created=False, exists=False, digest=None, changed=True)

        generated_secret = None
        plaintext = None
        encrypted = None
        try:
            generated_secret = "".join(
                secrets.choice(_ALPHANUMERIC) for unused in range(secret_length)
            )
            document = {
                "schema_version": schema_version,
                "subject": subject,
                secret_field: generated_secret,
            }
            plaintext = yaml.safe_dump(
                document,
                allow_unicode=True,
                default_flow_style=False,
                sort_keys=False,
            )
            encrypted = self._vault.encrypt(plaintext)
            if not isinstance(encrypted, bytes):
                encrypted = bytes(encrypted)
            created = self._exclusive_create(path, encrypted)
        except AnsibleActionFail:
            raise
        except AnsibleError as exc:
            raise AnsibleActionFail(
                "Unable to encrypt the document with the loaded Ansible Vault identity."
            ) from exc
        except (TypeError, ValueError, yaml.YAMLError) as exc:
            raise AnsibleActionFail("Unable to construct the secret document safely.") from exc
        finally:
            generated_secret = None
            plaintext = None
            encrypted = None

        if created:
            digest = self._load_validated(path, **validation_args)
        else:
            digest = self._load_race_winner(path, **validation_args)
        return self._result(path, created=created, exists=True, digest=digest)

    @staticmethod
    def _result(path, created, exists, digest, changed=None):
        return {
            "changed": created if changed is None else changed,
            "created": created,
            "exists": exists,
            "path": path,
            "ciphertext_sha256": digest,
        }

    def _load_validated(self, path, subject, schema_version, secret_field):
        ciphertext = self._read_existing(path)
        if ciphertext is None:
            _fail("The encrypted document disappeared during validation.")
        return self._validate_ciphertext(
            ciphertext,
            subject=subject,
            schema_version=schema_version,
            secret_field=secret_field,
        )

    def _load_race_winner(self, path, subject, schema_version, secret_field):
        last_error = None
        for attempt in range(_RACE_RETRIES):
            try:
                return self._load_validated(
                    path,
                    subject=subject,
                    schema_version=schema_version,
                    secret_field=secret_field,
                )
            except AnsibleActionFail as exc:
                last_error = exc
                if attempt + 1 < _RACE_RETRIES:
                    time.sleep(_RACE_RETRY_SECONDS)
        raise last_error

    def _validate_ciphertext(self, ciphertext, subject, schema_version, secret_field):
        plaintext = None
        document = None
        try:
            plaintext = self._vault.decrypt(ciphertext)
        except AnsibleError as exc:
            raise AnsibleActionFail(
                "The existing document cannot be decrypted with the loaded Ansible Vault identities."
            ) from exc
        except (TypeError, ValueError) as exc:
            raise AnsibleActionFail("The existing document is not valid Ansible Vault ciphertext.") from exc

        try:
            if isinstance(plaintext, bytes):
                plaintext = plaintext.decode("utf-8", errors="strict")
            document = yaml.load(plaintext, Loader=_UniqueKeySafeLoader)
        except (UnicodeError, TypeError, ValueError, yaml.YAMLError) as exc:
            raise AnsibleActionFail(
                "The decrypted document is not valid, unambiguous UTF-8 YAML."
            ) from exc
        finally:
            plaintext = None

        try:
            self._validate_document(
                document,
                subject=subject,
                schema_version=schema_version,
                secret_field=secret_field,
            )
        finally:
            document = None
        return hashlib.sha256(ciphertext).hexdigest()

    @staticmethod
    def _validate_document(document, subject, schema_version, secret_field):
        if not isinstance(document, dict):
            _fail("The decrypted document must be a mapping with the exact expected schema.")
        if any(not isinstance(key, str) for key in document):
            _fail("The decrypted document contains an invalid schema key.")

        expected_keys = {"schema_version", "subject", secret_field}
        if set(document) != expected_keys:
            _fail("The decrypted document does not match the exact expected schema.")
        if document["schema_version"] != schema_version:
            _fail("The decrypted document has the wrong schema version.")
        if document["subject"] != subject:
            _fail("The decrypted document is bound to a different subject.")

        value = document[secret_field]
        if not isinstance(value, str) or len(value) < 40:
            _fail("The decrypted document does not contain a valid secret field.")
        if "\r" in value or "\n" in value:
            _fail("The decrypted document secret field contains a forbidden line break.")

    @staticmethod
    def _directory_flags():
        if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
            _fail("This controller cannot provide secure no-follow filesystem operations.")
        return os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)

    def _open_parent(self, path, create):
        parent, name = os.path.split(path)
        if not name:
            _fail("path must identify a file.")

        flags = self._directory_flags()
        current_fd = os.open(os.path.sep, flags)
        try:
            components = [part for part in parent.split(os.path.sep) if part]
            for component in components:
                made_directory = False
                try:
                    child_fd = os.open(component, flags, dir_fd=current_fd)
                except FileNotFoundError:
                    if not create:
                        os.close(current_fd)
                        return None, name
                    try:
                        os.mkdir(component, mode=0o700, dir_fd=current_fd)
                        made_directory = True
                    except FileExistsError:
                        pass
                    try:
                        child_fd = os.open(component, flags, dir_fd=current_fd)
                    except OSError as exc:
                        _fail("A parent path component cannot be opened securely.")
                except OSError as exc:
                    if exc.errno in (errno.ELOOP, errno.ENOTDIR):
                        _fail("A parent path component is a symlink or is not a directory.")
                    _fail("A parent path component cannot be opened securely.")

                if made_directory:
                    os.fchmod(child_fd, 0o700)
                    if stat.S_IMODE(os.fstat(child_fd).st_mode) != 0o700:
                        os.close(child_fd)
                        _fail("A newly created parent directory does not have mode 0700.")
                os.close(current_fd)
                current_fd = child_fd
            return current_fd, name
        except BaseException:
            try:
                os.close(current_fd)
            except OSError:
                pass
            raise

    @staticmethod
    def _validate_file_stat(file_stat):
        if not stat.S_ISREG(file_stat.st_mode):
            _fail("The existing document is a symlink or is not a regular file.")
        if file_stat.st_uid != os.geteuid():
            _fail("The existing document is not owned by the controller user.")
        mode = stat.S_IMODE(file_stat.st_mode)
        if not mode & stat.S_IRUSR or mode & 0o077 or mode & 0o7000:
            _fail("The existing document has insecure permissions.")
        if file_stat.st_nlink != 1:
            raise _TransientPublicationError(
                "The existing document has an unsafe hard-link count."
            )
        if file_stat.st_size > _MAX_CIPHERTEXT_BYTES:
            _fail("The existing encrypted document is unexpectedly large.")

    def _read_existing(self, path):
        parent_fd, name = self._open_parent(path, create=False)
        if parent_fd is None:
            return None

        file_fd = None
        try:
            try:
                path_stat = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            except FileNotFoundError:
                return None
            self._validate_file_stat(path_stat)

            flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
            try:
                file_fd = os.open(name, flags, dir_fd=parent_fd)
            except OSError as exc:
                raise AnsibleActionFail(
                    "The existing document cannot be opened securely."
                ) from exc

            opened_stat = os.fstat(file_fd)
            self._validate_file_stat(opened_stat)
            if (path_stat.st_dev, path_stat.st_ino) != (opened_stat.st_dev, opened_stat.st_ino):
                _fail("The existing document changed during secure inspection.")

            chunks = []
            total = 0
            while True:
                chunk = os.read(file_fd, 65536)
                if not chunk:
                    break
                total += len(chunk)
                if total > _MAX_CIPHERTEXT_BYTES:
                    _fail("The existing encrypted document is unexpectedly large.")
                chunks.append(chunk)

            final_fd_stat = os.fstat(file_fd)
            final_path_stat = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            self._validate_file_stat(final_fd_stat)
            if (opened_stat.st_dev, opened_stat.st_ino) != (
                final_path_stat.st_dev,
                final_path_stat.st_ino,
            ):
                _fail("The existing document changed during secure inspection.")
            if final_fd_stat.st_size != total:
                _fail("The existing document changed while it was read.")
            return b"".join(chunks)
        except FileNotFoundError as exc:
            raise AnsibleActionFail(
                "The existing document changed during secure inspection."
            ) from exc
        finally:
            if file_fd is not None:
                os.close(file_fd)
            os.close(parent_fd)

    def _exclusive_create(self, path, ciphertext):
        parent_fd, name = self._open_parent(path, create=True)
        file_fd = None
        temp_name = None
        temp_stat = None
        try:
            temp_name, file_fd = self._open_exclusive_temp(parent_fd)
            temp_stat = os.fstat(file_fd)
            os.fchmod(file_fd, 0o600)
            self._write_ciphertext(file_fd, ciphertext)
            os.fsync(file_fd)
            final_temp_stat = os.fstat(file_fd)
            if stat.S_IMODE(final_temp_stat.st_mode) != 0o600:
                _fail("The staged encrypted document does not have mode 0600.")
            if final_temp_stat.st_size != len(ciphertext):
                _fail("The staged encrypted document was not written completely.")
            named_temp_stat = os.stat(
                temp_name,
                dir_fd=parent_fd,
                follow_symlinks=False,
            )
            if (temp_stat.st_dev, temp_stat.st_ino) != (
                named_temp_stat.st_dev,
                named_temp_stat.st_ino,
            ):
                _fail("The staged encrypted document changed before publication.")

            try:
                self._link_no_replace(parent_fd, temp_name, name)
                created = True
            except FileExistsError:
                created = False

            self._unlink_owned_temp(parent_fd, temp_name, temp_stat)
            temp_name = None
            os.fsync(parent_fd)
            return created
        except AnsibleActionFail:
            raise
        except (OSError, TypeError, ValueError) as exc:
            raise AnsibleActionFail(
                "The encrypted document could not be persisted atomically."
            ) from exc
        finally:
            if file_fd is not None:
                os.close(file_fd)
            if temp_name is not None:
                self._remove_owned_temp(parent_fd, temp_name, temp_stat)
            os.close(parent_fd)

    @staticmethod
    def _open_exclusive_temp(parent_fd):
        flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | os.O_NOFOLLOW
            | getattr(os, "O_CLOEXEC", 0)
        )
        for unused in range(_TEMP_CREATE_RETRIES):
            temp_name = ".ansible-vault-secret-{0}.tmp".format(secrets.token_hex(16))
            try:
                return temp_name, os.open(temp_name, flags, 0o600, dir_fd=parent_fd)
            except FileExistsError:
                continue
            except OSError as exc:
                raise AnsibleActionFail(
                    "A staged encrypted document cannot be created securely."
                ) from exc
        _fail("A unique staged encrypted document name could not be allocated.")

    @staticmethod
    def _write_ciphertext(file_fd, ciphertext):
        view = memoryview(ciphertext)
        try:
            while view:
                written = os.write(file_fd, view)
                if written <= 0:
                    raise OSError("short write while persisting ciphertext")
                view = view[written:]
        finally:
            view.release()

    @staticmethod
    def _link_no_replace(parent_fd, temp_name, target_name):
        os.link(
            temp_name,
            target_name,
            src_dir_fd=parent_fd,
            dst_dir_fd=parent_fd,
            follow_symlinks=False,
        )

    @staticmethod
    def _unlink_owned_temp(parent_fd, temp_name, temp_stat):
        current_stat = os.stat(temp_name, dir_fd=parent_fd, follow_symlinks=False)
        if (temp_stat.st_dev, temp_stat.st_ino) != (
            current_stat.st_dev,
            current_stat.st_ino,
        ):
            _fail("The staged encrypted document changed during publication.")
        os.unlink(temp_name, dir_fd=parent_fd)

    @staticmethod
    def _remove_owned_temp(parent_fd, temp_name, temp_stat):
        if temp_stat is None:
            return
        try:
            current_stat = os.stat(temp_name, dir_fd=parent_fd, follow_symlinks=False)
            if (temp_stat.st_dev, temp_stat.st_ino) == (
                current_stat.st_dev,
                current_stat.st_ino,
            ):
                os.unlink(temp_name, dir_fd=parent_fd)
        except FileNotFoundError:
            pass
        except OSError:
            pass


class ActionModule(ActionBase):
    """Ansible action-plugin entry point."""

    TRANSFERS_FILES = False
    _requires_connection = False
    _supports_check_mode = True
    _VALID_ARGS = _EXPECTED_ARGS

    def run(self, tmp=None, task_vars=None):
        if task_vars is None:
            task_vars = {}
        super(ActionModule, self).run(tmp, task_vars)

        config = _normalize_arguments(dict(self._task.args))
        vault = getattr(self._loader, "_vault", None)
        if not isinstance(vault, VaultLib) or not getattr(vault, "secrets", None):
            _fail("An Ansible Vault identity must already be loaded for this action.")

        store = _VaultSecretDocumentStore(vault)
        return store.ensure(
            path=config["path"],
            subject=config["subject"],
            schema_version=config["schema_version"],
            secret_field=config["secret_field"],
            secret_length=config["secret_length"],
            check_mode=bool(self._task.check_mode),
        )
