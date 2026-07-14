# Copyright: (c) 2026, Lightning IT
# SPDX-License-Identifier: MIT

"""Create one immutable, controller-local Ansible Vault secret document."""

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import errno
import hashlib
import math
import os
import secrets
import stat
import string
import time
from collections.abc import Mapping

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
_MAX_DOCUMENT_DEPTH = 64
_MAX_DOCUMENT_NODES = 10000
_RACE_RETRIES = 100
_RACE_RETRY_SECONDS = 0.01
_TEMP_CREATE_RETRIES = 100


def _plain_text(value):
    """Convert Ansible unsafe text proxies into an ordinary Python string."""
    if isinstance(value, str):
        return value.encode("utf-8").decode("utf-8")
    return value


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


def _normalize_document_mapping(document):
    """Return a plain JSON-safe mapping without rendering any values in errors."""

    if not isinstance(document, Mapping):
        _fail("document must be a mapping.")

    node_count = [0]
    active_containers = set()

    def normalize(value, depth):
        node_count[0] += 1
        if node_count[0] > _MAX_DOCUMENT_NODES:
            _fail("document contains too many values.")
        if depth > _MAX_DOCUMENT_DEPTH:
            _fail("document is nested too deeply.")

        if value is None:
            return None
        if isinstance(value, bool):
            return bool(value)
        if isinstance(value, str):
            # AnsibleUnsafeText.__str__ intentionally preserves its subclass,
            # which PyYAML refuses to represent. Invoke the built-in str
            # implementation directly so no Ansible/Jinja proxy reaches the
            # serializer while the exact string value remains unchanged.
            return str.__str__(value)
        if isinstance(value, int):
            return int(value)
        if isinstance(value, float):
            if not math.isfinite(value):
                _fail("document contains a non-finite floating-point value.")
            return float(value)

        if isinstance(value, Mapping):
            container_id = id(value)
            if container_id in active_containers:
                _fail("document contains a recursive mapping or list.")
            active_containers.add(container_id)
            try:
                normalized_mapping = {}
                for key, item in value.items():
                    if not isinstance(key, str):
                        _fail("document mapping keys must be strings.")
                    normalized_key = str.__str__(key)
                    if normalized_key in normalized_mapping:
                        _fail("document contains duplicate mapping keys.")
                    normalized_mapping[normalized_key] = normalize(item, depth + 1)
                return normalized_mapping
            finally:
                active_containers.remove(container_id)

        if isinstance(value, list):
            container_id = id(value)
            if container_id in active_containers:
                _fail("document contains a recursive mapping or list.")
            active_containers.add(container_id)
            try:
                return [normalize(item, depth + 1) for item in value]
            finally:
                active_containers.remove(container_id)

        _fail("document values must be JSON-safe scalars, mappings, or lists.")

    return normalize(document, 0)


def _documents_equal(left, right):
    """Compare normalized documents without bool/int or container coercion."""

    if type(left) is not type(right):
        return False
    if isinstance(left, dict):
        return set(left) == set(right) and all(
            _documents_equal(left[key], right[key]) for key in left
        )
    if isinstance(left, list):
        return len(left) == len(right) and all(
            _documents_equal(left_item, right_item)
            for left_item, right_item in zip(left, right)
        )
    if isinstance(left, float) and left == 0.0 and right == 0.0:
        return math.copysign(1.0, left) == math.copysign(1.0, right)
    return left == right


def _normalize_integer_argument(value, name):
    """Mirror safe module int coercion for Jinja-rendered action arguments."""

    if isinstance(value, bool):
        _fail("{0} must be an integer.".format(name))
    if isinstance(value, int):
        return value
    if (
        isinstance(value, str)
        and value
        and value.isascii()
        and value.isdecimal()
    ):
        return int(value, 10)
    _fail("{0} must be an integer.".format(name))


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

    schema_version = _normalize_integer_argument(
        args.get("schema_version", 1),
        "schema_version",
    )
    if schema_version < 1:
        _fail("schema_version must be at least 1.")

    secret_field = args.get("secret_field", "recovery_passphrase")
    if not isinstance(secret_field, str) or not secret_field:
        _fail("secret_field must be a non-empty string.")
    if "\r" in secret_field or "\n" in secret_field:
        _fail("secret_field must not contain a carriage return or newline.")
    if secret_field in ("schema_version", "subject"):
        _fail("secret_field conflicts with a required schema field.")

    secret_length = _normalize_integer_argument(
        args.get("secret_length", 64),
        "secret_length",
    )
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
    """Shared controller filesystem and Vault ciphertext implementation."""

    def __init__(
        self,
        vault,
        max_ciphertext_bytes=_MAX_CIPHERTEXT_BYTES,
        max_plaintext_bytes=None,
    ):
        if (
            isinstance(max_ciphertext_bytes, bool)
            or not isinstance(max_ciphertext_bytes, int)
            or max_ciphertext_bytes < 1
        ):
            _fail("The internal ciphertext size limit is invalid.")
        if max_plaintext_bytes is None:
            max_plaintext_bytes = max_ciphertext_bytes
        if (
            isinstance(max_plaintext_bytes, bool)
            or not isinstance(max_plaintext_bytes, int)
            or max_plaintext_bytes < 1
        ):
            _fail("The internal plaintext size limit is invalid.")
        self._vault = vault
        self._max_ciphertext_bytes = max_ciphertext_bytes
        self._max_plaintext_bytes = max_plaintext_bytes

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
            "secret_length": secret_length,
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
                # Jinja-rendered action arguments may be AnsibleUnsafeText;
                # normalize before PyYAML serialization just as exact-document
                # mode does.
                "subject": _plain_text(subject),
                _plain_text(secret_field): generated_secret,
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
        except AnsibleError:
            raise AnsibleActionFail(
                "Unable to encrypt the document with the loaded Ansible Vault identity."
            ) from None
        except (TypeError, ValueError, yaml.YAMLError):
            raise AnsibleActionFail("Unable to construct the secret document safely.") from None
        finally:
            generated_secret = None
            plaintext = None
            encrypted = None

        if created:
            digest = self._load_validated(path, **validation_args)
        else:
            digest = self._load_race_winner(path, **validation_args)
        return self._result(path, created=created, exists=True, digest=digest)

    def ensure_exact(
        self,
        path,
        document,
        check_mode=False,
        vault_secret=None,
        vault_id=None,
    ):
        """Create an exact immutable mapping or validate the existing mapping."""

        expected_document = _normalize_document_mapping(document)
        try:
            ciphertext = self._read_existing(path)
        except _TransientPublicationError:
            digest = self._load_exact_race_winner(path, expected_document)
            return self._result(path, created=False, exists=True, digest=digest)

        if ciphertext is not None:
            digest = self._validate_exact_ciphertext(ciphertext, expected_document)
            return self._result(path, created=False, exists=True, digest=digest)

        if check_mode:
            return self._result(path, created=False, exists=False, digest=None, changed=True)

        plaintext = None
        encrypted = None
        try:
            plaintext = self._serialize_document(expected_document)
            encrypted = self._vault.encrypt(
                plaintext,
                secret=vault_secret,
                vault_id=vault_id,
            )
            if not isinstance(encrypted, bytes):
                encrypted = bytes(encrypted)
            if len(encrypted) > self._max_ciphertext_bytes:
                _fail("The encrypted document is unexpectedly large.")
            # Fail closed before the immutable create-if-absent publication if
            # the Vault backend produced ciphertext that cannot be read back
            # exactly with the controller's loaded identities.
            self._validate_exact_ciphertext(encrypted, expected_document)
            created = self._exclusive_create(path, encrypted)
        except AnsibleActionFail:
            raise
        except AnsibleError:
            raise AnsibleActionFail(
                "Unable to encrypt the document with the loaded Ansible Vault identity."
            ) from None
        except (TypeError, UnicodeError, ValueError, yaml.YAMLError):
            raise AnsibleActionFail("Unable to construct the document safely.") from None
        finally:
            plaintext = None
            encrypted = None

        if created:
            digest = self._load_exact_validated(path, expected_document)
        else:
            digest = self._load_exact_race_winner(path, expected_document)
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

    def _load_validated(self, path, subject, schema_version, secret_field, secret_length):
        ciphertext = self._read_existing(path)
        if ciphertext is None:
            _fail("The encrypted document disappeared during validation.")
        return self._validate_ciphertext(
            ciphertext,
            subject=subject,
            schema_version=schema_version,
            secret_field=secret_field,
            secret_length=secret_length,
        )

    def _load_race_winner(self, path, subject, schema_version, secret_field, secret_length):
        last_error = None
        for attempt in range(_RACE_RETRIES):
            try:
                return self._load_validated(
                    path,
                    subject=subject,
                    schema_version=schema_version,
                    secret_field=secret_field,
                    secret_length=secret_length,
                )
            except AnsibleActionFail as exc:
                last_error = exc
                if attempt + 1 < _RACE_RETRIES:
                    time.sleep(_RACE_RETRY_SECONDS)
        raise last_error

    def _load_exact_validated(self, path, expected_document):
        ciphertext = self._read_existing(path)
        if ciphertext is None:
            _fail("The encrypted document disappeared during validation.")
        return self._validate_exact_ciphertext(ciphertext, expected_document)

    def _load_exact_race_winner(self, path, expected_document):
        last_error = None
        for attempt in range(_RACE_RETRIES):
            try:
                return self._load_exact_validated(path, expected_document)
            except AnsibleActionFail as exc:
                last_error = exc
                if attempt + 1 < _RACE_RETRIES:
                    time.sleep(_RACE_RETRY_SECONDS)
        raise last_error

    def _validate_ciphertext(self, ciphertext, subject, schema_version, secret_field, secret_length):
        document = self._decrypt_ciphertext(ciphertext)
        try:
            self._validate_document(
                document,
                subject=subject,
                schema_version=schema_version,
                secret_field=secret_field,
                secret_length=secret_length,
            )
        finally:
            document = None
        return hashlib.sha256(ciphertext).hexdigest()

    def _validate_exact_ciphertext(self, ciphertext, expected_document):
        document = self._decrypt_ciphertext(ciphertext)
        normalized_document = None
        try:
            normalized_document = _normalize_document_mapping(document)
            if not _documents_equal(normalized_document, expected_document):
                _fail("The existing document does not exactly match the requested document.")
        finally:
            document = None
            normalized_document = None
        return hashlib.sha256(ciphertext).hexdigest()

    def _serialize_document(self, document):
        plaintext = yaml.safe_dump(
            document,
            allow_unicode=True,
            default_flow_style=False,
            sort_keys=True,
        )
        if len(plaintext.encode("utf-8")) > self._max_plaintext_bytes:
            _fail("The document is unexpectedly large.")

        roundtrip_document = None
        normalized_roundtrip = None
        try:
            roundtrip_document = yaml.load(plaintext, Loader=_UniqueKeySafeLoader)
            normalized_roundtrip = _normalize_document_mapping(roundtrip_document)
            if not _documents_equal(normalized_roundtrip, document):
                _fail("The document cannot be represented as unambiguous YAML.")
        finally:
            roundtrip_document = None
            normalized_roundtrip = None
        return plaintext

    def _decrypt_ciphertext(self, ciphertext):
        plaintext = None
        document = None
        try:
            plaintext = self._vault.decrypt(ciphertext)
        except AnsibleError:
            raise AnsibleActionFail(
                "The existing document cannot be decrypted with the loaded Ansible Vault identities."
            ) from None
        except (TypeError, ValueError):
            raise AnsibleActionFail(
                "The existing document is not valid Ansible Vault ciphertext."
            ) from None

        try:
            if isinstance(plaintext, bytes):
                plaintext = plaintext.decode("utf-8", errors="strict")
            document = yaml.load(plaintext, Loader=_UniqueKeySafeLoader)
        except (UnicodeError, TypeError, ValueError, yaml.YAMLError):
            raise AnsibleActionFail(
                "The decrypted document is not valid, unambiguous UTF-8 YAML."
            ) from None
        finally:
            plaintext = None
        return document

    @staticmethod
    def _validate_document(document, subject, schema_version, secret_field, secret_length):
        if not isinstance(document, dict):
            _fail("The decrypted document must be a mapping with the exact expected schema.")
        if any(not isinstance(key, str) for key in document):
            _fail("The decrypted document contains an invalid schema key.")

        expected_keys = {"schema_version", "subject", secret_field}
        if set(document) != expected_keys:
            _fail("The decrypted document does not match the exact expected schema.")
        if (
            isinstance(document["schema_version"], bool)
            or not isinstance(document["schema_version"], int)
            or document["schema_version"] != schema_version
        ):
            _fail("The decrypted document has the wrong schema version.")
        if not isinstance(document["subject"], str) or document["subject"] != subject:
            _fail("The decrypted document is bound to a different subject.")

        value = document[secret_field]
        if not isinstance(value, str) or len(value) != secret_length:
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

    def _validate_file_stat(self, file_stat):
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
        if file_stat.st_size > self._max_ciphertext_bytes:
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
                if total > self._max_ciphertext_bytes:
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
        if len(ciphertext) > self._max_ciphertext_bytes:
            _fail("The encrypted document is unexpectedly large.")
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


_VaultDocumentStore = _VaultSecretDocumentStore


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
