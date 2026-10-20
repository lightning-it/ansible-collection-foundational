# Copyright: (c) 2026, Lightning IT
# SPDX-License-Identifier: MIT
"""Bound encrypted header packages and immutable provider transactions."""

import base64
import hashlib
import json
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request
import uuid

MAX_CIPHER = 64 * 1024 * 1024
MAX_PACKAGE = MAX_CIPHER + 1024 * 1024
CHUNK_SIZE = 256 * 1024
MANIFEST_FIELDS = {
    "schema_version",
    "subject",
    "source_machine_id",
    "luks_uuid",
    "luks_header_sha256_raw",
    "luks_header_raw_size_bytes",
    "ciphertext_sha256",
    "owner",
    "retention",
    "key_retrieval_reference",
}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def canonical(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate package field.")
        result[key] = value
    return result


def validate_package(package):
    """Validate public identity, strict schema and ciphertext before provider calls."""
    if not isinstance(package, dict) or set(package) != {"manifest", "ciphertext"}:
        raise ValueError("Invalid encrypted header package.")
    m = package["manifest"]
    if not isinstance(m, dict) or set(m) != MANIFEST_FIELDS:
        raise ValueError("Invalid header manifest.")
    if type(m["schema_version"]) is not int or m["schema_version"] != 1:
        raise ValueError("Invalid header schema version.")
    if not isinstance(m["subject"], str) or not re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9._-]{0,252}", m["subject"]
    ):
        raise ValueError("Invalid header subject.")
    if not isinstance(m["source_machine_id"], str) or not re.fullmatch(
        r"[0-9a-f]{32}", m["source_machine_id"]
    ):
        raise ValueError("Invalid source identity.")
    if (
        not isinstance(m["luks_uuid"], str)
        or str(uuid.UUID(m["luks_uuid"])) != m["luks_uuid"]
    ):
        raise ValueError("Invalid source disk identity.")
    for key in ("ciphertext_sha256", "luks_header_sha256_raw"):
        if not isinstance(m[key], str) or not re.fullmatch(r"[0-9a-f]{64}", m[key]):
            raise ValueError("Invalid header checksum.")
    if (
        type(m["luks_header_raw_size_bytes"]) is not int
        or not 0 < m["luks_header_raw_size_bytes"] <= 20 * 1024 * 1024
    ):
        raise ValueError("Invalid raw header size.")
    for key in ("owner", "retention", "key_retrieval_reference"):
        if (
            not isinstance(m[key], str)
            or not m[key].strip()
            or len(m[key]) > 2048
            or any(ord(c) < 32 for c in m[key])
        ):
            raise ValueError("Explicit bounded custody metadata is required.")
    text = package["ciphertext"]
    if not isinstance(text, str) or not text.startswith("$ANSIBLE_VAULT;1."):
        raise ValueError("Only Ansible Vault ciphertext can enter provider custody.")
    raw = text.encode("ascii")
    if not 0 < len(raw) <= MAX_CIPHER or digest(raw) != m["ciphertext_sha256"]:
        raise ValueError("Ciphertext checksum or size mismatch.")
    data = canonical(package)
    if len(data) > MAX_PACKAGE:
        raise ValueError("Header package exceeds its bound.")
    return data


def decode_package(data, expected):
    if not isinstance(data, bytes) or not 0 < len(data) <= MAX_PACKAGE:
        raise ValueError("Invalid provider package size.")
    value = json.loads(data, object_pairs_hook=unique_object)
    if validate_package(value) != data or data != expected:
        raise ValueError("Provider readback does not match the exact header package.")
    return value


def safe_path(path):
    if (
        not isinstance(path, str)
        or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,511}", path)
        or any(part in ("", ".", "..") for part in path.split("/"))
    ):
        raise ValueError("An exact normalized provider path is required.")
    return path


def validate_read_pins(pins):
    if not isinstance(pins, dict) or set(pins) != {
        "package_sha256",
        "subject",
        "source_machine_id",
        "luks_uuid",
    }:
        raise ValueError("A complete independent retrieval receipt is required.")
    if (
        not isinstance(pins["package_sha256"], str)
        or not re.fullmatch(r"[0-9a-f]{64}", pins["package_sha256"])
        or not isinstance(pins["source_machine_id"], str)
        or not re.fullmatch(r"[0-9a-f]{32}", pins["source_machine_id"])
        or not isinstance(pins["subject"], str)
        or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,252}", pins["subject"])
        or not isinstance(pins["luks_uuid"], str)
        or str(uuid.UUID(pins["luks_uuid"])) != pins["luks_uuid"]
    ):
        raise ValueError("Invalid independent source/package receipt.")


def verify_download(data, pins):
    validate_read_pins(pins)
    if (
        not isinstance(data, bytes)
        or not 0 < len(data) <= MAX_PACKAGE
        or digest(data) != pins["package_sha256"]
    ):
        raise ValueError("Downloaded package differs from the independent receipt.")
    package = json.loads(data, object_pairs_hook=unique_object)
    if validate_package(package) != data or any(
        package["manifest"][key] != pins[key]
        for key in ("subject", "source_machine_id", "luks_uuid")
    ):
        raise ValueError("Downloaded package source/schema is incorrect.")
    return package


def vault_read_custody(client, mount, prefix, pins):
    validate_read_pins(pins)
    safe_path(mount)
    safe_path(prefix)
    root = prefix + "/" + pins["package_sha256"]
    manifest = client.read(mount, root + "/manifest")
    if manifest is None:
        raise ValueError("Committed Vault header manifest is absent.")
    m = manifest["data"]
    size, count = m.get("package_size_bytes"), m.get("chunk_count")
    if (
        m.get("format") != "luks-header-custody-v1"
        or m.get("package_sha256") != pins["package_sha256"]
        or type(size) is not int
        or not 0 < size <= MAX_PACKAGE
        or type(count) is not int
        or count != (size + CHUNK_SIZE - 1) // CHUNK_SIZE
    ):
        raise ValueError("Invalid committed Vault header bounds.")
    chunks = []
    for index in range(count):
        row = client.read(mount, root + "/chunk-" + str(index))
        if row is None or not isinstance(row["data"], dict):
            raise ValueError("Vault header chunk is missing.")
        chunk = row["data"]
        if (
            set(chunk) != {"index", "payload_b64", "sha256"}
            or type(chunk["index"]) is not int
            or chunk["index"] != index
            or not isinstance(chunk["payload_b64"], str)
            or len(chunk["payload_b64"]) > ((CHUNK_SIZE + 2) // 3) * 4
        ):
            raise ValueError("Invalid Vault header chunk.")
        raw = base64.b64decode(chunk["payload_b64"], validate=True)
        if digest(raw) != chunk["sha256"]:
            raise ValueError("Vault header chunk checksum mismatch.")
        chunks.append(raw)
    raw = b"".join(chunks)
    if len(raw) != size or client.read(mount, root + "/manifest") != manifest:
        raise ValueError("Vault header changed during retrieval.")
    package = verify_download(raw, pins)
    if package["manifest"] != m.get("manifest"):
        raise ValueError("Vault manifest source metadata differs from its package.")
    return {
        "changed": False,
        "verified": True,
        "package": package,
        "package_sha256": pins["package_sha256"],
        "manifest_path": root + "/manifest",
        "manifest_version": manifest["version"],
    }


class VaultHTTP:
    """Explicit credential-only HTTPS client; redirects and retries are disabled."""

    def __init__(self, auth):
        self.auth = auth
        allowed = {
            "url",
            "namespace",
            "ca_cert",
            "timeout",
            "auth_method",
            "token",
            "role_id",
            "secret_id",
            "auth_mount_point",
        }
        if not isinstance(auth, dict) or set(auth) - allowed:
            raise ValueError("Unsupported Vault authentication contract.")
        self.url = auth.get("url", "")
        parsed = urllib.parse.urlsplit(self.url)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.path not in ("", "/")
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("An exact verified HTTPS Vault origin is required.")
        ca = auth.get("ca_cert")
        if not isinstance(ca, str) or not ca.startswith("/"):
            raise ValueError("An explicit Vault CA file is required.")
        self.context = ssl.create_default_context(cafile=ca)
        self.namespace = auth.get("namespace", "")
        if self.namespace:
            safe_path(self.namespace)
        self.timeout = auth.get("timeout", 30)
        if type(self.timeout) is not int or not 1 <= self.timeout <= 120:
            raise ValueError("Invalid Vault timeout.")
        self.token = ""
        method = auth.get("auth_method")
        if method == "token":
            self.token = auth.get("token", "")
            if auth.get("role_id") or auth.get("secret_id"):
                raise ValueError("Ambiguous Vault authentication.")
        elif method == "approle":
            if auth.get("token"):
                raise ValueError("Ambiguous Vault authentication.")
            role, secret = auth.get("role_id"), auth.get("secret_id")
            if not all(
                isinstance(x, str) and 16 <= len(x) <= 4096 for x in (role, secret)
            ):
                raise ValueError("Explicit AppRole credentials are required.")
            mount = safe_path(auth.get("auth_mount_point", "approle"))
            result = self.request(
                "POST",
                "auth/" + mount + "/login",
                {"role_id": role, "secret_id": secret},
            )
            self.token = result.get("auth", {}).get("client_token", "")
        else:
            raise ValueError(
                "Only explicit token or AppRole authentication is supported."
            )
        if (
            not isinstance(self.token, str)
            or not self.token
            or any(ord(c) < 33 for c in self.token)
        ):
            raise ValueError("Vault did not supply a valid scoped credential.")

    def request(self, method, path, data=None, missing_ok=False):
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, headers, newurl):
                return None

        headers = {"Content-Type": "application/json"}
        if self.token:
            headers["X-Vault-Token"] = self.token
        if self.namespace:
            headers["X-Vault-Namespace"] = self.namespace
        request = urllib.request.Request(
            self.url.rstrip("/") + "/v1/" + safe_path(path),
            data=canonical(data) if data is not None else None,
            headers=headers,
            method=method,
        )
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            NoRedirect(),
            urllib.request.HTTPSHandler(context=self.context),
        )
        try:
            with opener.open(request, timeout=self.timeout) as response:
                payload = response.read(1024 * 1024 + 1)
                if len(payload) > 1024 * 1024:
                    raise ValueError("Vault response exceeds its bound.")
                return json.loads(payload, object_pairs_hook=unique_object)
        except urllib.error.HTTPError as error:
            if missing_ok and error.code == 404:
                return None
            raise ValueError(
                "Vault request failed; no automatic write retry."
            ) from None
        except (urllib.error.URLError, OSError):
            raise ValueError(
                "Vault transport failed; outcome may be unknown, inspect before retry."
            ) from None

    def read(self, mount, path):
        result = self.request("GET", mount + "/data/" + path, missing_ok=True)
        if result is None:
            # A deleted/destroyed version is not permission to recreate custody.
            metadata = self.request("GET", mount + "/metadata/" + path, missing_ok=True)
            if metadata is not None:
                raise ValueError("Vault custody has deleted or destroyed history.")
            return None
        data = result.get("data", {})
        meta = data.get("metadata", {})
        if (
            type(meta.get("version")) is not int
            or meta["version"] < 1
            or meta.get("destroyed")
            or meta.get("deletion_time")
        ):
            raise ValueError("Vault custody version is not live.")
        return {"data": data.get("data"), "version": meta["version"]}

    def create(self, mount, path, data):
        self.request(
            "POST", mount + "/data/" + path, {"options": {"cas": 0}, "data": data}
        )


def vault_custody(client, mount, prefix, package, operation="verify", check_mode=False):
    """Preflight every object; create-only chunks and commit manifest last."""
    safe_path(mount)
    safe_path(prefix)
    if operation not in ("plan", "apply", "verify"):
        raise ValueError("Invalid custody operation.")
    raw = validate_package(package)
    sha = digest(raw)
    root = prefix + "/" + sha
    chunks = [raw[i : i + CHUNK_SIZE] for i in range(0, len(raw), CHUNK_SIZE)]
    objects = []
    for index, chunk in enumerate(chunks):
        objects.append(
            (
                root + "/chunk-" + str(index),
                {
                    "index": index,
                    "sha256": digest(chunk),
                    "payload_b64": base64.b64encode(chunk).decode("ascii"),
                },
            )
        )
    manifest = {
        "format": "luks-header-custody-v1",
        "package_sha256": sha,
        "package_size_bytes": len(raw),
        "chunk_count": len(chunks),
        "manifest": package["manifest"],
    }
    objects.append((root + "/manifest", manifest))
    observed = []
    for path, value in objects:
        current = client.read(mount, path)
        if current is not None and current["data"] != value:
            raise ValueError(
                "Existing Vault custody conflicts; no overwrite is allowed."
            )
        observed.append(current)
    missing = any(current is None for current in observed)
    if missing and operation == "verify":
        raise ValueError("Vault custody is incomplete.")
    changed = False
    if operation == "apply" and not check_mode:
        for (path, value), current in zip(objects, observed):
            if current is None:
                client.create(mount, path, value)
                changed = True
        verified = [client.read(mount, path) for path, _ in objects]
    else:
        verified = observed
    complete = all(row is not None for row in verified)
    if complete:
        assembled = b""
        for (_, value), row in zip(objects, verified):
            if row["data"] != value:
                raise ValueError("Vault custody changed during readback.")
        for row in verified[:-1]:
            assembled += base64.b64decode(row["data"]["payload_b64"], validate=True)
        decode_package(assembled, raw)
    return {
        "changed": changed,
        "verified": complete,
        "planned": missing and not changed,
        "package_sha256": sha,
        "manifest_path": root + "/manifest",
        "manifest_version": verified[-1]["version"] if complete else None,
    }
