"""Isolated HTTPS KV2 fixture; random temporary credentials, never production."""

import base64
from datetime import datetime, timedelta, timezone
import hashlib
from http.server import BaseHTTPRequestHandler, HTTPServer
import ipaddress
import json
import os
from pathlib import Path
import secrets
import signal
import ssl
import subprocess
import sys
import time

from ansible.parsing.vault import VaultLib, VaultSecret
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
import yaml

_CHILDREN = {}


def initialize(root):
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    (root / "endpoint.json").unlink(missing_ok=True)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "isolated-header-fixture")]
    )
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
            ),
            False,
        )
        .sign(key, hashes.SHA256())
    )
    (root / "key.pem").write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    (root / "ca.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (root / "key.pem").chmod(0o600)
    raw = b"isolated-synthetic-header-for-provider-transport"
    document = {
        "schema_version": 1,
        "subject": "host01.example.test",
        "luks_format": "luks2",
        "luks_uuid": "11111111-2222-4333-8444-555555555555",
        "luks_header_b64": base64.b64encode(raw).decode(),
        "luks_header_raw_size_bytes": len(raw),
        "luks_header_sha256_raw": hashlib.sha256(raw).hexdigest(),
    }
    secret = (root / "vault-password").read_bytes().strip()
    vault = VaultLib([("fixture", VaultSecret(secret))])
    ciphertext = vault.encrypt(yaml.safe_dump(document))
    (root / "header.vault.yml").write_bytes(ciphertext)
    (root / "header.vault.yml").chmod(0o600)
    (root / "fixture.json").write_text(
        json.dumps(
            {
                "token": secrets.token_hex(24),
                "ciphertext_sha256": hashlib.sha256(ciphertext).hexdigest(),
            }
        )
    )
    (root / "fixture.json").chmod(0o600)
    child = subprocess.Popen(
        [sys.executable, __file__, "serve", str(root)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    (root / "pid").write_text(str(child.pid))
    _CHILDREN[str(root)] = child
    for _ in range(100):
        if (root / "endpoint.json").exists():
            return
        if child.poll() is not None:
            raise ValueError("Isolated fixture server did not start.")
        time.sleep(0.05)
    child.terminate()
    raise ValueError("Isolated fixture startup timed out.")


def serve(root):
    token = json.loads((root / "fixture.json").read_text())["token"]
    rows = {}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def reply(self, status, data):
            body = json.dumps(data).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            if self.headers.get("X-Vault-Token") != token:
                return self.reply(403, {})
            if self.path == "/v1/redirect":
                self.send_response(302)
                self.send_header("Location", "/v1/unexpected")
                self.end_headers()
                return
            if "/data/" in self.path:
                row = rows.get(self.path)
                return (
                    self.reply(
                        200,
                        {
                            "data": {
                                "data": row,
                                "metadata": {
                                    "version": 1,
                                    "destroyed": False,
                                    "deletion_time": "",
                                },
                            }
                        },
                    )
                    if row
                    else self.reply(404, {})
                )
            if "/metadata/" in self.path:
                row = rows.get(self.path.replace("/metadata/", "/data/", 1))
                return self.reply(200 if row else 404, {"data": {"current_version": 1}})
            return self.reply(404, {})

        def do_POST(self):
            if self.headers.get("X-Vault-Token") != token:
                return self.reply(403, {})
            size = int(self.headers.get("Content-Length", "0"))
            if not 0 < size <= 1024 * 1024:
                return self.reply(413, {})
            data = json.loads(self.rfile.read(size))
            if (
                self.path in rows
                or data.get("options") != {"cas": 0}
                or "/data/" not in self.path
            ):
                return self.reply(400, {})
            rows[self.path] = data["data"]
            return self.reply(200, {"data": {"version": 1}})

    server = HTTPServer(("127.0.0.1", 0), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(root / "ca.pem"), str(root / "key.pem"))
    server.socket = context.wrap_socket(server.socket, server_side=True)
    (root / "endpoint.json").write_text(
        json.dumps({"url": "https://127.0.0.1:" + str(server.server_port)})
    )
    server.serve_forever()


def stop(root):
    marker = root / "pid"
    if not marker.exists():
        return
    pid = int(marker.read_text())
    process = Path("/proc") / str(pid)
    if process.exists():
        arguments = (process / "cmdline").read_bytes().split(b"\x00")
        if (
            str(root).encode() not in arguments
            or b"serve" not in arguments
            or process.stat().st_uid != os.geteuid()
        ):
            raise ValueError("Refuse to stop an unrelated fixture process.")
        os.kill(pid, signal.SIGTERM)
    child = _CHILDREN.pop(str(root), None)
    if child is not None:
        child.wait(timeout=10)
    marker.unlink()


if __name__ == "__main__":
    {"initialize": initialize, "serve": serve, "stop": stop}[sys.argv[1]](
        Path(sys.argv[2])
    )
