"""Ephemeral asymmetric Approval Authority used only by local unit tests."""

import base64
from datetime import datetime, timedelta, timezone
import hashlib
import stat
import struct
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from plugins.action import _onepassword_boundary as boundary


AUTHORITY_IDENTITY = "approval-authority@example.test"
AUTHORITY_NAMESPACE = "lit-onepassword-approval-v1"
_SIGNING_KEYS = {}


def _write_executable(path, source):
    path.write_text("#!{0}\n{1}".format(sys.executable, source), encoding="utf-8")
    path.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)


def build_authority(tmp_path):
    """Create an ephemeral Ed25519 authority and synthetic ssh-keygen facade."""
    signing_key = Ed25519PrivateKey.generate()
    public_key_bytes = signing_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    key_blob = (
        struct.pack(">I", len(b"ssh-ed25519"))
        + b"ssh-ed25519"
        + struct.pack(">I", len(public_key_bytes))
        + public_key_bytes
    )
    authority_public_key = "ssh-ed25519 {0}".format(
        base64.b64encode(key_blob).decode("ascii")
    )
    authority_fingerprint = "SHA256:{0}".format(
        base64.b64encode(hashlib.sha256(key_blob).digest()).decode("ascii").rstrip("=")
    )

    allowed_signers = tmp_path / "approval_allowed_signers"
    allowed_signers_line = "{0} {1}\n".format(AUTHORITY_IDENTITY, authority_public_key)
    allowed_signers.write_text(allowed_signers_line, encoding="ascii")
    allowed_signers.chmod(0o600)
    _SIGNING_KEYS[str(allowed_signers)] = signing_key

    verifier = tmp_path / "approval-ssh-keygen"
    _write_executable(
        verifier,
        "import base64, binascii, pathlib, sys\n"
        "from cryptography.exceptions import InvalidSignature\n"
        "from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey\n"
        "args = sys.argv[1:]\n"
        "required = {{'-Y', 'verify', '-f', '-I', '-n', '-s'}}\n"
        "if not required.issubset(set(args)):\n"
        "    raise SystemExit(10)\n"
        "if args[args.index('-I') + 1] != {0!r}:\n"
        "    raise SystemExit(11)\n"
        "if args[args.index('-n') + 1] != {1!r}:\n"
        "    raise SystemExit(12)\n"
        "allowed_signers = pathlib.Path(args[args.index('-f') + 1]).read_text(encoding='ascii')\n"
        "if allowed_signers != {2!r}:\n"
        "    raise SystemExit(13)\n"
        "signature_text = pathlib.Path(args[args.index('-s') + 1]).read_text(encoding='ascii')\n"
        "payload = sys.stdin.buffer.read()\n"
        "lines = signature_text.splitlines()\n"
        "if len(lines) != 3 or lines[0] != '-----BEGIN SSH SIGNATURE-----' or lines[2] != '-----END SSH SIGNATURE-----':\n"
        "    raise SystemExit(14)\n"
        "try:\n"
        "    signature = base64.b64decode(lines[1], validate=True)\n"
        "    public_key = base64.b64decode({3!r}, validate=True)\n"
        "    Ed25519PublicKey.from_public_bytes(public_key).verify(signature, payload)\n"
        "except (ValueError, binascii.Error, InvalidSignature):\n"
        "    raise SystemExit(15)\n".format(
            AUTHORITY_IDENTITY,
            AUTHORITY_NAMESPACE,
            allowed_signers_line,
            base64.b64encode(public_key_bytes).decode("ascii"),
        ),
    )
    return {
        "schema_version": 1,
        "identity": AUTHORITY_IDENTITY,
        "namespace": AUTHORITY_NAMESPACE,
        "fingerprint": authority_fingerprint,
        "allowed_signers_path": str(allowed_signers),
        "allowed_signers_sha256": hashlib.sha256(
            allowed_signers.read_bytes()
        ).hexdigest(),
        "ssh_keygen_path": str(verifier),
        "ssh_keygen_sha256": hashlib.sha256(verifier.read_bytes()).hexdigest(),
    }


def build_approval(
    tmp_path,
    authority,
    operation,
    target,
    binding,
    execution_id="execution-001",
    nonce="b" * 64,
    replay_name="approval-replay",
):
    replay = tmp_path / replay_name
    replay.mkdir(mode=0o700, exist_ok=True)
    replay.chmod(0o700)
    now = datetime.now(timezone.utc).replace(microsecond=0)
    approval = {
        "schema_version": 1,
        "execution_id": execution_id,
        "commit_shas": {"foundational": "a" * 40},
        "nonce": nonce,
        "issued_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "expires_at": (now + timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "replay_directory": str(replay),
    }
    return sign_approval(approval, authority, operation, target, binding), replay, now


def sign_approval(approval, authority, operation, target, binding):
    unsigned = dict(approval)
    unsigned.pop("signature", None)
    payload = boundary.approval_signing_payload(
        unsigned, authority, operation, target, binding
    )
    signature = _SIGNING_KEYS[authority["allowed_signers_path"]].sign(payload)
    signed = dict(unsigned)
    signed["signature"] = (
        "-----BEGIN SSH SIGNATURE-----\n"
        + base64.b64encode(signature).decode("ascii")
        + "\n-----END SSH SIGNATURE-----\n"
    )
    return signed
