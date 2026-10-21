#!/usr/bin/env python3
# Copyright: (c) 2026, Lightning IT
# SPDX-License-Identifier: MIT
"""Native desktop provider adapter; no SSH server or host Ansible is required.

Invoke from an approved, digest-bound Collection installation with python3 -I -S.
The trusted outer transport supplies one ciphertext-only EE request on stdin and
captures one ciphertext-only response. It must attest this invocation separately;
the returned JSON is a provider result, not a signed execution authorization.
"""

import argparse
import os
from pathlib import Path
import re
import resource
import selectors
import sys
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--request-sha256", required=True)
    args = parser.parse_args()
    try:
        if (
            not sys.flags.isolated
            or not sys.flags.no_site
            or not re.fullmatch(r"[0-9a-f]{64}", args.request_sha256)
        ):
            raise ValueError(
                "An isolated interpreter and exact EE request pin are required."
            )
        # Only the adjacent approved Collection is importable, never cwd/PYTHONPATH
        # or user-site packages. The outer launcher pins this complete installation.
        root = Path(__file__).resolve(strict=True).parents[1]
        sys.path.insert(0, str(root))
        from plugins.module_utils.luks_header_native_handoff import (
            MAX_HANDOFF,
            canonical,
            decode,
            execute_request,
        )

        _, hard = resource.getrlimit(resource.RLIMIT_CORE)
        resource.setrlimit(resource.RLIMIT_CORE, (0, hard))
        data = bytearray()
        deadline = time.monotonic() + 30
        descriptor = sys.stdin.fileno()
        os.set_blocking(descriptor, False)
        with selectors.DefaultSelector() as selector:
            selector.register(descriptor, selectors.EVENT_READ)
            while True:
                if time.monotonic() >= deadline:
                    raise ValueError("Native request input timed out.")
                if not selector.select(timeout=0.2):
                    continue
                chunk = os.read(descriptor, min(65536, MAX_HANDOFF + 1 - len(data)))
                if not chunk:
                    break
                data.extend(chunk)
                if len(data) > MAX_HANDOFF:
                    raise ValueError("Native request exceeded its bound.")
        response = execute_request(decode(bytes(data)), args.request_sha256)
        sys.stdout.buffer.write(canonical(response) + b"\n")
        sys.stdout.buffer.flush()
        return 0
    except Exception:
        # Do not print CLI bodies, source input, signing objects or tracebacks.
        sys.stderr.write(
            "Native header custody stopped; inspect provider outcome before retry.\n"
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
