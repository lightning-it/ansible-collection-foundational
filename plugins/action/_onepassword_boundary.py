# Copyright: (c) 2026, Lightning IT
# SPDX-License-Identifier: MIT
"""Compatibility imports from the single packaged trust-boundary implementation."""

from ..module_utils.onepassword_boundary import (
    _write_private_file,
    approval_signing_payload,
    claim_approval,
    normalize_approval,
    normalize_approval_authority,
    normalize_sha256,
    normalize_user_uuid_list,
    safe_approval_metadata,
    trusted_agent_socket,
    trusted_executable,
    trusted_pinned_regular_file,
    trusted_regular_file,
    trusted_replay_directory,
)
