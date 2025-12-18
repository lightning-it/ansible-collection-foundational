#!/usr/bin/env bash
set -euo pipefail

# Build and install the collection inside the wunder-devtools-ee container.
# Installs into /tmp/wunder/collections for use by other helper scripts.
#
# Expected to run INSIDE the container with:
#   - /workspace mounted as the collection repo
#   - COLLECTION_NAMESPACE and COLLECTION_NAME optionally set

# 1) Namespace with default
ns="${COLLECTION_NAMESPACE:-lit}"

# 2) Derive collection name if not provided
if [ -z "${COLLECTION_NAME:-}" ]; then
  # Prefer GITHUB_REPOSITORY if available (CI), else use /workspace basename
  if [ -n "${GITHUB_REPOSITORY:-}" ]; then
    repo_basename="${GITHUB_REPOSITORY##*/}"
  else
    repo_basename="$(basename /workspace)"
  fi

  case "$repo_basename" in
    ansible-collection-*)
      name="${repo_basename#ansible-collection-}"
      ;;
    *)
      echo "WARN: Could not infer COLLECTION_NAME from repo name '${repo_basename}', falling back to 'foundational'" >&2
      name="foundational"
      ;;
  esac
else
  name="${COLLECTION_NAME}"
fi

echo "Preparing collection ${ns}.${name} inside wunder-devtools-ee..."

# 1) Clean previous build + install
rm -rf /tmp/wunder/.cache/ansible-compat \
       /tmp/wunder/collections \
       /tmp/wunder/${ns}-${name}-*.tar.gz

# 2) Build collection from /workspace (mounted repo)
cd /workspace

ansible-galaxy collection build \
  --output-path /tmp/wunder \
  --force

# 3) Install built collection into /tmp/wunder/collections
ansible-galaxy collection install \
  /tmp/wunder/${ns}-${name}-*.tar.gz \
  -p /tmp/wunder/collections \
  --force

echo "Collection ${ns}.${name} installed in /tmp/wunder/collections."
