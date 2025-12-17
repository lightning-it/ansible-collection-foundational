#!/usr/bin/env bash
set -euo pipefail

# Build and install the collection inside the wunder-devtools-ee container.
# Installs into /tmp/wunder/collections for use by other helper scripts.
#
# Expected to run INSIDE the container with:
#   - /workspace mounted as the collection repo
#   - COLLECTION_NAMESPACE and COLLECTION_NAME set (defaults provided)

ns="${COLLECTION_NAMESPACE:-lit}"
name="${COLLECTION_NAME:-foundational}"

echo "Preparing collection ${ns}.${name} inside wunder-devtools-ee..."

# 1) Clean previous build + install
rm -rf /tmp/wunder/.cache/ansible-compat \
       /tmp/wunder/collections \
       /tmp/wunder/${ns}-${name}-*.tar.gz

# 2) Build collection from /workspace (mounted repo)
# Make sure we are in the repo root
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
