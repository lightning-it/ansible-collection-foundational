#!/usr/bin/env bash
set -euo pipefail

COLLECTION_NAMESPACE="${COLLECTION_NAMESPACE:-lit}"
COLLECTION_NAME="${COLLECTION_NAME:-foundational}"

bash scripts/wunder-devtools-ee.sh bash -lc '
  set -e

  ns="${COLLECTION_NAMESPACE}"
  name="${COLLECTION_NAME}"

  # 1) Build + install collection into /tmp/wunder/collections
  /workspace/scripts/devtools-collection-prepare.sh

  # 2) Switch into installed collection root
  cd /tmp/wunder/collections/ansible_collections/${ns}/${name}

  # 3) Use versions passed from CI (with defaults)
  core_ver="${ANSIBLE_CORE_VERSION:-2.15.13}"
  lint_ver="${ANSIBLE_LINT_VERSION:-6.22.2}"

  python3 -m pip install --upgrade \
    "ansible-core==${core_ver}" \
    "ansible-lint==${lint_ver}"

  export ANSIBLE_CONFIG="/workspace/ansible.cfg"
  export ANSIBLE_COLLECTIONS_PATHS="/tmp/wunder/collections"
  export ANSIBLE_LINT_OFFLINE=true
  export ANSIBLE_LINT_SKIP_GALAXY_INSTALL=1

  ansible-lint
'
