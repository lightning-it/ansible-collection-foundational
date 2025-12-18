#!/usr/bin/env bash
set -eo pipefail

COLLECTION_NAMESPACE="${COLLECTION_NAMESPACE:-lit}"
COLLECTION_NAME="${COLLECTION_NAME:-foundational}"
EXAMPLE_PLAYBOOK="${EXAMPLE_PLAYBOOK:-playbooks/example.yml}"

bash scripts/wunder-devtools-ee.sh bash -lc '
  set -e

  ns="${COLLECTION_NAMESPACE}"
  name="${COLLECTION_NAME}"
  example="${EXAMPLE_PLAYBOOK:-/workspace/playbooks/example.yml}"

  echo "Running collection smoke test for ${ns}.${name} with example playbook: ${example}"

  # 1) Build + install collection into /tmp/wunder/collections
  /workspace/scripts/devtools-collection-prepare.sh

  # 2) Use installed collection via ANSIBLE_COLLECTIONS_PATHS
  export ANSIBLE_COLLECTIONS_PATHS=/tmp/wunder/collections

  if [ -f /workspace/ansible.cfg ]; then
    export ANSIBLE_CONFIG=/workspace/ansible.cfg
  fi

  ansible-playbook \
    -i localhost, \
    "${example}"
'
