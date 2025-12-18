#!/usr/bin/env bash
set -eo pipefail

COLLECTION_NAMESPACE="${COLLECTION_NAMESPACE:-lit}"
COLLECTION_NAME="${COLLECTION_NAME:-foundational}"

bash scripts/wunder-devtools-ee.sh bash -lc '
  set -e

  ns="${COLLECTION_NAMESPACE}"
  name="${COLLECTION_NAME}"

  echo "Preparing collection ${ns}.${name} for Molecule tests..."

  # 1) Build + install collection into /tmp/wunder/collections
  /workspace/scripts/devtools-collection-prepare.sh

  # 2) Configure Ansible environment for Molecule
  export ANSIBLE_COLLECTIONS_PATHS=/tmp/wunder/collections

  if [ -f /workspace/ansible.cfg ]; then
    export ANSIBLE_CONFIG=/workspace/ansible.cfg
  fi

  export MOLECULE_NO_LOG="${MOLECULE_NO_LOG:-false}"

  # 3) Discover non-heavy scenarios and run molecule test -s ...
  scenarios=()
  if [ -d molecule ]; then
    for d in molecule/*; do
      if [ -d "$d" ] && [ -f "$d/molecule.yml" ]; then
        scen="$(basename "$d")"
        case "$scen" in
          *_heavy)
            echo "Skipping heavy scenario '${scen}' in devtools-molecule.sh (run manually via dedicated script)."
            continue
            ;;
        esac
        scenarios+=("$scen")
      fi
    done
  fi

  if [ "${#scenarios[@]}" -eq 0 ]; then
    echo "No non-heavy Molecule scenarios found - skipping Molecule tests."
    exit 0
  fi

  echo "Running Molecule scenarios: ${scenarios[*]}"

  for scen in "${scenarios[@]}"; do
    echo ">>> molecule test -s ${scen}"
    molecule test -s "${scen}"
  done
'
