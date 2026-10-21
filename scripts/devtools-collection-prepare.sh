#!/usr/bin/env bash
set -euo pipefail

# Build and install the collection inside the ee-wunder-devtools-ubi9 container.
# Installs into a per-run collections dir to avoid stale state.
# Prints COLLECTIONS_DIR as the last line for callers.

offline_local_only="${WUNDER_DEVTOOLS_OFFLINE_LOCAL_ONLY:-0}"
case "${offline_local_only}" in
  0|1) ;;
  *)
    echo "ERROR: WUNDER_DEVTOOLS_OFFLINE_LOCAL_ONLY must be 0 or 1." >&2
    exit 1
    ;;
esac

require_declared_dependencies="${WUNDER_DEVTOOLS_REQUIRE_DECLARED_DEPENDENCIES:-}"
if [ "${offline_local_only}" = 1 ]; then
  case "${require_declared_dependencies}" in
    0|1) ;;
    *)
      echo "ERROR: Offline mode requires WUNDER_DEVTOOLS_REQUIRE_DECLARED_DEPENDENCIES=0 or 1." >&2
      exit 1
      ;;
  esac
fi

# Bind every secure metadata read to the mounted workspace independently of
# the caller's current directory.
export WUNDER_DEVTOOLS_WORKSPACE_ROOT=/workspace

# Derive namespace+name from galaxy.yml (authoritative)
if ! ns="$(
  bash /workspace/scripts/devtools-galaxy.sh \
    value namespace /workspace/galaxy.yml
)"; then
  echo "ERROR: Failed to securely read namespace from /workspace/galaxy.yml." >&2
  exit 1
fi
if ! name="$(
  bash /workspace/scripts/devtools-galaxy.sh \
    value name /workspace/galaxy.yml
)"; then
  echo "ERROR: Failed to securely read name from /workspace/galaxy.yml." >&2
  exit 1
fi

ns="${COLLECTION_NAMESPACE:-$ns}"
if [ -z "${ns:-}" ] || [ -z "${name:-}" ]; then
  echo "ERROR: Failed to derive namespace/name (namespace='${ns:-}', name='${name:-}')" >&2
  exit 1
fi

echo "Preparing collection ${ns}.${name} inside ee-wunder-devtools-ubi9..."

# Stable HOME + stable ansible tmp (ansible-galaxy downloads)
export HOME="${HOME:-/tmp/wunder}"
mkdir -p "$HOME"
mkdir -p "$HOME/.ansible/tmp"
export ANSIBLE_LOCAL_TEMP="$HOME/.ansible/tmp"
export ANSIBLE_REMOTE_TEMP="$HOME/.ansible/tmp"

# Remove any stale copy so Molecule uses the freshly built collection.
stale_collection_dir="$HOME/.ansible/collections/ansible_collections/${ns}/${name}"
if [ -d "$stale_collection_dir" ]; then
  rm -rf "$stale_collection_dir"
fi

# Per-run XDG cache (avoids ansible-compat/ansible-lint races)
XDG_CACHE_HOME="$(mktemp -d "${HOME}/xdg-cache.XXXXXX")"
export XDG_CACHE_HOME
if [ "${DEBUG:-0}" = "1" ]; then
  echo "XDG_CACHE_HOME=$XDG_CACHE_HOME"
fi

# Per-run install target
COLLECTIONS_DIR="$(mktemp -d "${HOME}/collections.XXXXXX")"
export ANSIBLE_COLLECTIONS_PATH="${COLLECTIONS_DIR}:/usr/share/ansible/collections"
BUILD_OUTPUT_DIR="$(mktemp -d "${HOME}/build.XXXXXX")"

cd /workspace

dep_specs=()
dependency_output="$(
  bash /workspace/scripts/devtools-galaxy.sh \
    dependencies /workspace/galaxy.yml
)"
while IFS= read -r dep_spec; do
  if [ -n "${dep_spec}" ]; then
    dep_specs+=("${dep_spec}")
  fi
done <<< "${dependency_output}"

verify_offline_dependency_inventory() {
  python3 - "${require_declared_dependencies}" <<'PY'
import json
import os
import re
import stat
import sys
from pathlib import Path

import yaml
from ansible.galaxy.dependency_resolution.versioning import meets_requirements


workspace = Path("/workspace")
require_declared = sys.argv[1] == "1"
fqcn_pattern = re.compile(r"^[a-z0-9_]+\.[a-z0-9_]+$")
declared: list[tuple[str, str, object, str]] = []
missing_version = object()


def fail(message: str) -> None:
    print(f"ERROR: {message}", file=sys.stderr)
    raise SystemExit(1)


def path_is_present(path: Path) -> bool:
    try:
        path.lstat()
    except FileNotFoundError:
        return False
    except OSError as error:
        fail(f"Unable to inspect {path.relative_to(workspace)}: {error}")
    return True


def load_mapping(path: Path) -> dict[object, object]:
    relative_path = path.relative_to(workspace)
    parent = workspace
    for component in relative_path.parts[:-1]:
        parent /= component
        try:
            parent_metadata = parent.lstat()
        except OSError as error:
            fail(f"Unable to inspect {parent.relative_to(workspace)}: {error}")
        if stat.S_ISLNK(parent_metadata.st_mode) or not stat.S_ISDIR(
            parent_metadata.st_mode
        ):
            fail(
                f"{parent.relative_to(workspace)} must be a real directory, "
                "not a symlink or another file type."
            )

    try:
        metadata = path.lstat()
    except OSError as error:
        fail(f"Unable to inspect {relative_path}: {error}")
    if not stat.S_ISREG(metadata.st_mode):
        fail(f"{relative_path} must be a regular file and must not be a symlink.")

    no_follow = getattr(os, "O_NOFOLLOW", None)
    if no_follow is None:
        fail("This platform cannot open dependency manifests without following symlinks.")
    descriptor: int | None = None
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | no_follow,
        )
        opened_metadata = os.fstat(descriptor)
        if not stat.S_ISREG(opened_metadata.st_mode):
            fail(f"{relative_path} changed to a non-regular file while being opened.")
        if (opened_metadata.st_dev, opened_metadata.st_ino) != (
            metadata.st_dev,
            metadata.st_ino,
        ):
            fail(f"{relative_path} changed while being opened.")
        stream = os.fdopen(descriptor, "r", encoding="utf-8")
        descriptor = None
        with stream:
            value = yaml.safe_load(stream.read())
    except (OSError, UnicodeError, yaml.YAMLError) as error:
        fail(f"Unable to parse {relative_path}: {error}")
    finally:
        if descriptor is not None:
            os.close(descriptor)
    if value is None:
        return {}
    if not isinstance(value, dict):
        fail(f"{relative_path} must contain a YAML mapping.")
    return value


def load_installed_manifest(path: Path, expected_name: str) -> str:
    trusted_root = Path("/usr/share/ansible/collections/ansible_collections")
    try:
        trusted_root_metadata = trusted_root.lstat()
    except OSError as error:
        fail(f"Unable to inspect pinned collection root {trusted_root}: {error}")
    if stat.S_ISLNK(trusted_root_metadata.st_mode) or not stat.S_ISDIR(
        trusted_root_metadata.st_mode
    ):
        fail(
            f"Pinned collection root {trusted_root} must be a real directory, "
            "not a symlink or another file type."
        )
    try:
        relative_path = path.relative_to(trusted_root)
    except ValueError:
        fail(f"Pinned collection manifest {path} is outside {trusted_root}.")
    parent = trusted_root
    for component in relative_path.parts[:-1]:
        parent /= component
        try:
            parent_metadata = parent.lstat()
        except OSError as error:
            fail(f"Unable to inspect pinned collection path {parent}: {error}")
        if stat.S_ISLNK(parent_metadata.st_mode) or not stat.S_ISDIR(
            parent_metadata.st_mode
        ):
            fail(
                f"Pinned collection path {parent} must be a real directory, "
                "not a symlink or another file type."
            )

    try:
        metadata = path.lstat()
    except OSError as error:
        fail(f"Unable to inspect pinned collection manifest {path}: {error}")
    if not stat.S_ISREG(metadata.st_mode):
        fail(f"Pinned collection manifest {path} must be a regular file.")

    no_follow = getattr(os, "O_NOFOLLOW", None)
    if no_follow is None:
        fail("This platform cannot open pinned collection manifests safely.")
    descriptor: int | None = None
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | no_follow,
        )
        opened_metadata = os.fstat(descriptor)
        if not stat.S_ISREG(opened_metadata.st_mode):
            fail(f"Pinned collection manifest {path} changed file type while opening.")
        if (opened_metadata.st_dev, opened_metadata.st_ino) != (
            metadata.st_dev,
            metadata.st_ino,
        ):
            fail(f"Pinned collection manifest {path} changed while being opened.")
        stream = os.fdopen(descriptor, "r", encoding="utf-8")
        descriptor = None
        with stream:
            manifest = json.load(stream)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        fail(f"Unable to parse pinned collection manifest {path}: {error}")
    finally:
        if descriptor is not None:
            os.close(descriptor)

    if not isinstance(manifest, dict):
        fail(f"Pinned collection manifest {path} must contain a JSON object.")
    collection_info = manifest.get("collection_info")
    if not isinstance(collection_info, dict):
        fail(f"Pinned collection manifest {path} lacks collection_info metadata.")
    expected_namespace, expected_collection = expected_name.split(".", 1)
    namespace = collection_info.get("namespace")
    collection = collection_info.get("name")
    version = collection_info.get("version")
    if namespace != expected_namespace or collection != expected_collection:
        fail(
            f"Pinned collection manifest {path} identifies "
            f"{namespace!r}.{collection!r}, expected {expected_name}."
        )
    if not isinstance(version, str) or not version:
        fail(f"Pinned collection manifest {path} has an invalid version.")
    return version


def add_dependency(source: str, name: object, version: object, kind: object) -> None:
    if not isinstance(name, str) or not name:
        fail(f"{source} contains a collection dependency without a non-empty string name.")
    if version is not missing_version and not isinstance(version, str):
        fail(f"{source} dependency {name!r} has an invalid version.")
    if not isinstance(kind, str) or not kind:
        fail(f"{source} dependency {name!r} has an invalid type.")
    declared.append(
        (source, name, None if version is missing_version else version, kind)
    )


galaxy = load_mapping(workspace / "galaxy.yml")
galaxy_dependencies = galaxy.get("dependencies", {})
if galaxy_dependencies is None:
    galaxy_dependencies = {}
if not isinstance(galaxy_dependencies, dict):
    fail("galaxy.yml dependencies must be a YAML mapping.")
for dependency_name, dependency_version in galaxy_dependencies.items():
    add_dependency("galaxy.yml", dependency_name, dependency_version, "galaxy")

requirements_path = workspace / "collections/requirements.yml"
if path_is_present(requirements_path):
    requirements = load_mapping(requirements_path)
    requirement_entries = requirements.get("collections", [])
    if requirement_entries is None:
        requirement_entries = []
    if not isinstance(requirement_entries, list):
        fail("collections/requirements.yml collections must be a YAML list.")
    for index, entry in enumerate(requirement_entries):
        source = f"collections/requirements.yml collections[{index}]"
        if isinstance(entry, str):
            add_dependency(source, entry, missing_version, "galaxy")
            continue
        if not isinstance(entry, dict):
            fail(f"{source} must be a string or YAML mapping.")
        allowed_fields = {"name", "version", "type"}
        unsupported_fields = sorted(
            repr(field) for field in entry if field not in allowed_fields
        )
        if unsupported_fields:
            fail(
                f"{source} uses unsupported requirement field(s): "
                f"{', '.join(unsupported_fields)}."
            )
        add_dependency(
            source,
            entry.get("name"),
            entry["version"] if "version" in entry else missing_version,
            entry["type"] if "type" in entry else "galaxy",
        )

if not declared:
    print(
        "Offline dependency preflight: no collection dependencies are declared in "
        "galaxy.yml or collections/requirements.yml.",
        file=sys.stderr,
    )
    raise SystemExit(0)

problems: list[str] = []
installed_versions: dict[tuple[str, str], str | None] = {}
for source, name, version, kind in declared:
    version_text = "" if version in (None, "", "*", "null", "~") else f":{version}"
    display = f"{source}: {name}{version_text}"
    if kind != "galaxy":
        fail(f"{display} uses unsupported requirement type {kind!r}.")
    if not fqcn_pattern.fullmatch(name):
        fail(f"{source} contains invalid Galaxy collection name {name!r}.")
    namespace, collection = name.split(".", 1)
    manifest = (
        Path("/usr/share/ansible/collections/ansible_collections")
        / namespace
        / collection
        / "MANIFEST.json"
    )
    key = (name, str(manifest))
    if key not in installed_versions:
        try:
            manifest.lstat()
        except FileNotFoundError:
            installed_versions[key] = None
        except OSError as error:
            fail(f"Unable to inspect pinned collection manifest {manifest}: {error}")
        else:
            installed_versions[key] = load_installed_manifest(manifest, name)
    installed_version = installed_versions[key]
    if installed_version is None:
        problems.append(display)
    elif version not in (None, "", "*", "null", "~"):
        try:
            satisfies = meets_requirements(installed_version, version)
        except (TypeError, ValueError) as error:
            fail(
                f"{source} dependency {name!r} has an invalid Galaxy "
                f"version requirement {version!r}: {error}"
            )
        if not satisfies:
            problems.append(f"{display} (pinned version is {installed_version})")

if not problems:
    print(
        "Offline dependency preflight: every dependency declared in galaxy.yml and "
        "collections/requirements.yml is present in the pinned Devtools image.",
        file=sys.stderr,
    )
    raise SystemExit(0)

print(
    "Offline dependency preflight: declared collection dependencies missing from or "
    "unverifiable in the pinned Devtools image:",
    file=sys.stderr,
)
for problem in problems:
    print(f"  - {problem}", file=sys.stderr)
if require_declared:
    fail(
        "This offline gate requires every declared dependency under "
        "/usr/share/ansible/collections."
    )
print(
    "Offline dependency preflight: this explicitly dependency-free gate may continue; "
    "dependency-backed checks remain protected-pipeline work.",
    file=sys.stderr,
)
PY
}

install_collection_dependency() {
  local dep_spec="$1"
  local dep_fqcn="${dep_spec%%:*}"
  local dep_name="${dep_fqcn#lit.}"
  local source_root="${WUNDER_DEVTOOLS_SOURCE_ROOT:-}"
  local local_source=""

  if [[ "$dep_fqcn" == lit.* ]] && [ -n "$source_root" ]; then
    local_source="${source_root}/ansible-collection-${dep_name}"
    if [ -f "${local_source}/galaxy.yml" ]; then
      echo "Installing local dependency ${dep_fqcn} from ${local_source}..." >&2
      dep_build_out="$(
        cd "$local_source"
        ansible-galaxy collection build --output-path "${BUILD_OUTPUT_DIR}" --force
      )"
      dep_artifact="$(printf "%s\n" "$dep_build_out" | awk '/Created collection for/ {print $NF}' | tail -n 1)"
      if [ -z "${dep_artifact:-}" ] || [ ! -f "$dep_artifact" ]; then
        echo "ERROR: Local dependency artifact not found. Build output was:" >&2
        echo "$dep_build_out" >&2
        exit 1
      fi
      ansible-galaxy collection install "$dep_artifact" -p "${COLLECTIONS_DIR}" --force --no-deps >&2
      return
    fi
  fi

  echo "Installing dependency ${dep_spec} into ${COLLECTIONS_DIR}..." >&2
  ansible-galaxy collection install "$dep_spec" -p "${COLLECTIONS_DIR}" --force >&2
}

if [ "${offline_local_only}" = 1 ]; then
  echo "Offline local-only mode: external collection dependency installation is forbidden." >&2
  echo "Offline local-only mode is hermetic: local dependency source roots are intentionally not mounted." >&2
  verify_offline_dependency_inventory
else
  requirements_path=/workspace/collections/requirements.yml
  if [ -e "${requirements_path}" ] || [ -L "${requirements_path}" ]; then
    requirements_snapshot="${BUILD_OUTPUT_DIR}/validated-requirements.yml"
    requirements_snapshot="$(
      bash /workspace/scripts/devtools-galaxy.sh \
        snapshot "${requirements_path}" "${requirements_snapshot}"
    )"
    echo "Installing collection requirements from collections/requirements.yml into ${COLLECTIONS_DIR}..." >&2
    ansible-galaxy collection install \
      -r "${requirements_snapshot}" \
      -p "${COLLECTIONS_DIR}" \
      --force >&2
  else
    for dep_spec in "${dep_specs[@]}"; do
      install_collection_dependency "${dep_spec}"
    done
  fi
fi

# Build artifact and capture the output path
build_out="$(ansible-galaxy collection build --output-path "${BUILD_OUTPUT_DIR}" --force)"
artifact="$(printf "%s\n" "$build_out" | awk '/Created collection for/ {print $NF}' | tail -n 1)"

if [ -z "${artifact:-}" ] || [ ! -f "$artifact" ]; then
  echo "ERROR: Collection artifact not found. Build output was:" >&2
  echo "$build_out" >&2
  echo "DEBUG: ${HOME} contents:" >&2
  ls -la "${HOME}" >&2
  exit 1
fi

# Install this collection into per-run dir
ansible-galaxy collection install "$artifact" -p "${COLLECTIONS_DIR}" --force --no-deps

echo "Collection ${ns}.${name} installed in ${COLLECTIONS_DIR}"

# Print the path so caller scripts can capture it if needed
echo "${COLLECTIONS_DIR}"
