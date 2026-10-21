#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'USAGE'
Usage:
  scripts/devtools-galaxy.sh value <key> [galaxy.yml]
  scripts/devtools-galaxy.sh dependencies [galaxy.yml]
  scripts/devtools-galaxy.sh validate <yaml-file>
  scripts/devtools-galaxy.sh snapshot <yaml-file> <trusted-output-file>
USAGE
}

secure_yaml_content() {
  local file="$1"
  python3 - "$file" <<'PY'
import os
import stat
import sys
from pathlib import Path


path = sys.argv[1]
workspace = Path(os.environ.get("WUNDER_DEVTOOLS_WORKSPACE_ROOT", os.getcwd()))
workspace = Path(os.path.abspath(workspace))
absolute_path = Path(os.path.abspath(path))


def fail(message: str) -> None:
    print(f"ERROR: {message}", file=sys.stderr)
    raise SystemExit(1)


try:
    within_workspace = os.path.commonpath((workspace, absolute_path)) == str(workspace)
except ValueError:
    within_workspace = False
if not within_workspace:
    fail(f"{path} must be inside the trusted workspace {workspace}.")

parent = workspace
relative_path = absolute_path.relative_to(workspace)
for component in relative_path.parts[:-1]:
    parent /= component
    try:
        parent_metadata = os.lstat(parent)
    except OSError as error:
        fail(f"Unable to inspect {parent}: {error}")
    if stat.S_ISLNK(parent_metadata.st_mode) or not stat.S_ISDIR(
        parent_metadata.st_mode
    ):
        fail(f"{parent} must be a real directory, not a symlink or another file type.")

try:
    metadata = os.lstat(absolute_path)
except OSError as error:
    fail(f"Unable to inspect {path}: {error}")
if not stat.S_ISREG(metadata.st_mode):
    fail(f"{path} must be a regular file and must not be a symlink.")

no_follow = getattr(os, "O_NOFOLLOW", None)
if no_follow is None:
    fail("This platform cannot open galaxy metadata without following symlinks.")
descriptor = None
try:
    descriptor = os.open(
        absolute_path,
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | no_follow,
    )
    opened_metadata = os.fstat(descriptor)
    if not stat.S_ISREG(opened_metadata.st_mode):
        fail(f"{path} changed to a non-regular file while being opened.")
    if (opened_metadata.st_dev, opened_metadata.st_ino) != (
        metadata.st_dev,
        metadata.st_ino,
    ):
        fail(f"{path} changed while being opened.")
    with os.fdopen(descriptor, "r", encoding="utf-8") as stream:
        descriptor = None
        content = stream.read()
except (OSError, UnicodeError) as error:
    fail(f"Unable to read {path}: {error}")
finally:
    if descriptor is not None:
        os.close(descriptor)
if "\0" in content:
    fail(f"{path} contains a NUL byte.")
sys.stdout.write(content)
PY
}

secure_yaml_snapshot() {
  local file="$1"
  local output="$2"
  python3 - "$file" "$output" <<'PY'
import os
import stat
import sys
from pathlib import Path


path = sys.argv[1]
output = sys.argv[2]
workspace = Path(
    os.path.abspath(os.environ.get("WUNDER_DEVTOOLS_WORKSPACE_ROOT", os.getcwd()))
)
absolute_path = Path(os.path.abspath(path))
absolute_output = Path(os.path.abspath(output))


def fail(message: str) -> None:
    print(f"ERROR: {message}", file=sys.stderr)
    raise SystemExit(1)


try:
    within_workspace = os.path.commonpath((workspace, absolute_path)) == str(workspace)
except ValueError:
    within_workspace = False
if not within_workspace:
    fail(f"{path} must be inside the trusted workspace {workspace}.")

try:
    output_within_workspace = (
        os.path.commonpath((workspace, absolute_output)) == str(workspace)
    )
except ValueError:
    output_within_workspace = False
if output_within_workspace:
    fail(f"{output} must be outside the candidate-controlled workspace.")
if absolute_output.name in ("", ".", ".."):
    fail(f"{output} must name a trusted snapshot file.")

parent = workspace
relative_path = absolute_path.relative_to(workspace)
for component in relative_path.parts[:-1]:
    parent /= component
    try:
        parent_metadata = os.lstat(parent)
    except OSError as error:
        fail(f"Unable to inspect {parent}: {error}")
    if stat.S_ISLNK(parent_metadata.st_mode) or not stat.S_ISDIR(
        parent_metadata.st_mode
    ):
        fail(f"{parent} must be a real directory, not a symlink or another file type.")

try:
    metadata = os.lstat(absolute_path)
except OSError as error:
    fail(f"Unable to inspect {path}: {error}")
if not stat.S_ISREG(metadata.st_mode):
    fail(f"{path} must be a regular file and must not be a symlink.")

output_parent = absolute_output.parent
try:
    output_parent_metadata = os.lstat(output_parent)
except OSError as error:
    fail(f"Unable to inspect trusted snapshot directory {output_parent}: {error}")
if stat.S_ISLNK(output_parent_metadata.st_mode) or not stat.S_ISDIR(
    output_parent_metadata.st_mode
):
    fail(f"Trusted snapshot directory {output_parent} must be a real directory.")
if Path(os.path.realpath(output_parent)) != output_parent:
    fail(f"Trusted snapshot directory {output_parent} must not traverse symlinks.")

no_follow = getattr(os, "O_NOFOLLOW", None)
directory_flag = getattr(os, "O_DIRECTORY", None)
if no_follow is None or directory_flag is None:
    fail("This platform cannot create a no-follow dependency snapshot.")

source_descriptor: int | None = None
parent_descriptor: int | None = None
output_descriptor: int | None = None
created = False
completed = False
try:
    source_descriptor = os.open(
        absolute_path,
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | no_follow,
    )
    opened_metadata = os.fstat(source_descriptor)
    if not stat.S_ISREG(opened_metadata.st_mode):
        fail(f"{path} changed to a non-regular file while being opened.")
    if (opened_metadata.st_dev, opened_metadata.st_ino) != (
        metadata.st_dev,
        metadata.st_ino,
    ):
        fail(f"{path} changed while being opened.")

    chunks: list[bytes] = []
    while True:
        chunk = os.read(source_descriptor, 1024 * 1024)
        if not chunk:
            break
        chunks.append(chunk)
    content = b"".join(chunks)
    try:
        content.decode("utf-8")
    except UnicodeError as error:
        fail(f"Unable to read {path}: {error}")
    if b"\0" in content:
        fail(f"{path} contains a NUL byte.")

    parent_descriptor = os.open(
        output_parent,
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | no_follow
        | directory_flag,
    )
    opened_parent_metadata = os.fstat(parent_descriptor)
    if not stat.S_ISDIR(opened_parent_metadata.st_mode):
        fail(f"Trusted snapshot directory {output_parent} changed file type.")
    if (opened_parent_metadata.st_dev, opened_parent_metadata.st_ino) != (
        output_parent_metadata.st_dev,
        output_parent_metadata.st_ino,
    ):
        fail(f"Trusted snapshot directory {output_parent} changed while being opened.")

    output_descriptor = os.open(
        absolute_output.name,
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | no_follow,
        0o400,
        dir_fd=parent_descriptor,
    )
    created = True
    view = memoryview(content)
    while view:
        written = os.write(output_descriptor, view)
        if written <= 0:
            fail(f"Unable to complete trusted snapshot {absolute_output}.")
        view = view[written:]
    os.fsync(output_descriptor)
    os.fchmod(output_descriptor, 0o400)
    completed = True
except OSError as error:
    fail(f"Unable to create trusted snapshot {absolute_output}: {error}")
finally:
    if output_descriptor is not None:
        os.close(output_descriptor)
    if source_descriptor is not None:
        os.close(source_descriptor)
    if created and not completed and parent_descriptor is not None:
        try:
            os.unlink(absolute_output.name, dir_fd=parent_descriptor)
        except OSError:
            pass
    if parent_descriptor is not None:
        os.close(parent_descriptor)

sys.stdout.write(str(absolute_output))
PY
}

galaxy_value() {
  local key="$1"
  local file="$2"
  local content=""
  if ! content="$(secure_yaml_content "$file")"; then
    return 1
  fi
  awk -v key="$key" '
    BEGIN { found=0 }
    /^[[:space:]]*#/ { next }
    /^[[:space:]]*$/ { next }
    {
      line=$0
      sub(/^[[:space:]]+/, "", line)
      if (line ~ ("^" key ":[[:space:]]*")) {
        val=line
        sub(("^" key ":[[:space:]]*"), "", val)
        sub(/[[:space:]]+#.*$/, "", val)
        gsub(/^["\047]|["\047]$/, "", val)
        print val
        found=1
        exit
      }
    }
    END {
      if (!found) {
        exit 1
      }
    }
  ' <<<"$content"
}

galaxy_dependencies() {
  local file="$1"
  local content=""
  if ! content="$(secure_yaml_content "$file")"; then
    return 1
  fi
  awk '
    BEGIN { in_deps=0 }
    {
      raw=$0
      line=raw
      sub(/^[[:space:]]+/, "", line)

      if (line ~ /^#/ || line ~ /^$/) {
        next
      }

      if (!in_deps && line ~ /^dependencies:[[:space:]]*$/) {
        in_deps=1
        next
      }

      if (in_deps) {
        if (raw ~ /^[^[:space:]]/) {
          in_deps=0
          next
        }

        dep=line
        if (dep ~ /^#/ || dep ~ /^$/) {
          next
        }

        if (dep !~ /^[A-Za-z0-9_.-]+:[[:space:]]*/) {
          next
        }

        key=dep
        sub(/:.*/, "", key)

        val=dep
        sub(/^[^:]+:[[:space:]]*/, "", val)
        sub(/[[:space:]]+#.*$/, "", val)
        gsub(/^[[:space:]]+|[[:space:]]+$/, "", val)
        gsub(/["\047]/, "", val)

        if (val == "" || val == "*" || val == "null" || val == "~") {
          print key
        } else {
          print key ":" val
        }
      }
    }
  ' <<<"$content"
}

main() {
  local cmd="${1:-}"
  case "$cmd" in
    value)
      if [ "$#" -lt 2 ] || [ "$#" -gt 3 ]; then
        usage
        exit 2
      fi
      local key="$2"
      local file="${3:-galaxy.yml}"
      galaxy_value "$key" "$file"
      ;;
    dependencies)
      if [ "$#" -gt 2 ]; then
        usage
        exit 2
      fi
      local file="${2:-galaxy.yml}"
      galaxy_dependencies "$file"
      ;;
    validate)
      if [ "$#" -ne 2 ]; then
        usage
        exit 2
      fi
      secure_yaml_content "$2" >/dev/null
      ;;
    snapshot)
      if [ "$#" -ne 3 ]; then
        usage
        exit 2
      fi
      secure_yaml_snapshot "$2" "$3"
      ;;
    *)
      usage
      exit 2
      ;;
  esac
}

main "$@"
