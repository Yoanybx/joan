#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"

if [[ "$#" -ne 3 ]]; then
  printf '%s\n' 'usage: scripts/package-release.sh <tag> <target> <output-directory>' >&2
  exit 2
fi

tag="$1"
target="$2"
output_directory="$3"
target_dir="${CARGO_TARGET_DIR:-target}"
if [[ "$target_dir" != /* ]]; then
  target_dir="$root/$target_dir"
fi
binary="$target_dir/$target/release/joan"
executor_binary="$target_dir/$target/release/joan-executor"

if [[ ! "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+([-.][A-Za-z0-9.-]+)?$ ]]; then
  printf 'invalid release tag: %s\n' "$tag" >&2
  exit 2
fi
if [[ ! "$target" =~ ^[A-Za-z0-9_-]+$ ]]; then
  printf 'invalid Rust target: %s\n' "$target" >&2
  exit 2
fi
if [[ ! -x "$binary" ]]; then
  printf 'release binary does not exist or is not executable: %s\n' "$binary" >&2
  exit 3
fi
if [[ ! -x "$executor_binary" ]]; then
  printf 'release executor does not exist or is not executable: %s\n' "$executor_binary" >&2
  exit 3
fi

package="joan-${tag#v}-$target"
head_commit="$(git rev-parse HEAD)"
if [[ -n "$(git status --porcelain=v1 --untracked-files=all)" ]]; then
  printf '%s\n' 'release packaging requires a clean Git checkout' >&2
  exit 3
fi
if [[ -n "${GITHUB_SHA:-}" && "$GITHUB_SHA" != "$head_commit" ]]; then
  printf 'GITHUB_SHA does not match checked-out HEAD: %s != %s\n' "$GITHUB_SHA" "$head_commit" >&2
  exit 3
fi
source_commit="${GITHUB_SHA:-$head_commit}"
if [[ ! "$source_commit" =~ ^[0-9a-f]{40}$ ]]; then
  printf 'invalid source commit identity: %s\n' "$source_commit" >&2
  exit 3
fi
temporary_directory="$(mktemp -d "${TMPDIR:-/tmp}/joan-package.XXXXXX")"
trap 'rm -rf "$temporary_directory"' EXIT
stage="$temporary_directory/$package"
mkdir -p "$stage" "$output_directory"

sbom_directory="$temporary_directory/sbom"
bash scripts/generate-sbom.sh "$target" "$sbom_directory" >/dev/null

cp "$binary" "$stage/joan"
cp "$executor_binary" "$stage/joan-executor"
cp README.md LICENSE NOTICE COPYRIGHT AUTHORS.md SECURITY.md OPERATIONS.md TRADEMARKS.md "$stage/"
cp vectors/jce1/conformance-v1.json "$stage/jce1-conformance-v1.json"
mkdir -p "$stage/SBOM"
cp -R "$sbom_directory/." "$stage/SBOM/"
printf 'tag=%s\ntarget=%s\nsource_commit=%s\n' "$tag" "$target" "$source_commit" > "$stage/RELEASE-METADATA"

find "$stage" -type d -exec chmod 0755 {} +
find "$stage" -type f -exec chmod 0644 {} +
chmod 0755 "$stage/joan" "$stage/joan-executor"
find "$stage" -exec touch -h -t 200001010000.00 {} +

archive="$output_directory/$package.tar.gz"
archive_tar="$temporary_directory/$package.tar"
archive_list="$temporary_directory/archive.list"
(
  cd "$temporary_directory"
  find "$package" -print | LC_ALL=C sort > "$archive_list"
)

if tar --version 2>/dev/null | grep -q 'bsdtar'; then
  tar -c --format ustar --no-recursion \
    --uid 0 --gid 0 --uname root --gname root \
    --no-xattrs --no-acls --no-fflags \
    -f "$archive_tar" -C "$temporary_directory" -T "$archive_list"
else
  tar -c --format ustar --no-recursion \
    --owner=0 --group=0 --numeric-owner \
    --no-xattrs --no-acls --no-selinux \
    -f "$archive_tar" -C "$temporary_directory" -T "$archive_list"
fi
gzip -n -9 -c "$archive_tar" > "$archive"
(cd "$output_directory" && shasum -a 256 "$(basename "$archive")" > "$(basename "$archive").sha256")

printf '%s\n' "$archive"
printf '%s\n' "$archive.sha256"
