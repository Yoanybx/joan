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

package="joan-${tag#v}-$target"
if [[ -n "${GITHUB_SHA:-}" ]]; then
  source_commit="$GITHUB_SHA"
else
  source_commit="$(git rev-parse HEAD)"
fi
if [[ ! "$source_commit" =~ ^[0-9a-f]{40}$ ]]; then
  printf 'invalid source commit identity: %s\n' "$source_commit" >&2
  exit 3
fi
temporary_directory="$(mktemp -d "${TMPDIR:-/tmp}/joan-package.XXXXXX")"
trap 'rm -rf "$temporary_directory"' EXIT
stage="$temporary_directory/$package"
mkdir -p "$stage" "$output_directory"

cp "$binary" "$stage/joan"
cp README.md LICENSE NOTICE COPYRIGHT AUTHORS.md SECURITY.md OPERATIONS.md "$stage/"
cp vectors/jce1/conformance-v1.json "$stage/jce1-conformance-v1.json"
printf 'tag=%s\ntarget=%s\nsource_commit=%s\n' "$tag" "$target" "$source_commit" > "$stage/RELEASE-METADATA"

archive="$output_directory/$package.tar.gz"
tar -czf "$archive" -C "$temporary_directory" "$package"
(cd "$output_directory" && shasum -a 256 "$(basename "$archive")" > "$(basename "$archive").sha256")

printf '%s\n' "$archive"
printf '%s\n' "$archive.sha256"
