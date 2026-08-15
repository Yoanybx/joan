#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

if [[ "$#" -lt 2 || "$#" -gt 3 ]]; then
  printf '%s\n' 'usage: scripts/install-release.sh <owner/repository> <explicit-tag> [install-directory]' >&2
  exit 2
fi

repository="$1"
tag="$2"
install_directory="${3:-$HOME/.local/bin}"
policy='.joan/update-policy.json'

if ! command -v node >/dev/null 2>&1; then
  printf '%s\n' 'required command is unavailable: node' >&2
  exit 3
fi

official_repository="$(node -e 'const p=require("./.joan/update-policy.json"); process.stdout.write(p.official_repository ?? "")')"
updates_enabled="$(node -e 'const p=require("./.joan/update-policy.json"); process.stdout.write(String(p.enabled))')"
if [[ "$updates_enabled" != 'true' || -z "$official_repository" ]]; then
  printf '%s\n' 'trusted updates are disabled until .joan/update-policy.json names the official repository.' >&2
  exit 4
fi
if [[ "$repository" != "$official_repository" ]]; then
  printf 'repository %s is not the configured authority %s.\n' "$repository" "$official_repository" >&2
  exit 4
fi
if [[ ! "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+([-.][A-Za-z0-9.-]+)?$ ]]; then
  printf 'invalid explicit release tag: %s\n' "$tag" >&2
  exit 2
fi

for command in gh shasum tar; do
  if ! command -v "$command" >/dev/null 2>&1; then
    printf 'required command is unavailable: %s\n' "$command" >&2
    exit 3
  fi
done

case "$(uname -s):$(uname -m)" in
  Darwin:arm64) target='aarch64-apple-darwin' ;;
  Linux:x86_64) target='x86_64-unknown-linux-gnu' ;;
  *)
    printf 'unsupported installation platform: %s %s\n' "$(uname -s)" "$(uname -m)" >&2
    exit 5
    ;;
esac

archive="joan-${tag#v}-$target.tar.gz"
temporary_directory="$(mktemp -d "${TMPDIR:-/tmp}/joan-install.XXXXXX")"
install_started=0
install_committed=0
had_previous_node=0
had_previous_executor=0
destination=''
executor_destination=''
previous=''
executor_previous=''

cleanup() {
  status="$?"
  set +e
  if (( install_started == 1 && install_committed == 0 )); then
    if (( had_previous_node == 1 )); then
      mv -f "$previous" "$destination"
    else
      rm -f "$destination"
    fi
    if (( had_previous_executor == 1 )); then
      mv -f "$executor_previous" "$executor_destination"
    else
      rm -f "$executor_destination"
    fi
    printf '%s\n' 'installation did not commit; previous binary set restored.' >&2
  fi
  rm -rf "$temporary_directory"
  return "$status"
}
trap cleanup EXIT

gh release download "$tag" \
  --repo "$repository" \
  --pattern "$archive" \
  --pattern "$archive.sha256" \
  --dir "$temporary_directory"

(cd "$temporary_directory" && shasum -a 256 -c "$archive.sha256")
gh attestation verify "$temporary_directory/$archive" --repo "$repository"
tar -xzf "$temporary_directory/$archive" -C "$temporary_directory"

candidate="$temporary_directory/joan-${tag#v}-$target/joan"
candidate_executor="$temporary_directory/joan-${tag#v}-$target/joan-executor"
if [[ ! -x "$candidate" || ! -x "$candidate_executor" ]]; then
  printf '%s\n' 'verified archive does not contain both JOAN executables.' >&2
  exit 6
fi
"$candidate_executor" --self-check >/dev/null

mkdir -p "$install_directory"
destination="$install_directory/joan"
executor_destination="$install_directory/joan-executor"
staged="$install_directory/.joan.new.$$"
executor_staged="$install_directory/.joan-executor.new.$$"
previous="$install_directory/joan.previous"
executor_previous="$install_directory/joan-executor.previous"
cp "$candidate" "$staged"
cp "$candidate_executor" "$executor_staged"
chmod 0755 "$staged" "$executor_staged"

if [[ -e "$destination" ]]; then
  cp "$destination" "$previous"
  had_previous_node=1
fi
if [[ -e "$executor_destination" ]]; then
  cp "$executor_destination" "$executor_previous"
  had_previous_executor=1
fi
install_started=1
mv "$executor_staged" "$executor_destination"
mv "$staged" "$destination"

if ! "$executor_destination" --self-check >/dev/null \
  || ! "$destination" node self-check >/dev/null; then
  printf '%s\n' 'installed binary set failed self-check; previous set restored.' >&2
  exit 7
fi
install_committed=1

printf 'Installed %s from %s at %s and %s\n' "$tag" "$repository" "$destination" "$executor_destination"
if [[ -e "$previous" ]]; then
  printf 'Rollback binary: %s\n' "$previous"
fi
if [[ -e "$executor_previous" ]]; then
  printf 'Rollback executor: %s\n' "$executor_previous"
fi
