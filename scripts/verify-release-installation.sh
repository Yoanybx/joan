#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C LANG=C

cd "$(dirname "$0")/.."

for command in shasum tar; do
  if ! command -v "$command" >/dev/null 2>&1; then
    printf 'required release-installation test tool is unavailable: %s\n' "$command" >&2
    exit 3
  fi
done

case "$(uname -s):$(uname -m)" in
  Darwin:arm64) target='aarch64-apple-darwin' ;;
  Linux:x86_64) target='x86_64-unknown-linux-gnu' ;;
  *)
    printf '%s\n' 'release-installation test is not supported on this host' >&2
    exit 3
    ;;
esac

root="$(mktemp -d "${TMPDIR:-/tmp}/joan-install-test.XXXXXX")"
trap 'rm -rf -- "$root"' EXIT
fixture="$root/fixture"
fake_bin="$root/bin"
install_directory="$root/install"
mkdir -p "$fixture" "$fake_bin" "$install_directory"

cat > "$fake_bin/node" <<'SCRIPT'
#!/bin/sh
case "$*" in
  *official_repository*) printf '%s' 'led-action/joan' ;;
  *enabled*) printf '%s' 'true' ;;
  *) exit 9 ;;
esac
SCRIPT

cat > "$fake_bin/gh" <<'SCRIPT'
#!/bin/sh
set -eu
if [ "${1:-}:${2:-}" = 'release:download' ]; then
  destination=''
  while [ "$#" -gt 0 ]; do
    if [ "$1" = '--dir' ]; then
      destination="$2"
      shift 2
    else
      shift
    fi
  done
  [ -n "$destination" ]
  cp "$FIXTURE_DIRECTORY"/*.tar.gz "$destination/"
  cp "$FIXTURE_DIRECTORY"/*.tar.gz.sha256 "$destination/"
  exit 0
fi
if [ "${1:-}:${2:-}" = 'attestation:verify' ]; then
  exit 0
fi
exit 9
SCRIPT
chmod 0755 "$fake_bin/node" "$fake_bin/gh"

build_fixture() {
  mode="$1"
  marker="$2"
  stage="$root/stage"
  package="joan-0.1.0-$target"
  rm -rf -- "$stage"
  mkdir -p "$stage/$package"

  cat > "$stage/$package/joan" <<SCRIPT
#!/bin/sh
# $marker
if [ "\${1:-}" = node ] && [ "\${2:-}" = self-check ]; then
  [ '$mode' = success ]
  exit
fi
exit 8
SCRIPT
  cat > "$stage/$package/joan-executor" <<SCRIPT
#!/bin/sh
# $marker
[ "\${1:-}" = --self-check ]
SCRIPT
  chmod 0755 "$stage/$package/joan" "$stage/$package/joan-executor"
  rm -f -- "$fixture/$package.tar.gz" "$fixture/$package.tar.gz.sha256"
  tar -czf "$fixture/$package.tar.gz" -C "$stage" "$package"
  (
    cd "$fixture"
    shasum -a 256 "$package.tar.gz" > "$package.tar.gz.sha256"
  )
}

build_fixture success release-one
FIXTURE_DIRECTORY="$fixture" PATH="$fake_bin:/usr/bin:/bin" \
  bash scripts/install-release.sh led-action/joan v0.1.0 "$install_directory" >/dev/null
grep -q 'release-one' "$install_directory/joan"
grep -q 'release-one' "$install_directory/joan-executor"

build_fixture failure release-two
set +e
FIXTURE_DIRECTORY="$fixture" PATH="$fake_bin:/usr/bin:/bin" \
  bash scripts/install-release.sh led-action/joan v0.1.0 "$install_directory" \
  >"$root/failure.stdout" 2>"$root/failure.stderr"
status="$?"
set -e
if [[ "$status" -ne 7 ]]; then
  printf 'expected post-activation self-check failure 7, received %s\n' "$status" >&2
  exit 1
fi
grep -q 'installation did not commit; previous binary set restored.' "$root/failure.stderr"
grep -q 'release-one' "$install_directory/joan"
grep -q 'release-one' "$install_directory/joan-executor"
if grep -q 'release-two' "$install_directory/joan" \
  || grep -q 'release-two' "$install_directory/joan-executor"; then
  printf '%s\n' 'failed release left a mixed executable set' >&2
  exit 1
fi

printf '%s\n' 'JOAN two-binary release installation and rollback gate passed.'
