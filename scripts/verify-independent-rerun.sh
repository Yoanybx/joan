#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"

node tools/independent-rerun.mjs validate-manifest
node tools/independent-rerun.mjs self-test

printf '%s\n' 'JOAN independent rerun package gate passed: manifest frozen and 3 negative controls rejected.'
