#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"

node tools/adoption-trial.mjs validate-manifest
node tools/adoption-trial.mjs self-test

printf '%s\n' 'JOAN adoption trial package gate passed: frozen oracle and 3 negative controls rejected.'
