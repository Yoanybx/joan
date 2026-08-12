#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

node --test tools/payment-cost-reference.test.mjs

actual="$(mktemp "${TMPDIR:-/tmp}/joan-payment-cost.XXXXXX")"
trap 'rm -f "$actual"' EXIT

node tools/payment-cost-reference.mjs vectors/payment-cost/scenario-v0.json >"$actual"
cmp --silent vectors/payment-cost/report-v0.json "$actual"

printf '%s\n' 'JOAN payment-cost integer reference vector passed.'
