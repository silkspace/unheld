#!/usr/bin/env bash
# Prove every lemma in the policy-layer theory. Exit 1 if any lemma is not verified.
set -euo pipefail
cd "$(dirname "$0")/.."
command -v tamarin-prover >/dev/null || { echo "tamarin-prover not on PATH (brew install tamarin-prover/tap/tamarin-prover)"; exit 2; }
out="$(tamarin-prover --prove formal/unheld.spthy --output=formal/unheld.proved.spthy 2>&1 | grep -E '^  [a-z_]+ \((all|exists)-traces?\)')"
echo "$out"
if echo "$out" | grep -vq 'verified'; then echo "a lemma is not verified"; exit 1; fi
echo "every lemma verified"
