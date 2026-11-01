#!/usr/bin/env bash
# Prove every lemma in the policy-layer theory, one prover process per lemma.
# Exit 1 if any lemma is not verified. Pass lemma names to prove only those.
set -euo pipefail
cd "$(dirname "$0")/.."
command -v tamarin-prover >/dev/null || { echo "tamarin-prover not on PATH (brew install tamarin-prover/tap/tamarin-prover)"; exit 2; }
theory=formal/unheld.spthy
lemmas=("$@")
[ ${#lemmas[@]} -gt 0 ] || lemmas=($(sed -nE 's/^lemma ([a-z_]+).*/\1/p' "$theory"))
failed=0
for lemma in "${lemmas[@]}"; do
  line="$(tamarin-prover --prove="$lemma" "$theory" 2>&1 | grep -E "^  $lemma \((all|exists)-traces?\)" || true)"
  echo "${line:-  $lemma: no result}"
  echo "$line" | grep -q 'verified' || failed=1
done
[ $failed -eq 0 ] || { echo "a lemma is not verified"; exit 1; }
echo "every lemma verified"
