#!/usr/bin/env bash
# Fuzz every parser that takes bytes from outside the device, each for N seconds (default 60),
# starting from one real object of each kind. Exit non-zero on a panic or a broken invariant.
set -euo pipefail
cd "$(dirname "$0")/.."
secs="${1:-60}"
cargo fuzz --version >/dev/null 2>&1 || { echo "cargo-fuzz not installed (cargo install cargo-fuzz; needs the nightly toolchain)"; exit 2; }
cargo +nightly run -q --manifest-path fuzz/Cargo.toml --bin seeds -- fuzz/corpus
for target in blob_text open import enrolment attach shares relay_wire; do
  max_len=8192
  { [ "$target" = open ] || [ "$target" = relay_wire ]; } && max_len=70000
  cargo +nightly fuzz run "$target" -- -max_total_time="$secs" -max_len="$max_len"
done
echo "every target ran $secs s without a panic or a broken invariant"
