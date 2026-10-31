#!/usr/bin/env bash
# Two vaults, one file carrier, nobody in between. Runs the whole proof of concept in one terminal.
set -euo pipefail
cd "$(dirname "$0")/.."
cargo build --release -q
U=./target/release/unheld
export UNHELD_HOME="$(mktemp -d)" UNHELD_PASSPHRASE="${UNHELD_PASSPHRASE:-demo}"
D="$UNHELD_HOME"
say() { printf '\n\033[1m%s\033[0m\n' "$*"; sleep "${UNHELD_DEMO_PAUSE:-0}"; }

say "1. two identities, keys generated on device"
$U --profile alice id new alice
$U --profile bob   id new bob

say "2. introductions exchanged out of band (here: files)"
$U --profile alice intro export > "$D/alice.intro"
$U --profile bob   intro export > "$D/bob.intro"
$U --profile alice intro import bob   "$D/bob.intro"
$U --profile bob   intro import alice "$D/alice.intro"

say "3. sending before verification is refused (L3)"
echo "hi" | $U --profile alice send bob -c "file:$D/blob" || echo "exit $?"

say "4. the pairwise number is the same on both sides"
echo no | $U --profile alice verify bob   2>/dev/null | grep -E '^ +[0-9]{5}( [0-9]{5})+' || true
echo no | $U --profile bob   verify alice 2>/dev/null | grep -E '^ +[0-9]{5}( [0-9]{5})+' || true

say "5. both confirm by voice (here: yes on stdin)"
echo yes | $U --profile alice verify bob   | tail -1
echo yes | $U --profile bob   verify alice | tail -1

say "6. alice → bob through a file; the file holds a fixed-size blob"
echo "the carrier is a trait over bytes" | $U --profile alice send bob -c "file:$D/blob" 2>/dev/null
python3 -c "import base64,sys; t=open(sys.argv[1]).read().strip(); print(f'blob: {len(t)} chars of base64url, {len(base64.urlsafe_b64decode(t + \"=\" * (-len(t) % 4)))} raw bytes')" "$D/blob"
$U --profile bob open -c "file:$D/blob"

say "7. bob → alice through a pipe"
echo "and it cannot read this" | $U --profile bob send alice | $U --profile alice open

say "8. replay is refused (L11)"
$U --profile bob open -c "file:$D/blob" || echo "exit $?"

say "9. a flipped byte in a fresh blob is refused (L8)"
echo "a message nobody will read" | $U --profile alice send bob -c "file:$D/blob3" 2>/dev/null
python3 - "$D/blob3" "$D/blob4" <<'PY'
import sys
s = open(sys.argv[1]).read().strip(); l = list(s); i = 50
l[i] = 'A' if l[i] != 'A' else 'B'
open(sys.argv[2], 'w').write(''.join(l))
PY
$U --profile bob open -c "file:$D/blob4" || echo "exit $?"

say "10. peers and the vault at rest"
$U --profile alice peers
$U --profile bob   peers
printf 'vault header: '; head -c 8 "$D/alice/vault"; echo
grep -c alice "$D/alice/vault" >/dev/null && echo "plaintext found in vault" || echo "no plaintext in vault"
