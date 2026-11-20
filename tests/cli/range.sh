#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya
#
# kanhe-range, the range proofs' helper, end to end as the programs that call
# it do: one JSON object in on standard input, one out. A proof made (seeded,
# so it is the same twice), verified, and refused for another statement; a
# value outside its range; input errors; the circuit file, plain and with
# zstd; every command's --help.
# Usage: range.sh KANHE_RANGE
set -Eeuo pipefail
trap 'echo "FAILED at line $LINENO: $BASH_COMMAND" >&2' ERR

RANGE="$1"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
cd "$WORK"

fail() { echo "FAIL: $*"; [ -f out.json ] && cat out.json; [ -f err.txt ] && cat err.txt; exit 1; }
# run COMMAND EXIT INPUT: the output in out.json, standard error in err.txt.
run() {
    local actual=0
    printf '%s' "$3" | "$RANGE" "$1" > out.json 2> err.txt || actual=$?
    [ "$actual" -eq "$2" ] || fail "kanhe-range $1: expected exit $2, got $actual: $3"
}
json() { python3 -c "import json; d = json.load(open('out.json')); print($1)"; }

SALT=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
SEED=a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5
T=72616e67652068656c7065722074657374 # "range helper test"
C=1d3fb2cb17848a6696907d7bc4f9c2f6ea222d65bd45f1d0d244f6e6cdb66b52 # value 1000
ID=fc727b6726bd4bfe80b65d044cdb4d393fcc688b5aad0ab4ded3a9619459480a
max=18446744073709551615
statement() { # VALUE LOW HIGH [EXTRA]
    printf '{"salt":"%s","value":"%s","low":"%s","high":"%s","transcript":"%s"%s}' \
        "$SALT" "$1" "$2" "$3" "$T" "${4:-}"
}
check() { # LOW HIGH TRANSCRIPT PROOF [COMMITMENT]
    printf '{"commitment":"%s","low":"%s","high":"%s","transcript":"%s","proof":"%s"}' \
        "${5:-$C}" "$1" "$2" "$3" "$4"
}

# --- Help ----------------------------------------------------------------------
"$RANGE" --help > help.txt
grep -q '^  prove ' help.txt || fail "the overview lists no prove"
for command in prove verify circuit; do
    "$RANGE" "$command" --help > help.txt
    grep -q "^Usage: kanhe-range $command" help.txt || fail "$command --help"
    "$RANGE" help "$command" > help.txt
    grep -q "^Usage: kanhe-range $command" help.txt || fail "help $command"
done
code=0; "$RANGE" > /dev/null 2>&1 || code=$?
[ "$code" -eq 2 ] || fail "no command: exit $code"
code=0; "$RANGE" sign < /dev/null > /dev/null 2>&1 || code=$?
[ "$code" -eq 2 ] || fail "an unknown command: exit $code"
code=0; "$RANGE" prove extra < /dev/null > /dev/null 2>&1 || code=$?
[ "$code" -eq 2 ] || fail "an argument to prove: exit $code"

# --- A proof, verified -----------------------------------------------------------
run prove 0 "$(statement 1000 10 100000 ",\"seed\":\"$SEED\"")"
[ "$(json 'd["commitment"]')" = "$C" ] || fail "the commitment"
PROOF="$(json 'd["proof"]')"
[ "$(json 'sorted(d)')" = "['commitment', 'proof']" ] || fail "prove's output"
[ "${#PROOF}" -gt 120000 ] || fail "a short proof"
cp out.json seeded.json
run prove 0 "$(statement 1000 10 100000 ",\"seed\":\"$SEED\"")"
cmp -s seeded.json out.json || fail "the same seed made another proof"
run prove 0 "$(statement 1000 10 100000)"
cmp -s seeded.json out.json && fail "an unseeded proof is the seeded one"

run verify 0 "$(check 10 100000 "$T" "$PROOF")"
[ "$(json 'd')" = "{'valid': True}" ] || fail "verify's output"

# Another statement: not valid, the reason on standard error.
run verify 1 "$(check 11 100000 "$T" "$PROOF")"
[ "$(json 'd')" = "{'valid': False}" ] || fail "another bound"
grep -q 'does not verify' err.txt || fail "no reason given"
run verify 1 "$(check 10 100000 "${T}00" "$PROOF")"
run verify 1 "$(check 10 100000 "$T" "$PROOF" "$SALT")"
run verify 1 "$(check 10 100000 "$T" "${PROOF}00")"
run verify 1 "$(check 10 100000 "$T" "")"
run verify 1 "$(check 100000 10 "$T" "$PROOF")"

# The bounds' extremes.
run prove 0 "$(statement "$max" 0 "$max")"

# --- A false statement, and input errors -----------------------------------------
run prove 1 "$(statement 9 10 100000)"
json 'd["error"]' | grep -q 'outside the range' || fail "the out-of-range error"
run prove 1 "$(statement 0 1 "$max")"
for input in \
    'not JSON' \
    '[]' \
    "$(statement 1000 10 100000 ',"extra":"1"')" \
    "$(statement 01000 10 100000)" \
    "$(statement 18446744073709551616 10 100000)" \
    "$(statement -1 0 100000)" \
    "$(statement '' 10 100000)" \
    "$(statement 1000 10 100000 ',"seed":"a5a5"')" \
    "$(printf '{"salt":"00","value":"1000","low":"10","high":"100000","transcript":"%s"}' "$T")" \
    "$(printf '{"salt":"%s","value":1000,"low":"10","high":"100000","transcript":"%s"}' "$SALT" "$T")" \
    "$(printf '{"salt":"%s","value":"1000","low":"10","high":"100000"}' "$SALT")" \
    "$(printf '{"salt":"%s","value":"1000","low":"10","high":"100000","transcript":"xyz"}' "$SALT")"; do
    run prove 2 "$input"
    json 'd["error"]' > /dev/null || fail "no error: $input"
done
run verify 2 "$(check 10 100000 "$T" "$PROOF" 00)"
run verify 2 "$(printf '{"commitment":"%s","low":"10","high":"100000","transcript":"%s"}' "$C" "$T")"

# --- The circuit file --------------------------------------------------------------
"$RANGE" circuit --out circuit.bin > out.json
[ "$(json 'd["id"]')" = "$ID" ] || fail "the circuit's id"
[ "$(json 'd["size"]')" = "$(wc -c < circuit.bin | tr -d ' ')" ] || fail "the circuit's size"
[ "$(tail -c 32 circuit.bin | od -An -tx1 | tr -d ' \n')" = "$ID" ] || fail "the file's id"
if "$RANGE" circuit --out circuit.zst --zstd > out.json 2> err.txt; then
    [ "$(json 'd["size"]')" = "$(wc -c < circuit.zst | tr -d ' ')" ] || fail "the zstd size"
    if command -v zstd > /dev/null; then
        zstd -q -d -c circuit.zst | cmp -s - circuit.bin || fail "the zstd file"
    fi
else
    grep -q 'no zstd' err.txt || fail "circuit --zstd"
fi
code=0; "$RANGE" circuit > /dev/null 2>&1 || code=$?
[ "$code" -eq 2 ] || fail "circuit without --out: exit $code"

echo "kanhe-range end to end: OK"
