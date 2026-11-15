#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya
#
# Scripts (spec v0.18), end to end: a person approves one version of a
# script, in person with a hardware key (SoftHSM stands in for it), by its
# files' digests; a device's records name it; their evidence says what it
# was and who approved it, and that it was withdrawn since; files on disk
# are checked against the approval.
# Usage: scripts.sh KANHE SOFTHSM_MODULE
set -Eeuo pipefail
trap 'echo "FAILED at line $LINENO: $BASH_COMMAND" >&2' ERR

KANHE="$1"
MODULE="$2"
export LSAN_OPTIONS="suppressions=$(cd "$(dirname "$0")" && pwd)/lsan-softhsm.supp${LSAN_OPTIONS:+:$LSAN_OPTIONS}"
export ASAN_OPTIONS="fast_unwind_on_malloc=0${ASAN_OPTIONS:+:$ASAN_OPTIONS}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
cd "$WORK"

run() { "$KANHE" "$@"; }
fail() { echo "FAIL: $*"; [ -f out.txt ] && cat out.txt; exit 1; }
contains() { grep "$@" > /dev/null; }
json() { python3 -c "import json,sys; d=json.load(sys.stdin); print($1)"; }
expect_exit() {
    local code="$1"; shift
    local actual=0
    run "$@" > out.txt 2>&1 || actual=$?
    [ "$actual" -eq "$code" ] || fail "expected exit $code, got $actual: $*"
}

mkdir tokens
printf 'directories.tokendir = %s/tokens\nobjectstore.backend = file\nlog.level = ERROR\n' "$WORK" > softhsm2.conf
export SOFTHSM2_CONF="$WORK/softhsm2.conf"
softhsm2-util --init-token --free --label Kanhe --pin 123456 --so-pin 12345678 > /dev/null
export KANHE_PKCS11_PIN=123456 KANHE_PASSPHRASE="scripts test" KANHE_LEDGER="$WORK/ledger"
unset KANHE_SERVER KANHE_TOKEN
UKEY="pkcs11:token=Kanhe;object=alice-ukey?module-path=$MODULE"

for k in root log alice engine; do
    run key generate --out "$k.key" > /dev/null
    run key public "$k.key" --out "$k.pub" > /dev/null
done
run key generate --pkcs11 "$UKEY" --alg esp256 --out alice-ukey.pub > /dev/null
LEDGER_ID="$(run init --name "Example Bank" --root-key root.key --log-key log.key --json |
    json 'd["ledger_id"]')"
ALICE="$(run actor add --as root.key --kind person --name "Alice Risk Officer" --key alice.pub \
    --json | json 'd["actor"]["id"]')"
run presence enroll --pkcs11 "$UKEY" --label "Alice's UKey" --out alice.ukey > /dev/null
run actor set-presence "$ALICE" --as root.key --credential alice.ukey > /dev/null
run delegation grant --as root.key --to "$ALICE" --allow record-register,record-revoke --days 1 \
    > /dev/null
ENGINE="$(run actor add --as root.key --kind device --name "Risk Engine" --key engine.pub \
    --json | json 'd["actor"]["id"]')"
run delegation grant --as root.key --to "$ENGINE" --allow record-register --days 1 > /dev/null

# --- The script's files -----------------------------------------------------------------
mkdir -p src/model src/.git
printf '{"weights": [3, 1, 4]}\n' > src/model/weights.json
printf 'import json, sys\nprint(json.dumps({"score": 710}))\n' > src/run.py
printf 'not part of it\n' > src/.git/HEAD

# --- Approved in person, and only so -----------------------------------------------------
expect_exit 1 script approve risk-model 3.2 model run.py --root src --as alice.key
contains "approved in person" out.txt || fail "presence is required"
expect_exit 1 script approve risk-model 3.2 ../etc/passwd --root src --as alice.key \
    --presence-key "$UKEY"
expect_exit 1 script approve risk-model 3.2 nothing-here --root src --as alice.key \
    --presence-key "$UKEY"
# The organization is no person, and proves no presence.
expect_exit 1 script approve risk-model 3.2 model run.py --root src --as root.key \
    --presence-key "$UKEY"
contains "only people prove presence" out.txt || fail "not the organization"
A="$(run script approve risk-model 3.2 model run.py --root src --deterministic \
    --runtime "python 3.12" --note "reviewed with the model risk team" --as alice.key \
    --presence-key "$UKEY" --json)"
SCRIPT="$(echo "$A" | json 'd["script"]["script"]')"
[ "$(echo "$A" | json '[f["path"] for f in d["script"]["files"]]')" = \
    "['model/weights.json', 'run.py']" ] || fail "two files, by path, hidden ones left out: $A"
[ "$(echo "$A" | json 'd["script"]["presence"]')" = hardware-key ] || fail "in person: $A"
run script list > out.txt
contains "approved  risk-model 3.2  2 files  by Alice Risk Officer" out.txt || fail "listed"
run script show "$SCRIPT" > out.txt
contains "approved by:   Alice Risk Officer, in person (hardware-key)" out.txt || fail "shown"
contains "deterministic: yes" out.txt || fail "deterministic"
[ "$(run record show "$SCRIPT" --json | json 'd["state"]')" = approved ] || fail "a record"

# --- Files on disk, against the approval --------------------------------------------------
run script check "$SCRIPT" src | contains "matches script risk-model 3.2 as approved"
cp -r src changed
printf '{"weights": [2, 7, 1]}\n' > changed/model/weights.json
rm changed/run.py
expect_exit 3 script check "$SCRIPT" changed
contains "changed  model/weights.json" out.txt || fail "a changed file"
contains "missing  run.py" out.txt || fail "a missing file"
[ "$(run script check "$SCRIPT" changed --json | json 'd["same"]' || true)" = False ]

# --- Records name it; their evidence shows it ---------------------------------------------
BOOK="$(run record issue --as engine.key --type example.org.loan-book/1 --field total=1000 \
    --json | json 'd["record"]["id"]')"
expect_exit 1 record issue --as engine.key --type example.org.report/1 --field score=710 \
    --script "$BOOK"
SCORE="$(run record issue --as engine.key --type example.org.report/1 --field score=710 \
    --script "$SCRIPT" --source "$BOOK" --json | json 'd["record"]["id"]')"
run record show "$SCORE" | contains "script:     risk-model 3.2, $SCRIPT"
run checkpoint create --log-key log.key > /dev/null
run export "$SCORE" --log-key log.key --out score.cbor > /dev/null
V="$(run verify score.cbor --ledger-id "$LEDGER_ID" --json)"
[ "$(echo "$V" | json 'd["verified"] and d["complete"]')" = True ] || fail "it verifies: $V"
[ "$(echo "$V" | json 'd["scripts"][0]["name"] + " " + d["scripts"][0]["version"]')" = \
    "risk-model 3.2" ] || fail "the script: $V"
[ "$(echo "$V" | json 'd["scripts"][0]["presence"]["method"]')" = hardware-key ]
[ "$(echo "$V" | json 'd["scripts"][0]["approved_by"]["name"]')" = "Alice Risk Officer" ]
[ "$(echo "$V" | json 'd["scripts"][0]["withdrawn_at"]')" = None ]
[ "$(echo "$V" | json 'd["events"][0]["provenance"]["script"]')" = "$SCRIPT" ]
run verify score.cbor > out.txt
contains "Script       risk-model 3.2 (2 files, deterministic, python 3.12), approved in person by Alice Risk Officer" out.txt ||
    fail "the script in words"
contains "by the script risk-model 3.2" out.txt || fail "the history says which script"

# --- Withdrawn: no more records name it; earlier ones' evidence says so --------------------
run script revoke "$SCRIPT" --as alice.key --reason "replaced by 3.3" | contains "withdrew script"
expect_exit 2 record issue --as engine.key --type example.org.report/1 --field score=1 \
    --script "$SCRIPT"
[ "$(run script list --json | json 'len(d)')" = 0 ] || fail "withdrawn scripts are left out"
[ "$(run script list --all --json | json 'd[0]["status"]')" = withdrawn ]
run checkpoint create --log-key log.key > /dev/null
run export "$SCORE" --log-key log.key --out score-now.cbor > /dev/null
V="$(run verify score-now.cbor --json)"
[ "$(echo "$V" | json 'd["verified"] and d["scripts"][0]["withdrawn_at"] is not None')" = True ] ||
    fail "withdrawn since: $V"
run verify score-now.cbor | contains "WITHDRAWN on"
run script check "$SCRIPT" src | contains "(since withdrawn)"

# --- Help and completion -------------------------------------------------------------------
run script approve --help | contains -- "--deterministic"
run script check --help | contains "Exit status 3"
run completion bash | contains "script"
echo "scripts: passed"
