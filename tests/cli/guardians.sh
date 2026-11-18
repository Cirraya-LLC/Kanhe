#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya
#
# Guardians (spec v0.20), end to end: the organization names three, two of
# whom must approve its own statements, each in person with a hardware key
# (SoftHSM stands in for theirs). The setting is approved by the new
# guardians; a root key rotation is refused without them and registered
# with 2 of 3; a change is approved by both sets, a guardian in both
# counting in both; a guardian is not revoked below k; an administrator may
# not give a guardian a new key; and removing them takes k of them. The
# evidence shows every setting.
# Usage: guardians.sh KANHE SOFTHSM_MODULE
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
export KANHE_PKCS11_PIN=123456 KANHE_PASSPHRASE="guardians test" KANHE_LEDGER="$WORK/ledger"
unset KANHE_SERVER KANHE_TOKEN KANHE_CLOCK_OFFSET
ukey() { printf 'pkcs11:token=Kanhe;object=%s-ukey?module-path=%s' "$1" "$MODULE"; }

for k in root root2 log chan lee ho pat admin lee2; do
    run key generate --out "$k.key" > /dev/null
    run key public "$k.key" --out "$k.pub" > /dev/null
done
LEDGER_ID="$(run init --name "Example Office" --root-key root.key --log-key log.key --json |
    json 'd["ledger_id"]')"
person() {
    run actor add --as root.key --kind person --name "$1" --key "$2.pub" --json |
        json 'd["actor"]["id"]'
}
CHAN="$(person "Chan Tai Man" chan)"
LEE="$(person "Lee Ka Yan" lee)"
HO="$(person "Ho Wing" ho)"
PAT="$(person "Pat Lam" pat)"
ADMIN="$(person "Admin Office" admin)"
for p in chan lee ho pat; do
    run key generate --pkcs11 "$(ukey "$p")" --alg esp256 --out "$p-ukey.pub" > /dev/null
    run presence enroll --pkcs11 "$(ukey "$p")" --label "$p's key" --out "$p.ukey" > /dev/null
done
run actor set-presence "$CHAN" --as root.key --credential chan.ukey > /dev/null
run actor set-presence "$LEE" --as root.key --credential lee.ukey > /dev/null
run actor set-presence "$HO" --as root.key --credential ho.ukey > /dev/null
run actor set-presence "$PAT" --as root.key --credential pat.ukey > /dev/null
run delegation grant --as root.key --to "$ADMIN" \
    --allow actor-rotate-key,actor-set-presence,actor-revoke > /dev/null
# A record of the organization's, before it has guardians: its evidence will show them.
RECORD="$(run record issue --as root.key --type example.org.notice/1 --field text=hello --json |
    json 'd["record"]["id"]')"
run ledger guardians show | contains "guardians:     none"

# --- Set: approved by the new guardians -----------------------------------------------------
expect_exit 1 ledger guardians set 3 --guardian "$CHAN" --guardian "$LEE" --guardian "$HO" --as root.key
contains "no-spare" out.txt || fail "k equal to n is refused"
expect_exit 2 ledger guardians set 2 --guardian "$CHAN" --guardian "$ADMIN" --guardian "$HO" \
    --as root.key
contains "approves in person" out.txt || fail "a guardian has a passkey or hardware key"
expect_exit 1 ledger guardians set 2 --guardian "$CHAN" --guardian "$LEE" --guardian "$HO" \
    --as chan.key
expect_exit 1 ledger guardians set 2 --guardian "$CHAN" --guardian "$LEE" --guardian "$HO" \
    --as root.key --guard genesis
contains "never guard a genesis" out.txt || fail "not a genesis"
S="$(run ledger guardians set 2 --guardian "$CHAN" --guardian "$LEE" --guardian "$HO" --as root.key \
    --json)"
[ "$(echo "$S" | json 'd["sent_for_approval"] and d["where"] == "ledger directory"')" = True ] ||
    fail "always for approval: $S"
[ "$(echo "$S" | json '[r["source"] for r in d["rules"]]')" = "['new_guardians']" ] ||
    fail "the new guardians approve it: $S"
SET="$(echo "$S" | json 'd["statement_id"]')"
run approval show "$SET" | contains "what:          set guardians: 2 of 3 must approve"
G="$(run approval give "$SET" --as chan.key --presence-key "$(ukey chan)" --yes --json)"
[ "$(echo "$G" | json 'd["registered"]')" = False ] || fail "one of two: $G"
G="$(run approval give "$SET" --as lee.key --presence-key "$(ukey lee)" --yes --json)"
[ "$(echo "$G" | json 'd["registered"]')" = True ] || fail "set with two: $G"
SHOW="$(run ledger guardians show --json)"
[ "$(echo "$SHOW" | json 'd["in_effect"]["k"], d["in_effect"]["of"], d["in_effect"]["guards"]')" = \
    "2 3 None" ] || fail "in effect: $SHOW"
run ledger guardians show | contains "they guard:    every statement the organization signs"
run actor show "$HO" | contains "guardian:      yes"
[ "$(run actor show "$HO" --json | json 'd["guardian"]')" = True ]

# --- Guarded: the organization's own statements need them -----------------------------------
expect_exit 2 record issue --as root.key --type example.org.notice/1 --field text=again
contains "(the guardians)" out.txt || fail "guarded"
expect_exit 2 ledger rotate-root-key --as root.key --new-key root2.pub
contains "needs 2 of " out.txt || fail "the rotation needs them"
contains "add --for-approval" out.txt || fail "the way out"
run ledger rotate-root-key --as root.key --new-key root2.pub --for-approval rotate.kanheapproval \
    > out.txt
contains "written to rotate.kanheapproval" out.txt || fail "in a file"
run approval give rotate.kanheapproval --as ho.key --presence-key "$(ukey ho)" --yes > /dev/null
expect_exit 2 approval submit rotate.kanheapproval
contains "not every rule is met yet" out.txt || fail "1 of 2 is not enough"
[ "$(run ledger keys --json | json 'len(d["root_keys"])')" = 1 ] || fail "not rotated yet"
run approval give rotate.kanheapproval --as chan.key --presence-key "$(ukey chan)" --yes > /dev/null
run approval submit rotate.kanheapproval > out.txt
contains "with 2 approvals" out.txt || fail "registered with 2 of 3"
[ "$(run ledger keys --json | json 'len(d["root_keys"])')" = 2 ] || fail "rotated"
expect_exit 1 ledger guardians remove --as root.key

# --- An administrator may not give a guardian a new key ------------------------------------
expect_exit 2 actor rotate-key "$LEE" --as admin.key --new-key lee2.pub
contains "only by the approver or the organization" out.txt || fail "a guardian's key is protected"
expect_exit 2 actor rotate-key "$LEE" --as admin.key --new-key lee2.pub --for-approval
expect_exit 2 actor set-presence "$LEE" --as admin.key --credential pat.ukey

# --- Changed: approved by both sets ---------------------------------------------------------
S="$(run ledger guardians set 2 --guardian "$LEE" --guardian "$HO" --guardian "$PAT" \
    --as root2.key --for-approval change.kanheapproval --approval-note "Chan steps down" --json)"
[ "$(echo "$S" | json 'sorted(r["source"] for r in d["rules"])')" = \
    "['guardians', 'new_guardians']" ] || fail "both sets: $S"
CHANGE="$(echo "$S" | json 'd["statement_id"]')"
run approval give change.kanheapproval --as chan.key --presence-key "$(ukey chan)" --yes > /dev/null
run approval give change.kanheapproval --as pat.key --presence-key "$(ukey pat)" --yes > /dev/null
expect_exit 2 approval submit change.kanheapproval
contains "not every rule is met yet" out.txt || fail "one of each set is not enough"
run approval show change.kanheapproval > out.txt
contains "note:          Chan steps down" out.txt || fail "the note"
# Lee is in both: approving once, counting in both.
G="$(run approval give change.kanheapproval --as lee.key --presence-key "$(ukey lee)" --yes --json)"
[ "$(echo "$G" | json 'd["complete"]')" = True ] || fail "met with three: $G"
run approval submit change.kanheapproval --json | json 'd["approvals"]' | contains -x 3
SHOW="$(run ledger guardians show --json)"
[ "$(echo "$SHOW" | json 'len(d["settings"])')" = 2 ] || fail "two settings: $SHOW"
run actor show "$CHAN" --json | json 'd["guardian"]' | contains -x False

# --- Not revoked below k ---------------------------------------------------------------------
S="$(run actor revoke "$HO" --as root2.key --for-approval --json)"
REVOKE="$(echo "$S" | json 'd["statement_id"]')"
run approval give "$REVOKE" --as lee.key --presence-key "$(ukey lee)" --yes > /dev/null
run approval give "$REVOKE" --as pat.key --presence-key "$(ukey pat)" --yes --json |
    json 'd["registered"]' | contains -x True
expect_exit 2 actor revoke "$PAT" --as root2.key --for-approval
contains "fewer guardians than must approve" out.txt || fail "fewer than k would remain"
expect_exit 2 actor revoke "$LEE" --as admin.key
contains "organization" out.txt || fail "only the organization revokes a guardian"

# --- Removed: by k of them -------------------------------------------------------------------
S="$(run ledger guardians remove --as root2.key --json)"
REMOVE="$(echo "$S" | json 'd["statement_id"]')"
[ "$(echo "$S" | json '[r["source"] for r in d["rules"]]')" = "['guardians']" ] ||
    fail "the current guardians approve it: $S"
run approval give "$REMOVE" --as lee.key --presence-key "$(ukey lee)" --yes > /dev/null
run approval give "$REMOVE" --as pat.key --presence-key "$(ukey pat)" --yes > /dev/null
[ "$(run ledger guardians show --json | json 'd["in_effect"]')" = None ] || fail "removed"
run ledger guardians show | contains "removed them"
# The root key alone signs again.
run record issue --as root2.key --type example.org.notice/1 --field text=again > /dev/null

# --- The evidence shows every setting -----------------------------------------------------
run checkpoint create --log-key log.key > /dev/null
run export "$RECORD" --log-key log.key --out record.cbor > /dev/null
V="$(run verify record.cbor --ledger-id "$LEDGER_ID" --json)"
[ "$(echo "$V" | json 'd["verified"]')" = True ] || fail "it verifies: $V"
[ "$(echo "$V" | json 'len(d["guardians"]["settings"])')" = 3 ] || fail "every setting: $V"
[ "$(echo "$V" | json 'd["guardians"]["in_effect"]')" = None ] || fail "none in effect: $V"

# --- Help and completion ------------------------------------------------------------------
run ledger guardians set --help | contains -- "--no-spare"
run ledger guardians set --help | contains "always goes for approval"
run ledger rotate-root-key --help | contains -- "--for-approval"
run completion bash | contains "guardians"
echo "guardians: passed"
