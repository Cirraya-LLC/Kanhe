#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya
#
# Approvals (spec v0.20), end to end: a clerk's records need 2 of 3 named
# people, each approving in person with a hardware key (SoftHSM stands in
# for theirs). A record is refused without --for-approval, with its rule in
# words; sent for approval, it is held in the ledger directory, or at the
# server and approved from two other machines (two mirrors), or carried in
# approval files and submitted with them combined. Refused: an actor no rule
# names, the signer, an approval twice, one without presence, one after the
# statement lapsed (a clock run ahead), and one with a key rotated since;
# withdrawn by an admin. The evidence shows who approved.
# Usage: approvals.sh KANHE SOFTHSM_MODULE
set -Eeuo pipefail
trap 'echo "FAILED at line $LINENO: $BASH_COMMAND" >&2' ERR

KANHE="$1"
MODULE="$2"
export LSAN_OPTIONS="suppressions=$(cd "$(dirname "$0")" && pwd)/lsan-softhsm.supp${LSAN_OPTIONS:+:$LSAN_OPTIONS}"
export ASAN_OPTIONS="fast_unwind_on_malloc=0${ASAN_OPTIONS:+:$ASAN_OPTIONS}"
WORK="$(mktemp -d)"
SERVERS=()
cleanup() {
    for pid in ${SERVERS[@]+"${SERVERS[@]}"}; do kill "$pid" 2> /dev/null || true; done
    rm -rf "$WORK"
}
trap cleanup EXIT
cd "$WORK"

# A command, here; or, as `at MACHINE ...`, on a machine of its own: the
# server's ledger through that machine's verified mirror.
run() {
    if [ "$1" = at ]; then
        local cache="$2"
        shift 2
        "$KANHE" "$@" --server "$URL" --cache "$WORK/$cache" --ledger-id "$LEDGER_ID"
    else
        "$KANHE" "$@"
    fi
}
at() { run at "$@"; }
fail() { echo "FAIL: $*"; [ -f out.txt ] && cat out.txt; exit 1; }
contains() { grep "$@" > /dev/null; }
json() { python3 -c "import json,sys; d=json.load(sys.stdin); print($1)"; }
expect_exit() {
    local code="$1"; shift
    local actual=0
    run "$@" > out.txt 2>&1 || actual=$?
    [ "$actual" -eq "$code" ] || fail "expected exit $code, got $actual: $*"
}
start_server() {
    local out="$1"; shift
    "$KANHE" serve --listen 127.0.0.1:0 --json "$@" > "$out" 2> "$out.log" &
    SERVERS+=("$!")
    for _ in $(seq 1 300); do
        if [ -s "$out" ] && python3 -c "import json,sys; json.load(open('$out'))" 2> /dev/null; then
            return 0
        fi
        sleep 0.1
    done
    cat "$out.log"
    fail "the server did not start"
}

mkdir tokens
printf 'directories.tokendir = %s/tokens\nobjectstore.backend = file\nlog.level = ERROR\n' "$WORK" > softhsm2.conf
export SOFTHSM2_CONF="$WORK/softhsm2.conf"
softhsm2-util --init-token --free --label Kanhe --pin 123456 --so-pin 12345678 > /dev/null
export KANHE_PKCS11_PIN=123456 KANHE_PASSPHRASE="approvals test"
unset KANHE_LEDGER KANHE_SERVER KANHE_TOKEN KANHE_CLOCK_OFFSET
L="$WORK/ledger"
ukey() { printf 'pkcs11:token=Kanhe;object=%s-ukey?module-path=%s' "$1" "$MODULE"; }

for k in root log clerk chan lee ho pat; do
    run key generate --out "$k.key" > /dev/null
    run key public "$k.key" --out "$k.pub" > /dev/null
done
LEDGER_ID="$(run init --ledger "$L" --name "Example Office" --root-key root.key --log-key log.key \
    --json | json 'd["ledger_id"]')"
person() {
    run actor add --ledger "$L" --as root.key --kind person --name "$1" --key "$2.pub" --json |
        json 'd["actor"]["id"]'
}
CLERK="$(person "Wong Siu Ming" clerk)"
CHAN="$(person "Chan Tai Man" chan)"
LEE="$(person "Lee Ka Yan" lee)"
HO="$(person "Ho Wing" ho)"
PAT="$(person "Pat Lam" pat)"
for p in chan lee ho pat; do
    run key generate --pkcs11 "$(ukey "$p")" --alg esp256 --out "$p-ukey.pub" > /dev/null
    run presence enroll --pkcs11 "$(ukey "$p")" --label "$p's key" --out "$p.ukey" > /dev/null
done
run actor set-presence "$CHAN" --ledger "$L" --as root.key --credential chan.ukey > /dev/null
run actor set-presence "$LEE" --ledger "$L" --as root.key --credential lee.ukey > /dev/null
run actor set-presence "$HO" --ledger "$L" --as root.key --credential ho.ukey > /dev/null
run actor set-presence "$PAT" --ledger "$L" --as root.key --credential pat.ukey > /dev/null

# --- The rule: 2 of Chan, Lee, and Ho, within 7 days, in person ---------------------------
expect_exit 1 delegation grant --ledger "$L" --as root.key --to "$CLERK" --allow record-register \
    --approvals 4 --approver "$CHAN" --approver "$LEE" --approver "$HO"
expect_exit 1 delegation grant --ledger "$L" --as root.key --to "$CLERK" --allow record-register \
    --approvals 2 --approver "$CHAN" --approver "$LEE" --approval-within 31d
expect_exit 1 delegation grant --ledger "$L" --as root.key --to "$CLERK" --allow record-register \
    --approval-within 7d
expect_exit 1 delegation grant --ledger "$L" --as root.key --to "$CLERK" --allow record-register \
    --approvals 1 --approver "$LEDGER_ID"
CLERK_DELEGATION="$(run delegation grant --ledger "$L" --as root.key --to "$CLERK" \
    --allow record-register,record-revoke --approvals 2 --approver "$CHAN" --approver "$LEE" \
    --approver "$HO" --json | json 'd["statement_id"]')"
D="$(run delegation show "$CLERK_DELEGATION" --ledger "$L" --json)"
[ "$(echo "$D" | json 'd["scope"]["approvals"]["needed"]')" = 2 ] || fail "k: $D"
[ "$(echo "$D" | json 'd["scope"]["approvals"]["within_ms"]')" = 604800000 ] || fail "7 days: $D"
[ "$(echo "$D" | json 'len(d["approval_rules"])')" = 1 ] || fail "the chain's rules: $D"
run delegation show "$CLERK_DELEGATION" --ledger "$L" > out.txt
contains "approvals:     2 of " out.txt || fail "the rule in words"
contains "Ho Wing" out.txt && contains "within 7 days, in person" out.txt || fail "who, how"
run actor show "$CHAN" --ledger "$L" > out.txt
contains 'approves:      statements of "Wong Siu Ming"' out.txt || fail "what Chan approves"
[ "$(run actor show "$LEE" --ledger "$L" --json | json 'd["approves"][0]["needed"]')" = 2 ]

# --- Refused without --for-approval, with the rule in words --------------------------------
expect_exit 2 record issue --ledger "$L" --as clerk.key --type example.org.form/1 --field amount=1200
contains "needs 2 of " out.txt || fail "the rule"
contains "within 7 days: add --for-approval" out.txt || fail "the way out"
expect_exit 1 record issue --ledger "$L" --as clerk.key --type example.org.form/1 \
    --field amount=1200 --show-fields

# --- Held in the ledger directory ---------------------------------------------------------
S="$(run record issue --ledger "$L" --as clerk.key --type example.org.form/1 --field amount=1200 \
    --for-approval --show-fields --approval-note "the first form" --json)"
[ "$(echo "$S" | json 'd["sent_for_approval"] and d["where"] == "ledger directory"')" = True ] ||
    fail "held here: $S"
[ "$(echo "$S" | json 'd["rules"][0]["missing"]')" = 2 ] || fail "two missing: $S"
[ "$(echo "$S" | json 'd["fields_shown"]')" = True ]
FIRST="$(echo "$S" | json 'd["statement_id"]')"
[ -f "$L/approvals/held/$FIRST.cbor" ] || fail "held in the directory"
run approval list --ledger "$L" > out.txt
contains "${FIRST:0:12}  open" out.txt || fail "listed"
contains "needs 2 more of 2" out.txt || fail "what is missing"
[ "$(run approval list --ledger "$L" --mine --as chan.pub --json | json 'len(d["approvals"])')" = 1 ]
[ "$(run approval list --ledger "$L" --mine --as clerk.pub --json | json 'len(d["approvals"])')" = 0 ]
[ "$(run approval list --ledger "$L" --approver "$PAT" --json | json 'len(d["approvals"])')" = 0 ]
expect_exit 1 approval list --ledger "$L" --wait 5
run approval show "${FIRST:0:12}" --ledger "$L" > out.txt
contains "what:          issue example.org.form/1" out.txt || fail "what it does"
contains "amount: 1200" out.txt || fail "the fields shown"
contains "note:          the first form" out.txt || fail "the note"
contains "status:        waiting for approvals" out.txt || fail "waiting"
V="$(run approval show "$FIRST" --ledger "$L" --json)"
[ "$(echo "$V" | json 'd["fields"][0]["name"] + "=" + d["fields"][0]["value"]')" = amount=1200 ]
[ "$(echo "$V" | json 'd["missing"]')" = "[2]" ] || fail "missing: $V"
# Refused: the signer, an actor no rule names, without presence.
expect_exit 2 approval give "$FIRST" --ledger "$L" --as clerk.key --presence-key "$(ukey chan)" --yes
contains "you signed this statement" out.txt || fail "the signer"
expect_exit 2 approval give "$FIRST" --ledger "$L" --as pat.key --presence-key "$(ukey pat)" --yes
contains "no approval rule of this statement names" out.txt || fail "not an approver"
expect_exit 1 approval give "$FIRST" --ledger "$L" --as chan.key --yes
contains "approve in person" out.txt || fail "without presence"
G="$(run approval give "${FIRST:0:12}" --ledger "$L" --as chan.key --presence-key "$(ukey chan)" \
    --yes --json)"
[ "$(echo "$G" | json 'd["registered"]')" = False ] || fail "one of two: $G"
expect_exit 2 approval give "$FIRST" --ledger "$L" --as chan.key --presence-key "$(ukey chan)" --yes
contains "approved this statement already" out.txt || fail "twice"
G="$(run approval give "$FIRST" --ledger "$L" --as ho.key --presence-key "$(ukey ho)" --yes --json)"
[ "$(echo "$G" | json 'd["registered"]')" = True ] || fail "registered with the second: $G"
run record show "$FIRST" --ledger "$L" > /dev/null
[ ! -f "$L/approvals/held/$FIRST.cbor" ] || fail "held no more"
[ "$(run approval list --ledger "$L" --all --json | json 'd["approvals"][0]["state"]')" = registered ]

# --- Held at a server, approved from two other machines -------------------------------------
run token create --ledger "$L" ops --scope read,submit,admin --out ops.token > /dev/null
run token create --ledger "$L" desk --scope read,submit --out desk.token > /dev/null
start_server server.json --ledger "$L" --log-key log.key --checkpoint-interval 0
URL="$(json 'd["url"]' < server.json)"
export KANHE_TOKEN="$(cat desk.token)"
S="$(at clerk-machine record issue --as clerk.key --type example.org.form/1 --field amount=880 \
    --field payee="Lee Ka Yan" --for-approval --json)"
[ "$(echo "$S" | json 'd["where"]')" = server ] || fail "held at the server: $S"
[ "$(echo "$S" | json 'd["held"]["missing"]')" = "[2]" ] || fail "the server's answer: $S"
SECOND="$(echo "$S" | json 'd["statement_id"]')"
at chan-machine approval list --mine --as chan.pub > out.txt
contains "${SECOND:0:12}  open" out.txt || fail "Chan's list"
at chan-machine approval show "${SECOND:0:12}" > out.txt
contains "from:          held at http://127.0.0.1" out.txt || fail "where it is held"
contains "fields:        not shown" out.txt || fail "fields stay sealed"
G="$(at chan-machine approval give "${SECOND:0:12}" --as chan.key --presence-key "$(ukey chan)" \
    --yes --json)"
[ "$(echo "$G" | json 'd["registered"] is False and d["held"]["missing"] == [1]')" = True ] ||
    fail "one more needed: $G"
# Twice: the server keeps one per approver.
expect_exit 2 at chan-machine approval give "$SECOND" --as chan.key --presence-key "$(ukey chan)" --yes
expect_exit 2 at pat-machine approval give "$SECOND" --as pat.key --presence-key "$(ukey pat)" --yes
G="$(at lee-machine approval give "$SECOND" --as lee.key --presence-key "$(ukey lee)" --yes --json)"
[ "$(echo "$G" | json 'd["registered"]')" = True ] || fail "registered by the server: $G"
INDEX="$(echo "$G" | json 'd["index"]')"
at clerk-machine record show "$SECOND" > /dev/null
# The evidence names who approved, and how.
KANHE_TOKEN="$(cat ops.token)" at clerk-machine checkpoint create > /dev/null
at clerk-machine export "$SECOND" --out second.cbor > /dev/null
E="$(run verify second.cbor --ledger-id "$LEDGER_ID" --json)"
[ "$(echo "$E" | json 'd["verified"]')" = True ] || fail "it verifies: $E"
[ "$(echo "$E" | json 'sorted(a["approver"]["name"] for e in d["events"] for a in e["approvals"])')" = \
    "['Chan Tai Man', 'Lee Ka Yan']" ] || fail "the approvers: $E"
run verify second.cbor --ledger-id "$LEDGER_ID" > out.txt
contains "Lee Ka Yan" out.txt || fail "the approvers in words"
[ "$(at clerk-machine log show "$INDEX" --json | json 'len(d["approvals"])')" = 2 ] ||
    fail "the log entry keeps both"

# --- By file: carried between the approvers, combined, and submitted ------------------------
S="$(at clerk-machine record issue --as clerk.key --type example.org.form/1 --field amount=990 \
    --for-approval third.kanheapproval --show-fields --json)"
[ "$(echo "$S" | json 'd["where"] + " " + d["file"]')" = "file third.kanheapproval" ] ||
    fail "written to a file: $S"
THIRD="$(echo "$S" | json 'd["statement_id"]')"
at clerk-machine record issue --as clerk.key --type example.org.form/1 --field amount=990 \
    --for-approval "$WORK" > out.txt
contains "written to $WORK/" out.txt || fail "a file named after it, in a directory"
contains "its fields" out.txt && fail "no fields unless shown"
at chan-machine approval show third.kanheapproval --json | json 'd["fields"][0]["value"]' |
    contains -x 990
cp third.kanheapproval lee-copy.kanheapproval
G="$(at chan-machine approval give third.kanheapproval --as chan.key \
    --presence-key "$(ukey chan)" --yes --json)"
[ "$(echo "$G" | json 'd["complete"]')" = False ] || fail "one of two: $G"
expect_exit 2 at clerk-machine approval submit third.kanheapproval
contains "not every rule is met yet" out.txt || fail "one is not enough"
at lee-machine approval give lee-copy.kanheapproval --as lee.key --presence-key "$(ukey lee)" \
    --yes --out lee.kanheapproval > out.txt
contains "approved statement $THIRD" out.txt || fail "into another file"
R="$(at clerk-machine approval submit third.kanheapproval lee.kanheapproval --json)"
[ "$(echo "$R" | json 'd["statement_id"] + " " + str(d["approvals"])')" = "$THIRD 2" ] ||
    fail "combined and registered: $R"
# Submitted again: registered already.
at clerk-machine approval submit third.kanheapproval lee.kanheapproval | contains "registered already"
# Another statement's file is not combined with it.
at clerk-machine record issue --as clerk.key --type example.org.form/1 --field amount=1 \
    --for-approval other.kanheapproval > /dev/null
expect_exit 2 at clerk-machine approval submit third.kanheapproval other.kanheapproval
contains "different statements" out.txt || fail "one statement"
printf 'not an approval file' > junk.kanheapproval
expect_exit 2 at clerk-machine approval show junk.kanheapproval

# --- Lapsed: an approver's clock past the window ------------------------------------------
at clerk-machine record issue --as clerk.key --type example.org.form/1 --field amount=5 \
    --for-approval late.kanheapproval > /dev/null
KANHE_CLOCK_OFFSET=8d expect_exit 2 at chan-machine approval give late.kanheapproval --as chan.key \
    --presence-key "$(ukey chan)" --yes
contains "lapsed" out.txt || fail "lapsed"
KANHE_CLOCK_OFFSET=8d at chan-machine approval show late.kanheapproval | contains "LAPSED"

# --- An approver's key rotated: its approval dies with the old key ------------------------
S="$(at clerk-machine record issue --as clerk.key --type example.org.form/1 --field amount=7 \
    --for-approval --json)"
FOURTH="$(echo "$S" | json 'd["statement_id"]')"
at chan-machine approval give "$FOURTH" --as chan.key --presence-key "$(ukey chan)" --yes > /dev/null
run key generate --out chan2.key > /dev/null
run key public chan2.key --out chan2.pub > /dev/null
at chan-machine actor rotate-key "$CHAN" --as chan.key --new-key chan2.pub \
    --presence-key "$(ukey chan)" > /dev/null
for _ in $(seq 1 50); do
    DROPPED="$(at chan-machine approval list --json | python3 -c "
import json, sys
d = json.load(sys.stdin)
print(sum(len(a['dropped']) for a in d['approvals'] if a['id'] == '$FOURTH'))")"
    [ "$DROPPED" = 1 ] && break
    sleep 0.2
done
[ "$DROPPED" = 1 ] || fail "the old key's approval is dropped and listed"
[ "$(at chan-machine approval show "$FOURTH" --json | json 'd["missing"]')" = "[2]" ]
expect_exit 2 at chan-machine approval give "$FOURTH" --as chan.key --presence-key "$(ukey chan)" --yes
contains "does not belong to any actor" out.txt || fail "the old key approves nothing"
G="$(at chan-machine approval give "$FOURTH" --as chan2.key --presence-key "$(ukey chan)" --yes \
    --json)"
[ "$(echo "$G" | json 'd["held"]["missing"]')" = "[1]" ] || fail "approved again: $G"

# --- Withdrawn: by an admin ---------------------------------------------------------------
expect_exit 2 at clerk-machine approval withdraw "$FOURTH"
KANHE_TOKEN="$(cat ops.token)" at clerk-machine approval withdraw "${FOURTH:0:12}" |
    contains "withdrew statement $FOURTH"
[ "$(at clerk-machine approval list --all --json | python3 -c "
import json, sys
print([a['state'] for a in json.load(sys.stdin)['approvals'] if a['id'] == '$FOURTH'])")" = \
    "['withdrawn']" ] || fail "listed as withdrawn"
expect_exit 2 at chan-machine approval give "$FOURTH" --as lee.key --presence-key "$(ukey lee)" --yes

# --- Help and completion ------------------------------------------------------------------
run record issue --help | contains -- "--for-approval \[FILE\]"
run actor revoke --help | contains -- "--show-fields"
run approval give --help | contains -- "--presence-key"
run approval list --help | contains -- "--mine"
run approval submit --help | contains "approval files"
run delegation grant --help | contains -- "--approvals-without-presence"
run completion bash | contains "approval"
run completion bash | contains -- "--for-approval"
echo "approvals: passed"
