#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya
#
# Range proofs (spec v0.22), end to end: a record issued with provable
# values (a date, money, a number); its openings exported to a file and
# shown; proofs added to its evidence by a holder (from the file) and by the
# issuer (from the vault), replaced and removed, and verified with and
# without a required context; refusals: values and bounds that cannot be
# read, a value outside its bounds, a field that is not provable, openings
# of another record or altered, a tampered proof; an AI agent's tools; help,
# JSON, and completion. A build without range proofs makes none, and says so.
# Usage: ranges.sh KANHE
set -Eeuo pipefail
trap 'echo "FAILED at line $LINENO: $BASH_COMMAND" >&2' ERR

KANHE="$1"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
cd "$WORK"

export KANHE_PASSPHRASE="ranges test"
export KANHE_LEDGER="$WORK/ledger"
unset KANHE_SERVER KANHE_TOKEN

run() { "$KANHE" "$@"; }
fail() { echo "FAIL: $*"; [ -f out.txt ] && cat out.txt; exit 1; }
expect_exit() {
    local code="$1"; shift
    local actual=0
    run "$@" > out.txt 2>&1 || actual=$?
    [ "$actual" -eq "$code" ] || fail "expected exit $code, got $actual: $*"
}
contains() { grep "$@" > /dev/null; }
json() { python3 -c "import json,sys; d=json.load(sys.stdin); print($1)"; }

# --- Help, JSON, and completion ----------------------------------------------------
for command in "record openings export" "record openings show" "evidence prove" \
    "evidence proof list" "evidence proof remove"; do
    read -r -a words <<< "$command"
    run "${words[@]}" --help | contains -- '--json' || fail "$command --help"
done
run record issue --help | contains -- '--provable NAME:ENCODING' || fail "record issue --help"
run record issue --help | contains 'money:CCY:SCALE' || fail "the encodings, in help"
run evidence prove --help | contains -- '--range-context' || fail "evidence prove --help"
run help --json | json '[c["command"] for c in d]' > commands.txt
for command in "record openings export" "record openings show" "evidence prove" \
    "evidence proof list" "evidence proof remove"; do
    contains "'$command'" commands.txt || fail "help --json: $command"
done
run completion bash > completion.txt
contains -F '"record openings") words="export show"' completion.txt || fail "completion: openings"
contains -F '"evidence proof") words="list remove"' completion.txt || fail "completion: proofs"
contains -F -- '--provable' completion.txt || fail "completion: --provable"
contains -F -- '--at-least' completion.txt || fail "completion: --at-least"
run completion zsh | contains 'prove' || fail "zsh completion"

# --- A record with provable values ---------------------------------------------------
for k in root log person agent; do run key generate --out "$k.key" > /dev/null; done
LEDGER_ID="$(run init --name "Example Staffing" --root-key root.key --log-key log.key --json |
    json 'd["ledger_id"]')"
STAFF="$(run record issue --as root.key --type example.org.staff/1 --field name="Chan Tai Man" \
    --field born=2001-04-02 --field monthly_salary="HKD 32,000.50" --field score=87.5 \
    --provable score:number:1 --provable born:date --provable monthly_salary:money:HKD:2 --json)"
RECORD="$(echo "$STAFF" | json 'd["record"]["id"]')"
[ "$(echo "$STAFF" | json '[p["field"] for p in d["record"]["provable"]]')" = \
    "['born', 'monthly_salary', 'score']" ] || fail "provable values, by name: $STAFF"
[ "$(echo "$STAFF" | json 'd["record"]["provable"][1]["encoding"]')" = \
    "{'type': 'money', 'scale': 2, 'currency': 'HKD'}" ] || fail "money's encoding"
[ "$(echo "$STAFF" | json 'd["record"]["provable"][0]["encoding"]')" = \
    "{'type': 'date', 'scale': None, 'currency': None}" ] || fail "a date's encoding"
[ "$(echo "$STAFF" | json 'len(d["record"]["provable"][2]["commitment"])')" = 64 ] ||
    fail "a commitment of 32 bytes"
run record show "$RECORD" > out.txt
contains "provable:   born (date)" out.txt || fail "record show: a date"
contains "provable:   monthly_salary (money HKD, scale 2)" out.txt || fail "record show: money"
! contains "32,000" out.txt || fail "the values stay sealed"
[ "$(run log show "$RECORD" --json | json 'len(d["statement"]["body"]["provable"])')" = 3 ] ||
    fail "the registration's view"

# Refused, each for its reason; nothing is registered.
issue() { expect_exit 1 record issue --as root.key --type example.org.staff/1 "$@"; }
issue --field age=18 --provable height:number
contains "no field height" out.txt || fail "a field that is not there"
issue --field age=18 --provable age:number --provable age:number:1
contains "marked provable twice" out.txt || fail "a field twice"
issue --field age=18.5 --provable age:number
contains "more than 0 decimals" out.txt || fail "more decimals than the scale"
issue --field born=2001-02-29 --provable born:date
contains "is not a date" out.txt || fail "a date that is not one"
issue --field pay="USD 10.00" --provable pay:money:HKD:2
contains "is in USD, not HKD" out.txt || fail "money of another currency"
issue --field age=9223372036854775808 --provable age:number
contains "out of range" out.txt || fail "a value out of range"
issue --field age=18 --provable age:text
contains "an encoding is number" out.txt || fail "an encoding that is not one"
issue --field age=18 --provable age:number:19
issue --field pay=1 --provable pay:money:hkd:2
issue --field age=18 --provable age
contains "NAME:ENCODING" out.txt || fail "the option's form"
many=()
for i in $(seq 1 65); do many+=(--field "f$i=$i" --provable "f$i:number"); done
issue "${many[@]}"
contains "at most 64 provable values" out.txt || fail "65 provable values"
expect_exit 1 record issue --as root.key --type kanhe.claim/1 --field age=18 --provable age:number
contains "has no provable values" out.txt || fail "a mechanism type"
[ "$(run record list --json | json 'len(d)')" = 1 ] || fail "nothing else registered"

# --- Openings: exported and shown ------------------------------------------------------------
O="$(run record openings export "$RECORD" --out all.kanheopenings --json)"
[ "$(echo "$O" | json 'd["fields"]')" = "['born', 'monthly_salary', 'score']" ] ||
    fail "every opening by default: $O"
[ "$(python3 -c 'import os, sys; print(oct(os.stat(sys.argv[1]).st_mode & 0o777))' \
    all.kanheopenings)" = 0o600 ] || fail "the file is private"
run record openings export "$RECORD" --field born --out born.kanheopenings |
    contains "give it only to whom they belong" || fail "the warning"
S="$(run record openings show born.kanheopenings --json)"
[ "$(echo "$S" | json 'd["record"]')" = "$RECORD" ] || fail "its record"
[ "$(echo "$S" | json 'd["ledger"]')" = "$LEDGER_ID" ] || fail "its ledger"
[ "$(echo "$S" | json '[o["field"] for o in d["openings"]]')" = "['born']" ] || fail "one opening"
[ "$(echo "$S" | json '"x" in d["openings"][0] or "salt" in d["openings"][0]')" = False ] ||
    fail "values hidden unless asked"
[ "$(run record openings show born.kanheopenings --values --json | json 'd["openings"][0]["x"]')" = \
    11414 ] || fail "2001-04-02 is day 11414"
run record openings show born.kanheopenings > out.txt
contains "values hidden" out.txt || fail "values hidden in text"
! contains "11414" out.txt || fail "no value in text"
run record openings show all.kanheopenings --values | contains "monthly_salary  x = 3200050" ||
    fail "money's x"
expect_exit 1 record openings export "$RECORD" --field name --out x.kanheopenings
contains "not a provable value" out.txt || fail "a field that is not provable"
expect_exit 1 record openings export "$RECORD" --field born --field born --out x.kanheopenings
PLAIN="$(run record issue --as root.key --type example.org.note/1 --field text=hello --json |
    json 'd["record"]["id"]')"
expect_exit 2 record openings export "$PLAIN" --out x.kanheopenings
contains "has no provable values" out.txt || fail "a record without provable values"
expect_exit 2 record openings show root.key
contains "is not a range openings file" out.txt || fail "not a range openings file"
[ ! -e x.kanheopenings ] || fail "nothing written on refusal"

# The openings survive a new vault key, and a backup restored elsewhere.
KANHE_NEW_PASSPHRASE="$KANHE_PASSPHRASE" run vault rekey > /dev/null
run record openings export "$RECORD" --field born --out rekeyed.kanheopenings > /dev/null
cmp -s born.kanheopenings rekeyed.kanheopenings || fail "the openings after vault rekey"
run backup create --log-key log.key --out ledger.backup > /dev/null
run backup restore ledger.backup --ledger restored > /dev/null
run record openings export "$RECORD" --ledger restored --field born \
    --out restored.kanheopenings > /dev/null
cmp -s born.kanheopenings restored.kanheopenings || fail "the openings in a restored backup"

# Another record's openings, for the refusals below.
OTHER="$(run record issue --as root.key --type example.org.staff/1 --field born=1999-12-31 \
    --provable born:date --json | json 'd["record"]["id"]')"
run record openings export "$OTHER" --out other.kanheopenings > /dev/null

# --- Its evidence: provable values reported, no proofs yet ------------------------------
run checkpoint create --log-key log.key > /dev/null
run export "$RECORD" --log-key log.key --out staff.cbor > /dev/null
run export "$OTHER" --log-key log.key --out other.cbor > /dev/null
R="$(run verify staff.cbor --ledger-id "$LEDGER_ID" --json)"
[ "$(echo "$R" | json '[p["field"] for p in d["provable"]]')" = \
    "['born', 'monthly_salary', 'score']" ] || fail "the report's provable values: $R"
[ "$(echo "$R" | json 'd["provable"][2]["encoding"]')" = \
    "{'type': 'number', 'scale': 1, 'currency': None}" ] || fail "a number's encoding"
[ "$(echo "$R" | json 'd["range_proofs"]')" = "[]" ] || fail "no proofs yet"

# --- Without range proofs in the build: none made --------------------------------------
code=0
run evidence prove staff.cbor --field born --at-most 2008-11-21 --openings born.kanheopenings \
    --out holder.cbor > out.txt 2>&1 || code=$?
if [ "$code" -eq 2 ] && contains "built without range proofs" out.txt; then
    [ ! -e holder.cbor ] || fail "nothing written without range proofs"
    run evidence proof list staff.cbor | contains "none" || fail "listed without range proofs"
    echo "ranges: passed (built without range proofs: none made)"
    exit 0
fi
[ "$code" -eq 0 ] || fail "a holder proves from the file (exit $code)"

# --- A holder proves, from the file ----------------------------------------------------
P="$(run evidence prove staff.cbor --field born --at-most 2008-11-21 \
    --openings born.kanheopenings --out holder.cbor --json)"
[ "$(echo "$P" | json 'd["proved"]')" = True ] || fail "proved: $P"
[ "$(echo "$P" | json 'd["text"]')" = "born is at most 2008-11-21" ] || fail "in words"
[ "$(echo "$P" | json 'd["opening"]')" = file ] || fail "from the file"
[ "$(echo "$P" | json 'd["replaced"]')" = False ] || fail "a new proof"
[ "$(echo "$P" | json 'd["proof_size"] > 50000')" = True ] || fail "a proof's size"
[ "$(echo "$P" | json 'len(d["range_proofs"])')" = 1 ] || fail "one proof listed"
R="$(run verify holder.cbor --ledger-id "$LEDGER_ID" --json)"
[ "$(echo "$R" | json 'd["verified"]')" = True ] || fail "it verifies: $R"
[ "$(echo "$R" | json 'd["range_proofs"][0]["field"]')" = born ]
[ "$(echo "$R" | json 'd["range_proofs"][0]["text"]')" = "born is at most 2008-11-21" ]
[ "$(echo "$R" | json 'd["range_proofs"][0]["status"]')" = verified ] || fail "verified"
[ "$(echo "$R" | json 'd["range_proofs"][0]["low"]')" = None ] || fail "no low"
[ "$(echo "$R" | json 'd["range_proofs"][0]["high"]')" = 2008-11-21 ] || fail "the high"
[ "$(echo "$R" | json 'd["range_proofs"][0]["context"]')" = None ] || fail "no context"
[ "$(echo "$R" | json 'd["range_proofs"][0]["system"]')" = 1 ] || fail "system 1"
! echo "$R" | contains "2001-04-02" || fail "the birth date stays sealed"
run verify holder.cbor --ledger-id "$LEDGER_ID" | contains "born is at most 2008-11-21" ||
    fail "the text report"
# The default name, never written over.
run evidence prove staff.cbor --field score --between "60 and 99.5" \
    --openings all.kanheopenings > out.txt
contains "wrote staff-proved.cbor (1 range proof, verified)" out.txt || fail "the default name"
contains "proved: score is between 60 and 99.5" out.txt || fail "a number's words"
expect_exit 2 evidence prove staff.cbor --field score --at-least 60 --openings all.kanheopenings
contains "exists already" out.txt || fail "the default never overwrites"

# --- The issuer proves, from the vault, with a context ---------------------------------
CONTEXT=5f1e0c9a2b7d
P="$(run evidence prove staff.cbor --field monthly_salary --at-least "HKD 30,000.00" \
    --context "$CONTEXT" --out issuer.cbor --json)"
[ "$(echo "$P" | json 'd["opening"]')" = vault ] || fail "from the vault: $P"
[ "$(echo "$P" | json 'd["text"]')" = "monthly_salary is at least HKD 30,000.00" ] ||
    fail "money in words"
[ "$(echo "$P" | json 'd["low"]')" = "[3000000, 'HKD', 2]" ] || fail "money's low"
[ "$(echo "$P" | json 'd["context"]')" = "$CONTEXT" ] || fail "its context"
# A required context, met and missed.
R="$(run verify issuer.cbor --ledger-id "$LEDGER_ID" --range-context "$CONTEXT" --json)"
[ "$(echo "$R" | json 'd["verified"]')" = True ] || fail "the context met: $R"
[ "$(echo "$R" | json 'd["range_proofs"][0]["context"]')" = "$CONTEXT" ] || fail "reported"
expect_exit 3 verify issuer.cbor --ledger-id "$LEDGER_ID" --range-context 0102
expect_exit 3 verify holder.cbor --ledger-id "$LEDGER_ID" --range-context "$CONTEXT"
R="$(run verify staff.cbor --ledger-id "$LEDGER_ID" --range-context "$CONTEXT" --json)"
[ "$(echo "$R" | json 'd["verified"] and d["range_proofs"] == []')" = True ] ||
    fail "no proofs meet the requirement, and prove nothing"
# Bare amounts are in the value's currency.
run evidence prove staff.cbor --field monthly_salary --at-most 40000 --out bare.cbor |
    contains "monthly_salary is at most HKD 40,000.00" || fail "a bare amount"

# --- Replaced, added, listed, and removed ------------------------------------------------
cp holder.cbor both.cbor
P="$(run evidence prove both.cbor --field born --between "1990-01-01 and 2008-11-21" \
    --openings all.kanheopenings --in-place --json)"
[ "$(echo "$P" | json 'd["replaced"]')" = True ] || fail "the proof of born replaced"
[ "$(echo "$P" | json 'd["file"]')" = both.cbor ] || fail "in place"
run evidence prove both.cbor --field score --at-least 60 --openings all.kanheopenings \
    --in-place > /dev/null
L="$(run evidence proof list both.cbor --ledger-id "$LEDGER_ID" --json)"
[ "$(echo "$L" | json '[p["text"] for p in d["range_proofs"]]')" = \
    "['born is between 1990-01-01 and 2008-11-21', 'score is at least 60']" ] ||
    fail "two proofs, in order: $L"
[ "$(echo "$L" | json 'len(d["provable"])')" = 3 ] || fail "the values it can prove"
run evidence proof list both.cbor > out.txt
contains "proof:     score is at least 60, verified" out.txt || fail "listed in text"
contains "provable:  born (date), monthly_salary (money:HKD:2), score (number:1)" out.txt ||
    fail "provable values in text"
U="$(run evidence proof remove both.cbor score --out removed.cbor --json)"
[ "$(echo "$U" | json 'd["removed"][0]["text"]')" = "score is at least 60" ] || fail "removed: $U"
[ "$(echo "$U" | json 'len(d["range_proofs"])')" = 1 ] || fail "one left"
[ "$(run verify removed.cbor --json | json 'len(d["range_proofs"])')" = 1 ] || fail "verified"
expect_exit 2 evidence proof remove removed.cbor score --out x.cbor
contains "no range proof of score" out.txt || fail "removing what is not there"
expect_exit 1 evidence proof remove removed.cbor born
contains -- "--in-place" out.txt || fail "where it goes"
expect_exit 1 evidence proof remove removed.cbor born born --out x.cbor
run evidence proof list staff.cbor | contains "proofs:    none" || fail "none listed"

# --- Refusals ---------------------------------------------------------------------------
prove() { expect_exit "$1" evidence prove staff.cbor --out x.cbor "${@:2}"; }
# A value outside the bounds makes no proof.
prove 2 --field born --at-least 2005-01-01 --openings born.kanheopenings
contains "no proof can be made that born is at least 2005-01-01" out.txt || fail "outside"
prove 2 --field monthly_salary --at-least "HKD 40,000"
# A field that is not provable, and bounds that cannot be read.
prove 1 --field name --at-most 5 --openings all.kanheopenings
contains "not a provable value" out.txt || fail "a field that is not provable"
prove 1 --field born --at-most 2008-02-30 --openings all.kanheopenings
prove 1 --field born --at-most 18 --openings all.kanheopenings
prove 1 --field monthly_salary --at-least "USD 5" --openings all.kanheopenings
contains "is in USD, not HKD" out.txt || fail "another currency"
prove 1 --field score --at-least 60.55 --openings all.kanheopenings
contains "more than 1 decimal" out.txt || fail "more decimals than the scale"
prove 1 --field born --between "2008-01-01 and 2007-01-01" --openings all.kanheopenings
prove 1 --field score --between "60 99" --openings all.kanheopenings
prove 1 --field score --at-least 1 --between "1 and 2" --openings all.kanheopenings
prove 1 --field score --openings all.kanheopenings
prove 1 --field score --at-least 1 --context zz --openings all.kanheopenings
prove 1 --field score --at-least 1 --openings all.kanheopenings --ledger ledger
KANHE_LEDGER="" prove 1 --field score --at-least 1
contains "say where the value's opening comes from" out.txt || fail "no opening"
# Openings of another record, and openings altered.
prove 2 --field born --at-most 2008-11-21 --openings other.kanheopenings
contains "the openings are of record" out.txt || fail "another record's openings"
run record openings show born.kanheopenings --values --json > values.json
python3 - values.json altered.kanheopenings <<'PY'
import json, sys
def head(major, n):
    if n < 24: return bytes([major << 5 | n])
    for size, extra in ((1, 24), (2, 25), (4, 26), (8, 27)):
        if n < 1 << (8 * size): return bytes([major << 5 | extra]) + n.to_bytes(size, "big")
def enc(v):
    if isinstance(v, int): return head(0, v) if v >= 0 else head(1, -1 - v)
    if isinstance(v, bytes): return head(2, len(v)) + v
    if isinstance(v, str): return head(3, len(v.encode())) + v.encode()
    if isinstance(v, list): return head(4, len(v)) + b"".join(enc(x) for x in v)
    return head(5, len(v)) + b"".join(enc(k) + enc(x) for k, x in v.items())
d = json.load(open(sys.argv[1]))
o = d["openings"][0]
openings = [[o["field"], bytes.fromhex(o["salt"]), o["x"] + 1]]  # a day later
open(sys.argv[2], "wb").write(enc({1: bytes.fromhex(d["ledger"]), 2: bytes.fromhex(d["record"]),
                                   3: openings}))
PY
[ "$(run record openings show altered.kanheopenings --values --json | json 'd["openings"][0]["x"]')" = \
    11415 ] || fail "the altered file reads"
prove 2 --field born --at-most 2008-11-21 --openings altered.kanheopenings
contains "does not match its commitment" out.txt || fail "an altered opening"
[ ! -e x.cbor ] || fail "nothing written on refusal"

# A tampered proof fails verification, and blocks proving over it; removing it helps.
SIZE="$(run evidence prove staff.cbor --field born --at-most 2008-11-21 \
    --openings born.kanheopenings --out fresh.cbor --json | json 'd["proof_size"]')"
python3 - fresh.cbor tampered.cbor "$SIZE" <<'PY'
import sys
data = bytearray(open(sys.argv[1], "rb").read())
size = int(sys.argv[3])
# The proof's byte string: its head, then its bytes; one bit flipped midway.
head = b"\x59" + size.to_bytes(2, "big") if size < 65536 else b"\x5a" + size.to_bytes(4, "big")
at = data.find(head)
assert at > 0, "the proof's bytes"
data[at + len(head) + size // 2] ^= 0x01
open(sys.argv[2], "wb").write(data)
PY
expect_exit 3 verify tampered.cbor --ledger-id "$LEDGER_ID"
expect_exit 3 evidence proof list tampered.cbor
expect_exit 3 evidence prove tampered.cbor --field score --at-least 60 \
    --openings all.kanheopenings --out x.cbor
contains "the new bundle does not verify" out.txt || fail "proving over a tampered proof"
[ ! -e x.cbor ] || fail "nothing written"
run evidence proof remove tampered.cbor born --out fixed.cbor > /dev/null
[ "$(run verify fixed.cbor --json | json 'd["verified"] and d["range_proofs"] == []')" = True ] ||
    fail "the tampered proof removed"

# --- An AI agent's tools ---------------------------------------------------------------
id_from() { grep -oE '[0-9a-f]{64}' | sed -n 1p; }
PERSON="$(run actor add --as root.key --kind person --name "Pat Issuer" --key person.key | id_from)"
AGENT="$(run actor add --as root.key --kind agent --name "Issuing Agent" --key agent.key \
    --responsible "$PERSON" --model test-model | id_from)"
run delegation grant --as root.key --to "$AGENT" --allow record-register \
    --record-types example.org.staff/1 --days 7 > /dev/null
META='"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientInfo":{"name":"test","version":"1"}}'
cat > requests.jsonl <<JSON
{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{$META,"name":"kanhe_issue_record","arguments":{"record_type":"example.org.staff/1","fields":{"born":"1999-12-31"},"provable":{"born":"date"}}}}
{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{$META,"name":"kanhe_issue_record","arguments":{"record_type":"example.org.staff/1","fields":{"born":"soon"},"provable":{"born":"date"}}}}
{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{$META,"name":"kanhe_verify_evidence","arguments":{"bundle_path":"issuer.cbor","expected_ledger_id":"$LEDGER_ID","range_context":"$CONTEXT"}}}
{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{$META,"name":"kanhe_verify_evidence","arguments":{"bundle_path":"holder.cbor","range_context":"$CONTEXT"}}}
{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{$META,"name":"kanhe_prove_range","arguments":{"bundle_path":"staff.cbor","openings_path":"born.kanheopenings","field":"born","at_most":"2008-11-21","context":"$CONTEXT","out_path":"agent.cbor"}}}
{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{$META,"name":"kanhe_prove_range","arguments":{"bundle_path":"staff.cbor","openings_path":"born.kanheopenings","field":"born","at_least":"2005-01-01","out_path":"agent2.cbor"}}}
{"jsonrpc":"2.0","id":7,"method":"tools/list","params":{$META}}
JSON
run mcp --as agent.key < requests.jsonl > responses.txt 2> /dev/null
result() { sed -n "${1}p" responses.txt | json "d['result']$2"; }
ISSUED="$(result 1 "['structuredContent']['record_id']")"
[ "$(run record show "$ISSUED" --json | json 'd["provable"][0]["field"]')" = born ] ||
    fail "the agent's record has a provable value"
[ "$(result 2 "['isError']")" = True ] || fail "a value that cannot be read, refused"
[ "$(result 3 "['structuredContent']['range_proofs'][0]['status']")" = verified ] ||
    fail "the agent verifies a proof with its context"
[ "$(result 3 "['structuredContent']['provable'][0]['field']")" = born ] || fail "provable"
[ "$(result 4 "['isError']")" = True ] || fail "a proof without the context required"
[ "$(result 5 "['structuredContent']['text']")" = "born is at most 2008-11-21" ] ||
    fail "the agent proves from the openings file"
[ "$(run verify agent.cbor --range-context "$CONTEXT" --json | json 'd["verified"]')" = True ] ||
    fail "the agent's proof verifies"
[ "$(result 6 "['isError']")" = True ] || fail "a value outside the bounds"
[ ! -e agent2.cbor ] || fail "nothing written"
sed -n 7p responses.txt | contains '"name":"kanhe_prove_range"' || fail "tools/list"

echo "ranges: passed"
