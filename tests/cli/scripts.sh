#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya
#
# Scripts (spec v0.18), end to end: a person approves one version of a
# script, in person with a hardware key (SoftHSM stands in for it), by its
# files' digests; a device's records name it; their evidence says what it
# was and who approved it, and that it was withdrawn since; files on disk
# are checked against the approval. An auditor runs a deterministic script
# again on a record's sources and compares (record recompute); an
# executor's connector names the script it runs.
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
ENGINE_DELEGATION="$(run delegation grant --as root.key --to "$ENGINE" --allow record-register \
    --days 1 --json | json 'd["statement_id"]')"

# --- The script's files -----------------------------------------------------------------
mkdir -p src/model src/.git
printf '{"weights": [3, 1, 4]}\n' > src/model/weights.json
# The score from the book's total and the weights; "band" is no field of the record.
cat > src/run.py << 'EOF'
import json, sys
weights = json.load(open("model/weights.json"))["weights"]
book = json.load(sys.stdin)["sources"][0]["fields"]
print(json.dumps({"score": str(int(book["total"]) * weights[0] // 4 - weights[2] * 10),
                  "band": "B"}))
EOF
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
    --field note=checked --script "$SCRIPT" --source "$BOOK" --json | json 'd["record"]["id"]')"
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

# --- Recomputed: the script run again on its source's fields, and compared ----------------
run export "$BOOK" --log-key log.key --disclose total --out book.cbor > /dev/null
run export "$SCORE" --log-key log.key --disclose score,note --out score-fields.cbor > /dev/null
R="$(run record recompute score-fields.cbor --script-dir src --run "python3 run.py" \
    --source book.cbor --ledger-id "$LEDGER_ID" --json)"
[ "$(echo "$R" | json 'd["recomputed"] and d["verified"]')" = True ] || fail "it recomputes: $R"
[ "$(echo "$R" | json '[(f["name"], f["status"]) for f in d["fields"]]')" = \
    "[('band', 'not_disclosed'), ('note', 'not_recomputed'), ('score', 'match')]" ] ||
    fail "each field: $R"
[ "$(echo "$R" | json 'd["sources"][0]["record"] + " " + ",".join(d["sources"][0]["fields"])')" = \
    "$BOOK total" ] || fail "the source: $R"
[ "$(echo "$R" | json '[f["status"] for f in d["script"]["files"]]')" = "['same', 'same']" ]
run record recompute score-fields.cbor --script-dir src --run "python3 run.py" \
    --source book.cbor > out.txt
contains "score: match" out.txt || fail "a match in words"
contains "band: cannot be checked (not disclosed)" out.txt || fail "not disclosed"
contains "note: not recomputed" out.txt || fail "not recomputed"
contains "Recomputed: every field compared matches (1 of 2 disclosed)" out.txt || fail "verdict"
# A record that does not hold what its script makes: it differs.
WRONG="$(run record issue --as engine.key --type example.org.report/1 --field score=999 \
    --script "$SCRIPT" --source "$BOOK" --json | json 'd["record"]["id"]')"
run checkpoint create --log-key log.key > /dev/null
run export "$WRONG" --log-key log.key --disclose score --out wrong.cbor > /dev/null
expect_exit 3 record recompute wrong.cbor --script-dir src --run "python3 run.py" \
    --source book.cbor
contains 'score: differs (recorded "999", recomputed "710")' out.txt || fail "both values"
contains "RECOMPUTATION DIFFERS: 1 field differs" out.txt || fail "the verdict, differs"
[ "$(run record recompute wrong.cbor --script-dir src --run "python3 run.py" \
    --source book.cbor --json | json 'd["recomputed"]' || true)" = False ]
# The auditor's own command line: split into words, run without a shell, in the directory,
# with a minimal environment (no KANHE_* variable reaches it).
E="$(run record recompute score-fields.cbor --script-dir src --source book.cbor --json \
    --run "python3 -c 'import json, os; print(json.dumps({\"score\": sorted(os.environ), \"note\": os.getcwd()}))'")" ||
    true
[ "$(echo "$E" | json 'd["differ"]')" = 2 ] || fail "both differ: $E"
echo "$E" | python3 -c '
import json, os, sys
d = {f["name"]: f["recomputed"] for f in json.load(sys.stdin)["fields"]}
assert not [n for n in d["score"] if n.startswith("KANHE_")], d["score"]
assert "LC_ALL" in d["score"] and "TZ" in d["score"] and "PATH" in d["score"], d["score"]
assert d["note"] == os.path.realpath("src"), d["note"]
' || fail "a minimal environment, in the directory: $E"
expect_exit 1 record recompute score-fields.cbor --script-dir src --source book.cbor \
    --run "python3 run.py > out.json"
contains "without a shell" out.txt || fail "no shell"
[ ! -e src/out.json ] && [ ! -e out.json ] || fail "nothing redirected"
# Refused: files not as approved, a source missing or not named, a timeout, a failure,
# nothing disclosed, evidence that does not verify.
expect_exit 2 record recompute score-fields.cbor --script-dir changed --run "python3 run.py" \
    --source book.cbor
contains "as approved: model/weights.json changed, run.py missing" out.txt || fail "the files"
expect_exit 1 record recompute score-fields.cbor --script-dir src --run "python3 run.py"
contains "no --source for the source ${BOOK:0:12} (on this ledger)" out.txt ||
    fail "the missing source named"
expect_exit 1 record recompute score-fields.cbor --script-dir src --run "python3 run.py" \
    --source book.cbor --source book.cbor
expect_exit 1 record recompute score-fields.cbor --script-dir src --run "python3 run.py" \
    --source score.cbor
contains "not of a source the record names" out.txt || fail "a record that is no source"
expect_exit 2 record recompute score-fields.cbor --script-dir src --source book.cbor \
    --run "python3 -c 'import time; time.sleep(30)'" --timeout 1
contains "did not finish within 1 s" out.txt || fail "stopped at the timeout"
expect_exit 2 record recompute score-fields.cbor --script-dir src --source book.cbor \
    --run "python3 -c 'import sys; sys.exit(4)'"
contains "exited with status 4" out.txt || fail "a failure"
expect_exit 2 record recompute score-fields.cbor --script-dir src --source book.cbor \
    --run "python3 -c 'print(42)'"
contains "not one JSON object" out.txt || fail "not an object"
expect_exit 2 record recompute score.cbor --script-dir src --run "python3 run.py" \
    --source book.cbor
contains "discloses none" out.txt || fail "nothing to compare"
printf 'not evidence' > junk.cbor
expect_exit 3 record recompute junk.cbor --script-dir src --run "python3 run.py"
contains "VERIFICATION FAILED" out.txt || fail "evidence that does not verify"
expect_exit 1 record recompute score-fields.cbor --script-dir src --run "python3 run.py" \
    --source book.cbor --timeout 0

# --- An executor's connector names the script it runs ---------------------------------------
printf '{"version": 1, "ledger_id": "%s", "actor": "%s", "delegation": "%s"}\n' \
    "$LEDGER_ID" "$ENGINE" "$ENGINE_DELEGATION" > engine.json
run executor connector add scorer --config engine.json --type command --kinds score.request \
    --program "$WORK/src/run.py" --script "${SCRIPT:0:12}" > out.txt
contains "its answers name the script $SCRIPT" out.txt || fail "the script, in full"
[ "$(run executor connector show scorer --config engine.json --json | json 'd["script"]')" = \
    "$SCRIPT" ] || fail "kept in the config"
run executor connector show scorer --config engine.json | contains "script: *$SCRIPT"
run executor connector list --config engine.json | contains "script ${SCRIPT:0:12}"
[ "$(run executor connector list --config engine.json --json | json 'd[0]["script"]')" = \
    "$SCRIPT" ]
# An approved script of the executor's own ledger, for a command or a program only.
expect_exit 1 executor connector add other --config engine.json --type command --kinds other \
    --program /bin/true --script "$BOOK"
contains "not an approved script" out.txt || fail "a record that is no script"
expect_exit 1 executor connector add hook --config engine.json --type webhook --kinds hook \
    --url https://hooks.example.com/x --secret hook-key --script "$SCRIPT"
printf '{"version": 1, "ledger_id": "%s", "actor": "%s", "delegation": "%s"}\n' \
    "$(printf 'a%.0s' {1..64})" "$ENGINE" "$ENGINE_DELEGATION" > elsewhere.json
expect_exit 1 executor connector add scorer --config elsewhere.json --type command \
    --kinds score.request --program /bin/true --script "$SCRIPT"
contains "checked on the executor's own ledger" out.txt || fail "another ledger's config"
[ "$(run executor connector list --config engine.json --json | json 'len(d)')" = 1 ] ||
    fail "nothing added by the refusals"

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
# Recomputed only against an approval that stands, as of the evidence's checkpoint.
run export "$SCORE" --log-key log.key --disclose score --out score-now-fields.cbor > /dev/null
expect_exit 2 record recompute score-now-fields.cbor --script-dir src --run "python3 run.py" \
    --source book.cbor
contains "was withdrawn on" out.txt || fail "withdrawn: nothing to recompute against"
run record recompute score-fields.cbor --script-dir src --run "python3 run.py" \
    --source book.cbor > /dev/null
expect_exit 2 executor connector add late --config engine.json --type command --kinds late \
    --program /bin/true --script "$SCRIPT"
contains "was withdrawn" out.txt || fail "a withdrawn script names no connector's answers"

# --- A script not stated deterministic: nothing to recompute -------------------------------
DRAFT_SCRIPT="$(run script approve draft-model 0.1 model run.py --root src --as alice.key \
    --presence-key "$UKEY" --json | json 'd["script"]["script"]')"
DRAFT="$(run record issue --as engine.key --type example.org.report/1 --field score=710 \
    --script "$DRAFT_SCRIPT" --source "$BOOK" --json | json 'd["record"]["id"]')"
run checkpoint create --log-key log.key > /dev/null
run export "$DRAFT" --log-key log.key --disclose score --out draft.cbor > /dev/null
expect_exit 2 record recompute draft.cbor --script-dir src --run "python3 run.py" \
    --source book.cbor
contains "not stated deterministic" out.txt || fail "not deterministic"

# --- Help and completion -------------------------------------------------------------------
run script approve --help | contains -- "--deterministic"
run script check --help | contains "Exit status 3"
run record recompute --help | contains "no shell runs it"
run executor connector add --help | contains "name it in their provenance"
run completion bash | contains "script"
run completion bash | contains "recompute"
echo "scripts: passed"
