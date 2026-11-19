#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya
#
# Evidence for decades (spec v0.21), end to end: a ledger begun with classical
# keys exports a record's evidence; ledger long-term moves its root and log
# keys to ML-DSA-65 (planned, refused when it should be, made, run again); a
# witness whose key is ML-DSA cosigns, dated, beside a classical one; the old
# bundle is renewed from the ledger's directory, renewed again, and renewed
# from its server's open route; verify reports its long-term status; status,
# GET /v1/status, and the MCP tools show the ledger's. With SoftHSM, a ledger
# with guardians sends each rotation for their approval and goes on once
# each is registered.
# Usage: longterm.sh KANHE [SOFTHSM_MODULE]
set -Eeuo pipefail
trap 'echo "FAILED at line $LINENO: $BASH_COMMAND" >&2' ERR

KANHE="$1"
MODULE="${2:-}"
WORK="$(mktemp -d)"
SERVERS=()
cleanup() {
    for pid in ${SERVERS[@]+"${SERVERS[@]}"}; do kill "$pid" 2> /dev/null || true; done
    rm -rf "$WORK"
}
trap cleanup EXIT
cd "$WORK"

export KANHE_PASSPHRASE="long-term test"
export KANHE_LEDGER="$WORK/ledger"
unset KANHE_TOKEN KANHE_SERVER KANHE_CLOCK_OFFSET

# A command line as typed: bo, kanhe-console, and kanhe-index are the
# programs beside kanhe.
run() {
    case "$1" in
    bo | kanhe-console | kanhe-index) "$(dirname "$KANHE")/$1" "${@:2}" ;;
    *) "$KANHE" "$@" ;;
    esac
}
fail() { echo "FAIL: $*"; [ -f out.txt ] && cat out.txt; exit 1; }
expect_exit() {
    local code="$1"; shift
    local actual=0
    run "$@" > out.txt 2>&1 || actual=$?
    [ "$actual" -eq "$code" ] || fail "expected exit $code, got $actual: $*"
}
contains() { grep "$@" > /dev/null; }
json() { python3 -c "import json,sys; d=json.load(sys.stdin); print($1)"; }
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
stop_servers() {
    for pid in ${SERVERS[@]+"${SERVERS[@]}"}; do kill "$pid" 2> /dev/null || true; done
    for pid in ${SERVERS[@]+"${SERVERS[@]}"}; do wait "$pid" 2> /dev/null || true; done
    SERVERS=()
}
# get URL TOKEN OUT: fetches a route to OUT (TOKEN may be empty); prints the status.
get() {
    python3 - "$@" << 'PY'
import sys, urllib.request, urllib.error
url, token, out = sys.argv[1], sys.argv[2], sys.argv[3]
headers = {"Authorization": "Bearer " + token} if token else {}
request = urllib.request.Request(url, headers=headers)
try:
    with urllib.request.urlopen(request, timeout=10) as response:
        status, body = response.status, response.read()
except urllib.error.HTTPError as error:
    status, body = error.code, error.read()
open(out, "wb").write(body)
print(status)
PY
}

# --- The commands exist, with help, JSON, and completion -------------------------------
run ledger long-term --help | contains 'ML-DSA'
run ledger long-term --help | contains -- '--for-approval'
run evidence renew --help | contains 'GET URL/v1/renewal'
run witness cosign --help | contains 'dated'
run status --help | contains 'long-term status'
run help --json | json '[c["command"] for c in d]' > commands.txt
contains "'ledger long-term'" commands.txt || fail "help --json: ledger long-term"
contains "'evidence renew'" commands.txt || fail "help --json: evidence renew"
run completion bash | contains 'long-term'
run completion zsh | contains 'renew'

# --- A ledger begun with classical keys, and a record's evidence ------------------------
for k in root log witness agent other; do run key generate --out "$k.key" > /dev/null; done
for k in pq-witness root-pq log-pq other-root other-log; do
    run key generate --alg ml-dsa-65 --out "$k.key" > /dev/null
done
run key public witness.key --out witness.pub > /dev/null
run key public pq-witness.key --out pq-witness.pub > /dev/null
LEDGER_ID="$(run init --org "Archive Org" --root-key root.key --log-key log.key --json |
    json 'd["ledger_id"]')"
FIRST="$(run record issue --as root.key --type example.document/1 --field result=pass --json |
    json 'd["statement_id"]')"
run checkpoint create --log-key log.key > /dev/null
EXPORTED="$(run export "$FIRST" --log-key log.key --out old.cbor --json | json 'd["checkpoint_size"]')"
run verify old.cbor --ledger-id "$LEDGER_ID" --json > report.json
json 'd["long_term"]["post_quantum"] is False and d["long_term"]["renew_before"].startswith("2030-01-01")' \
    < report.json | contains -x True || fail "a classical bundle: $(cat report.json)"

# The ledger's own status says what to do.
run status --json > status.json
json 'd["long_term"]["post_quantum"], d["long_term"]["genesis_post_quantum"]' < status.json |
    contains -x 'False False' || fail "status: $(cat status.json)"
json 'd["long_term"]["last_post_quantum_cosignature"] is None' < status.json | contains -x True
run status > out.txt
contains 'long term:     root key Ed25519 (classical)' out.txt || fail "status in words"
contains 'run kanhe ledger long-term' out.txt || fail "the advice"

# Two witnesses follow it from its genesis: a classical one, and one whose key is ML-DSA.
run ledger genesis --out genesis.entry > /dev/null
run witness add-log --dir classic-witness --genesis genesis.entry --ledger-id "$LEDGER_ID" > /dev/null
run witness add-log --dir pq-witness --genesis genesis.entry --ledger-id "$LEDGER_ID" > /dev/null
run witness add-log --help | contains 'ml-dsa-65'

# --- ledger long-term: refused when it should be -----------------------------------------
LT=(ledger long-term --as root.key --log-key log.key --new-root-key root-pq.key --new-log-key log-pq.key)
expect_exit 1 ledger long-term --as root.key --log-key log.key --new-root-key other.key \
    --new-log-key log-pq.key
contains 'not post-quantum' out.txt || fail "a classical new key"
expect_exit 1 ledger long-term --as log.key --log-key log.key --new-root-key root-pq.key \
    --new-log-key log-pq.key
contains 'root key in effect' out.txt || fail "--as is not the root key"
expect_exit 1 ledger long-term --as root.key --log-key witness.key --new-root-key root-pq.key \
    --new-log-key log-pq.key
contains 'log key in effect' out.txt || fail "--log-key is not the log key"
expect_exit 1 "${LT[@]}" --alg ml-dsa-87
contains 'goes with --generate' out.txt
expect_exit 1 ledger long-term --as root.key --log-key log.key --new-root-key root-pq.key \
    --new-log-key root-pq.key
contains 'must differ' out.txt

# The plan, and nothing changed.
run "${LT[@]}" --dry-run --json > plan.json
json 'd["dry_run"], [s["status"] for s in d["steps"]], d["remaining"]' < plan.json |
    contains -Fx "True ['planned', 'planned', 'planned'] ['rotate-log-key', 'rotate-root-key', 'checkpoint']" ||
    fail "the plan: $(cat plan.json)"
run "${LT[@]}" --dry-run | contains 'nothing was changed'
[ "$(run ledger keys --json | json 'len(d["log_keys"]), len(d["root_keys"])')" = "1 1" ] ||
    fail "a dry run changes nothing"

# --- ...then made: both keys rotated, a checkpoint with the new log key -------------------
run "${LT[@]}" --json > converted.json
json '[s["status"] for s in d["steps"]], d["remaining"]' < converted.json |
    contains -Fx "['rotated', 'rotated', 'made'] []" || fail "converted: $(cat converted.json)"
json 'd["steps"][0]["to"]["algorithm"], d["steps"][1]["to"]["algorithm"]' < converted.json |
    contains -x 'ML-DSA-65 ML-DSA-65'
json 'd["long_term"]["post_quantum"], d["long_term"]["genesis_post_quantum"]' < converted.json |
    contains -x 'True False'
run ledger keys --json > keys.json
json 'd["log_keys"][-1]["key"]["algorithm"], d["root_keys"][-1]["key"]["algorithm"]' < keys.json |
    contains -x 'ML-DSA-65 ML-DSA-65'
run audit | contains 'audit passed'
# Run again: nothing left to do.
run "${LT[@]}" --json | json '[s["status"] for s in d["steps"]]' |
    contains -Fx "['done', 'done', 'done']"
# Post-quantum already, with other keys: refused.
expect_exit 2 ledger long-term --as root-pq.key --log-key log-pq.key --new-root-key other-root.key \
    --new-log-key other-log.key
contains 'post-quantum already' out.txt || fail "already post-quantum"
# The old root key no longer signs; the ML-DSA one does.
expect_exit 2 record issue --as root.key --type example.document/1 --field result=late
SECOND="$(run record issue --as root-pq.key --type example.document/1 --field result=again --json |
    json 'd["statement_id"]')"
run checkpoint create --log-key log-pq.key > /dev/null
run status | contains 'genesis named classical keys'

# --- Witnesses cosign, dated: one ML-DSA, one classical ------------------------------------
run checkpoint cosign-request --witness pq-witness.pub --from 0 --out pq-request.cbor > /dev/null
run witness cosign pq-request.cbor --dir pq-witness --key pq-witness.key --out pq-cosig.cbor \
    --json > cosigned.json
json 'd["cosigned"], d["algorithm"], d["time"] is not None' < cosigned.json |
    contains -x 'True ML-DSA-65 True' || fail "an ML-DSA dated cosignature: $(cat cosigned.json)"
run checkpoint add-cosignature pq-cosig.cbor --witness pq-witness.pub > /dev/null
run checkpoint cosign-request --witness witness.pub --from 0 --out request.cbor > /dev/null
run witness cosign request.cbor --dir classic-witness --key witness.key --out cosig.cbor |
    contains 'Ed25519 dated'
run checkpoint add-cosignature cosig.cbor --witness witness.pub > /dev/null
run status --json > status.json
json 'd["long_term"]["last_post_quantum_cosignature"]["algorithm"], d["long_term"]["last_post_quantum_cosignature"]["time"] is not None' \
    < status.json | contains -x 'ML-DSA-65 True' || fail "the witness in the status: $(cat status.json)"

# --- The old bundle renewed from the ledger's directory ------------------------------------
expect_exit 1 evidence renew old.cbor --out x.cbor --in-place
expect_exit 1 evidence renew old.cbor --size 1 --out x.cbor
contains 'never goes back' out.txt
KANHE_LEDGER="" expect_exit 1 evidence renew old.cbor --out x.cbor
contains 'say where the renewal comes from' out.txt
run init --ledger other-ledger --org "Other Org" --root-key other.key --log-key log.key > /dev/null
expect_exit 2 evidence renew old.cbor --ledger other-ledger --out x.cbor
contains "not the bundle's" out.txt
[ ! -e x.cbor ] || fail "nothing is written when it is refused"

run evidence renew old.cbor --ledger "$WORK/ledger" --out renewed.cbor --witness pq-witness.pub \
    --json > renew.json
json 'd["renewed"], d["from_size"] == '"$EXPORTED"', d["added"]["key_rotations"], d["added"]["cosignatures"], d["renewals"]' \
    < renew.json | contains -x 'True True 2 2 1' || fail "renewed: $(cat renew.json)"
json 'd["long_term"]["post_quantum"], d["long_term"]["checkpoint"]["renewal"]' < renew.json |
    contains -x 'True 1' || fail "post-quantum by the renewal: $(cat renew.json)"
cmp -s old.cbor renewed.cbor && fail "the renewed bundle is another file"
run verify renewed.cbor --ledger-id "$LEDGER_ID" --witness pq-witness.pub --json > report.json
json 'd["verified"], len(d["renewals"]), d["long_term"]["post_quantum"], d["checkpoint"]["tree_size"] == '"$EXPORTED" \
    < report.json | contains -x 'True 1 True True' || fail "verified: $(cat report.json)"
json '[a["algorithm"] for a in d["long_term"]["attested_by"]]' < report.json | contains 'ml-dsa-65'
# Trusting no witness, nothing post-quantum is relied on: advice instead.
run verify renewed.cbor --ledger-id "$LEDGER_ID" --json |
    json 'd["long_term"]["post_quantum"], d["long_term"]["renew_before"][:10]' |
    contains -x 'False 2030-01-01'
run evidence renew old.cbor --ledger "$WORK/ledger" --witness pq-witness.pub > out.txt
contains 'wrote old-renewed.cbor' out.txt || fail "the default name"
contains 'long-term status: post-quantum' out.txt || fail "the status in words"
expect_exit 2 evidence renew old.cbor --ledger "$WORK/ledger"
contains 'exists already' out.txt || fail "the default never overwrites"
# Renewed to the same checkpoint with nothing new: refused, nothing written.
expect_exit 2 evidence renew renewed.cbor --ledger "$WORK/ledger" --out again.cbor
contains 'adds nothing' out.txt
[ ! -e again.cbor ]

# A year on: a newer checkpoint, cosigned again, renews it in place.
run record issue --as root-pq.key --type example.document/1 --field result=later > /dev/null
run checkpoint create --log-key log-pq.key > /dev/null
run checkpoint cosign-request --witness pq-witness.pub --out pq-request2.cbor > /dev/null
run witness cosign pq-request2.cbor --dir pq-witness --key pq-witness.key --out pq-cosig2.cbor > /dev/null
run checkpoint add-cosignature pq-cosig2.cbor --witness pq-witness.pub > /dev/null
FROM="$(json 'd["added"]["tree_size"]' < renew.json)"
run evidence renew renewed.cbor --in-place --witness pq-witness.pub --json > renew2.json
json 'd["from_size"] == '"$FROM"', d["added"]["key_rotations"], d["renewals"], d["long_term"]["checkpoint"]["renewal"]' \
    < renew2.json | contains -x 'True 0 2 2' || fail "renewed again: $(cat renew2.json)"
run verify renewed.cbor --ledger-id "$LEDGER_ID" --witness pq-witness.pub --json |
    json 'd["verified"], len(d["renewals"])' | contains -x 'True 2'

# --- From the server's open route ----------------------------------------------------------
run token create reader --scope read --json | json 'd["token"]' > reader.token
start_server server.json --log-key log-pq.key --checkpoint-interval 0
URL="$(json 'd["url"]' < server.json)"
[ "$(get "$URL/v1/renewal?from=$EXPORTED" "" renewal.cbor)" = 200 ] || fail "the route, with no token"
[ "$(get "$URL/v1/renewal?from=0" "" bad.json)" = 400 ] || fail "from=0"
[ "$(get "$URL/v1/renewal?from=$EXPORTED&size=$((EXPORTED + 1))" "" none.json)" = 404 ] ||
    fail "no checkpoint of that size"
run evidence renew old.cbor --server "$URL" --out from-server.cbor --witness pq-witness.pub \
    --json > served.json
json 'd["renewed"], d["source"] == "'"$URL"'", d["added"]["key_rotations"], d["long_term"]["post_quantum"]' \
    < served.json | contains -x 'True True 2 True' || fail "from the server: $(cat served.json)"
expect_exit 1 evidence renew old.cbor --server "$URL" --ledger "$WORK/ledger" --out y.cbor
[ "$(get "$URL/v1/status" "$(cat reader.token)" served-status.json)" = 200 ]
json 'd["long_term"]["post_quantum"], d["long_term"]["last_post_quantum_cosignature"]["algorithm"]' \
    < served-status.json | contains -x 'True ML-DSA-65' || fail "GET /v1/status: $(cat served-status.json)"
stop_servers

# --- MCP: read-only long-term status, of the ledger and of a bundle -------------------------
run actor add --as root-pq.key --kind device --name "Archive Device" --key agent.key > /dev/null
META='"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientInfo":{"name":"test","version":"1"}}'
cat > requests.jsonl << JSON
{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{$META}}
{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{$META,"name":"kanhe_ledger_status","arguments":{}}}
{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{$META,"name":"kanhe_verify_evidence","arguments":{"bundle_path":"renewed.cbor","expected_ledger_id":"$LEDGER_ID"}}}
JSON
run mcp --as agent.key < requests.jsonl > responses.txt 2> /dev/null
result() { sed -n "${1}p" responses.txt | json "d['result']['structuredContent']$2"; }
if sed -n 1p responses.txt | contains -E '"name":"kanhe_[a-z_]*(rotate|long_term)'; then
    fail "an MCP tool changes keys"
fi
[ "$(result 2 "['long_term']['post_quantum']")" = True ] || fail "MCP ledger status: $(cat responses.txt)"
[ "$(result 3 "['verified'], d['result']['structuredContent']['long_term']['post_quantum']")" = \
    "True False" ] || fail "MCP verify: $(cat responses.txt)"

# --- --generate: the keys made too, any ML-DSA ---------------------------------------------
run init --ledger generated --org "Generated Org" --root-key root.key --log-key log.key > /dev/null
GEN=(ledger long-term --ledger generated --as root.key --log-key log.key --new-root-key gen-root.key
    --new-log-key gen-log.key)
run "${GEN[@]}" --generate --alg ml-dsa-87 --dry-run > /dev/null
[ ! -e gen-root.key ] && [ ! -e gen-log.key ] || fail "a dry run writes no key"
run "${GEN[@]}" --generate --alg ml-dsa-87 --json > generated.json
json 'd["keys_written"], [s["status"] for s in d["steps"]]' < generated.json |
    contains -Fx "['gen-log.key', 'gen-root.key'] ['rotated', 'rotated', 'made']" ||
    fail "generated: $(cat generated.json)"
run key show gen-root.key --json | json 'd["public_key"]["algorithm"]' | contains -x ML-DSA-87
expect_exit 2 "${GEN[@]}" --generate
contains 'drop --generate' out.txt
run "${GEN[@]}" --json | json '[s["status"] for s in d["steps"]]' | contains -Fx "['done', 'done', 'done']"

# --- Guardians: each rotation goes for their approval (SoftHSM stands in for their keys) ----
if [ -z "$MODULE" ]; then
    echo "longterm end-to-end: ok (no SoftHSM module: guardians not tried)"
    exit 0
fi
export LSAN_OPTIONS="suppressions=$(cd "$(dirname "$0")" && pwd)/lsan-softhsm.supp${LSAN_OPTIONS:+:$LSAN_OPTIONS}"
export ASAN_OPTIONS="fast_unwind_on_malloc=0${ASAN_OPTIONS:+:$ASAN_OPTIONS}"
mkdir tokens
printf 'directories.tokendir = %s/tokens\nobjectstore.backend = file\nlog.level = ERROR\n' "$WORK" > softhsm2.conf
export SOFTHSM2_CONF="$WORK/softhsm2.conf"
softhsm2-util --init-token --free --label Kanhe --pin 123456 --so-pin 12345678 > /dev/null
export KANHE_PKCS11_PIN=123456 KANHE_LEDGER="$WORK/guarded"
ukey() { printf 'pkcs11:token=Kanhe;object=%s-ukey?module-path=%s' "$1" "$MODULE"; }
for k in groot glog chan lee ho; do
    run key generate --out "$k.key" > /dev/null
    run key public "$k.key" --out "$k.pub" > /dev/null
done
run key generate --alg ml-dsa-65 --out groot-pq.key > /dev/null
run key generate --alg ml-dsa-65 --out glog-pq.key > /dev/null
run init --name "Guarded Office" --root-key groot.key --log-key glog.key > /dev/null
GUARDIANS=()
for p in chan lee ho; do
    ID="$(run actor add --as groot.key --kind person --name "$p" --key "$p.pub" --json |
        json 'd["actor"]["id"]')"
    run key generate --pkcs11 "$(ukey "$p")" --alg esp256 --out "$p-ukey.pub" > /dev/null
    run presence enroll --pkcs11 "$(ukey "$p")" --label "$p's key" --out "$p.ukey" > /dev/null
    run actor set-presence "$ID" --as groot.key --credential "$p.ukey" > /dev/null
    GUARDIANS+=(--guardian "$ID")
done
SET="$(run ledger guardians set 2 "${GUARDIANS[@]}" --as groot.key --json | json 'd["statement_id"]')"
for p in chan lee; do
    run approval give "$SET" --as "$p.key" --presence-key "$(ukey "$p")" --yes > /dev/null
done
run ledger guardians show --json | json 'd["in_effect"]["k"]' | contains -x 2

GT=(ledger long-term --as groot.key --log-key glog.key --new-root-key groot-pq.key
    --new-log-key glog-pq.key)
expect_exit 1 "${GT[@]}"
contains 'add --for-approval' out.txt || fail "guardians guard the rotations"
run "${GT[@]}" --dry-run | contains 'guardians guard both rotations'
S="$(run "${GT[@]}" --for-approval --json)"
[ "$(echo "$S" | json 'd["sent_for_approval"]["step"], d["sent_for_approval"]["where"], d["remaining"]')" = \
    "rotate-log-key ledger directory ['rotate-log-key', 'rotate-root-key', 'checkpoint']" ] ||
    fail "the log key's rotation for approval: $S"
LOG_ROTATION="$(echo "$S" | json 'd["sent_for_approval"]["statement_id"]')"
expect_exit 2 "${GT[@]}" --for-approval
contains "waits for the guardians' approvals" out.txt || fail "pending approvals"
for p in chan lee; do
    run approval give "$LOG_ROTATION" --as "$p.key" --presence-key "$(ukey "$p")" --yes > /dev/null
done
S="$(run "${GT[@]}" --for-approval --json)"
[ "$(echo "$S" | json 'd["steps"][0]["status"], d["sent_for_approval"]["step"]')" = \
    "done rotate-root-key" ] || fail "then the root key's: $S"
ROOT_ROTATION="$(echo "$S" | json 'd["sent_for_approval"]["statement_id"]')"
for p in lee ho; do
    run approval give "$ROOT_ROTATION" --as "$p.key" --presence-key "$(ukey "$p")" --yes > /dev/null
done
run "${GT[@]}" --json > guarded.json
json '[s["status"] for s in d["steps"]], d["remaining"]' < guarded.json |
    contains -Fx "['done', 'done', 'made'] []" || fail "guarded, converted: $(cat guarded.json)"
run ledger keys --json |
    json 'd["log_keys"][-1]["key"]["algorithm"], d["root_keys"][-1]["key"]["algorithm"]' |
    contains -x 'ML-DSA-65 ML-DSA-65'

echo "longterm end-to-end: ok"
