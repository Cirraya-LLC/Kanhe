#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya
#
# Public witnesses, end to end: a witness server (serve --witness-public)
# that any ledger registers with, by its genesis entry and a cosign request
# that proves it holds its log key. A key that is not the witness's is
# refused; a registered ledger is cosigned at once, listed, and then
# cosigned after each new checkpoint by serve; exported evidence carries the
# cosignature and verifies with the witness required. Quotas hold, a ledger
# showing another history is refused, and unregistering stops the asking.
# Behind a reverse proxy on the same host (--witness-trust-proxy), the quota
# counts the address the proxy forwards, an IPv6 address by its /64.
# Usage: public_witness.sh KANHE
set -Eeuo pipefail
dump_logs() {
    for log in "$WORK"/*.json.log; do
        [ -f "$log" ] && { echo "--- $log"; tail -n 20 "$log"; }
    done
    return 0
}
trap 'echo "FAILED at line $LINENO: $BASH_COMMAND" >&2; dump_logs >&2' ERR

KANHE="$1"
WORK="$(mktemp -d)"
SERVERS=()
cleanup() {
    for pid in ${SERVERS[@]+"${SERVERS[@]}"}; do kill "$pid" 2> /dev/null || true; done
    rm -rf "$WORK"
}
trap cleanup EXIT
cd "$WORK"

export KANHE_PASSPHRASE="witness test"
unset KANHE_LEDGER KANHE_TOKEN

# A command line as typed: bo, kanhe-console, and kanhe-index are the
# programs beside kanhe.
run() {
    case "$1" in
    bo | kanhe-console | kanhe-index) "$(dirname "$KANHE")/$1" "${@:2}" ;;
    *) "$KANHE" "$@" ;;
    esac
}
fail() { echo "FAIL: $*"; [ -f out.txt ] && cat out.txt; dump_logs; exit 1; }
expect_exit() {
    local code="$1"; shift
    local actual=0
    run "$@" > out.txt 2>&1 || actual=$?
    [ "$actual" -eq "$code" ] || fail "expected exit $code, got $actual: $*"
}
contains() { grep "$@" > /dev/null; }
json() { python3 -c "import json,sys; d=json.load(sys.stdin); print($1)"; }
# post URL FILE: POSTs the file as CBOR; prints the status.
post() {
    python3 - "$@" << 'PY'
import sys, urllib.request, urllib.error
request = urllib.request.Request(sys.argv[1], method="POST", data=open(sys.argv[2], "rb").read(),
                                 headers={"Content-Type": "application/cbor"})
try:
    with urllib.request.urlopen(request, timeout=10) as response:
        print(response.status)
except urllib.error.HTTPError as error:
    print(error.code)
PY
}
# post_as FORWARDED URL FILE: as post, with "X-Forwarded-For: FORWARDED" (none
# if it is empty), as a reverse proxy on this host would send it.
post_as() {
    python3 - "$@" << 'PY'
import sys, urllib.request, urllib.error
headers = {"Content-Type": "application/cbor"}
if sys.argv[1]:
    headers["X-Forwarded-For"] = sys.argv[1]
request = urllib.request.Request(sys.argv[2], method="POST", data=open(sys.argv[3], "rb").read(),
                                 headers=headers)
try:
    with urllib.request.urlopen(request, timeout=10) as response:
        print(response.status)
except urllib.error.HTTPError as error:
    print(error.code)
PY
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
url_of() { json 'd["url"]' < "$1"; }
cosigned_size() {
    run witness registered test-witness --ledger "$1" --json |
        json 'd["last_cosigned"]["tree_size"] if d["last_cosigned"] else 0'
}
latest_size() { run checkpoint list --ledger "$1" --json | json 'max(c["tree_size"] for c in d)'; }

for command in "witness register" "witness registered" "witness unregister"; do
    # shellcheck disable=SC2086
    run $command --help | contains -F "kanhe $command" || fail "help for $command"
done
run completion bash | contains unregister || fail "completion"
run serve --help | contains -F -- '--witness-public' || fail "serve --help"
run serve --help | contains -F -- '--witness-trust-proxy' || fail "serve --help: the proxy"
run completion bash | contains '"serve") opts=.*--witness-trust-proxy' || fail "completion: the proxy"

# --- The witness: a server of its own ledger, public, with small quotas ----------
for k in w-root w-log witness a-root a-log b-root b-log c-root c-log other; do
    run key generate --out "$k.key" > /dev/null
done
run key public witness.key --out witness.pub > /dev/null
run key public other.key --out other.pub > /dev/null
run init --ledger witness-ledger --org "Witness Org" --root-key w-root.key \
    --log-key w-log.key > /dev/null
expect_exit 1 serve --ledger witness-ledger --witness-public
contains -- '--witness-dir' out.txt || fail "--witness-public needs a witness"
expect_exit 1 serve --ledger witness-ledger --witness-name x
expect_exit 1 serve --ledger witness-ledger --relay-dir relay
contains -- '--witness-public' out.txt || fail "a relay serves a public witness's ledgers"
expect_exit 1 serve --ledger witness-ledger --witness-trust-proxy
contains -- '--witness-public' out.txt || fail "a proxy is trusted for a public witness only"
start_server witness.json --ledger witness-ledger --witness-dir wdir --witness-key witness.key \
    --witness-public --witness-name test-witness --witness-registrations-per-day 2 \
    --witness-cosign-interval 1 --relay-dir relay
W="$(url_of witness.json)"
# The relay beside it reads only signed fetches.
[ "$(python3 -c "
import urllib.request, urllib.error
try:
    urllib.request.urlopen('$W/v1/relay/messages?to=' + '00' * 32, timeout=10)
except urllib.error.HTTPError as e:
    print(e.code)")" = 401 ] || fail "the relay asks who fetches"

# --- Alice: a ledger with a record and a checkpoint --------------------------------
run init --ledger alice --org Alice --root-key a-root.key --log-key a-log.key > /dev/null
RECORD="$(run record issue --ledger alice --as a-root.key --type example.document/1 \
    --field result=pass --json | json 'd["record"]["id"]')"
run checkpoint create --ledger alice --log-key a-log.key > /dev/null

# Another key than the witness's: refused, nothing registered.
expect_exit 2 witness register "$W" --ledger alice --witness-key other.pub
contains "another key" out.txt || fail "a witness with another key"
[ ! -e alice/witnesses.json ] || fail "nothing listed"
[ "$(ls wdir | wc -l | tr -d ' ')" = 0 ] || fail "the witness followed nothing"

# Registered: cosigned at once, listed, followed with no name.
run witness register "$W" --ledger alice --witness-key witness.pub --json > registered.json
[ "$(json '(d["registered"], d["name"])' < registered.json)" = "(True, 'test-witness')" ] ||
    fail "registered"
[ "$(cosigned_size alice)" = "$(latest_size alice)" ] || fail "cosigned at once"
run witness registered --ledger alice | contains "test-witness" || fail "listed"
run witness registered test-witness --ledger alice | contains "url: $W" || fail "shown"
[ "$(run witness status --dir wdir --json | json 'len(d)')" = 1 ] || fail "the witness follows it"
# Registering again (the key given as hex) is a cosign request like any other.
KEY_HEX="$(run witness registered test-witness --ledger alice --json | json 'd["key"]')"
sleep 1.1
run witness register "$W" --ledger alice --witness-key "$KEY_HEX" > /dev/null
[ "$(run witness registered --ledger alice --json | json 'len(d["witnesses"])')" = 1 ] ||
    fail "listed once"

# serve asks it after each new checkpoint.
BEFORE="$(cosigned_size alice)"
start_server alice.json --ledger alice --log-key a-log.key --checkpoint-interval 1
run record issue --ledger alice --as a-root.key --type example.document/1 --field result=again \
    > /dev/null
for _ in $(seq 1 150); do
    [ "$(cosigned_size alice)" -gt "$BEFORE" ] && break
    sleep 0.2
done
[ "$(cosigned_size alice)" -gt "$BEFORE" ] || fail "serve asked the witness"
contains "witness test-witness cosigned" alice.json.log || fail "serve says so"
kill "${SERVERS[1]}"
wait "${SERVERS[1]}" 2> /dev/null || true
for _ in $(seq 1 50); do
    [ "$(cosigned_size alice)" = "$(latest_size alice)" ] && break
    run witness register "$W" --ledger alice --witness-key witness.pub > /dev/null 2>&1 || true
    sleep 1.1
done

# Exported evidence carries the cosignature, and verifies with the witness required.
run export "$RECORD" --ledger alice --log-key a-log.key --out evidence.cbor > /dev/null
run verify evidence.cbor --witness witness.pub --min-witnesses 1 > out.txt || fail "verified"
expect_exit 3 verify evidence.cbor --witness other.pub --min-witnesses 1

# --- Quotas: two new ledgers a day from this address --------------------------------
run init --ledger bob --org Bob --root-key b-root.key --log-key b-log.key > /dev/null
run checkpoint create --ledger bob --log-key b-log.key > /dev/null
run witness register "$W" --ledger bob --witness-key witness.pub > /dev/null
run init --ledger carol --org Carol --root-key c-root.key --log-key c-log.key > /dev/null
run checkpoint create --ledger carol --log-key c-log.key > /dev/null
# Alice's and Bob's registrations count (the key refused earlier never reached it).
expect_exit 2 witness register "$W" --ledger carol --witness-key witness.pub
contains "too many registrations" out.txt || fail "the daily quota"
[ ! -e carol/witnesses.json ] || fail "carol not listed"

# --- Another history: a copy of Alice's ledger that went its own way ----------------
cp -R alice fork
run record issue --ledger alice --as a-root.key --type example.document/1 --field result=a \
    > /dev/null
run checkpoint create --ledger alice --log-key a-log.key > /dev/null
sleep 1.1
run witness register "$W" --ledger alice --witness-key witness.pub > /dev/null
ALICE_SIZE="$(cosigned_size alice)"
run record issue --ledger fork --as a-root.key --type example.document/1 --field result=b \
    > /dev/null
run record issue --ledger fork --as a-root.key --type example.document/1 --field result=c \
    > /dev/null
run checkpoint create --ledger fork --log-key a-log.key > /dev/null
run checkpoint cosign-request --ledger fork --witness witness.pub --from "$ALICE_SIZE" \
    --out fork-request.cbor > /dev/null
sleep 1.1
[ "$(post "$W/v1/witness/cosign" fork-request.cbor)" = 422 ] || fail "the fork is refused"
[ "$(cosigned_size alice)" = "$ALICE_SIZE" ] || fail "alice's history stands"

# --- Unregistered: no longer asked; what was cosigned stays -------------------------
run witness unregister test-witness --ledger alice | contains "no longer asking" ||
    fail "unregister"
[ "$(run witness registered --ledger alice --json | json 'len(d["witnesses"])')" = 0 ] ||
    fail "unlisted"
expect_exit 2 witness unregister test-witness --ledger alice
run verify evidence.cbor --witness witness.pub --min-witnesses 1 > /dev/null ||
    fail "still verified"

# --- Behind a reverse proxy on this host: the quota counts the forwarded address ---
for k in p-root p-log d-root d-log; do
    run key generate --out "$k.key" > /dev/null
done
run init --ledger proxied-ledger --org "Proxied Witness Org" --root-key p-root.key \
    --log-key p-log.key > /dev/null
start_server proxied.json --ledger proxied-ledger --witness-dir wdir2 --witness-key witness.key \
    --witness-public --witness-registrations-per-day 1 --witness-trust-proxy
P="$(url_of proxied.json)"
# A registration each witness counts, then refuses (its genesis entry is not
# one), for a ledger neither follows.
run init --ledger dora --org Dora --root-key d-root.key --log-key d-log.key > /dev/null
run checkpoint create --ledger dora --log-key d-log.key > /dev/null
run checkpoint cosign-request --ledger dora --witness witness.pub --out dora-request.cbor > /dev/null
python3 - dora-request.cbor counted.cbor << 'PY'
import sys
request = open(sys.argv[1], "rb").read()
def bytes_head(n):  # a CBOR byte string's head
    if n < 24:
        return bytes([0x40 + n])
    if n < 256:
        return bytes([0x58, n])
    if n < 65536:
        return bytes([0x59]) + n.to_bytes(2, "big")
    return bytes([0x5a]) + n.to_bytes(4, "big")
open(sys.argv[2], "wb").write(b"\xa2\x01" + bytes_head(4) + b"junk" + b"\x02" +
                              bytes_head(len(request)) + request)
PY
through_proxy() { post_as "$1" "$P/v1/witness/register" counted.cbor; }
# Each forwarded address has its own share (one a day here).
[ "$(through_proxy 203.0.113.5)" = 400 ] || fail "counted, then refused"
[ "$(through_proxy 203.0.113.5)" = 429 ] || fail "that address's share is spent"
[ "$(through_proxy 198.51.100.7)" = 400 ] || fail "another address has its own"
# The address the proxy appended counts, never one written before it.
[ "$(through_proxy "203.0.113.9, 198.51.100.7")" = 429 ] || fail "the last address counts"
# An IPv6 address counts by its /64.
[ "$(through_proxy 2001:db8:5:6::1)" = 400 ] || fail "an IPv6 caller"
[ "$(through_proxy 2001:db8:5:6:a::2)" = 429 ] || fail "the same /64"
[ "$(through_proxy 2001:db8:5:7::1)" = 400 ] || fail "another /64"
# With no header, the connection's own address.
[ "$(through_proxy "")" = 400 ] || fail "the proxy's own address"
[ "$(through_proxy "")" = 429 ] || fail "the proxy's own share"
[ "$(run witness status --dir wdir2 --json | json 'len(d)')" = 0 ] || fail "nothing followed"
# A witness that trusts no proxy reads no header: this address spent its share.
[ "$(post_as 192.0.2.200 "$W/v1/witness/register" counted.cbor)" = 429 ] ||
    fail "without --witness-trust-proxy the header counts for nothing"

echo "public witness: all checks passed"
