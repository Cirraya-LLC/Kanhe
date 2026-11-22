#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya
#
# Archives, end to end: a member serves its ledger with an archive token and
# a published certificate, and has a public witness whose key is ML-DSA
# cosign its checkpoints. A trust node archives it (archive add: exactly
# that ledger, with that token), serves the kept evidence at
# /a/LEDGER/c/TOKEN, which verifies, and re-attests it (archive attest) with
# the witness and a local time-stamp authority, while the member's own
# requests to the witness go on. The member's server stops: the archive
# still serves the evidence, renews a holder's older bundle (evidence renew
# --server .../a/LEDGER), and its status says the member cannot be reached.
# The member lists the archive (trust archive), and its links and QR codes
# name it as a fallback. An archive token reaches no vault, evidence, or
# write; a wrong ledger id is refused; backups keep the archive.
# Usage: archive.sh KANHE
set -Eeuo pipefail
dump_logs() {
    for log in "$WORK"/*.json.log; do
        [ -f "$log" ] && { echo "--- $log"; tail -n 30 "$log"; }
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

export KANHE_PASSPHRASE="archive test"
unset KANHE_LEDGER KANHE_SERVER KANHE_TOKEN KANHE_CLOCK_OFFSET
export NO_PROXY=127.0.0.1,localhost no_proxy=127.0.0.1,localhost

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
# get URL TOKEN OUT [METHOD]: fetches a route to OUT (TOKEN may be empty);
# prints the status. Headers go to OUT.headers.
get() {
    python3 - "$@" << 'PY'
import sys, urllib.request, urllib.error
url, token, out = sys.argv[1], sys.argv[2], sys.argv[3]
method = sys.argv[4] if len(sys.argv) > 4 else "GET"
headers = {"Authorization": "Bearer " + token} if token else {}
data = b"" if method == "POST" else None
request = urllib.request.Request(url, headers=headers, method=method, data=data)
try:
    with urllib.request.urlopen(request, timeout=20) as response:
        status, body, head = response.status, response.read(), response.headers
except urllib.error.HTTPError as error:
    status, body, head = error.code, error.read(), error.headers
open(out, "wb").write(body)
open(out + ".headers", "w").write("".join(f"{k}: {v}\n" for k, v in head.items()))
print(status)
PY
}
cosigned_size() {
    run witness registered test-witness --ledger member --json |
        json 'd["last_cosigned"]["tree_size"] if d["last_cosigned"] else 0'
}
latest_size() { run checkpoint list --ledger "$1" --json | json 'max(c["tree_size"] for c in d)'; }

# --- The commands exist, with help, JSON, and completion --------------------------------
for command in "archive config" "archive add" "archive list" "archive show" "archive sync" \
    "archive attest" "archive remove" "trust archive add" "trust archive list" \
    "trust archive remove" "trust archive check"; do
    # shellcheck disable=SC2086
    run $command --help | contains -F "kanhe $command" || fail "help for $command"
done
run archive add --help | contains 'never sealed data' || fail "archive add --help"
run archive attest --help | contains 'never moved' || fail "archive attest --help"
run archive config --help | contains 'Network cosignatures' || fail "archive config --help"
run qr --help | contains -- '--fallback-url' || fail "qr --help"
run token create --help | contains 'archive (for another server' || fail "token create --help"
run help --json | json '[c["command"] for c in d]' > commands.txt
for command in "archive add" "archive attest" "trust archive check"; do
    contains "'$command'" commands.txt || fail "help --json: $command"
done
run completion bash | contains 'attest' || fail "completion: archive attest"
run completion zsh | contains 'archive' || fail "completion zsh"
run completion bash | contains -- '--fallback-url' || fail "completion: qr --fallback-url"

# --- A time-stamp authority: OpenSSL's responder behind a small HTTP front ---------------
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout root.key.pem \
    -out root.pem -days 3650 -subj "/CN=Test TSA Root" \
    -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign" 2> /dev/null
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout tsa.key.pem -out tsa.csr \
    -subj "/CN=Test TSA" 2> /dev/null
printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=critical,timeStamping\n' > tsa.ext
openssl x509 -req -in tsa.csr -CA root.pem -CAkey root.key.pem -CAcreateserial -out tsa.pem \
    -days 3650 -extfile tsa.ext 2> /dev/null
cat > tsa.cnf << EOF
[ tsa ]
default_tsa = tsa_config
[ tsa_config ]
serial = $WORK/tsa.serial
crypto_device = builtin
signer_cert = $WORK/tsa.pem
certs = $WORK/root.pem
signer_key = $WORK/tsa.key.pem
signer_digest = sha256
default_policy = 1.2.3.4.1
digests = sha256, sm3
accuracy = secs:1
clock_precision_digits = 3
ess_cert_id_alg = sha256
EOF
echo 01 > tsa.serial
cat > tsa.py << 'EOF'
import http.server, os, socketserver, subprocess, sys, tempfile

class Authority(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        query = self.rfile.read(int(self.headers["Content-Length"]))
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "q"), "wb") as f:
                f.write(query)
            subprocess.run(["openssl", "ts", "-reply", "-config", sys.argv[1], "-queryfile",
                            os.path.join(d, "q"), "-out", os.path.join(d, "r")],
                           check=True, capture_output=True)
            with open(os.path.join(d, "r"), "rb") as f:
                answer = f.read()
        self.send_response(200)
        self.send_header("Content-Type", "application/timestamp-reply")
        self.send_header("Content-Length", str(len(answer)))
        self.end_headers()
        self.wfile.write(answer)

    def log_message(self, *args):
        pass

class Server(http.server.HTTPServer):
    def server_bind(self):
        socketserver.TCPServer.server_bind(self)
        self.server_name, self.server_port = "127.0.0.1", self.server_address[1]

server = Server(("127.0.0.1", 0), Authority)
print(server.server_address[1], flush=True)
server.serve_forever()
EOF
python3 tsa.py "$WORK/tsa.cnf" > tsa.port 2> tsa.log &
SERVERS+=("$!")
for _ in $(seq 1 300); do [ -s tsa.port ] && break; sleep 0.1; done
[ -s tsa.port ] || { cat tsa.log; fail "the test time-stamp authority did not start"; }
TSA="http://127.0.0.1:$(cat tsa.port)/tsa"

# --- Public witnesses: the member's, whose key is ML-DSA, and another ---------------
for k in w-root w-log v-root v-log other-witness m-root m-log t-root t-log; do
    run key generate --out "$k.key" > /dev/null
done
run key generate --alg ml-dsa-65 --out pq-witness.key > /dev/null
run key public pq-witness.key --out pq-witness.pub > /dev/null
run init --ledger witness-ledger --name "Witness Org" --root-key w-root.key --log-key w-log.key \
    > /dev/null
start_server witness.json --ledger witness-ledger --witness-dir wdir --witness-key pq-witness.key \
    --witness-public --witness-name test-witness --witness-cosign-interval 0
W="$(url_of witness.json)"
run init --ledger witness2-ledger --name "Other Witness Org" --root-key v-root.key \
    --log-key v-log.key > /dev/null
start_server witness2.json --ledger witness2-ledger --witness-dir vdir \
    --witness-key other-witness.key --witness-public --witness-name other-witness \
    --witness-cosign-interval 0
W2="$(url_of witness2.json)"

# --- The member: a certificate, published, an archive token, its witness ----------------
MEMBER_ID="$(run init --ledger member --name "Member School" --root-key m-root.key \
    --log-key m-log.key --json | json 'd["ledger_id"]')"
CERT="$(run record issue --ledger member --as m-root.key --type example.org.diploma/1 \
    --field name="Chan Tai Man" --field degree="BSc" --json | json 'd["record"]["id"]')"
run checkpoint create --ledger member --log-key m-log.key > /dev/null
# A holder's bundle, from before.
run export "$CERT" --ledger member --log-key m-log.key --out old.cbor > /dev/null
TOKEN="$(run record publish --ledger member "$CERT" --disclose name,degree --json |
    json 'd["token"]')"
run token create archiver --ledger member --scope archive --out archive.token --json |
    json 'd["scopes"]' | contains -F "['archive']" || fail "an archive token"
run witness register "$W" --ledger member --witness-key pq-witness.pub > /dev/null
start_server member.json --ledger member --log-key m-log.key --checkpoint-interval 1
M="$(url_of member.json)"
AT="$(cat archive.token)"

# What an archive token reaches on the member's server, and what it does not.
for route in /v1/status "/v1/entries?start=0&count=1" "/v1/checkpoints?start=0&count=5" \
    "/v1/cosignatures?start=0&count=5" "/v1/timestamps?start=0&count=5" \
    "/v1/network-cosignatures?start=0&count=5" /v1/published; do
    [ "$(get "$M$route" "$AT" answer.bin)" = 200 ] || fail "the archive token reads $route"
done
json '[sorted(p.keys()) for p in d]' < answer.bin | contains -F "[['published_at', 'record', 'token']]" ||
    fail "the list an archive sees: $(cat answer.bin)"
for route in /v1/vault/public-key "/v1/evidence/$CERT" "/v1/state/$CERT" /metrics /v1/genesis \
    "/v1/vault/records/$CERT"; do
    [ "$(get "$M$route" "$AT" answer.bin)" = 403 ] || fail "the archive token is refused $route"
done
for route in /v1/statements /v1/checkpoint /v1/published; do
    [ "$(get "$M$route" "$AT" answer.bin POST)" = 403 ] || fail "the archive token writes $route"
done

# --- The trust node: its archive config, then the member archived ----------------------
run init --ledger trust --name "Trust Node" --root-key t-root.key --log-key t-log.key > /dev/null
run archive config --ledger trust --json | json 'd["witnesses"], d["sync_interval"]' |
    contains -Fx '[] 3600' || fail "the default config"
expect_exit 1 archive config --ledger trust --sync-interval 5x
expect_exit 1 archive config --ledger trust --witness "$W" --no-witnesses
expect_exit 2 archive config --ledger trust --witness http://127.0.0.1:1
run archive config --ledger trust --witness "$W" --witness "$W2" --tsa "$TSA" \
    --attest-interval 30d --json > config.json
json 'd["changed"], d["witnesses"][0]["algorithm"], d["witnesses"][1]["post_quantum"], d["authorities"], d["attest_interval"], d["classical_witnesses_only"]' \
    < config.json | contains -Fx "True ML-DSA-65 False ['$TSA'] 2592000 False" ||
    fail "the config: $(cat config.json)"
run archive config --ledger trust | contains 'attestation every:  30 d' || fail "config in words"
run archive list --ledger trust | contains 'no ledger is archived here'
expect_exit 2 archive attest --ledger trust
contains 'no ledger is archived' out.txt || fail "nothing to attest"

# Refused: another ledger's id, an unknown token, its own id.
WITNESS_ID="$(run status --ledger witness-ledger --json | json 'd["ledger_id"]')"
expect_exit 3 archive add "$WITNESS_ID" --ledger trust --source "$M" --token-file archive.token
contains 'NOT VERIFIED' out.txt || fail "another ledger's id"
[ ! -e "trust/archive/$WITNESS_ID" ] || fail "nothing kept of a refused archive"
echo kht_nobody > nobody.token
expect_exit 2 archive add "$MEMBER_ID" --ledger trust --source "$M" --token-file nobody.token
TRUST_ID="$(run status --ledger trust --json | json 'd["ledger_id"]')"
expect_exit 1 archive add "$TRUST_ID" --ledger trust --source "$M" --token-file archive.token
expect_exit 1 archive add abc --ledger trust --source "$M" --token-file archive.token

run archive add "$MEMBER_ID" --ledger trust --source "$M" --token-file archive.token --json \
    > added.json
json 'd["archived"], d["organization"], d["published"], d["sync"]["synced"]' < added.json |
    contains -Fx 'True Member School 1 True' || fail "archived: $(cat added.json)"
[ ! -e "trust/archive/$MEMBER_ID/vault" ] || fail "an archive keeps no sealed data"
[ "$(stat -c %a "trust/archive/$MEMBER_ID/token" 2> /dev/null ||
    stat -f %Lp "trust/archive/$MEMBER_ID/token")" = 600 ] || fail "the token kept owner-only"
expect_exit 2 archive add "$MEMBER_ID" --ledger trust --source "$M" --token-file archive.token
contains 'archived here already' out.txt || fail "archived once"
run archive list --ledger trust --json | json 'len(d), d[0]["ledger_id"], d[0]["published"]' |
    contains -Fx "1 $MEMBER_ID 1" || fail "archive list"
run archive list --ledger trust | contains 'Member School' || fail "archive list in words"
run archive show "${MEMBER_ID:0:12}" --ledger trust --json > shown.json
json 'd["bundles"][0]["token"], d["bundles"][0]["record"], d["address"]' < shown.json |
    contains -Fx "$TOKEN $CERT /a/$MEMBER_ID" || fail "archive show: $(cat shown.json)"
run archive show "$MEMBER_ID" --ledger trust | contains "$TOKEN" || fail "archive show in words"
expect_exit 2 archive show ffff --ledger trust

# --- Served by the trust node: the kept evidence verifies ------------------------------
run token create status --ledger trust --scope read --out trust-read.token > /dev/null
start_server trust.json --ledger trust --log-key t-log.key
T="$(url_of trust.json)"
json 'd["archives"]' < trust.json | contains -x 1 || fail "serve counts the archives"
[ "$(get "$T/a/$MEMBER_ID/c/$TOKEN" "" kept.cbor)" = 200 ] || fail "GET /a/LEDGER/c/TOKEN"
contains -i 'access-control-allow-origin: \*' kept.cbor.headers || fail "any page may read it"
contains -i 'cache-control: no-store' kept.cbor.headers || fail "never cached"
run verify kept.cbor --ledger-id "$MEMBER_ID" --json > kept.json
json 'd["record"]["id"], d["disclosed_fields"]["name"]' < kept.json |
    contains -Fx "$CERT Chan Tai Man" || fail "the kept evidence verifies: $(cat kept.json)"
[ "$(get "$T/a/$MEMBER_ID/v1/checkpoint" "" checkpoint.bin)" = 200 ] || fail "the checkpoint"
[ "$(get "$T/a/$MEMBER_ID/c/AAAAAAAAAAAAAAAAAAAAAA" "" none.bin)" = 404 ] || fail "nothing kept"
json 'd["error"]["code"]' < none.bin | contains -x not_found || fail "a JSON error"
[ "$(get "$T/a/$WITNESS_ID/v1/checkpoint" "" none.bin)" = 404 ] || fail "a ledger not archived"
[ "$(get "$T/a/$MEMBER_ID/v1/checkpoint" "" none.bin POST)" = 405 ] || fail "GET only"
[ "$(get "$T/a/$MEMBER_ID/v1/renewal?from=0" "" none.bin)" = 400 ] || fail "a bad renewal"
[ "$(get "$T/v1/status" "$(cat trust-read.token)" status.json)" = 200 ] || fail "the trust's status"
json 'd["archives"]["count"], d["archives"]["unreachable"], d["archives"]["witnesses_post_quantum"]' \
    < status.json | contains -Fx '1 0 True' || fail "GET /v1/status: $(cat status.json)"

# --- Re-attested while the member is alive: the member's own requests go on -------------
# Once the witness has cosigned the member's latest checkpoint, and the archive has it.
for _ in $(seq 1 100); do
    [ "$(cosigned_size)" = "$(latest_size member)" ] && break
    sleep 0.2
done
[ "$(cosigned_size)" = "$(latest_size member)" ] || fail "the member's witness cosigned"
run archive sync --ledger trust --json | json 'd[0]["synced"]' | contains -x True || fail "synced"
run archive attest --ledger trust --json > not-due.json
json 'd[0]["due"]' < not-due.json | contains -x False || fail "not due: $(cat not-due.json)"
# The member's witness has cosigned the latest checkpoint: it is not asked
# (a ledger keeps one cosignature per witness and checkpoint). The other is
# registered and cosigns it, dated; the authority stamps it.
run archive attest --ledger trust --force --json > attested.json
json '[(o["kind"], o["attested"] is not None, o["already"]) for o in d[0]["outcomes"]], d[0]["outcomes"][1]["registered"]' \
    < attested.json |
    contains -Fx "[('witness', False, True), ('witness', True, False), ('authority', True, False)] True" ||
    fail "re-attested: $(cat attested.json)"
run archive show "$MEMBER_ID" --ledger trust --json | json 'd["attested_at"] is not None' |
    contains -x True || fail "attested"
# The member's next checkpoint still gets cosigned by that witness.
BEFORE="$(cosigned_size)"
run record issue --ledger member --as m-root.key --type example.org.diploma/1 \
    --field name="Lee Siu Ming" --field degree="BA" > /dev/null
for _ in $(seq 1 150); do
    [ "$(latest_size member)" -gt "$BEFORE" ] && [ "$(cosigned_size)" = "$(latest_size member)" ] &&
        break
    sleep 0.2
done
[ "$(cosigned_size)" -gt "$BEFORE" ] || fail "the member's next checkpoint was cosigned"
[ "$(cosigned_size)" = "$(latest_size member)" ] || fail "the member's witness is not moved"

# --- The member lists the archive; its links name it ----------------------------------
ARCHIVE_URL="$T/a/$MEMBER_ID"
expect_exit 1 trust archive add "$T/a/$WITNESS_ID" --ledger member
expect_exit 2 trust archive add "http://127.0.0.1:1/a/$MEMBER_ID" --ledger member
run trust archive add "$ARCHIVE_URL" --ledger member --json | json 'd["url"]' |
    contains -Fx "$ARCHIVE_URL" || fail "trust archive add"
expect_exit 2 trust archive add "$ARCHIVE_URL" --ledger member
run trust archive list --ledger member --json | json '[a["url"] for a in d]' |
    contains -Fx "['$ARCHIVE_URL']" || fail "trust archive list"
run archive sync --ledger trust > /dev/null
run trust archive check --ledger member --json > checked.json
json 'd[0]["ok"], d[0]["problem"]' < checked.json | contains -Fx 'True None' ||
    fail "trust archive check: $(cat checked.json)"
run qr "$CERT" --ledger member --bundle-url "$M/c/$TOKEN" \
    --verifier-url https://verify.example/verify/ --json > qr.json
json 'd["fallbacks"]' < qr.json | contains -Fx "['$ARCHIVE_URL/c/$TOKEN']" ||
    fail "the QR code's fallbacks: $(cat qr.json)"
json 'd["url"]' < qr.json | contains -F "&a=$ARCHIVE_URL/c/$TOKEN" || fail "the link: $(cat qr.json)"
json 'd["url"].index("&b=") < d["url"].index("&a=")' < qr.json | contains -x True
run qr "$CERT" --ledger member --bundle-url "$M/c/$TOKEN" \
    --verifier-url https://verify.example/verify/ --fallback-url https://mirror.example/c/x \
    --json | json 'len(d["fallbacks"])' | contains -x 2 || fail "--fallback-url"
expect_exit 1 qr "$CERT" --ledger member --bundle-url "$M/c/$TOKEN" \
    --verifier-url https://verify.example/verify/ --fallback-url https://a.example/1 \
    --fallback-url https://a.example/2 --fallback-url https://a.example/3 \
    --fallback-url https://a.example/4
contains 'at most 4' out.txt || fail "at most 4 fallbacks"
run record published --ledger member --json | json 'd[0]["fallbacks"]' |
    contains -Fx "['$ARCHIVE_URL/c/$TOKEN']" || fail "record published names the fallback"

# --- The member's server stops: the archive still serves, and renews ---------------------
run archive sync --ledger trust > /dev/null
kill "${SERVERS[3]}"
wait "${SERVERS[3]}" 2> /dev/null || true
expect_exit 2 archive sync --ledger trust
contains 'cannot be reached' out.txt || fail "an unreachable member"
run status --ledger trust --json | json 'd["archives"]["unreachable"]' | contains -x 1 ||
    fail "the status says so"
run status --ledger trust | contains 'archives:' || fail "the status in words"
[ "$(get "$T/a/$MEMBER_ID/c/$TOKEN" "" kept2.cbor)" = 200 ] || fail "still served"
run verify kept2.cbor --ledger-id "$MEMBER_ID" --witness pq-witness.pub --json > kept2.json
json 'd["record"]["id"], len(d["renewals"]) >= 1' < kept2.json | contains -Fx "$CERT True" ||
    fail "served with a renewal: $(cat kept2.json)"
run archive attest --ledger trust --force --json > attested2.json
json '[o["attested"] is not None or o["already"] for o in d[0]["outcomes"]], d[0]["outcomes"][1]["attested"] is not None' \
    < attested2.json | contains -Fx '[True, True, True] True' ||
    fail "re-attested with the member gone: $(cat attested2.json)"
# (Once the server has picked up what archive attest kept, within seconds.)
for _ in $(seq 1 50); do
    rm -f renewed.cbor
    run evidence renew old.cbor --server "$ARCHIVE_URL" --out renewed.cbor --json \
        > renewed.json 2>&1 || true
    json 'd["renewed"] and d["added"]["timestamps"] >= 1' < renewed.json 2> /dev/null |
        contains -x True && break
    sleep 0.2
done
json 'd["renewed"], d["source"]' < renewed.json | contains -Fx "True $ARCHIVE_URL" ||
    fail "renewed from the archive: $(cat renewed.json)"
json 'd["added"]["cosignatures"] >= 1, d["added"]["timestamps"] >= 1' < renewed.json |
    contains -Fx 'True True' || fail "the archive's attestations: $(cat renewed.json)"
run verify renewed.cbor --ledger-id "$MEMBER_ID" --witness pq-witness.pub --tsa-root root.pem \
    --json | json 'd["long_term"]["post_quantum"]' | contains -x True ||
    fail "the renewed bundle is post-quantum by the archive's witness"

# --- Backups keep the archive ---------------------------------------------------------
run backup create --ledger trust --log-key t-log.key --out trust.kanhebackup > /dev/null
run backup verify trust.kanhebackup > /dev/null
run backup restore trust.kanhebackup --ledger restored > /dev/null
run archive list --ledger restored --json | json 'len(d), d[0]["published"]' |
    contains -Fx '1 1' || fail "the restored archive"
SIZE="$(run archive show "$MEMBER_ID" --ledger trust --json | json 'd["size"]')"
expect_exit 2 archive sync --ledger restored
[ "$(run archive show "$MEMBER_ID" --ledger restored --json | json 'd["size"]')" = "$SIZE" ] ||
    fail "the restored replica"
[ -e "restored/archive/$MEMBER_ID/statements" ] || fail "the replica restored from its copy"

# --- Removing: only with --yes; then not served ----------------------------------------
run trust archive remove "$ARCHIVE_URL" --ledger member > /dev/null
run trust archive list --ledger member --json | json 'len(d)' | contains -x 0
expect_exit 2 trust archive remove "$ARCHIVE_URL" --ledger member
expect_exit 1 archive remove "$MEMBER_ID" --ledger trust
contains -- '--yes' out.txt || fail "remove asks for --yes"
run archive remove "$MEMBER_ID" --ledger trust --yes --json | json 'd["removed"]' |
    contains -x "$MEMBER_ID"
[ ! -e "trust/archive/$MEMBER_ID" ] || fail "removed"
for _ in $(seq 1 50); do
    [ "$(get "$T/a/$MEMBER_ID/v1/checkpoint" "" none.bin)" = 404 ] && break
    sleep 0.2
done
[ "$(get "$T/a/$MEMBER_ID/v1/checkpoint" "" none.bin)" = 404 ] || fail "no longer served"
run archive list --ledger trust --json | json 'len(d)' | contains -x 0
echo "archive end-to-end test passed"
