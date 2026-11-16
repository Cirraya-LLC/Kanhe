#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya
#
# Who sees what along a supply chain, narrated step by step. A core
# enterprise (A) owes its supplier (B) CNY 1,000,000 for goods delivered: a
# receivable, under a contract in Bo (receivable.bo, next to this script), on
# A's ledger. B orders parts from its own supplier (C) for CNY 400,000: an
# order, a record on B's own ledger, whose fields stay private until B
# discloses them.
#   - C receives the order with what it needs (goods, amount, due date): its
#     evidence names nothing of A, not even the field that says what backs
#     the order, which stays sealed;
#   - C accepts it on its own ledger, naming B's order as its source;
#   - Bank A receives everything: the order with that field disclosed, and
#     the receivable's evidence from A's ledger; it checks that one backs the
#     other, and B pledges the receivable to it, so that Bank A pays C early;
#   - the receivable cannot back a second financing while pledged;
#   - A sees the pledge to Bank A, never C.
# Four ledgers, each its own organization, talk over HTTP where they must. It
# needs a kanhe built with the Bo compiler (GCC 16; the release build and
# the Docker image have it).
#
# Usage: supply-chain-privacy.sh [KANHE] [DIR]
#   KANHE  the command-line tool (default: kanhe on the PATH)
#   DIR    where to keep the ledgers (default: a temporary directory,
#          removed at the end; give one to look around afterwards)
set -Eeuo pipefail
trap 'echo "FAILED at line $LINENO: $BASH_COMMAND" >&2' ERR

KANHE="${1:-kanhe}"
# A path relative to where the script starts works too.
case "$KANHE" in */*) KANHE="$(cd "$(dirname "$KANHE")" && pwd)/$(basename "$KANHE")" ;; esac
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -n "${2:-}" ]; then
    WORK="$2"; KEEP=1; mkdir -p "$WORK"
else
    WORK="$(mktemp -d)"; KEEP=0
fi
WORK="$(cd "$WORK" && pwd)"
SERVER=""
cleanup() {
    if [ -n "$SERVER" ]; then
        kill "$SERVER" 2> /dev/null || true
        wait "$SERVER" 2> /dev/null || true
    fi
    [ "$KEEP" = 0 ] && rm -rf "$WORK"
    return 0
}
trap cleanup EXIT
cd "$WORK"
export KANHE_PASSPHRASE="demo only: use real passphrases or hardware keys"
unset KANHE_LEDGER KANHE_SERVER KANHE_TOKEN

step() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
say() { printf '   %s\n' "$*"; }
# A command line as typed: bo is the program beside kanhe.
run() {
    case "$1" in
    bo) "$(dirname "$KANHE")/bo" "${@:2}" ;;
    *) "$KANHE" "$@" ;;
    esac
}
field() { python3 -c "import json,sys; print(json.load(sys.stdin)$1)"; }
indent() { sed 's/^/   /'; }
check() {
    # check WHAT PYTHON-CONDITION: fails the demo unless the condition, on
    # the JSON read from standard input, holds.
    python3 -c "import json,sys; d=json.load(sys.stdin); sys.exit(0 if ($2) else 1)" \
        || { echo "unexpected: $1" >&2; exit 1; }
}
# names_none WHAT PATH TEXT...: fails the demo if any file at PATH (a file, or
# every file under a directory) holds any of the texts, as text or, for hex,
# as the bytes they spell.
names_none() {
    local what="$1" path="$2"
    shift 2
    python3 - "$path" "$@" << 'PY' || { echo "unexpected: $what" >&2; exit 1; }
import os, sys
path, texts = sys.argv[1], sys.argv[2:]
needles = [t.encode() for t in texts]
for t in texts:
    try:
        needles.append(bytes.fromhex(t))
    except ValueError:
        pass
files = [path] if os.path.isfile(path) else [os.path.join(d, f) for d, _, fs in os.walk(path) for f in fs]
for name in files:
    data = open(name, "rb").read()
    if any(n in data for n in needles):
        print(f"{name} names what it should not", file=sys.stderr)
        sys.exit(1)
PY
}

# One organization per name: its ledger directory, and its keys (ORG-root.key
# signs for the organization, ORG-log.key signs its log).
# (Plain variables, not associative arrays: macOS ships bash 3.2.)
ORGS=(core supplier sub bank)
name_of() {
    case "$1" in
    core) echo "Core Enterprise Co." ;;
    supplier) echo "Tier-1 Supplier Ltd." ;;
    sub) echo "Tier-2 Supplier Ltd." ;;
    bank) echo "Bank A" ;;
    esac
}
dir() { echo "$WORK/$1"; }
# An organization's ledger id, once its ledger exists.
id() { cat "$WORK/$1.id"; }

step "1. Four organizations, each with its own ledger"
for org in "${ORGS[@]}"; do
    run key generate --out "$org-root.key" > /dev/null
    run key generate --out "$org-log.key" > /dev/null
    run init --name "$(name_of "$org")" --root-key "$org-root.key" --log-key "$org-log.key" \
        --ledger "$(dir "$org")" > /dev/null
    run status --ledger "$(dir "$org")" --json | field '["ledger_id"]' > "$WORK/$org.id"
    say "$(printf '%-22s ledger %s...' "$(name_of "$org")" "$(id "$org" | cut -c1-16)")"
done
CORE_ID="$(id core)"; SUPPLIER_ID="$(id supplier)"; SUB_ID="$(id sub)"; BANK_ID="$(id bank)"
say "A (the core enterprise) deals with B (the tier-1 supplier) and Bank A. C (the tier-2"
say "supplier) knows B's ledger id, as any supplier knows its customer: nothing of A."
for org in supplier bank; do
    run peer add "$org" --ledger-id "$(id "$org")" --ledger "$(dir core)" > /dev/null
done

step "2. A deploys the receivable's contract on its ledger"
if [ ! -x "$(dirname "$KANHE")/bo" ]; then
    echo "This demo needs a kanhe built with the Bo compiler (GCC 16)." >&2
    exit 1
fi
cp "$HERE/receivable.bo" .
run bo test receivable.bo | tail -n 1 | indent
run bo build receivable.bo --out receivable.boc > /dev/null 2>&1
CONTRACT="$(run contract deploy receivable.boc --as core-root.key --ledger "$(dir core)" \
    --json 2> /dev/null | field '["contract"]["id"]')"
say "Deployed as ${CONTRACT:0:16}..."

step "3. A confirms what it owes B: a receivable of CNY 1,000,000, held by B"
# Money is in the smallest unit (fen); dates in milliseconds since 1970.
DUE=1806940800000   # 2027-04-06, 00:00 in Shanghai and Hong Kong
ISSUE="{\"fields\": {\"amount\": 100000000, \"due\": $DUE}, \"parties\": {\"issuer\": h'$CORE_ID', \"supplier\": h'$SUPPLIER_ID'}}"
RECEIVABLE="$(run contract create "$CONTRACT" issue --args "$ISSUE" --reference "PO-2026-0815" \
    --as core-root.key --ledger "$(dir core)" --json | field '["instance"]["id"]')"
run contract instance "$RECEIVABLE" --ledger "$(dir core)" | sed -n '1,6p' | indent

step "4. A runs its server with a registrar, for the calls that need consents"
run key generate --out registrar.key > /dev/null
run key public registrar.key --out registrar.pub > /dev/null
REGISTRAR="$(run actor add --as core-root.key --kind device --name "Contract Registrar" \
    --key registrar.pub --ledger "$(dir core)" --json | field '["actor"]["id"]')"
run delegation grant --as core-root.key --to "$REGISTRAR" --allow contract-call \
    --contracts "$CONTRACT" --ledger "$(dir core)" > /dev/null
for org in supplier bank; do
    run token create "$org" --scope peer --out "$org.token" --ledger "$(dir core)" > /dev/null
done
# Started directly (not through a shell function), so $! is the server itself.
"$KANHE" serve --ledger "$(dir core)" --log-key core-log.key --registrar-key registrar.key \
    --listen 127.0.0.1:0 --json --quiet > core.json 2> core.log &
SERVER=$!
for _ in $(seq 1 300); do
    python3 -c "import json; json.load(open('core.json'))" 2> /dev/null && break
    sleep 0.1
done
URL="$(field '["url"]' < core.json)"
for org in supplier bank; do
    run peer add core --ledger-id "$CORE_ID" --url "$URL" --token-file "$org.token" \
        --ledger "$(dir "$org")" > /dev/null
done
say "Serving at $URL, for B and Bank A only."

step "5. B orders parts from C: a record on B's own ledger"
# Every field is private: the ledger keeps its salted commitment, B's vault
# the value. backed_by says what pays for the order; only B decides who reads it.
ORDER="$(run record issue --as supplier-root.key --type example.org.purchase-order/1 \
    --field goods="Gear sets, 2,000 units" --field amount="CNY 400,000.00" \
    --field due=2027-03-31 --field supplier="$(name_of sub)" \
    --field backed_by="receivable $RECEIVABLE on ledger $CORE_ID" \
    --ledger "$(dir supplier)" --json | field '["record"]["id"]')"
run record show "$ORDER" --ledger "$(dir supplier)" | sed -n '1,4p' | indent
run checkpoint create --log-key supplier-log.key --ledger "$(dir supplier)" > /dev/null

step "6. C receives the order: what it needs, and nothing of A"
run export "$ORDER" --disclose goods,amount,due,supplier --log-key supplier-log.key \
    --ledger "$(dir supplier)" --out order-for-c.cbor > /dev/null
run verify order-for-c.cbor --ledger-id "$SUPPLIER_ID" > c-sees.txt
sed -n '/^  Ledger/p; /^  Record/p; /^  Disclosed fields/,/^$/p' c-sees.txt | sed '/^$/d' | indent
run verify order-for-c.cbor --ledger-id "$SUPPLIER_ID" --json \
    | check "C's copy of the order" 'd["verified"] and sorted(d["disclosed_fields"]) == ["amount", "due", "goods", "supplier"]'
names_none "C's copy names A" order-for-c.cbor "$CORE_ID" "$RECEIVABLE" "$(name_of core)"
say "Its evidence verifies against B's ledger, and nowhere in it are A's name, A's ledger id,"
say "or the receivable: the field that names them stays sealed. C can see that the order has"
say "one more field, never what it holds."

step "7. C accepts the order on its own ledger, naming B's order as its source"
ACCEPTED="$(run record issue --as sub-root.key --type example.org.order-acceptance/1 \
    --field delivery=2027-02-28 --source "$SUPPLIER_ID:$ORDER" --source-proof order-for-c.cbor \
    --ledger "$(dir sub)" --json | field '["record"]["id"]')"
run record show "$ACCEPTED" --ledger "$(dir sub)" | grep -E '^source' | indent
names_none "C's ledger names A" "$(dir sub)" "$CORE_ID" "$RECEIVABLE" "$(name_of core)"
say "C's ledger keeps B's evidence as the proof of its source; it names nothing of A either."

step "8. B asks Bank A to pay C early against A's receivable: Bank A sees everything"
run export "$ORDER" --disclose goods,amount,due,supplier,backed_by --log-key supplier-log.key \
    --ledger "$(dir supplier)" --out order-for-bank.cbor > /dev/null
run contract fetch --peer core --instance "$RECEIVABLE" --out receivable.cbor \
    --ledger "$(dir supplier)" > /dev/null
say "The order, with what backs it:"
run verify order-for-bank.cbor --ledger-id "$SUPPLIER_ID" --json \
    | check "the order names the receivable" 'd["verified"] and d["disclosed_fields"]["backed_by"] == "receivable '"$RECEIVABLE"' on ledger '"$CORE_ID"'"'
run verify order-for-bank.cbor --ledger-id "$SUPPLIER_ID" | grep -E '^ +backed_by' | indent
say "and the receivable itself, verified offline against A's ledger, held by B, not pledged:"
run contract verify receivable.cbor --ledger-id "$CORE_ID" | grep -E 'Contract|Status' | indent
run contract verify receivable.cbor --ledger-id "$CORE_ID" --json \
    | check "the receivable backs it" 'd["verified"] and d["instance"]["status"] == "active" and d["instance"]["parties"]["holder"]["ledger_id"] == "'"$SUPPLIER_ID"'"'
# org CALL REFERENCE: the organization reviews the call it is asked to
# consent to, and consents on its own ledger; the consent's evidence goes to
# the registrar.
consent() {
    run contract consent --peer core --call "$2" --reference "$3" --as "$1-root.key" \
        --log-key "$1-log.key" --send --ledger "$(dir "$1")" | indent
}
PLEDGE="{\"counterparty\": h'$BANK_ID'}"
CALL="$(run contract propose "$RECEIVABLE" pledge --args "$PLEDGE" --peer core \
    --ledger "$(dir supplier)" --json | field '["call"]')"
# A consent's reference goes with it to A's ledger, which keeps the evidence of
# every consent its calls cite: it names the facility, never C or the order.
consent supplier "$CALL" "Pledge to Bank A, facility SCF-2026-0099"
consent bank "$CALL" "Facility SCF-2026-0099"
run contract instance "$RECEIVABLE" --ledger "$(dir core)" --json \
    | check "the receivable is pledged" 'd["status"] == "pledged"'
say "Pledged. Bank A pays C early under the facility, and is paid by A at maturity."

step "9. The receivable cannot back a second financing while it is pledged"
# (The trap is cleared inside: a refusal is what this step expects.)
if out="$(trap - ERR; run contract propose "$RECEIVABLE" pledge --args "$PLEDGE" --peer core \
    --ledger "$(dir supplier)" 2>&1)"; then
    echo "unexpected: a second pledge was accepted" >&2
    exit 1
fi
say "Refused: ${out#error: }"

step "10. Who saw what"
run contract fetch --peer core --instance "$RECEIVABLE" --out pledged.cbor --ledger "$(dir bank)" > /dev/null
run contract verify pledged.cbor --ledger-id "$CORE_ID" --json \
    | check "Bank A holds the pledge" 'd["verified"] and d["calls"][-1]["function"] == "pledge"'
names_none "A's ledger names C" "$(dir core)" "$SUB_ID" "$ORDER" "$(name_of sub)"
say "A:      its receivable, pledged to Bank A. Nothing on its ledger names C or the order."
say "C:      B's order (goods, amount, due date) and its own acceptance. Nothing names A."
say "Bank A: both, and the link between them, each verified against its own ledger."
for org in "${ORGS[@]}"; do run audit --ledger "$(dir "$org")" > /dev/null; done
say "Every ledger audits clean."
if [ "$KEEP" = 1 ]; then
    say "Ledgers kept in $WORK."
fi
