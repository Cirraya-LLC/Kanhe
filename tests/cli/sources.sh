#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya
#
# Sources (spec v0.18), end to end: a bank's report names the records it was
# made from, a loan book on its own ledger and a land title on a registry's;
# the title's evidence, as the registry exported it, is kept as its proof;
# the report's evidence shows both, where each stood when the report was
# made and now, and warns when one was revoked since; verify --follow walks
# the chain through the sources' own evidence, level by level.
# Usage: sources.sh KANHE
set -Eeuo pipefail
trap 'echo "FAILED at line $LINENO: $BASH_COMMAND" >&2' ERR

KANHE="$1"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
cd "$WORK"

export KANHE_PASSPHRASE="sources test"
export KANHE_LEDGER="$WORK/bank"
unset KANHE_SERVER KANHE_TOKEN

run() { "$KANHE" "$@"; }
registry() { KANHE_LEDGER="$WORK/registry" "$KANHE" "$@"; }
fail() { echo "FAIL: $*"; [ -f out.txt ] && cat out.txt; exit 1; }
expect_exit() {
    local code="$1"; shift
    local actual=0
    run "$@" > out.txt 2>&1 || actual=$?
    [ "$actual" -eq "$code" ] || fail "expected exit $code, got $actual: $*"
}
contains() { grep "$@" > /dev/null; }
json() { python3 -c "import json,sys; d=json.load(sys.stdin); print($1)"; }

for k in root log reg-root reg-log; do run key generate --out "$k.key" > /dev/null; done
REGISTRY="$(registry init --name "Land Registry" --root-key reg-root.key --log-key reg-log.key \
    --json | json 'd["ledger_id"]')"
BANK="$(run init --name "Example Bank" --root-key root.key --log-key log.key --json |
    json 'd["ledger_id"]')"

# --- The registry's titles, exported as their evidence ----------------------------------
issue_title() {
    registry record issue --as reg-root.key --type example.org.land-title/1 --field lot="$1" \
        --json | json 'd["record"]["id"]'
}
TITLE="$(issue_title "DD 123 Lot 456")"
OTHER_TITLE="$(issue_title "DD 123 Lot 457")"
registry checkpoint create --log-key reg-log.key > /dev/null
registry export "$TITLE" --log-key reg-log.key --out title.cbor > /dev/null
registry export "$OTHER_TITLE" --log-key reg-log.key --out other-title.cbor > /dev/null

# --- A loan book, itself made from a title (no proof of it kept) -------------------------
BOOK="$(run record issue --as root.key --type example.org.loan-book/1 --field total="HKD 1,000" \
    --source "$REGISTRY:$OTHER_TITLE" --json | json 'd["record"]["id"]')"
run record source list "$BOOK" | contains "on ledger $REGISTRY (no proof kept"

# --- The report: from the book here and the title there ----------------------------------
# A proof must be of a source the record names on another ledger, and verify.
expect_exit 2 record issue --as root.key --type example.org.report/1 --field score=710 \
    --source "$BOOK" --source "$REGISTRY:$TITLE" --source-proof other-title.cbor
contains "not of a source the record names" out.txt || fail "a proof of another record"
printf 'not evidence' > junk.cbor
expect_exit 2 record issue --as root.key --type example.org.report/1 --field score=710 \
    --source "$REGISTRY:$TITLE" --source-proof junk.cbor
# A source is RECORD, or LEDGER:RECORD with full ids; a local one exists and is current.
expect_exit 1 record issue --as root.key --type example.org.report/1 --field score=710 \
    --source "abc:$TITLE"
expect_exit 2 record issue --as root.key --type example.org.report/1 --field score=710 \
    --source "$BANK:$(printf '7%.0s' {1..64})"
# --script names an approved script, not any record.
expect_exit 1 record issue --as root.key --type example.org.report/1 --field score=710 \
    --script "$BOOK"
[ "$(run record list --json | json 'len(d)')" = 1 ] || fail "nothing registered by the refusals"

R="$(run record issue --as root.key --type example.org.report/1 --field score=710 \
    --source "$BOOK" --source "$REGISTRY:$TITLE" --source-proof title.cbor --json)"
REPORT="$(echo "$R" | json 'd["record"]["id"]')"
[ "$(echo "$R" | json 'len(d["record"]["sources"])')" = 2 ] || fail "two sources: $R"
run record show "$REPORT" > out.txt
contains "source:     $BOOK (example.org.loan-book/1, live)" out.txt || fail "the local source"
contains "source:     $TITLE on ledger $REGISTRY (its proof is kept)" out.txt || fail "the title"
S="$(run record source list "$REPORT" --json)"
[ "$(echo "$S" | json 'd["sources"][0]["local"]')" = True ] || fail "local first: $S"
[ "$(echo "$S" | json 'd["sources"][1]["proof_kept"]')" = True ] || fail "the proof is kept: $S"
run record history "$REPORT" | contains "from 2 sources"
# A source revoked or replaced is no source for a new record.
NOV="$(run record issue --as root.key --type example.org.loan-book/1 --field total=1 --json |
    json 'd["record"]["id"]')"
run record revoke "$NOV" --as root.key --reason "restated" > /dev/null
expect_exit 2 record issue --as root.key --type example.org.report/1 --field score=1 \
    --source "$NOV"

# --- Its evidence -----------------------------------------------------------------------
run checkpoint create --log-key log.key > /dev/null
run export "$REPORT" --log-key log.key --out report.cbor > /dev/null
V="$(run verify report.cbor --ledger-id "$BANK" --json)"
[ "$(echo "$V" | json 'd["verified"] and d["complete"]')" = True ] || fail "it verifies: $V"
[ "$(echo "$V" | json 'd["sources"][0]["at_checkpoint"]')" = live ] || fail "the book is live"
[ "$(echo "$V" | json 'd["sources"][1]["provided"]')" = True ] || fail "the title is proven"
[ "$(echo "$V" | json 'd["sources"][1]["organization"]')" = "Land Registry" ]
[ "$(echo "$V" | json 'd["sources"][1]["type"]')" = example.org.land-title/1 ]
run verify report.cbor --ledger-id "$BANK" > out.txt
contains "Source       example.org.land-title/1 (id ${TITLE:0:12}) on Land Registry's ledger" out.txt ||
    fail "the title in words"
! contains "revoked or replaced since" out.txt || fail "no warning yet"

# --- The title revoked since: proven again, the evidence warns ---------------------------
registry record revoke "$TITLE" --as reg-root.key --reason "sold" > /dev/null
registry checkpoint create --log-key reg-log.key > /dev/null
registry export "$TITLE" --log-key reg-log.key --out title-now.cbor > /dev/null
run record source prove "$REPORT" title-now.cbor > out.txt
contains "revoked as of" out.txt || fail "the new proof says so"
expect_exit 2 record source prove "$REPORT" other-title.cbor
run export "$REPORT" --log-key log.key --out report-now.cbor > /dev/null
V="$(run verify report-now.cbor --ledger-id "$BANK" --json)"
[ "$(echo "$V" | json 'd["verified"]')" = True ] || fail "the report still verifies: $V"
[ "$(echo "$V" | json 'd["sources"][1]["at_record"]')" = live ] || fail "live when made"
[ "$(echo "$V" | json 'd["sources"][1]["at_checkpoint"]')" = revoked ] || fail "revoked now"
run verify report-now.cbor | contains "A source was revoked or replaced since"

# --- Forgotten: the title shows as not provided -----------------------------------------
run record source forget "$REPORT" "$REGISTRY:$TITLE" | contains "no longer goes with"
expect_exit 2 record source forget "$REPORT" "$REGISTRY:$TITLE"
run export "$REPORT" --log-key log.key --out report-bare.cbor > /dev/null
V="$(run verify report-bare.cbor --ledger-id "$BANK" --json)"
[ "$(echo "$V" | json 'd["verified"] and not d["sources"][1]["provided"]')" = True ] ||
    fail "a source without a proof is not provided, and the report still verifies: $V"

# --- verify --follow: the chain, through the sources' own evidence ----------------------
mkdir follow
cp title-now.cbor other-title.cbor follow/
run export "$BOOK" --log-key log.key --out follow/book.cbor > /dev/null
F="$(run verify report-bare.cbor --follow follow --json)"
[ "$(echo "$F" | json 'd["chain"]["sources"][0]["sources"][0]["record"]')" = "$OTHER_TITLE" ] ||
    fail "the book's own source, a level down: $F"
[ "$(echo "$F" | json 'd["chain"]["sources"][0]["sources"][0]["organization"]')" = "Land Registry" ]
[ "$(echo "$F" | json 'd["chain"]["sources"][1]["at_checkpoint"]')" = revoked ] ||
    fail "the title, found in the directory: $F"
[ "$(echo "$F" | json 'd["chain"]["revoked_or_replaced"]')" = 1 ] || fail "one warning: $F"
run verify report-bare.cbor --follow follow > out.txt
contains "Where it came from (followed in follow)" out.txt || fail "the chain in words"
contains "    <- ${OTHER_TITLE:0:12} example.org.land-title/1, Land Registry: live" out.txt ||
    fail "two levels"
contains "WARNING: 1 source in the chain was revoked or replaced since" out.txt || fail "warned"
run verify title.cbor --follow follow | contains "(it names no sources)"

# --- Help and completion -----------------------------------------------------------------
run record source prove --help | contains "one level per bundle"
run verify --help | contains -- "--follow DIR"
run completion bash | contains "source"
echo "sources: passed"
