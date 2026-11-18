# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya
"""Approvals and guardians (spec v0.20, sections 5.1 and 5.2).

An approval is an actor's COSE_Sign1 (content type
application/kanhe-approval+cbor) over {1: ledger, 2: approver, 3: statement
id, 4: approved at, ? 5: proof of presence}. A delegation's rule (scope key
10) asks for k of up to 16 named approvers within a window; the
organization's guardians (ledger-set-guardians, statement type 9) are a rule
on the organization's own statements. Approvals travel in the log entry
(key 5), strictly ascending by approver.

check() applies the checks of section 5.1, "What the ledger checks", in
their order, with the state before the statement, and returns what a report
states: each rule that applied (in the order of "The rules that apply"),
whether the signer counted for it, and each approval with the rules it
counted for. Every refusal is an ApprovalError whose `why` names the rule,
as the test vectors do.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import NoReturn

from . import cbor, cose, crypto, presence, protocol
from .errors import ApprovalError, VerifyError

APPROVAL_CONTEXT = b"Kanhe approval v1"
MAX_APPROVALS = 32
MAX_APPROVAL_SIZE = 24_576
SKEW_MS = 300_000  # approved-at: from issued_at - 5 minutes to registration + 5 minutes

# Where a rule that applies comes from (section 5.1, "The rules that apply").
DELEGATION, GUARDIANS, NEW_GUARDIANS = "delegation", "guardians", "new_guardians"


def _fail(why: str, message: str) -> NoReturn:
    raise ApprovalError(why, message)


@dataclass
class Approval:
    encoded: bytes
    sign1: cose.Sign1
    payload: dict
    ledger: bytes
    approver: bytes
    statement: bytes
    approved_at: int
    presence: protocol.PresenceProof | None


def parse(data: bytes) -> Approval:
    """An approval in the profile of section 2, at most 24,576 bytes."""
    if not isinstance(data, bytes) or len(data) > MAX_APPROVAL_SIZE:
        _fail("too large", "an approval is more than 24,576 bytes encoded")
    try:
        sign1 = cose.parse_sign1(data, cose.APPROVAL_TYPE, "an approval")
    except cose.ContentTypeError as e:
        _fail("content type", str(e))
    except VerifyError as e:
        _fail("envelope", str(e))
    try:
        payload = cbor.decode(sign1.payload)
    except VerifyError as e:
        _fail("payload", f"an approval's payload is not deterministic CBOR: {e}")
    ok = (isinstance(payload, dict) and all(isinstance(k, int) and not isinstance(k, bool) for k in payload)
          and {1, 2, 3, 4} <= set(payload) <= {1, 2, 3, 4, 5}
          and all(isinstance(payload[k], bytes) and len(payload[k]) == 32 for k in (1, 2, 3))
          and isinstance(payload[4], int) and not isinstance(payload[4], bool) and payload[4] >= 0)
    if not ok:
        _fail("payload", "an approval's payload is not {1: ledger, 2: approver, 3: statement, 4: approved at, "
                         "? 5: proof of presence}")
    proof = None
    if 5 in payload:
        try:
            proof = protocol.parse_presence_proof(payload[5])
        except VerifyError as e:
            _fail("payload", f"an approval's proof of presence is malformed: {e}")
    return Approval(encoded=data, sign1=sign1, payload=payload, ledger=payload[1], approver=payload[2],
                    statement=payload[3], approved_at=payload[4], presence=proof)


def challenge(h, approval: Approval) -> bytes:
    """HASH("Kanhe approval v1" || kid || A), A the payload without key 5
    (section 7)."""
    without_proof = {k: v for k, v in approval.payload.items() if k != 5}
    return h(APPROVAL_CONTEXT + approval.sign1.kid + cbor.encode(without_proof))


def check_guardians_body(body: protocol.GuardiansBody):
    """The rules of section 5.2 about a setting's body alone: key 2 only with
    a rule; the guardians' rule never has key 4; key 2 never lists genesis."""
    if body.rule is None:
        if body.types is not None:
            _fail("null with types", "a setting that removes the guardians lists no types")
        return
    if body.rule.without_presence:
        _fail("guardians without presence", "the guardians' rule never counts approvals without presence (key 4)")
    if body.types is not None and protocol.GENESIS in body.types:
        _fail("genesis", "guardians never guard genesis")


@dataclass
class RuleResult:
    """A rule that applied to a statement, as a report states it."""
    source: str  # DELEGATION, GUARDIANS, or NEW_GUARDIANS
    delegation: bytes | None  # the delegation's id, for DELEGATION
    rule: protocol.ApprovalRule
    signer_counted: bool = False
    count: int = 0  # the approvals that counted for it, with the signer if it counted


@dataclass
class ApprovalResult:
    """An approval a statement carried, checked."""
    approval: Approval
    presence: presence.PresenceResult | None
    counted_for: list = field(default_factory=list)  # indices into the statement's rules


def rules_that_apply(ledger, statement: protocol.Statement, signer, chain: list) -> list:
    """Section 5.1, in its order: each delegation's rule in the chain (the
    signer's own first), the guardians' if the organization signs a guarded
    statement, and the rule a guardian setting sets."""
    out = []
    for d in chain:
        if d.scope.approval_rule is not None:
            out.append(RuleResult(source=DELEGATION, delegation=d.id, rule=d.scope.approval_rule))
    if signer.kind == protocol.ORGANIZATION:
        setting = ledger.guardians_in_effect()
        if setting is not None and ledger.is_guarded(statement, setting.body):
            out.append(RuleResult(source=GUARDIANS, delegation=None, rule=setting.body.rule))
        if statement.type == protocol.LEDGER_SET_GUARDIANS and statement.fields["guardians"].rule is not None:
            out.append(RuleResult(source=NEW_GUARDIANS, delegation=None, rule=statement.fields["guardians"].rule))
    return out


def _counts(rule: protocol.ApprovalRule, proven) -> bool:
    return rule.without_presence or (proven is not None and proven.user_verified)


def check(ledger, statement: protocol.Statement, statement_id: bytes, signer, chain: list, proven,
          encoded: list | None, now: int) -> tuple[list, list]:
    """Section 5.1, "What the ledger checks", with the state before the
    statement (`ledger`), at its registration time `now`. `encoded` is the
    approvals the log entry carries, in its order. Returns (the rules that
    applied, the approvals checked)."""
    rules = rules_that_apply(ledger, statement, signer, chain)
    encoded = encoded or []
    # 1. No approvals without a rule.
    if encoded and not rules:
        _fail("no rule", "the statement carries approvals, but no approval rule applies to it")
    # 2. At most 32, no approver twice, none by the signer; strictly ascending.
    if len(encoded) > MAX_APPROVALS:
        _fail("too many", "the statement carries more than 32 approvals")
    approvals = [parse(e) for e in encoded]
    ids = [a.approver for a in approvals]
    if signer.id in ids:
        _fail("signer", "the statement's own signer approves it (the signer counts through its statement)")
    if len(set(ids)) != len(ids):
        _fail("twice", "one approver approves the statement twice")
    if any(a >= b for a, b in zip(ids, ids[1:])):
        _fail("order", "the statement's approvals are not strictly ascending by approver")
    # 3. Each approval.
    h = ledger.h
    named = set()
    for r in rules:
        named |= set(r.rule.approvers)
    results = []
    for a in approvals:
        who = a.approver.hex()[:12]
        if a.ledger != ledger.id:
            _fail("ledger", f"an approval by {who} is for another ledger")
        if a.statement != statement_id:
            _fail("statement", f"an approval by {who} is of another statement")
        if a.approver not in named:
            _fail("not named", f"an approval by {who}, whom no rule that applies names")
        actor = ledger.actors.get(a.approver)
        if actor is None:
            _fail("unknown approver", f"an approval by {who}, whom the bundle does not register")
        if actor.revoked:
            _fail("revoked approver", f"an approval by {who}, who has been revoked")
        if a.sign1.alg != actor.key.alg or a.sign1.kid != actor.key.kid(h):
            _fail("key", f"an approval by {who} is not signed with the approver's current key")
        if not crypto.verify_signature(actor.key, a.sign1.to_be_signed(), a.sign1.signature):
            _fail("signature", f"an approval's signature by {who} does not verify")
        if a.approved_at < statement.issued_at - SKEW_MS or a.approved_at > now + SKEW_MS:
            _fail("approved at", f"an approval by {who} claims a time outside the statement's issue time minus "
                                 "5 minutes and its registration plus 5 minutes")
        proven_a = None
        if a.presence is not None:
            if actor.kind != protocol.PERSON:
                _fail("presence", f"an approval by {who} carries proof of presence, but only people prove presence")
            try:
                proven_a = presence.verify_proof(a.presence, actor.credentials, challenge(h, a), "approval")
            except VerifyError as e:
                _fail("presence", f"an approval's proof of presence by {who} does not verify: {e}")
        counted = [i for i, r in enumerate(rules) if a.approver in r.rule.approvers and _counts(r.rule, proven_a)]
        if not counted:
            _fail("does not count", f"an approval by {who} counts for no rule that applies (in person and "
                                    "user-verified is required)")
        results.append(ApprovalResult(approval=a, presence=proven_a, counted_for=counted))
    # 4. Each rule: its window, and k approvals that count.
    for i, r in enumerate(rules):
        if now > statement.issued_at + r.rule.within:
            _fail("lapsed", "the statement is registered after its approval rule's window")
        r.signer_counted = signer.id in r.rule.approvers and _counts(r.rule, proven)
        r.count = int(r.signer_counted) + sum(1 for x in results if i in x.counted_for)
        if r.count < r.rule.k:
            _fail("not met", f"an approval rule needs {r.rule.k} approvals, and {r.count} count")
    return rules, results
