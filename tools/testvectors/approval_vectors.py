# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya
"""Test vectors for specification revision v0.20 (approvals and guardians),
built from spec/README.md (sections 5.1, 5.2, 7, 8, 9, and 11) and
spec/kanhe.cddl with the independent encoder of generate.py. Writes
testvectors/protocol-v0.20.json.

The ledger rules are modelled here on their own, from the text: every case
is checked against the model, which collects every rule a statement breaks,
so that each refused case breaks exactly one. Keys are Ed25519 throughout
(passkeys included), so that the file is the same on every run.

Usage: python3 tools/testvectors/approval_vectors.py
(generate.py runs it too.)
"""

from __future__ import annotations

import hashlib
import json

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519

import generate as g

APPROVAL_TYPE = "application/kanhe-approval+cbor"
PRESENCE_CONTEXT = b"Kanhe presence v1"
APPROVAL_CONTEXT = b"Kanhe approval v1"
SECOND, MINUTE, DAY = 1_000, 60_000, 86_400_000
SKEW = 5 * MINUTE
PERSON, AGENT, DEVICE = 1, 2, 3
KNOWN_TYPES = (1, 2, 3, 4, 5, 6, 7, 8, 9, 16, 17, 18, 19, 21, 22, 23)
PO, PAYMENT, INVOICE, READING, MEMO = ("example.org.po/1", "example.org.payment/1", "example.org.invoice/1",
                                       "example.org.reading/1", "example.org.memo/1")


def _int(v) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


def _ascending(items) -> bool:
    return all(a < b for a, b in zip(items, items[1:]))


# ---------------------------------------------------------------------------
# Shapes: the approval rule and the guardian setting's body (the CDDL)
# ---------------------------------------------------------------------------

def rule_problem(rule) -> str | None:
    """The one rule of `approval-rule` (spec section 5.1 and the CDDL) that
    `rule` breaks, or None, in the order the shape is read."""
    if not isinstance(rule, dict):
        return "not a map"
    if not all(_int(k) for k in rule) or set(rule) - {1, 2, 3, 4}:
        return "unknown key"
    if not {1, 2, 3} <= set(rule):
        return "missing key"
    if not (_int(rule[1]) and 1 <= rule[1] <= 16):
        return "k"
    if not (isinstance(rule[2], list) and 1 <= len(rule[2]) <= 16):
        return "approvers"
    if not all(isinstance(a, bytes) and len(a) == 32 for a in rule[2]):
        return "approver"
    if not _ascending(rule[2]):
        return "order"
    if len(rule[2]) < rule[1]:
        return "fewer than k"
    if not (_int(rule[3]) and 60_000 <= rule[3] <= 2_592_000_000):
        return "within"
    if 4 in rule and rule[4] is not True:
        return "without presence"
    return None


def guardians_shape_problem(body) -> str | None:
    """The one rule of `ledger-set-guardians-body`'s shape that `body`
    breaks, or None."""
    if not isinstance(body, dict):
        return "not a map"
    if not all(_int(k) for k in body) or set(body) - {1, 2}:
        return "unknown key"
    if 1 not in body:
        return "missing key"
    if body[1] is not None:
        problem = rule_problem(body[1])
        if problem is not None:
            return problem
    if 2 in body:
        if not (isinstance(body[2], list) and body[2]):
            return "types"
        if not all(_int(t) and t in KNOWN_TYPES for t in body[2]):
            return "type"
        if not _ascending(body[2]):
            return "type order"
    return None


def guardians_body_rules(body) -> list:
    """The ledger's rules about a setting's body alone (section 5.2)."""
    out = []
    if body[1] is None:
        if 2 in body:
            out.append("null with types")
        return out
    if body[1].get(4) is True:
        out.append("guardians without presence")
    if 1 in body.get(2, []):
        out.append("genesis")
    return out


def rule_cases() -> dict:
    ids = sorted(hashlib.sha256(f"approver {i}".encode()).digest() for i in range(17))
    base = {1: 2, 2: ids[:3], 3: 7 * DAY}
    valid = [base, {1: 1, 2: ids[:1], 3: 60_000}, {1: 16, 2: ids[:16], 3: 2_592_000_000, 4: True},
             {1: 3, 2: ids[:5], 3: DAY, 4: True}]

    def w(**changes):
        out = dict(base)
        for k, v in changes.items():
            key = int(k[1:])
            if v is ...:
                out.pop(key)
            else:
                out[key] = v
        return out

    refused = [
        ("not a map", [2, ids[:3], 7 * DAY], "not a map"),
        ("an unknown key", w(k5=True), "unknown key"),
        ("a key that is not an integer", {**base, "k": 2}, "unknown key"),
        ("no k", w(k1=...), "missing key"),
        ("no window", w(k3=...), "missing key"),
        ("k of 0", w(k1=0), "k"),
        ("k of 17", {1: 17, 2: ids[:16], 3: DAY}, "k"),
        ("k as text", w(k1="2"), "k"),
        ("no approvers", w(k2=[]), "approvers"),
        ("17 approvers", w(k2=ids[:17]), "approvers"),
        ("approvers as a map", w(k2={ids[0]: 1}), "approvers"),
        ("an approver of 31 bytes", w(k2=[ids[0][:31], ids[1], ids[2]]), "approver"),
        ("an approver as text", w(k2=[ids[0].hex(), ids[1], ids[2]]), "approver"),
        ("approvers out of order", w(k2=[ids[1], ids[0], ids[2]]), "order"),
        ("an approver twice", w(k2=[ids[0], ids[0], ids[1]]), "order"),
        ("fewer approvers than k", w(k1=3, k2=ids[:2]), "fewer than k"),
        ("a window of 59,999 ms", w(k3=59_999), "within"),
        ("a window of 30 days and 1 ms", w(k3=2_592_000_001), "within"),
        ("key 4 false", w(k4=False), "without presence"),
        ("key 4 as 1", w(k4=1), "without presence"),
    ]
    out_valid = [{"rule": g.dcbor(r).hex(), "k": r[1], "approvers": [a.hex() for a in r[2]], "within_ms": r[3],
                  "without_presence": 4 in r} for r in valid]
    for r in valid:
        assert rule_problem(r) is None
    out_refused = []
    for name, r, why in refused:
        assert rule_problem(r) == why, (name, rule_problem(r), why)
        out_refused.append({"name": name, "rule": g.dcbor(r).hex(), "why": why})
    return {"valid": out_valid, "refused": out_refused}


def guardian_body_cases() -> dict:
    ids = sorted(hashlib.sha256(f"guardian {i}".encode()).digest() for i in range(3))
    rule = {1: 2, 2: ids, 3: 7 * DAY}
    valid = [{1: rule}, {1: rule, 2: [16]}, {1: rule, 2: [2, 3, 4, 5, 6, 7, 8, 9, 16, 17, 18, 19, 21, 22, 23]},
             {1: None}]
    refused = [
        ("not a map", [rule], "not a map"),
        ("an unknown key", {1: rule, 3: True}, "unknown key"),
        ("no key 1", {2: [16]}, "missing key"),
        ("a rule of k 0", {1: {**rule, 1: 0}}, "k"),
        ("guardians as text", {1: "Chan, Lee, Ho"}, "not a map"),
        ("an empty list of types", {1: rule, 2: []}, "types"),
        ("types as a map", {1: rule, 2: {16: True}}, "types"),
        ("type 20 (reserved)", {1: rule, 2: [16, 20]}, "type"),
        ("types out of order", {1: rule, 2: [16, 5]}, "type order"),
        ("a type twice", {1: rule, 2: [16, 16]}, "type order"),
        ("null with types", {1: None, 2: [16]}, "null with types"),
        ("guardians counting approvals without presence", {1: {**rule, 4: True}}, "guardians without presence"),
        ("guardians guarding genesis", {1: rule, 2: [1, 16]}, "genesis"),
    ]
    out_valid = []
    for body in valid:
        assert guardians_shape_problem(body) is None and guardians_body_rules(body) == []
        out_valid.append({"body": g.dcbor(body).hex(), "removes": body[1] is None,
                          "types": body.get(2)})
    out_refused = []
    for name, body, why in refused:
        problem = guardians_shape_problem(body)
        got = [problem] if problem is not None else guardians_body_rules(body)
        assert got == [why], (name, got, why)
        out_refused.append({"name": name, "body": g.dcbor(body).hex(), "why": why,
                            "shape": problem is not None})
    return {"valid": out_valid, "refused": out_refused}


# ---------------------------------------------------------------------------
# A ledger written by hand, with a model of its rules
# ---------------------------------------------------------------------------

def _verify(public, message: bytes, signature: bytes) -> bool:
    try:
        public.verify(signature, message)
        return True
    except InvalidSignature:
        return False


class Book:
    """One ledger's log, built statement by statement, and the model of the
    rules of sections 5, 5.1, and 5.2 that these statements meet."""

    def __init__(self, hash_id: int, t0: int, keys: dict):
        self.lg = g.Ledger(hash_id)
        self.hash_id = hash_id
        self.keys = keys
        self.clock = t0 + SECOND
        self.counter = 0
        self.statements, self.refused, self.malformed, self.entries = [], [], [], []
        self.malformed_entries = []
        self.actors: dict[bytes, dict] = {}
        self.delegations: dict[bytes, dict] = {}
        self.records: dict[bytes, dict] = {}
        self.settings: list = []  # [(index, body, registered_at)]
        self.names: dict[str, bytes] = {}
        self.ledger_id = None
        self.log_keys = ["log"]
        self.root = "org_root"

    # -- keys and objects ----------------------------------------------------

    def h(self, data: bytes) -> bytes:
        return self.lg.h(data)

    def key(self, name: str):
        return self.keys[name]

    def kid(self, key_name: str) -> bytes:
        return self.lg.kid(self.keys[key_name])

    def actor(self, name: str) -> bytes:
        return self.names[name]

    def guardians(self):
        """The body of the setting in effect, or None."""
        if not self.settings or self.settings[-1][1][1] is None:
            return None
        return self.settings[-1][1]

    def named(self, rule: dict) -> list:
        return list(rule[2])

    # -- presence ------------------------------------------------------------

    def passkey_proof(self, credential: str, challenge: bytes, flags: int = 0x05) -> dict:
        cred_id = hashlib.sha256(f"credential {credential}".encode()).digest()[:16]
        auth = hashlib.sha256(b"localhost").digest() + bytes([flags]) + (7).to_bytes(4, "big")
        client = ('{"type":"webauthn.get","challenge":"' + g.b64url(challenge) +
                  '","origin":"http://localhost:43210","crossOrigin":false}').encode()
        return {1: cred_id, 2: auth, 3: client, 4: self.keys[credential].sign(auth + hashlib.sha256(client).digest())}

    def hardware_proof(self, credential: str, challenge: bytes) -> dict:
        return {1: hashlib.sha256(g.dcbor(g.ed_public(self.keys[credential]))).digest(),
                4: self.keys[credential].sign(challenge)}

    def passkey_credential(self, credential: str, label: str) -> dict:
        return {1: "localhost", 2: hashlib.sha256(f"credential {credential}".encode()).digest()[:16],
                3: g.ed_public(self.keys[credential]), 4: label}

    def hardware_credential(self, credential: str, label: str) -> dict:
        return {2: hashlib.sha256(g.dcbor(g.ed_public(self.keys[credential]))).digest(),
                3: g.ed_public(self.keys[credential]), 4: label, 5: 2}

    def proof_ok(self, actor_id: bytes, proof: dict, expected: bytes) -> tuple[bool, bool]:
        """(valid, user-verified) of a proof against the person's credentials
        (section 7)."""
        creds = self.actors[actor_id]["credentials"]
        cred = next((c for c in creds if c[2] == proof[1]), None)
        if cred is None:
            return False, False
        public = ed25519.Ed25519PublicKey.from_public_bytes(cred[3][1])
        if 5 in cred:  # a hardware key: its signature over the challenge itself
            return 2 not in proof and _verify(public, expected, proof[4]), True
        if 2 not in proof:
            return False, False
        auth, client = proof[2], proof[3]
        prefix = ('{"type":"webauthn.get","challenge":"' + g.b64url(expected) + '","origin":"').encode()
        ok = (auth[:32] == hashlib.sha256(cred[1].encode()).digest() and auth[32] & 0x01
              and client.startswith(prefix) and _verify(public, auth + hashlib.sha256(client).digest(), proof[4]))
        return bool(ok), bool(auth[32] & 0x04)

    # -- statements and approvals ----------------------------------------------

    def payload(self, signer: str, kind: int, body, delegation=None, issued_at=None) -> dict:
        self.counter += 1
        p = {0: 1, 1: kind, 5: self.clock - 500 if issued_at is None else issued_at,
             6: self.counter.to_bytes(16, "big"), 7: body}
        if self.ledger_id is not None:
            p[2], p[3] = self.ledger_id, self.actor(signer)
        if delegation is not None:
            p[4] = delegation
        return p

    def signing_key(self, signer: str) -> str:
        return self.root if signer == "org" else self.actors[self.actor(signer)]["key"]

    def present(self, p: dict, signer: str, credential: str, kind: str = "passkey", flags: int = 0x05) -> dict:
        """Adds the signer's proof of presence over the statement's challenge."""
        challenge = self.h(PRESENCE_CONTEXT + self.kid(self.signing_key(signer)) + g.dcbor(p))
        p[8] = self.hardware_proof(credential, challenge) if kind == "hardware" else \
            self.passkey_proof(credential, challenge, flags)
        return p

    def statement_id(self, signer: str, p: dict) -> bytes:
        protected = g.dcbor({1: g.COSE["Ed25519"], 3: g.STATEMENT_TYPE, 4: self.kid(self.signing_key(signer))})
        return self.h(g.dcbor(["Signature1", protected, b"", g.dcbor(p)]))

    def approval(self, approver: str, statement_id: bytes, issued_at: int, *, presence=None, credential=None,
                 flags: int = 0x05, approved_at=None, key=None, ledger=None, statement=None,
                 bad_signature=False, wrong_challenge=False) -> dict:
        """An approval (section 5.1) and what it is made of. `presence`:
        None, "passkey", or "hardware"; `key` signs in place of the
        approver's current key."""
        approver_id = self.actor(approver)
        key_name = key or self.actors[approver_id]["key"]
        payload = {1: ledger or self.ledger_id, 2: approver_id, 3: statement or statement_id,
                   4: issued_at + 200 if approved_at is None else approved_at}
        kid = self.kid(key_name)
        challenge = None
        if presence is not None:
            challenge = self.h(APPROVAL_CONTEXT + kid + g.dcbor(payload))
            signed_over = self.h(PRESENCE_CONTEXT + kid + g.dcbor(payload)) if wrong_challenge else challenge
            payload[5] = self.hardware_proof(credential, signed_over) if presence == "hardware" else \
                self.passkey_proof(credential, signed_over, flags)
        protected = g.dcbor({1: g.COSE["Ed25519"], 3: APPROVAL_TYPE, 4: kid})
        tbs = g.dcbor(["Signature1", protected, b"", g.dcbor(payload)])
        signature = self.keys[key_name].sign(tbs)
        if bad_signature:
            signature = bytes([signature[0] ^ 1]) + signature[1:]
        encoded = g.dcbor(g.cbor2.CBORTag(18, [protected, {}, g.dcbor(payload), signature]))
        return {"approver": approver_id, "payload": payload, "encoded": encoded, "kid": kid, "challenge": challenge,
                "key": key_name, "presence": presence, "tbs": tbs, "signature": signature}

    # -- the model -----------------------------------------------------------

    def chain(self, p: dict) -> list:
        out, d = [], p.get(4)
        while d is not None:
            out.append(d)
            d = self.delegations[d]["parent"]
        return out

    def guarded(self, p: dict, body: dict) -> bool:
        kind, b = p[1], p[7]
        if 2 not in body or kind in body[2]:
            return True
        if kind in (8, 9):
            return True
        if kind == 3 and b[1] == self.ledger_id:
            return True
        return kind in (3, 4, 7) and b[1] in body[1][2]

    def rules_that_apply(self, p: dict) -> list:
        """[(source, delegation, rule)], in section 5.1's order."""
        out = [("delegation", d, self.delegations[d]["scope"][10]) for d in self.chain(p)
               if 10 in self.delegations[d]["scope"]]
        if p[3] == self.ledger_id:
            current = self.guardians()
            if current is not None and self.guarded(p, current):
                out.append(("guardians", None, current[1]))
            if p[1] == 9 and p[7][1] is not None:
                out.append(("new_guardians", None, p[7][1]))
        return out

    def protected(self, actor_id: bytes) -> bool:
        current = self.guardians()
        if current is not None and actor_id in current[1][2]:
            return True
        return any(not d["revoked"] and 10 in d["scope"] and actor_id in d["scope"][10][2]
                   for d in self.delegations.values())

    def signer_uv(self, p: dict) -> bool:
        if 8 not in p:
            return False
        ok, uv = self.proof_ok(p[3], p[8], self.h(PRESENCE_CONTEXT + self.kid(self.signing_key_of(p[3]))
                                                  + g.dcbor({k: v for k, v in p.items() if k != 8})))
        return ok and uv

    def signing_key_of(self, actor_id: bytes) -> str:
        return self.root if actor_id == self.ledger_id else self.actors[actor_id]["key"]

    def approval_reasons(self, p: dict, sid: bytes, approvals: list, now: int):
        """Every rule of section 5.1 the approvals break, and, if none, what
        the report states: [(source, delegation, rule, signer counted,
        count)] and each approval's rules counted for."""
        rules = self.rules_that_apply(p)
        reasons = []
        if approvals and not rules:
            reasons.append("no rule")
        ids = [a["approver"] for a in approvals]
        if p[3] in ids:
            reasons.append("signer")
        if len(set(ids)) != len(ids):
            reasons.append("twice")
        elif not _ascending(ids):
            reasons.append("order")
        named = {a for _, _, r in rules for a in r[2]}
        counted = []
        for a in approvals:
            pl = a["payload"]
            if pl[1] != self.ledger_id:
                reasons.append("ledger")
                continue
            if pl[3] != sid:
                reasons.append("statement")
                continue
            if a["approver"] not in named:
                if rules:
                    reasons.append("not named")
                continue
            actor = self.actors[a["approver"]]
            if actor["revoked"]:
                reasons.append("revoked approver")
                continue
            if a["kid"] != self.kid(actor["key"]):
                reasons.append("key")
                continue
            if not _verify(self.keys[actor["key"]].public_key(), a["tbs"], a["signature"]):
                reasons.append("signature")
                continue
            if pl[4] < p[5] - SKEW or pl[4] > now + SKEW:
                reasons.append("approved at")
                continue
            uv = False
            if 5 in pl:
                expected = self.h(APPROVAL_CONTEXT + a["kid"] + g.dcbor({k: v for k, v in pl.items() if k != 5}))
                valid, uv = (False, False) if actor["kind"] != PERSON else self.proof_ok(a["approver"], pl[5],
                                                                                          expected)
                if not valid:
                    reasons.append("presence")
                    continue
            mine = [i for i, (_, _, r) in enumerate(rules) if a["approver"] in r[2] and (r.get(4) is True or uv)]
            if not mine:
                reasons.append("does not count")
                continue
            counted.append(mine)
        # Each rule, counting the approvals that passed every check above.
        report = []
        uv_signer = self.signer_uv(p)
        for i, (source, d, r) in enumerate(rules):
            if now > p[5] + r[3]:
                reasons.append("lapsed")
            signer = p[3] in r[2] and (r.get(4) is True or uv_signer)
            count = int(signer) + sum(1 for c in counted if i in c)
            if count < r[1]:
                reasons.append("not met")
            report.append({"source": source, "delegation": d.hex() if d else None, "k": r[1],
                           "approvers": [x.hex() for x in r[2]], "within_ms": r[3],
                           "without_presence": r.get(4) is True, "signer_counted": signer, "count": count})
        return list(dict.fromkeys(reasons)), report, counted

    def body_reasons(self, p: dict) -> list:
        """The rules of sections 5, 5.1, and 5.2 about these statements'
        bodies that v0.20 adds or that these vectors meet."""
        kind, b, signer = p[1], p[7], p[3]
        out = []
        if kind == 5:
            scope = b[2]
            if 9 in scope[1]:
                out.append("scope")
            for a in scope.get(10, {}).get(2, []):
                actor = self.actors.get(a)
                if actor is None or actor["kind"] is None or actor["revoked"] or \
                        (scope[10].get(4) is not True and actor["kind"] != PERSON):
                    out.append("approver")
                    break
        if kind in (3, 7):
            if self.protected(b[1]) and signer not in (b[1], self.ledger_id):
                out.append("protected")
        if kind == 4:
            current = self.guardians()
            if current is not None and b[1] in current[1][2]:
                if signer != self.ledger_id:
                    out.append("guardian")
                remaining = [a for a in current[1][2] if a != b[1] and not self.actors[a]["revoked"]]
                if len(remaining) < current[1][1]:
                    out.append("below k")
        if kind == 9:
            out += guardians_body_rules(b)
            if b[1] is None and self.guardians() is None:
                out.append("no guardians")
            if b[1] is not None:
                for a in b[1][2]:
                    actor = self.actors.get(a)
                    if actor is None or actor["kind"] != PERSON or actor["revoked"]:
                        out.append("approver")
                        break
        return out

    def check(self, signer: str, p: dict, approvals: list, now: int):
        sid = self.statement_id(signer, p)
        reasons, report, counted = self.approval_reasons(p, sid, approvals, now)
        return reasons + [r for r in self.body_reasons(p) if r not in reasons], report, counted

    # -- the log -------------------------------------------------------------

    def entry(self, sid: bytes, at: int, signed: bytes, approvals: list) -> bytes:
        e = {1: sid, 2: at, 3: signed}
        if approvals:
            e[5] = [a["encoded"] for a in approvals]
        return g.dcbor(e)

    def approval_json(self, a: dict, counted_for=None) -> dict:
        out = {"approver": a["approver"].hex(), "encoded": a["encoded"].hex(), "payload": g.dcbor(a["payload"]).hex(),
               "kid": a["kid"].hex(), "presence": {"passkey": "webauthn", "hardware": "hardware-key"}.get(
                   a["presence"]), "challenge": a["challenge"].hex() if a["challenge"] is not None else None}
        if counted_for is not None:
            out["counted_for"] = counted_for
        return out

    def add(self, name: str, signer: str, p: dict, approvals=(), *, creates=None, touches=()) -> bytes:
        approvals = sorted(approvals, key=lambda a: a["approver"])
        now = self.clock
        if self.ledger_id is not None:
            reasons, report, counted = self.check(signer, p, approvals, now)
            assert reasons == [], (name, reasons)
        else:
            report, counted = [], []
        signed, sid = self.lg.statement(self.keys[self.signing_key(signer)], p)
        index = len(self.entries)
        self.entries.append(self.entry(sid, now, signed, approvals))
        self.statements.append({"name": name, "signer": signer, "index": index, "encoded": signed.hex(),
                                "payload": g.dcbor(p).hex(), "statement_id": sid.hex(), "registered_at": now,
                                "approvals": [self.approval_json(a, c) for a, c in zip(approvals, counted)],
                                "rules": report, "entry": self.entries[-1].hex()})
        self.clock += MINUTE
        if creates == "actor":
            self.actors[sid] = {"kind": p[7][1], "name": p[7][2], "key": self._new_key, "revoked": False,
                                "credentials": [], "history": [index]}
        elif creates == "delegation":
            self.delegations[sid] = {"scope": p[7][2], "parent": p.get(4), "revoked": False, "history": [index]}
        elif creates == "record":
            self.records[sid] = {"history": [index]}
        for target in touches:
            obj = self.actors.get(target) or self.delegations.get(target) or self.records.get(target)
            obj["history"].append(index)
        return sid

    def refuse(self, name: str, signer: str, p: dict, approvals=(), why: str = "", *, unsorted=False):
        """A statement the ledger refuses for exactly the rule `why` names,
        validated against the state after the statements so far, at the time
        the next would be registered. `unsorted`: the approvals as given."""
        approvals = list(approvals) if unsorted else sorted(approvals, key=lambda a: a["approver"])
        reasons, _, _ = self.check(signer, p, approvals, self.clock)
        assert reasons == [why], (name, reasons, why)
        signed, sid = self.lg.statement(self.keys[self.signing_key(signer)], p)
        self.refused.append({"name": name, "signer": signer, "encoded": signed.hex(), "payload": g.dcbor(p).hex(),
                             "approvals": [self.approval_json(a) for a in approvals],
                             "entry": self.entry(sid, self.clock, signed, approvals).hex(),
                             "after": len(self.entries), "at": self.clock, "why": why})

    def unparsable(self, name: str, signer: str, p: dict, why: str):
        signed, _ = self.lg.statement(self.keys[self.signing_key(signer)], p)
        self.malformed.append({"name": name, "encoded": signed.hex(), "why": why})


def build(hash_id: int, t0: int, keys: dict) -> dict:
    b = Book(hash_id, t0, keys)
    lg = b.lg

    def register(name: str, kind: int, key_name: str, responsible=None, model=None) -> bytes:
        body = {1: kind, 2: name, 3: g.ed_public(keys[key_name])}
        if responsible is not None:
            body[4] = b.actor(responsible)
        if model is not None:
            body[5] = {1: model}
        b._new_key = key_name
        actor = b.add(f"register {name}", "org", b.payload("org", 2, body), creates="actor")
        b.names[name] = actor
        return actor

    def credentials(person: str, creds: list):
        actor = b.actor(person)
        b.add(f"register {person}'s presence credentials", "org", b.payload("org", 7, {1: actor, 2: creds}),
              touches=[actor])
        b.actors[actor]["credentials"] = creds

    def rule(k: int, people: list, within: int, without_presence: bool = False) -> dict:
        r = {1: k, 2: sorted(b.actor(x) for x in people), 3: within}
        if without_presence:
            r[4] = True
        return r

    def grant(name: str, by: str, grantee: str, scope: dict, under=None, approvals=(), presence=None) -> bytes:
        p = b.payload(by, 5, {1: b.actor(grantee), 2: scope}, under)
        if presence is not None:
            b.present(p, by, *presence)
        return b.add(name, by, p, approvals, creates="delegation")

    def fields(text: str):
        leaves = [g.dcbor(["text", bytes([0xA0]) * 16, text])]
        return lg.merkle().mth(leaves), 1

    def record_body(kind: str, text: str) -> dict:
        root, count = fields(text)
        return {1: kind, 2: root, 3: count}

    def approve(who: str, p: dict, signer: str, **kw) -> dict:
        """`who`'s approval of the statement `signer` signs with payload `p`.
        Directors approve with their own credentials, unless `kw` says."""
        credential = {"Chan Tai Man": ("passkey", "chan_passkey"), "Lee Ka Yan": ("hardware", "lee_ukey"),
                      "Ho Wing": ("passkey", "ho_passkey"), "Tse Mei": ("passkey", "tse_passkey"),
                      "Lam Po": ("passkey", "lam_passkey"), "Ng Siu": ("hardware", "ng_ukey")}.get(who)
        if credential is not None and "presence" not in kw:
            kw["presence"], kw["credential"] = credential
        elif "presence" in kw and kw["presence"] is not None and "credential" not in kw:
            kw["credential"] = credential[1]
        return b.approval(who, b.statement_id(signer, p), p[5], **kw)

    # --- Genesis and the people --------------------------------------------------
    b.ledger_id = None
    genesis = b.add("genesis", "org", b.payload("org", 1, {
        1: hash_id, 2: "Example Holdings", 3: g.ed_public(keys["org_root"]), 4: g.ed_public(keys["log"])}))
    b.ledger_id = genesis
    b.names["org"] = genesis
    b.actors[genesis] = {"kind": None, "name": "Example Holdings", "key": "org_root", "revoked": False,
                         "credentials": [], "history": [0]}
    for name, kind, key_name in (("Chan Tai Man", PERSON, "chan"), ("Lee Ka Yan", PERSON, "lee"),
                                 ("Ho Wing", PERSON, "ho"), ("Tse Mei", PERSON, "tse"),
                                 ("Wong Siu Ming", PERSON, "wong"), ("Yip Ka Ho", PERSON, "yip"),
                                 ("Cheung Wai", PERSON, "cheung"), ("Lam Po", PERSON, "lam"),
                                 ("Ng Siu", PERSON, "ng")):
        register(name, kind, key_name)
    register("Review Agent", AGENT, "agent", responsible="Chan Tai Man", model="example-model-7")
    register("Compliance Checker", DEVICE, "device")
    credentials("Chan Tai Man", [b.passkey_credential("chan_passkey", "Chan's phone")])
    credentials("Lee Ka Yan", [b.hardware_credential("lee_ukey", "Lee's UKey"),
                               b.passkey_credential("lee_passkey", "Lee's laptop")])
    credentials("Ho Wing", [b.passkey_credential("ho_passkey", "Ho's phone")])
    credentials("Tse Mei", [b.passkey_credential("tse_passkey", "Tse's phone")])
    credentials("Wong Siu Ming", [b.passkey_credential("wong_passkey", "Wong's phone")])
    credentials("Lam Po", [b.passkey_credential("lam_passkey", "Lam's phone")])
    credentials("Ng Siu", [b.hardware_credential("ng_ukey", "Ng's UKey")])
    d_admin = grant("delegate actor management to the HR administrator", "org", "Cheung Wai", {1: [2, 3, 4, 7]})

    # --- Rules checked at the grant -------------------------------------------------
    directors = ["Chan Tai Man", "Lee Ka Yan", "Ho Wing"]
    refused_grants = [
        ("a rule naming the organization", {1: 1, 2: sorted([genesis, b.actor("Chan Tai Man")]), 3: DAY}),
        ("a rule naming a device, without key 4", rule(1, ["Chan Tai Man", "Compliance Checker"], DAY)),
        ("a rule naming an actor that is not registered",
         {1: 1, 2: sorted([b.actor("Chan Tai Man"), lg.h(b"nobody")]), 3: DAY}),
    ]
    for name, r in refused_grants:
        b.refuse(name, "org", b.payload("org", 5, {1: b.actor("Wong Siu Ming"), 2: {1: [16], 10: r}}),
                 why="approver")
    b.refuse("a scope that covers ledger-set-guardians", "org",
             b.payload("org", 5, {1: b.actor("Cheung Wai"), 2: {1: [9, 16]}}), why="scope")
    good = rule(2, directors, 7 * DAY)
    for name, r, why in (("a rule needing 0 approvals", {**good, 1: 0}, "k"),
                         ("a rule whose approvers are out of order", {**good, 2: list(reversed(good[2]))}, "order"),
                         ("a rule needing more approvals than it names", {**good, 1: 4}, "fewer than k"),
                         ("a rule whose window is under a minute", {**good, 3: 59_999}, "within"),
                         ("a rule whose key 4 is false", {**good, 4: False}, "without presence")):
        assert rule_problem(r) == why
        b.unparsable(name, "org", b.payload("org", 5, {1: b.actor("Wong Siu Ming"), 2: {1: [16], 10: r}}), why)

    d_po = grant("delegate purchase orders to Wong, needing 2 of Chan, Lee, Ho, and Tse within 7 days", "org",
                 "Wong Siu Ming", {1: [16], 2: [PO], 10: rule(2, directors + ["Tse Mei"], 7 * DAY)})
    d_chan = grant("delegate payments and orders to Chan, who may delegate, needing 2 of the directors", "org",
                   "Chan Tai Man", {1: [5, 16], 2: sorted([PAYMENT, PO], key=str.encode), 5: True,
                                    10: rule(2, directors, 7 * DAY)})
    d_auto = grant("delegate invoices to Wong, needing 2 of the review agent, the compliance checker, and Chan, "
                   "approvals without presence counting (key 4)", "org", "Wong Siu Ming",
                   {1: [16], 2: [INVOICE], 10: rule(2, ["Review Agent", "Compliance Checker", "Chan Tai Man"], DAY,
                                                    without_presence=True)})
    d_reading = grant("delegate readings to the compliance checker, without a rule", "org", "Compliance Checker",
                      {1: [16], 2: [READING]})

    # --- A purchase order: 2 of 4 --------------------------------------------------
    def po(text: str, **kw):
        return b.payload("Wong Siu Ming", 16, record_body(PO, text), d_po, **kw)

    def wong_po(name: str, text: str, who: list, extra=(), why=None, unsorted=False, **kw):
        p = po(text, **kw)
        approvals = [approve(x, p, "Wong Siu Ming") for x in who] + [f(p) for f in extra]
        if why is None:
            return b.add(name, "Wong Siu Ming", p, approvals, creates="record")
        if unsorted:
            approvals = sorted(approvals, key=lambda a: a["approver"], reverse=True)
        b.refuse(name, "Wong Siu Ming", p, approvals, why, unsorted=unsorted)

    wong_po("a purchase order with one approval (k - 1)", "PO-1 one", ["Chan Tai Man"], why="not met")
    wong_po("a purchase order without approvals", "PO-1 none", [], why="not met")
    po1 = wong_po("Wong's purchase order, approved by Chan (passkey) and Lee (hardware key)", "PO-1",
                  ["Chan Tai Man", "Lee Ka Yan"])
    wong_po("the same approvals out of order", "PO-2", ["Chan Tai Man", "Lee Ka Yan"], why="order", unsorted=True)
    wong_po("Chan approves twice", "PO-2", ["Chan Tai Man", "Lee Ka Yan"],
            extra=[lambda p: approve("Chan Tai Man", p, "Wong Siu Ming", approved_at=p[5] + 300)], why="twice")
    wong_po("an approval by the HR administrator, whom no rule that applies names", "PO-2",
            ["Chan Tai Man", "Lee Ka Yan"], extra=[lambda p: approve("Cheung Wai", p, "Wong Siu Ming")],
            why="not named")
    wong_po("an approval of another statement", "PO-2", ["Chan Tai Man", "Lee Ka Yan"],
            extra=[lambda p: approve("Ho Wing", p, "Wong Siu Ming", statement=po1)], why="statement")
    wong_po("an approval for another ledger", "PO-2", ["Chan Tai Man", "Lee Ka Yan"],
            extra=[lambda p: approve("Ho Wing", p, "Wong Siu Ming", ledger=lg.h(b"another ledger"))], why="ledger")
    wong_po("a third approval without presence", "PO-2", ["Chan Tai Man", "Lee Ka Yan"],
            extra=[lambda p: approve("Ho Wing", p, "Wong Siu Ming", presence=None)], why="does not count")
    wong_po("a third approval by a passkey that did not verify the user", "PO-2", ["Chan Tai Man", "Lee Ka Yan"],
            extra=[lambda p: approve("Ho Wing", p, "Wong Siu Ming", presence="passkey", flags=0x01)],
            why="does not count")
    wong_po("a passkey assertion over the statement's challenge, not the approval's", "PO-2",
            ["Chan Tai Man", "Lee Ka Yan"],
            extra=[lambda p: approve("Ho Wing", p, "Wong Siu Ming", wrong_challenge=True)], why="presence")
    wong_po("an approval claimed 5 minutes and 1 ms before the statement's issue time", "PO-2",
            ["Chan Tai Man", "Lee Ka Yan"],
            extra=[lambda p: approve("Ho Wing", p, "Wong Siu Ming", approved_at=p[5] - SKEW - 1)], why="approved at")
    wong_po("an approval claimed 5 minutes and 1 ms after the registration", "PO-2", ["Chan Tai Man", "Lee Ka Yan"],
            extra=[lambda p: approve("Ho Wing", p, "Wong Siu Ming", approved_at=b.clock + SKEW + 1)],
            why="approved at")
    lapsed_at = b.clock - 7 * DAY - 1
    wong_po("registered 7 days and 1 ms after it was issued", "PO-2", ["Chan Tai Man", "Lee Ka Yan"],
            issued_at=lapsed_at, why="lapsed")
    wong_po("an approval signed with another actor's key", "PO-2", ["Chan Tai Man", "Lee Ka Yan"],
            extra=[lambda p: approve("Ho Wing", p, "Wong Siu Ming", key="tse")], why="key")
    wong_po("an approval whose signature does not verify", "PO-2", ["Chan Tai Man", "Lee Ka Yan"],
            extra=[lambda p: approve("Ho Wing", p, "Wong Siu Ming", bad_signature=True)], why="signature")
    p = b.payload("Compliance Checker", 16, record_body(READING, "reading 7"), d_reading)
    b.refuse("approvals on a statement no rule applies to", "Compliance Checker", p,
             [approve("Chan Tai Man", p, "Compliance Checker")], "no rule")
    wong_po("a purchase order registered 7 days after it was issued, the last moment", "PO-3",
            ["Chan Tai Man", "Ho Wing"], issued_at=b.clock - 7 * DAY)
    wong_po("a purchase order approved by Chan, Lee, Ho, and Tse (more than k)", "PO-4",
            ["Chan Tai Man", "Lee Ka Yan", "Ho Wing", "Tse Mei"])

    # --- The signer counts ------------------------------------------------------------
    def payment(text: str, presence=None, flags=0x05):
        p = b.payload("Chan Tai Man", 16, record_body(PAYMENT, text), d_chan)
        if presence:
            b.present(p, "Chan Tai Man", "chan_passkey", flags=flags)
        return p

    p = payment("payment 1", presence=True)
    b.add("Chan registers a payment in person (passkey, user verified), Lee approves: 2 of the directors, the "
          "signer counting", "Chan Tai Man", p, [approve("Lee Ka Yan", p, "Chan Tai Man")], creates="record")
    p = payment("payment 2")
    b.refuse("Chan registers a payment without presence, Lee approves: the signer does not count", "Chan Tai Man",
             p, [approve("Lee Ka Yan", p, "Chan Tai Man")], "not met")
    p = payment("payment 2", presence=True, flags=0x01)
    b.refuse("Chan registers a payment with a passkey that did not verify them, Lee approves", "Chan Tai Man", p,
             [approve("Lee Ka Yan", p, "Chan Tai Man")], "not met")
    p = payment("payment 2", presence=True)
    b.refuse("Chan approves their own payment", "Chan Tai Man", p,
             [approve("Chan Tai Man", p, "Chan Tai Man"), approve("Lee Ka Yan", p, "Chan Tai Man")], "signer")

    # --- Rules through a chain of two delegations ----------------------------------
    p = b.payload("Chan Tai Man", 5, {1: b.actor("Yip Ka Ho"), 2: {1: [16], 2: [PO], 10: rule(1, ["Ho Wing"], DAY)}},
                  d_chan)
    b.present(p, "Chan Tai Man", "chan_passkey")
    d_yip = b.add("Chan delegates orders to Yip, needing 1 of Ho within a day; Chan in person and Lee approve "
                  "under Chan's own rule", "Chan Tai Man", p, [approve("Lee Ka Yan", p, "Chan Tai Man")],
                  creates="delegation")

    def yip_po(name: str, text: str, who: list, why=None):
        p = b.payload("Yip Ka Ho", 16, record_body(PO, text), d_yip)
        approvals = [approve(x, p, "Yip Ka Ho") for x in who]
        if why is None:
            return b.add(name, "Yip Ka Ho", p, approvals, creates="record")
        b.refuse(name, "Yip Ka Ho", p, approvals, why)

    yip_po("Yip's order approved by Ho and Lee: Yip's rule (Ho) and Chan's (2 of the directors) both met",
           "PO-Y1", ["Ho Wing", "Lee Ka Yan"])
    yip_po("Yip's order approved by Chan and Lee: Yip's own rule not met", "PO-Y2", ["Chan Tai Man", "Lee Ka Yan"],
           why="not met")
    yip_po("Yip's order approved by Ho alone: the grantor's rule not met", "PO-Y2", ["Ho Wing"], why="not met")

    # --- Approvals without presence (key 4): an agent and a device -------------------
    def invoice(text: str):
        return b.payload("Wong Siu Ming", 16, record_body(INVOICE, text), d_auto)

    p = invoice("invoice 1")
    b.add("Wong's invoice approved by the review agent and the compliance checker, without presence (key 4)",
          "Wong Siu Ming", p, [approve("Review Agent", p, "Wong Siu Ming"),
                               approve("Compliance Checker", p, "Wong Siu Ming")], creates="record")
    p = invoice("invoice 2")
    b.add("Wong's invoice approved by Chan's key alone and by the review agent (key 4)", "Wong Siu Ming", p,
          [approve("Chan Tai Man", p, "Wong Siu Ming", presence=None),
           approve("Review Agent", p, "Wong Siu Ming")], creates="record")
    p = invoice("invoice 3")
    fake = b.approval("Review Agent", b.statement_id("Wong Siu Ming", p), p[5], presence="passkey",
                      credential="chan_passkey")
    b.refuse("the review agent's approval carries a proof of presence (only people prove presence)",
             "Wong Siu Ming", p, [approve("Compliance Checker", p, "Wong Siu Ming"), fake,
                                  approve("Chan Tai Man", p, "Wong Siu Ming")], "presence")

    # --- Approvers are protected -------------------------------------------------------
    b.refuse("the HR administrator rotates Ho's key (Ho is an approver)", "Cheung Wai",
             b.payload("Cheung Wai", 3, {1: b.actor("Ho Wing"), 2: g.ed_public(keys["ho_2"])}, d_admin),
             why="protected")
    b.refuse("the HR administrator replaces Lee's presence credentials (Lee is an approver)", "Cheung Wai",
             b.payload("Cheung Wai", 7, {1: b.actor("Lee Ka Yan"), 2: [b.passkey_credential("thief_passkey", "x")]},
                       d_admin), why="protected")
    yip = b.actor("Yip Ka Ho")
    b.add("the HR administrator rotates Yip's key (no rule names Yip)", "Cheung Wai",
          b.payload("Cheung Wai", 3, {1: yip, 2: g.ed_public(keys["yip_2"])}, d_admin), touches=[yip])
    b.actors[yip]["key"] = "yip_2"
    ho = b.actor("Ho Wing")
    p = b.payload("Ho Wing", 3, {1: ho, 2: g.ed_public(keys["ho_2"])})
    b.present(p, "Ho Wing", "ho_passkey")
    b.add("Ho rotates their own key, in person", "Ho Wing", p, touches=[ho])
    b.actors[ho]["key"] = "ho_2"
    wong_po("an approval by Ho with the old key, after the rotation", "PO-5", ["Chan Tai Man", "Lee Ka Yan"],
            extra=[lambda p: approve("Ho Wing", p, "Wong Siu Ming", key="ho")], why="key")
    wong_po("a purchase order approved by Ho with the new key, and by Chan", "PO-5", ["Ho Wing", "Chan Tai Man"])
    tse = b.actor("Tse Mei")
    b.add("the HR administrator revokes Tse (revoking a delegation's approver stays open)", "Cheung Wai",
          b.payload("Cheung Wai", 4, {1: tse, 2: "left"}, d_admin), touches=[tse])
    b.actors[tse]["revoked"] = True
    wong_po("an approval by Tse after Tse was revoked", "PO-6", ["Chan Tai Man", "Lee Ka Yan", "Tse Mei"],
            why="revoked approver")

    # --- Guardians ----------------------------------------------------------------------
    def org(kind: int, body, approvers=(), name="", why=None, **kw):
        p = b.payload("org", kind, body)
        approvals = [approve(x, p, "org") for x in approvers]
        if why is not None:
            b.refuse(name, "org", p, approvals, why)
            return None
        return b.add(name, "org", p, approvals, **kw)

    g1 = rule(2, directors, 7 * DAY)
    org(9, {1: None}, name="remove guardians when none are in effect", why="no guardians")
    org(9, {1: {**g1, 4: True}}, ["Chan Tai Man", "Lee Ka Yan"],
        name="guardians whose rule counts approvals without presence", why="guardians without presence")
    org(9, {1: rule(2, ["Chan Tai Man", "Lee Ka Yan", "Compliance Checker"], 7 * DAY)}, ["Chan Tai Man", "Lee Ka Yan"],
        name="guardians naming the compliance checker, a device", why="approver")
    org(9, {1: g1, 2: [1, 16]}, ["Chan Tai Man", "Lee Ka Yan"], name="guardians that would guard genesis",
        why="genesis")
    org(9, {1: g1}, ["Chan Tai Man"], name="guardians set with one new guardian's approval (k - 1)", why="not met")
    org(9, {1: g1}, ["Chan Tai Man", "Lee Ka Yan"],
        name="the organization names Chan, Lee, and Ho guardians, 2 of 3 within 7 days, guarding every statement; "
             "Chan and Lee approve", touches=[genesis])
    b.settings.append((len(b.entries) - 1, {1: g1}, b.clock - MINUTE))
    org(16, record_body(MEMO, "memo 1"), name="the organization registers a record without its guardians' approvals",
        why="not met")
    org(16, record_body(MEMO, "memo 1"), ["Chan Tai Man", "Ho Wing"],
        name="the organization registers a record, approved by Chan and Ho", creates="record")
    org(9, {1: None, 2: [16]}, ["Chan Tai Man", "Lee Ka Yan"],
        name="a setting that removes the guardians and lists types", why="null with types")
    p = b.payload("Cheung Wai", 4, {1: ho, 2: "left"}, d_admin)
    b.refuse("the HR administrator revokes a guardian", "Cheung Wai", p, why="guardian")
    org(3, {1: genesis, 2: g.ed_public(keys["org_root_2"])}, name="the organization rotates its root key without "
        "its guardians' approvals", why="not met")
    org(3, {1: genesis, 2: g.ed_public(keys["org_root_2"])}, ["Chan Tai Man", "Lee Ka Yan"],
        name="the organization rotates its root key, approved by Chan and Lee", touches=[genesis])
    b.root = "org_root_2"
    b.actors[genesis]["key"] = "org_root_2"
    org(4, {1: ho, 2: "retired"}, ["Chan Tai Man", "Lee Ka Yan"],
        name="the organization revokes Ho, a guardian, approved by Chan and Lee: 2 of 3 remain", touches=[ho])
    b.actors[ho]["revoked"] = True
    lee = b.actor("Lee Ka Yan")
    org(4, {1: lee, 2: "retired"}, ["Chan Tai Man", "Lee Ka Yan"],
        name="the organization revokes Lee too: fewer than 2 would remain", why="below k")

    g2 = rule(2, ["Chan Tai Man", "Lam Po", "Ng Siu"], 7 * DAY)
    org(9, {1: g2, 2: [16]}, ["Chan Tai Man", "Lam Po"],
        name="new guardians approved by the new set only: the current guardians' rule not met", why="not met")
    org(9, {1: g2, 2: [16]}, ["Chan Tai Man", "Lee Ka Yan", "Lam Po"],
        name="the organization names Chan, Lam, and Ng guardians of its registrations only; Chan and Lee (the "
             "current set) and Lam (the new) approve, Chan counting in both", touches=[genesis])
    b.settings.append((len(b.entries) - 1, {1: g2, 2: [16]}, b.clock - MINUTE))
    org(5, {1: b.actor("Compliance Checker"), 2: {1: [17]}},
        name="the organization grants a delegation without approvals: not guarded", creates="delegation")
    org(5, {1: b.actor("Compliance Checker"), 2: {1: [19]}}, ["Lam Po"],
        name="approvals on a statement the guardians do not guard", why="no rule")
    org(16, record_body(MEMO, "memo 2"), name="the organization registers a record without approvals: guarded",
        why="not met")
    org(8, {1: g.ed_public(keys["log_2"])}, name="the organization rotates the log key without approvals: always "
        "guarded", why="not met")
    org(8, {1: g.ed_public(keys["log_2"])}, ["Lam Po", "Ng Siu"],
        name="the organization rotates the log key, approved by Lam and Ng", touches=[genesis])
    b.log_keys.append("log_2")
    lam = b.actor("Lam Po")
    org(7, {1: lam, 2: [b.passkey_credential("lam_passkey", "Lam's phone")]},
        name="the organization sets a guardian's credentials without approvals: always guarded", why="not met")
    org(3, {1: genesis, 2: g.ed_public(keys["org_root_3"])},
        name="the organization rotates its root key without approvals: always guarded", why="not met")
    wong = b.actor("Wong Siu Ming")
    org(7, {1: wong, 2: [b.passkey_credential("wong_passkey", "Wong's phone")]},
        name="the organization sets Wong's credentials without approvals: Wong is no guardian, and type 7 is not "
             "listed", touches=[wong])
    org(9, {1: None}, ["Lam Po"], name="the guardians removed with one current guardian's approval (k - 1)",
        why="not met")
    org(9, {1: None}, ["Lam Po", "Ng Siu"], name="the organization removes its guardians, approved by Lam and Ng",
        touches=[genesis])
    b.settings.append((len(b.entries) - 1, {1: None}, b.clock - MINUTE))
    org(16, record_body(MEMO, "memo 3"), ["Lam Po"], name="approvals after the guardians were removed",
        why="no rule")
    org(16, record_body(MEMO, "memo 3"), name="the organization registers a record alone again", creates="record")

    # Guardian settings that do not parse (the CDDL's shape).
    for name, body, why in (("a guardian setting whose types are out of order", {1: g1, 2: [16, 5]}, "type order"),
                            ("a guardian setting naming type 20", {1: g1, 2: [20]}, "type"),
                            ("a guardian setting with key 3", {1: g1, 3: True}, "unknown key")):
        b.unparsable(name, "org", b.payload("org", 9, body), why)

    # Log entries that do not parse (section 8; the CDDL's log-entry).
    sid, signed = bytes.fromhex(b.statements[-1]["statement_id"]), bytes.fromhex(b.statements[-1]["encoded"])
    approval = bytes.fromhex(next(st for st in b.statements if st["approvals"])["approvals"][0]["encoded"])
    commitment_like = g.dcbor({1: sid, 2: b.clock, 4: signed, 5: [approval]})
    for name, entry, why in (
            ("approvals beside a state commitment", commitment_like, "beside a commitment"),
            ("an empty list of approvals", g.dcbor({1: sid, 2: b.clock, 3: signed, 5: []}), "empty"),
            ("33 approvals", g.dcbor({1: sid, 2: b.clock, 3: signed, 5: [approval] * 33}), "too many"),
            ("an approval that is not a byte string", g.dcbor({1: sid, 2: b.clock, 3: signed, 5: [1]}), "shape")):
        b.malformed_entries.append({"name": name, "entry": entry.hex(), "why": why})

    # The state commitment and checkpoint, under the log key in effect.
    leaves = sorted([[1, a, v["history"]] for a, v in b.actors.items()]
                    + [[2, d, v["history"]] for d, v in b.delegations.items()]
                    + [[3, r, v["history"]] for r, v in b.records.items()], key=lambda leaf: leaf[1])
    log_key = keys[b.log_keys[-1]]
    commitment_index = len(b.entries)
    commitment_id = g.append_state_commitment(lg, log_key, b.ledger_id, b.entries, leaves, b.clock)
    checkpoint_time = b.clock + SECOND
    checkpoint, _ = g.sign_log_checkpoint(lg, log_key, b.ledger_id, b.entries, checkpoint_time)

    # The genesis entry with an approval, which a verifier refuses.
    genesis_entry = g.dcbor({**g.cbor2.loads(b.entries[0]), 5: [approval]})
    return {
        "hash": hash_id,
        "ledger_id": b.ledger_id.hex(),
        "actors": {("Example Holdings" if n == "org" else n): a.hex() for n, a in b.names.items()},
        "delegations": {"admin": d_admin.hex(), "purchase_orders": d_po.hex(), "chan": d_chan.hex(),
                        "invoices": d_auto.hex(), "readings": d_reading.hex(), "yip": d_yip.hex()},
        "statements": b.statements,
        "refused": b.refused,
        "malformed": b.malformed,
        "malformed_entries": b.malformed_entries,
        "genesis_with_approvals": genesis_entry.hex(),
        "guardian_settings": [{"index": i, "removes": body[1] is None,
                               "k": body[1][1] if body[1] else None,
                               "guardians": [x.hex() for x in body[1][2]] if body[1] else [],
                               "within_ms": body[1][3] if body[1] else None,
                               "types": body.get(2), "registered_at": at} for i, body, at in b.settings],
        "guardians_in_effect": None,
        "log_entries": [e.hex() for e in b.entries],
        "log_key": b.log_keys[-1],
        "state_leaves": [{"kind": leaf[0], "id": leaf[1].hex(), "history": leaf[2]} for leaf in leaves],
        "state_root": g.smt_root(lg, leaves).hex(),
        "state_commitment": {"index": commitment_index, "id": commitment_id.hex()},
        "checkpoint": checkpoint.hex(),
        "checkpoint_time": checkpoint_time,
    }


def approval_object_cases(t0: int, keys: dict) -> dict:
    """Approvals that do not decode (the profile of section 2, the CDDL's
    approval-payload), each for the one rule `why` names, on a SHA-256
    ledger: "envelope", "content type", "payload"."""
    lg = g.Ledger(-16)
    key = keys["chan"]
    kid = lg.kid(key)
    good = {1: lg.h(b"ledger"), 2: lg.h(b"approver"), 3: lg.h(b"statement"), 4: t0}

    def signed(payload: bytes, content_type=APPROVAL_TYPE, unprotected=None, tag=True, header_extra=None):
        protected = g.dcbor({1: g.COSE["Ed25519"], 3: content_type, 4: kid, **(header_extra or {})})
        body = [protected, unprotected or {}, payload, key.sign(g.dcbor(["Signature1", protected, b"", payload]))]
        return g.dcbor(g.cbor2.CBORTag(18, body) if tag else body)

    valid = signed(g.dcbor(good))
    cases = [
        ("not tagged", signed(g.dcbor(good), tag=False), "envelope"),
        ("an unprotected header that is not empty", signed(g.dcbor(good), unprotected={4: kid}), "envelope"),
        ("a protected header with a fourth key", signed(g.dcbor(good), header_extra={2: [3]}), "envelope"),
        ("a statement's content type", signed(g.dcbor(good), content_type=g.STATEMENT_TYPE), "content type"),
        ("a payload key 6", signed(g.dcbor({**good, 6: 1})), "payload"),
        ("no approved-at", signed(g.dcbor({k: v for k, v in good.items() if k != 4})), "payload"),
        ("an approver of 31 bytes", signed(g.dcbor({**good, 2: good[2][:31]})), "payload"),
        ("a negative approved-at", signed(g.dcbor({**good, 4: -1})), "payload"),
        ("a proof of presence without a signature", signed(g.dcbor({**good, 5: {1: b"x"}})), "payload"),
        ("a payload that is not deterministic CBOR (approved-at 5 in two bytes)",
         signed(bytes([0xA4]) + g.dcbor(1) + g.dcbor(good[1]) + g.dcbor(2) + g.dcbor(good[2]) + g.dcbor(3)
                + g.dcbor(good[3]) + g.dcbor(4) + b"\x18\x05"), "payload"),
    ]
    return {"valid": {"encoded": valid.hex(), "payload": g.dcbor(good).hex()},
            "refused": [{"name": n, "encoded": e.hex(), "why": w} for n, e, w in cases]}


def generate() -> None:
    t0 = 1_795_478_400_000  # 2026-11-24T00:00:00Z
    names = ("org_root", "org_root_2", "org_root_3", "log", "log_2", "chan", "lee", "ho", "ho_2", "tse", "wong", "yip",
             "yip_2", "cheung", "lam", "ng", "agent", "device", "chan_passkey", "lee_ukey", "lee_passkey", "ho_passkey",
             "tse_passkey", "wong_passkey", "lam_passkey", "ng_ukey", "thief_passkey")
    seeds = {name: hashlib.sha256(f"Kanhe test key: v0.20 {name}".encode()).hexdigest() for name in names}
    keys = {name: ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(seed)) for name, seed in seeds.items()}
    ledgers = [build(hash_id, t0, keys) for hash_id in (-16, -65538)]
    document = {
        "description": (
            "Kanhe protocol objects of specification revision v0.20 (approvals and guardians), built by an "
            "independent Python encoder (tools/testvectors/approval_vectors.py, with generate.py's) from "
            "spec/README.md (sections 5.1, 5.2, 7, 8, 9, and 11) and spec/kanhe.cddl; the rules are modelled there "
            "on their own, and each refused case breaks exactly the one rule its `why` names. Times are "
            "milliseconds since the epoch. Keys are Ed25519, passkeys included: seed = SHA-256(\"Kanhe test key: "
            "v0.20 <name>\"), `seeds`. `approval_rules` holds approval rules (scope key 10) on their own: `valid`, "
            "each its deterministic CBOR and values; `refused`, each breaking one rule of the CDDL's approval-rule, "
            "in the order the shape is read: \"not a map\", \"unknown key\", \"missing key\", \"k\" (not 1 to 16), "
            "\"approvers\" (not a list of 1 to 16), \"approver\" (not a 32-byte id), \"order\" (not strictly "
            "ascending), \"fewer than k\", \"within\" (not 60,000 to 2,592,000,000 ms), \"without presence\" (key "
            "4 not true). `guardian_bodies` holds ledger-set-guardians bodies: `valid` (a rule, with types or not, "
            "and null); `refused` for their shape (`shape` true: the rule's reasons, \"types\", \"type\" (unknown), "
            "\"type order\") or for the ledger's rules about a body alone (`shape` false: \"null with types\", "
            "\"guardians without presence\", \"genesis\"). `approval_objects` holds an approval that decodes and "
            "approvals that do not: \"envelope\" (not a tagged COSE_Sign1 with exactly alg, content type, and kid "
            "and an empty unprotected header), \"content type\", \"payload\" (not an approval-payload in "
            "deterministic CBOR). `ledgers` holds one log for each hash (SHA-256, SM3): Example Holdings registers "
            "directors with passkeys and a hardware key, a clerk, an AI agent, and a device; delegations with "
            "approval rules (2 of 4 for purchase orders; 2 of the directors for Chan's payments and orders, with a "
            "delegation beneath it needing 1 of Ho; 2 of an agent, a device, and Chan with key 4); guardians set, "
            "changed by both sets, and removed. Each statement lists its `approvals` as its log entry carries them "
            "(each with its encoding, payload, kid, presence method, its `challenge` when it proves presence, and "
            "`counted_for`, the indices of the rules it counted for), and its `rules`, in the order of section "
            "5.1 (source \"delegation\" with the delegation's id, \"guardians\", or \"new_guardians\"; k; "
            "approvers; within_ms; without_presence; whether the signer counted; how many counted). `refused` "
            "statements, with the approvals their log `entry` would carry, are validated against the state after "
            "the first `after` entries, at `at`, and break exactly one rule: \"approver\" (a rule naming an actor "
            "that is not a registered, unrevoked person, or the organization, or without key 4 a non-person), "
            "\"scope\" (a scope naming ledger-set-guardians), \"no rule\", \"signer\", \"twice\", \"order\" "
            "(approvals not strictly ascending by approver), \"ledger\", \"statement\", \"not named\", \"revoked "
            "approver\", \"key\" (not the approver's current key), \"signature\", \"approved at\", \"presence\", "
            "\"does not count\", \"lapsed\", \"not met\", \"protected\" (an approver's key or credentials changed "
            "by another than the approver or the organization), \"guardian\" (a guardian revoked by another than "
            "the organization), \"below k\", \"no guardians\", and the body rules above. `malformed` statements "
            "do not parse (a scope's rule or a guardian setting of the wrong shape, `why` as above); "
            "`malformed_entries` are log entries that do not parse (\"beside a commitment\", \"empty\", \"too "
            "many\", \"shape\"); `genesis_with_approvals` is the genesis entry with an approval, which a verifier "
            "refuses. `guardian_settings` lists the settings registered, in log order. `log_entries` holds the "
            "whole log, ending with the state commitment over `state_leaves`, in which the organization's leaf "
            "lists its root and log key rotations and the guardian settings, and approvals change no leaf; "
            "`checkpoint` (signed at `checkpoint_time`) covers it, signed by the log key `log_key` names."),
        "seeds": seeds,
        "approval_rules": rule_cases(),
        "guardian_bodies": guardian_body_cases(),
        "approval_objects": approval_object_cases(t0, keys),
        "ledgers": ledgers,
    }
    (g.OUT / "protocol-v0.20.json").write_text(json.dumps(document, indent=1, ensure_ascii=False) + "\n")
    first = ledgers[0]
    reasons = sorted({r["why"] for r in first["refused"]})
    print(f"wrote protocol vectors to testvectors/protocol-v0.20.json: {len(document['approval_rules']['refused'])} "
          f"refused rules, {len(document['guardian_bodies']['refused'])} refused guardian bodies; "
          f"{len(ledgers)} ledgers of {len(first['statements'])} statements, {len(first['refused'])} refused "
          f"({', '.join(reasons)}), {len(first['malformed'])} malformed")


if __name__ == "__main__":
    generate()
