# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya
"""Test vectors for specification revision v0.22 (range proofs), built from
spec/README.md (sections 5, 6, 11, and 11.3) and spec/kanhe.cddl with the
independent encoder of generate.py and the ledger forge of evidence_suite.py.
Writes testvectors/protocol-v0.22.json.

Everything is written here from the text: provable values (registration key
8) with their encodings and commitments, values read as integers, bounds,
statements in words, transcripts and their public values, range openings
files, a ledger whose registrations carry provable values, and evidence
bundles that carry range proofs (bundle key 12), each with the options to
verify it with, the verdict the specification decides (a failure names the
section and step that decide it), and facts its report must show. Only the
proofs' arithmetic is not: each proof of system 1 is made by a program that
proves with the Longfellow ZK library, given as --range-helper (the
reference implementation's kanhe-range), from a fixed seed, for tests only.
Nothing here uses the Python verifier.

The helper's protocol (spec-independent; the same as the Python verifier's):
`PROGRAM prove` reads {"salt": hex, "value": v in decimal, "low": lo' in
decimal, "high": hi' in decimal, "transcript": hex, "seed": hex} on its
standard input and writes {"commitment": hex, "proof": hex}; `PROGRAM
verify` reads {"commitment", "low", "high", "transcript", "proof"} and writes
{"valid": bool}, exiting 0 when valid and 1 when not. Every proof made here is
checked with `verify`, and every forged one must be refused by it.

Keys are Ed25519 throwaway keys, salts and seeds are derived from names, and
times are chosen, so a deterministic helper makes the same file every run.

Usage: python3 tools/testvectors/range_vectors.py --range-helper PROGRAM [--openssl PATH]
Run alone, it also puts its conformance cases into testvectors/evidence-v1.json,
replacing those of the same names and leaving every other case as it was.
generate.py runs it too when given --range-helper (and evidence_suite.py adds
the conformance cases).
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import pathlib
import re
import subprocess
import tempfile

import evidence_suite as es
import generate as g
import wasm_ref as w

OUT = g.OUT / "protocol-v0.22.json"
SHA256, SM3 = es.SHA256, es.SM3
PERSON, DEVICE = es.PERSON, es.DEVICE
CERTIFICATE = "example.org.certificate/1"
EMPLOYMENT = "example.org.employment/1"
RECEIPT = "kanhe.access-receipt/1"

# Section 6 and 11.3.
DOMAIN = b"Kanhe range v1"
LABEL = "kanhe.range/1"
OFFSET = 2 ** 63
INT64 = (-2 ** 63, 2 ** 63 - 1)
U64_MAX = 2 ** 64 - 1
SYSTEM = 1
LIBRARY_COMMIT = "1c0662989b919fe7b53a209a0a96f61f0e1b45c7"
CIRCUIT = "kanhe-range-64/1"
CIRCUIT_ID = "fc727b6726bd4bfe80b65d044cdb4d393fcc688b5aad0ab4ded3a9619459480a"
DECIMAL = re.compile(r"(-?)([0-9]+)(?:\.([0-9]+))?")
CURRENCY = re.compile(r"[A-Z]{3}")
DATE = re.compile(r"([0-9]{4})-([0-9]{2})-([0-9]{2})")
EPOCH = datetime.date(1970, 1, 1).toordinal()
CONTEXT_1 = hashlib.sha256(b"Kanhe test range context: a relying party's challenge").digest()[:16]
CONTEXT_2 = hashlib.sha256(b"Kanhe test range context: another challenge").digest()[:16]
DUMMY_PROOF = bytes(32)  # for cases refused before any proof is checked


# ---------------------------------------------------------------------------
# Values, bounds, commitments, transcripts, and words (sections 6 and 11.3)
# ---------------------------------------------------------------------------

def days(text: str) -> int:
    """A date's days from 1970-01-01, by Python's proleptic Gregorian
    ordinals."""
    y, m, d = (int(x) for x in text.split("-"))
    return datetime.date(y, m, d).toordinal() - EPOCH


def bound_x(encoding: list, value) -> tuple[int | None, str | None]:
    """(x, None) for a bound in the encoding, or (None, why it is refused)."""
    kind = encoding[0]
    if kind == "number":
        scale = encoding[1]
        if isinstance(value, int) and not isinstance(value, bool):
            x = value * 10 ** scale
        else:
            m = DECIMAL.fullmatch(value) if isinstance(value, str) and len(value) <= 40 else None
            if m is None:
                return None, "not a number"
            fraction = m.group(3) or ""
            if len(fraction) > scale:
                return None, "too many digits after the point"
            x = int(m.group(2) + fraction.ljust(scale, "0"))
            x = -x if m.group(1) else x
    elif kind == "money":
        if not (isinstance(value, list) and len(value) == 3 and g.claim_value_ok("money", value)):
            return None, "not money"
        if value[1] != encoding[1]:
            return None, "another currency"
        if value[2] != encoding[2]:
            return None, "another scale"
        x = value[0]
    else:
        if not g.claim_value_ok("date", value):
            return None, "not a date"
        if int(value[:4]) < 1:
            return None, "before 0001-01-01"
        x = days(value)
    if not INT64[0] <= x <= INT64[1]:
        return None, "out of range"
    return x, None


def commitment(salt: bytes, x: int) -> bytes:
    """SHA-256 on every ledger, SM3 ledgers too (section 6)."""
    return hashlib.sha256(DOMAIN + salt + (x + OFFSET).to_bytes(8, "big")).digest()


def public(low_x, high_x) -> tuple[int, int]:
    return (0 if low_x is None else low_x + OFFSET, U64_MAX if high_x is None else high_x + OFFSET)


def transcript(ledger: bytes, record: bytes, field: str, c: bytes, lo: int, hi: int, context) -> bytes:
    return g.dcbor([LABEL, ledger, record, field, c, lo, hi, context or b""])


def kind_of(encoding: list) -> str:
    return encoding[0]


def words(field: str, encoding: list, low, high) -> str:
    """Section 11.3, in a claim's words."""
    def v(x):
        return g.claim_value_words(kind_of(encoding), x)
    if low is not None and high is not None:
        return f"{field} is between {v(low)} and {v(high)}"
    if low is not None:
        return f"{field} is at least {v(low)}"
    return f"{field} is at most {v(high)}"


def encoding_fact(encoding: list) -> dict:
    """The report's JSON of an encoding (section 11.3)."""
    if encoding[0] == "number":
        return {"type": "number", "scale": encoding[1], "currency": None}
    if encoding[0] == "money":
        return {"type": "money", "scale": encoding[2], "currency": encoding[1]}
    return {"type": "date", "scale": None, "currency": None}


# ---------------------------------------------------------------------------
# The helper: a program that proves with the library
# ---------------------------------------------------------------------------

class Helper:
    def __init__(self, program: str):
        self.program = program

    def _run(self, command: str, request: dict) -> tuple[int, dict]:
        done = subprocess.run([self.program, command], input=json.dumps(request).encode(), capture_output=True,
                              timeout=300)
        assert done.returncode in (0, 1), (command, done.returncode, done.stderr.decode(errors="replace")[:400])
        return done.returncode, json.loads(done.stdout)

    def prove(self, salt: bytes, x: int, lo: int, hi: int, t: bytes, seed: bytes) -> tuple[bytes, bytes]:
        code, answer = self._run("prove", {"salt": salt.hex(), "value": str(x + OFFSET), "low": str(lo),
                                           "high": str(hi), "transcript": t.hex(), "seed": seed.hex()})
        assert code == 0, answer
        return bytes.fromhex(answer["commitment"]), bytes.fromhex(answer["proof"])

    def verify(self, c: bytes, lo: int, hi: int, t: bytes, proof: bytes) -> bool:
        code, answer = self._run("verify", {"commitment": c.hex(), "low": str(lo), "high": str(hi),
                                            "transcript": t.hex(), "proof": proof.hex()})
        assert answer.get("valid") is (code == 0), (code, answer)
        return code == 0


class Value:
    """A provable value of a record: its name, encoding, salt s, and x."""

    def __init__(self, f: es.Forge, name: str, encoding: list, x: int):
        self.name, self.encoding, self.x = name, encoding, x
        self.salt = hashlib.sha256(f"Kanhe test range salt: {f.name} {name}".encode()).digest()
        self.c = commitment(self.salt, x)

    @property
    def entry(self) -> list:
        return [self.name, self.encoding, self.c]


def provable(*values: Value) -> dict:
    """Key 8 of a registration, its entries in the names' bytewise order."""
    return {8: [v.entry for v in sorted(values, key=lambda v: v.name.encode())]}


class Prover:
    def __init__(self, helper: Helper):
        self.helper = helper
        self.made = 0

    def proof(self, f: es.Forge, record: bytes, value: Value, low=None, high=None, context=None) -> dict:
        """A range proof (bundle key 12) of `value` within [low, high], made by
        the helper from a seed derived from what it proves, and checked with
        it; and a copy with one bit flipped is refused."""
        low_x = bound_x(value.encoding, low)[0] if low is not None else None
        high_x = bound_x(value.encoding, high)[0] if high is not None else None
        lo, hi = public(low_x, high_x)
        assert lo <= value.x + OFFSET <= hi, (value.name, low, high)
        t = transcript(f.id, record, value.name, value.c, lo, hi, context)
        seed = hashlib.sha256(b"Kanhe test range seed: " + t).digest()
        c, proof = self.helper.prove(value.salt, value.x, lo, hi, t, seed)
        assert c == value.c, "the helper's commitment is not the specification's"
        assert self.helper.verify(c, lo, hi, t, proof)
        assert not self.helper.verify(c, lo, hi, t, tampered(proof))
        self.made += 1
        out = {1: value.name, 4: SYSTEM, 5: proof}
        if low is not None:
            out[2] = low
        if high is not None:
            out[3] = high
        if context is not None:
            out[6] = context
        return out


def tampered(proof: bytes) -> bytes:
    b = bytearray(proof)
    b[len(b) // 2] ^= 0x01
    return bytes(b)


def with_ranges(bundle: dict, proofs: list) -> bytes:
    out = dict(bundle)
    out[12] = list(proofs)
    return es.enc(out)


def proof_fact(p: dict, encoding: list, status: str = "verified") -> dict:
    return {"field": p[1], "low": p.get(2), "high": p.get(3), "text": words(p[1], encoding, p.get(2), p.get(3)),
            "context": p[6].hex() if 6 in p else None, "system": p[4], "status": status}


def provable_fact(*values: Value) -> list:
    return [{"field": v.name, "encoding": encoding_fact(v.encoding)}
            for v in sorted(values, key=lambda v: v.name.encode())]


def record_fact(record: bytes, kind: str, revoked: bool = False) -> dict:
    return {"id": record.hex(), "type": kind, "state": "registered", "revoked": revoked}


# ---------------------------------------------------------------------------
# The bundles
# ---------------------------------------------------------------------------

def bundle_cases(suite: es.Suite, helper: Helper) -> dict:
    """Every v0.22 bundle case, added to `suite`; returns what the file's
    other sections use."""
    prover = Prover(helper)
    systems = [SYSTEM]

    # --- A registrar's ledger: an employment record with three provable values
    f = es.Forge("Range Lab")
    clerk = f.actor(PERSON, "Registrar", es.Key("range lab registrar"))
    d = f.grant(clerk, {1: [16, 19]})
    birth = Value(f, "birth_date", ["date"], days("1990-05-17"))
    salary = Value(f, "monthly_salary", ["money", "HKD", 2], 3_500_000)
    score = Value(f, "score", ["number", 1], 875)
    fields = {"birth_date": "1990-05-17", "monthly_salary": [3_500_000, "HKD", 2], "name": "Chan Siu Ming",
              "score": "87.5"}
    rec = f.record(clerk, EMPLOYMENT, delegation=d, fields=fields, salt_size=32,
                   extra=provable(birth, salary, score))
    f.commit()
    base = f.bundle(rec)
    p_birth = prover.proof(f, rec, birth, high="2008-11-20")
    p_salary = prover.proof(f, rec, salary, low=[3_000_000, "HKD", 2], context=CONTEXT_1)
    p_score = prover.proof(f, rec, score, low=60, high="99.5")
    facts = {"ledger": f.ledger_fact(), "record": record_fact(rec, EMPLOYMENT),
             "provable": provable_fact(birth, salary, score), "complete": True}

    def ok(name, description, proofs, encodings, *, context=None, forge=f, subject=rec, kind=EMPLOYMENT,
           values=(birth, salary, score), bundle=None, revoked=False):
        suite.add(name, description, "record", with_ranges(bundle or base, proofs), True, ledger_id=forge.id,
                  range_context=context, range_systems=systems,
                  facts={"ledger": forge.ledger_fact(), "record": record_fact(subject, kind, revoked),
                         "provable": provable_fact(*values), "complete": True,
                         "range_proofs": [proof_fact(p, e) for p, e in zip(proofs, encodings)]})

    def bad(name, description, rule, evidence, *, context=None, needs=False, kind="record", ledger_id=None):
        suite.add(name, description, kind, evidence, False, rule=rule, ledger_id=ledger_id or f.id,
                  range_context=context, range_systems=systems if needs else ())

    ok("range-proof-verified",
       "An employment record whose registration marks a date, an amount, and a number provable, and a range proof "
       "that the date is at most 2008-11-20, without a context.", [p_birth], [birth.encoding])
    ok("range-proof-context-required",
       "A range proof that the monthly salary is at least HKD 30,000.00, carrying a relying party's challenge as "
       "its context, verified by a verifier that requires that context.", [p_salary], [salary.encoding],
       context=CONTEXT_1)
    ok("range-proofs-three",
       "Three range proofs of one record: a date at most a bound, money at least a bound with a context, and a "
       "number of scale 1 between an integer and a decimal text.", [p_birth, p_salary, p_score],
       [birth.encoding, salary.encoding, score.encoding])
    suite.add("range-provable-no-proofs",
              "A record with provable values and no range proofs: the report lists the provable values only.",
              "record", es.enc(base), True, ledger_id=f.id,
              facts={**facts, "range_proofs": []})

    bad("range-proof-tampered", "A range proof with one bit of its proof flipped: it does not verify under system 1.",
        "11.3, 11 step 13", with_ranges(base, [{**p_birth, 5: tampered(p_birth[5])}]), needs=True)
    bad("range-context-missing",
        "A range proof without a context, verified by a verifier that requires one: a required context is missing.",
        "11.3 (a required context), 11 step 13", with_ranges(base, [p_birth]), context=CONTEXT_1)
    bad("range-context-other",
        "A range proof whose context is one challenge, verified by a verifier that requires another.",
        "11.3 (a required context), 11 step 13", with_ranges(base, [p_salary]), context=CONTEXT_2)
    bad("range-system-unknown", "A valid proof of system 1, labelled system 2, which is not defined.",
        "11.3 check 4, 11 step 13", with_ranges(base, [{**p_birth, 4: 2}]))
    bad("range-field-not-provable",
        "A range proof of the field name, which the record has but its registration does not mark provable.",
        "11.3 check 2, 11 step 13", with_ranges(base, [{1: "name", 3: "Z", 4: SYSTEM, 5: DUMMY_PROOF}]))
    bad("range-field-twice", "Two copies of one valid range proof: a field is proven at most once in a bundle.",
        "11.3 check 1, 11 step 13", with_ranges(base, [p_birth, p_birth]))
    bad("range-low-above-high", "A range proof of the number score between 99.5 and 60: its low is above its high.",
        "11.3 check 3, 11 step 13", with_ranges(base, [{1: "score", 2: "99.5", 3: 60, 4: SYSTEM, 5: DUMMY_PROOF}]))
    bad("range-money-other-currency",
        "The valid proof that the salary is at least HKD 30,000.00, its low written in USD: a bound is in the "
        "provable's currency.", "11.3 check 3, 11 step 13",
        with_ranges(base, [{**p_salary, 2: [3_000_000, "USD", 2]}]), context=CONTEXT_1)
    bad("range-money-other-scale",
        "The valid proof that the salary is at least HKD 30,000.00, its low written as [30000, \"HKD\", 0], an equal "
        "amount of another scale: a bound has the provable's scale.", "11.3 check 3, 11 step 13",
        with_ranges(base, [{**p_salary, 2: [30_000, "HKD", 0]}]), context=CONTEXT_1)
    bad("range-number-too-many-decimals",
        "A range proof that the score, a number of scale 1, is at least \"60.25\", which has two digits after the "
        "point.", "11.3 check 3, 11 step 13",
        with_ranges(base, [{1: "score", 2: "60.25", 4: SYSTEM, 5: DUMMY_PROOF}]))
    bad("range-bound-out-of-range",
        "A range proof that the score, a number of scale 1, is at most 922337203685477581, whose x is above "
        "2^63 - 1.", "11.3 check 3, 11 step 13",
        with_ranges(base, [{1: "score", 3: 922337203685477581, 4: SYSTEM, 5: DUMMY_PROOF}]))
    bad("range-date-before-year-one", "A range proof of the date birth_date at least 0000-12-31, before 0001-01-01.",
        "11.3 check 3, 11 step 13",
        with_ranges(base, [{1: "birth_date", 2: "0000-12-31", 4: SYSTEM, 5: DUMMY_PROOF}]))
    bad("range-proof-without-bound", "A range proof with neither a low nor a high.", "11.3, CDDL range-proof",
        with_ranges(base, [{1: "score", 4: SYSTEM, 5: DUMMY_PROOF}]))
    bad("range-proof-unknown-key", "A range proof with a key 7, which the CDDL does not define.",
        "11.3, CDDL range-proof", with_ranges(base, [{1: "score", 2: 60, 4: SYSTEM, 5: DUMMY_PROOF, 7: True}]))
    bad("range-proof-empty-context", "A range proof with a context of 0 bytes.",
        "11.3, CDDL range-proof", with_ranges(base, [{1: "score", 2: 60, 4: SYSTEM, 5: DUMMY_PROOF, 6: b""}]))

    # --- On an SM3 ledger the commitment is SHA-256 all the same -------------------
    s3 = es.Forge("Range SM3 Org", hash_id=SM3)
    income = Value(s3, "income", ["money", "CNY", 2], 1_250_000)
    s3_rec = s3.record(s3.org, CERTIFICATE, fields={"income": "CNY 12,500.00", "holder": "Wong Mei"}, salt_size=32,
                       extra=provable(income))
    s3.commit()
    p_income = prover.proof(s3, s3_rec, income, low=[1_000_000, "CNY", 2])
    ok("range-proof-sm3-ledger",
       "An SM3 ledger's record with a provable amount, whose commitment is SHA-256, and a range proof that it is at "
       "least CNY 10,000.00.", [p_income], [income.encoding], forge=s3, subject=s3_rec, kind=CERTIFICATE,
       values=(income,), bundle=s3.bundle(s3_rec))

    # --- Negative values, dates before 1970, and a revoked record ---------------------
    e = es.Forge("Range Edge Org")
    temperature = Value(e, "temperature", ["number", 1], -125)
    founded = Value(e, "founded", ["date"], days("1901-03-01"))
    e_rec = e.record(e.org, CERTIFICATE, fields={"founded": "1901-03-01", "temperature": "-12.5"}, salt_size=32,
                     extra=provable(founded, temperature))
    level = Value(e, "level", ["number", 0], 3)
    e_old = e.record(e.org, CERTIFICATE, fields={"level": 3}, salt_size=32, extra=provable(level))
    e.about(19, e_old, {2: "issued in error"}, e.org)
    e.commit()
    p_temp = prover.proof(e, e_rec, temperature, low="-20", high="-10.0")
    p_founded = prover.proof(e, e_rec, founded, high="1950-01-01")
    p_level = prover.proof(e, e_old, level, low=2)
    ok("range-proof-negative-values",
       "A number of scale 1 below zero proven between -20 and -10.0, and a date before 1970 proven at most "
       "1950-01-01.", [p_founded, p_temp], [founded.encoding, temperature.encoding], forge=e, subject=e_rec,
       kind=CERTIFICATE, values=(founded, temperature), bundle=e.bundle(e_rec))
    ok("range-proof-revoked-record",
       "A range proof of a revoked record's provable value: it verifies, and the record is reported revoked.",
       [p_level], [level.encoding], forge=e, subject=e_old, kind=CERTIFICATE, values=(level,),
       bundle=e.bundle(e_old), revoked=True)

    # --- A mechanism type with provable values, refused at replay -----------------
    m = es.Forge("Range Receipt Org")
    note = Value(m, "note", ["number", 0], 1)
    m_rec = m.record(m.org, RECEIPT, fields={"note": 1}, salt_size=32,
                     metadata={"ledger": hashlib.sha256(b"a granter").digest(),
                               "grant": hashlib.sha256(b"a grant").digest(),
                               "delivery": hashlib.sha256(b"a delivery").digest()},
                     extra=provable(note))
    m.commit()
    bad("range-provable-on-mechanism-type",
        "An access receipt, of a mechanism type, whose registration marks a value provable: the ledger refuses it.",
        "5 (provable values), 6, 11 step 3", es.enc(m.bundle(m_rec)), ledger_id=m.id)

    # --- Range proofs in an instance's bundle ------------------------------------
    k = es.Forge("Range Instance Home")
    contract = k.deploy(g.oracle_contract(w), es.INTERFACE)
    instance, _, _ = k.create(contract, "propose", {1: 0, 2: "proposed"}, by=k.org)
    k.commit()
    instance_bundle = with_ranges(k.bundle(instance), [{1: "amount", 2: 0, 4: SYSTEM, 5: DUMMY_PROOF}])
    bad("range-proofs-in-instance-bundle",
        "An instance's contract evidence whose bundle carries a range proof: only a record's bundle carries them.",
        "11 step 13, 11.3", es.enc({0: 1, 1: instance_bundle}), kind="contract", ledger_id=k.id)

    # --- Range proofs in a source proof ------------------------------------------
    src = es.Forge("Range Source Org")
    grade = Value(src, "grade", ["number", 0], 7)
    src_rec = src.record(src.org, CERTIFICATE, fields={"grade": 7}, salt_size=32, extra=provable(grade))
    src.commit()
    p_grade = prover.proof(src, src_rec, grade, low=5)
    src_bundle = with_ranges(src.bundle(src_rec), [p_grade])
    a = es.Forge("Range Derived Org")
    a_rec = a.record(a.org, CERTIFICATE, fields={"summary": "made from a grade"}, salt_size=32,
                     extra={7: [[src.id, src_rec]]})
    a.commit()
    a_bundle = dict(a.bundle(a_rec))
    a_bundle[10] = [src_bundle]
    bad("range-proofs-in-source-proof",
        "A record whose registration names a source on another ledger, and whose bundle carries that source's "
        "evidence with a valid range proof in it: a source proof carries none.", "11 step 10",
        es.enc(a_bundle), ledger_id=a.id)

    return {"f": f, "rec": rec, "values": (birth, salary, score), "proofs": (p_birth, p_salary, p_score),
            "made": prover.made}


# Cases also put in the conformance suite (testvectors/evidence-v1.json).
SUITE_CASES = ("range-proof-verified", "range-proof-context-required", "range-proof-sm3-ledger",
               "range-proof-tampered", "range-context-missing", "range-context-other", "range-system-unknown",
               "range-field-not-provable", "range-field-twice", "range-low-above-high", "range-money-other-currency",
               "range-money-other-scale", "range-number-too-many-decimals", "range-bound-out-of-range",
               "range-provable-on-mechanism-type", "range-proofs-in-instance-bundle", "range-proofs-in-source-proof")


def suite_cases(suite: es.Suite, helper_program: str) -> None:
    """Adds the conformance cases of v0.22 to the suite (evidence_suite.py)."""
    mine = es.Suite()
    bundle_cases(mine, Helper(helper_program))
    for case in mine.cases:
        if case["name"] in SUITE_CASES:
            suite.cases.append(case)


# ---------------------------------------------------------------------------
# Shapes: provable values, values and bounds, words, transcripts, openings
# ---------------------------------------------------------------------------

def _c(label: str) -> bytes:
    return hashlib.sha256(label.encode()).digest()


def provable_cases() -> dict:
    """Key 8 of a registration, as it parses (section 6, CDDL provable), and
    refused, each for one rule."""
    def entry(name, encoding=("number", 0)):
        return [name, list(encoding), _c(f"commitment {name}")]

    valid = [
        ("one number", [entry("age")], 1),
        ("a number of scale 18, money of scale 4, and a date",
         [entry("a", ("number", 18)), entry("b", ("money", "USD", 4)), entry("c", ("date",))], 3),
        ("names ascending by their UTF-8 bytes", [entry("Z"), entry("a"), entry("é")], 3),
        ("64 entries, as many as the fields", [entry(f"f{i:02d}") for i in range(64)], 64),
        ("a name of 64 bytes", [entry("n" * 64)], 2),
    ]
    refused = [
        ("an empty list", [], 1),
        ("65 entries", [entry(f"f{i:02d}") for i in range(65)], 70),
        ("more entries than the record's fields", [entry("a"), entry("b")], 1),
        ("an entry that is not a list", ["age"], 1),
        ("an entry of two elements", [["age", ["number", 0]]], 1),
        ("an empty name", [entry("")], 1),
        ("a name of 65 bytes", [entry("n" * 65)], 1),
        ("a name that is a byte string", [[b"age", ["number", 0], _c("age")]], 1),
        ("names not ascending", [entry("b"), entry("a")], 2),
        ("a name twice", [entry("a"), entry("a")], 2),
        ("an unknown encoding", [entry("a", ("percent", 2))], 1),
        ("an encoding that is text", [["a", "number", _c("a")]], 1),
        ("a number of scale 19", [entry("a", ("number", 19))], 1),
        ("a number without its scale", [entry("a", ("number",))], 1),
        ("a number of a negative scale", [entry("a", ("number", -1))], 1),
        ("money of scale 5", [entry("a", ("money", "HKD", 5))], 1),
        ("money in a lower-case currency", [entry("a", ("money", "hkd", 2))], 1),
        ("money in a currency of four letters", [entry("a", ("money", "HKDX", 2))], 1),
        ("money without its scale", [entry("a", ("money", "HKD"))], 1),
        ("a date with a parameter", [entry("a", ("date", 0))], 1),
        ("a commitment of 31 bytes", [["a", ["number", 0], _c("a")[:31]]], 1),
        ("a commitment that is text", [["a", ["number", 0], _c("a").hex()]], 1),
    ]

    def entries_fact(value):
        return [{"name": n, "encoding": encoding_fact(e), "commitment": c.hex()} for n, e, c in value]
    return {"valid": [{"name": n, "provable": g.dcbor(v).hex(), "field_count": k, "entries": entries_fact(v)}
                      for n, v, k in valid],
            "refused": [{"name": n, "provable": g.dcbor(v).hex(), "field_count": k} for n, v, k in refused]}


def value_cases() -> list:
    """Values read as x in each encoding, at the ends of their ranges, with v
    and the commitment under a fixed salt."""
    salt = _c("Kanhe test range value salt")
    items = [
        (["number", 0], 0), (["number", 0], 18), (["number", 0], -5), (["number", 0], "007"),
        (["number", 0], 9223372036854775807), (["number", 0], -9223372036854775808),
        (["number", 2], 18), (["number", 2], "18.5"), (["number", 2], "18.50"), (["number", 2], "-0.01"),
        (["number", 18], 9), (["number", 18], "9.223372036854775807"), (["number", 18], "-9.223372036854775808"),
        (["money", "HKD", 2], [3_000_000, "HKD", 2]), (["money", "HKD", 2], [-25_000, "HKD", 2]),
        (["money", "JPY", 0], [123_456_789, "JPY", 0]),
        (["date"], "1970-01-01"), (["date"], "1969-12-31"), (["date"], "0001-01-01"), (["date"], "9999-12-31"),
        (["date"], "2000-02-29"), (["date"], "2008-11-20"),
    ]
    out = []
    for encoding, value in items:
        x, why = bound_x(encoding, value)
        assert why is None, (encoding, value, why)
        out.append({"encoding": encoding, "value": value, "x": x, "v": str(x + OFFSET), "salt": salt.hex(),
                    "commitment": commitment(salt, x).hex()})
    return out


def bound_cases() -> dict:
    """Bounds refused in an encoding, each for one rule (section 11.3)."""
    refused = [
        (["number", 0], 9223372036854775808, "out of range"), (["number", 0], -9223372036854775809, "out of range"),
        (["number", 0], "1.5", "too many digits after the point"), (["number", 0], "1e3", "not a number"),
        (["number", 0], "", "not a number"), (["number", 0], "+5", "not a number"),
        (["number", 0], "5.", "not a number"),
        (["number", 0], ".5", "not a number"), (["number", 0], "1" * 41, "not a number"),
        (["number", 0], True, "not a number"), (["number", 0], [1], "not a number"),
        (["number", 2], "18.505", "too many digits after the point"),
        (["number", 2], "18.500", "too many digits after the point"),
        (["number", 2], 92233720368547759, "out of range"),
        (["number", 18], 10, "out of range"),
        (["money", "HKD", 2], [3_000_000, "USD", 2], "another currency"),
        (["money", "HKD", 2], [30_000, "HKD", 0], "another scale"),
        (["money", "HKD", 2], [1, "HKD"], "not money"), (["money", "HKD", 2], [1, "hkd", 2], "not money"),
        (["money", "HKD", 2], [9223372036854775808, "HKD", 2], "out of range"),
        (["money", "HKD", 2], "HKD 30,000.00", "not money"),
        (["date"], "0000-12-31", "before 0001-01-01"), (["date"], "2026-02-29", "not a date"),
        (["date"], "2026-13-01", "not a date"), (["date"], "26-01-01", "not a date"),
        (["date"], "2026-1-01", "not a date"), (["date"], 20261120, "not a date"),
    ]
    out = []
    for encoding, value, why in refused:
        assert bound_x(encoding, value) == (None, why), (encoding, value, bound_x(encoding, value))
        out.append({"name": why, "encoding": encoding, "bound": value})
    return {"refused": out}


def word_cases() -> list:
    items = [
        ("birth_date", ["date"], None, "2008-11-20"),
        ("monthly_salary", ["money", "HKD", 2], [3_000_000, "HKD", 2], None),
        ("score", ["number", 1], 60, "99.5"),
        ("balance", ["money", "HKD", 2], [-25_000, "HKD", 2], [100_000_000, "HKD", 2]),
        ("height", ["number", 2], None, "18.50"),
        ("price", ["money", "JPY", 0], [123_456_789, "JPY", 0], None),
        ("temperature", ["number", 1], "-20", "-10.0"),
    ]
    return [{"field": f, "encoding": e, "low": lo, "high": hi, "text": words(f, e, lo, hi)} for f, e, lo, hi in items]


def transcript_cases(made: dict) -> list:
    """The transcripts of the Range Lab's three proofs, and of bounds at the
    ends of the range."""
    f, rec = made["f"], made["rec"]
    out = []
    for value, p in zip(made["values"], made["proofs"]):
        low_x = bound_x(value.encoding, p[2])[0] if 2 in p else None
        high_x = bound_x(value.encoding, p[3])[0] if 3 in p else None
        lo, hi = public(low_x, high_x)
        out.append({"ledger": f.id.hex(), "record": rec.hex(), "field": value.name, "commitment": value.c.hex(),
                    "low_bound": p.get(2), "high_bound": p.get(3), "encoding": value.encoding,
                    "low": str(lo), "high": str(hi), "context": p[6].hex() if 6 in p else None,
                    "transcript": transcript(f.id, rec, value.name, value.c, lo, hi, p.get(6)).hex()})
    c = _c("an edge commitment")
    for low_x, high_x, context in ((INT64[0], INT64[1], None), (None, None, bytes(range(64))), (0, 0, b"\x00")):
        lo, hi = public(low_x, high_x)
        out.append({"ledger": f.id.hex(), "record": rec.hex(), "field": "x", "commitment": c.hex(),
                    "low_bound": None, "high_bound": None, "encoding": ["number", 0],
                    "low": str(lo), "high": str(hi), "context": context.hex() if context else None,
                    "transcript": transcript(f.id, rec, "x", c, lo, hi, context).hex()})
    return out


def opening_cases(made: dict) -> dict:
    f, rec = made["f"], made["rec"]
    good = [[v.name, v.salt, v.x] for v in made["values"]]
    valid = {1: f.id, 2: rec, 3: good}
    refused = [
        ("a salt of 16 bytes", {1: f.id, 2: rec, 3: [[good[0][0], good[0][1][:16], good[0][2]]]}),
        ("names not ascending", {1: f.id, 2: rec, 3: [good[1], good[0]]}),
        ("a name twice", {1: f.id, 2: rec, 3: [good[0], good[0]]}),
        ("x out of range", {1: f.id, 2: rec, 3: [[good[0][0], good[0][1], 2 ** 63]]}),
        ("an empty list", {1: f.id, 2: rec, 3: []}),
        ("65 openings", {1: f.id, 2: rec, 3: [[f"f{i:02d}", good[0][1], i] for i in range(65)]}),
        ("an unknown key", {1: f.id, 2: rec, 3: good, 4: True}),
        ("no record", {1: f.id, 3: good}),
        ("a ledger id of 31 bytes", {1: f.id[:31], 2: rec, 3: good}),
        ("an opening of two elements", {1: f.id, 2: rec, 3: [good[0][:2]]}),
    ]
    return {"valid": [{"file": g.dcbor(valid).hex(), "ledger": f.id.hex(), "record": rec.hex(),
                       "openings": [{"name": n, "salt": s.hex(), "x": x,
                                     "commitment": commitment(s, x).hex()} for n, s, x in good]}],
            "refused": [{"name": n, "file": g.dcbor(v).hex()} for n, v in refused]}


def ledger_section() -> dict:
    """A log whose registrations carry provable values, one superseding
    another with its own, and the registrations the ledger refuses after it."""
    f = es.Forge("Range Registry")
    clerk = f.actor(PERSON, "Clerk", es.Key("range registry clerk"))
    d = f.grant(clerk, {1: [16]})
    v1 = Value(f, "grade", ["number", 0], 6)
    r1 = f.record(clerk, CERTIFICATE, delegation=d, fields={"grade": 6, "holder": "Lee Ka Yan"}, salt_size=32,
                  extra=provable(v1))
    v2 = Value(f, "grade", ["number", 1], 65)
    v3 = Value(f, "issued_on", ["date"], days("2026-09-01"))
    r2 = f.record(clerk, CERTIFICATE, delegation=d, fields={"grade": "6.5", "holder": "Lee Ka Yan",
                                                            "issued_on": "2026-09-01"},
                  supersedes=r1, salt_size=32, extra=provable(v3, v2))
    r3 = f.record(clerk, CERTIFICATE, delegation=d, fields={"holder": "Lee Ka Yan"}, salt_size=32)
    f.commit()
    after = len(f.entries)
    at = f.time

    def statement(by, body) -> str:
        """A signed registration the ledger is not given: refused after the
        log above."""
        f.nonce += 1
        p = {0: 1, 1: 16, 2: f.id, 3: by, 5: at - es.SECOND,
             6: hashlib.sha256(f"nonce {f.name} refused {f.nonce}".encode()).digest()[:16], 7: body}
        if by == clerk:
            p[4] = d
        return f.sign(f.key_of(by), g.STATEMENT_TYPE, g.dcbor(p))[0].hex()

    leaf = g.dcbor(["note", bytes(32), 1])
    root = f.merkle().mth([leaf])
    receipt_meta = {"ledger": _c("a granter"), "grant": _c("a grant"), "delivery": _c("a delivery")}
    note = [["note", ["number", 0], _c("note")]]
    refused = [
        ("a mechanism type with provable values", "mechanism type", False,
         statement(f.org, {1: RECEIPT, 2: root, 3: 1, 5: receipt_meta, 8: note})),
        ("more provable values than fields", "shape", True,
         statement(clerk, {1: CERTIFICATE, 2: root, 3: 1, 8: note + [["zz", ["date"], _c("zz")]]})),
        ("provable values not ascending", "shape", True,
         statement(clerk, {1: CERTIFICATE, 2: root, 3: 2, 8: [["zz", ["date"], _c("zz")]] + note})),
        ("an empty list of provable values", "shape", True, statement(clerk, {1: CERTIFICATE, 2: root, 3: 1, 8: []})),
    ]
    records = [{"id": r.hex(), "type": CERTIFICATE,
                "provable": [{"name": v.name, "encoding": encoding_fact(v.encoding), "commitment": v.c.hex()}
                             for v in vs]}
               for r, vs in ((r1, [v1]), (r2, [v2, v3]), (r3, []))]
    return {"name": f.name, "ledger_id": f.id.hex(), "hash": SHA256, "log_entries": [x.hex() for x in f.entries],
            "records": records,
            "refused": [{"name": n, "why": why, "malformed": malformed, "after": after, "at": at, "encoded": enc}
                        for n, why, malformed, enc in refused]}


DESCRIPTION = (
    "Kanhe protocol v0.22 test vectors: range proofs (spec sections 5, 6, 11, and 11.3). `system`: system 1, the "
    "library, its commit, and the circuit's name and id. `provable`: key 8 of a registration (the CDDL "
    "`provable`), valid with its entries decoded and refused, each for one rule, with the record's field count. "
    "`values`: values read as the integer x in each encoding, at the ends of the ranges, with v = x + 2^63 in "
    "decimal and the commitment SHA-256(\"Kanhe range v1\" || salt || BE64(v)) under the given salt. `bounds`: "
    "bounds refused in an encoding, each named for its rule. `words`: statements in words. `transcripts`: the "
    "deterministic encoding T of [\"kanhe.range/1\", ledger, record, field, C, lo', hi', context], with lo' and "
    "hi' in decimal. `openings`: range openings files (`.kanheopenings`), valid with the commitments of its "
    "openings and refused. `ledger`: a log whose registrations carry provable values (one superseding another "
    "with its own), and signed registrations refused after it, `malformed` when they do not parse. `bundles`: "
    "evidence bundles with range proofs (key 12), each with the options to verify it with (as "
    "testvectors/evidence-v1.json gives them, `range_context` among them), the verdict, for a failure the "
    "section and step that decide it, for a verified bundle facts its JSON report must show, matched as in "
    "evidence-v1.json, and `range_systems` on each case whose verdict or facts need system 1's arithmetic. "
    "Written by tools/testvectors/range_vectors.py from the specification with evidence_suite.py's forge and "
    "throwaway Ed25519 keys (seed = SHA-256(\"Kanhe test key: evidence <name>\")), salts SHA-256(\"Kanhe test "
    "range salt: <ledger> <name>\"), and proofs of system 1 made by the program that proves with the Longfellow "
    "ZK library (the reference implementation's kanhe-range) from the seed SHA-256(\"Kanhe test range seed: \" "
    "|| T), for tests only: a real prover draws fresh randomness for every proof (section 11.3).")


def generate(openssl: str = "openssl", helper_program: str | None = None, splice: bool = False) -> None:
    if helper_program is None:
        raise SystemExit("range_vectors.py needs --range-helper PROGRAM, the program that proves with the library")
    helper = Helper(helper_program)
    with tempfile.TemporaryDirectory() as tmp:
        es.Env.openssl, es.Env.work = openssl, pathlib.Path(tmp)
        suite = es.Suite()
        made = bundle_cases(suite, helper)
        document = {"description": DESCRIPTION,
                    "system": {"number": SYSTEM, "library": "Longfellow ZK", "commit": LIBRARY_COMMIT,
                               "zk_spec_version": 7, "circuit": CIRCUIT, "circuit_id": CIRCUIT_ID},
                    "provable": provable_cases(), "values": value_cases(), "bounds": bound_cases(),
                    "words": word_cases(), "transcripts": transcript_cases(made), "openings": opening_cases(made),
                    "ledger": ledger_section(), "bundles": suite.cases}
    OUT.write_text(json.dumps(document, indent=1, ensure_ascii=False) + "\n")
    verdicts = sum(1 for c in suite.cases if c["verified"])
    print(f"wrote {len(suite.cases)} bundles ({verdicts} verified, {made['made']} proofs made) to "
          f"testvectors/{OUT.name}")
    if splice:
        # The conformance suite: these cases replace those of the same
        # names, and every other case stays byte for byte as it was.
        current = json.loads(es.OUT.read_text())
        mine = [c for c in suite.cases if c["name"] in SUITE_CASES]
        names = {c["name"] for c in mine}
        current["cases"] = [c for c in current["cases"] if c["name"] not in names] + mine
        current["description"] = es.DESCRIPTION
        es.OUT.write_text(json.dumps(current, indent=1, ensure_ascii=False) + "\n")
        print(f"put {len(mine)} cases into testvectors/{es.OUT.name} ({len(current['cases'])} in all)")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--openssl", default="openssl", help="OpenSSL 3.5+ command-line tool")
    parser.add_argument("--range-helper", metavar="PROGRAM", required=True,
                        help="the program that proves with the Longfellow ZK library (kanhe-range)")
    args = parser.parse_args()
    generate(args.openssl, args.range_helper, splice=True)


if __name__ == "__main__":
    main()
