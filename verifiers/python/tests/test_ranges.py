# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya
"""Range proofs (spec v0.22, sections 6, 11, and 11.3): provable values and
the range proofs a record's bundle carries.

Unit tests of everything but a proof's arithmetic: the encodings and the
integers x they read, bounds and their refusals, commitments, the public
values, the transcript's bytes, the words, the shapes of key 8, key 12, and
range openings files. The plumbing to the helper program runs against a fake
helper written here, which accepts a proof exactly when it is a fixed hash of
the commitment, the public values, and the transcript, so that a ledger
forged here can carry proofs the fake makes, verified, refused, or not
checked. And the v0.22 vectors (testvectors/protocol-v0.22.json), when they
exist: their bundles that need system 1's arithmetic run only with
KANHE_RANGE_HELPER, the reference implementation's kanhe-range."""

from __future__ import annotations

import contextlib
import copy
import datetime
import hashlib
import io
import json
import pathlib
import sys
import tempfile
import unittest

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE))

from kanhe_verify import cbor, cli, protocol, ranges, rules  # noqa: E402
from kanhe_verify.errors import VerifyError  # noqa: E402

from probes import Forge  # noqa: E402
from test_conformance import RANGE_HELPER, mismatches, run, runnable  # noqa: E402
from test_vectors import hx  # noqa: E402

VECTORS = HERE.parents[2] / "testvectors" / "protocol-v0.22.json"

# A stand-in for the helper program: `prove` checks the bounds and makes the
# commitment as the specification does, and its "proof" is a hash of what
# the verifier gives `verify`, which accepts exactly that hash.
FAKE_HELPER = r'''#!{python}
import hashlib, json, sys

def fake(c, lo, hi, t):
    return hashlib.sha256(b"fake range proof" + c + lo.to_bytes(8, "big") + hi.to_bytes(8, "big") + t).digest() * 3

def main():
    command = sys.argv[1] if len(sys.argv) == 2 else ""
    try:
        r = json.loads(sys.stdin.read())
        lo, hi = int(r["low"]), int(r["high"])
        t = bytes.fromhex(r["transcript"])
        assert 0 <= lo < 2 ** 64 and 0 <= hi < 2 ** 64
        if command == "verify":
            c, proof = bytes.fromhex(r["commitment"]), bytes.fromhex(r["proof"])
        elif command == "prove":
            salt, v = bytes.fromhex(r["salt"]), int(r["value"])
            assert len(salt) == 32 and 0 <= v < 2 ** 64
        else:
            raise ValueError(command)
    except Exception as e:
        print(json.dumps({"error": str(e)}))
        return 2
    if command == "verify":
        valid = proof == fake(c, lo, hi, t)
        print(json.dumps({"valid": valid}))
        return 0 if valid else 1
    if not lo <= v <= hi:
        print(json.dumps({"error": "the value is not within the bounds"}))
        return 1
    c = hashlib.sha256(b"Kanhe range v1" + salt + v.to_bytes(8, "big")).digest()
    print(json.dumps({"commitment": c.hex(), "proof": fake(c, lo, hi, t).hex()}))
    return 0

sys.exit(main())
'''


def write_helper(directory: pathlib.Path, name: str, text: str) -> str:
    path = directory / name
    path.write_text(text.replace("{python}", sys.executable))
    path.chmod(0o755)
    return str(path)


def salt_of(name: str) -> bytes:
    return hashlib.sha256(f"Kanhe test range salt (Python): {name}".encode()).digest()


class Provable:
    """A record with provable values, forged by hand (probes.Forge), and
    range proofs of them made by a helper."""

    def __init__(self, values: dict, kind: str = "example.org.probe/1", fields: dict | None = None):
        self.f = f = Forge()
        self.values = values  # name -> (encoding as in CBOR, x)
        entries = [[name, encoding, ranges.commitment(salt_of(name), x)]
                   for name, (encoding, x) in sorted(values.items(), key=lambda v: v[0].encode())]
        fields = fields or {name: "value" for name in list(values) + ["note"]}
        self.record = f.record("root", f.ledger_id, kind=kind, fields=fields, extra={8: entries})

    def proof(self, helper: ranges.Helper, name: str, low=None, high=None, context=None, system=1) -> dict:
        encoding, x = self.values[name]
        e = ranges.parse_encoding(encoding)
        low_x = ranges.bound_x(e, low) if low is not None else None
        high_x = ranges.bound_x(e, high) if high is not None else None
        lo, hi = ranges.public_values(low_x, high_x)
        c = ranges.commitment(salt_of(name), x)
        t = ranges.transcript(self.f.ledger_id, self.record, name, c, lo, hi, context)
        made, proof = helper.prove(salt_of(name), x, lo, hi, t)
        assert made == c
        out = {1: name, 4: system, 5: proof}
        if low is not None:
            out[2] = low
        if high is not None:
            out[3] = high
        if context is not None:
            out[6] = context
        return out

    def bundle(self, proofs: list | None) -> bytes:
        def add(b):
            if proofs is not None:
                b[12] = proofs
        return self.f.bundle(self.record, mutate=add)


def verify(work: pathlib.Path, evidence: bytes, *options: str) -> tuple[int, dict, str]:
    """The command line on a bundle: (exit code, JSON report, stderr)."""
    path = work / "bundle.cbor"
    path.write_bytes(evidence)
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = cli.main([str(path), "--json", *options])
    text = out.getvalue()
    return code, json.loads(text) if text.strip() else {}, err.getvalue()


def text_report(work: pathlib.Path, evidence: bytes, *options: str) -> str:
    path = work / "bundle.cbor"
    path.write_bytes(evidence)
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        cli.main([str(path), *options])
    return out.getvalue()


class Encodings(unittest.TestCase):
    def test_encodings(self):
        self.assertEqual(ranges.parse_encoding(["number", 0]), ranges.Encoding("number", 0))
        self.assertEqual(ranges.parse_encoding(["number", 18]), ranges.Encoding("number", 18))
        self.assertEqual(ranges.parse_encoding(["money", "HKD", 4]), ranges.Encoding("money", 4, "HKD"))
        self.assertEqual(ranges.parse_encoding(["date"]), ranges.Encoding("date"))
        for bad in (["number", 19], ["number", -1], ["number"], ["number", True], ["money", "HKD", 5],
                    ["money", "hkd", 2], ["money", "HKDX", 2], ["money", "HKD"], ["date", 0], ["percent", 2], [],
                    "number", None):
            with self.subTest(bad), self.assertRaises(VerifyError):
                ranges.parse_encoding(bad)

    def test_numbers(self):
        n0, n2, n18 = (ranges.Encoding("number", s) for s in (0, 2, 18))
        for e, value, x in ((n0, 18, 18), (n0, "18", 18), (n0, "-5", -5), (n0, "007", 7), (n0, "-0", 0),
                            (n2, 18, 1800), (n2, "18.5", 1850), (n2, "18.50", 1850), (n2, "-0.01", -1),
                            (n0, 2 ** 63 - 1, 2 ** 63 - 1), (n0, -2 ** 63, -2 ** 63),
                            (n18, "9.223372036854775807", 2 ** 63 - 1), (n18, "-9.223372036854775808", -2 ** 63)):
            with self.subTest((e.scale, value)):
                self.assertEqual(ranges.bound_x(e, value), x)
        for e, value in ((n0, 2 ** 63), (n0, -2 ** 63 - 1), (n0, "1.5"), (n2, "18.505"), (n2, "18.500"),
                         (n0, "1e3"), (n0, ""), (n0, "+5"), (n0, "5."), (n0, ".5"), (n0, "1" * 41), (n0, True),
                         (n0, [1]), (n0, None), (n18, 10), (n2, 92233720368547759)):
            with self.subTest((e.scale, value)), self.assertRaises(VerifyError):
                ranges.bound_x(e, value)

    def test_money(self):
        hkd = ranges.Encoding("money", 2, "HKD")
        self.assertEqual(ranges.bound_x(hkd, [3_000_000, "HKD", 2]), 3_000_000)
        self.assertEqual(ranges.bound_x(hkd, [-5, "HKD", 2]), -5)
        for value in ([3_000_000, "USD", 2], [30_000, "HKD", 0], [1, "HKD"], [1, "hkd", 2], [2 ** 63, "HKD", 2],
                      "HKD 30,000.00", [True, "HKD", 2]):
            with self.subTest(value), self.assertRaises(VerifyError):
                ranges.bound_x(hkd, value)

    def test_dates(self):
        d = ranges.Encoding("date")
        epoch = datetime.date(1970, 1, 1).toordinal()
        for text in ("1970-01-01", "1969-12-31", "0001-01-01", "9999-12-31", "2000-02-29", "1900-03-01",
                     "2008-11-20", "1600-02-29"):
            y, m, day = (int(x) for x in text.split("-"))
            self.assertEqual(ranges.bound_x(d, text), datetime.date(y, m, day).toordinal() - epoch, text)
        self.assertEqual(ranges.bound_x(d, "0001-01-01"), -719_162)
        self.assertEqual(ranges.bound_x(d, "9999-12-31"), 2_932_896)
        # Every day of four centuries agrees with Python's calendar.
        start = datetime.date(1800, 1, 1)
        for n in range(0, 146_097, 7):
            day = start + datetime.timedelta(days=n)
            self.assertEqual(ranges.days_from_civil(day.year, day.month, day.day), day.toordinal() - epoch)
        for text in ("0000-12-31", "2026-02-29", "2026-13-01", "26-01-01", "2026-1-01", 20261120, "2026-04-31"):
            with self.subTest(text), self.assertRaises(VerifyError):
                ranges.bound_x(d, text)

    def test_commitment(self):
        salt = bytes(range(32))
        self.assertEqual(len(ranges.DOMAIN), 14)
        message = b"Kanhe range v1" + salt + (5 + 2 ** 63).to_bytes(8, "big")
        self.assertEqual(len(message), 54)
        self.assertEqual(ranges.commitment(salt, 5), hashlib.sha256(message).digest())
        self.assertEqual(ranges.commitment(salt, -2 ** 63), hashlib.sha256(message[:46] + bytes(8)).digest())
        with self.assertRaises(VerifyError):
            ranges.commitment(salt, 2 ** 63)

    def test_public_values(self):
        self.assertEqual(ranges.public_values(None, None), (0, 2 ** 64 - 1))
        self.assertEqual(ranges.public_values(-2 ** 63, 2 ** 63 - 1), (0, 2 ** 64 - 1))
        self.assertEqual(ranges.public_values(0, None), (2 ** 63, 2 ** 64 - 1))
        self.assertEqual(ranges.public_values(None, -1), (0, 2 ** 63 - 1))

    def test_transcript(self):
        ledger, record, c = bytes([1]) * 32, bytes([2]) * 32, bytes([3]) * 32
        expected = (bytes([0x88, 0x6D]) + b"kanhe.range/1" + bytes([0x58, 0x20]) + ledger + bytes([0x58, 0x20])
                    + record + bytes([0x63]) + b"age" + bytes([0x58, 0x20]) + c + bytes([0x00])
                    + bytes([0x1B]) + b"\xff" * 8 + bytes([0x40]))
        self.assertEqual(ranges.transcript(ledger, record, "age", c, 0, 2 ** 64 - 1, None), expected)
        with_context = ranges.transcript(ledger, record, "age", c, 2 ** 63, 2 ** 63 + 17, b"\xaa\xbb")
        self.assertTrue(with_context.endswith(bytes([0x1B, 0x80]) + bytes(7) + bytes([0x1B, 0x80]) + bytes(6)
                                              + bytes([0x11, 0x42, 0xAA, 0xBB])))
        self.assertEqual(cbor.decode(with_context), ["kanhe.range/1", ledger, record, "age", c, 2 ** 63, 2 ** 63 + 17,
                                                     b"\xaa\xbb"])

    def test_words(self):
        date, hkd, n1 = ranges.Encoding("date"), ranges.Encoding("money", 2, "HKD"), ranges.Encoding("number", 1)
        self.assertEqual(ranges.words("birth_date", date, None, "2008-11-20"), "birth_date is at most 2008-11-20")
        self.assertEqual(ranges.words("monthly_salary", hkd, [3_000_000, "HKD", 2], None),
                         "monthly_salary is at least HKD 30,000.00")
        self.assertEqual(ranges.words("score", n1, 60, "99.5"), "score is between 60 and 99.5")
        self.assertEqual(ranges.words("balance", hkd, [-25_000, "HKD", 2], [100_000_000, "HKD", 2]),
                         "balance is between HKD -250.00 and HKD 1,000,000.00")
        self.assertEqual(ranges.words("t", n1, "-20", "-10.0"), "t is between -20 and -10.0")


class Shapes(unittest.TestCase):
    def entry(self, name, encoding=("number", 0)):
        return [name, list(encoding), bytes(32)]

    def test_provable(self):
        parsed = ranges.parse_provable([self.entry("Z"), self.entry("a"), self.entry("é", ("date",))], 3)
        self.assertEqual([p.name for p in parsed], ["Z", "a", "é"])
        self.assertEqual(len(ranges.parse_provable([self.entry(f"f{i:02d}") for i in range(64)], 64)), 64)
        refused = [
            ([], 1), ([self.entry(f"f{i:02d}") for i in range(65)], 70), ([self.entry("a"), self.entry("b")], 1),
            (["age"], 1), ([["age", ["number", 0]]], 1), ([self.entry("")], 1), ([self.entry("n" * 65)], 1),
            ([[b"age", ["number", 0], bytes(32)]], 1), ([self.entry("b"), self.entry("a")], 2),
            ([self.entry("a"), self.entry("a")], 2), ([["a", ["number", 0], bytes(31)]], 1), ("a", 1),
        ]
        for value, count in refused:
            with self.subTest(value), self.assertRaises(VerifyError):
                ranges.parse_provable(value, count)

    def test_registration(self):
        """Key 8 in a registration's body, through the statement parser."""
        body = {1: "example.org.probe/1", 2: bytes(32), 3: 1, 8: [self.entry("age")]}
        fields = protocol._parse_body(protocol.RECORD_REGISTER, body)
        self.assertEqual([p.name for p in fields["provable"]], ["age"])
        with self.assertRaises(VerifyError):
            protocol._parse_body(protocol.RECORD_REGISTER, {**body, 8: [self.entry("a"), self.entry("b")]})
        self.assertEqual(protocol._parse_body(protocol.RECORD_REGISTER, {k: v for k, v in body.items() if k != 8})
                         ["provable"], [])

    def test_proofs(self):
        good = {1: "age", 2: 18, 4: 1, 5: b"\x01"}
        self.assertEqual(ranges.parse_proofs([good])[0].field, "age")
        self.assertEqual(ranges.parse_proofs([{**good, 3: 99, 6: bytes(64), 5: bytes(262_144)}])[0].high, 99)
        self.assertEqual(ranges.parse_proofs([{**good, 4: 7}])[0].system, 7)  # refused in step 13, not here
        refused = [
            [], [good] * 17, [[good]], [{k: v for k, v in good.items() if k != 1}],
            [{k: v for k, v in good.items() if k != 4}], [{k: v for k, v in good.items() if k != 5}],
            [{1: "age", 4: 1, 5: b"\x01"}], [{**good, 7: 1}], [{**good, 1: ""}], [{**good, 1: "n" * 65}],
            [{**good, 4: -1}], [{**good, 4: True}], [{**good, 5: b""}], [{**good, 5: bytes(262_145)}],
            [{**good, 6: b""}], [{**good, 6: bytes(65)}], [{**good, 2: None}], [{**good, "x": 1}],
        ]
        for value in refused:
            with self.subTest(str(value)[:80]), self.assertRaises(VerifyError):
                ranges.parse_proofs(value)
        bundle = {0: 1, 1: bytes(32), 2: [[b"\x00", b"\x00"]], 3: b"\x00", 12: [good]}
        self.assertEqual(len(protocol.parse_bundle(cbor.encode(bundle)).ranges), 1)
        with self.assertRaises(VerifyError):
            protocol.parse_bundle(cbor.encode({**bundle, 12: []}))

    def test_openings(self):
        ledger, record = bytes([1]) * 32, bytes([2]) * 32
        good = [["a", bytes(32), -2 ** 63], ["b", bytes([9]) * 32, 2 ** 63 - 1]]
        parsed = ranges.parse_openings(cbor.encode({1: ledger, 2: record, 3: good}))
        self.assertEqual((parsed.ledger, parsed.record, parsed.openings),
                         (ledger, record, [tuple(o) for o in good]))
        for value in ({1: ledger, 2: record, 3: [["a", bytes(16), 1]]}, {1: ledger, 2: record, 3: good[::-1]},
                      {1: ledger, 2: record, 3: [good[0], good[0]]},
                      {1: ledger, 2: record, 3: [["a", bytes(32), 2 ** 63]]}, {1: ledger, 2: record, 3: []},
                      {1: ledger, 2: record, 3: good, 4: True}, {1: ledger, 3: good},
                      {1: ledger[:31], 2: record, 3: good}, [ledger, record, good]):
            with self.subTest(str(value)[:60]), self.assertRaises(VerifyError):
                ranges.parse_openings(cbor.encode(value))
        with self.assertRaises(VerifyError):
            ranges.parse_openings(b"\x00" * 65_537)


class Plumbing(unittest.TestCase):
    """Bundles forged here with proofs a fake helper makes, verified through
    the command line with and without the helper."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.work = pathlib.Path(cls.tmp.name)
        cls.fake = write_helper(cls.work, "fake-range", FAKE_HELPER)
        cls.helper = ranges.Helper(cls.fake)
        cls.r = Provable({"birth_date": (["date"], ranges.bound_x(ranges.Encoding("date"), "1990-05-17")),
                          "monthly_salary": (["money", "HKD", 2], 3_500_000), "score": (["number", 1], 875)})
        cls.p_birth = cls.r.proof(cls.helper, "birth_date", high="2008-11-20")
        cls.context = bytes.fromhex("0a1b2c3d")
        cls.p_salary = cls.r.proof(cls.helper, "monthly_salary", low=[3_000_000, "HKD", 2], context=cls.context)
        cls.p_score = cls.r.proof(cls.helper, "score", low=60, high="99.5")

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def check(self, proofs, *options, verified=True):
        code, result, err = verify(self.work, self.r.bundle(proofs), *options)
        self.assertEqual(code, cli.EXIT_VERIFIED if verified else cli.EXIT_NOT_VERIFIED, (result, err))
        return result

    def test_verified(self):
        result = self.check([self.p_birth, self.p_salary, self.p_score], "--range-helper", self.fake)
        self.assertEqual(result["provable"], [
            {"field": "birth_date", "encoding": {"type": "date", "scale": None, "currency": None}},
            {"field": "monthly_salary", "encoding": {"type": "money", "scale": 2, "currency": "HKD"}},
            {"field": "score", "encoding": {"type": "number", "scale": 1, "currency": None}}])
        self.assertEqual(result["range_proofs"], [
            {"field": "birth_date", "low": None, "high": "2008-11-20", "text": "birth_date is at most 2008-11-20",
             "context": None, "system": 1, "status": "verified"},
            {"field": "monthly_salary", "low": [3_000_000, "HKD", 2], "high": None,
             "text": "monthly_salary is at least HKD 30,000.00", "context": "0a1b2c3d", "system": 1,
             "status": "verified"},
            {"field": "score", "low": 60, "high": "99.5", "text": "score is between 60 and 99.5", "context": None,
             "system": 1, "status": "verified"}])
        text = text_report(self.work, self.r.bundle([self.p_birth]), "--range-helper", self.fake)
        self.assertIn("Range proof  birth_date is at most 2008-11-20: verified (system 1, no context)", text)
        self.assertIn("Provable     birth_date (date), monthly_salary (money, HKD, scale 2), score (number, "
                      "scale 1)", text)

    def test_not_checked(self):
        result = self.check([self.p_birth, {**self.p_score, 5: b"not a proof"}])
        self.assertEqual([r["status"] for r in result["range_proofs"]], ["not-checked", "not-checked"])
        self.assertIn("NOT CHECKED", text_report(self.work, self.r.bundle([self.p_birth])))

    def test_no_proofs(self):
        result = self.check(None, "--range-helper", self.fake)
        self.assertEqual(len(result["provable"]), 3)
        self.assertEqual(result["range_proofs"], [])

    def test_refused(self):
        h = ("--range-helper", self.fake)
        flipped = bytearray(self.p_birth[5])
        flipped[3] ^= 1
        cases = {
            "tampered": [{**self.p_birth, 5: bytes(flipped)}],
            "other bounds": [{**self.p_birth, 3: "2008-11-21"}],
            "another field's proof": [{**self.p_birth, 1: "score", 3: "99.5"}],
            "another context": [{**self.p_salary, 6: b"\x00"}],
            "context dropped": [{k: v for k, v in self.p_salary.items() if k != 6}],
            "a field twice": [self.p_birth, self.p_birth],
            "not provable": [{**self.p_birth, 1: "note"}],
            "unknown system": [{**self.p_birth, 4: 2}],
            "system 0": [{**self.p_birth, 4: 0}],
            "low above high": [{**self.p_score, 2: "99.5", 3: 60}],
            "another currency": [{**self.p_salary, 2: [3_000_000, "USD", 2]}],
            "another scale": [{**self.p_salary, 2: [30_000, "HKD", 0]}],
            "too many decimals": [{**self.p_score, 2: "60.25"}],
            "out of range": [{**self.p_score, 3: 922337203685477581}],
            "a date before year one": [{**self.p_birth, 3: "0000-12-31"}],
            "a number for a date": [{**self.p_birth, 3: 20081120}],
        }
        for name, proofs in cases.items():
            with self.subTest(name):
                code, result, _ = verify(self.work, self.r.bundle(proofs), *h)
                self.assertEqual(code, cli.EXIT_NOT_VERIFIED, result)
                self.assertFalse(result["verified"])
        # Without the helper, only the arithmetic is not done: a tampered
        # proof is not checked, every other refusal stands.
        code, result, _ = verify(self.work, self.r.bundle(cases["tampered"]))
        self.assertEqual((code, result["range_proofs"][0]["status"]), (cli.EXIT_VERIFIED, "not-checked"))
        for name in ("a field twice", "not provable", "unknown system", "low above high", "another currency"):
            with self.subTest(f"{name}, without a helper"):
                self.assertEqual(verify(self.work, self.r.bundle(cases[name]))[0], cli.EXIT_NOT_VERIFIED)

    def test_required_context(self):
        ctx = ("--range-context", self.context.hex())
        self.check([self.p_salary], *ctx, "--range-helper", self.fake)
        self.check([self.p_salary], *ctx)  # not checked, and the context is the one required
        result = self.check([self.p_salary, self.p_birth], *ctx, verified=False)
        self.assertIn("carries no context", result["error"])
        self.assertEqual(len(result["range_proofs"]), 2)  # the full report, as for a minimum of witnesses
        result = self.check([self.p_salary], "--range-context", "0a1b2c3e", verified=False)
        self.assertIn("not the required", result["error"])
        self.check(None, *ctx)  # nothing to require it of
        for bad in ("", "0a1", "zz", "00" * 65, "0a 1b"):
            with self.subTest(bad):
                self.assertEqual(verify(self.work, self.r.bundle(None), "--range-context", bad)[0], cli.EXIT_USAGE)

    def test_helper_failures(self):
        evidence = self.r.bundle([self.p_birth])
        broken = write_helper(self.work, "broken-range", f"#!{sys.executable}\nimport sys\nsys.exit(2)\n")
        liar = write_helper(self.work, "liar-range",
                            f"#!{sys.executable}\nimport sys\nprint('{{\"valid\": false}}')\nsys.exit(0)\n")
        garbage = write_helper(self.work, "garbage-range", f"#!{sys.executable}\nprint('not json')\n")
        for program in (broken, liar, garbage, str(self.work / "no-such-helper")):
            with self.subTest(program):
                code, _, err = verify(self.work, evidence, "--range-helper", program)
                self.assertEqual(code, cli.EXIT_INPUT, err)
                self.assertIn("range helper", err)

    def test_mechanism_type(self):
        """Key 8 on a mechanism type is refused at replay (section 5)."""
        r = Provable({"note": (["number", 0], 1)}, kind="kanhe.access-receipt/1",
                     fields={"note": 1})
        code, result, _ = verify(self.work, r.bundle(None))
        self.assertEqual(code, cli.EXIT_NOT_VERIFIED)
        self.assertIn("mechanism type", result["error"])

    def test_replay(self):
        """A superseding registration carries its own provable values."""
        f = Forge()
        old = f.record("root", f.ledger_id, fields={"a": 1, "b": 2}, extra={8: [["a", ["number", 0], bytes(32)]]})
        new = f.record("root", f.ledger_id, fields={"a": 1, "b": 2},
                       extra={6: old, 8: [["b", ["date"], bytes([1]) * 32]]})
        entries = [protocol.parse_log_entry(e) for e in f.entries]
        ledger = rules.Ledger(entries[0], 0)
        for i, entry in enumerate(entries[1:], start=1):
            ledger.apply(entry, i)
        self.assertEqual([p.name for p in ledger.records[old].provable], ["a"])
        self.assertEqual([p.name for p in ledger.records[new].provable], ["b"])

    def test_nested(self):
        """A source proof or a membership proof carries no range proofs:
        refused before anything in it is checked."""
        from kanhe_verify import evidence
        inner = self.r.bundle([self.p_birth])
        for as_proof, as_source in ((True, False), (False, True)):
            with self.subTest(as_proof=as_proof), self.assertRaises(VerifyError) as caught:
                evidence._verify(inner, ledger_id=None, witnesses=[], tsa_roots_pem=b"", attachments={},
                                 network_witnesses=[], trust_nodes={}, as_proof=as_proof, as_source=as_source,
                                 range_helper=self.helper)
            self.assertIn("range proofs", str(caught.exception))


@unittest.skipUnless(VECTORS.exists(), "testvectors/protocol-v0.22.json is not there yet")
class ProtocolV22(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.d = json.loads(VECTORS.read_text())

    def test_system(self):
        s = self.d["system"]
        self.assertEqual((s["number"], s["commit"], s["circuit"], bytes.fromhex(s["circuit_id"])),
                         (ranges.LONGFELLOW, ranges.LIBRARY_COMMIT, ranges.CIRCUIT, ranges.CIRCUIT_ID))

    def test_provable(self):
        for case in self.d["provable"]["valid"]:
            with self.subTest(case["name"]):
                parsed = ranges.parse_provable(cbor.decode(hx(case["provable"])), case["field_count"])
                self.assertEqual([{"name": p.name, "encoding": {"type": p.encoding.type, "scale": p.encoding.scale,
                                                                "currency": p.encoding.currency},
                                   "commitment": p.commitment.hex()} for p in parsed], case["entries"])
        for case in self.d["provable"]["refused"]:
            with self.subTest(case["name"]), self.assertRaises(VerifyError):
                ranges.parse_provable(cbor.decode(hx(case["provable"])), case["field_count"])

    def test_values_and_bounds(self):
        for case in self.d["values"]:
            with self.subTest(case["value"]):
                x = ranges.bound_x(ranges.parse_encoding(case["encoding"]), case["value"])
                self.assertEqual((x, str(x + ranges.OFFSET)), (case["x"], case["v"]))
                self.assertEqual(ranges.commitment(hx(case["salt"]), x).hex(), case["commitment"])
        for case in self.d["bounds"]["refused"]:
            with self.subTest(case["name"], bound=case["bound"]), self.assertRaises(VerifyError):
                ranges.bound_x(ranges.parse_encoding(case["encoding"]), case["bound"])

    def test_words(self):
        for case in self.d["words"]:
            e = ranges.parse_encoding(case["encoding"])
            self.assertEqual(ranges.words(case["field"], e, case["low"], case["high"]), case["text"])

    def test_transcripts(self):
        for case in self.d["transcripts"]:
            e = ranges.parse_encoding(case["encoding"])
            if case["low_bound"] is not None or case["high_bound"] is not None:
                lo, hi = ranges.public_values(
                    ranges.bound_x(e, case["low_bound"]) if case["low_bound"] is not None else None,
                    ranges.bound_x(e, case["high_bound"]) if case["high_bound"] is not None else None)
                self.assertEqual((str(lo), str(hi)), (case["low"], case["high"]))
            t = ranges.transcript(hx(case["ledger"]), hx(case["record"]), case["field"], hx(case["commitment"]),
                                  int(case["low"]), int(case["high"]),
                                  hx(case["context"]) if case["context"] else None)
            self.assertEqual(t.hex(), case["transcript"])

    def test_openings(self):
        for case in self.d["openings"]["valid"]:
            parsed = ranges.parse_openings(hx(case["file"]))
            self.assertEqual((parsed.ledger.hex(), parsed.record.hex()), (case["ledger"], case["record"]))
            self.assertEqual([[n, s.hex(), x] for n, s, x in parsed.openings],
                             [[o["name"], o["salt"], o["x"]] for o in case["openings"]])
            for (_, s, x), o in zip(parsed.openings, case["openings"]):
                self.assertEqual(ranges.commitment(s, x).hex(), o["commitment"])
        for case in self.d["openings"]["refused"]:
            with self.subTest(case["name"]), self.assertRaises(VerifyError):
                ranges.parse_openings(hx(case["file"]))

    def test_ledger(self):
        lg = self.d["ledger"]
        entries = [protocol.parse_log_entry(hx(e)) for e in lg["log_entries"]]

        def replay(upto=None):
            ledger = rules.Ledger(entries[0], 0)
            for i, entry in enumerate(entries[1:upto], start=1):
                if entry.commitment is not None:
                    ledger.apply_commitment(entry, i)
                else:
                    ledger.apply(entry, i)
            return ledger
        ledger = replay()
        for r in lg["records"]:
            record = ledger.records[hx(r["id"])]
            self.assertEqual([{"name": p.name, "encoding": {"type": p.encoding.type, "scale": p.encoding.scale,
                                                            "currency": p.encoding.currency},
                               "commitment": p.commitment.hex()} for p in record.provable], r["provable"])
        for refused in lg["refused"]:
            with self.subTest(refused["name"]), self.assertRaises(VerifyError):
                signed = hx(refused["encoded"])
                if refused["malformed"]:
                    protocol.parse_statement(signed)
                else:
                    s = protocol.parse_statement(signed)
                    entry = protocol.LogEntry(encoded=b"", id=ledger.h(s.sign1.to_be_signed()),
                                              registered_at=refused["at"], statement=signed, commitment=None)
                    copy.deepcopy(replay(refused["after"])).apply(entry, refused["after"])

    def test_bundles(self):
        with tempfile.TemporaryDirectory() as tmp:
            work = pathlib.Path(tmp)
            for case in self.d["bundles"]:
                if not runnable(case):
                    continue
                with self.subTest(case["name"]):
                    code, result = run(case, work, RANGE_HELPER)
                    self.assertEqual(code == cli.EXIT_VERIFIED, case["verified"],
                                     f"{case['description']} ({result.get('error')})")
                    if case["verified"]:
                        self.assertEqual(mismatches(case["facts"], result), [])
                    else:
                        self.assertTrue(case["rule"])


if __name__ == "__main__":
    unittest.main()
