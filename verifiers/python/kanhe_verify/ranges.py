# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya
"""Range proofs (spec v0.22, sections 6, 11, and 11.3): a registration's
provable values (key 8 of record-register-body), and the range proofs a
record's bundle carries (key 12), each a zero-knowledge proof that one
provable value lies within bounds.

Everything but a proof's arithmetic is here: the shapes, the encodings and
the integers x they read, the bounds, the public values lo' and hi', the
transcript, and the words. The arithmetic of system 1 (Longfellow ZK with the
circuit kanhe-range-64/1) is handed to a helper program the verifier is
given (`--range-helper`): this verifier implements no proof system itself,
as it implements no signature. Without a helper, a proof of system 1 is
reported as not checked and relied on for nothing (step 13).

The helper's protocol: `PROGRAM verify` reads one JSON object on its
standard input, {"commitment": hex, "low": lo' in decimal, "high": hi' in
decimal, "transcript": hex, "proof": hex}, writes {"valid": true or false},
and exits 0 when the proof is valid, 1 when it is not, and 2 when its input
is wrong. `PROGRAM prove` reads {"salt": hex, "value": v in decimal, "low",
"high", "transcript", and optionally "seed": hex} and writes {"commitment":
hex, "proof": hex} (the test vectors' generator uses it, with fixed seeds).
"""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
from dataclasses import dataclass

from . import cbor, claims
from .errors import UsageError, VerifyError

DOMAIN = b"Kanhe range v1"  # the commitment's 14 bytes of domain
LABEL = "kanhe.range/1"  # the transcript's first element
OFFSET = 1 << 63  # v = x + 2^63
MIN_X, MAX_X = -(1 << 63), (1 << 63) - 1
MAX_U64 = (1 << 64) - 1
SALT_SIZE = 32
MAX_NAME = 64
MAX_PROVABLE = 64  # key 8
MAX_PROOFS = 16  # bundle key 12
MAX_PROOF_BYTES = 262_144
MAX_CONTEXT = 64
MAX_OPENINGS_FILE = 65_536
MAX_NUMBER_SCALE, MAX_MONEY_SCALE = 18, 4
MAX_DECIMAL_TEXT = 40

# System 1 (section 11.3).
LONGFELLOW = 1
SYSTEMS = (LONGFELLOW,)
LIBRARY_COMMIT = "1c0662989b919fe7b53a209a0a96f61f0e1b45c7"
CIRCUIT = "kanhe-range-64/1"
CIRCUIT_ID = bytes.fromhex("fc727b6726bd4bfe80b65d044cdb4d393fcc688b5aad0ab4ded3a9619459480a")

VERIFIED, NOT_CHECKED = "verified", "not-checked"
NUMBER, MONEY, DATE = "number", "money", "date"

_CURRENCY = re.compile(r"[A-Z]{3}")
_DECIMAL = re.compile(r"(-?)([0-9]+)(?:\.([0-9]+))?")
_DATE = re.compile(r"([0-9]{4})-([0-9]{2})-([0-9]{2})")
_WORDS_EN = {(True, False): "is at least {L}", (False, True): "is at most {H}", (True, True): "is between {L} and {H}"}
_ABSENT = object()


def fail(message: str):
    raise VerifyError(message)


def _int(v) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


def _name(v) -> bool:
    return isinstance(v, str) and 1 <= len(v.encode("utf-8")) <= MAX_NAME


# ---------------------------------------------------------------------------
# Provable values (section 6, record-register-body key 8)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Encoding:
    """How a provable value is read as an integer x: a number with a scale,
    money in a currency with a scale, or a date."""
    type: str
    scale: int | None = None
    currency: str | None = None


@dataclass(frozen=True)
class Provable:
    name: str
    encoding: Encoding
    commitment: bytes


def parse_encoding(value) -> Encoding:
    """["number", scale 0..18] / ["money", currency, scale 0..4] / ["date"]."""
    if not (isinstance(value, list) and value and isinstance(value[0], str)):
        fail("a provable value's encoding is not [type, ...]")
    kind = value[0]
    if kind == NUMBER:
        if len(value) == 2 and _int(value[1]) and 0 <= value[1] <= MAX_NUMBER_SCALE:
            return Encoding(NUMBER, scale=value[1])
        fail("a provable number's encoding is not [\"number\", scale of 0 to 18]")
    if kind == MONEY:
        if (len(value) == 3 and isinstance(value[1], str) and _CURRENCY.fullmatch(value[1])
                and _int(value[2]) and 0 <= value[2] <= MAX_MONEY_SCALE):
            return Encoding(MONEY, scale=value[2], currency=value[1])
        fail("a provable amount's encoding is not [\"money\", currency of three upper-case letters, scale of 0 to 4]")
    if kind == DATE:
        if len(value) == 1:
            return Encoding(DATE)
        fail("a provable date's encoding is not [\"date\"]")
    fail("a provable value's encoding is not number, money, or date")


def parse_provable(value, field_count: int) -> list:
    """Key 8 of a registration: 1 to 64 [name, encoding, commitment], names of
    1 to 64 bytes strictly ascending by their UTF-8, no more entries than the
    record's field count, each commitment 32 bytes (section 6)."""
    if not (isinstance(value, list) and value):
        fail("a registration's provable values (key 8) are not a non-empty list")
    if len(value) > MAX_PROVABLE:
        fail("a registration has more than 64 provable values")
    if len(value) > field_count:
        fail("a registration has more provable values than fields")
    out = []
    for item in value:
        if not (isinstance(item, list) and len(item) == 3):
            fail("a provable value is not [name, encoding, commitment]")
        name, encoding, commitment = item
        if not _name(name):
            fail("a provable value's name is not 1 to 64 bytes of text")
        if not (isinstance(commitment, bytes) and len(commitment) == 32):
            fail("a provable value's commitment is not 32 bytes")
        out.append(Provable(name=name, encoding=parse_encoding(encoding), commitment=commitment))
    names = [p.name.encode("utf-8") for p in out]
    if any(a >= b for a, b in zip(names, names[1:])):
        fail("a registration's provable values are not strictly ascending by name")
    return out


# ---------------------------------------------------------------------------
# Values and their integers x
# ---------------------------------------------------------------------------

def days_from_civil(year: int, month: int, day: int) -> int:
    """Days from 1970-01-01 in the proleptic Gregorian calendar (H. Hinnant's
    algorithm)."""
    y = year - (month <= 2)
    era = y // 400
    yoe = y - era * 400
    doy = (153 * (month + (-3 if month > 2 else 9)) + 2) // 5 + day - 1
    doe = yoe * 365 + yoe // 4 - yoe // 100 + doy
    return era * 146_097 + doe - 719_468


def _days_in_month(year: int, month: int) -> int:
    if month == 2:
        return 29 if year % 4 == 0 and (year % 100 != 0 or year % 400 == 0) else 28
    return 30 if month in (4, 6, 9, 11) else 31


def date_x(text, what: str = "a date") -> int:
    """A date YYYY-MM-DD, valid, from 0001-01-01 to 9999-12-31: its days
    from 1970-01-01."""
    m = _DATE.fullmatch(text) if isinstance(text, str) else None
    if m is None:
        fail(f"{what} is not a date (YYYY-MM-DD)")
    year, month, day = int(m.group(1)), int(m.group(2)), int(m.group(3))
    if not (1 <= month <= 12 and 1 <= day <= _days_in_month(year, month)):
        fail(f"{what} is not a valid date")
    if year < 1:
        fail(f"{what} is before 0001-01-01")
    return days_from_civil(year, month, day)


def _in_range(x: int, what: str) -> int:
    if not MIN_X <= x <= MAX_X:
        fail(f"{what} is out of range: its integer is not within -2^63 to 2^63 - 1")
    return x


def bound_x(encoding: Encoding, value, what: str = "a bound") -> int:
    """A bound written as a claim writes values (section 11.3), in the
    provable's encoding, as the integer x the encoding reads: a number times
    10^scale, with at most `scale` digits after the point; money in the
    provable's currency and scale, its amount; a date, its days."""
    if encoding.type == NUMBER:
        if _int(value):
            return _in_range(value * 10 ** encoding.scale, what)
        m = _DECIMAL.fullmatch(value) if isinstance(value, str) and len(value) <= MAX_DECIMAL_TEXT else None
        if m is None:
            fail(f"{what} is not a number (an integer, or a decimal text of at most 40 characters)")
        sign, whole, fraction = m.group(1), m.group(2), m.group(3) or ""
        if len(fraction) > encoding.scale:
            fail(f"{what} has more digits after the point than the provable's scale ({encoding.scale})")
        x = int(whole) * 10 ** encoding.scale + int(fraction.ljust(encoding.scale, "0") or "0")
        return _in_range(-x if sign else x, what)
    if encoding.type == MONEY:
        if not (isinstance(value, list) and len(value) == 3 and _int(value[0]) and isinstance(value[1], str)
                and _CURRENCY.fullmatch(value[1]) and _int(value[2]) and 0 <= value[2] <= MAX_MONEY_SCALE):
            fail(f"{what} is not money ([amount, currency, scale])")
        if value[1] != encoding.currency:
            fail(f"{what} is in {value[1]}, not the provable's currency ({encoding.currency})")
        if value[2] != encoding.scale:
            fail(f"{what} has the scale {value[2]}, not the provable's ({encoding.scale})")
        return _in_range(value[0], what)
    return date_x(value, what)


def commitment(salt: bytes, x: int) -> bytes:
    """C = SHA-256("Kanhe range v1" || s || BE64(x + 2^63)), on every ledger."""
    return hashlib.sha256(DOMAIN + salt + (_in_range(x, "a value") + OFFSET).to_bytes(8, "big")).digest()


def public_values(low_x: int | None, high_x: int | None) -> tuple:
    """(lo', hi'): x + 2^63 of each bound, 0 without a low, 2^64 - 1 without
    a high."""
    return (0 if low_x is None else low_x + OFFSET, MAX_U64 if high_x is None else high_x + OFFSET)


def transcript(ledger_id: bytes, record_id: bytes, field: str, commitment_: bytes, lo: int, hi: int,
               context: bytes | None) -> bytes:
    """T: the deterministic encoding of ["kanhe.range/1", ledger, record,
    field, C, lo', hi', context or empty], from which a proof's Fiat-Shamir
    transcript starts."""
    return cbor.encode([LABEL, ledger_id, record_id, field, commitment_, lo, hi, context or b""])


def value_words(encoding: Encoding, value) -> str:
    """A bound written as a claim writes a value (section 11)."""
    return claims.value_words(encoding.type, value)


def words(field: str, encoding: Encoding, low, high) -> str:
    """The statement in words: `F is at least L`, `F is at most H`, or `F is
    between L and H`; a bound absent is None."""
    template = _WORDS_EN[(low is not None, high is not None)]
    return f"{field} " + template.format(L=value_words(encoding, low) if low is not None else "",
                                         H=value_words(encoding, high) if high is not None else "")


# ---------------------------------------------------------------------------
# Range proofs (bundle key 12)
# ---------------------------------------------------------------------------

@dataclass
class RangeProof:
    """A range proof as the bundle carries it; its bounds are None when
    absent, and checked against the provable's encoding in step 13."""
    field: str
    low: object
    high: object
    system: int
    proof: bytes
    context: bytes | None


def parse_proofs(value) -> list:
    """Bundle key 12: 1 to 16 range-proof maps, {1: field, ? 2: low, ? 3:
    high, 4: system, 5: proof, ? 6: context}, with a low, a high, or both."""
    if not (isinstance(value, list) and value):
        fail("the list of range proofs (key 12) is not a non-empty list")
    if len(value) > MAX_PROOFS:
        fail("the bundle carries more than 16 range proofs")
    out = []
    for item in value:
        if not isinstance(item, dict) or not all(_int(k) for k in item):
            fail("a range proof is not a map with integer keys")
        keys = set(item)
        if not {1, 4, 5} <= keys:
            fail(f"a range proof lacks key {min({1, 4, 5} - keys)}")
        if keys - {1, 2, 3, 4, 5, 6}:
            fail(f"a range proof has an unknown key {min(keys - {1, 2, 3, 4, 5, 6})}")
        if not keys & {2, 3}:
            fail("a range proof has neither a low (key 2) nor a high (key 3)")
        if not _name(item[1]):
            fail("a range proof's field is not 1 to 64 bytes of text")
        if not (_int(item[4]) and item[4] >= 0):
            fail("a range proof's system is not an unsigned integer")
        if not (isinstance(item[5], bytes) and 1 <= len(item[5]) <= MAX_PROOF_BYTES):
            fail("a range proof's proof is not 1 to 262,144 bytes")
        if 6 in item and not (isinstance(item[6], bytes) and 1 <= len(item[6]) <= MAX_CONTEXT):
            fail("a range proof's context is not 1 to 64 bytes")
        for key in (2, 3):
            if key in item and item[key] is None:
                fail("a range proof's bound is null")
        out.append(RangeProof(field=item[1], low=item.get(2), high=item.get(3), system=item[4], proof=item[5],
                              context=item.get(6)))
    return out


@dataclass
class RangeReport:
    """A range proof as a report states it (section 11.3)."""
    field: str
    encoding: Encoding
    low: object  # as written, or None
    high: object
    low_x: int | None
    high_x: int | None
    lo: int  # lo'
    hi: int  # hi'
    text: str
    context: bytes | None
    system: int
    status: str  # VERIFIED or NOT_CHECKED


class HelperError(UsageError):
    """The range helper could not be run, or answered outside its protocol."""


class Helper:
    """A program that does a proof system's arithmetic (system 1), run once
    per proof with JSON on its standard input."""

    def __init__(self, program: str, timeout: float = 120.0):
        self.program, self.timeout = program, timeout

    def _run(self, command: str, request: dict) -> tuple[int, dict]:
        try:
            done = subprocess.run([self.program, command], input=json.dumps(request).encode(), capture_output=True,
                                  timeout=self.timeout)
        except (OSError, subprocess.SubprocessError) as e:
            raise HelperError(f"cannot run the range helper {self.program}: {e}") from e
        if done.returncode not in (0, 1):
            detail = done.stderr.decode("utf-8", "replace").strip()[:200]
            raise HelperError(f"the range helper {self.program} failed ({command}, exit {done.returncode})"
                              + (f": {detail}" if detail else ""))
        try:
            answer = json.loads(done.stdout.decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as e:
            raise HelperError(f"the range helper {self.program} did not answer JSON ({command})") from e
        if not isinstance(answer, dict):
            raise HelperError(f"the range helper {self.program} did not answer a JSON object ({command})")
        return done.returncode, answer

    def verify(self, commitment_: bytes, lo: int, hi: int, transcript_: bytes, proof: bytes) -> bool:
        code, answer = self._run("verify", {"commitment": commitment_.hex(), "low": str(lo), "high": str(hi),
                                            "transcript": transcript_.hex(), "proof": proof.hex()})
        valid = answer.get("valid")
        if not isinstance(valid, bool) or valid != (code == 0):
            raise HelperError(f"the range helper {self.program} answered {answer!r} with exit {code}")
        return valid

    def prove(self, salt: bytes, x: int, lo: int, hi: int, transcript_: bytes, seed: bytes | None = None) -> tuple:
        """(commitment, proof); used to make test vectors."""
        request = {"salt": salt.hex(), "value": str(x + OFFSET), "low": str(lo), "high": str(hi),
                   "transcript": transcript_.hex()}
        if seed is not None:
            request["seed"] = seed.hex()
        code, answer = self._run("prove", request)
        if code != 0:
            raise HelperError(f"the range helper {self.program} could not prove: {answer!r}")
        try:
            return bytes.fromhex(answer["commitment"]), bytes.fromhex(answer["proof"])
        except (KeyError, TypeError, ValueError) as e:
            raise HelperError(f"the range helper {self.program} answered {answer!r}") from e


def check(ledger_id: bytes, record, proofs: list, helper: Helper | None) -> list:
    """Section 11, step 13: each range proof of the bundle, in its order,
    against the provable values of the record's own registration. A proof
    that fails a check fails the evidence; without a helper, a proof of
    system 1 is not checked."""
    provable = {p.name: p for p in record.provable}
    out, seen = [], set()
    for n, p in enumerate(proofs, start=1):
        what = f"range proof {n}"
        if p.field in seen:
            fail(f"{what} is a second proof of the field {p.field!r}")
        seen.add(p.field)
        value = provable.get(p.field)
        if value is None:
            fail(f"{what} is of {p.field!r}, which is not a provable value of the record's registration")
        encoding = value.encoding
        low_x = bound_x(encoding, p.low, f"{what}'s low") if p.low is not None else None
        high_x = bound_x(encoding, p.high, f"{what}'s high") if p.high is not None else None
        if low_x is not None and high_x is not None and low_x > high_x:
            fail(f"{what}'s low is above its high")
        if p.system not in SYSTEMS:
            fail(f"{what} is of the proof system {p.system}, which is not defined (only system 1 is)")
        lo, hi = public_values(low_x, high_x)
        t = transcript(ledger_id, record.id, p.field, value.commitment, lo, hi, p.context)
        status = NOT_CHECKED
        if helper is not None:
            if not helper.verify(value.commitment, lo, hi, t, p.proof):
                fail(f"{what} ({words(p.field, encoding, p.low, p.high)}) does not verify")
            status = VERIFIED
        out.append(RangeReport(field=p.field, encoding=encoding, low=p.low, high=p.high, low_x=low_x, high_x=high_x,
                               lo=lo, hi=hi, text=words(p.field, encoding, p.low, p.high), context=p.context,
                               system=p.system, status=status))
    return out


# ---------------------------------------------------------------------------
# Range openings files (.kanheopenings)
# ---------------------------------------------------------------------------

@dataclass
class Openings:
    ledger: bytes
    record: bytes
    openings: list  # [(name, salt, x)], names ascending


def parse_openings(data: bytes) -> Openings:
    """A range openings file (section 6, range-openings in the CDDL): at most
    65,536 bytes, {1: ledger, 2: record, 3: [1*64 [name, salt (32 bytes),
    x]]}, names strictly ascending, each x within -2^63 to 2^63 - 1."""
    if len(data) > MAX_OPENINGS_FILE:
        fail("a range openings file is larger than 65,536 bytes")
    m = cbor.decode(data)
    if not (isinstance(m, dict) and set(m) == {1, 2, 3}):
        fail("a range openings file is not {1: ledger, 2: record, 3: openings}")
    for key, what in ((1, "ledger"), (2, "record")):
        if not (isinstance(m[key], bytes) and len(m[key]) == 32):
            fail(f"a range openings file's {what} is not a 32-byte id")
    items = m[3]
    if not (isinstance(items, list) and 1 <= len(items) <= MAX_PROVABLE):
        fail("a range openings file does not hold 1 to 64 openings")
    out = []
    for item in items:
        if not (isinstance(item, list) and len(item) == 3 and _name(item[0]) and isinstance(item[1], bytes)
                and len(item[1]) == SALT_SIZE and _int(item[2]) and MIN_X <= item[2] <= MAX_X):
            fail("a range opening is not [name, 32-byte salt, x within -2^63 to 2^63 - 1]")
        out.append((item[0], item[1], item[2]))
    names = [name.encode("utf-8") for name, _, _ in out]
    if any(a >= b for a, b in zip(names, names[1:])):
        fail("a range openings file's names are not strictly ascending")
    return Openings(ledger=m[1], record=m[2], openings=out)


__all__ = ["CIRCUIT", "CIRCUIT_ID", "Encoding", "Helper", "HelperError", "LONGFELLOW", "NOT_CHECKED", "Openings",
           "Provable", "RangeProof", "RangeReport", "VERIFIED", "bound_x", "check", "commitment", "date_x",
           "days_from_civil", "parse_encoding", "parse_openings", "parse_proofs", "parse_provable", "public_values",
           "transcript", "words"]
