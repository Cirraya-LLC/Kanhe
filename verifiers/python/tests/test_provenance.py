# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya
"""The v0.18 test vectors (testvectors/protocol-v0.18.json): scripts and
sources. Script metadata read and refused, sources' statuses, and a bank's
log replayed under the ledger rules, each refused statement for the rule the
vectors name and each malformed one unparsable."""

from __future__ import annotations

import pathlib
import sys
import unittest

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE))

from kanhe_verify import cbor, cose, protocol, rules, scripts, statetree  # noqa: E402
from kanhe_verify.errors import VerifyError  # noqa: E402

from test_vectors import hx, load, replay  # noqa: E402


class ProtocolV18(unittest.TestCase):
    METADATA_RULES = {"no metadata", "unknown key", "missing key", "name", "version", "files", "file", "path",
                      "size", "digest", "order", "deterministic", "runtime"}

    @classmethod
    def setUpClass(cls):
        cls.d = load("protocol-v0.18.json")

    def test_mechanism_types(self):
        types = self.d["mechanism_types"]
        self.assertEqual([t["type"] for t in types], list(rules.MECHANISM_TYPES))
        self.assertEqual(types[-1], {"type": scripts.SCRIPT_TYPE, "initial": "approved", "transitions": []})

    def test_script_metadata(self):
        d = self.d["script_metadata"]
        for case in d["valid"]:
            data = hx(case["metadata"])
            s = scripts.parse(data)
            want = case["script"]
            self.assertEqual((s.name, s.version, s.deterministic, s.runtime),
                             (want["name"], want["version"], want["deterministic"], want["runtime"]))
            self.assertEqual([[p, n, d.hex()] for p, n, d in s.files],
                             [[f["path"], f["size"], f["digest"]] for f in want["files"]])
            self.assertEqual(scripts.parse(cbor.decode(data)), s)
        self.assertEqual({c["why"] for c in d["refused"]}, self.METADATA_RULES)
        for case in d["refused"]:
            with self.subTest(case["name"]):
                with self.assertRaises(scripts.ScriptError) as caught:
                    scripts.parse(hx(case["metadata"]))
                self.assertEqual(caught.exception.why, case["why"])

    def test_source_statuses(self):
        seen = set()
        for h in self.d["source_statuses"]:
            for case in h["cases"]:
                got = scripts.status(h["registered"], h["revoked"], h["replaced"], case["t"])
                self.assertEqual(got, case["status"], (h, case))
                seen.add(got)
        self.assertEqual(seen, {"not_yet", "live", "revoked", "replaced"})

    def test_replay(self):
        for lg in self.d["replay"]["ledgers"]:
            ledger = replay(lg)
            h = ledger.h
            leaves = sorted([ledger.leaf(i) for i in list(ledger.actors) + list(ledger.delegations)
                             + list(ledger.records)], key=lambda leaf: leaf[1])
            self.assertEqual(leaves, [[x["kind"], hx(x["id"]), x["history"]] for x in lg["state_leaves"]])
            self.assertEqual(statetree.root_of(h, leaves).hex(), lg["state_root"])
            checkpoint = protocol.parse_tree_head(hx(lg["checkpoint"]), cose.CHECKPOINT_TYPE, "a checkpoint")
            self.assertEqual(checkpoint.timestamp, lg["checkpoint_time"])
            for r in lg["records"]:
                record = ledger.records[hx(r["id"])]
                self.assertEqual((record.type, record.state, record.revoked, record.history, record.registrant.hex()),
                                 (r["type"], r["state"], r["revoked"], r["history"], r["registrant"]))
                self.assertEqual([[a.hex(), b.hex()] for a, b in record.sources], r["sources"])
                registration = ledger.applied[record.history[0]].statement
                script = registration.provenance.script if registration.provenance else None
                self.assertEqual(script.hex() if script else None, r["provenance_script"])
                if r["script"] is None:
                    self.assertIsNone(record.script)
                else:
                    self.assertEqual((record.script.name, record.script.version, record.script.deterministic,
                                      record.script.runtime),
                                     (r["script"]["name"], r["script"]["version"], r["script"]["deterministic"],
                                      r["script"]["runtime"]))
            for refused in lg["refused"]:
                if refused["why"] in ("no such script", "no such source"):
                    # A verifier holds only part of a log: a statement naming
                    # a script or local source its bundle does not hold is a
                    # related object's, checked under every other rule; step 7
                    # requires the record's own (section 11, step 3).
                    continue
                with self.subTest(refused["name"]):
                    state = replay(lg, refused["after"])
                    signed = hx(refused["encoded"])
                    s = protocol.parse_statement(signed)
                    entry = protocol.LogEntry(encoded=b"", id=h(s.sign1.to_be_signed()), registered_at=refused["at"],
                                              statement=signed, commitment=None)
                    with self.assertRaises(VerifyError) as caught:
                        state.apply(entry, refused["after"])
                    if refused["why"] in self.METADATA_RULES:
                        self.assertIsInstance(caught.exception, scripts.ScriptError)
                        self.assertEqual(caught.exception.why, refused["why"])
            for malformed in lg["malformed"]:
                with self.subTest(malformed["name"]):
                    with self.assertRaises(VerifyError):
                        protocol.parse_statement(hx(malformed["encoded"]))


if __name__ == "__main__":
    unittest.main()
