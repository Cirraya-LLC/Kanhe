# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya
"""The v0.20 test vectors (testvectors/protocol-v0.20.json): approvals and
guardians. Approval rules and guardian settings read and refused, approvals
decoded and refused, and a log for each hash replayed under the ledger
rules: each statement's rules and approvals as the vectors state them, each
refused statement for the rule the vectors name, each malformed statement
and log entry unparsable."""

from __future__ import annotations

import pathlib
import sys
import unittest

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE))

from kanhe_verify import approvals, cbor, cose, protocol, rules, statetree  # noqa: E402
from kanhe_verify.errors import ApprovalError, VerifyError  # noqa: E402

from test_vectors import hx, load, replay  # noqa: E402


class ProtocolV20(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.d = load("protocol-v0.20.json")

    def assertWhy(self, why: str, fn, *args):
        with self.assertRaises(ApprovalError) as caught:
            fn(*args)
        self.assertEqual(caught.exception.why, why, str(caught.exception))

    def test_approval_rules(self):
        d = self.d["approval_rules"]
        for case in d["valid"]:
            r = protocol.parse_approval_rule(cbor.decode(hx(case["rule"])))
            self.assertEqual((r.k, [a.hex() for a in r.approvers], r.within, r.without_presence),
                             (case["k"], case["approvers"], case["within_ms"], case["without_presence"]))
        for case in d["refused"]:
            with self.subTest(case["name"]):
                self.assertWhy(case["why"], protocol.parse_approval_rule, cbor.decode(hx(case["rule"])))

    def test_guardian_bodies(self):
        d = self.d["guardian_bodies"]
        for case in d["valid"]:
            body = protocol.parse_guardians_body(cbor.decode(hx(case["body"])))
            approvals.check_guardians_body(body)
            self.assertEqual(body.rule is None, case["removes"])
            self.assertEqual(list(body.types) if body.types is not None else None, case["types"])
        for case in d["refused"]:
            with self.subTest(case["name"]):
                value = cbor.decode(hx(case["body"]))
                if case["shape"]:
                    self.assertWhy(case["why"], protocol.parse_guardians_body, value)
                else:
                    body = protocol.parse_guardians_body(value)
                    self.assertWhy(case["why"], approvals.check_guardians_body, body)

    def test_approval_objects(self):
        d = self.d["approval_objects"]
        a = approvals.parse(hx(d["valid"]["encoded"]))
        self.assertEqual(cbor.encode(a.payload).hex(), d["valid"]["payload"])
        for case in d["refused"]:
            with self.subTest(case["name"]):
                self.assertWhy(case["why"], approvals.parse, hx(case["encoded"]))

    def test_replay(self):
        for lg in self.d["ledgers"]:
            with self.subTest(hash=lg["hash"]):
                self._replay(lg)

    def _replay(self, lg: dict):
        ledger = replay(lg)
        h = ledger.h
        leaves = sorted([ledger.leaf(i) for i in list(ledger.actors) + list(ledger.delegations)
                         + list(ledger.records)], key=lambda leaf: leaf[1])
        self.assertEqual(leaves, [[x["kind"], hx(x["id"]), x["history"]] for x in lg["state_leaves"]])
        self.assertEqual(statetree.root_of(h, leaves).hex(), lg["state_root"])
        checkpoint = protocol.parse_tree_head(hx(lg["checkpoint"]), cose.CHECKPOINT_TYPE, "a checkpoint")
        self.assertEqual(checkpoint.timestamp, lg["checkpoint_time"])
        self.assertEqual(checkpoint.tree_size, len(lg["log_entries"]))
        ledger.check_signed_head(checkpoint, ledger.log_key_for_size(checkpoint.tree_size), "the checkpoint")
        # Every statement: its rules, in section 5.1's order, and its approvals.
        for st in lg["statements"]:
            applied = ledger.applied[st["index"]]
            self.assertEqual(applied.id.hex(), st["statement_id"])
            got = [{"source": r.source, "delegation": r.delegation.hex() if r.delegation else None, "k": r.rule.k,
                    "approvers": [a.hex() for a in r.rule.approvers], "within_ms": r.rule.within,
                    "without_presence": r.rule.without_presence, "signer_counted": r.signer_counted,
                    "count": r.count} for r in applied.rules]
            self.assertEqual(got, st["rules"], st["name"])
            self.assertEqual([x.approval.encoded.hex() for x in applied.approvals],
                             [a["encoded"] for a in st["approvals"]], st["name"])
            for x, want in zip(applied.approvals, st["approvals"]):
                self.assertEqual(x.approval.approver.hex(), want["approver"])
                self.assertEqual(x.counted_for, want["counted_for"], st["name"])
                self.assertEqual(x.presence.method if x.presence else None, want["presence"])
                if want["challenge"] is not None:
                    self.assertEqual(approvals.challenge(h, x.approval).hex(), want["challenge"])
        # The guardian settings, and the guardians in effect at the end.
        self.assertEqual([s.index for s in ledger.guardian_settings], [s["index"] for s in lg["guardian_settings"]])
        for s, want in zip(ledger.guardian_settings, lg["guardian_settings"]):
            rule = s.body.rule
            self.assertEqual(rule is None, want["removes"])
            if rule is not None:
                self.assertEqual((rule.k, [a.hex() for a in rule.approvers], rule.within),
                                 (want["k"], want["guardians"], want["within_ms"]))
            self.assertEqual(list(s.body.types) if s.body.types else None, want["types"])
        self.assertIsNone(ledger.guardians_in_effect() if lg["guardians_in_effect"] is None else None)
        reasons = set()
        for refused in lg["refused"]:
            with self.subTest(refused["name"]):
                state = replay(lg, refused["after"])
                entry = protocol.parse_log_entry(hx(refused["entry"]))
                self.assertEqual(entry.registered_at, refused["at"])
                self.assertWhy(refused["why"], state.apply, entry, refused["after"])
                reasons.add(refused["why"])
        self.assertGreaterEqual(len(reasons), 20)
        for malformed in lg["malformed"]:
            with self.subTest(malformed["name"]):
                with self.assertRaises(VerifyError) as caught:
                    protocol.parse_statement(hx(malformed["encoded"]))
                if isinstance(caught.exception, ApprovalError):
                    self.assertEqual(caught.exception.why, malformed["why"])
        for malformed in lg["malformed_entries"]:
            with self.subTest(malformed["name"]):
                with self.assertRaises(VerifyError):
                    protocol.parse_log_entry(hx(malformed["entry"]))
        with self.assertRaises(VerifyError):
            rules.Ledger(protocol.parse_log_entry(hx(lg["genesis_with_approvals"])), 0)


if __name__ == "__main__":
    unittest.main()
