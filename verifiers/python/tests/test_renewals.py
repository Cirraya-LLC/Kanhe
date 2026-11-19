# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya
"""The v0.21 test vectors (testvectors/protocol-v0.21.json): long-term
evidence. Salts of 16 or 32 bytes read and others refused; renewals parsed
and refused; the distrust option read and refused; the archive ledger's
renewal parts (consistency proof and rotations) checked against its
checkpoints; and every bundle verified as the command line verifies it,
with its options, reaching its verdict and, when verified, its facts:
renewals, the long-term status, and distrusted signatures with what covers
each."""

from __future__ import annotations

import calendar
import datetime
import hashlib
import pathlib
import subprocess
import sys
import tempfile
import unittest

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE))

from kanhe_verify import cbor, cli, cose, crypto, longterm, merkle, protocol, report, timestamps  # noqa: E402
from kanhe_verify.errors import UsageError, VerifyError  # noqa: E402

from test_conformance import mismatches, run  # noqa: E402
from test_vectors import hx, load  # noqa: E402


def _bundle_with(key: int, value) -> bytes:
    """A bundle that parse_bundle reads up to `key` (its entries are only
    shaped, not checked, when parsed)."""
    return cbor.encode({0: 1, 1: bytes(32), 2: [[b"\x00", b"\x00"]], 3: b"\x00", key: value})


class ProtocolV21(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.d = load("protocol-v0.21.json")

    def test_field_salts(self):
        d = self.d["salts"]["field_leaves"]
        for case in d["valid"]:
            name, salt, value = protocol.parse_field_leaf(hx(case["leaf"]))
            self.assertEqual(len(salt), case["salt_size"])
        for case in d["refused"]:
            with self.subTest(case["name"]), self.assertRaises(VerifyError):
                protocol.parse_field_leaf(hx(case["leaf"]))

    def test_attachment_salts(self):
        d = self.d["salts"]["attachment_openings"]
        for case in d["valid"]:
            bundle = protocol.parse_bundle(_bundle_with(6, [cbor.decode(hx(case["opening"]))]))
            self.assertEqual(len(bundle.openings[0][1]), case["salt_size"])
        for case in d["refused"]:
            with self.subTest(case["name"]), self.assertRaises(VerifyError):
                protocol.parse_bundle(_bundle_with(6, [cbor.decode(hx(case["opening"]))]))

    def test_renewal_shapes(self):
        d = self.d["renewals"]
        for case in d["valid"]:
            with self.subTest(case["name"]):
                protocol.parse_renewal(cbor.decode(hx(case["renewal"])))
        for case in d["refused"]:
            with self.subTest(case["name"]), self.assertRaises(VerifyError):
                protocol.parse_renewal(cbor.decode(hx(case["renewal"])))
        for case in d["bundle_lists_refused"]:
            with self.subTest(case["name"]), self.assertRaises(VerifyError):
                protocol.parse_bundle(_bundle_with(11, cbor.decode(hx(case["renewals"]))))

    def test_distrust_options(self):
        d = self.d["distrust_options"]
        for case in d["valid"]:
            parsed = longterm.parse_distrust(case["options"])
            self.assertEqual([{"algorithm": a, "after": report.iso_time(ms)} for a, ms in parsed.items()],
                             case["algorithms"])
        for case in d["refused"]:
            with self.subTest(case["name"]), self.assertRaises(UsageError):
                longterm.parse_distrust(case["options"])
        # Times are Unix times: a date before 1970 is refused, as the C++
        # verifier refuses it.
        with self.assertRaises(UsageError):
            longterm.parse_distrust(["ed25519@1969-12-31"])
        self.assertEqual(longterm.parse_distrust(["ed25519@1970-01-01"]), {"ed25519": 0})

    def test_ledger(self):
        """The renewal a server answers from the bundle's size: its
        consistency proof leads from the first checkpoint to the second, and
        each rotation is in the second's tree, at its index."""
        lg = self.d["ledger"]
        h = crypto.hash_function(lg["hash"])
        entries = [hx(e) for e in lg["entries"]]
        first, second = (protocol.parse_tree_head(hx(c), cose.CHECKPOINT_TYPE, "a checkpoint")
                         for c in lg["checkpoints"])
        self.assertEqual((first.tree_size, second.tree_size), (lg["renewal_from"], lg["renewal_size"]))
        self.assertEqual(first.root, merkle.tree_hash(h, entries[:first.tree_size]))
        self.assertEqual(second.root, merkle.tree_hash(h, entries[:second.tree_size]))
        self.assertTrue(merkle.verify_consistency(h, first.tree_size, second.tree_size, first.root, second.root,
                                                  [hx(x) for x in lg["consistency"]]))
        self.assertEqual([r[0] for r in lg["rotation_proofs"]], lg["rotations"])
        for index, entry, path in lg["rotation_proofs"]:
            self.assertEqual(hx(entry), entries[index])
            self.assertTrue(merkle.verify_inclusion(h, index, second.tree_size, merkle.leaf_hash(h, hx(entry)),
                                                    [hx(p) for p in path], second.root))
        self.assertNotEqual(first.sign1.alg, second.sign1.alg)  # Ed25519, then ML-DSA-65

    def test_bundles(self):
        with tempfile.TemporaryDirectory() as tmp:
            work = pathlib.Path(tmp)
            for case in self.d["bundles"]:
                with self.subTest(case["name"]):
                    code, result = run({**case, "kind": "record"}, work)
                    self.assertEqual(code == cli.EXIT_VERIFIED, case["verified"],
                                     f"{case['description']} ({result.get('error')})")
                    if case["verified"]:
                        self.assertEqual(mismatches(case["facts"], result), [])
                    else:
                        self.assertTrue(case["rule"])


def _der(tag: int, content: bytes) -> bytes:
    n = len(content)
    length = bytes([n]) if n < 128 else bytes([0x81, n]) if n < 256 else bytes([0x82, n >> 8, n & 0xFF])
    return bytes([tag]) + length + content


class Sm2Authority(unittest.TestCase):
    """A time-stamp authority whose keys are SM2 (sections 10.1 and 11.1):
    `cryptography` loads no SM2 key and OpenSSL's PKCS #7 code verifies no SM2
    signature, so its token is read here and checked through CMS. Its
    authority is the SHA-256 of its key's bytes, its algorithms are sm2 and
    sm2, and it is trusted under its root."""

    def test_sm2_token(self):
        openssl = crypto.openssl_binary()
        with tempfile.TemporaryDirectory() as tmp:
            d = pathlib.Path(tmp)

            def run(*args) -> subprocess.CompletedProcess:
                return subprocess.run([openssl, *args], cwd=d, capture_output=True)

            if run("genpkey", "-algorithm", "SM2", "-out", "root.key").returncode != 0:
                self.skipTest("this OpenSSL makes no SM2 keys")
            (d / "ext.cnf").write_text("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n"
                                       "extendedKeyUsage=critical,timeStamping\n")
            for args in (("req", "-x509", "-new", "-key", "root.key", "-subj", "/CN=SM2 Test Root", "-days", "3650",
                          "-sm3", "-addext", "basicConstraints=critical,CA:TRUE", "-addext",
                          "keyUsage=critical,keyCertSign,cRLSign", "-out", "root.pem"),
                         ("genpkey", "-algorithm", "SM2", "-out", "tsa.key"),
                         ("req", "-new", "-key", "tsa.key", "-subj", "/CN=SM2 Test TSA", "-sm3", "-out", "tsa.csr"),
                         ("x509", "-req", "-in", "tsa.csr", "-CA", "root.pem", "-CAkey", "root.key", "-sm3",
                          "-set_serial", "2", "-days", "3650", "-extfile", "ext.cnf", "-out", "tsa.pem")):
                self.assertEqual(run(*args).returncode, 0, args)
            # A TSTInfo a minute from now, inside the certificates' validity.
            imprint = hashlib.sha256(b"a checkpoint's payload").digest()
            at = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=1)
            tstinfo = _der(0x30, _der(0x02, b"\x01") + _der(0x06, bytes.fromhex("2a03040501"))
                           + _der(0x30, _der(0x30, _der(0x06, timestamps.IMPRINT_OIDS[crypto.SHA256]))
                                  + _der(0x04, imprint))
                           + _der(0x02, b"\x01") + _der(0x18, at.strftime("%Y%m%d%H%M%SZ").encode())
                           + _der(0x30, _der(0x02, b"\x01")))
            (d / "tstinfo.der").write_bytes(tstinfo)
            signed = run("cms", "-sign", "-binary", "-nodetach", "-in", "tstinfo.der", "-signer", "tsa.pem", "-inkey",
                         "tsa.key", "-certfile", "root.pem", "-econtent_type", "1.2.840.113549.1.9.16.1.4", "-cades",
                         "-md", "sm3", "-outform", "DER", "-out", "token.der")
            if signed.returncode != 0:
                self.skipTest("this OpenSSL signs no SM2 CMS")
            token = (d / "token.der").read_bytes()
            spki = run("x509", "-in", "tsa.pem", "-pubkey", "-noout")
            der = subprocess.run([openssl, "pkey", "-pubin", "-outform", "DER"], input=spki.stdout,
                                 capture_output=True).stdout
            roots = (d / "root.pem").read_bytes()

            info = timestamps.check_token(token, imprint, crypto.SHA256, b"")
            self.assertEqual(info.algorithms, ("sm2", "sm2"))
            self.assertEqual(info.authority, "CN=SM2 Test TSA")
            self.assertEqual(info.authority_id, hashlib.sha256(der).digest())
            self.assertEqual(info.time_ms, calendar.timegm(at.timetuple()) * 1000)
            self.assertFalse(info.trusted)
            self.assertTrue(timestamps.check_token(token, imprint, crypto.SHA256, roots).trusted)
            with self.assertRaises(VerifyError):
                timestamps.check_token(token, hashlib.sha256(b"another").digest(), crypto.SHA256, roots)
            broken = bytearray(token)
            broken[-1] ^= 1  # the signature's last byte
            with self.assertRaises(VerifyError):
                timestamps.check_token(bytes(broken), imprint, crypto.SHA256, roots)


if __name__ == "__main__":
    unittest.main()
