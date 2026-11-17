# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya
"""The credential test vectors (testvectors/credentials-v1.json), against
kanhe_verify/credentials.py: JCS, thumbprints, base URLs, roles, credentials,
DID documents, and status lists, each reproduced or refused as the vectors
say; and what comes from outside (credentials, status lists, DID documents)
read within the bounds both verifiers keep, refused without a crash."""

from __future__ import annotations

import base64
import hashlib
import json
import pathlib
import sys
import unittest

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

from kanhe_verify import credentials, crypto  # noqa: E402
from kanhe_verify.errors import VerifyError  # noqa: E402

VECTORS = json.loads((HERE.parents[2] / "testvectors" / "credentials-v1.json").read_text())


def key(hex_point: str) -> crypto.PublicKey:
    return crypto.PublicKey(crypto.ESP256, bytes.fromhex(hex_point))


def did_document(base: str, keys: list, ledger: str) -> str:
    """Section 3, from the text."""
    b = credentials.base_url(base)
    methods = {}
    for k in keys:
        methods[credentials.thumbprint(k)] = k
    order = sorted(methods)
    return credentials.jcs({
        "@context": ["https://www.w3.org/ns/did/v1", "https://www.w3.org/ns/cid/v1"],
        "id": b.did,
        "verificationMethod": [{"id": b.did + "#" + t, "type": "JsonWebKey", "controller": b.did,
                                "publicKeyJwk": {**credentials.jwk(methods[t]), "alg": "ES256"}} for t in order],
        "assertionMethod": [b.did + "#" + t for t in order],
        "service": [{"id": b.did + "#kanhe", "type": "KanheLedger", "serviceEndpoint": b.url, "ledger": ledger}],
    })


class CredentialVectors(unittest.TestCase):
    def test_jcs(self):
        for case in VECTORS["jcs"]:
            self.assertEqual(credentials.jcs(case["value"]), case["jcs"])
            self.assertEqual(credentials.parse_jcs(case["jcs"]), case["value"])
        for text in VECTORS["jcs_refused"]:
            with self.subTest(text=text), self.assertRaises(VerifyError):
                credentials.parse_jcs(text)

    def test_thumbprints(self):
        for t in VECTORS["thumbprints"]:
            self.assertEqual(credentials.thumbprint(key(t["key"])), t["thumbprint"])
            self.assertEqual(credentials.jwk(key(t["key"])), t["jwk"])
            self.assertEqual(credentials.jwk_key(t["jwk"]), key(t["key"]))

    def test_base_urls(self):
        for b in VECTORS["base_urls"]:
            base = credentials.base_url(b["url"])
            self.assertEqual((base.url, base.did, base.did_document), (b["base"], b["did"], b["did_document"]))
        for url in VECTORS["base_urls_refused"]:
            with self.subTest(url=url), self.assertRaises(VerifyError):
                credentials.base_url(url)

    def test_roles(self):
        for r in VECTORS["roles"]:
            self.assertEqual(credentials.role_entry(r["role"]), (r["list"], r["index"]))
        for role in VECTORS["roles_refused"]:
            self.assertIsNone(credentials.role_entry(role), role)

    def test_credentials(self):
        for c in VECTORS["credentials"]:
            with self.subTest(c["description"]):
                parsed = credentials.parse_credential(c["jws"])
                self.assertEqual(credentials.jcs(parsed.jws.header), c["header"])
                self.assertEqual(credentials.jcs(parsed.jws.payload), c["payload"])
                self.assertTrue(crypto.verify_signature(key(c["key"]), parsed.jws.signing_input,
                                                        parsed.jws.signature))
                self.assertEqual(parsed.thumbprint, credentials.thumbprint(key(c["key"])))
                content = c["content"]
                self.assertEqual(parsed.subject, {name: value for name, value in content["subject"]})
                self.assertEqual((parsed.list, parsed.index), (content["list"], content["index"]))
                self.assertEqual(parsed.record.hex(), content["record"])

    def test_did_documents(self):
        for d in VECTORS["did_documents"]:
            with self.subTest(d["description"]):
                self.assertEqual(did_document(d["base"], [key(k) for k in d["keys"]], d["ledger"]), d["document"])

    def test_status_lists(self):
        for s in VECTORS["status_lists"]:
            with self.subTest(s["description"]):
                bits = credentials.decode_list(s["encoded"])
                self.assertEqual(hashlib.sha256(bits).hexdigest(), s["sha256"])
                for i in s["set"]:
                    self.assertTrue(credentials.bit(bits, i))
        for s in VECTORS["status_lists_refused"]:
            with self.subTest(s["why"]), self.assertRaises(VerifyError):
                credentials.decode_list(s["encoded"])

    def test_read_and_refused(self):
        """Section 7: what a verifier reads, and what it refuses."""
        for c in VECTORS["credentials_read"]:
            with self.subTest(c["why"]):
                credentials.parse_credential(c["jws"])
        for c in VECTORS["credentials_refused"]:
            with self.subTest(c["why"]), self.assertRaises(VerifyError):
                credentials.parse_credential(c["jws"])
        for d in VECTORS["did_documents_read"]:
            with self.subTest(d["why"]):
                credentials.parse_did_document(d["document"])
        for d in VECTORS["did_documents_refused"]:
            with self.subTest(d["why"]), self.assertRaises(VerifyError):
                credentials.parse_did_document(d["document"])


def nested(arrays: int, inner: str = "") -> str:
    """`arrays` arrays, one in the other, around `inner`."""
    return "[" * arrays + inner + "]" * arrays


def with_payload(jws: str, change) -> str:
    """A compact JWS with its payload changed by `change` (in place), still
    JCS, and its signature kept: parsing does not check it."""
    header, payload, signature = jws.split(".")
    value = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    change(value)
    return header + "." + credentials.b64(credentials.jcs(value).encode()) + "." + signature


class UntrustedInput(unittest.TestCase):
    """Input from outside, read as section 7 says: strict I-JSON (RFC 7493),
    no deeper than 64 (the top at 0), a compact JWS of at most 1 MiB once the
    line ends after it are off, a DID document of at most 256 KiB whose
    verification methods' ids are distinct and its services', decimals of at
    most 20 digits. Whatever arrives is read or refused (VerifyError), never a
    crash."""

    JWS = VECTORS["credentials"][0]["jws"]

    @staticmethod
    def why(text: str) -> str:
        try:
            credentials.parse_i_json(text)
        except VerifyError as e:
            return str(e)
        return "read"

    def test_jcs_nesting(self):
        credentials.parse_jcs(nested(65))  # the innermost array at depth 64
        credentials.parse_jcs(nested(64, "0"))
        for text in (nested(66), nested(65, "0"), nested(5000), nested(100_000)):
            with self.subTest(arrays=text.count("[")), self.assertRaises(VerifyError) as e:
                credentials.parse_jcs(text)
            self.assertEqual(str(e.exception), "JSON nested too deeply")
        deep = []
        for _ in range(5000):
            deep = [deep]
        with self.assertRaises(VerifyError):
            credentials.jcs(deep)

    def test_strict_i_json(self):
        why = self.why
        self.assertEqual(why(nested(66)), "JSON nested too deeply")
        self.assertEqual(why("\ufeff{}"), "JSON text that begins with a byte order mark")
        self.assertEqual(why('{"a":1,"a":2}'), "a JSON object names a member twice")
        self.assertEqual(why('["\uffff"]'), "JSON text with a noncharacter, which I-JSON excludes")
        self.assertEqual(why('["\\ufdd0"]'), "JSON text with a noncharacter, which I-JSON excludes")
        self.assertEqual(why('{"\U0010fffe":1}'), "JSON text with a noncharacter, which I-JSON excludes")
        self.assertEqual(why('["\\udbff\\udfff"]'), "JSON text with a noncharacter, which I-JSON excludes")
        for text in ("{}\x00x", "[1e400]", "[-1e400]", "[1" + "0" * 309 + "]", "[NaN]", "[Infinity]", "[-Infinity]",
                     '["\\ud800"]', '["\\udc00"]', '["\\ud800\\u0041"]', '{"\\ud800":1}',
                     '{"a":"\\ud800","a":1}',  # before the name given twice
                     '{"a":["\\udc00"],"a":1}'):
            with self.subTest(text=text[:24]):
                self.assertEqual(why(text), "not JSON")
        for text in ('["\ufffd"]', '["\\ud83d\\ude00"]', "[1e-400]", "[1.7976931348623157e308]",
                     "[18446744073709551616]", "[" + "9" * 20 + "]", '["\\\\ud800"]'):
            with self.subTest(text=text[:24]):
                self.assertEqual(why(text), "read")
        # JCS is strict I-JSON too, and the writer makes only I-JSON.
        for text in ('{"\\ud800":1}', '{"a":"\\udc00"}', '["\\ud800"]', '{"a":"\uffff"}', "\ufeff{}"):
            with self.subTest(text=text), self.assertRaises(VerifyError):
                credentials.parse_jcs(text)
        for value in ({"\ud800": 1}, ["\udfff"], "\ufdd0", {"\U0001ffff": 1}):
            with self.subTest(value=ascii(value)), self.assertRaises(VerifyError):
                credentials.jcs(value)

    def test_jcs_not_json(self):
        for text in ("[NaN]", "[Infinity]", "[-Infinity]", '{"a":NaN}', "[1" + "0" * 5000 + "]"):
            with self.subTest(text=text[:20]), self.assertRaises(VerifyError):
                credentials.parse_jcs(text)

    def test_jws_text_around_it(self):
        for text in (self.JWS + "\n", self.JWS + "\r\n", self.JWS + "\n\n"):
            self.assertEqual(credentials.parse_jws(text).kid, credentials.parse_jws(self.JWS).kid)
        for text in (" " + self.JWS, "\n" + self.JWS, self.JWS + " ", self.JWS + "\t", self.JWS + " \n",
                     self.JWS + "\x0b", "\ufeff" + self.JWS):
            with self.subTest(text=ascii(text[:3] + text[-3:])), self.assertRaises(VerifyError):
                credentials.parse_jws(text)

    def test_jws_size(self):
        header = credentials.b64(b'{"alg":"ES256","kid":"k"}')
        signature = credentials.b64(bytes(64))

        def jws_of(fill: int) -> str:
            return header + "." + credentials.b64(b'{"x":"' + b"a" * fill + b'"}') + "." + signature

        fill = (credentials.MAX_COMPACT - len(header) - 88) * 3 // 4 - 8
        while len(jws_of(fill + 1)) <= credentials.MAX_COMPACT:
            fill += 1
        while len(jws_of(fill)) > credentials.MAX_COMPACT:
            fill -= 1
        credentials.parse_jws(jws_of(fill))
        credentials.parse_jws(jws_of(fill) + "\r\n\n")  # line ends after it are not counted
        with self.assertRaises(VerifyError) as e:
            credentials.parse_jws(jws_of(fill + 1))
        self.assertEqual(str(e.exception), "a credential larger than 1 MiB")

    def test_decimals(self):
        def index(text):
            def change(p):
                status = p["credentialStatus"]
                status["statusListIndex"] = text
                status["id"] = status["statusListCredential"] + "#" + text
            return with_payload(self.JWS, change)

        def status_list(n):
            def change(p):
                status = p["credentialStatus"]
                status["statusListCredential"] = status["statusListCredential"].rsplit("/", 1)[0] + "/" + n
                status["id"] = status["statusListCredential"] + "#" + status["statusListIndex"]
            return with_payload(self.JWS, change)

        self.assertEqual(credentials.parse_credential(index("131071")).index, 131071)
        for text in ("131072", "01", "-1", "1" * 21, "1" * 5000):
            with self.subTest(index=text[:24]), self.assertRaises(VerifyError):
                credentials.parse_credential(index(text))
        self.assertEqual(credentials.parse_credential(status_list(str(2**64 - 2))).list, 2**64 - 2)
        for n in ("0", "01", str(2**64 - 1), "1" * 5000):
            with self.subTest(list=n[:24]), self.assertRaises(VerifyError):
                credentials.parse_credential(status_list(n))
        self.assertEqual(credentials.base_url("https://example.com:65535").did, "did:web:example.com%3A65535")
        with self.assertRaises(VerifyError):
            credentials.base_url("https://example.com:" + "1" * 5000)
        for role in ("credential/18446744073709551615/1", "credential/" + "1" * 5000 + "/1",
                     "credential/1/" + "1" * 5000):
            self.assertIsNone(credentials.role_entry(role), role[:40])

    def test_did_document_read(self):
        d = VECTORS["did_documents"][0]
        doc = credentials.parse_did_document(d["document"])
        self.assertEqual(doc["id"], credentials.base_url(d["base"]).did)
        self.assertEqual(credentials.parse_did_document(d["document"].encode()), doc)
        head = '{"id":"did:web:ledger.example.com","x":'

        def text(x: str) -> str:
            return head + x + "}"

        def refused(document, why: str):
            with self.assertRaises(VerifyError) as e:
                credentials.parse_did_document(document)
            self.assertEqual(str(e.exception), why)

        credentials.parse_did_document(text(nested(64)))
        for arrays in (65, 5000, 120_000):
            with self.subTest(arrays=arrays):
                refused(text(nested(arrays)), "the DID document cannot be read (JSON nested too deeply)")
        filler = '"' + "a" * (credentials.MAX_DID_DOCUMENT - len(text('""'))) + '"'
        self.assertEqual(len(text(filler)), credentials.MAX_DID_DOCUMENT)
        credentials.parse_did_document(text(filler))
        refused(text(filler) + " ", "the DID document is larger than 256 KiB")
        # Not JSON: NaN and Infinity, bytes that are not UTF-8, half a surrogate
        # pair escaped alone, a number a double cannot hold, other number forms.
        for x in ("NaN", "Infinity", "-Infinity", '"\\ud800"', '"\\udc00"', '"\\ud800\\u0041"', "1e400",
                  "-1e400", "1" + "0" * 309, "01", "1.", "+1", "'a'"):
            with self.subTest(x=x[:24]):
                refused(text(x), "the DID document cannot be read (not JSON)")
        for raw in (b"\xff", b"\xc0\xaf"):
            with self.subTest(raw=raw):
                refused(text('"X"').encode().replace(b"X", raw), "the DID document cannot be read (not JSON)")
        refused(text('"\ud800"'), "the DID document cannot be read (not JSON)")  # text no UTF-8 can carry
        refused("\ufeff" + text("1"), "the DID document cannot be read (JSON text that begins with a byte order mark)")
        refused(b"\xef\xbb\xbf" + text("1").encode(),
                "the DID document cannot be read (JSON text that begins with a byte order mark)")
        refused(text('1,"x":2'), "the DID document cannot be read (a JSON object names a member twice)")
        for x in ('"\uffff"', '"\\ufdd0"', '"\\uFFFE"', '"\\udbff\\udfff"'):
            with self.subTest(x=ascii(x)):
                refused(text(x), "the DID document cannot be read (JSON text with a noncharacter, which I-JSON "
                                 "excludes)")
        for x in ("1e300", "-0", "1.5", "1e-400", "18446744073709551616", '"\\ud83d\\ude00"', '"\\\\ud800"',
                  '"\\u0000"', '"\ufffd"'):
            with self.subTest(x=x):
                credentials.parse_did_document(text(x))
        refused("[" + text("1") + "]", "the DID document is not a JSON object")
        refused(text("1") + "x", "the DID document cannot be read (not JSON)")
        refused(text("1") + "\x00x", "the DID document cannot be read (not JSON)")  # a NUL, then more
        # DID Core: verification methods' ids are distinct, and services'.
        refused('{"verificationMethod":[{"id":"#a"},{"id":"#a"}]}',
                "the DID document gives two of its verification methods the same id")
        refused('{"service":[{"id":"#s","type":"KanheLedger"},{"id":"#s"}]}',
                "the DID document gives two of its services the same id")
        credentials.parse_did_document('{"verificationMethod":[{"id":"#a"},{"id":"#b"},{"id":1},{"id":1},2,2],'
                                       '"service":3}')

    def test_did_document_shapes(self):
        d = VECTORS["did_documents"][1]
        keys = [key(k) for k in d["keys"]]
        did = credentials.base_url(d["base"]).did
        kid = did + "#" + credentials.thumbprint(keys[0])
        ledger = bytes.fromhex(d["ledger"])
        doc = credentials.parse_did_document(d["document"])

        def problems(document):
            return credentials.did_document_problems(document, did, kid, keys[0], ledger)

        self.assertEqual(problems(doc), [])
        listed = sorted({k.key for k in keys})
        self.assertEqual(sorted(k.key for k in credentials.did_assertion_keys(doc)), listed)
        # Members of other shapes than section 3's are read as naming nothing.
        for shape in (1, True, None, "x", {}, {"a": 1}):
            with self.subTest(shape=shape):
                self.assertEqual(len(problems(dict(doc, verificationMethod=shape))), 1)
                self.assertEqual(len(problems(dict(doc, service=shape))), 1)
                self.assertEqual(credentials.did_assertion_keys(dict(doc, verificationMethod=shape)), [])
                self.assertEqual(credentials.did_assertion_keys(dict(doc, assertionMethod=shape)), [])
        self.assertEqual(credentials.did_assertion_keys(dict(doc, assertionMethod=doc["assertionMethod"][0])), [])
        # A second method under the kid is no document's (its ids are distinct).
        methods = doc["verificationMethod"]
        for first in ({"id": kid}, {"id": kid, "publicKeyJwk": 1}):
            with self.subTest(first=first), self.assertRaises(VerifyError):
                credentials.parse_did_document(json.dumps(dict(doc, verificationMethod=[first] + methods)))
        # The method under the kid without a JWK gives none.
        without = [{"id": kid} if m["id"] == kid else m for m in methods]
        self.assertEqual(len(problems(dict(doc, verificationMethod=without))), 1)
        # The first KanheLedger service that names a ledger (a string) is read.
        services = doc["service"]
        self.assertEqual(problems(dict(doc, service=[{"type": "KanheLedger"}, {"type": "KanheLedger", "ledger": 5}]
                                       + services)), [])
        self.assertEqual(len(problems(dict(doc, service=[{"type": "KanheLedger", "ledger": "00" * 32}] + services))),
                         1)


if __name__ == "__main__":
    unittest.main()
