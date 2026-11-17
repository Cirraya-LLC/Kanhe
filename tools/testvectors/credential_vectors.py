# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya
"""Test vectors for Kanhe credentials (spec/credentials.md), made from the
specification with Python's standard library and `cryptography`, apart from
both verifiers. Writes testvectors/credentials-v1.json:

- JCS serializations (RFC 8785), and JSON that is not canonical or not
  strict I-JSON (RFC 7493), or nested too deeply (section 7);
- JWK thumbprints (RFC 7638) of P-256 keys;
- base URLs and their did:web, and URLs refused;
- endorsement roles naming status entries, and roles that do not;
- credentials: the content (section 4), its payload and header byte for
  byte, and a JWS that verifies with the key (ECDSA is randomized: an
  implementation reproduces the payload and header, and checks the
  signature); the same with line ends after it, which are a file's; and
  credentials refused before anything is checked against evidence;
- DID documents (section 3), byte for byte; and DID documents a verifier
  reads (section 7), and ones it refuses;
- status lists GZIP-compressed by Python (any encoder's output must
  decode), with the bits they set, and encodedLists refused.

Usage: python3 tools/testvectors/credential_vectors.py
"""

from __future__ import annotations

import base64
import gzip
import hashlib
import json
import pathlib

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

ROOT = pathlib.Path(__file__).resolve().parents[2]
OUT = ROOT / "testvectors" / "credentials-v1.json"
N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def jcs(value) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, int):
        assert abs(value) <= 2**53 - 1
        return str(value)
    if isinstance(value, str):
        out = '"'
        for ch in value:
            if ch == '"':
                out += '\\"'
            elif ch == "\\":
                out += "\\\\"
            elif ch in "\b\f\n\r\t":
                out += {"\b": "\\b", "\f": "\\f", "\n": "\\n", "\r": "\\r", "\t": "\\t"}[ch]
            elif ord(ch) < 0x20:
                out += "\\u%04x" % ord(ch)
            else:
                out += ch
        return out + '"'
    if isinstance(value, list):
        return "[" + ",".join(jcs(v) for v in value) + "]"
    assert isinstance(value, dict)
    keys = sorted(value, key=lambda k: k.encode("utf-16-be"))
    return "{" + ",".join(jcs(k) + ":" + jcs(value[k]) for k in keys) + "}"


def private_key(seed: str) -> ec.EllipticCurvePrivateKey:
    scalar = int.from_bytes(hashlib.sha256(("Kanhe test credential key: " + seed).encode()).digest(), "big")
    return ec.derive_private_key(scalar % (N - 1) + 1, ec.SECP256R1())


def point(key: ec.EllipticCurvePrivateKey) -> bytes:
    return key.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)


def jwk(p: bytes) -> dict:
    return {"kty": "EC", "crv": "P-256", "x": b64(p[1:33]), "y": b64(p[33:])}


def thumbprint(p: bytes) -> str:
    k = jwk(p)
    return b64(hashlib.sha256(jcs({"crv": k["crv"], "kty": k["kty"], "x": k["x"], "y": k["y"]}).encode()).digest())


def did_of(url: str) -> tuple[str, str]:
    rest = url.split("://", 1)[1]
    authority, _, path = rest.partition("/")
    host, _, port = authority.partition(":")
    did = "did:web:" + host + ("%3A" + port if port else "") + "".join(":" + s for s in path.split("/") if s)
    return did, url + ("/did.json" if path else "/.well-known/did.json")


def iso(ms: int) -> str:
    import datetime
    t = datetime.datetime.fromtimestamp(ms // 1000, datetime.timezone.utc)
    return t.strftime("%Y-%m-%dT%H:%M:%S") + ".%03dZ" % (ms % 1000)


def sign(key: ec.EllipticCurvePrivateKey, did: str, payload: dict) -> tuple[str, str, str]:
    header = {"alg": "ES256", "cty": "vc", "kid": did + "#" + thumbprint(point(key)), "typ": "vc+jwt"}
    h, p = jcs(header), jcs(payload)
    signing_input = b64(h.encode()) + "." + b64(p.encode())
    r, s = decode_dss_signature(key.sign(signing_input.encode(), ec.ECDSA(hashes.SHA256())))
    s = min(s, N - s)  # low-S, as ESP256 requires
    return h, p, signing_input + "." + b64(r.to_bytes(32, "big") + s.to_bytes(32, "big"))


def credential(content: dict) -> dict:
    did, _ = did_of(content["base"])
    out = {
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        "type": ["VerifiableCredential"],
        "issuer": {"id": did, "name": content["organization"]},
        "validFrom": iso(content["registered_at"]),
        "credentialSubject": {name: value for name, value in content["subject"]},
        "credentialStatus": {
            "id": "%s/status/%d#%d" % (content["base"], content["list"], content["index"]),
            "type": "BitstringStatusListEntry",
            "statusPurpose": "revocation",
            "statusListIndex": str(content["index"]),
            "statusListCredential": "%s/status/%d" % (content["base"], content["list"]),
        },
        "evidence": [{"id": content["base"] + "/c/" + content["token"], "type": ["KanheEvidence"],
                      "ledger": content["ledger"], "record": content["record"]}],
    }
    if content.get("name") is not None:
        out["name"] = content["name"]
    return out


def did_document(base: str, keys: list[bytes], ledger: str) -> str:
    return jcs(did_document_value(base, keys, ledger))


def did_document_value(base: str, keys: list[bytes], ledger: str) -> dict:
    did, _ = did_of(base)
    methods = sorted((thumbprint(k), k) for k in keys)
    unique = []
    for t, k in methods:
        if not unique or unique[-1][0] != t:
            unique.append((t, k))
    return {
        "@context": ["https://www.w3.org/ns/did/v1", "https://www.w3.org/ns/cid/v1"],
        "id": did,
        "verificationMethod": [{"id": did + "#" + t, "type": "JsonWebKey", "controller": did,
                                "publicKeyJwk": {**jwk(k), "alg": "ES256"}} for t, k in unique],
        "assertionMethod": [did + "#" + t for t, _ in unique],
        "service": [{"id": did + "#kanhe", "type": "KanheLedger", "serviceEndpoint": base, "ledger": ledger}],
    }


def nested(arrays: int):
    """`arrays` arrays, one in the other: the innermost at depth arrays - 1."""
    value = []
    for _ in range(arrays - 1):
        value = [value]
    return value


def did_documents_read_and_refused(base: str, key: bytes, ledger: str) -> tuple[list, list]:
    """Section 7: a DID document is at most 256 KiB of strict I-JSON (RFC
    7493), nested at most 64 deep, an object whose verification methods have
    distinct ids, and so do its services. Each case is the document of
    section 3 with one thing changed. (A document past 256 KiB is left to the
    verifiers' own tests, to keep this file small.)"""
    value = did_document_value(base, [key], ledger)
    text = jcs(value)

    def member(x: str) -> str:  # one more member, "x", written as given
        return text[:-1] + ',"x":' + x + "}"

    read = [
        {"why": "a member nested 64 deep", "document": member(json.dumps(nested(64)))},
        {"why": "an escaped surrogate pair", "document": member('"\\ud83d\\ude00"')},
        {"why": "an integer past 64 bits, which a double holds", "document": member("18446744073709551616")},
        {"why": "a number near the largest a double holds", "document": member("1.7976931348623157e308")},
        {"why": "a number too small for a double, which rounds to 0", "document": member("1e-400")},
        {"why": "whitespace, and members in another order", "document": json.dumps(value, indent=2)},
        {"why": "a KanheLedger service without a ledger first",
         "document": jcs({**value, "service": [{"id": value["id"] + "#first", "type": "KanheLedger"}]
                          + value["service"]})},
    ]
    refused = [
        {"why": "a byte order mark", "document": "\ufeff" + text},
        {"why": "half of a surrogate pair escaped alone", "document": member('"\\ud800"')},
        {"why": "the other half alone", "document": member('"\\udc00x"')},
        {"why": "a high half followed by another character", "document": member('"\\ud800\\u0041"')},
        {"why": "a noncharacter", "document": member('"\uffff"')},
        {"why": "a noncharacter, escaped", "document": member('"\\ufdd0"')},
        {"why": "a noncharacter in a member name", "document": text[:-1] + ',"\U0010fffe":1}'},
        {"why": "a number a double cannot hold", "document": member("1e400")},
        {"why": "an integer of 310 digits", "document": member("1" + "0" * 309)},
        {"why": "NaN", "document": member("NaN")},
        {"why": "Infinity", "document": member("-Infinity")},
        {"why": "a member name twice", "document": text[:-1] + ',"id":' + jcs(value["id"]) + "}"},
        {"why": "a member nested 65 deep", "document": member(json.dumps(nested(65)))},
        {"why": "two verification methods with the same id",
         "document": jcs({**value, "verificationMethod": value["verificationMethod"] * 2})},
        {"why": "two services with the same id", "document": jcs({**value, "service": value["service"] * 2})},
        {"why": "not an object", "document": "[" + text + "]"},
        {"why": "more after the object", "document": text + "x"},
        {"why": "a NUL after the object, then more", "document": text + "\x00x"},
    ]
    return read, refused


def bits_with(indices: list[int]) -> bytes:
    bits = bytearray(16384)
    for i in indices:
        bits[i // 8] |= 0x80 >> (i % 8)
    return bytes(bits)


def generate() -> None:
    college, rotated, other = private_key("college"), private_key("college, rotated"), private_key("other")
    ledger = hashlib.sha256(b"Kanhe test ledger").hexdigest()
    record = hashlib.sha256(b"Kanhe test record").hexdigest()
    contents = [
        {"description": "a diploma: two disclosed fields and an integer metadata entry, named",
         "content": {"base": "https://ledger.example.com", "organization": "Example College",
                     "name": "Diploma in Nursing", "registered_at": 1782892800000,
                     "subject": [["name", "Chan Siu Ming"], ["programme", "Nursing"], ["year", 2026]],
                     "list": 1, "index": 94567, "token": "Xq3vB9tPz0LmN4kR7wYcAg", "ledger": ledger,
                     "record": record}},
        {"description": "no name; a base URL with a port and a path; text in Chinese, a boolean, escapes",
         "content": {"base": "https://example.com:8443/kanhe/college", "organization": "示例學院",
                     "name": None, "registered_at": 1791244800123,
                     "subject": [["姓名", "陳小明"], ["graduated", True], ["note", "line\none\t\"two\"\u001f"],
                                 ["😀", -42]],
                     "list": 2, "index": 0, "token": "AAAAAAAAAAAAAAAAAAAA-_", "ledger": ledger,
                     "record": record}},
    ]
    credentials = []
    for item in contents:
        c = item["content"]
        did, _ = did_of(c["base"])
        header, payload, token = sign(college, did, credential(c))
        credentials.append({"description": item["description"], "content": c, "key": point(college).hex(),
                            "header": header, "payload": payload, "jws": token})
    # Section 7: a compact JWS is read without the line ends after it (a
    # file's), and nothing else is taken off; a list number N is below 2^64 - 1.
    first = credentials[0]["jws"]
    did, _ = did_of(contents[0]["content"]["base"])
    credentials_read = [{"why": why, "jws": first + end}
                        for why, end in (("LF after it", "\n"), ("CR LF after it", "\r\n"), ("LF, CR LF", "\n\r\n"))]
    credentials_refused = [
        {"why": why, "jws": jws} for why, jws in (
            ("a space before it", " " + first), ("LF before it", "\n" + first), ("a space after it", first + " "),
            ("a tab after it", first + "\t"), ("a space before its line end", first + " \n"),
            ("a byte order mark before it", "\ufeff" + first),
            ("a list number of 2^64 - 1",
             sign(college, did, credential({**contents[0]["content"], "list": 2**64 - 1}))[2]),
            ("a list number of 21 digits",
             sign(college, did, credential({**contents[0]["content"], "list": 10**20}))[2]))]

    status = []
    for description, indices, level in [
            ("nothing revoked", [], 9), ("the first, a middle, and the last index", [0, 94567, 131071], 9),
            ("a few, stored without compression", [7, 8, 9], 0), ("many, compressed less", list(range(0, 131072, 97)), 1)]:
        bits = bits_with(indices)
        status.append({"description": description, "set": indices,
                       "sha256": hashlib.sha256(bits).hexdigest(),
                       "encoded": "u" + b64(gzip.compress(bits, compresslevel=level, mtime=0))})
    # A GZIP whose base64 needs padding (a length not a multiple of 3).
    padded = next(z for z in (gzip.compress(bits_with([i]), mtime=0) for i in range(64)) if len(z) % 3)
    refused_lists = [
        {"why": "no u prefix", "encoded": b64(gzip.compress(bits_with([]), mtime=0))},
        {"why": "base64 with padding", "encoded": "u" + base64.urlsafe_b64encode(padded).decode()},
        {"why": "too short a bitstring", "encoded": "u" + b64(gzip.compress(bytes(8192), mtime=0))},
        {"why": "too long a bitstring", "encoded": "u" + b64(gzip.compress(bytes(16385), mtime=0))},
        {"why": "two GZIP members", "encoded": "u" + b64(gzip.compress(bytes(8192), mtime=0) * 2)},
        {"why": "a bad checksum", "encoded": "u" + b64(gzip.compress(bits_with([1]), mtime=0)[:-8] + bytes(8))},
        {"why": "not GZIP", "encoded": "u" + b64(bits_with([]))},
    ]

    jcs_cases = [
        {"value": {"b": 1, "a": [True, False, None, -5, 9007199254740991]}},
        {"value": {"～": 1, "\U0001F600": 2, "€": 3, "z": 4}},
        {"value": "\b\f\n\r\t\u0000\u001f\u007f\"\\/é"},
        {"value": {"credentialSubject": {"姓名": "陳小明"}, "@context": []}},
        {"value": nested(65)},  # the innermost array at depth 64, the deepest read (section 7)
    ]
    for case in jcs_cases:
        case["jcs"] = jcs(case["value"])

    vectors = {
        "description": "Kanhe credentials (spec/credentials.md), made with Python apart from both verifiers "
                       "(tools/testvectors/credential_vectors.py). Byte strings and text are as given; keys are "
                       "SEC 1 uncompressed points in hex.",
        "jcs": jcs_cases,
        "jcs_refused": ['{"b":1,"a":2}', '{"a":1,"a":1}', '{"a": 1}', '{"a":"\\u0041"}', '{"a":1e2}', '{"a":1.5}',
                        '{"a":"\\u001F"}', '[9007199254740992]', ' {}',
                        # Not strict I-JSON (RFC 7493), or nested past 64 (section 7):
                        "\ufeff{}", '{"a":"\\ud800"}', '{"a":"\uffff"}', '{"\ufdd0":1}', "[1e400]",
                        "[1" + "0" * 309 + "]", jcs(nested(66))],
        "thumbprints": [{"key": point(k).hex(), "jwk": jwk(point(k)), "thumbprint": thumbprint(point(k))}
                        for k in (college, rotated, other)],
        "base_urls": [{"url": u, "base": u.rstrip("/"), "did": did_of(u.rstrip("/"))[0],
                       "did_document": did_of(u.rstrip("/"))[1]}
                      for u in ("https://ledger.example.com", "https://ledger.example.com/",
                                "https://example.com:8443/kanhe/college", "http://127.0.0.1:8080",
                                "http://localhost:8080/a_b~c.d")],
        "base_urls_refused": ["http://example.com", "https://1.2.3.4", "https://Example.com", "https://a..b",
                              "ftp://example.com", "https://example.com:0", "https://example.com:65536",
                              "https://example.com:080", "https://example.com/a/../b", "https://example.com/a b",
                              "https://", "example.com", "https://example.com//x"],
        "roles": [{"role": "credential/1/94567", "list": 1, "index": 94567},
                  {"role": "credential/18446744073709551614/131071", "list": 18446744073709551614,
                   "index": 131071}],
        "roles_refused": ["credential/0/1", "credential/01/1", "credential/1/01", "credential/1/131072",
                          "credential/1/", "credential/1", "credential/1/2/3", "credentials/1/2", "credential//1",
                          "reviewer", "credential/-1/2", "credential/18446744073709551615/1",
                          "credential/100000000000000000000/1"],
        "credentials": credentials,
        "credentials_read": credentials_read,
        "credentials_refused": credentials_refused,
        "did_documents": [
            {"description": "one key", "base": "https://ledger.example.com", "keys": [point(college).hex()],
             "ledger": ledger},
            {"description": "a key, rotated, and another credential key's, one given twice: each once, ordered by "
                            "thumbprint", "base": "https://example.com:8443/kanhe",
             "keys": [point(college).hex(), point(rotated).hex(), point(other).hex(), point(college).hex()],
             "ledger": ledger},
        ],
        "status_lists": status,
        "status_lists_refused": refused_lists,
    }
    for d in vectors["did_documents"]:
        d["document"] = did_document(d["base"], [bytes.fromhex(k) for k in d["keys"]], d["ledger"])
    vectors["did_documents_read"], vectors["did_documents_refused"] = did_documents_read_and_refused(
        "https://ledger.example.com", point(college), ledger)
    OUT.write_text(json.dumps(vectors, indent=2, ensure_ascii=False) + "\n")
    print(f"wrote {OUT.relative_to(ROOT)}")


if __name__ == "__main__":
    generate()
