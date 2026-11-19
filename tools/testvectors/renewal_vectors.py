# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya
"""Test vectors for specification revision v0.21 (long-term evidence), built
from spec/README.md (sections 6, 10, 11, 11.1, and 16) and spec/kanhe.cddl
with the independent encoder of generate.py and the ledger forge of
evidence_suite.py. Writes testvectors/protocol-v0.21.json.

Ledgers are written by hand: a ledger with a classical genesis (Ed25519
root and log keys) whose bundle is exported before it rotates its root key
and then its log key to ML-DSA-65, renewals after the rotation, a ledger
whose genesis names ML-DSA-65 keys, time-stamp tokens with chosen times
(each a TSTInfo written here and signed by `openssl cms`, with ECDSA P-256
and ML-DSA-65 authorities whose certificates `cryptography` makes), and
open-network witnesses' cosignatures (Ed25519 and ML-DSA-44, as c2sp.org's
texts define them). Each bundle comes with the options to verify it with,
the verdict the specification decides (a failure names the section and step
that decide it), and facts its report must show, which a model here derives
from what was forged: the renewals, the long-term status, and, for a
distrusted algorithm, every signature by it with the attestation that covers
it. Nothing here uses the C++ programs or the Python verifier.

ML-DSA and ECDSA signatures differ from run to run (and so do the bytes of
everything they sign); verdicts and facts do not, since every time is chosen.

Usage: python3 tools/testvectors/renewal_vectors.py [--openssl PATH]
Run alone, it also puts its conformance cases into testvectors/evidence-v1.json,
replacing those of the same names and leaving every other case as it was.
generate.py runs it too (and evidence_suite.py adds the conformance cases).
"""

from __future__ import annotations

import argparse
import base64
import calendar
import datetime
import hashlib
import json
import pathlib
import struct
import subprocess
import tempfile

import cbor2
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, mldsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

import evidence_suite as es
import generate as g

OUT = g.OUT / "protocol-v0.21.json"
SHA256, SM3 = es.SHA256, es.SM3
ED25519, ESP256, MLDSA44, MLDSA65 = es.ED25519, es.ESP256, es.MLDSA44, es.MLDSA65
PERSON = es.PERSON
CERTIFICATE = "example.org.certificate/1"

# Algorithms as section 11.1 names them.
NAMES = {ED25519: "ed25519", ESP256: "ecdsa", es.SM2: "sm2", MLDSA44: "ml-dsa-44", MLDSA65: "ml-dsa-65",
         es.MLDSA87: "ml-dsa-87"}
POST_QUANTUM = ("ml-dsa-44", "ml-dsa-65", "ml-dsa-87")
CLASSICAL = ("ed25519", "ecdsa", "sm2", "rsa", "other")
RENEW_BEFORE = "2030-01-01T00:00:00.000Z"


def utc_ms(*parts) -> int:
    return calendar.timegm(parts + (0,) * (6 - len(parts))) * 1000


NETWORK_T = utc_ms(2026, 11, 1) // 1000  # the network witnesses' time, POSIX seconds
TOKEN_T = utc_ms(2026, 11, 2)  # the authorities' time
EARLY_TOKEN_T = utc_ms(2026, 10, 1)  # before the ledgers' entries: for the clock rule
ACCURACY = 1_000


def iso(ms: int | None) -> str | None:
    return None if ms is None else es.iso(ms)


def cose_alg(signed: bytes) -> int:
    """The alg of a tagged COSE_Sign1's protected header."""
    return cbor2.loads(cbor2.loads(signed).value[0])[1]


# ---------------------------------------------------------------------------
# Attesters: time-stamp authorities and open-network witnesses
# ---------------------------------------------------------------------------

def _der(tag: int, content: bytes) -> bytes:
    n = len(content)
    if n < 128:
        length = bytes([n])
    elif n < 256:
        length = bytes([0x81, n])
    else:
        length = bytes([0x82, n >> 8, n & 0xFF])
    return bytes([tag]) + length + content


IMPRINT_OIDS = {SHA256: bytes.fromhex("608648016503040201"), SM3: bytes.fromhex("2a811ccf55018311")}


class Stamper:
    """A time-stamp authority (section 10.1) whose tokens carry a chosen time:
    a TSTInfo written here (version 1, the imprint, a serial number, genTime,
    an accuracy of one second), signed by `openssl cms -sign -cades` (which
    adds the signing-certificate attribute, RFC 5816), with its certificate
    and root in the token. `alg` is "ecdsa" (P-256) or "ml-dsa-65"."""

    def __init__(self, name: str, alg: str):
        self.name, self.alg = name, alg

        def key(label: str):
            s = es.seed(f"renewal tsa {label} {name}")
            if alg == "ml-dsa-65":
                return mldsa.MLDSA65PrivateKey.from_seed_bytes(s)
            return ec.derive_private_key(int.from_bytes(s, "big") % (2**255), ec.SECP256R1())

        root_key, tsa_key = key("root"), key("signer")
        digest = None if alg == "ml-dsa-65" else hashes.SHA256()
        start = datetime.datetime(2020, 1, 1, tzinfo=datetime.timezone.utc)
        end = datetime.datetime(2040, 1, 1, tzinfo=datetime.timezone.utc)
        root_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"Renewal Test Root {name}")])
        tsa_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"Renewal Test TSA {name}")])
        root = (x509.CertificateBuilder().subject_name(root_name).issuer_name(root_name)
                .public_key(root_key.public_key()).serial_number(1).not_valid_before(start).not_valid_after(end)
                .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
                .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False),
                               critical=True)
                .sign(root_key, digest))
        tsa = (x509.CertificateBuilder().subject_name(tsa_name).issuer_name(root_name)
               .public_key(tsa_key.public_key()).serial_number(2).not_valid_before(start).not_valid_after(end)
               .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
               .add_extension(x509.KeyUsage(True, False, False, False, False, False, False, False, False),
                              critical=True)
               .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.TIME_STAMPING]), critical=True)
               .sign(root_key, digest))
        self.authority = tsa.subject.rfc4514_string()
        pem = serialization.Encoding.PEM
        self.root_pem = root.public_bytes(pem).decode()
        d = self.dir = es.Env.work / f"stamper-{hashlib.sha256(name.encode()).hexdigest()[:12]}"
        d.mkdir()
        (d / "root.pem").write_bytes(root.public_bytes(pem))
        (d / "tsa.pem").write_bytes(tsa.public_bytes(pem))
        (d / "tsa.key").write_bytes(tsa_key.private_bytes(pem, serialization.PrivateFormat.PKCS8,
                                                          serialization.NoEncryption()))
        self.serial = 0

    def stamp(self, payload: bytes, hash_id: int, at_ms: int) -> bytes:
        """A token over a checkpoint's payload under the ledger's hash, with
        genTime `at_ms` (whole seconds)."""
        assert at_ms % 1000 == 0
        self.serial += 1
        imprint = hashlib.new(g.HASHES[hash_id], payload).digest()
        when = datetime.datetime.fromtimestamp(at_ms / 1000, datetime.timezone.utc).strftime("%Y%m%d%H%M%SZ")
        tstinfo = _der(0x30, _der(0x02, b"\x01") + _der(0x06, bytes.fromhex("2a03040501"))  # policy 1.2.3.4.5.1
                       + _der(0x30, _der(0x30, _der(0x06, IMPRINT_OIDS[hash_id])) + _der(0x04, imprint))
                       + _der(0x02, bytes([self.serial])) + _der(0x18, when.encode())
                       + _der(0x30, _der(0x02, b"\x01")))
        d = self.dir
        (d / "tstinfo.der").write_bytes(tstinfo)
        subprocess.run([es.Env.openssl, "cms", "-sign", "-binary", "-nodetach", "-in", str(d / "tstinfo.der"),
                        "-signer", str(d / "tsa.pem"), "-inkey", str(d / "tsa.key"), "-certfile", str(d / "root.pem"),
                        "-econtent_type", "1.2.840.113549.1.9.16.1.4", "-cades", "-md", "sha256", "-outform", "DER",
                        "-out", str(d / "token.der")], check=True, capture_output=True)
        return (d / "token.der").read_bytes()


class NetworkWitness:
    """An open network's witness (section 10.2): Ed25519 (signature type 0x04,
    cosignature/v1) or ML-DSA-44 (0x06, a CosignedSubtree)."""

    def __init__(self, name: str, kind: int):
        self.name, self.kind = name, kind
        s = es.seed(f"renewal network witness {name}")
        if kind == 0x04:
            self.key = ed25519.Ed25519PrivateKey.from_private_bytes(s)
            self.public = self.key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        else:
            self.key = mldsa.MLDSA44PrivateKey.from_seed_bytes(s)
            self.public = self.key.public_key().public_bytes_raw()
        self.key_id = hashlib.sha256(name.encode() + b"\n" + bytes([kind]) + self.public).digest()[:4]
        self.vkey = f"{name}+{self.key_id.hex()}+{base64.b64encode(bytes([kind]) + self.public).decode()}"
        self.algorithm = "ed25519" if kind == 0x04 else "ml-dsa-44"

    def cosign(self, ledger_id: bytes, size: int, root: bytes, at: int) -> list:
        origin = "cirraya.com/kanhe/" + ledger_id.hex()
        if self.kind == 0x04:
            note = f"{origin}\n{size}\n{base64.b64encode(root).decode()}\n"
            message = f"cosignature/v1\ntime {at}\n{note}".encode()
        else:
            message = (b"subtree/v1\n\0" + bytes([len(self.name)]) + self.name.encode() + struct.pack(">Q", at)
                       + bytes([len(origin)]) + origin.encode() + struct.pack(">QQ", 0, size) + root)
        return [self.name, self.key_id + struct.pack(">Q", at) + self.key.sign(message)]


# ---------------------------------------------------------------------------
# Renewals and the model of a report's v0.21 fields
# ---------------------------------------------------------------------------

def head_of(signed: bytes) -> dict:
    """A signed checkpoint's payload: {1: ledger, 2: hash, 3: size, 4: root, 5: time}."""
    return cbor2.loads(cbor2.loads(signed).value[2])


def renewal(f: es.Forge, previous_size: int, checkpoint: tuple, *, rotations=(), cosignatures=(), tokens=(),
            network=(), consistency=None) -> dict:
    """A renewal (section 11.1) of `checkpoint` (signed, payload, root), from
    a previous checkpoint of `previous_size`: the consistency proof when it is
    larger, the rotations at the given indices with their paths in its tree,
    and its attestations."""
    signed, payload, root = checkpoint
    size = cbor2.loads(payload)[3]
    r = {1: signed}
    if size > previous_size:
        r[2] = f.consistency(previous_size, size) if consistency is None else consistency
    if rotations:
        r[3] = [[i, f.entries[i], f.merkle().path(i, f.entries[:size])] for i in rotations]
    if cosignatures:
        r[4] = list(cosignatures)
    if tokens:
        r[5] = list(tokens)
    if network:
        r[6] = list(network)
    return r


def dated_cosign(f: es.Forge, key: es.Key, payload: bytes, iat, claims=None) -> bytes:
    """A witness's cosignature that carries its time (v0.21, section 10): its
    protected header also holds the CWT Claims header parameter (RFC 9597,
    label 15) with exactly iat (6), in whole seconds; `claims` replaces that
    map, for a forgery."""
    protected = g.dcbor({1: key.alg, 3: g.COSIGNATURE_TYPE, 4: f.kid(key), 15: {6: iat} if claims is None else claims})
    tbs = g.dcbor(["Signature1", protected, b"", payload])
    return g.dcbor(cbor2.CBORTag(18, [protected, {}, payload, key.sign(tbs)]))


def long_term_fact(head: dict | None = None, renewal_number=None, attested=()) -> dict:
    if head is None:
        return {"post_quantum": False, "checkpoint": None, "attested_by": [], "renew_before": RENEW_BEFORE}
    return {"post_quantum": True,
            "checkpoint": {"tree_size": head[3], "timestamp": iso(head[5]), "renewal": renewal_number},
            "attested_by": list(attested), "renew_before": None}


def witness_by(f: es.Forge, key: es.Key, iat: int | None = None) -> dict:
    return {"kind": "witness", "by": f.kid(key).hex(), "algorithm": NAMES[key.alg],
            "time": iso(iat * 1000) if iat is not None else None}


def renewal_fact(r: dict, log_key: es.Key, *, log_rotations=0, root_rotations=0, trusted=0, untrusted=0,
                 network=(), tokens=()) -> dict:
    head = head_of(r[1])
    return {"tree_size": head[3], "root": head[4].hex(), "timestamp": iso(head[5]),
            "log_key": es.key_fact(log_key), "log_key_rotations": log_rotations, "root_key_rotations": root_rotations,
            "witnesses": {"trusted": trusted, "untrusted": untrusted, "network": list(network)},
            "timestamps": list(tokens)}


def relied_signatures(f: es.Forge, bundle: dict, presence_algs: dict) -> list:
    """Every signature a verifier relies on, in section 11.1's order:
    (signed, index, tree size, anchor, renewal, algorithm name)."""
    size = head_of(bundle[3])[3]
    out = []
    for entry_bytes, receipt in bundle[2]:
        entry = cbor2.loads(entry_bytes)
        index = f.entries.index(entry_bytes)
        if 4 in entry:
            out.append(("state-commitment", index, None, None, None, NAMES[cose_alg(entry[4])]))
        else:
            out.append(("statement", index, None, None, None, NAMES[cose_alg(entry[3])]))
            if index in presence_algs:
                out.append(("presence", index, None, None, None, NAMES[presence_algs[index]]))
            assert 5 not in entry  # no approvals in these ledgers
        out.append(("receipt", index, size, None, None, NAMES[cose_alg(receipt)]))
    out.append(("checkpoint", None, size, None, None, NAMES[cose_alg(bundle[3])]))
    for n, a in enumerate(bundle.get(8, []), start=1):
        out.append(("anchor", None, head_of(a[1])[3], n, None, NAMES[cose_alg(a[1])]))
    for n, r in enumerate(bundle.get(11, []), start=1):
        for index, entry_bytes, _ in r.get(3, []):
            out.append(("rotation", index, None, None, n, NAMES[cose_alg(cbor2.loads(entry_bytes)[3])]))
        out.append(("renewal", None, head_of(r[1])[3], None, n, NAMES[cose_alg(r[1])]))
    return out


def distrust_fact(f: es.Forge, bundle: dict, distrust: dict, covered_by: dict, set_aside=(), presence_algs=None
                  ) -> dict:
    """The report's `distrust`, by the model of section 11.1, when one dated
    attestation (`covered_by`, its size given) is the earliest that covers
    every signature by a distrusted algorithm."""
    signatures = []
    for signed, index, tree_size, anchor, renewal_number, name in relied_signatures(f, bundle, presence_algs or {}):
        if name not in distrust:
            continue
        # A tree head a log key signed (a receipt among them): a tree of at
        # least its size; any other signature: a tree above its entry's index.
        inside = covered_by["checkpoint_size"] >= tree_size if tree_size is not None else \
            covered_by["checkpoint_size"] > index
        assert inside, (signed, index, tree_size)
        signatures.append({"signed": signed, "index": index, "tree_size": tree_size, "approver": None,
                           "anchor": anchor, "renewal": renewal_number, "algorithm": name,
                           "covered_by": covered_by})
    order = ("ed25519", "ecdsa", "sm2", "rsa", "ml-dsa-44", "ml-dsa-65", "ml-dsa-87", "other")
    return {"algorithms": [{"algorithm": a, "after": distrust[a]} for a in order if a in distrust],
            "set_aside": list(set_aside), "signatures": signatures}


def expand(options: list) -> dict:
    """--distrust options as section 11.1 reads them: {name: the date as a time}."""
    out = {}
    for text in options:
        name, date = text.split("@")
        for n in (CLASSICAL if name == "classical" else (name,)):
            out[n] = date + "T00:00:00.000Z"
    return out


# ---------------------------------------------------------------------------
# The ledgers
# ---------------------------------------------------------------------------

def archive(name: str = "Archive Org", *, hash_id: int = SHA256, forged_log_rotation: bool = False) -> dict:
    """A ledger with a classical genesis: a clerk with a hardware key
    registers a certificate in person; a state commitment; the checkpoint the
    bundle is exported at (size 6). Then the organization rotates its root key
    to ML-DSA-65 (signed by its Ed25519 root key) and its log key to
    ML-DSA-65 (signed by the new root key), the clerk registers another
    certificate, and a state commitment; the checkpoint of size 10 is signed
    by the ML-DSA-65 log key. With `forged_log_rotation`, the log key's
    rotation is signed by the old root key instead."""
    f = es.Forge(name, hash_id=hash_id)
    s = {"f": f}
    s["clerk_ukey"] = es.Key(f"{name} clerk ukey")
    s["clerk"] = f.actor(PERSON, "Clerk", es.Key(f"{name} clerk"))
    f.set_presence(s["clerk"], [es.hardware_credential(s["clerk_ukey"], b"clerk-ukey", "UKey")])
    s["d_clerk"] = f.grant(s["clerk"], {1: [16, 17]})
    s["record"] = f.record(s["clerk"], CERTIFICATE, delegation=s["d_clerk"],
                           fields={"holder": "Chan Tai Man", "grade": "A"},
                           presence=es.hardware_proof(s["clerk_ukey"], b"clerk-ukey"))
    s["presence_algs"] = {f.index[s["record"]]: ED25519}
    f.commit()
    s["n1"] = len(f.entries)
    s["log1"] = f.log_key_for(s["n1"])
    s["c1"] = f.checkpoint(s["n1"])
    s["root2"] = es.Key(f"{name} root ml-dsa-65", MLDSA65)
    s["log2"] = es.Key(f"{name} log ml-dsa-65", MLDSA65)
    old_root = f.root
    s["rot_root"] = f.rotate_key(f.org, s["root2"])
    if forged_log_rotation:
        sid = f.add(8, old_root, f.org, {1: s["log2"].public}, touches=[f.org])
        f.log_keys.append((f.index[sid], s["log2"]))
        s["rot_log"] = sid
    else:
        s["rot_log"] = f.rotate_log_key(s["log2"])
    s["rotations"] = [f.index[s["rot_root"]], f.index[s["rot_log"]]]
    s["other"] = f.record(s["clerk"], CERTIFICATE, delegation=s["d_clerk"], fields={"holder": "Lee Ka Yan",
                                                                                    "grade": "B"})
    f.commit()
    s["n2"] = len(f.entries)
    s["c2"] = f.checkpoint(s["n2"])
    return s


def record_fact(f: es.Forge, record: bytes) -> dict:
    return {"id": record.hex(), "type": CERTIFICATE, "state": "registered", "revoked": False}


# ---------------------------------------------------------------------------
# The cases
# ---------------------------------------------------------------------------

def bundle_cases(suite: es.Suite) -> dict:
    """Every v0.21 bundle case, added to `suite`; returns the ledger the
    first ones are about, for the file's `ledger` section."""
    w_ed = es.Key("renewal witness ed25519")
    w_pq = es.Key("renewal witness ml-dsa-65", MLDSA65)
    nw_pq = NetworkWitness("witness.example/renewal-ml-dsa-44", 0x06)
    nw_ed = NetworkWitness("witness.example/renewal-ed25519", 0x04)

    s = archive()
    f = s["f"]
    n1, n2 = s["n1"], s["n2"]
    c1_signed, c1_payload, c1_root = s["c1"]
    c2_signed, c2_payload, c2_root = s["c2"]
    c2 = head_of(c2_signed)
    rec = s["record"]

    def b1(**kw) -> dict:
        return f.bundle(rec, size=n1, checkpoint=s["c1"], cosignatures=[f.cosign(w_ed, c1_payload)], **kw)

    r1 = renewal(f, n1, s["c2"], rotations=s["rotations"], cosignatures=[f.cosign(w_pq, c2_payload)])
    nw_cosig = nw_pq.cosign(f.id, n2, c2_root, NETWORK_T)
    r2 = renewal(f, n2, s["c2"], cosignatures=[f.cosign(w_ed, c2_payload)], network=[nw_cosig])
    r1_fact = renewal_fact(r1, s["log2"], log_rotations=1, root_rotations=1, trusted=1)
    nw_fact = {"witness": nw_pq.name, "size": n2, "time": iso(NETWORK_T * 1000), "trusted": True}
    nw_by = {"kind": "network-witness", "by": nw_pq.name, "algorithm": "ml-dsa-44", "time": iso(NETWORK_T * 1000)}
    nw_cover = {"kind": "network-witness", "by": nw_pq.name, "checkpoint_size": n2, "anchor": None, "renewal": 2,
                "time": iso(NETWORK_T * 1000)}

    def with_renewals(*renewals) -> bytes:
        b = b1()
        b[11] = list(renewals)
        return es.enc(b)

    # --- Verified --------------------------------------------------------------------
    suite.add("renewal-none-classical",
              "A certificate's bundle exported before its ledger left classical keys: Ed25519 genesis, log key, "
              "and witness. No post-quantum attestation covers it, so the report advises renewing before 2030.",
              "record", es.enc(b1()), True, ledger_id=f.id, witnesses=[w_ed], facts={
                  "record": record_fact(f, rec), "renewals": [], "long_term": long_term_fact(), "distrust": None,
                  "witnesses": {"trusted": 1, "untrusted": 0}, "keys": {"log_key": es.key_fact(s["log1"])},
                  "complete": True})
    suite.add("renewal-post-quantum-witness",
              "The same bundle renewed after the ledger rotated its root key and then its log key to ML-DSA-65: "
              "the checkpoint of size 10, proven consistent with the bundle's, both rotations followed (the first "
              "signed by the Ed25519 root key, the second by the new ML-DSA-65 one), and a cosignature by a "
              "trusted witness with an ML-DSA-65 key, which is the latest post-quantum attestation. The bundle's "
              "own checkpoint, log key, and history are unchanged.",
              "record", with_renewals(r1), True, ledger_id=f.id, witnesses=[w_ed, w_pq], facts={
                  "record": record_fact(f, rec), "renewals": [r1_fact],
                  "long_term": long_term_fact(c2, 1, [witness_by(f, w_pq)]), "distrust": None,
                  "witnesses": {"trusted": 2, "untrusted": 0},
                  "keys": {"log_key": es.key_fact(s["log1"]), "log_key_rotations": 0, "root_key_rotations": 0},
                  "checkpoint": {"tree_size": n1}, "complete": True})
    suite.add("renewal-witness-not-trusted",
              "The renewal of renewal-post-quantum-witness verified without trusting its ML-DSA-65 witness: the "
              "cosignature is counted and relied on for nothing, and the renewal's ML-DSA-65 log key is no "
              "post-quantum attestation, since the ledger's genesis keys were Ed25519.",
              "record", with_renewals(r1), True, ledger_id=f.id, witnesses=[w_ed], facts={
                  "renewals": [{**r1_fact, "witnesses": {"trusted": 0, "untrusted": 1, "network": []}}],
                  "long_term": long_term_fact(), "witnesses": {"trusted": 1, "untrusted": 1}})
    r2_fact = renewal_fact(r2, s["log2"], trusted=2, network=[nw_fact])
    suite.add("renewal-repeated-checkpoint",
              "Two renewals: the first as in renewal-post-quantum-witness, the second repeating its checkpoint "
              "(the same size and root, no consistency proof, no rotations) with a newer cosignature by the "
              "Ed25519 witness and a trusted network witness's ML-DSA-44 cosignature, which is now the latest "
              "post-quantum attestation.",
              "record", with_renewals(r1, r2), True, ledger_id=f.id, witnesses=[w_ed, w_pq],
              witness_vkeys=[nw_pq.vkey], facts={
                  "renewals": [r1_fact, r2_fact], "long_term": long_term_fact(c2, 2, [nw_by]),
                  "witnesses": {"trusted": 3, "untrusted": 0}})
    resigned = f.checkpoint(n2, at=c2[5] + es.DAY)
    r2b = renewal(f, n2, resigned, network=[nw_pq.cosign(f.id, n2, c2_root, NETWORK_T)])
    suite.add("renewal-re-signed-checkpoint",
              "A second renewal with a checkpoint of the same size and root that the ledger signed again a day "
              "later: it repeats the tree, and its time is the newer one.",
              "record", with_renewals(r1, r2b), True, ledger_id=f.id, witnesses=[w_ed, w_pq],
              witness_vkeys=[nw_pq.vkey], facts={
                  "renewals": [r1_fact, renewal_fact(r2b, s["log2"], trusted=1, network=[nw_fact])],
                  "long_term": long_term_fact(head_of(resigned[0]), 2, [nw_by])})
    distrust = ["ed25519@2027-01-01"]
    bundle = b1()
    bundle[11] = [r1, r2]
    set_aside = [{"kind": "witness", "by": f.kid(w_ed).hex(), "algorithm": "ed25519", "checkpoint_size": n1,
                  "anchor": None, "renewal": None},
                 {"kind": "witness", "by": f.kid(w_ed).hex(), "algorithm": "ed25519", "checkpoint_size": n2,
                  "anchor": None, "renewal": 2}]
    suite.add("distrust-covered-by-network-witness",
              "renewal-repeated-checkpoint verified with Ed25519 distrusted from 2027-01-01: the Ed25519 witness's "
              "cosignatures are set aside, and every Ed25519 signature the evidence relies on (the statements, "
              "the clerk's hardware key, the state commitment, the receipts, the checkpoint, and the root key's "
              "rotation) is in the tree of size 10 that the trusted ML-DSA-44 network witness cosigned on "
              "2026-11-01, before that date.",
              "record", es.enc(bundle), True, ledger_id=f.id, witnesses=[w_ed, w_pq], witness_vkeys=[nw_pq.vkey],
              distrust=distrust, facts={
                  "distrust": distrust_fact(f, bundle, expand(distrust), nw_cover, set_aside, s["presence_algs"]),
                  "long_term": long_term_fact(c2, 2, [nw_by]), "witnesses": {"trusted": 2, "untrusted": 1},
                  "renewals": [r1_fact, {**r2_fact, "witnesses": {"trusted": 1, "untrusted": 1,
                                                                   "network": [nw_fact]}}]})
    distrust = ["ml-dsa-44@2030-01-01"]
    suite.add("distrust-network-witness-set-aside",
              "renewal-repeated-checkpoint verified with ML-DSA-44 distrusted: the network witness's cosignature "
              "is set aside, no signature the evidence relies on is ML-DSA-44, and the latest post-quantum "
              "attestation is the first renewal's ML-DSA-65 witness again.",
              "record", with_renewals(r1, r2), True, ledger_id=f.id, witnesses=[w_ed, w_pq],
              witness_vkeys=[nw_pq.vkey], distrust=distrust, facts={
                  "distrust": {"algorithms": [{"algorithm": "ml-dsa-44", "after": "2030-01-01T00:00:00.000Z"}],
                               "set_aside": [{"kind": "network-witness", "by": nw_pq.name, "algorithm": "ml-dsa-44",
                                              "checkpoint_size": n2, "anchor": None, "renewal": 2}],
                               "signatures": []},
                  "long_term": long_term_fact(c2, 1, [witness_by(f, w_pq)])})

    # Dated witness cosignatures (v0.21): the witness's time in its header.
    dated = renewal(f, n1, s["c2"], rotations=s["rotations"],
                    cosignatures=[dated_cosign(f, w_pq, c2_payload, NETWORK_T)])
    dated_cover = {"kind": "witness", "by": f.kid(w_pq).hex(), "checkpoint_size": n2, "anchor": None, "renewal": 1,
                   "time": iso(NETWORK_T * 1000)}
    distrust = ["classical@2027-01-01"]
    bundle = b1()
    bundle[11] = [dated]
    suite.add("distrust-classical-covered-by-dated-witness",
              "renewal-post-quantum-witness with the ML-DSA-65 witness's cosignature dated 2026-11-01 (CWT claims, "
              "header 15, with only iat), verified with every classical algorithm distrusted from 2027-01-01: the "
              "Ed25519 witness's cosignature of the bundle's checkpoint is set aside, and the dated cosignature "
              "of the tree of size 10 covers every Ed25519 signature, the root key's rotation included.",
              "record", es.enc(bundle), True, ledger_id=f.id, witnesses=[w_ed, w_pq], distrust=distrust, facts={
                  "distrust": distrust_fact(f, bundle, expand(distrust), dated_cover, [
                      {"kind": "witness", "by": f.kid(w_ed).hex(), "algorithm": "ed25519", "checkpoint_size": n1,
                       "anchor": None, "renewal": None}], s["presence_algs"]),
                  "long_term": long_term_fact(c2, 1, [witness_by(f, w_pq, NETWORK_T)]),
                  "renewals": [r1_fact], "witnesses": {"trusted": 1, "untrusted": 1}})
    own = f.bundle(rec, size=n1, checkpoint=s["c1"], cosignatures=[dated_cosign(f, w_pq, c1_payload, NETWORK_T)])
    distrust = ["ed25519@2027-01-01"]
    suite.add("distrust-covered-by-dated-bundle-cosignature",
              "The bundle exported before the rotation, with no renewal and a dated cosignature of its own "
              "checkpoint by the ML-DSA-65 witness: with Ed25519 distrusted from 2027-01-01, it covers every "
              "Ed25519 signature, and it is the bundle's own post-quantum attestation.",
              "record", es.enc(own), True, ledger_id=f.id, witnesses=[w_pq], distrust=distrust, facts={
                  "distrust": distrust_fact(f, own, expand(distrust), {**dated_cover, "checkpoint_size": n1,
                                                                       "renewal": None}, (), s["presence_algs"]),
                  "long_term": long_term_fact(head_of(s["c1"][0]), None, [witness_by(f, w_pq, NETWORK_T)])})
    early_iat = EARLY_TOKEN_T // 1000
    early_dated = renewal(f, n1, s["c2"], rotations=s["rotations"],
                          cosignatures=[dated_cosign(f, w_pq, c2_payload, early_iat)])
    suite.add("renewal-dated-cosignature-early",
              "A renewal whose witness dated its cosignature 2026-10-01, before the ledger dated the checkpoint it "
              "cosigns: the clock rule is for time-stamp authorities' tokens only, so the time is reported, as the "
              "witness's word, and refused for nothing.",
              "record", with_renewals(early_dated), True, ledger_id=f.id, witnesses=[w_ed, w_pq], facts={
                  "long_term": long_term_fact(c2, 1, [witness_by(f, w_pq, early_iat)])})

    # A ledger whose genesis names ML-DSA-65 root and log keys.
    q = es.Forge("Quantum Safe Org", root=es.Key("quantum safe root", MLDSA65),
                 log=es.Key("quantum safe log", MLDSA65))
    clerk = q.actor(PERSON, "Clerk", es.Key("quantum safe clerk"))
    d_clerk = q.grant(clerk, {1: [16]})
    q_rec = q.record(clerk, CERTIFICATE, delegation=d_clerk, fields={"holder": "Ho Wing"})
    q.commit()
    q_cp = q.checkpoint()
    log = q.log_key_for(len(q.entries))
    suite.add("renewal-post-quantum-genesis",
              "A ledger whose genesis named ML-DSA-65 root and log keys, which it never rotated: its checkpoint's "
              "own signature is a post-quantum attestation, since its id commits to those keys. No witness.",
              "record", es.enc(q.bundle(q_rec, checkpoint=q_cp)), True, ledger_id=q.id, facts={
                  "long_term": long_term_fact(head_of(q_cp[0]), None, [
                      {"kind": "log-key", "by": q.kid(log).hex(), "algorithm": "ml-dsa-65", "time": None}]),
                  "renewals": []})

    # Time-stamp authorities: ML-DSA-65 and ECDSA P-256, at chosen times.
    pq_tsa = Stamper("ML-DSA-65", "ml-dsa-65")
    ec_tsa = Stamper("ECDSA", "ecdsa")
    t = archive("Stamped Org")
    tf, n = t["f"], t["n1"]
    t_signed, t_payload, _ = t["c1"]

    def stamped(stamper: Stamper) -> dict:
        b = tf.bundle(t["record"], size=n, checkpoint=t["c1"])
        b[8] = [es.anchor(t_signed, [stamper.stamp(t_payload, SHA256, TOKEN_T)])]
        return b

    pq_bundle = stamped(pq_tsa)
    token_fact = {"checkpoint_size": n, "time": iso(TOKEN_T), "accuracy_ms": ACCURACY, "authority": pq_tsa.authority,
                  "trusted": True}
    pq_cover = {"kind": "timestamp", "by": pq_tsa.authority, "checkpoint_size": n, "anchor": 1, "renewal": None,
                "time": iso(TOKEN_T + ACCURACY)}
    distrust = ["ed25519@2027-01-01"]
    suite.add("renewal-post-quantum-timestamp",
              "A classical ledger's bundle with an anchor at its checkpoint: a token by a trusted authority whose "
              "signature and certificate are ML-DSA-65, the post-quantum attestation. With Ed25519 distrusted from "
              "2027-01-01, the token (2026-11-02, accuracy 1 s) covers every Ed25519 signature.",
              "record", es.enc(pq_bundle), True, ledger_id=tf.id, tsa_roots=[pq_tsa], distrust=distrust, facts={
                  "timestamps": {"trusted_authorities": 1, "tokens": [token_fact]},
                  "long_term": long_term_fact(head_of(t_signed), None, [
                      {"kind": "timestamp", "by": pq_tsa.authority, "algorithm": "ml-dsa-65", "time": iso(TOKEN_T)}]),
                  "distrust": distrust_fact(tf, pq_bundle, expand(distrust), pq_cover, (), t["presence_algs"])})
    ec_bundle = stamped(ec_tsa)
    ec_cover = {**pq_cover, "by": ec_tsa.authority}
    suite.add("distrust-covered-by-classical-timestamp",
              "The same with a trusted ECDSA P-256 authority's token: ECDSA is not distrusted, so the token covers "
              "every Ed25519 signature, and the long-term status has no post-quantum attestation.",
              "record", es.enc(ec_bundle), True, ledger_id=tf.id, tsa_roots=[ec_tsa], distrust=distrust, facts={
                  "long_term": long_term_fact(),
                  "distrust": distrust_fact(tf, ec_bundle, expand(distrust), ec_cover, (), t["presence_algs"])})

    # 32-byte salts.
    v = es.Forge("Salted Org")
    clerk = v.actor(PERSON, "Clerk", es.Key("salted clerk"))
    d_clerk = v.grant(clerk, {1: [16]})
    content = b"%PDF-1.7 a transcript"
    fields = {"holder": "Wong Siu Ming", "passed": True}
    v_rec = v.record(clerk, CERTIFICATE, delegation=d_clerk, fields=fields,
                     attachments=[("transcript.pdf", "application/pdf", content)], salt_size=32)
    v.commit()
    suite.add("salts-32-bytes",
              "A record whose fields and attachment have 32-byte salts (v0.21), both fields disclosed and the "
              "attachment opened with its content.",
              "record", es.enc(v.bundle(v_rec, disclose=["holder", "passed"], open_=["transcript.pdf"])), True,
              ledger_id=v.id, attachments={"transcript.pdf": content}, facts={
                  "disclosed_fields": fields,
                  "attachments": [{"name": "transcript.pdf", "media_type": "application/pdf", "size": len(content),
                                   "status": "verified"}]})

    # --- Failures ---------------------------------------------------------------------
    def bad(name: str, description: str, rule: str, bundle_or_renewals, **options):
        evidence = bundle_or_renewals if isinstance(bundle_or_renewals, bytes) else with_renewals(*bundle_or_renewals)
        suite.add(name, description, "record", evidence, False, rule=rule, ledger_id=options.pop("ledger_id", f.id),
                  witnesses=options.pop("witnesses", [w_ed, w_pq]), **options)

    broken = renewal(f, n1, s["c2"], rotations=s["rotations"], cosignatures=[f.cosign(w_pq, c2_payload)],
                     consistency=[g.flip_first_bit(f.consistency(n1, n2)[0])] + f.consistency(n1, n2)[1:])
    bad("renewal-broken-consistency", "A renewal whose consistency proof has a flipped bit.", "11.1 check 1",
        [broken])
    moved = renewal(f, n1, s["c2"], rotations=s["rotations"], cosignatures=[f.cosign(w_pq, c2_payload)])
    moved[3][0][2] = f.merkle().path(s["rotations"][1], f.entries[:n2])
    bad("renewal-rotation-not-in-tree",
        "A renewal whose root key rotation comes with another entry's inclusion path: it is not proven in the "
        "renewal's tree.", "11.1 check 2", [moved])
    bad("renewal-rotation-left-out",
        "A renewal that leaves its rotations out: its checkpoint is signed by an ML-DSA-65 log key, and the log "
        "key in effect is still the Ed25519 one.", "11.1 check 3",
        [renewal(f, n1, s["c2"], cosignatures=[f.cosign(w_pq, c2_payload)])])
    small = f.checkpoint(n1 - 1)
    bad("renewal-smaller-than-previous",
        "A renewal whose checkpoint (size 5, signed by the log key then in effect) is smaller than the bundle's.",
        "11.1 check 1", [{1: small[0], 4: [f.cosign(w_ed, small[1])]}])
    wrong_key = f.checkpoint(n2, key=s["log1"])
    bad("renewal-wrong-log-key",
        "A renewal whose checkpoint of size 10 is signed by the Ed25519 log key, which the rotation it carries "
        "replaced.", "11.1 check 3",
        [renewal(f, n1, wrong_key, rotations=s["rotations"], cosignatures=[f.cosign(w_pq, wrong_key[1])])])
    other_payload = g.dcbor({1: f.id, 2: SHA256, 3: n2, 4: f.h(b"another root"), 5: c2[5] + es.DAY})
    other_root = f.sign(s["log2"], g.CHECKPOINT_TYPE, other_payload)[0]
    bad("renewal-repeat-other-root",
        "A second renewal at the first one's size whose root differs.", "11.1 check 1",
        [r1, {1: other_root, 4: [f.cosign(w_pq, other_payload)]}])
    bad("renewal-repeat-with-consistency",
        "A second renewal that repeats the first one's checkpoint and carries a consistency proof.", "11.1 check 1",
        [r1, {1: c2_signed, 2: [f.h(b"a hash")], 4: [f.cosign(w_pq, c2_payload)]}])
    bad("renewal-without-attestation",
        "A renewal with a checkpoint, its consistency proof, and its rotations, and no cosignature, token, or "
        "network cosignature.", "11.1, CDDL renewal",
        [{k: x for k, x in r1.items() if k != 4}])
    bad("renewal-cosignature-of-another-checkpoint",
        "A renewal whose trusted witness's cosignature is of the bundle's checkpoint, not of the renewal's.",
        "11.1 check 4", [renewal(f, n1, s["c2"], rotations=s["rotations"], cosignatures=[f.cosign(w_pq, c1_payload)])])
    early = renewal(f, n2, s["c2"], tokens=[ec_tsa.stamp(c2_payload, SHA256, EARLY_TOKEN_T)])
    bad("renewal-clock-rule",
        "A second renewal with a trusted token dated 2026-10-01, before the ledger dated the entries the "
        "renewal's checkpoint covers.", "11.1 check 4, 10.1", [r1, early], tsa_roots=[ec_tsa])
    x = archive("Forged Rotation Org", forged_log_rotation=True)
    xf = x["f"]
    x_c1_payload, x_c2_payload = x["c1"][1], x["c2"][1]
    xb = xf.bundle(x["record"], size=x["n1"], checkpoint=x["c1"], cosignatures=[xf.cosign(w_ed, x_c1_payload)])
    xb[11] = [renewal(xf, x["n1"], x["c2"], rotations=x["rotations"], cosignatures=[xf.cosign(w_pq, x_c2_payload)])]
    bad("renewal-rotation-wrong-root-key",
        "A renewal whose log key rotation is signed by the Ed25519 root key that the rotation before it "
        "replaced.", "11.1 check 2", es.enc(xb), ledger_id=xf.id)
    m = archive("SM3 Archive Org", hash_id=SM3)
    mf = m["f"]
    mb = mf.bundle(m["record"], size=m["n1"], checkpoint=m["c1"])
    mb[11] = [{1: m["c1"][0], 6: [nw_ed.cosign(mf.id, m["n1"], m["c1"][2], NETWORK_T)]}]
    bad("renewal-network-cosignature-sm3",
        "An SM3 ledger's bundle whose renewal (repeating its checkpoint) carries a network cosignature.",
        "11.1 check 4, 10.2", es.enc(mb), ledger_id=mf.id, witnesses=[])
    m_c2_signed, m_c2_payload, _ = m["c2"]
    mb[11] = [renewal(mf, m["n1"], m["c2"], rotations=m["rotations"], cosignatures=[mf.cosign(w_pq, m_c2_payload)],
                      tokens=[pq_tsa.stamp(m_c2_payload, SM3, TOKEN_T)])]
    suite.add("renewal-sm3-ledger",
              "An SM3 ledger's bundle renewed after the same two rotations, with an ML-DSA-65 witness's cosignature "
              "and an ML-DSA-65 authority's token over the renewal's checkpoint (its imprint under SM3): both are "
              "post-quantum attestations, and the token bounds when the bundle's entries existed.",
              "record", es.enc(mb), True, ledger_id=mf.id, witnesses=[w_pq], tsa_roots=[pq_tsa], facts={
                  "renewals": [renewal_fact(mb[11][0], m["log2"], log_rotations=1, root_rotations=1, trusted=1,
                                            tokens=[{**token_fact, "checkpoint_size": m["n2"]}])],
                  "long_term": long_term_fact(head_of(m_c2_signed), 1, [
                      witness_by(mf, w_pq),
                      {"kind": "timestamp", "by": pq_tsa.authority, "algorithm": "ml-dsa-65", "time": iso(TOKEN_T)}]),
                  "timestamps": {"trusted_authorities": 1, "tokens": [], "existed_by": iso(TOKEN_T + ACCURACY)},
                  "witnesses": {"trusted": 1, "untrusted": 0}})
    bad("distrust-cutoff-before-attestation",
        "renewal-repeated-checkpoint with Ed25519 distrusted from 2026-10-25: the network witness cosigned on "
        "2026-11-01, after that date, so it covers no Ed25519 signature.", "11.1, 11 step 12",
        [r1, r2], witness_vkeys=[nw_pq.vkey], distrust=["ed25519@2026-10-25"])
    bad("distrust-dated-witness-after-cutoff",
        "distrust-classical-covered-by-dated-witness with every classical algorithm distrusted from 2026-10-25: "
        "the witness dated its cosignature 2026-11-01, after that date, so it covers no Ed25519 signature.",
        "11.1, 11 step 12", [dated], distrust=["classical@2026-10-25"])
    for name, claims, what in (("renewal-dated-cosignature-other-claim", {1: "witness.example", 6: NETWORK_T},
                                "its CWT claims hold an issuer (1) beside iat"),
                               ("renewal-dated-cosignature-text-iat", {6: str(NETWORK_T)}, "its iat is text"),
                               ("renewal-dated-cosignature-negative-iat", {6: -1}, "its iat is negative")):
        bad(name, f"A renewal whose witness's cosignature is malformed: {what}.", "10, 11 step 6",
            [renewal(f, n1, s["c2"], rotations=s["rotations"],
                     cosignatures=[dated_cosign(f, w_pq, c2_payload, None, claims=claims)])])
    bad("distrust-cose-witness-only",
        "renewal-post-quantum-witness with Ed25519 distrusted from 2035-01-01: its COSE cosignature carries no "
        "time (no header 15), so the ML-DSA-65 witness covers no Ed25519 signature.", "11.1, 11 step 12", [r1],
        distrust=["ed25519@2035-01-01"])
    bad("distrust-classical-timestamp-set-aside",
        "distrust-covered-by-classical-timestamp with every classical algorithm distrusted from 2027-01-01: the "
        "ECDSA token is set aside, and nothing covers the Ed25519 signatures.", "11.1, 11 step 12",
        es.enc(ec_bundle), ledger_id=tf.id, witnesses=[], tsa_roots=[ec_tsa], distrust=["classical@2027-01-01"])
    for size, what in ((17, "fields"), (15, "fields")):
        y = es.Forge(f"Salt {size} Org")
        clerk = y.actor(PERSON, "Clerk", es.Key(f"salt {size} clerk"))
        d = y.grant(clerk, {1: [16]})
        y_rec = y.record(clerk, CERTIFICATE, delegation=d, fields={"holder": "Ho Wing"}, salt_size=size)
        y.commit()
        bad(f"salt-{size}-bytes-field", f"A disclosed field whose salt is {size} bytes, neither 16 nor 32.",
            "6, CDDL record-field", es.enc(y.bundle(y_rec, disclose=["holder"])), ledger_id=y.id, witnesses=[])
    y = es.Forge("Salt 17 Attachment Org")
    clerk = y.actor(PERSON, "Clerk", es.Key("salt 17 attachment clerk"))
    d = y.grant(clerk, {1: [16]})
    y_rec = y.record(clerk, CERTIFICATE, delegation=d, fields={"holder": "Ho Wing"}, salt_size=32,
                     attachments=[("scan.png", "image/png", b"\x89PNG a scan")], attachment_salt_size=17)
    y.commit()
    bad("salt-17-bytes-attachment", "An attachment opened with a 17-byte salt.", "6, CDDL attachment-opening",
        es.enc(y.bundle(y_rec, open_=["scan.png"])), ledger_id=y.id, witnesses=[],
        attachments={"scan.png": b"\x89PNG a scan"})
    return {"s": s, "r1": r1, "r2": r2}


# Cases also put in the conformance suite (testvectors/evidence-v1.json).
SUITE_CASES = ("renewal-post-quantum-witness", "renewal-repeated-checkpoint", "renewal-post-quantum-genesis",
               "renewal-sm3-ledger",
               "renewal-post-quantum-timestamp", "distrust-covered-by-network-witness", "salts-32-bytes",
               "renewal-broken-consistency", "renewal-rotation-not-in-tree", "renewal-smaller-than-previous",
               "renewal-wrong-log-key", "renewal-repeat-other-root", "distrust-cose-witness-only",
               "distrust-cutoff-before-attestation", "salt-17-bytes-field",
               "distrust-classical-covered-by-dated-witness", "distrust-dated-witness-after-cutoff",
               "renewal-dated-cosignature-other-claim", "renewal-dated-cosignature-text-iat")


def suite_cases(suite: es.Suite) -> None:
    """Adds the conformance cases of v0.21 to the suite (evidence_suite.py)."""
    mine = es.Suite()
    bundle_cases(mine)
    for case in mine.cases:
        if case["name"] in SUITE_CASES:
            suite.cases.append(case)


# ---------------------------------------------------------------------------
# Shapes: salts, renewals, and the distrust option
# ---------------------------------------------------------------------------

def salt_cases() -> dict:
    def leaf(salt) -> str:
        return g.dcbor(["holder", salt, "Chan Tai Man"]).hex()

    def opening(salt) -> str:
        return g.dcbor(["scan.png", salt]).hex()

    valid = [16, 32]
    refused = [(0, "empty"), (15, "15 bytes"), (17, "17 bytes"), (31, "31 bytes"), (33, "33 bytes"),
               (64, "64 bytes")]
    salt = hashlib.sha256(b"a salt").digest() * 2
    return {
        "field_leaves": {"valid": [{"leaf": leaf(salt[:n]), "salt_size": n} for n in valid],
                         "refused": [{"name": why, "leaf": leaf(salt[:n])} for n, why in refused]
                         + [{"name": "a salt as text", "leaf": leaf(salt[:16].hex())}]},
        "attachment_openings": {"valid": [{"opening": opening(salt[:n]), "salt_size": n} for n in valid],
                                "refused": [{"name": why, "opening": opening(salt[:n])} for n, why in refused]},
    }


def renewal_shape_cases(s: dict, r1: dict) -> dict:
    """Renewals that parse (the CDDL), and some that do not, each for its rule."""
    f = s["f"]
    cosig = r1[4][0]
    rotation = r1[3][0]
    base = {1: r1[1], 2: r1[2], 3: r1[3], 4: r1[4]}

    def w(**changes):
        out = dict(base)
        for k, v in changes.items():
            key = int(k[1:])
            if v is ...:
                out.pop(key)
            else:
                out[key] = v
        return out

    valid = [("a checkpoint with its proof, rotations, and a cosignature", base),
             ("a repeated checkpoint with a cosignature", {1: r1[1], 4: [cosig]}),
             ("a token alone", {1: r1[1], 5: [b"\x30\x00"]}),
             ("a network cosignature alone", {1: r1[1], 6: [["witness.example/x", bytes(12)]]}),
             ("every attestation", {1: r1[1], 4: [cosig], 5: [b"\x30\x00"], 6: [["witness.example/x", bytes(12)]]})]
    refused = [
        ("not a map", [r1[1], r1[4]]),
        ("an unknown key", w(k7=True)),
        ("no checkpoint", w(k1=...)),
        ("a checkpoint that is not a byte string", w(k1=[r1[1]])),
        ("no attestation", w(k4=...)),
        ("an empty consistency proof", w(k2=[])),
        ("a consistency proof with a 31-byte hash", w(k2=[r1[2][0][:31]] + r1[2][1:])),
        ("a consistency proof of 66 hashes", w(k2=[f.h(bytes([i])) for i in range(66)])),
        ("an empty list of rotations", w(k3=[])),
        ("a rotation that is not [index, entry, path]", w(k3=[rotation[:2]])),
        ("a rotation whose index is negative", w(k3=[[-1, rotation[1], rotation[2]]])),
        ("a rotation path with a 33-byte hash", w(k3=[[rotation[0], rotation[1], [bytes(33)]]])),
        ("an empty list of cosignatures", w(k4=[])),
        ("a cosignature that is not a byte string", w(k4=[[cosig]])),
        ("an empty list of tokens", {1: r1[1], 5: []}),
        ("a network cosignature with a name holding a space", {1: r1[1], 6: [["witness example", bytes(12)]]}),
        ("a network cosignature of 11 bytes", {1: r1[1], 6: [["witness.example/x", bytes(11)]]}),
    ]
    bundle_refused = [("an empty list of renewals", []), ("65 renewals", [{1: b"\x00", 4: [b"\x00"]}] * 65)]
    return {"valid": [{"name": n, "renewal": g.dcbor(r).hex()} for n, r in valid],
            "refused": [{"name": n, "renewal": g.dcbor(r).hex()} for n, r in refused],
            "bundle_lists_refused": [{"name": n, "renewals": g.dcbor(r).hex()} for n, r in bundle_refused]}


def distrust_option_cases() -> dict:
    valid = [
        ("ed25519@2035-01-01", {"ed25519": "2035-01-01T00:00:00.000Z"}),
        ("ml-dsa-44@2040-06-30", {"ml-dsa-44": "2040-06-30T00:00:00.000Z"}),
        ("classical@2035-01-01", {n: "2035-01-01T00:00:00.000Z" for n in CLASSICAL}),
    ]
    out_valid = [{"options": [text], "algorithms": [{"algorithm": a, "after": t} for a, t in m.items()]}
                 for text, m in valid]
    out_valid.append({"options": ["ml-dsa-65@2045-01-01", "ecdsa@2034-12-31"],
                      "algorithms": [{"algorithm": "ecdsa", "after": "2034-12-31T00:00:00.000Z"},
                                     {"algorithm": "ml-dsa-65", "after": "2045-01-01T00:00:00.000Z"}]})
    refused = [
        ("an unknown algorithm", ["esp256@2035-01-01"]),
        ("other, which only classical names", ["other@2035-01-01"]),
        ("no date", ["ed25519"]),
        ("a date that is none", ["ed25519@2035-02-30"]),
        ("a date with a time", ["ed25519@2035-01-01T00:00:00Z"]),
        ("upper case", ["Ed25519@2035-01-01"]),
        ("an algorithm twice", ["sm2@2035-01-01", "sm2@2036-01-01"]),
        ("an algorithm also named through classical", ["classical@2035-01-01", "rsa@2034-01-01"]),
    ]
    return {"valid": out_valid, "refused": [{"name": n, "options": o} for n, o in refused]}


def ledger_section(s: dict, r1: dict) -> dict:
    """The archive ledger's log, its two checkpoints, and what a server's
    renewal route answers from size 6 to size 10 (section 16), so that an
    implementation can build the same renewal from the same log."""
    f = s["f"]
    return {"name": f.name, "ledger_id": f.id.hex(), "hash": SHA256, "entries": [e.hex() for e in f.entries],
            "rotations": s["rotations"], "bundle_size": s["n1"], "checkpoints": [s["c1"][0].hex(), s["c2"][0].hex()],
            "renewal_from": s["n1"], "renewal_size": s["n2"], "consistency": [x.hex() for x in r1[2]],
            "rotation_proofs": [[i, e.hex(), [p.hex() for p in path]] for i, e, path in r1[3]]}


DESCRIPTION = (
    "Kanhe protocol v0.21 test vectors: long-term evidence (spec sections 6, 10, 11, 11.1, and 16). `salts`: field "
    "leaves and attachment openings whose salts are 16 or 32 bytes, and others, refused. `renewals`: renewal "
    "objects that parse, and refused ones (the CDDL `renewal`), and bundles' lists of renewals refused. "
    "`distrust_options`: `ALG@YYYY-MM-DD` options read, as the report's `distrust.algorithms` lists them, and "
    "refused (usage errors). `ledger`: a ledger with a classical genesis that rotates its root key and then its log "
    "key to ML-DSA-65, with its log, the checkpoints of sizes 6 and 10, and the renewal's parts a server answers "
    "from size 6 (consistency proof, rotations with their paths). `bundles`: evidence bundles, each with the options "
    "to verify it with (as testvectors/evidence-v1.json gives them: `ledger_id`, `witnesses` (hex public key files), "
    "`witness_vkeys`, `tsa_roots` (PEM), `attachments`, `distrust`), the verdict, for a failure the section and step "
    "that decide it, and for a verified bundle facts its JSON report must show, matched as in evidence-v1.json. "
    "Written by tools/testvectors/renewal_vectors.py from the specification with evidence_suite.py's forge and "
    "throwaway keys (seed = SHA-256(\"Kanhe test key: evidence <name>\")); time-stamp tokens are TSTInfos written "
    "there with chosen times, signed by `openssl cms -sign -cades` under ECDSA P-256 and ML-DSA-65 authorities; "
    "network cosignatures follow c2sp.org's texts; dated witness cosignatures carry RFC 9597's CWT claims with "
    "only iat. ML-DSA and ECDSA signatures differ from run to run; verdicts and "
    "facts do not.")


def generate(openssl: str = "openssl", splice: bool = False) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        es.Env.openssl, es.Env.work = openssl, pathlib.Path(tmp)
        suite = es.Suite()
        made = bundle_cases(suite)
        document = {"description": DESCRIPTION, "salts": salt_cases(),
                    "renewals": renewal_shape_cases(made["s"], made["r1"]),
                    "distrust_options": distrust_option_cases(),
                    "ledger": ledger_section(made["s"], made["r1"]), "bundles": suite.cases}
    OUT.write_text(json.dumps(document, indent=1, ensure_ascii=False) + "\n")
    verdicts = sum(1 for c in suite.cases if c["verified"])
    print(f"wrote {len(suite.cases)} bundles ({verdicts} verified) to testvectors/{OUT.name}")
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
    generate(parser.parse_args().openssl, splice=True)


if __name__ == "__main__":
    main()
