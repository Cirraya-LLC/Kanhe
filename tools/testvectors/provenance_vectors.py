# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya
"""Test vectors for specification revision v0.18 (where a record came from:
scripts and sources), built from spec/README.md (sections 5, 6, and 11) and
spec/kanhe.cddl with the independent encoder of generate.py. Writes
testvectors/protocol-v0.18.json.

Usage: python3 tools/testvectors/provenance_vectors.py
(generate.py runs it too.)
"""

from __future__ import annotations

import hashlib
import json

from cryptography.hazmat.primitives.asymmetric import ed25519

import generate as g

SCRIPT = "kanhe.script/1"
LOAN_BOOK = "example.org.loan-book/1"
REPORT = "example.org.report/1"
MECHANISM_TYPES_V18 = {**g.MECHANISM_TYPES_V16, SCRIPT: ("approved", set())}
SCRIPT_REQUIRED = ("name", "version", "files", "deterministic")
SCRIPT_OPTIONAL = ("runtime",)
NOT_YET, LIVE, REVOKED, REPLACED = "not_yet", "live", "revoked", "replaced"


def _text(v, low: int, high: int) -> bool:
    return isinstance(v, str) and low <= len(v.encode("utf-8")) <= high


def valid_path(path) -> bool:
    return _text(path, 1, 1024) and all(s not in ("", ".", "..") for s in path.split("/"))


def script_problem(metadata) -> str | None:
    """The one rule of the `script` CDDL and section 6 that `metadata`
    breaks, or None."""
    if not isinstance(metadata, dict):
        return "no metadata"
    if any(not isinstance(k, str) for k in metadata) or set(metadata) - set(SCRIPT_REQUIRED) - set(SCRIPT_OPTIONAL):
        return "unknown key"
    if any(k not in metadata for k in SCRIPT_REQUIRED):
        return "missing key"
    m = metadata
    if not _text(m["name"], 1, 128):
        return "name"
    if not _text(m["version"], 1, 64):
        return "version"
    if not (isinstance(m["files"], list) and 1 <= len(m["files"]) <= 256):
        return "files"
    previous = None
    for f in m["files"]:
        if not (isinstance(f, list) and len(f) == 3):
            return "file"
        path, size, digest = f
        if not valid_path(path):
            return "path"
        if not (isinstance(size, int) and not isinstance(size, bool) and size >= 0):
            return "size"
        if not (isinstance(digest, bytes) and len(digest) == 32):
            return "digest"
        if previous is not None and not previous.encode() < path.encode():
            return "order"
        previous = path
    if not isinstance(m["deterministic"], bool):
        return "deterministic"
    if "runtime" in m and not _text(m["runtime"], 1, 128):
        return "runtime"
    return None


def digest(content: bytes) -> bytes:
    return hashlib.sha256(content).digest()


def example_script() -> dict:
    """The specification's example: risk-model 3.2, two files."""
    return {"name": "risk-model", "version": "3.2",
            "files": [["model/weights.json", 48213, digest(b"weights")],
                      ["run.py", 1204, digest(b"run")]],
            "deterministic": True, "runtime": "python 3.12"}


def script_metadata_cases() -> tuple[list, list]:
    base = example_script()
    valid = [base,
             {"name": "a", "version": "1", "files": [["x", 0, bytes(32)]], "deterministic": False},
             {"name": "n" * 128, "version": "v" * 64,
              "files": [[f"f{i:03d}", i, digest(bytes([i % 256]))] for i in range(256)],
              "deterministic": False, "runtime": "r" * 128},
             {"name": "名字", "version": "二", "files": [["目录/文件.py", 1, bytes(32)], ["😀", 2, bytes(32)]],
              "deterministic": True}]
    file = base["files"][0]

    def with_(key, value):
        out = dict(base)
        out[key] = value
        return out

    def without(key):
        return {k: v for k, v in base.items() if k != key}

    def files(*entries):
        return with_("files", list(entries))

    refused = [
        ("not a map", ["risk-model"], "no metadata"),
        ("an unknown key", with_("entry", "run.py"), "unknown key"),
        ("a key that is not text", {**base, 1: "x"}, "unknown key"),
        ("no name", without("name"), "missing key"),
        ("no deterministic", without("deterministic"), "missing key"),
        ("an empty name", with_("name", ""), "name"),
        ("a name of 129 bytes", with_("name", "n" * 129), "name"),
        ("a version of 65 bytes", with_("version", "v" * 65), "version"),
        ("a version that is a number", with_("version", 3), "version"),
        ("no files", files(), "files"),
        ("257 files", files(*[[f"f{i:03d}", 1, bytes(32)] for i in range(257)]), "files"),
        ("files that are a map", with_("files", {"run.py": 1}), "files"),
        ("a file of two items", files(["run.py", 1]), "file"),
        ("an empty path", files(["", 1, bytes(32)]), "path"),
        ("an absolute path", files(["/run.py", 1, bytes(32)]), "path"),
        ("an empty segment", files(["model//run.py", 1, bytes(32)]), "path"),
        ("a path ending in /", files(["model/", 1, bytes(32)]), "path"),
        ("a . segment", files(["./run.py", 1, bytes(32)]), "path"),
        ("a .. segment", files(["model/../run.py", 1, bytes(32)]), "path"),
        ("a path of 1025 bytes", files(["a" * 1025, 1, bytes(32)]), "path"),
        ("a negative size", files(["run.py", -1, bytes(32)]), "size"),
        ("a size that is text", files(["run.py", "1", bytes(32)]), "size"),
        ("a digest of 31 bytes", files(["run.py", 1, bytes(31)]), "digest"),
        ("a digest that is text", files(["run.py", 1, "00" * 32]), "digest"),
        ("files out of order", files(base["files"][1], file), "order"),
        ("one path twice", files(file, file), "order"),
        ("deterministic as text", with_("deterministic", "yes"), "deterministic"),
        ("an empty runtime", with_("runtime", ""), "runtime"),
        ("a runtime of 129 bytes", with_("runtime", "r" * 129), "runtime"),
    ]
    out_valid = []
    for m in valid:
        assert script_problem(m) is None, m
        out_valid.append({"metadata": g.dcbor(m).hex(), "script": {
            "name": m["name"], "version": m["version"],
            "files": [{"path": p, "size": s, "digest": d.hex()} for p, s, d in m["files"]],
            "deterministic": m["deterministic"], "runtime": m.get("runtime")}})
    out_refused = []
    for name, m, why in refused:
        assert script_problem(m) == why, (name, script_problem(m), why)
        out_refused.append({"name": name, "metadata": g.dcbor(m).hex(), "why": why})
    return out_valid, out_refused


def source_status(registered: int, revoked, replaced, t: int) -> str:
    if t < registered:
        return NOT_YET
    if revoked is not None and revoked <= t:
        return REVOKED
    if replaced is not None and replaced <= t:
        return REPLACED
    return LIVE


def source_status_cases(t0: int) -> list:
    minute = 60_000
    out = []
    for registered, revoked, replaced in ((t0, None, None), (t0, t0 + 10 * minute, None),
                                          (t0, None, t0 + 5 * minute), (t0, t0 + 10 * minute, t0 + 5 * minute)):
        cases = [{"t": t, "status": source_status(registered, revoked, replaced, t)}
                 for t in (t0 - 1, t0, t0 + 5 * minute - 1, t0 + 5 * minute, t0 + 10 * minute, t0 + 20 * minute)]
        out.append({"registered": registered, "revoked": revoked, "replaced": replaced, "cases": cases})
    return out


def provenance_replay(t0: int) -> dict:
    """A bank's log, for each hash, replayed under the ledger rules (sections
    5 and 6), in the format of protocol-v0.16.json's ledgers."""
    names = ("org_root", "log", "person", "device", "passkey", "ukey")
    seeds = {name: hashlib.sha256(f"Kanhe test key: v0.18 {name}".encode()).hexdigest() for name in names}
    keys = {name: ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(seed)) for name, seed in seeds.items()}
    minute = 60_000
    exchange = hashlib.sha256(b"Example Exchange's ledger").digest()
    rate_table = hashlib.sha256(b"Example Exchange's rate table 2026-Q4").digest()

    ledgers = []
    for hash_id in (-16, -65538):
        lg = g.Ledger(hash_id)
        statements, refused, malformed = [], [], []
        actors, delegations, records = {}, {}, {}
        kinds = {}  # actor id -> kind (1 person, 2 agent, 3 device; None the organization)
        clock = [t0 + 1000]
        counter = [0]

        def payload(signer_actor, body_type, body, delegation=None, script=None):
            counter[0] += 1
            out = {0: 1, 1: body_type, 5: clock[0] - 500, 6: counter[0].to_bytes(16, "big"), 7: body}
            if signer_actor is not None:  # absent only in genesis
                out[2] = ledger_id
                out[3] = signer_actor
            if delegation is not None:
                out[4] = delegation
            if script is not None:
                out[9] = {5: script}
            return out

        def with_ukey(p):
            """Proof of presence with the person's hardware key: user-verified."""
            challenge = lg.h(b"Kanhe presence v1" + lg.kid(keys["person"]) + g.dcbor(p))
            p[8] = {1: ukey_id, 4: keys["ukey"].sign(challenge)}
            return p

        def with_passkey(p, verified):
            """A passkey's assertion: user-verified (flags 0x05) or present only (0x01)."""
            challenge = lg.h(b"Kanhe presence v1" + lg.kid(keys["person"]) + g.dcbor(p))
            authenticator_data = hashlib.sha256(b"localhost").digest() + bytes([0x05 if verified else 0x01]) + \
                (counter[0]).to_bytes(4, "big")
            client_data = ('{"type":"webauthn.get","challenge":"' + g.b64url(challenge) +
                           '","origin":"http://localhost:43210","crossOrigin":false}').encode()
            signature = keys["passkey"].sign(authenticator_data + hashlib.sha256(client_data).digest())
            p[8] = {1: passkey_id, 2: authenticator_data, 3: client_data, 4: signature}
            return p

        def rules(p) -> list:
            """Every rule of section 5 that refuses these statements: the
            v0.18 rules for scripts and sources, and the record rules they
            meet (versions, endorsements, revocations). The signers are
            always authorized by their scopes."""
            body, fails = p[7], []
            provenance = p.get(9, {})
            if 5 in provenance:
                script = records.get(provenance[5])
                if script is None:
                    fails.append("no such script")
                elif script["type"] != SCRIPT:
                    fails.append("not a script")
                elif script["revoked"]:
                    fails.append("withdrawn")
            if p[1] == 16:
                kind = body[1]
                if kind == SCRIPT:
                    # A hardware key's proof is user-verified; a passkey's when its
                    # authenticator data's UV flag (0x04) is set.
                    present = 8 in p and (p[8][1] == ukey_id or (2 in p[8] and bool(p[8][2][32] & 0x04)))
                    if kinds.get(p[3]) != 1 or not present:
                        fails.append("in person")
                    problem = script_problem(body.get(5))
                    if problem is not None:
                        fails.append(problem)
                if 7 in body:
                    if kind in MECHANISM_TYPES_V18:
                        fails.append("mechanism")
                    for source_ledger, source in body[7]:
                        if source_ledger != ledger_id:
                            continue
                        r = records.get(source)
                        if r is None:
                            fails.append("no such source")
                        elif r["type"] in MECHANISM_TYPES_V18:
                            fails.append("mechanism source")
                        elif r["revoked"]:
                            fails.append("revoked source")
                        elif r["superseded_by"] is not None:
                            fails.append("superseded source")
                if 6 in body:
                    old = records.get(body[6])
                    if kind in MECHANISM_TYPES_V18 or old is None or old["type"] in MECHANISM_TYPES_V18:
                        fails.append("mechanism")
                    elif old["superseded_by"] is not None:
                        fails.append("superseded")
                return fails
            if p[1] in (17, 19):
                record = records.get(body[1])
                if record is None:
                    return fails + ["no such record"]
                if record["revoked"]:
                    fails.append("revoked")
                if p[1] == 17 and record["type"] in MECHANISM_TYPES_V18:
                    fails.append("role")
            return fails

        def add(name, signer, p):
            assert rules(p) == [], (name, rules(p))
            encoded, statement_id = lg.statement(keys[signer], p)
            index, now = len(statements), clock[0]
            statements.append({"name": name, "signer": signer, "encoded": encoded.hex(), "payload": g.dcbor(p).hex(),
                               "statement_id": statement_id.hex(), "registered_at": now})
            clock[0] += minute
            body = p[7]
            if p[1] in (1, 2):
                actors[statement_id] = [index]
                kinds[statement_id] = None if p[1] == 1 else body[1]
            elif p[1] == 7:
                actors[body[1]].append(index)
            elif p[1] == 5:
                delegations[statement_id] = [index]
            elif p[1] == 16:
                kind = body[1]
                initial = MECHANISM_TYPES_V18[kind][0] if kind in MECHANISM_TYPES_V18 else "registered"
                records[statement_id] = {"type": kind, "state": initial, "revoked": False, "history": [index],
                                         "registrant": p[3], "supersedes": body.get(6), "superseded_by": None,
                                         "registered_at": now, "sources": body.get(7, []),
                                         "script": body[5] if kind == SCRIPT else None,
                                         "provenance": p.get(9, {}).get(5)}
                if 6 in body:
                    old = records[body[6]]
                    old["superseded_by"] = statement_id
                    old["history"].append(index)
            elif p[1] in (17, 19):
                # Sources' and scripts' histories do not change when a record
                # names them: a revocation is a statement about its record.
                record = records[body[1]]
                record["history"].append(index)
                if p[1] == 19:
                    record["revoked"] = True
            return statement_id

        def refuse(name, signer, p, why):
            assert rules(p) == [why], (name, rules(p), why)
            encoded, _ = lg.statement(keys[signer], p)
            refused.append({"name": name, "signer": signer, "encoded": encoded.hex(), "payload": g.dcbor(p).hex(),
                            "after": len(statements), "at": clock[0], "why": why})

        def unparsable(name, signer, p, why):
            """A statement whose payload does not decode (the CDDL's sizes and
            uniqueness are decoding rules)."""
            encoded, _ = lg.statement(keys[signer], p)
            malformed.append({"name": name, "encoded": encoded.hex(), "why": why})

        def fields(*values):
            leaves = [g.dcbor([name, bytes([0xD0 + i]) * 16, value])
                      for i, (name, value) in enumerate(sorted(values, key=lambda f: f[0].encode()))]
            return lg.merkle().mth(leaves), len(leaves)

        def script_body(metadata, sources=None):
            root, count = fields(("approver", "Chan Tai Man"), ("note", "model validated by the risk committee"))
            body = {1: SCRIPT, 2: root, 3: count}
            if metadata is not None:
                body[5] = metadata
            if sources is not None:
                body[7] = sources
            return body

        def record_body(kind, text, sources=None, supersedes=None):
            root, count = fields(("text", text),)
            body = {1: kind, 2: root, 3: count}
            if supersedes is not None:
                body[6] = supersedes
            if sources is not None:
                body[7] = sources
            return body

        ledger_id = None
        ledger_id = add("genesis", "org_root", payload(None, 1, {
            1: hash_id, 2: "Example Bank", 3: g.ed_public(keys["org_root"]), 4: g.ed_public(keys["log"])}))
        org = ledger_id
        kinds[org] = None
        person = add("register the risk officer, a person", "org_root", payload(org, 2, {
            1: 1, 2: "Chan Tai Man", 3: g.ed_public(keys["person"])}))
        passkey_id = bytes(range(16))
        ukey_id = hashlib.sha256(g.dcbor(g.ed_public(keys["ukey"]))).digest()
        add("register the officer's passkey and hardware key", "org_root", payload(org, 7, {1: person, 2: [
            {1: "localhost", 2: passkey_id, 3: g.ed_public(keys["passkey"]), 4: "officer's passkey"},
            {2: ukey_id, 3: g.ed_public(keys["ukey"]), 4: "officer's UKey", 5: 2}]}))
        officer = add("delegate scripts, loan books, and reports to the officer", "org_root", payload(org, 5, {
            1: person, 2: {1: [16, 19], 2: sorted([SCRIPT, LOAN_BOOK, REPORT], key=str.encode)}}))
        device = add("register the risk engine, a device", "org_root", payload(org, 2, {
            1: 3, 2: "Risk Engine", 3: g.ed_public(keys["device"])}))
        engine = add("delegate loan books and reports to the risk engine", "org_root", payload(org, 5, {
            1: device, 2: {1: [16], 2: sorted([LOAN_BOOK, REPORT], key=str.encode)}}))

        # A script is approved by a person in person, user-verified.
        s1 = add("the officer approves risk-model 3.2 with the hardware key", "person",
                 with_ukey(payload(person, 16, script_body(example_script()), officer)))
        refuse("approve a script without proof of presence", "person",
               payload(person, 16, script_body(example_script()), officer), "in person")
        refuse("approve a script with a passkey that did not verify the person", "person",
               with_passkey(payload(person, 16, script_body(example_script()), officer), verified=False), "in person")
        refuse("the organization approves a script (no person)", "org_root",
               payload(org, 16, script_body(example_script())), "in person")
        refuse("a script whose metadata has an unknown key", "person",
               with_ukey(payload(person, 16, script_body({**example_script(), "entry": "run.py"}), officer)),
               "unknown key")
        refuse("a script whose files are out of order", "person",
               with_ukey(payload(person, 16, script_body({**example_script(), "files": list(reversed(
                   example_script()["files"]))}), officer)), "order")
        refuse("a script without metadata", "person",
               with_ukey(payload(person, 16, script_body(None), officer)), "no metadata")

        # Records made by the script, from their sources.
        l1 = add("the risk engine registers the November loan book", "device",
                 payload(device, 16, record_body(LOAN_BOOK, "loan book 2026-11"), engine))
        refuse("a script that names sources", "person",
               with_ukey(payload(person, 16, script_body(example_script(), [[ledger_id, l1]]), officer)), "mechanism")
        r1 = add("the risk engine registers the monthly report, by the script, from the loan book and the exchange's "
                 "rate table", "device", payload(device, 16, record_body(
                     REPORT, "risk report 2026-12", sources=[[ledger_id, l1], [exchange, rate_table]]), engine,
                     script=s1))
        refuse("a report naming a loan book as its script", "device",
               payload(device, 16, record_body(REPORT, "risk report"), engine, script=l1), "not a script")
        refuse("a report naming a script that does not exist", "device",
               payload(device, 16, record_body(REPORT, "risk report"), engine, script=lg.h(b"no such script")),
               "no such script")
        refuse("a report from a local source that does not exist", "device",
               payload(device, 16, record_body(REPORT, "risk report", sources=[[ledger_id, lg.h(b"no record")]]),
                       engine), "no such source")
        refuse("a report from the script as its source (a mechanism type)", "device",
               payload(device, 16, record_body(REPORT, "risk report", sources=[[ledger_id, s1]]), engine),
               "mechanism source")
        refuse("the organization endorses the script", "org_root", payload(org, 17, {1: s1, 2: "reviewer"}), "role")

        # A replaced source and a revoked one are refused when a record is made.
        l2 = add("the risk engine registers the December loan book", "device",
                 payload(device, 16, record_body(LOAN_BOOK, "loan book 2026-12 v1"), engine))
        l3 = add("and a corrected version of it", "device",
                 payload(device, 16, record_body(LOAN_BOOK, "loan book 2026-12 v2", supersedes=l2), engine))
        refuse("a report from the replaced December book", "device",
               payload(device, 16, record_body(REPORT, "risk report", sources=[[ledger_id, l2]]), engine),
               "superseded source")
        add("the organization revokes the November loan book: a figure was wrong", "org_root",
            payload(org, 19, {1: l1, 2: "a figure was wrong"}))
        refuse("a report from the revoked November book", "device",
               payload(device, 16, record_body(REPORT, "risk report", sources=[[ledger_id, l1]]), engine),
               "revoked source")
        r2 = add("the risk engine registers another report from the corrected book, by the script", "device",
                 payload(device, 16, record_body(REPORT, "risk report 2026-12 v2", sources=[[ledger_id, l3]]), engine,
                         script=s1))

        # A withdrawn script makes nothing more.
        add("the officer withdraws risk-model 3.2", "person", payload(person, 19, {1: s1, 2: "superseded by 3.3"},
                                                                      officer))
        refuse("a report by the withdrawn script", "device",
               payload(device, 16, record_body(REPORT, "risk report"), engine, script=s1), "withdrawn")
        refuse("withdraw it again", "person", payload(person, 19, {1: s1}, officer), "revoked")
        s2 = add("the officer approves risk-model 3.3 with a passkey that verified them", "person",
                 with_passkey(payload(person, 16, script_body({**example_script(), "version": "3.3"}), officer),
                              verified=True))

        # Statements that do not parse: the CDDL's sizes and uniqueness.
        unparsable("a source list that is empty", "device",
                   payload(device, 16, record_body(REPORT, "x", sources=[]), engine), "empty sources")
        unparsable("a source named twice", "device",
                   payload(device, 16, record_body(REPORT, "x", sources=[[ledger_id, l3], [ledger_id, l3]]), engine),
                   "source twice")
        unparsable("65 sources", "device", payload(device, 16, record_body(
            REPORT, "x", sources=[[exchange, lg.h(bytes([i]))] for i in range(65)]), engine), "too many sources")
        unparsable("a source of three items", "device", payload(device, 16, record_body(
            REPORT, "x", sources=[[ledger_id, l3, 1]]), engine), "source shape")
        unparsable("a source whose record is 31 bytes", "device", payload(device, 16, record_body(
            REPORT, "x", sources=[[ledger_id, l3[:31]]]), engine), "source shape")
        bad = payload(device, 16, record_body(REPORT, "x"), engine)
        bad[9] = {5: s2[:31]}
        unparsable("a provenance script of 31 bytes", "device", bad, "script id")
        bad = payload(device, 16, record_body(REPORT, "x"), engine)
        bad[9] = {6: s2}
        unparsable("a provenance key the CDDL does not name", "device", bad, "provenance key")

        entries = [g.encode_log_entry(bytes.fromhex(st["statement_id"]), st["registered_at"],
                                      bytes.fromhex(st["encoded"])) for st in statements]
        leaves = [[1, a, h] for a, h in actors.items()] + [[2, d, h] for d, h in delegations.items()] + \
                 [[3, r, v["history"]] for r, v in records.items()]
        sorted_leaves = sorted(leaves, key=lambda leaf: leaf[1])
        commitment_index = len(entries)
        commitment_time = clock[0]
        commitment_id = g.append_state_commitment(lg, keys["log"], ledger_id, entries, sorted_leaves,
                                                  commitment_time)
        checkpoint_time = commitment_time + 1000
        checkpoint, _ = g.sign_log_checkpoint(lg, keys["log"], ledger_id, entries, checkpoint_time)

        def script_json(m):
            return {"name": m["name"], "version": m["version"],
                    "files": [{"path": p, "size": s, "digest": d.hex()} for p, s, d in m["files"]],
                    "deterministic": m["deterministic"], "runtime": m.get("runtime")}

        ledgers.append({
            "hash": hash_id,
            "ledger_id": ledger_id.hex(),
            "statements": statements,
            "refused": refused,
            "malformed": malformed,
            "scripts": [s1.hex(), s2.hex()],
            "reports": [r1.hex(), r2.hex()],
            "records": [{"id": r.hex(), "type": v["type"], "state": v["state"], "revoked": v["revoked"],
                         "registrant": v["registrant"].hex(), "history": v["history"],
                         "supersedes": v["supersedes"].hex() if v["supersedes"] else None,
                         "superseded_by": v["superseded_by"].hex() if v["superseded_by"] else None,
                         "sources": [[a.hex(), b.hex()] for a, b in v["sources"]],
                         "provenance_script": v["provenance"].hex() if v["provenance"] else None,
                         "script": script_json(v["script"]) if v["script"] is not None else None}
                        for r, v in records.items()],
            "log_entries": [e.hex() for e in entries],
            "state_leaves": [{"kind": leaf[0], "id": leaf[1].hex(), "history": leaf[2]} for leaf in sorted_leaves],
            "state_root": g.smt_root(lg, sorted_leaves).hex(),
            "state_commitment": {"index": commitment_index, "id": commitment_id.hex()},
            "checkpoint": checkpoint.hex(),
            "checkpoint_time": checkpoint_time,
        })
    return {"t0": t0, "seeds": seeds, "ledgers": ledgers}


def generate() -> None:
    t0 = 1_794_700_800_000  # 2026-11-15T00:00:00Z
    valid, refused = script_metadata_cases()
    statuses = source_status_cases(t0)
    replay = provenance_replay(t0)

    def lifecycle(kind):
        initial, transitions = MECHANISM_TYPES_V18[kind]
        ordered = g.MEMBERSHIP_TRANSITIONS if kind == g.MEMBERSHIP else sorted(transitions)
        return {"type": kind, "initial": initial, "transitions": [list(t) for t in ordered]}

    document = {
        "description": "Kanhe protocol objects of specification revision v0.18 (where a record came from: scripts "
                       "and sources), built by an independent Python encoder (tools/testvectors/"
                       "provenance_vectors.py, with generate.py's) from spec/README.md (sections 5, 6, and 11) and "
                       "spec/kanhe.cddl. Times are milliseconds since the epoch. `mechanism_types` lists the seven "
                       "mechanism types in the specification's table order. `script_metadata` holds script metadata "
                       "(record key 5 of a kanhe.script/1 record) on its own: `valid` cases, each its deterministic "
                       "CBOR and its values (digests in hex, runtime null when absent), the specification's example "
                       "first; `refused` cases, each breaking the one rule that `why` names: \"no metadata\" (not a "
                       "map), \"unknown key\", \"missing key\", and the key or file part whose rule is broken: "
                       "\"name\", \"version\", \"files\" (not 1 to 256), \"file\" (not [path, size, digest]), "
                       "\"path\", \"size\", \"digest\" (not 32 bytes), \"order\" (paths not strictly ascending by "
                       "bytes), \"deterministic\", \"runtime\". `source_statuses` holds where a source stood at "
                       "given times (section 11, step 10): its registration time, when it was revoked and replaced "
                       "(null if never), and cases of a time `t` and the status then: \"not_yet\", \"revoked\", "
                       "\"replaced\", or \"live\", in that order of precedence. `replay` holds a bank's log for each "
                       "hash, in the format of protocol-v0.16.json's ledgers: the organization (Example Bank) "
                       "registers a person with a passkey and a hardware key (user-verified) and a device, and "
                       "delegates to each; the person approves scripts in person; the device registers records "
                       "naming a script in their provenance (key 5) and sources (key 7), on this ledger and "
                       "another. `refused` statements are validated against the state after the first `after` "
                       "statements, at `at`, and break exactly one rule, which `why` names: \"in person\" (a "
                       "script's registration without a person's user-verified proof of presence), the script "
                       "metadata rules above, \"mechanism\" (a mechanism type names sources), \"not a script\", "
                       "\"no such script\", \"withdrawn\" (provenance naming a record that is not a script, none, "
                       "or a revoked script), \"no such source\", \"mechanism source\", \"superseded source\", "
                       "\"revoked source\" (a local source missing, of a mechanism type, superseded, or revoked), "
                       "\"role\" (a script takes no endorsement), \"revoked\" (a revoked record takes nothing "
                       "more). `malformed` statements do not parse, for the CDDL rule `why` names. A registration "
                       "is a statement about its own record only: a source's and a script's histories do not change "
                       "when a record names them. `records` gives each record's type, state, revocation, "
                       "registrant, history, versions, sources (ledger and record ids), the script its "
                       "registration's provenance names, and, for a script, its values. `log_entries` holds the "
                       "whole log, ending with the state commitment over `state_leaves`; `checkpoint` (signed at "
                       "`checkpoint_time`) covers it; keys are seed = SHA-256(\"Kanhe test key: v0.18 <name>\"), "
                       "`seeds`. Evidence bundles with scripts and sources are made by the reference "
                       "implementation's tests, which both verifiers must report alike.",
        "mechanism_types": [lifecycle(kind) for kind in MECHANISM_TYPES_V18],
        "script_metadata": {"valid": valid, "refused": refused},
        "source_statuses": statuses,
        "replay": replay,
    }
    (g.OUT / "protocol-v0.18.json").write_text(json.dumps(document, indent=1, ensure_ascii=False) + "\n")
    first = replay["ledgers"][0]
    reasons = sorted({r["why"] for r in first["refused"]})
    print(f"wrote protocol vectors to testvectors/protocol-v0.18.json: {len(valid)} script metadata, "
          f"{len(refused)} refused; {len(statuses)} source histories; {len(replay['ledgers'])} ledgers of "
          f"{len(first['statements'])} statements, {len(first['refused'])} refused ({', '.join(reasons)}), "
          f"{len(first['malformed'])} malformed")


if __name__ == "__main__":
    generate()
