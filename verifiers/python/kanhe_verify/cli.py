# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya
"""The command line, mirroring the reference implementation's two commands:

    python3 -m kanhe_verify BUNDLE [options]             as `kanhe verify`
    python3 -m kanhe_verify contract FILE [options]      as `kanhe contract verify`
    python3 -m kanhe_verify credential FILE [options]    as `kanhe credential verify --offline`

Exit codes, as those commands use them: 0 verified, 1 usage error, 2 an
input file could not be read (or an output file written), 3 not verified.
"""

from __future__ import annotations

import argparse
import json
import sys

from . import cbor, contract_report, credentials, crypto, longterm, network, ranges, report, timestamps
from .contract_evidence import verify_contract_evidence
from .errors import UsageError, VerifyError
from .evidence import verify_bundle

EXIT_VERIFIED, EXIT_USAGE, EXIT_INPUT, EXIT_NOT_VERIFIED = 0, 1, 2, 3
EPILOG = "Exit codes: 0 verified, 1 usage error, 2 an input file could not be read, 3 not verified."


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        self.print_usage(sys.stderr)
        print(f"usage error: {message}", file=sys.stderr)
        sys.exit(EXIT_USAGE)


def _common(p: argparse.ArgumentParser, issuer: str):
    p.add_argument("--ledger-id", metavar="HEX", help=f"the {issuer}'s ledger id (64 hex digits), learned out of band")
    p.add_argument("--witness", metavar="PUBKEY_FILE", action="append", default=[],
                   help="trust this witness's public key file (CBOR [alg, key]) [repeatable]")
    p.add_argument("--witness-vkey", metavar="VKEY", action="append", default=[],
                   help="trust this open network's witness, by its verifier key, <name>+<key ID>+<key> of "
                        "signature type 0x04 (Ed25519) or 0x06 (ML-DSA-44) (spec section 10.2); it counts toward "
                        "--min-witnesses [repeatable]")
    p.add_argument("--min-witnesses", metavar="N", type=int, default=0,
                   help="fail unless at least N trusted witnesses cosigned")
    p.add_argument("--tsa-root", metavar="CERT_FILE", action="append", default=[],
                   help="trust time-stamp authorities under this root certificate (PEM or DER) [repeatable]")
    p.add_argument("--min-timestamps", metavar="N", type=int, default=0,
                   help="fail unless at least N trusted time-stamp authorities stamped it")
    p.add_argument("--trust-node", metavar="LEDGER=NAME", action="append", default=[],
                   help="believe this trust node's memberships (spec v0.16, section 11): its ledger id (64 hex "
                        "digits) and the name to call it by, which the report gives it; a membership proof from "
                        "any other ledger is reported and relied on for nothing [repeatable]")
    p.add_argument("--distrust", metavar="ALG@YYYY-MM-DD", action="append", default=[],
                   help="distrust an algorithm from a date (spec v0.21, section 11.1): ed25519, ecdsa, sm2, rsa, "
                        "ml-dsa-44, ml-dsa-65, ml-dsa-87, or classical (every one but ML-DSA). Attestations by it "
                        "are relied on for nothing, and every signature by it must be in a tree that a trusted "
                        "time-stamp token, network witness's cosignature, or dated witness cosignature, by an "
                        "algorithm not distrusted, dated before that date, attested [repeatable]")


def _bundle_parser() -> argparse.ArgumentParser:
    p = _Parser(
        prog="python3 -m kanhe_verify",
        description="Verify a Kanhe evidence bundle about a record or an instance, offline, independently of "
                    "the reference implementation (spec section 11). For an instance's contract evidence, with "
                    "its consents and every call's outcome, use: python3 -m kanhe_verify contract FILE.",
        epilog=EPILOG)
    p.add_argument("bundle", metavar="BUNDLE", help="the evidence bundle (CBOR)")
    _common(p, "issuer")
    p.add_argument("--attachment", metavar="NAME=FILE", action="append", default=[],
                   help="check an attachment's content [repeatable]")
    p.add_argument("--range-helper", metavar="PROGRAM",
                   help="the program that does range proofs' arithmetic for system 1 (spec v0.22, section 11.3), "
                        "such as kanhe-range: PROGRAM verify reads JSON on its standard input; without it, range "
                        "proofs are reported as not checked and relied on for nothing")
    p.add_argument("--range-context", metavar="HEX",
                   help="require every range proof to carry this context, a challenge you gave the prover (1 to "
                        "64 bytes in hex): a proof without it, or with another, fails (spec v0.22, section 11.3)")
    p.add_argument("--json", action="store_true", help="print machine-readable JSON")
    return p


def _contract_parser() -> argparse.ArgumentParser:
    p = _Parser(
        prog="python3 -m kanhe_verify contract",
        description="Verify an instance's contract evidence offline (spec section 15): replay its calls, running "
                    "the contract again on each, check every consent a call cites on the consenting party's own "
                    "ledger, and derive the requests the calls made with their answers. A Bo contract's source "
                    "is not rebuilt here: the code is checked as run (--deploy-out writes the deploy, for bo "
                    "rebuild).",
        epilog=EPILOG)
    p.add_argument("evidence", metavar="FILE", help="the contract evidence (CBOR)")
    _common(p, "home")
    p.add_argument("--require-presence", action="store_true",
                   help="fail unless a person proved presence for each consent")
    p.add_argument("--require-answered", action="store_true",
                   help="fail if a request is still open past its deadline at the checkpoint's time")
    p.add_argument("--deploy-out", metavar="FILE", help="write the deploy the evidence carries here, as a deploy file")
    p.add_argument("--json", action="store_true", help="print machine-readable JSON")
    return p


def _credential_parser() -> argparse.ArgumentParser:
    p = _Parser(
        prog="python3 -m kanhe_verify credential",
        description="Verify a W3C Verifiable Credential issued from a Kanhe record (spec/credentials.md, "
                    "section 7): the credential, and the record behind it in its evidence bundle; with the "
                    "issuer's DID document and status list when given. Offline: nothing is fetched.",
        epilog=EPILOG)
    p.add_argument("credential", metavar="FILE", help="the credential (a compact JWS)")
    p.add_argument("--evidence", metavar="BUNDLE", required=True, help="the record's evidence bundle (CBOR)")
    p.add_argument("--did-document", metavar="FILE", help="the issuer's DID document (JSON)")
    p.add_argument("--status-list", metavar="FILE", help="the status list credential (a compact JWS)")
    p.add_argument("--ledger-id", metavar="HEX", help="the issuer's ledger id (64 hex digits), learned out of band")
    p.add_argument("--witness", metavar="PUBKEY_FILE", action="append", default=[],
                   help="trust this witness's public key file (CBOR [alg, key]) [repeatable]")
    p.add_argument("--json", action="store_true", help="print machine-readable JSON")
    return p


def _credential_main(argv: list[str]) -> int:
    args = _credential_parser().parse_args(argv)
    try:
        ledger_id = _ledger_id(args.ledger_id)
    except UsageError as e:
        print(f"usage error: {e}", file=sys.stderr)
        return EXIT_USAGE
    try:
        # A file's line ends are not part of the credential (`kanhe credential verify` too).
        compact = _read(args.credential).decode("utf-8", "replace").rstrip("\r\n")
        bundle = _read(args.evidence)
        # As read: its bytes are part of what is checked (UTF-8, size).
        did = _read(args.did_document) if args.did_document else None
        lst = _read(args.status_list).decode("utf-8", "replace") if args.status_list else None
        witnesses = [_witness_key(path) for path in args.witness]
    except UsageError as e:
        print(f"error: {e}", file=sys.stderr)
        return EXIT_INPUT
    try:
        result = credentials.verify_credential(compact, bundle, did_document=did, status_list=lst,
                                               ledger_id=ledger_id, witnesses=witnesses)
    except VerifyError as e:
        return _not_verified(args, e)
    document = credentials.to_json(result)
    if args.json:
        print(json.dumps(document, indent=2, ensure_ascii=False))
    else:
        print(credentials.to_text(result))
    return EXIT_VERIFIED if result.verified else EXIT_NOT_VERIFIED


def _read(path: str) -> bytes:
    try:
        with open(path, "rb") as f:
            return f.read()
    except OSError as e:
        raise UsageError(f"cannot read {path}") from e


def _witness_key(path: str) -> crypto.PublicKey:
    data = _read(path)
    try:
        return crypto.parse_public_key(cbor.decode(data), f"the witness key in {path}")
    except VerifyError as e:
        raise UsageError(f"{path} is not a public key file: {e}") from e


def _witness_vkeys(texts: list[str]) -> list:
    keys = []
    for text in texts:
        try:
            key = network.parse_witness_key(text)
        except VerifyError as e:
            raise UsageError(f"--witness-vkey takes a network witness's verifier key: {e} ({text!r})") from e
        if key not in keys:
            keys.append(key)
    return keys


def _trust_nodes(items: list[str]) -> dict:
    """--trust-node LEDGER=NAME: a full ledger id and a non-empty name; a
    ledger named twice is a usage error."""
    nodes = {}
    for item in items:
        text, sep, name = item.partition("=")
        try:
            ledger = bytes.fromhex(text) if len(text) == 64 else b""
        except ValueError:
            ledger = b""
        if not sep or len(ledger) != 32 or not name:
            raise UsageError(f"--trust-node takes LEDGER=NAME, a full ledger id (64 hex digits) and a name ({item!r})")
        if ledger in nodes:
            raise UsageError(f"--trust-node names the ledger {text} twice")
        nodes[ledger] = name
    return nodes


def _ledger_id(text: str | None) -> bytes | None:
    if text is None:
        return None
    try:
        value = bytes.fromhex(text)
    except ValueError:
        value = b""
    if len(value) != 32:
        raise UsageError("--ledger-id takes a full ledger id, 64 hex digits")
    return value


def _not_verified(args, error: VerifyError) -> int:
    if args.json:
        print(json.dumps({"verified": False, "error": str(error)}, indent=2, ensure_ascii=False))
    else:
        print(f"VERIFICATION FAILED: {error}")
    return EXIT_NOT_VERIFIED


def _finish(args, document: dict, text: str, failure: str | None) -> int:
    """Prints the full report, failed by what the verifier was asked to
    require beside the evidence, if anything."""
    if failure is not None:
        document["verified"] = False
        document["error"] = failure
    if args.json:
        print(json.dumps(document, indent=2, ensure_ascii=False))
    else:
        print(text)
        if failure is not None:
            print(f"\nVERIFICATION FAILED: {failure}")
    return EXIT_NOT_VERIFIED if failure is not None else EXIT_VERIFIED


def _required(result, args, range_context: bytes | None = None) -> str | None:
    """--min-witnesses and --min-timestamps, on a bundle's report; and, with
    --range-context (v0.22), every range proof's context."""
    if result.witnesses_trusted < args.min_witnesses:
        return f"{result.witnesses_trusted} trusted witness cosignatures, {args.min_witnesses} required"
    if result.trusted_authorities < args.min_timestamps:
        return f"{result.trusted_authorities} trusted time-stamp authorities, {args.min_timestamps} required"
    if range_context is not None:
        for r in result.range_proofs:
            if r.context is None:
                return (f"the range proof of {r.field!r} carries no context, and the context {range_context.hex()} "
                        "is required")
            if r.context != range_context:
                return (f"the range proof of {r.field!r} carries the context {r.context.hex()}, not the required "
                        f"{range_context.hex()}")
    return None


def _range_context(text: str | None) -> bytes | None:
    if text is None:
        return None
    try:
        value = bytes.fromhex(text)
    except ValueError:
        value = b""
    if not 1 <= len(value) <= ranges.MAX_CONTEXT or len(text) != 2 * len(value):
        raise UsageError("--range-context takes 1 to 64 bytes in hex")
    return value


def _bundle_main(argv: list[str]) -> int:
    args = _bundle_parser().parse_args(argv)
    contents = {}
    for item in args.attachment:
        name, sep, path = item.partition("=")
        if not sep or not name or not path:
            print("usage error: --attachment takes NAME=FILE", file=sys.stderr)
            return EXIT_USAGE
        contents[name] = path
    try:
        ledger_id = _ledger_id(args.ledger_id)
        vkeys = _witness_vkeys(args.witness_vkey)
        nodes = _trust_nodes(args.trust_node)
        distrust = longterm.parse_distrust(args.distrust)
        range_context = _range_context(args.range_context)
    except UsageError as e:
        print(f"usage error: {e}", file=sys.stderr)
        return EXIT_USAGE
    helper = ranges.Helper(args.range_helper) if args.range_helper else None
    try:
        data = _read(args.bundle)
        witnesses = [_witness_key(path) for path in args.witness]
        roots = timestamps.load_roots(args.tsa_root)
        files = {name: _read(path) for name, path in contents.items()}
    except UsageError as e:
        print(f"error: {e}", file=sys.stderr)
        return EXIT_INPUT
    try:
        result = verify_bundle(data, ledger_id=ledger_id, witnesses=witnesses, tsa_roots_pem=roots,
                               attachments=files, network_witnesses=vkeys, trust_nodes=nodes, distrust=distrust,
                               range_helper=helper)
    except VerifyError as e:
        return _not_verified(args, e)
    except ranges.HelperError as e:
        # The helper failed, which says nothing of the evidence.
        print(f"error: {e}", file=sys.stderr)
        return EXIT_INPUT
    failure = _required(result, args, range_context)
    if any(status == "mismatch" for _, _, _, status in result.attachments):
        failure = "an attachment does not match its commitment"
    return _finish(args, report.to_json(result), report.to_text(result), failure)


def _contract_main(argv: list[str]) -> int:
    args = _contract_parser().parse_args(argv)
    try:
        ledger_id = _ledger_id(args.ledger_id)
        vkeys = _witness_vkeys(args.witness_vkey)
        nodes = _trust_nodes(args.trust_node)
        distrust = longterm.parse_distrust(args.distrust)
    except UsageError as e:
        print(f"usage error: {e}", file=sys.stderr)
        return EXIT_USAGE
    try:
        data = _read(args.evidence)
        witnesses = [_witness_key(path) for path in args.witness]
        roots = timestamps.load_roots(args.tsa_root)
    except UsageError as e:
        print(f"error: {e}", file=sys.stderr)
        return EXIT_INPUT
    try:
        result = verify_contract_evidence(data, ledger_id=ledger_id, witnesses=witnesses, tsa_roots_pem=roots,
                                          network_witnesses=vkeys, trust_nodes=nodes, distrust=distrust)
    except VerifyError as e:
        return _not_verified(args, e)
    if args.deploy_out is not None:
        try:
            with open(args.deploy_out, "wb") as f:
                f.write(result.deploy_file())
        except OSError:
            print(f"error: cannot write {args.deploy_out}", file=sys.stderr)
            return EXIT_INPUT
    failure = _required(result.bundle, args)
    if failure is None and args.require_presence:
        for consents in result.consents.values():
            missing = [c for c in consents if c.registration.presence is None]
            if missing:
                failure = (f"a consent of {missing[0].report.ledger.name} was given without proof of a "
                           "person's presence")
                break
    if failure is None and args.require_answered:
        overdue = [q for q in result.open_requests() if result.overdue(q)]
        if overdue:
            failure = (f"{len(overdue)} request(s) still open past their deadline at the checkpoint: "
                       + ", ".join(f"{q.id.hex()[:12]} ({q.kind})" for q in overdue))
    return _finish(args, contract_report.to_json(result), contract_report.to_text(result), failure)


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if argv and argv[0] == "contract":
        return _contract_main(argv[1:])
    if argv and argv[0] == "credential":
        return _credential_main(argv[1:])
    return _bundle_main(argv)
