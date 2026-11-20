# An independent verifier, in Python

A second verifier of Kanhe evidence, written from the specification alone:
[the protocol in prose](../../spec/README.md), [`spec/kanhe.cddl`](../../spec/kanhe.cddl),
and the test vectors in [`testvectors/`](../../testvectors/). It shares no code with the C++
implementation, and its authors did not read it. A protocol that only one program can verify is
defined by that program. A second one, written from the text, shows that the text is enough, and
every place where the two disagree is a place where the text needs fixing.

It verifies an evidence bundle (spec section 11), a record's or an instance's, every step:

- deterministic CBOR and COSE_Sign1;
- the log, its receipts and checkpoints, under the log key in effect at each size;
- a replay of the ledger rules: actors, delegations, key rotations, revocations, versions,
  claims, memberships, and contracts (below);
- proof of presence, by passkey or hardware key;
- disclosed fields and attachments;
- completeness against the state commitment, a claim's source, a record's local sources, and
  the scripts its statements name included;
- claims: the condition in words, whether it holds, as of when and until when, whether it has
  lapsed, and whether its source is live, revoked, or replaced (`kanhe_verify/claims.py`);
- witness cosignatures;
- RFC 3161 time-stamp tokens and the clock rule;
- open witness networks (C2SP): their witnesses' cosignatures of a SHA-256 ledger's checkpoint
  notes, Ed25519 (`cosignature/v1`) and ML-DSA-44 (a `CosignedSubtree`), trusted by their
  verifier keys and counted with the ledger's own witnesses;
- trust nodes: the membership proofs a bundle carries (key 9), each a trust node's complete
  evidence of a `kanhe.membership/1` record naming the bundle's ledger, verified as a bundle of
  its own, and where the membership stood when the record was registered and at the proof's
  checkpoint (`kanhe_verify/memberships.py`). A trust node is trusted, and named, only by the
  verifier's list (`--trust-node`), never by anything the evidence says;
- scripts and sources (spec v0.18): the scripts a record's statements name (provenance key 5),
  what each is, who approved it in person, and whether it was withdrawn since; the sources its
  registration names (key 7), each on this ledger from the bundle itself or on another from its
  source proof (bundle key 10, a complete bundle of that ledger, one level, verified with the
  same trust settings), and where each stood when the record was registered and at the
  checkpoint (`kanhe_verify/scripts.py`);
- approvals and guardians (spec v0.20): the approval rules of a statement's delegation chain
  (scope key 10) and of the organization's guardians (statement type 9), and each approval its
  log entry carries (key 5), checked as the ledger checked it, with its own presence challenge;
  the rules that protect approvers' keys and credentials and keep guardians from being revoked
  below k; every approver and guardian an involved object; and, for each event, the rules that
  applied, who approved, how, and what counted, with the guardians in effect
  (`kanhe_verify/approvals.py`);
- long-term evidence (spec v0.21): a bundle's renewals (key 11), each a newer checkpoint proven
  consistent with the one before it, with the rotations of the root and log keys in between,
  followed as a witness follows them, and its cosignatures, tokens, and network cosignatures
  checked and counted as the bundle's own; the long-term status, the latest post-quantum
  attestation that covers the bundle; dated witness cosignatures (the witness's time as CWT
  claims with only iat, protected header label 15); algorithms distrusted from a date
  (`--distrust`), whose attestations are set aside and whose every signature must be covered by
  a dated attestation (a token, a network cosignature, or a dated witness cosignature) before
  that date; and field and attachment salts of 16 or 32 bytes (`kanhe_verify/longterm.py`);
- range proofs (spec v0.22): a registration's provable values (key 8), each a field's name, its
  encoding (a number with a scale, money in a currency with a scale, or a date), and a SHA-256
  commitment of its own; and the range proofs a record's bundle carries (key 12), each that one
  provable value is at least, at most, or between bounds: their shapes, the bounds read in the
  provable's encoding, the public values and the transcript, a context the verifier may require,
  and the statement in words (`kanhe_verify/ranges.py`). The proof's arithmetic, system 1's
  (Longfellow ZK), is the one thing done elsewhere: a helper program does it (below).

And it verifies an instance's contract evidence (sections 14 and 15):

- deploys, calls, and retires under their ledger rules: the code loads in the deterministic
  WebAssembly profile, interfaces, heads, function kinds, consent citations, scope keys 7 to 9;
- every call's contract run again, on the contract input the home built, its output read as a
  contract output: states, statuses, parties, events, finality;
- instances created by a call: their ids, depth (at most 8), and a part's ancestors' calls up to
  each one that created the next generation;
- requests and answers: their ids, deadlines, replies, at most 64 open per instance, answers
  done, failed, or expired (only once due), at most once, late or on time, and the open requests
  overdue at the checkpoint;
- completeness with state leaves of kinds 4 and 5: the instance, its contract, and everyone its
  calls and its ancestors' calls involve;
- every consent a call cites: its bundle verified completely for the party's ledger, as any
  record's, a live `kanhe.contract-consent/1` record whose terms are the call's, not lapsed when
  the call was registered, signed as the call claims; no bundle without a citation, no citation
  without a bundle.

The interpreter, `kanhe_verify/wasm.py`, is the specification's reference interpreter,
written from it independently of the C++ implementation; the vector tools use it through
[`tools/testvectors/wasm_ref.py`](../../tools/testvectors/wasm_ref.py), and
`testvectors/vm-v1.json` holds its runs. A Bo contract's source is not rebuilt (there is no Bo
compiler here): like `kanhe contract verify`, it checks the code as run, and `--deploy-out`
writes the deploy for `bo rebuild`.

## Running it

Python 3.11 or later, with the packages in [`requirements.txt`](requirements.txt). `openssl`
3.5 or later must be on `PATH`, for SM2 and for time-stamp tokens; `KANHE_OPENSSL` names
another binary.

```sh
python3 -m venv .venv && .venv/bin/pip install -r verifiers/python/requirements.txt
PYTHONPATH=verifiers/python .venv/bin/python -m kanhe_verify evidence.cbor --ledger-id <ledger-id>
PYTHONPATH=verifiers/python .venv/bin/python -m kanhe_verify contract deal.cbor --ledger-id <home-id>
```

Its two commands mirror the reference implementation's, with the same options, exit codes, and
JSON fields:

| This verifier | Mirrors | Options besides `--json` |
|---|---|---|
| `python3 -m kanhe_verify BUNDLE` | `kanhe verify` | `--ledger-id`, `--witness`, `--witness-vkey`, `--min-witnesses`, `--tsa-root`, `--min-timestamps`, `--trust-node LEDGER=NAME`, `--distrust ALG@YYYY-MM-DD`, `--attachment NAME=FILE`, `--range-context HEX`, `--range-helper PROGRAM` |
| `python3 -m kanhe_verify contract FILE` | `kanhe contract verify` | `--ledger-id`, `--witness`, `--witness-vkey`, `--min-witnesses`, `--tsa-root`, `--min-timestamps`, `--trust-node LEDGER=NAME`, `--distrust ALG@YYYY-MM-DD`, `--require-presence`, `--require-answered`, `--deploy-out FILE` |

Exit codes: 0 verified, 1 a usage error, 2 an input file that cannot be read (or a
`--deploy-out` file that cannot be written, or a range helper that fails), 3 not verified.

The first command verifies any evidence bundle, an instance's included (it reports it as a
record without a type, its calls as its events); contract evidence, which wraps an instance's
bundle with its consents, takes the second. A command of its own keeps each one's options and
errors exactly those of the command it mirrors, and a file is never verified as what it is not.

Nothing cryptographic is implemented here:

- Ed25519, ECDSA P-256, and ML-DSA come from the `cryptography` package;
- SHA-256 and SM3 come from `hashlib`;
- SM2 and the CMS signatures of time-stamp tokens come from the `openssl` command line. Its
  `ts -verify` reads a token as PKCS #7, which has no ML-DSA and does not verify SM2, so a
  token whose signing certificate's key is ML-DSA or SM2 is checked with `cms -verify -purpose
  timestampsign -cades -attime`, the same conditions of trust. An authority is the SHA-256 of
  its certificate's SubjectPublicKeyInfo, read from the certificate's bytes (`cryptography`
  loads no SM2 key).

`--trust-node` takes a trust node the verifier believes: its ledger id (64 hex digits) and the
name the report gives it, repeatable; a ledger named twice is a usage error. The JSON report's
`memberships` lists every proof, trusted or not, in the bundle's order, with the field names of
`kanhe verify --json` and its times in ISO 8601 like every other time in the report.

Approvals and guardians (spec v0.20) appear in the JSON report with these fields, which
`kanhe verify --json` shares (actors as everywhere in the report, `{id, kind, name, revoked}` and
an agent's `model`, `model_version`, `responsible`; presence as an event's, or null; times in ISO
8601):

- each event (and, in contract evidence, each call and each consent) has `rules`, the approval
  rules that applied to it in the order of section 5.1, each `{source, delegation, k, approvers,
  within_ms, without_presence, signer_counted, count}` (`source` is `delegation`, with the
  delegation's id, or `guardians` or `new_guardians`, with `delegation` null; `approvers` the
  actors it names; `count` the approvals that counted, with the signer if it did), and
  `approvals`, in the log entry's order, each `{approver, approved_at, presence, counted_for}`
  (`approved_at` as the approver claims it; `presence` null when not in person; `counted_for` the
  indices in `rules` it counted for). Both lists are empty when no rule applied;
- the report has `guardians`: `in_effect`, the guardians at the checkpoint, `{k, within_ms,
  guardians, guards, since, index}` (`guards` null for every statement the organization signs, or
  the names of the types key 2 lists), or null; and `settings`, every guardian setting the bundle
  holds, in log order, each `{index, registered_at, removed, k, within_ms, guardians, guards,
  rules, approvals}` (a removal has `k`, `within_ms`, and `guards` null and no `guardians`).

Long-term evidence (spec v0.21) appears in the JSON report as `renewals`, `long_term`, and
`distrust`, with the fields section 11.1 of the specification defines, which `kanhe verify --json`
shares. `--distrust ALG@YYYY-MM-DD` (repeatable) names `ed25519`, `ecdsa`, `sm2`, `rsa`,
`ml-dsa-44`, `ml-dsa-65`, `ml-dsa-87`, or `classical`; an unknown name, a date that is none, and an
algorithm named twice are usage errors.

Range proofs (spec v0.22) appear in the JSON report as `provable` and `range_proofs`, with the
fields section 11.3 of the specification defines, which `kanhe verify --json` shares. Nothing
cryptographic is implemented here, and a range proof's arithmetic is no exception: with
`--range-helper PROGRAM`, each proof of system 1 is handed to PROGRAM, and without it each one is
reported as `not-checked` and relied on for nothing, while every other check of step 13 is made.
PROGRAM is the reference implementation's `kanhe-range`, built with the Longfellow ZK library; its
protocol is fixed, so that another may stand in for it:

- `PROGRAM verify` reads one JSON object on its standard input, `{"commitment": hex, "low": lo'
  in decimal, "high": hi' in decimal, "transcript": hex, "proof": hex}`, writes `{"valid": true}`
  or `{"valid": false}`, and exits 0 when the proof is valid, 1 when it is not, and 2 when its
  input is wrong;
- `PROGRAM prove` reads `{"salt": hex, "value": v in decimal, "low", "high", "transcript"}` and,
  for test vectors only, `"seed": hex`, and writes `{"commitment": hex, "proof": hex}`.

A helper that cannot be run, exits otherwise, or answers outside this protocol is an error (exit
2), never a verdict on the evidence. `--range-context HEX` (1 to 64 bytes) requires every range
proof to carry that context, a challenge the verifier gave the prover: a proof without it, or with
another, fails, and the report is printed with the reason, as for `--min-witnesses`.

`--witness-vkey` takes an open network's witness by its verifier key,
`<name>+<key ID>+<base64(type || key)>` (c2sp.org/signed-note), of signature type 0x04 (Ed25519)
or 0x06 (ML-DSA-44); any other key is a usage error. The report lists each network cosignature
with the size it cosigned and the witness's own time, which is relied on for nothing.

## Tests

[`tests/verifiers/python_verifier.sh`](../../tests/verifiers/python_verifier.sh) is CTest's
`verifier_python_end_to_end`. It builds ledgers with the command line and hands every bundle to
both verifiers, which must reach the same verdict and report the same facts. The ledgers cover
many algorithms and actors:

- SHA-256 and SM3 ledgers;
- Ed25519, ESP256, SM2, and ML-DSA keys;
- an AI agent, delegation chains, and key rotations;
- witnesses, time-stamp authorities, and hardware keys on SoftHSM;
- open witness networks: witnesses written from c2sp.org's texts
  ([`c2sp_witness.py`](../../tests/verifiers/c2sp_witness.py), with the `openssl` command line)
  cosign checkpoint notes with Ed25519 and ML-DSA-44, through `checkpoint network-cosign`; their
  cosignatures trusted or not, at two sizes, beside a ledger witness and a time-stamp, damaged,
  and on a contract's home and a party's consent.

Contract evidence is compared with `kanhe contract verify --json` the same way, field by
field:

- parts split across a SHA-256 and an SM3 party, with consents of an organization, a person, a
  device, an AI agent under a chain of delegations, and (on SoftHSM) a person present with a
  hardware key; a retired contract; witnesses and time-stamps on the home and on a consent;
- requests answered done, failed, and expired, on time and late, by executors under scope keys 8
  and 9, an AI agent, a keeper, and a person; a final instance that takes an answer; requests
  overdue at the checkpoint, with `--require-answered`;
- an SM3 home whose contract hashes its input, children without parties, and arguments of every
  kind of CBOR value;
- the contract evidence the examples (`examples/`) leave behind: Bo contracts with time rules,
  keepers, executors, consents through MCP, and parts;
- the signed contract evidence of `protocol-v0.7.json` and `protocol-v0.8.json` (and that of
  `protocol-v0.6.json`, whose bundles are opaque bytes, which must fail);
- damaged contract evidence (entries, proofs, consents left out, repeated, or unpinned; flipped
  bytes), which must fail in both;
- home and party ledgers forged at the contract rules' edges (`tests/contract_probes.py`).

It also checks other inputs:

- damaged bundles, which must fail in both;
- bundles packed from the test vectors, which must verify in both;
- ledgers forged at the specification's edges (`tests/probes.py`, `tests/contract_probes.py`),
  where both must agree when the specification decides the outcome. Where it does not, they are
  printed but do not fail;
- anchors forged with open-network cosignatures at the edges of sections 10.2 and 11
  (`tests/network_probes.py`), verified with the witnesses' verifier keys: both kinds, trusted
  and not, damaged, repeated, of other sizes, roots, origins, and times, and the CDDL's sizes.

[`testvectors/evidence-v1.json`](../../testvectors/evidence-v1.json) is a conformance suite that
every verifier must pass: evidence bundles and contract evidence forged from the specification by
[`tools/testvectors/evidence_suite.py`](../../tools/testvectors/evidence_suite.py), independently of
both verifiers, each with the options to verify it with, the verdict the specification decides (a
failure names the section and step that decide it), and facts its JSON report must show.
`tests/test_conformance.py` runs this verifier's command line on every case; a case that needs a
range proof system's arithmetic (`range_systems`) runs with `KANHE_RANGE_HELPER` (a `kanhe-range`)
as `--range-helper`, and is skipped without it.

The verifier's own unit tests run against `testvectors/`: `tests/test_vectors.py` for records
and claims (`protocol-v0.14.json`: claim metadata with its words, and refused, and a log with
claims, every refused statement, and what a report states of each claim) and for asking about a
condition (`protocol-v0.15.json`, with `kanhe_verify/access.py`: access requests of both forms,
decoded to their values, and refused, each for its rule; claims checked as answers to requests,
accepted or refused for the acceptance check they fail) and for trust nodes (`protocol-v0.16.json`:
the six mechanism types, membership metadata with its values, and refused, each for its rule; where
memberships stood at given times; a trust node's log, every refused statement; and member ledgers'
bundles with membership proofs, each proof's report under the trust list, or refused whatever the
list, and `--trust-node`), `tests/test_approvals.py` for approvals and guardians
(`protocol-v0.20.json`: approval rules, guardian settings, and approvals decoded and refused, each
for its rule; a log for each hash, every statement's rules and approvals as the vectors state
them, every refused statement for its rule, and the logs that do not parse),
`tests/test_renewals.py` for long-term evidence (`protocol-v0.21.json`: salts, renewals, and the
distrust option read and refused; the archive ledger's renewal parts; and every bundle verified
with its options, to its verdict and facts), `tests/test_ranges.py` for range proofs (the
encodings, bounds, commitments, public values, transcript bytes, words, and shapes, by hand; the
plumbing to a helper, with a fake one the test writes, which accepts a proof exactly when it is a
fixed hash of what it is given; and `protocol-v0.22.json`, its bundles that need system 1 with
`KANHE_RANGE_HELPER` only),
`tests/test_network.py` for open witness networks (`protocol-v0.13.json`: the origin, the note,
the note key's signed note, verifier keys, every cosignature's verdict and time, the anchor, in
bundles too, and signed-note's own example), and `tests/test_contracts.py` for the profile (`vm-v1.json`), contracts, parts, requests and
answers (`protocol-v0.6.json` to `protocol-v0.8.json`: every statement, every refused one, every
contract run's input and outcome, the state, and the signed evidence), and Bo's calls
(`bo-v1.json`: each call's input as the ledger encodes it, and its outcome).

CTest finds the Python as `KANHE_PYTHON`, or `python3`; without the packages the test is
skipped. CI installs them in `/opt/python-verifier` and names it, so there the test cannot be
skipped.
