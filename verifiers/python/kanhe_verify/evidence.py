# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya
"""Verifying an evidence bundle (spec section 11): a record's, or an
instance's (section 15), whose calls the replay runs again.

verify_bundle follows the verifier's steps of section 11 in order:

1. the ledger's identity, hash, and first keys from the genesis entry;
2. every receipt's inclusion proof against the checkpoint;
3. a replay of the included statements under the ledger rules;
4. the checkpoint's and the receipts' signatures with the log key in effect;
5. disclosed fields and attachment contents;
6. witness cosignatures, counted with the open-network witnesses' of step 8;
7. completeness against the state commitment the checkpoint ends with;
8. anchors: time-stamp tokens over checkpoints, and the clock rule; and
   open-network witnesses' cosignatures of checkpoint notes (section 10.2);
9. membership proofs (v0.16): each a trust node's complete evidence of a
   membership naming this bundle's ledger, verified as a bundle of its own,
   and where the membership stood when the record was registered and at the
   proof's checkpoint. A trust node is trusted, and named, only by the
   verifier's own list;
10. source proofs (v0.18);
11. renewals (v0.21): newer attestations of the tree (longterm.py);
12. signatures by algorithms the verifier distrusts (v0.21), each covered by
    a dated attestation before its date; and the long-term status.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import dataclasses

from . import (contracts, cose, crypto, longterm, memberships, merkle, network, protocol, rules, scripts, statetree,
               timestamps)
from .errors import VerifyError
from .protocol import AGENT


@dataclass
class TokenReport:
    checkpoint_size: int
    info: timestamps.TokenInfo


@dataclass
class NetworkCosignature:
    """An open-network witness's cosignature of an anchor's checkpoint note
    (section 10.2): who, the size it cosigned, and its time T, which is
    reported and relied on for nothing."""
    witness: str
    size: int
    time: int  # POSIX seconds, the witness's own clock
    trusted: bool


@dataclass
class MembershipProof:
    """A membership proof (section 11, step 9) as a report states it: the
    trust node's ledger, whether the verifier trusts it and the name its list
    gives it (never one the evidence gives), the membership and its values,
    and where it stood when the bundle's record was registered and at the
    proof's checkpoint. Times are ms."""
    trust_node: bytes
    trusted: bool
    trust_node_name: str | None
    membership: bytes  # the membership record's id on the trust node's ledger
    values: memberships.Membership
    registered_at: int
    record_time: int
    at_record: str
    checkpoint_time: int
    at_checkpoint: str
    report: "Report"  # the proof's own verification


@dataclass
class ScriptReport:
    """A script the record's events name (v0.18)."""
    id: bytes
    values: scripts.Script
    approved_by: bytes  # the person's actor id
    presence: object  # presence.PresenceResult or None
    approved_at: int
    withdrawn_at: int | None


@dataclass
class SourceReport:
    """A source the record's registration names (v0.18)."""
    ledger: bytes
    record: bytes
    local: bool
    provided: bool
    record_time: int
    type: str | None = None
    organization: str | None = None
    trust_node: str | None = None
    at_record: str | None = None
    checkpoint_time: int | None = None
    at_checkpoint: str | None = None
    changed_at: int | None = None
    replaced_by: bytes | None = None


@dataclass
class Report:
    ledger: rules.Ledger
    id_checked: bool
    checkpoint: protocol.TreeHead
    log_key: crypto.PublicKey
    record: rules.Record | None  # the subject: a record, or
    instance: contracts.Instance | None  # an instance
    events: list  # [rules.Applied], in log order
    disclosed: list  # [(name, value)]
    attachments: list  # [(name, media type, size, status)]
    witnesses_trusted: int
    witnesses_untrusted: int
    tokens: list  # [TokenReport]
    trusted_authorities: int
    existed_by: dict  # log index -> ms
    complete: bool
    commitment: protocol.TreeHead | None
    commitment_index: int | None
    entries: int = 0
    notes: list = field(default_factory=list)
    network: list = field(default_factory=list)  # [NetworkCosignature], in the bundle's order
    memberships: list = field(default_factory=list)  # [MembershipProof], in the bundle's order (v0.16)
    scripts: list = field(default_factory=list)  # [ScriptReport], first named first (v0.18)
    sources: list = field(default_factory=list)  # [SourceReport], in the registration's order (v0.18)
    renewals: list = field(default_factory=list)  # [longterm.RenewalReport], in order (v0.21)
    long_term: longterm.LongTerm | None = None  # v0.21
    distrust: dict = field(default_factory=dict)  # v0.21: {algorithm: its date in ms}
    set_aside: list = field(default_factory=list)  # v0.21: [longterm.Attestation], in the bundle's order
    distrusted: list = field(default_factory=list)  # v0.21: [longterm.Distrusted], in section 11.1's order


def fail(message: str):
    raise VerifyError(message)


def verify_bundle(data: bytes, *, ledger_id: bytes | None = None, witnesses: list | None = None,
                  tsa_roots_pem: bytes = b"", attachments: dict | None = None,
                  network_witnesses: list | None = None, trust_nodes=None, distrust: dict | None = None) -> Report:
    """Verifies an evidence bundle. Raises VerifyError if it does not
    verify; returns the report otherwise.

    witnesses: trusted witness public keys (crypto.PublicKey);
    tsa_roots_pem: trusted time-stamp authority roots, PEM;
    attachments: attachment contents by name;
    network_witnesses: trusted open-network witnesses' verifier keys
    (network.VerifierKey);
    trust_nodes: the trust nodes it believes (v0.16), as {ledger id: name}
    or [(ledger id, name)]: the name is the verifier's, and the only one a
    report gives a trust node;
    distrust: the algorithms it distrusts (v0.21), {name: date in ms}, as
    longterm.parse_distrust gives them.
    """
    names = dict(trust_nodes or {})
    return _verify(data, ledger_id=ledger_id, witnesses=witnesses or [], tsa_roots_pem=tsa_roots_pem,
                   attachments=attachments or {}, network_witnesses=network_witnesses or [], trust_nodes=names,
                   as_proof=False, distrust=dict(distrust or {}))


def _verify(data: bytes, *, ledger_id, witnesses: list, tsa_roots_pem: bytes, attachments: dict,
            network_witnesses: list, trust_nodes: dict, as_proof: bool, as_source: bool = False,
            distrust: dict | None = None) -> Report:
    """Steps 1 to 10; for a membership proof (as_proof), steps 1 to 8 only,
    and a proof that carries membership proofs of its own is refused before
    anything else; for a source proof (as_source, v0.18), steps 1 to 9, and
    one that carries source proofs of its own is refused before anything
    else."""
    bundle = protocol.parse_bundle(data)
    if as_source and bundle.sources:
        fail("a source proof carries source proofs of its own (key 10)")
    if as_proof and bundle.sources:
        fail("a membership proof carries source proofs")
    if as_proof and bundle.memberships:
        fail("a membership proof carries membership proofs of its own (key 9)")
    checkpoint = protocol.parse_tree_head(bundle.checkpoint, cose.CHECKPOINT_TYPE, "the checkpoint")
    size = checkpoint.tree_size

    # Entries and receipts, strictly ascending from index 0 (step 2).
    entries = []
    previous = -1
    for encoded, encoded_receipt in bundle.entries:
        entry = protocol.parse_log_entry(encoded)
        receipt = cose.parse_receipt(encoded_receipt)
        if receipt.tree_size != size:
            fail("a receipt is not against the bundle's checkpoint (its tree size differs)")
        if receipt.leaf_index <= previous or (previous < 0 and receipt.leaf_index != 0):
            fail("the bundle's entries are not strictly ascending from index 0")
        previous = receipt.leaf_index
        entries.append((receipt.leaf_index, entry, receipt))

    # Step 1: the ledger from its genesis entry.
    ledger = rules.Ledger(entries[0][1], entries[0][0])
    h = ledger.h
    if ledger_id is not None and ledger_id != ledger.id:
        fail("the bundle comes from a different ledger")
    if checkpoint.ledger_id != ledger.id:
        fail("the checkpoint is for another ledger")
    if checkpoint.hash != ledger.hash_alg:
        fail("the checkpoint's tree hash is not the ledger's")

    # Step 2: inclusion of every entry in the checkpointed tree.
    for index, entry, receipt in entries:
        if receipt.vds != protocol.VDS[ledger.hash_alg]:
            fail("a receipt's verifiable data structure is not the ledger's tree")
        leaf = merkle.leaf_hash(h, entry.encoded)
        if not merkle.verify_inclusion(h, index, size, leaf, receipt.path, checkpoint.root):
            fail("an entry is not proven to be in the checkpointed log")

    # Step 3: replay, at the registration times, which follows the
    # organization's key rotations.
    last_time = None
    for index, entry, _ in entries:
        if last_time is not None and entry.registered_at < last_time:
            fail("registration times go back in the log")
        last_time = entry.registered_at
        if index == 0:
            continue
        if entry.commitment is not None:
            ledger.apply_commitment(entry, index)
        else:
            ledger.apply(entry, index)

    # Step 4: the checkpoint and every receipt, under the log key in effect
    # at the checkpoint's size. (State commitments were checked under the key
    # in effect at their index during replay.)
    log_key = ledger.log_key_for_size(size)
    ledger.check_signed_head(checkpoint, log_key, "the checkpoint")
    for index, entry, receipt in entries:
        if receipt.alg != log_key.alg or receipt.kid != log_key.kid(h):
            fail("a receipt is not signed by the log key in effect")
        if not crypto.verify_signature(log_key, receipt.to_be_signed(checkpoint.root), receipt.signature):
            fail("a receipt's signature does not verify")

    record = ledger.records.get(bundle.subject)
    instance = ledger.instances.get(bundle.subject) if record is None else None
    if record is None and instance is None:
        fail("the bundle does not hold the registration of its record, or the creation of its instance")

    # Step 5: disclosed fields and attachment contents.
    if instance is not None and (bundle.disclosures or bundle.openings):
        fail("an instance's bundle discloses no fields and opens no attachments")
    disclosed = _check_disclosures(h, record, bundle.disclosures) if record is not None else []
    attachment_report = (_check_attachments(h, record, bundle.openings, attachments)
                         if record is not None else [])

    # Step 6: cosignatures, by witnesses it trusts, each witness once (the
    # open-network witnesses' are counted with them after step 8, and the
    # renewals' after step 11). The tally keeps every attestation (v0.21).
    distrust = distrust or {}
    tally = Tally(ledger, witnesses, tsa_roots_pem, network_witnesses, distrust,
                  bundle_indices=[index for index, _, _ in entries])
    tally.cosignatures(checkpoint, bundle.cosignatures, anchor=None, renewal=None)

    # Step 7: completeness.
    included = {index: entry for index, entry, _ in entries}
    subject = record if record is not None else instance
    complete, commitment = _check_completeness(ledger, subject, size, included, bundle.proofs)

    # Step 8: anchors.
    tokens, cosigned, anchor_heads = _check_anchors(ledger, checkpoint, included, bundle.anchors, tally)

    # The scripts the record's events name, and its sources (v0.18).
    script_reports, source_reports = _provenance(ledger, subject, checkpoint)
    if instance is not None and bundle.sources:
        fail("an instance's bundle carries no source proofs")

    # Step 9: membership proofs.
    proofs = _check_memberships(ledger, subject, bundle.memberships, witnesses=witnesses,
                                tsa_roots_pem=tsa_roots_pem, network_witnesses=network_witnesses,
                                trust_nodes=trust_nodes, distrust=distrust)

    # Step 10: source proofs (v0.18).
    _check_sources(source_reports, bundle.sources, witnesses=witnesses, tsa_roots_pem=tsa_roots_pem,
                   network_witnesses=network_witnesses, trust_nodes=trust_nodes, distrust=distrust)

    # Step 11: renewals (v0.21), from the keys the replay reached.
    held = {index: entry.registered_at for index, entry, _ in entries}
    renewals = longterm.check_renewals(ledger, checkpoint, bundle.renewals, tally, held)

    # Step 12: signatures by distrusted algorithms, each covered; and the
    # long-term status (v0.21).
    distrusted = longterm.covered(ledger, entries, checkpoint, anchor_heads, renewals, tally.items, distrust)
    status = longterm.long_term(ledger, checkpoint, log_key, renewals, tally.items, distrust)

    events = [ledger.applied[i] for i in event_indices(ledger, subject)]
    return Report(
        ledger=ledger, id_checked=ledger_id is not None, checkpoint=checkpoint, log_key=log_key,
        record=record, instance=instance, events=events, disclosed=disclosed, attachments=attachment_report,
        witnesses_trusted=len(tally.trusted), witnesses_untrusted=len(tally.untrusted), tokens=tokens,
        trusted_authorities=len(tally.authorities), existed_by=tally.existed_by, complete=complete,
        commitment=commitment, commitment_index=size - 1 if commitment is not None else None,
        entries=len(entries), network=[n for _, n in cosigned], memberships=proofs,
        scripts=script_reports, sources=source_reports, renewals=renewals, long_term=status,
        distrust=distrust, set_aside=longterm.in_bundle_order([a for a in tally.items if a.set_aside]),
        distrusted=distrusted)


def related_records(ledger: rules.Ledger, subject, events: list) -> list:
    """Section 11, step 7: the records the subject's own events name, its
    related objects: a claim's source (v0.14); the local sources its own
    registration names (v0.18); the scripts its events' provenance names
    (v0.18). Each once, in that order, first named first."""
    out = []

    def add(record_id: bytes):
        if record_id not in out:
            out.append(record_id)

    if isinstance(subject, rules.Record):
        if subject.claim is not None:
            add(subject.claim.source)
        for ledger_id, record_id in subject.sources:
            if ledger_id == ledger.id:
                add(record_id)
    for index in events:
        provenance = ledger.applied[index].statement.provenance
        if provenance is not None and provenance.script is not None:
            add(provenance.script)
    return out


def _times(ledger: rules.Ledger, record: rules.Record) -> tuple:
    """When a record of the bundle was registered, first revoked, and
    replaced (with the newer version's id)."""
    registered = ledger.applied[record.history[0]].registered_at
    revoked = replaced = replaced_by = None
    for index in record.history:
        applied = ledger.applied[index]
        if applied.statement.type == protocol.RECORD_REVOKE and revoked is None:
            revoked = applied.registered_at
        if applied.statement.type == protocol.RECORD_REGISTER and applied.id != record.id:
            replaced, replaced_by = applied.registered_at, applied.id
    return registered, revoked, replaced, replaced_by


def _set_statuses(s: SourceReport, registered: int, revoked, replaced, replaced_by):
    s.at_record = scripts.status(registered, revoked, replaced, s.record_time)
    s.at_checkpoint = scripts.status(registered, revoked, replaced, s.checkpoint_time)
    if s.at_checkpoint == scripts.REVOKED:
        s.changed_at = revoked
    elif s.at_checkpoint == scripts.REPLACED:
        s.changed_at, s.replaced_by = replaced, replaced_by


def _provenance(ledger: rules.Ledger, subject, checkpoint) -> tuple:
    """Section 11, the report (v0.18): each script the subject's events
    name, once, first named first, with who approved it in person and
    whether it was withdrawn since; each source its registration names, a
    local one's status from this bundle (another ledger's from its proof,
    step 10)."""
    script_reports = []
    for index in event_indices(ledger, subject):
        provenance = ledger.applied[index].statement.provenance
        if provenance is None or provenance.script is None:
            continue
        script = ledger.records.get(provenance.script)
        # Approved before it is named (v0.19): the replay let a script the
        # bundle did not hold yet pass, so the order is checked here.
        if script is not None and script.history[0] >= index:
            fail("an event of the record names a script approved only after it")
        if any(s.id == provenance.script for s in script_reports):
            continue
        if script is None or script.script is None:
            fail("a script the record's events name is not in its evidence")
        registered, revoked, _, _ = _times(ledger, script)
        approval = ledger.applied[script.history[0]]
        script_reports.append(ScriptReport(id=script.id, values=script.script, approved_by=approval.signer,
                                           presence=approval.presence, approved_at=registered,
                                           withdrawn_at=revoked))
    source_reports = []
    if isinstance(subject, rules.Record):
        record_time = registration_time(ledger, subject)
        for ledger_id, record_id in subject.sources:
            s = SourceReport(ledger=ledger_id, record=record_id, local=ledger_id == ledger.id, provided=False,
                             record_time=record_time)
            if s.local:
                source = ledger.records.get(record_id)
                if source is None:
                    fail("a local source is not in the record's evidence")
                # Registered before the record that names it (v0.19).
                if source.history[0] >= subject.history[0]:
                    fail("a local source is registered only after the record that names it")
                s.provided, s.type, s.checkpoint_time = True, source.type, checkpoint.timestamp
                _set_statuses(s, *_times(ledger, source))
            source_reports.append(s)
    return script_reports, source_reports


def _check_sources(sources: list, proofs: list, *, witnesses: list, tsa_roots_pem: bytes,
                   network_witnesses: list, trust_nodes: dict, distrust: dict):
    """Section 11, step 10 (v0.18). Each proof is verified as an evidence
    bundle under steps 1 to 9, for the ledger its own genesis names, with no
    attachment contents and this bundle's trusted witnesses, network
    witnesses, time-stamp authorities, and trust nodes. It must verify, be
    complete, be about a record the registration names as a source on that
    ledger (not this one), and carry no source proofs of its own; two proofs
    of one source fail. A source without a proof is not provided."""
    for n, encoded in enumerate(proofs, start=1):
        what = f"source proof {n}"
        try:
            proof = _verify(encoded, ledger_id=None, witnesses=witnesses, tsa_roots_pem=tsa_roots_pem,
                            attachments={}, network_witnesses=network_witnesses, trust_nodes=trust_nodes,
                            as_proof=False, as_source=True, distrust=distrust)
        except VerifyError as e:
            fail(f"{what} does not verify: {e}")
        if not proof.complete:
            fail(f"{what} is not complete: its checkpoint does not end with a state commitment")
        if proof.record is None:
            fail(f"{what} is not about a record")
        named = next((s for s in sources if not s.local and s.ledger == proof.ledger.id
                      and s.record == proof.record.id), None)
        if named is None:
            fail(f"{what} is not of a source the record names on another ledger")
        if named.provided:
            fail(f"{what} is a second proof of one source")
        named.provided, named.type, named.organization = True, proof.record.type, proof.ledger.name
        for m in proof.memberships:
            if m.trusted and m.at_checkpoint == memberships.ACTIVE:
                named.trust_node = m.trust_node_name
                break
        named.checkpoint_time = proof.checkpoint.timestamp
        _set_statuses(named, *_times(proof.ledger, proof.record))


def registration_time(ledger: rules.Ledger, subject) -> int:
    """When the bundle's subject came to be: a record's registration, or
    the registration of the call that created an instance."""
    if isinstance(subject, rules.Record):
        return ledger.applied[subject.history[0]].registered_at
    return ledger.applied[subject.created_by].registered_at


def _check_memberships(ledger: rules.Ledger, subject, proofs: list, *, witnesses: list, tsa_roots_pem: bytes,
                       network_witnesses: list, trust_nodes: dict, distrust: dict) -> list:
    """Section 11, step 9 (v0.16). Each proof is verified as an evidence
    bundle under steps 1 to 8, for the ledger its own genesis names, with no
    attachment contents, and by the same witnesses, open-network witnesses,
    and time-stamp authorities this bundle is: it must verify, be complete,
    be about a kanhe.membership/1 record (whose metadata the replay
    checked) naming this bundle's ledger as its member, and carry no proofs
    of its own. Two proofs of one membership (the same ledger and record)
    fail. A proof that fails any of this fails the evidence."""
    out, seen = [], set()
    record_time = registration_time(ledger, subject) if proofs else None
    for n, encoded in enumerate(proofs, start=1):
        what = f"membership proof {n}"
        try:
            proof = _verify(encoded, ledger_id=None, witnesses=witnesses, tsa_roots_pem=tsa_roots_pem,
                            attachments={}, network_witnesses=network_witnesses, trust_nodes={}, as_proof=True,
                            distrust=distrust)
        except VerifyError as e:
            fail(f"{what} does not verify: {e}")
        if not proof.complete:
            fail(f"{what} is not complete: its checkpoint does not end with a state commitment")
        record = proof.record
        if record is None or record.type != memberships.MEMBERSHIP_TYPE or record.membership is None:
            fail(f"{what} is not about a {memberships.MEMBERSHIP_TYPE} record")
        values = record.membership
        if values.member != ledger.id:
            fail(f"{what} is a membership of another ledger ({values.member.hex()[:12]}), not of this bundle's")
        key = (proof.ledger.id, record.id)
        if key in seen:
            fail(f"{what} is a second proof of one membership ({record.id.hex()[:12]} on {proof.ledger.id.hex()[:12]})")
        seen.add(key)
        registered_at, changes = memberships.history(proof.ledger, record)
        checkpoint_time = proof.checkpoint.timestamp
        trusted = proof.ledger.id in trust_nodes
        out.append(MembershipProof(
            trust_node=proof.ledger.id, trusted=trusted,
            trust_node_name=trust_nodes[proof.ledger.id] if trusted else None, membership=record.id,
            values=values, registered_at=registered_at, record_time=record_time,
            at_record=memberships.standing(registered_at, values.until, changes, record_time),
            checkpoint_time=checkpoint_time,
            at_checkpoint=memberships.standing(registered_at, values.until, changes, checkpoint_time),
            report=proof))
    return out


def _check_disclosures(h, record: rules.Record, disclosures: list) -> list:
    """Section 6: each disclosed leaf against the field root and count; no
    leaf twice; names ascending with their indices."""
    seen = set()
    ordered = []
    for d in sorted(disclosures, key=lambda d: d.index):
        if d.index in seen:
            fail("the bundle discloses one field twice")
        seen.add(d.index)
        if d.index >= record.field_count:
            fail("a disclosed field's index is beyond the record's field count")
        name, _salt, value = protocol.parse_field_leaf(d.leaf)
        if not merkle.verify_inclusion(h, d.index, record.field_count, merkle.leaf_hash(h, d.leaf), d.path,
                                       record.field_root):
            fail(f"the disclosed field {name!r} does not match the record's commitment")
        ordered.append((name, value))
    names = [name.encode("utf-8") for name, _ in ordered]
    if any(a >= b for a, b in zip(names, names[1:])):
        fail("disclosed fields' names do not ascend with their indices")
    return ordered


def _check_attachments(h, record: rules.Record, openings: list, contents: dict) -> list:
    """Attachment contents provided beside the bundle, against the record's
    commitments HASH(salt || content)."""
    names = {a[0] for a in record.attachments}
    salts = {}
    for name, salt in openings:
        if name not in names:
            fail(f"the bundle opens an attachment the record does not have ({name!r})")
        if name in salts:
            fail(f"the bundle opens the attachment {name!r} twice")
        salts[name] = salt
    out = []
    for name, media_type, size, commitment in record.attachments:
        if name in salts and name in contents:
            content = contents[name]
            ok = len(content) == size and h(salts[name] + content) == commitment
            status = "verified" if ok else "mismatch"
        else:
            status = "not-provided"
        out.append((name, media_type, size, status))
    return out


def event_indices(ledger: rules.Ledger, subject) -> list:
    """The log indices of a record's events, or of an instance's calls with,
    for a child, its ancestors' calls up to each one that created the next
    generation (section 15), in log order."""
    if isinstance(subject, rules.Record):
        return list(subject.history)
    events = set(subject.history)
    node = subject
    while node.parent is not None:
        parent = ledger.instances[node.parent]
        events |= {i for i in parent.history if i <= node.created_by}
        node = parent
    return sorted(events)


def involved_objects(ledger: rules.Ledger, subject) -> dict:
    """Section 11, step 7: the record, or the instance and its contract, and
    for each of its events the signer, an agent signer's responsible person,
    and every delegation in the chain with its grantor. A child's ancestors
    need no proof, but their included calls count as events. A claim's source
    (v0.14) is involved, and its statements count as events too, the
    registration that superseded it included. From v0.20, also the
    organization, every guardian, and every approver of an included entry.
    Returns {id: state kind}."""
    events = event_indices(ledger, subject)
    if isinstance(subject, rules.Record):
        involved = {subject.id: statetree.RECORD}
    else:
        involved = {subject.id: statetree.INSTANCE, subject.contract: statetree.CONTRACT}
    # Its related objects (a claim's source, v0.14; its local sources and the
    # scripts its events name, v0.18): their statements count as events too,
    # and bring in no further related objects.
    for record_id in related_records(ledger, subject, events):
        related = ledger.records.get(record_id)
        if related is None:
            fail("the bundle does not hold a record its record's events name")
        involved[record_id] = statetree.RECORD
        events = sorted(set(events) | set(related.history))
    for index in events:
        applied = ledger.applied[index]
        signer = ledger.actors[applied.signer]
        involved[signer.id] = statetree.ACTOR
        if signer.kind == AGENT and signer.responsible is not None:
            involved[signer.responsible] = statetree.ACTOR
        for delegation_id in applied.chain:
            involved[delegation_id] = statetree.DELEGATION
            involved[ledger.delegations[delegation_id].grantor] = statetree.ACTOR
    # v0.20: the organization, whose leaf lists every guardian setting; every
    # actor a guardian setting the bundle includes names; and the approver of
    # every approval any included entry carries, event or not.
    involved.setdefault(ledger.id, statetree.ACTOR)
    for setting in ledger.guardian_settings:
        if setting.body.rule is not None:
            for guardian in setting.body.rule.approvers:
                involved.setdefault(guardian, statetree.ACTOR)
    for applied in ledger.applied.values():
        for result in applied.approvals:
            involved.setdefault(result.approval.approver, statetree.ACTOR)
    return involved


def _check_completeness(ledger: rules.Ledger, subject, size: int, included: dict, proofs: list):
    last = included.get(size - 1)
    commitment = ledger.commitments.get(size - 1) if last is not None and last.commitment is not None else None
    if commitment is None:
        # Without the commitment the checkpoint ends with, a bundle cannot
        # rule out omissions: it verifies, and is not complete. State proofs
        # could not be verified against any root, so they are refused.
        if proofs:
            fail("state proofs need the state commitment the checkpoint ends with")
        return False, None
    h = ledger.h
    by_id = {}
    for proof in proofs:
        if proof.id in by_id:
            fail("the bundle holds two state proofs for one object")
        if statetree.root_from_proof(h, proof.leaf, proof.siblings) != commitment.root:
            fail("a state proof does not lead to the state commitment")
        by_id[proof.id] = proof
    for object_id, kind in involved_objects(ledger, subject).items():
        proof = by_id.get(object_id)
        expected = ledger.leaf(object_id)
        if proof is None:
            fail(f"the bundle holds no state proof for an involved {statetree.KIND_NAMES[kind]} "
                 f"({object_id.hex()[:12]})")
        if proof.leaf != expected:
            fail(f"the history of an involved {statetree.KIND_NAMES[kind]} ({object_id.hex()[:12]}) "
                 "differs from the state commitment: the bundle leaves part of it out")
    return True, commitment


class Tally:
    """Every attestation of a bundle, its anchors, and its renewals (v0.21),
    checked as steps 6 and 8 check them and counted once per witness and
    authority across all of them. A witness, authority, or network witness
    the verifier trusts, by an algorithm it distrusts, is set aside: treated
    as one it does not trust (section 11.1)."""

    def __init__(self, ledger: rules.Ledger, witnesses: list, roots_pem: bytes, network_witnesses: list,
                 distrust: dict, bundle_indices: list):
        self.ledger, self.h = ledger, ledger.h
        self.by_kid = {key.kid(ledger.h): key for key in witnesses}
        self.roots_pem, self.network_witnesses, self.distrust = roots_pem, network_witnesses, distrust
        self.bundle_indices = list(bundle_indices)
        self.trusted, self.untrusted, self.authorities = set(), set(), set()
        self.existed_by: dict = {}  # log index -> ms
        self.items: list = []  # [longterm.Attestation], as checked

    def cosignatures(self, head: protocol.TreeHead, cosignatures: list, *, anchor, renewal) -> tuple:
        """Step 6: the witnesses (by kid) whose cosignatures of `head` these
        are: those it trusts, each of whose cosignatures verifies, and the
        others."""
        trusted, untrusted = set(), set()
        for encoded in cosignatures:
            sign1 = cose.parse_sign1(encoded, cose.COSIGNATURE_TYPE, "a cosignature", dated=True)
            if sign1.payload != head.sign1.payload:
                fail("a cosignature is not over the checkpoint it is given with")
            key = self.by_kid.get(sign1.kid)
            name = longterm.cose_name(key.alg if key is not None else sign1.alg)
            set_aside = key is not None and name in self.distrust
            if key is not None and not set_aside:
                if sign1.alg != key.alg or not crypto.verify_signature(key, sign1.to_be_signed(), sign1.signature):
                    fail("a cosignature by a trusted witness does not verify")
                trusted.add(sign1.kid)
            else:
                untrusted.add(sign1.kid)
            # A dated cosignature (v0.21) is dated by its iat, the witness's word.
            when = sign1.iat * 1000 if sign1.iat is not None else None
            self.items.append(longterm.Attestation(
                kind="witness", by=sign1.kid.hex(), algorithms=(name,), time=when, dated_by=when,
                checkpoint_size=head.tree_size, anchor=anchor, renewal=renewal,
                relied_on=key is not None and not set_aside, set_aside=set_aside, identity=(sign1.kid,)))
        self.trusted |= trusted
        self.untrusted |= untrusted
        return trusted, untrusted

    def tokens(self, head: protocol.TreeHead, tokens: list, held: dict, *, anchor, renewal) -> list:
        """Step 8, for the tokens over `head`'s payload: each verifies with its
        signing certificate and stamps it; for those it trusts, the clock rule
        (section 10.1) on `head` and on every entry `held` holds below its
        size, and when the bundle's entries existed by."""
        out = []
        imprint = self.h(head.sign1.payload)
        for token in tokens:
            info = timestamps.check_token(token, imprint, self.ledger.hash_alg, self.roots_pem)
            attestation = longterm.token_attestation(info, head.tree_size, anchor, renewal, self.distrust)
            self.items.append(attestation)
            if attestation.set_aside:
                info = dataclasses.replace(info, trusted=False)
            out.append(TokenReport(checkpoint_size=head.tree_size, info=info))
            if not info.trusted:
                continue
            # The clock rule (section 10.1).
            bound = info.time_ms + info.accuracy_ms + timestamps.CLOCK_ALLOWANCE_MS
            if head.timestamp > bound:
                fail("the ledger dated a checkpoint later than a trusted time-stamp authority saw it")
            for index, registered_at in held.items():
                if index < head.tree_size and registered_at > bound:
                    fail("the ledger dated an entry later than a trusted time-stamp authority saw it")
            self.authorities.add(info.authority_id)
            seen = info.time_ms + info.accuracy_ms
            for index in self.bundle_indices:
                if index < head.tree_size and (index not in self.existed_by or seen < self.existed_by[index]):
                    self.existed_by[index] = seen
        return out

    def network(self, head: protocol.TreeHead, cosignatures: list, *, anchor, renewal) -> list:
        """Step 8, for open-network cosignatures of `head`'s note (section
        10.2): none in an SM3 ledger's bundle; one whose name and key ID are a
        trusted witness's must verify against the note, and counts as that
        witness's; the others are counted, by name and key ID, and relied on
        for nothing. The time T of each is reported, and not put to the clock
        rule.

        Returns [(witness identity, NetworkCosignature)], in their order: a
        trusted witness is identified by its verifier key, another by its name
        and key ID."""
        if cosignatures and self.ledger.hash_alg != crypto.SHA256:
            fail("an SM3 ledger's anchor or renewal carries network cosignatures: only SHA-256 ledgers are "
                 "witnessed so (section 10.2)")
        note_origin = network.origin(self.ledger.id)
        out = []
        for name, data in cosignatures:
            key_id = network.cosignature_key_id(data)
            keys = [k for k in self.network_witnesses if k.name == name and k.key_id == key_id]
            when = network.cosignature_time(data)
            algorithm = longterm.NETWORK_NAMES.get(keys[0].kind, "other") if keys else "other"
            set_aside = bool(keys) and algorithm in self.distrust
            trusted = bool(keys) and not set_aside
            report = NetworkCosignature(witness=name, size=head.tree_size, time=when, trusted=trusted)
            attestation = longterm.Attestation(
                kind="network-witness", by=name, algorithms=(algorithm,), time=when * 1000, dated_by=when * 1000,
                checkpoint_size=head.tree_size, anchor=anchor, renewal=renewal, relied_on=trusted,
                set_aside=set_aside, identity=("network", name, key_id))
            self.items.append(attestation)
            if not trusted:
                out.append((("network", name, key_id), report))
                continue
            # Two trusted keys could share a name and a 4-byte key ID: the
            # cosignature is that of the first one it verifies with.
            key = next((k for k in keys
                        if network.verify_cosignature(k, note_origin, head.tree_size, head.root, data)), None)
            if key is None:
                fail(f"a trusted network witness's cosignature does not verify against the note of the checkpoint "
                     f"of size {head.tree_size} ({name})")
            attestation.identity = ("network", key.name, key.key_id, key.kind, key.public.key)
            out.append((attestation.identity, report))
        self.trusted |= {w for w, n in out if n.trusted}
        self.untrusted |= {w for w, n in out if not n.trusted}
        return out


def _check_anchors(ledger: rules.Ledger, checkpoint: protocol.TreeHead, included: dict, anchors: list,
                   tally: Tally):
    """Step 8: each anchor's checkpoint, its network cosignatures, and its
    tokens. Returns (tokens, network cosignatures, the anchors' checkpoints)."""
    h = ledger.h
    size = checkpoint.tree_size
    held = {index: entry.registered_at for index, entry in included.items()}
    reports, cosigned, heads = [], [], []
    for n, anchor in enumerate(anchors, start=1):
        head = protocol.parse_tree_head(anchor.checkpoint, cose.CHECKPOINT_TYPE, "an anchor's checkpoint")
        if head.ledger_id != ledger.id or head.hash != ledger.hash_alg:
            fail("an anchor's checkpoint is of another ledger")
        if head.tree_size > size:
            fail("an anchor's checkpoint is larger than the bundle's")
        ledger.check_signed_head(head, ledger.log_key_for_size(head.tree_size), "an anchor's checkpoint")
        if head.tree_size == size:
            if anchor.consistency is not None or head.root != checkpoint.root:
                fail("an anchor's checkpoint of the bundle's size is not the bundle's checkpoint")
        elif anchor.consistency is None or not merkle.verify_consistency(
                h, head.tree_size, size, head.root, checkpoint.root, anchor.consistency):
            fail("an anchor's checkpoint is not proven consistent with the bundle's")
        heads.append(head)
        cosigned += tally.network(head, anchor.cosignatures, anchor=n, renewal=None)
        reports += tally.tokens(head, anchor.tokens, held, anchor=n, renewal=None)
    return reports, cosigned, heads


__all__ = ["MembershipProof", "NetworkCosignature", "Report", "VerifyError", "event_indices", "involved_objects",
           "registration_time", "verify_bundle"]
