# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya
"""Long-term evidence (spec v0.21, section 11.1): renewals, the long-term
status, and distrusted algorithms.

A renewal is a newer attestation of a bundle's tree: a checkpoint at a size
no smaller than the previous one, proven consistent with it, with the
rotations of the root and log keys in between, followed as a witness follows
them, and its witnesses' cosignatures, time-stamp tokens, and open-network
cosignatures, checked and counted as the bundle's own (section 11, step 11).

Every attestation a bundle holds (its own cosignatures, its anchors' tokens
and network cosignatures, its renewals' three kinds) is kept here as an
Attestation, in the bundle's order, so that the long-term status (the latest
post-quantum attestation that covers the bundle) and the coverage of
signatures by a distrusted algorithm (step 12) are read from one list.
"""

from __future__ import annotations

import calendar
import datetime
import re
from dataclasses import dataclass, field
from typing import NoReturn

from . import cose, crypto, merkle, network, protocol, timestamps
from .errors import UsageError, VerifyError
from .protocol import ACTOR_ROTATE_KEY, LEDGER_ROTATE_LOG_KEY

# Algorithms as section 11.1 names them, in its order; `classical` stands for
# every one but ML-DSA, `other` included.
NAMES = ("ed25519", "ecdsa", "sm2", "rsa", "ml-dsa-44", "ml-dsa-65", "ml-dsa-87", "other")
CLASSICAL = ("ed25519", "ecdsa", "sm2", "rsa", "other")
POST_QUANTUM = ("ml-dsa-44", "ml-dsa-65", "ml-dsa-87")
COSE_NAMES = {crypto.ED25519: "ed25519", crypto.ESP256: "ecdsa", crypto.SM2_SM3: "sm2",
              crypto.MLDSA44: "ml-dsa-44", crypto.MLDSA65: "ml-dsa-65", crypto.MLDSA87: "ml-dsa-87"}
NETWORK_NAMES = {network.COSIGNATURE_ED25519: "ed25519", network.COSIGNATURE_MLDSA44: "ml-dsa-44"}

# Without a post-quantum attestation, a report advises renewing before this
# (NIST IR 8547: classical signatures deprecated after 2030).
RENEW_BEFORE_MS = calendar.timegm((2030, 1, 1, 0, 0, 0)) * 1000

_OPTION = re.compile(r"([a-z0-9-]+)@([0-9]{4})-([0-9]{2})-([0-9]{2})")


def fail(message: str) -> NoReturn:
    raise VerifyError(message)


def cose_name(alg: int) -> str:
    return COSE_NAMES.get(alg, "other")


def parse_distrust(texts: list[str]) -> dict:
    """`--distrust ALG@YYYY-MM-DD`, repeatable: {name: the date, in ms from
    the epoch, at 00:00 UTC}. An unknown algorithm, a date that is none or
    before 1970, and an algorithm named twice (directly or through
    `classical`) are usage errors."""
    out = {}
    for text in texts:
        m = _OPTION.fullmatch(text)
        names = None
        if m is not None:
            names = CLASSICAL if m.group(1) == "classical" else (m.group(1),) if m.group(1) in NAMES[:-1] else None
        if names is None:
            raise UsageError(f"--distrust takes ALG@YYYY-MM-DD, ALG one of {', '.join(NAMES[:-1])}, or classical "
                             f"({text!r})")
        try:
            day = datetime.date(int(m.group(2)), int(m.group(3)), int(m.group(4)))
        except ValueError as e:
            raise UsageError(f"--distrust names a date that is none ({text!r})") from e
        if day.year < 1970:
            # Times are Unix times, from 1970 (as the C++ verifier reads them).
            raise UsageError(f"--distrust names a date before 1970 ({text!r})")
        cutoff = calendar.timegm(day.timetuple()) * 1000
        for name in names:
            if name in out:
                raise UsageError(f"--distrust names {name} twice ({text!r})")
            out[name] = cutoff
    return {name: out[name] for name in NAMES if name in out}


@dataclass
class Attestation:
    """One cosignature, token, or network cosignature a bundle holds, in its
    order (section 11.1)."""
    kind: str  # "witness", "timestamp", or "network-witness"
    by: str  # a witness key's kid (hex), an authority's name, a network witness's name
    algorithms: tuple  # its signature's first; a token's signing certificate's signature's second
    time: int | None  # ms: a token's time, a network cosignature's T, a dated cosignature's iat; else None
    dated_by: int | None  # ms: a token's time plus its accuracy, a network cosignature's T, an iat
    checkpoint_size: int
    anchor: int | None  # the anchor's number from 1, or None
    renewal: int | None  # the renewal's number from 1, or None
    relied_on: bool  # trusted by the verifier, and not set aside
    set_aside: bool  # trusted, but by an algorithm the verifier distrusts
    identity: tuple = ()  # the attester, counted once: a witness's kid, an authority's key, a verifier key

    @property
    def algorithm(self) -> str:
        return self.algorithms[0]

    @property
    def post_quantum(self) -> bool:
        return all(a in POST_QUANTUM for a in self.algorithms)


@dataclass
class RenewalReport:
    """A renewal as a report states it (section 11.1)."""
    checkpoint: protocol.TreeHead
    log_key: crypto.PublicKey
    log_key_rotations: int
    root_key_rotations: int
    witnesses_trusted: int
    witnesses_untrusted: int
    network: list  # [evidence.NetworkCosignature]
    tokens: list  # [evidence.TokenReport]
    rotations: list = field(default_factory=list)  # [(index, COSE alg of its signature)]
    key_algs: tuple = ()  # the COSE algorithms of every root and log key the ledger had up to its checkpoint


def key_in_effect(log_keys: list, size: int) -> crypto.PublicKey:
    """The log key in effect for a tree of `size` entries (section 8)."""
    key = log_keys[0][1]
    for index, k in log_keys:
        if index < size:
            key = k
    return key


def check_renewals(ledger, checkpoint: protocol.TreeHead, renewals: list, tally, held: dict) -> list:
    """Section 11, step 11, for each renewal in order, from the root key and
    log keys the replay reached at the bundle's checkpoint. `tally` checks and
    counts the attestations as the bundle's own; `held` maps every entry the
    bundle holds to its registration time, for the clock rule, and grows with
    each renewal's rotations."""
    h = ledger.h
    root_key = ledger.actors[ledger.id].key
    log_keys = list(ledger.log_keys)
    key_algs = tuple(k.alg for _, k in ledger.root_keys + ledger.log_keys)
    previous = checkpoint
    held = dict(held)
    out = []
    for n, renewal in enumerate(renewals, start=1):
        what = f"renewal {n}"
        head = protocol.parse_tree_head(renewal.checkpoint, cose.CHECKPOINT_TYPE, f"{what}'s checkpoint")
        if head.ledger_id != ledger.id or head.hash != ledger.hash_alg:
            fail(f"{what}'s checkpoint is of another ledger")
        if head.tree_size < previous.tree_size:
            fail(f"{what}'s checkpoint is smaller than the one before it")
        if head.tree_size == previous.tree_size:
            if renewal.consistency is not None or renewal.rotations:
                fail(f"{what} repeats the size before it, and carries a consistency proof or key rotations")
            if head.root != previous.root:
                fail(f"{what} repeats the size before it with another root")
        elif renewal.consistency is None or not merkle.verify_consistency(
                h, previous.tree_size, head.tree_size, previous.root, head.root, renewal.consistency):
            fail(f"{what}'s checkpoint is not proven consistent with the one before it")
        # The rotations in between, followed as a witness follows them.
        last = previous.tree_size - 1
        rotations, log_rotations, root_rotations = [], 0, 0
        for index, encoded, path in renewal.rotations:
            if index <= last or index >= head.tree_size:
                fail(f"{what}'s key rotations do not ascend from the previous size to below its own")
            last = index
            if not merkle.verify_inclusion(h, index, head.tree_size, merkle.leaf_hash(h, encoded), path, head.root):
                fail(f"{what}'s key rotation at {index} is not in its checkpoint's tree")
            entry = protocol.parse_log_entry(encoded)
            if entry.statement is None:
                fail(f"{what}'s entry at {index} rotates no key")
            statement = protocol.parse_statement(entry.statement)
            if entry.id != h(statement.sign1.to_be_signed()):
                fail(f"{what}'s entry at {index} has the wrong statement id")
            if statement.ledger_id != ledger.id or statement.actor != ledger.id or statement.delegation is not None:
                fail(f"{what}'s entry at {index} is not the organization's own statement")
            f = statement.fields
            if statement.type == LEDGER_ROTATE_LOG_KEY:
                is_log = True
            elif statement.type == ACTOR_ROTATE_KEY and f["actor"] == ledger.id:
                is_log = False
            else:
                fail(f"{what}'s entry at {index} rotates no key")
            sign1 = statement.sign1
            if sign1.alg != root_key.alg or sign1.kid != root_key.kid(h) or \
                    not crypto.verify_signature(root_key, sign1.to_be_signed(), sign1.signature):
                fail(f"{what}'s key rotation at {index} is not signed by the root key in effect")
            key = f["key"]
            if crypto.is_weak(key):
                fail(f"{what}'s key rotation at {index} names a weak key")
            if any(k.encoded == key.encoded for _, k in log_keys):
                fail(f"{what}'s key rotation at {index} names a key that was a log key")
            if is_log:
                log_keys.append((index, key))
                log_rotations += 1
            else:
                root_key = key
                root_rotations += 1
            key_algs += (key.alg,)
            rotations.append((index, sign1.alg))
            held[index] = entry.registered_at
        log_key = key_in_effect(log_keys, head.tree_size)
        ledger.check_signed_head(head, log_key, f"{what}'s checkpoint")
        trusted, untrusted = tally.cosignatures(head, renewal.cosignatures, anchor=None, renewal=n)
        tokens = tally.tokens(head, renewal.tokens, held, anchor=None, renewal=n)
        cosigned = tally.network(head, renewal.network, anchor=None, renewal=n)
        trusted |= {w for w, c in cosigned if c.trusted}
        untrusted |= {w for w, c in cosigned if not c.trusted}
        out.append(RenewalReport(checkpoint=head, log_key=log_key, log_key_rotations=log_rotations,
                                 root_key_rotations=root_rotations, witnesses_trusted=len(trusted),
                                 witnesses_untrusted=len(untrusted), network=[c for _, c in cosigned],
                                 tokens=tokens, rotations=rotations, key_algs=key_algs))
        previous = head
    return out


@dataclass
class LongTerm:
    """The long-term status (section 11.1): the latest covering checkpoint
    with a post-quantum attestation, and those attestations, or None."""
    checkpoint: protocol.TreeHead | None
    renewal: int | None
    attested_by: list  # [(kind, by, algorithm, time)]


def long_term(ledger, checkpoint: protocol.TreeHead, log_key: crypto.PublicKey, renewals: list,
              attestations: list, distrust: dict) -> LongTerm:
    """The last covering checkpoint (the bundle's, or a renewal's) with a
    post-quantum attestation the verifier relies on."""
    def usable(name: str) -> bool:
        return name in POST_QUANTUM and name not in distrust

    # The log key's own signature counts if every root and log key up to the
    # checkpoint, the genesis keys first, is ML-DSA (and not distrusted).
    bundle_keys = [k.alg for _, k in ledger.root_keys + ledger.log_keys]
    candidates = [(None, checkpoint, log_key, all(usable(cose_name(a)) for a in bundle_keys))]
    for n, r in enumerate(renewals, start=1):
        candidates.append((n, r.checkpoint, r.log_key, all(usable(cose_name(a)) for a in r.key_algs)))
    for n, head, key, keys_ok in reversed(candidates):
        if n is None:
            mine = [a for a in attestations if a.renewal is None and a.checkpoint_size == head.tree_size]
        else:
            mine = [a for a in attestations if a.renewal == n]
        found, seen = [], set()
        for kind in ("witness", "timestamp", "network-witness"):
            for a in mine:
                if a.kind != kind or not a.relied_on or not a.post_quantum or (kind, a.identity) in seen:
                    continue
                seen.add((kind, a.identity))
                found.append((kind, a.by, a.algorithm, a.time))
        if keys_ok and usable(cose_name(key.alg)):
            found.append(("log-key", key.kid(ledger.h).hex(), cose_name(key.alg), None))
        if found:
            return LongTerm(checkpoint=head, renewal=n, attested_by=found)
    return LongTerm(checkpoint=None, renewal=None, attested_by=[])


@dataclass
class Distrusted:
    """A signature by a distrusted algorithm that the evidence relies on, and
    the dated attestation that covers it (section 11.1)."""
    signed: str
    index: int | None
    tree_size: int | None
    approver: bytes | None
    anchor: int | None
    renewal: int | None
    algorithm: str
    covered_by: Attestation


def relied_signatures(ledger, entries: list, checkpoint, anchors: list, renewals: list) -> list:
    """Every signature steps 1 to 11 relied on, in the order of section 11.1:
    (signed, index, tree size, approver, anchor, renewal, COSE alg)."""
    out = []
    for index, entry, receipt in entries:
        if entry.commitment is not None:
            out.append(("state-commitment", index, None, None, None, None, ledger.commitments[index].sign1.alg))
        else:
            applied = ledger.applied[index]
            out.append(("statement", index, None, None, None, None, applied.statement.sign1.alg))
            if applied.presence is not None:
                out.append(("presence", index, None, None, None, None, applied.presence.alg))
            for result in applied.approvals:
                approver = result.approval.approver
                out.append(("approval", index, None, approver, None, None, result.approval.sign1.alg))
                if result.presence is not None:
                    out.append(("approval-presence", index, None, approver, None, None, result.presence.alg))
        out.append(("receipt", index, checkpoint.tree_size, None, None, None, receipt.alg))
    out.append(("checkpoint", None, checkpoint.tree_size, None, None, None, checkpoint.sign1.alg))
    for n, head in enumerate(anchors, start=1):
        out.append(("anchor", None, head.tree_size, None, n, None, head.sign1.alg))
    for n, r in enumerate(renewals, start=1):
        for index, alg in r.rotations:
            out.append(("rotation", index, None, None, None, n, alg))
        out.append(("renewal", None, r.checkpoint.tree_size, None, None, n, r.checkpoint.sign1.alg))
    return out


def covered(ledger, entries: list, checkpoint, anchors: list, renewals: list, attestations: list,
            distrust: dict) -> list:
    """Section 11, step 12: each signature by a distrusted algorithm that the
    evidence relies on, with the dated attestation that covers it (the
    earliest, the first in the bundle's order among equals). One that none
    covers fails the evidence."""
    if not distrust:
        return []
    # The bundle's own cosignatures, then anchors, then renewals; in each,
    # cosignatures, tokens, then network cosignatures. A witness's
    # cosignature is dated only when it carries its time (v0.21).
    dated = in_bundle_order([a for a in attestations if a.relied_on and a.dated_by is not None])
    out = []
    for signed, index, tree_size, approver, anchor, renewal, alg in relied_signatures(
            ledger, entries, checkpoint, anchors, renewals):
        name = cose_name(alg)
        if name not in distrust:
            continue
        cutoff = distrust[name]
        best = None
        for a in dated:
            # A tree head a log key signed (a receipt among them) is in a
            # tree of at least its size; any other signature, in a tree
            # above its entry's index.
            inside = a.checkpoint_size >= tree_size if tree_size is not None else a.checkpoint_size > index
            dated_by = a.dated_by
            assert dated_by is not None
            if inside and dated_by < cutoff and (best is None or dated_by < (best.dated_by or 0)):
                best = a
        if best is None:
            where = f"entry {index}" if index is not None else f"the checkpoint of size {tree_size}"
            day = datetime.date(1970, 1, 1) + datetime.timedelta(days=cutoff // 86_400_000)
            fail(f"a {signed} signature ({where}) by {name}, distrusted from {day}, is covered by no trusted "
                 "dated attestation (a time-stamp token, a network cosignature, or a dated witness cosignature) "
                 "before it")
        out.append(Distrusted(signed=signed, index=index, tree_size=tree_size, approver=approver, anchor=anchor,
                              renewal=renewal, algorithm=name, covered_by=best))
    return out


def _order(a: Attestation) -> tuple:
    """The bundle's order of attestations (section 11.1): its own
    cosignatures; each anchor's tokens, then network cosignatures; each
    renewal's cosignatures, tokens, then network cosignatures."""
    kinds = {"witness": 0, "timestamp": 1, "network-witness": 2}
    if a.anchor is not None:
        return (1, a.anchor, kinds[a.kind])
    if a.renewal is not None:
        return (2, a.renewal, kinds[a.kind])
    return (0, 0, kinds[a.kind])


def in_bundle_order(items: list) -> list:
    return [a for _, a in sorted(enumerate(items), key=lambda p: _order(p[1]) + (p[0],))]


def token_attestation(info: timestamps.TokenInfo, size: int, anchor, renewal, distrust: dict) -> Attestation:
    set_aside = info.trusted and any(a in distrust for a in info.algorithms)
    return Attestation(kind="timestamp", by=info.authority, algorithms=tuple(info.algorithms), time=info.time_ms,
                       dated_by=info.time_ms + info.accuracy_ms, checkpoint_size=size, anchor=anchor,
                       renewal=renewal, relied_on=info.trusted and not set_aside, set_aside=set_aside,
                       identity=(info.authority_id,))


__all__ = ["Attestation", "Distrusted", "LongTerm", "NAMES", "RENEW_BEFORE_MS", "RenewalReport", "check_renewals",
           "cose_name", "covered", "in_bundle_order", "long_term", "parse_distrust"]
