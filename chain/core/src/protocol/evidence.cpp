// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include <algorithm>
#include <limits>
#include <map>
#include <set>
#include <span>
#include <utility>
#include <variant>
#include <vector>

#include <kanhe/core/merkle.hpp>
#include <kanhe/core/protocol/evidence.hpp>
#include <kanhe/core/protocol/state.hpp>

#include "evidence_detail.hpp"
#include "longterm.hpp"
#include "reader.hpp"

namespace kanhe::protocol {

namespace {

using detail::entry;
using detail::MapReader;

struct Included {
    std::uint64_t index = 0;
    LogEntry log_entry;
    SignedStatement statement;
    /// Set for a state commitment entry, which carries no statement.
    std::optional<SignedStateCommitment> commitment;
    Receipt receipt;
    /// The statement's approvals (v0.20), in its log entry's order.
    std::vector<SignedApproval> approvals = {};
};

std::unexpected<Error> verification_failure(std::string_view detail) {
    return fail(Errc::verification_failed, detail);
}

ActorSummary summarize(const LedgerState& state, const Id& id) {
    ActorSummary summary;
    summary.id = id;
    if (const ActorState* actor = state.actor(id)) {
        summary.kind = actor->kind;
        summary.name = actor->display_name;
        summary.agent = actor->agent;
        summary.revoked = actor->revoked;
        if (actor->responsible) {
            if (const ActorState* responsible = state.actor(*actor->responsible)) {
                summary.responsible = responsible->display_name;
            }
        }
    }
    return summary;
}

std::vector<ActorSummary> authority_chain(const LedgerState& state,
                                          const std::optional<Id>& delegation_id) {
    std::vector<ActorSummary> chain;
    std::optional<Id> next = delegation_id;
    while (next) {
        const DelegationState* delegation = state.delegation(*next);
        if (delegation == nullptr) {
            break;
        }
        chain.push_back(summarize(state, delegation->grantor));
        next = delegation->parent;
    }
    return chain;
}

std::string event_detail(const Statement& statement) {
    if (const auto* b = std::get_if<RecordEndorseBody>(&statement.body)) {
        return b->role;
    }
    if (const auto* b = std::get_if<RecordTransitionBody>(&statement.body)) {
        return b->from_state + " -> " + b->to_state;
    }
    if (const auto* b = std::get_if<RecordRevokeBody>(&statement.body)) {
        return b->reason.value_or("");
    }
    if (const auto* b = std::get_if<ContractCallBody>(&statement.body)) {
        return b->function;
    }
    return {};
}

/// The rules a statement met and the approvals it carried (v0.20), as a
/// report states them.
void report_approvals(const LedgerState& state, const ApprovalTally& tally,
                      std::vector<ApprovalRuleReport>& rules,
                      std::vector<ApprovalReport>& approvals) {
    for (const RuleTally& r : tally.rules) {
        ApprovalRuleReport rule;
        rule.source = r.applied.source;
        rule.delegation = r.applied.delegation;
        rule.rule = r.applied.rule;
        for (const Id& approver : r.applied.rule.approvers) {
            rule.approvers.push_back(summarize(state, approver));
        }
        rule.counted = r.counted;
        rule.signer_counted = r.signer_counts;
        rules.push_back(std::move(rule));
    }
    for (const ApprovalCheck& a : tally.approvals) {
        approvals.push_back(
            ApprovalReport{summarize(state, a.approver), a.approved_at, a.presence});
    }
}

/// A request (v0.8) as the replayed state has it, as of a checkpoint signed
/// at `checkpoint_time`.
RequestReport request_report(const RequestState& r, Timestamp checkpoint_time) {
    return RequestReport{
        .id = r.id,
        .instance = r.instance,
        .call = r.call,
        .position = r.position,
        .kind = r.kind,
        .params = r.params,
        .deadline = r.deadline,
        .reply = r.reply,
        .asked_at = r.asked_at,
        .status = r.status,
        .answered_by = r.answered_by,
        .answered_at = r.answered_at,
        .late_by = r.late_by(),
        .overdue = r.open() && checkpoint_time >= r.deadline,
    };
}

} // namespace

std::vector<std::size_t> InstanceReport::open_requests() const {
    std::vector<std::size_t> out;
    for (std::size_t i = 0; i < requests.size(); ++i) {
        if (!requests[i].status) {
            out.push_back(i);
        }
    }
    return out;
}

std::vector<std::size_t> InstanceReport::overdue_requests() const {
    std::vector<std::size_t> out;
    for (std::size_t i = 0; i < requests.size(); ++i) {
        if (requests[i].overdue) {
            out.push_back(i);
        }
    }
    return out;
}

std::vector<Id> involved_objects(const LedgerState& state, const Id& record,
                                 std::span<const Statement> events, std::span<const Id> related) {
    return involved_objects(state, record, events, related, {});
}

std::vector<Id> approvers_of(const LogEntry& entry) {
    std::vector<Id> out;
    for (const Bytes& encoded : entry.approvals) {
        if (auto approval = parse_approval(encoded)) {
            out.push_back(approval->approval.approver);
        }
    }
    return out;
}

std::vector<Id> involved_objects(const LedgerState& state, const Id& record,
                                 std::span<const Statement> events, std::span<const Id> related,
                                 std::span<const Id> approvers) {
    std::vector<Id> out;
    auto add = [&](const Id& id) {
        if (!std::ranges::contains(out, id)) {
            out.push_back(id);
        }
    };
    add(record);
    if (const InstanceState* instance = state.instance(record)) {
        add(instance->contract);
    }
    for (const Id& id : related) {
        add(id);
    }
    for (const Statement& statement : events) {
        if (!statement.actor_id) {
            continue;
        }
        add(*statement.actor_id);
        if (const ActorState* actor = state.actor(*statement.actor_id);
            actor != nullptr && actor->kind == ActorKind::agent && actor->responsible) {
            add(*actor->responsible);
        }
        std::optional<Id> next = statement.delegation_id;
        for (std::size_t links = 0; next && links < 64; ++links) {
            add(*next);
            const DelegationState* delegation = state.delegation(*next);
            if (delegation == nullptr) {
                break;
            }
            add(delegation->grantor);
            next = delegation->parent;
        }
    }
    for (const Id& id : approvers) {
        add(id);
    }
    return out;
}

// ---------------------------------------------------------------------------
// Encoding
// ---------------------------------------------------------------------------

namespace {

/// An RFC 9162 proof's or path's hashes, each 32 bytes (both ledger
/// hashes'), at most 65.
Status check_hashes(std::span<const crypto::Digest> hashes, Errc code) {
    if (hashes.size() > merkle::max_consistency_proof_length) {
        return fail(code, "a proof holds at most 65 hashes");
    }
    for (const crypto::Digest& h : hashes) {
        if (h.size() != id_size) {
            return fail(code, "a proof's hashes are 32 bytes");
        }
    }
    return {};
}

cbor::Value hashes_value(std::span<const crypto::Digest> hashes) {
    cbor::Array out;
    for (const crypto::Digest& h : hashes) {
        out.push_back(cbor::Value::bytes(h.bytes()));
    }
    return cbor::Value::array(std::move(out));
}

Result<std::vector<crypto::Digest>> hashes_from(const cbor::Value& value) {
    KANHE_TRY(const cbor::Array* list, detail::as_array(value));
    if (list->size() > merkle::max_consistency_proof_length) {
        return fail(Errc::malformed, "a proof holds at most 65 hashes");
    }
    std::vector<crypto::Digest> out;
    out.reserve(list->size());
    for (const cbor::Value& item : *list) {
        const Bytes* bytes = item.as_bytes();
        if (bytes == nullptr || bytes->size() != id_size) {
            return fail(Errc::malformed, "a proof's hashes are 32-byte strings");
        }
        KANHE_TRY(crypto::Digest digest, crypto::Digest::from_bytes(*bytes));
        out.push_back(digest);
    }
    return out;
}

cbor::Value note_signatures_value(std::span<const network::NoteSignature> signatures) {
    cbor::Array out;
    for (const network::NoteSignature& s : signatures) {
        out.push_back(cbor::Value::array({cbor::Value::text(s.name), cbor::Value::bytes(s.bytes)}));
    }
    return cbor::Value::array(std::move(out));
}

/// A non-empty list of note cosignatures (v0.13): [name, 12 to 8,192 bytes].
Result<std::vector<network::NoteSignature>> note_signatures_from(const cbor::Value& value) {
    const cbor::Array* list = value.as_array();
    if (list == nullptr) {
        return fail(Errc::malformed, "expected an array");
    }
    if (list->empty()) {
        return fail(Errc::non_canonical, "an empty list must be omitted");
    }
    std::vector<network::NoteSignature> out;
    for (const cbor::Value& item : *list) {
        const cbor::Array* pair = item.as_array();
        const std::string* name =
            pair != nullptr && pair->size() == 2 ? (*pair)[0].as_text() : nullptr;
        const Bytes* bytes = pair != nullptr && pair->size() == 2 ? (*pair)[1].as_bytes() : nullptr;
        if (name == nullptr || bytes == nullptr || !network::valid_name(*name) ||
            bytes->size() < 12 || bytes->size() > 8192) {
            return fail(Errc::malformed, "a network cosignature is not [name, 12 to 8,192 bytes]");
        }
        out.push_back({*name, *bytes});
    }
    return out;
}

Status check_note_signatures(std::span<const network::NoteSignature> signatures) {
    for (const network::NoteSignature& s : signatures) {
        if (!network::valid_name(s.name) || s.bytes.size() < 12 || s.bytes.size() > 8192) {
            return fail(Errc::invalid_argument,
                        "a network cosignature is not [name, 12 to 8,192 bytes]");
        }
    }
    return {};
}

/// A renewal as a CBOR map (v0.21), every bound of the CDDL checked.
Result<cbor::Value> renewal_value(const Renewal& r) {
    if (r.cosignatures.empty() && r.timestamps.empty() && r.network_cosignatures.empty()) {
        return fail(Errc::invalid_argument,
                    "a renewal needs a cosignature, a time-stamp token, or a network cosignature");
    }
    if (r.rotations.size() > max_key_rotations) {
        return fail(Errc::invalid_argument, "a renewal carries at most 4,096 key rotations");
    }
    KANHE_CHECK(check_hashes(r.consistency, Errc::invalid_argument));
    KANHE_CHECK(check_note_signatures(r.network_cosignatures));
    cbor::Map map{entry(1, cbor::Value::bytes(r.checkpoint))};
    if (!r.consistency.empty()) {
        map.push_back(entry(2, hashes_value(r.consistency)));
    }
    if (!r.rotations.empty()) {
        cbor::Array rotations;
        for (const KeyRotationProof& rotation : r.rotations) {
            KANHE_CHECK(check_hashes(rotation.path, Errc::invalid_argument));
            rotations.push_back(cbor::Value::array({cbor::Value::unsigned_integer(rotation.index),
                                                    cbor::Value::bytes(rotation.entry),
                                                    hashes_value(rotation.path)}));
        }
        map.push_back(entry(3, cbor::Value::array(std::move(rotations))));
    }
    for (const auto& [key, list] : {std::pair{4, &r.cosignatures}, std::pair{5, &r.timestamps}}) {
        if (!list->empty()) {
            cbor::Array items;
            for (const Bytes& item : *list) {
                items.push_back(cbor::Value::bytes(item));
            }
            map.push_back(entry(key, cbor::Value::array(std::move(items))));
        }
    }
    if (!r.network_cosignatures.empty()) {
        map.push_back(entry(6, note_signatures_value(r.network_cosignatures)));
    }
    return cbor::Value::map(std::move(map));
}

Result<Renewal> renewal_from(const cbor::Value& value) {
    KANHE_TRY(MapReader reader, MapReader::open(value));
    Renewal r;
    KANHE_TRY(r.checkpoint, reader.need_bytes(1));
    auto non_empty = [](const cbor::Value& list_value) -> Result<const cbor::Array*> {
        KANHE_TRY(const cbor::Array* list, detail::as_array(list_value));
        if (list->empty()) {
            return fail(Errc::non_canonical, "an empty list must be omitted");
        }
        return list;
    };
    if (const cbor::Value* proof = reader.get(2)) {
        KANHE_TRY(r.consistency, hashes_from(*proof));
        if (r.consistency.empty()) {
            return fail(Errc::non_canonical, "an empty consistency proof must be omitted");
        }
    }
    if (const cbor::Value* rotations = reader.get(3)) {
        KANHE_TRY(const cbor::Array* list, non_empty(*rotations));
        if (list->size() > max_key_rotations) {
            return fail(Errc::malformed, "a renewal carries at most 4,096 key rotations");
        }
        for (const cbor::Value& item : *list) {
            const cbor::Array* parts = item.as_array();
            if (parts == nullptr || parts->size() != 3) {
                return fail(Errc::malformed, "a key rotation must be [index, entry, path]");
            }
            KeyRotationProof rotation;
            KANHE_TRY(rotation.index, detail::as_uint((*parts)[0]));
            KANHE_TRY(rotation.entry, detail::as_bytes_value((*parts)[1]));
            KANHE_TRY(rotation.path, hashes_from((*parts)[2]));
            r.rotations.push_back(std::move(rotation));
        }
    }
    for (const auto& [key, list] : {std::pair{4, &r.cosignatures}, std::pair{5, &r.timestamps}}) {
        if (const cbor::Value* items = reader.get(key)) {
            KANHE_TRY(const cbor::Array* array, non_empty(*items));
            for (const cbor::Value& item : *array) {
                KANHE_TRY(Bytes bytes, detail::as_bytes_value(item));
                list->push_back(std::move(bytes));
            }
        }
    }
    if (const cbor::Value* cosignatures = reader.get(6)) {
        KANHE_TRY(r.network_cosignatures, note_signatures_from(*cosignatures));
    }
    if (r.cosignatures.empty() && r.timestamps.empty() && r.network_cosignatures.empty()) {
        return fail(Errc::malformed, "a renewal holds no attestation: no cosignature, "
                                     "time-stamp token, or network cosignature");
    }
    KANHE_CHECK(reader.finish());
    return r;
}

/// Decoding options for bundles and renewals, which hold many signed
/// objects: more items than the default.
cbor::DecodeOptions large_decode_options() {
    cbor::DecodeOptions options;
    options.max_items = std::size_t{1} << 20;
    return options;
}

} // namespace

Result<Bytes> encode_renewal(const Renewal& renewal) {
    KANHE_TRY(cbor::Value value, renewal_value(renewal));
    return cbor::encode(value);
}

Result<Renewal> decode_renewal(ByteView encoded) {
    if (encoded.size() > max_bundle_size) {
        return fail(Errc::limit_exceeded, "the renewal is too large");
    }
    KANHE_TRY(cbor::Value value, cbor::decode(encoded, large_decode_options()));
    return renewal_from(value);
}

Result<Bytes> encode_bundle(const EvidenceBundle& bundle) {
    if (bundle.entries.empty()) {
        return fail(Errc::invalid_argument, "a bundle needs at least the genesis entry");
    }
    cbor::Array entries;
    for (const EvidenceEntry& e : bundle.entries) {
        entries.push_back(
            cbor::Value::array({cbor::Value::bytes(e.entry), cbor::Value::bytes(e.receipt)}));
    }
    cbor::Map map{
        entry(0, cbor::Value::unsigned_integer(evidence_bundle_version)),
        entry(1, cbor::Value::bytes(bundle.record.bytes())),
        entry(2, cbor::Value::array(std::move(entries))),
        entry(3, cbor::Value::bytes(bundle.checkpoint)),
    };
    if (!bundle.cosignatures.empty()) {
        cbor::Array cosignatures;
        for (const Bytes& c : bundle.cosignatures) {
            cosignatures.push_back(cbor::Value::bytes(c));
        }
        map.push_back(entry(4, cbor::Value::array(std::move(cosignatures))));
    }
    if (!bundle.disclosures.empty()) {
        cbor::Array disclosures;
        for (const FieldDisclosure& d : bundle.disclosures) {
            cbor::Array path;
            for (const crypto::Digest& node : d.path) {
                path.push_back(cbor::Value::bytes(node.bytes()));
            }
            disclosures.push_back(cbor::Value::array({cbor::Value::bytes(d.leaf),
                                                      cbor::Value::unsigned_integer(d.index),
                                                      cbor::Value::array(std::move(path))}));
        }
        map.push_back(entry(5, cbor::Value::array(std::move(disclosures))));
    }
    if (!bundle.attachments.empty()) {
        cbor::Array attachments;
        for (const AttachmentOpening& a : bundle.attachments) {
            attachments.push_back(
                cbor::Value::array({cbor::Value::text(a.name), cbor::Value::bytes(a.salt)}));
        }
        map.push_back(entry(6, cbor::Value::array(std::move(attachments))));
    }
    if (!bundle.state_proofs.empty()) {
        cbor::Array proofs;
        for (const StateProof& p : bundle.state_proofs) {
            KANHE_TRY(Bytes leaf, encode_state_leaf(p.leaf));
            KANHE_TRY(cbor::Value leaf_value, cbor::decode(leaf));
            cbor::Array siblings;
            for (const crypto::Digest& s : p.siblings) {
                siblings.push_back(cbor::Value::bytes(s.bytes()));
            }
            proofs.push_back(cbor::Value::array(
                {std::move(leaf_value), cbor::Value::array(std::move(siblings))}));
        }
        map.push_back(entry(7, cbor::Value::array(std::move(proofs))));
    }
    if (!bundle.anchors.empty()) {
        cbor::Array anchors;
        for (const Anchor& a : bundle.anchors) {
            if (a.timestamps.empty() && a.network_cosignatures.empty()) {
                return fail(Errc::invalid_argument,
                            "an anchor needs a time-stamp token or a network cosignature");
            }
            cbor::Map anchor{entry(1, cbor::Value::bytes(a.checkpoint))};
            if (!a.timestamps.empty()) {
                cbor::Array tokens;
                for (const Bytes& token : a.timestamps) {
                    tokens.push_back(cbor::Value::bytes(token));
                }
                anchor.push_back(entry(2, cbor::Value::array(std::move(tokens))));
            }
            if (!a.consistency.empty()) {
                cbor::Array proof;
                for (const crypto::Digest& node : a.consistency) {
                    proof.push_back(cbor::Value::bytes(node.bytes()));
                }
                anchor.push_back(entry(3, cbor::Value::array(std::move(proof))));
            }
            if (!a.network_cosignatures.empty()) {
                cbor::Array cosignatures;
                for (const network::NoteSignature& s : a.network_cosignatures) {
                    cosignatures.push_back(cbor::Value::array(
                        {cbor::Value::text(s.name), cbor::Value::bytes(s.bytes)}));
                }
                anchor.push_back(entry(4, cbor::Value::array(std::move(cosignatures))));
            }
            anchors.push_back(cbor::Value::map(std::move(anchor)));
        }
        map.push_back(entry(8, cbor::Value::array(std::move(anchors))));
    }
    if (!bundle.memberships.empty()) {
        if (bundle.memberships.size() > max_membership_proofs) {
            return fail(Errc::invalid_argument, "a bundle carries at most 16 membership proofs");
        }
        cbor::Array proofs;
        for (const Bytes& proof : bundle.memberships) {
            proofs.push_back(cbor::Value::bytes(proof));
        }
        map.push_back(entry(9, cbor::Value::array(std::move(proofs))));
    }
    if (!bundle.source_proofs.empty()) {
        if (bundle.source_proofs.size() > max_source_proofs) {
            return fail(Errc::invalid_argument, "a bundle carries at most 64 source proofs");
        }
        cbor::Array proofs;
        for (const Bytes& proof : bundle.source_proofs) {
            proofs.push_back(cbor::Value::bytes(proof));
        }
        map.push_back(entry(10, cbor::Value::array(std::move(proofs))));
    }
    if (!bundle.renewals.empty()) {
        if (bundle.renewals.size() > max_renewals) {
            return fail(Errc::invalid_argument, "a bundle carries at most 64 renewals");
        }
        cbor::Array renewals;
        for (const Renewal& r : bundle.renewals) {
            KANHE_TRY(cbor::Value value, renewal_value(r));
            renewals.push_back(std::move(value));
        }
        map.push_back(entry(11, cbor::Value::array(std::move(renewals))));
    }
    return cbor::encode(cbor::Value::map(std::move(map)));
}

Result<Id> bundle_ledger_id(ByteView encoded) {
    KANHE_TRY(EvidenceBundle bundle, decode_bundle(encoded));
    if (bundle.entries.empty()) {
        return fail(Errc::malformed, "the bundle has no genesis entry");
    }
    KANHE_TRY(LogEntry genesis, decode_log_entry(bundle.entries.front().entry));
    return genesis.statement_id;
}

Result<EvidenceBundle> decode_bundle(ByteView encoded) {
    if (encoded.size() > max_bundle_size) {
        return fail(Errc::limit_exceeded, "the evidence bundle is too large");
    }
    // Bundles hold many signed objects; allow more items than the default.
    KANHE_TRY(cbor::Value value, cbor::decode(encoded, large_decode_options()));
    KANHE_TRY(MapReader reader, MapReader::open(value));
    EvidenceBundle bundle;

    KANHE_TRY(std::uint64_t version, reader.need_uint(0));
    if (version != evidence_bundle_version) {
        return fail(Errc::unsupported, "unsupported evidence bundle version");
    }
    KANHE_TRY(bundle.record, reader.need_id(1));

    KANHE_TRY(const cbor::Value* entries_value, reader.need(2));
    KANHE_TRY(const cbor::Array* entries, detail::as_array(*entries_value));
    if (entries->empty()) {
        return fail(Errc::malformed, "a bundle needs at least the genesis entry");
    }
    for (const cbor::Value& item : *entries) {
        const cbor::Array* pair = item.as_array();
        if (pair == nullptr || pair->size() != 2) {
            return fail(Errc::malformed, "evidence entry must be [entry, receipt]");
        }
        EvidenceEntry e;
        KANHE_TRY(e.entry, detail::as_bytes_value((*pair)[0]));
        KANHE_TRY(e.receipt, detail::as_bytes_value((*pair)[1]));
        bundle.entries.push_back(std::move(e));
    }
    KANHE_TRY(bundle.checkpoint, reader.need_bytes(3));

    auto non_empty_list = [](const cbor::Value& list_value) -> Result<const cbor::Array*> {
        const cbor::Array* list = list_value.as_array();
        if (list == nullptr) {
            return fail(Errc::malformed, "expected an array");
        }
        if (list->empty()) {
            return fail(Errc::non_canonical, "an empty list must be omitted");
        }
        return list;
    };
    if (const cbor::Value* list_value = reader.get(4)) {
        KANHE_TRY(const cbor::Array* list, non_empty_list(*list_value));
        for (const cbor::Value& item : *list) {
            KANHE_TRY(Bytes cosignature, detail::as_bytes_value(item));
            bundle.cosignatures.push_back(std::move(cosignature));
        }
    }
    if (const cbor::Value* list_value = reader.get(5)) {
        KANHE_TRY(const cbor::Array* list, non_empty_list(*list_value));
        for (const cbor::Value& item : *list) {
            const cbor::Array* parts = item.as_array();
            if (parts == nullptr || parts->size() != 3) {
                return fail(Errc::malformed, "field disclosure must be [leaf, index, path]");
            }
            FieldDisclosure d;
            KANHE_TRY(d.leaf, detail::as_bytes_value((*parts)[0]));
            KANHE_TRY(d.index, detail::as_uint((*parts)[1]));
            KANHE_TRY(const cbor::Array* path, detail::as_array((*parts)[2]));
            for (const cbor::Value& node : *path) {
                KANHE_TRY(Bytes bytes, detail::as_bytes_value(node));
                KANHE_TRY(crypto::Digest digest, crypto::Digest::from_bytes(bytes));
                d.path.push_back(digest);
            }
            bundle.disclosures.push_back(std::move(d));
        }
    }
    if (const cbor::Value* list_value = reader.get(6)) {
        KANHE_TRY(const cbor::Array* list, non_empty_list(*list_value));
        for (const cbor::Value& item : *list) {
            const cbor::Array* parts = item.as_array();
            if (parts == nullptr || parts->size() != 2) {
                return fail(Errc::malformed, "attachment opening must be [name, salt]");
            }
            AttachmentOpening a;
            KANHE_TRY(a.name, detail::as_text((*parts)[0]));
            // 16 or 32 bytes (v0.21).
            const Bytes* salt = (*parts)[1].as_bytes();
            if (salt == nullptr || !Salt::valid_size(salt->size())) {
                return fail(Errc::malformed, "attachment salt must be 16 or 32 bytes");
            }
            KANHE_TRY(a.salt, Salt::from_bytes(*salt));
            bundle.attachments.push_back(std::move(a));
        }
    }
    if (const cbor::Value* list_value = reader.get(7)) {
        KANHE_TRY(const cbor::Array* list, non_empty_list(*list_value));
        for (const cbor::Value& item : *list) {
            const cbor::Array* parts = item.as_array();
            const cbor::Array* leaf =
                parts == nullptr || parts->size() != 2 ? nullptr : (*parts)[0].as_array();
            if (leaf == nullptr || leaf->size() != 3 || (*parts)[1].as_array() == nullptr) {
                return fail(Errc::malformed,
                            "a state proof must be [[kind, id, history], siblings]");
            }
            StateProof p;
            KANHE_TRY(std::uint64_t kind, detail::as_uint((*leaf)[0]));
            if (kind < 1 || kind > static_cast<std::uint64_t>(ObjectKind::instance)) {
                return fail(Errc::malformed, "a state proof names an unknown kind of object");
            }
            p.leaf.kind = static_cast<ObjectKind>(kind);
            KANHE_TRY(Bytes id, detail::as_bytes_value((*leaf)[1]));
            KANHE_TRY(p.leaf.id, to_id(id));
            KANHE_TRY(const cbor::Array* history, detail::as_array((*leaf)[2]));
            for (const cbor::Value& index : *history) {
                KANHE_TRY(std::uint64_t i, detail::as_uint(index));
                p.leaf.history.push_back(i);
            }
            const cbor::Array& siblings = *(*parts)[1].as_array();
            if (siblings.size() > id_size * 8) {
                return fail(Errc::malformed, "a state proof is deeper than the tree");
            }
            for (const cbor::Value& node : siblings) {
                KANHE_TRY(Bytes bytes, detail::as_bytes_value(node));
                KANHE_TRY(crypto::Digest digest, crypto::Digest::from_bytes(bytes));
                p.siblings.push_back(digest);
            }
            if (!encode_state_leaf(p.leaf)) {
                return fail(Errc::malformed,
                            "a state proof's history must be non-empty and ascending");
            }
            bundle.state_proofs.push_back(std::move(p));
        }
    }
    if (const cbor::Value* list_value = reader.get(8)) {
        KANHE_TRY(const cbor::Array* list, non_empty_list(*list_value));
        for (const cbor::Value& item : *list) {
            KANHE_TRY(MapReader anchor_reader, MapReader::open(item));
            Anchor a;
            KANHE_TRY(a.checkpoint, anchor_reader.need_bytes(1));
            if (const cbor::Value* tokens_value = anchor_reader.get(2)) {
                KANHE_TRY(const cbor::Array* tokens, non_empty_list(*tokens_value));
                for (const cbor::Value& token : *tokens) {
                    KANHE_TRY(Bytes bytes, detail::as_bytes_value(token));
                    a.timestamps.push_back(std::move(bytes));
                }
            }
            if (const cbor::Value* proof_value = anchor_reader.get(3)) {
                KANHE_TRY(const cbor::Array* proof, non_empty_list(*proof_value));
                if (proof->size() > merkle::max_consistency_proof_length) {
                    return fail(Errc::malformed, "an anchor's consistency proof is too long");
                }
                for (const cbor::Value& node : *proof) {
                    KANHE_TRY(Bytes bytes, detail::as_bytes_value(node));
                    KANHE_TRY(crypto::Digest digest, crypto::Digest::from_bytes(bytes));
                    a.consistency.push_back(digest);
                }
            }
            if (const cbor::Value* cosignatures_value = anchor_reader.get(4)) {
                KANHE_TRY(a.network_cosignatures, note_signatures_from(*cosignatures_value));
            }
            if (a.timestamps.empty() && a.network_cosignatures.empty()) {
                return fail(Errc::malformed,
                            "an anchor holds no time-stamp token and no network cosignature");
            }
            KANHE_CHECK(anchor_reader.finish());
            bundle.anchors.push_back(std::move(a));
        }
    }
    if (const cbor::Value* list_value = reader.get(9)) {
        KANHE_TRY(const cbor::Array* list, non_empty_list(*list_value));
        if (list->size() > max_membership_proofs) {
            return fail(Errc::malformed, "a bundle carries at most 16 membership proofs");
        }
        for (const cbor::Value& item : *list) {
            KANHE_TRY(Bytes proof, detail::as_bytes_value(item));
            bundle.memberships.push_back(std::move(proof));
        }
    }
    if (const cbor::Value* list_value = reader.get(10)) {
        KANHE_TRY(const cbor::Array* list, non_empty_list(*list_value));
        if (list->size() > max_source_proofs) {
            return fail(Errc::malformed, "a bundle carries at most 64 source proofs");
        }
        for (const cbor::Value& item : *list) {
            KANHE_TRY(Bytes proof, detail::as_bytes_value(item));
            bundle.source_proofs.push_back(std::move(proof));
        }
    }
    // Renewals (v0.21): 1 to 64, in order; checked in step 11.
    if (const cbor::Value* list_value = reader.get(11)) {
        KANHE_TRY(const cbor::Array* list, non_empty_list(*list_value));
        if (list->size() > max_renewals) {
            return fail(Errc::malformed, "a bundle carries at most 64 renewals");
        }
        for (const cbor::Value& item : *list) {
            KANHE_TRY(Renewal renewal, renewal_from(item));
            bundle.renewals.push_back(std::move(renewal));
        }
    }
    KANHE_CHECK(reader.finish());
    return bundle;
}

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------

namespace {

/// Checks the bundle's anchors (v0.11) into `report`: each checkpoint signed
/// by the log key in effect at its size and consistent with the bundle's,
/// its network cosignatures of its note (v0.13), and its tokens over its
/// payload, checked and counted in `tally` (step 8). A trusted token bounds
/// when the entries below its checkpoint's size existed, and the ledger's
/// clock must agree with it. Returns the anchors' checkpoints.
Result<std::vector<SignedCheckpoint>> check_anchors(const crypto::Provider& provider,
                                                    const LedgerState& state,
                                                    const SignedCheckpoint& checkpoint,
                                                    const EvidenceBundle& bundle,
                                                    const std::map<std::uint64_t, Timestamp>& held,
                                                    detail::Tally& tally, EvidenceReport& report) {
    std::vector<SignedCheckpoint> heads;
    for (std::size_t n = 1; n <= bundle.anchors.size(); ++n) {
        const Anchor& anchor = bundle.anchors[n - 1];
        auto stamped = parse_checkpoint(anchor.checkpoint);
        if (!stamped || !stamped->envelope.payload) {
            return verification_failure("an anchor's checkpoint is malformed");
        }
        const Checkpoint& at = stamped->checkpoint;
        if (at.ledger_id != state.ledger_id() || at.tree_hash != state.hash()) {
            return verification_failure("an anchor's checkpoint belongs to a different ledger");
        }
        if (at.tree_size > checkpoint.checkpoint.tree_size) {
            return verification_failure("an anchor's checkpoint is later than the bundle's");
        }
        if (!verify_checkpoint(provider, *stamped, state.log_key_for(at.tree_size))) {
            return verification_failure(
                "an anchor's checkpoint is not signed by the ledger's log key");
        }
        if (at.tree_size == checkpoint.checkpoint.tree_size) {
            if (at.root != checkpoint.checkpoint.root || !anchor.consistency.empty()) {
                return verification_failure("an anchor's checkpoint disagrees with the bundle's");
            }
        } else if (!merkle::verify_consistency(provider, state.hash(), at.tree_size,
                                               checkpoint.checkpoint.tree_size, at.root,
                                               checkpoint.checkpoint.root, anchor.consistency)) {
            return verification_failure(
                "an anchor's checkpoint is not consistent with the bundle's");
        }
        // Open-network witnesses' cosignatures of the checkpoint's note
        // (v0.13), then the tokens.
        if (auto cosigned = tally.note_cosignatures(*stamped, anchor.network_cosignatures, n,
                                                    std::nullopt, report.network_cosignatures);
            !cosigned) {
            return std::unexpected(cosigned.error());
        }
        KANHE_CHECK(tally.tokens(*stamped, anchor.timestamps, held, n, std::nullopt,
                                 report.timestamps, report.events));
        heads.push_back(std::move(*stamped));
    }
    return heads;
}

/// A source's status at the record's registration and at a checkpoint,
/// from when it was registered, revoked, and replaced.
void set_statuses(SourceReport& s, Timestamp registered, std::optional<Timestamp> revoked,
                  std::optional<Timestamp> replaced, std::optional<Id> replaced_by) {
    s.at_record = source_status_at(registered, revoked, replaced, s.record_time);
    s.at_checkpoint = source_status_at(registered, revoked, replaced, s.checkpoint_time);
    if (s.at_checkpoint == SourceStatus::revoked) {
        s.changed_at = revoked;
    } else if (s.at_checkpoint == SourceStatus::replaced) {
        s.changed_at = replaced;
        s.replaced_by = std::move(replaced_by);
    }
}

/// Step 10 (v0.18): each source proof is a complete bundle of its own
/// ledger, about one of the record's sources there; it says where the
/// source stood when the record was registered and at its checkpoint.
Result<EvidenceReport> check_sources(const crypto::Provider& provider, const EvidenceBundle& bundle,
                                     const VerifyOptions& options, EvidenceReport report) {
    if (bundle.source_proofs.empty()) {
        return report;
    }
    VerifyOptions inner;
    inner.trusted_witnesses = options.trusted_witnesses;
    inner.trusted_timestamp_roots = options.trusted_timestamp_roots;
    inner.trusted_network_witnesses = options.trusted_network_witnesses;
    inner.trust_nodes = options.trust_nodes;
    inner.modules = options.modules;
    inner.distrust = options.distrust;
    for (const Bytes& proof : bundle.source_proofs) {
        auto decoded = decode_bundle(proof);
        if (!decoded) {
            return verification_failure("a source proof is malformed");
        }
        if (!decoded->source_proofs.empty()) {
            return verification_failure("a source proof carries source proofs");
        }
        auto checked = detail::verify_bundle_as_given(provider, proof, inner);
        if (!checked) {
            return verification_failure("a source proof does not verify");
        }
        if (!checked->complete) {
            return verification_failure("a source proof is not complete");
        }
        if (checked->instance || checked->events.empty()) {
            return verification_failure("a source proof is not a record's");
        }
        const auto named = std::ranges::find_if(report.sources, [&](const SourceReport& s) {
            return !s.local && s.source.ledger == checked->ledger_id &&
                   s.source.record == checked->record;
        });
        if (named == report.sources.end()) {
            return verification_failure(
                "a source proof is not of a source the record names on another ledger");
        }
        if (named->provided) {
            return verification_failure("a source is proven twice");
        }
        SourceReport& s = *named;
        s.provided = true;
        s.type = checked->record_type;
        s.organization = checked->organization;
        for (const auto& m : checked->memberships) {
            if (m.trusted && m.at_checkpoint == Standing::active) {
                s.trust_node = m.trust_node_name;
                break;
            }
        }
        std::optional<Timestamp> revoked;
        std::optional<Timestamp> replaced;
        std::optional<Id> replaced_by;
        for (const RecordEvent& e : checked->events) {
            if (e.type == StatementType::record_revoke && !revoked) {
                revoked = e.registered_at;
            }
            if (e.new_version && !replaced) {
                replaced = e.registered_at;
                replaced_by = e.new_version;
            }
        }
        s.checkpoint_time = checked->checkpoint.timestamp;
        set_statuses(s, checked->events.front().registered_at, revoked, replaced, replaced_by);
    }
    return report;
}

/// Step 9 (v0.16): each membership proof is a complete bundle of its own
/// ledger, about a membership that names this bundle's ledger; it says where
/// the membership stood when the record was registered (an instance's
/// creating call) and at the proof's checkpoint.
Result<EvidenceReport> check_memberships(const crypto::Provider& provider,
                                         const EvidenceBundle& bundle, const VerifyOptions& options,
                                         EvidenceReport report) {
    if (bundle.memberships.empty()) {
        return report;
    }
    const RecordEvent* registered = nullptr;
    if (report.instance) {
        const auto it =
            std::ranges::find(report.events, report.instance->created_by, &RecordEvent::index);
        registered = it == report.events.end() ? nullptr : &*it;
    } else if (!report.events.empty()) {
        registered = &report.events.front();
    }
    if (registered == nullptr) {
        return verification_failure("the bundle does not show when its record was registered");
    }
    // The proofs are other ledgers' evidence: none is expected, and the
    // verifier's trust in witnesses and authorities applies to them too.
    VerifyOptions inner;
    inner.trusted_witnesses = options.trusted_witnesses;
    inner.trusted_timestamp_roots = options.trusted_timestamp_roots;
    inner.trusted_network_witnesses = options.trusted_network_witnesses;
    inner.modules = options.modules;
    inner.distrust = options.distrust;
    std::vector<std::pair<Id, Id>> seen;
    for (const Bytes& proof : bundle.memberships) {
        auto decoded = decode_bundle(proof);
        if (!decoded) {
            return verification_failure("a membership proof is malformed");
        }
        if (!decoded->memberships.empty()) {
            return verification_failure("a membership proof carries membership proofs");
        }
        auto checked = detail::verify_bundle_as_given(provider, proof, inner);
        if (!checked) {
            return verification_failure("a membership proof does not verify");
        }
        if (!checked->complete) {
            return verification_failure("a membership proof is not complete");
        }
        if (checked->record_type != membership_type || !checked->metadata ||
            checked->events.empty()) {
            return verification_failure("a membership proof is not of a membership");
        }
        auto membership = decode_membership(*checked->metadata);
        if (!membership) {
            return verification_failure("a membership proof's metadata is not a membership");
        }
        if (membership->member != report.ledger_id) {
            return verification_failure("a membership proof names another ledger as its member");
        }
        std::pair key{checked->ledger_id, checked->record};
        if (std::ranges::contains(seen, key)) {
            return verification_failure("a membership is proven twice");
        }
        seen.push_back(std::move(key));
        // Its history after its registration: transitions ("from -> to")
        // and a revocation.
        std::vector<MembershipChange> changes;
        for (const RecordEvent& e : checked->events) {
            if (e.type == StatementType::record_transition) {
                const std::size_t arrow = e.detail.find(" -> ");
                changes.push_back({e.registered_at,
                                   arrow == std::string::npos ? "" : e.detail.substr(arrow + 4)});
            } else if (e.type == StatementType::record_revoke) {
                changes.push_back({e.registered_at, ""});
            }
        }
        EvidenceReport::MembershipReport m;
        m.trust_node = checked->ledger_id;
        const auto node = std::ranges::find(options.trust_nodes, m.trust_node, &TrustNode::ledger);
        m.trusted = node != options.trust_nodes.end();
        if (m.trusted) {
            m.trust_node_name = node->name;
        }
        m.record = checked->record;
        m.registered_at = checked->events.front().registered_at;
        m.membership = std::move(*membership);
        m.record_time = registered->registered_at;
        m.at_record = standing_at(m.membership, m.registered_at, changes, m.record_time);
        m.checkpoint_time = checked->checkpoint.timestamp;
        m.at_checkpoint = standing_at(m.membership, m.registered_at, changes, m.checkpoint_time);
        report.memberships.push_back(std::move(m));
    }
    return report;
}

/// The last steps of a verification: witnesses (step 6), anchors (8),
/// memberships (9), sources (10), renewals (11), and the signatures by
/// distrusted algorithms with the long-term status (12, v0.21). `relied` is
/// every signature the entries carry that the steps before relied on, in
/// log order (section 11.1); the tree heads' follow here.
Result<EvidenceReport> finish_report(const crypto::Provider& provider, const LedgerState& state,
                                     const SignedCheckpoint& checkpoint,
                                     const EvidenceBundle& bundle,
                                     std::span<const Included> included,
                                     std::vector<detail::ReliedSignature> relied,
                                     const VerifyOptions& options, EvidenceReport report) {
    // Every attestation of the bundle, its anchors, and its renewals, each
    // witness and authority counted once across them.
    detail::Tally tally(provider, state, options);
    if (auto own = tally.cosignatures(checkpoint, bundle.cosignatures, std::nullopt, std::nullopt);
        !own) {
        return std::unexpected(own.error());
    }
    std::map<std::uint64_t, Timestamp> held;
    for (const Included& i : included) {
        held.emplace(i.index, i.log_entry.registered_at);
    }
    KANHE_TRY(std::vector<SignedCheckpoint> anchors,
              check_anchors(provider, state, checkpoint, bundle, held, tally, report));
    KANHE_TRY(report, check_memberships(provider, bundle, options, std::move(report)));
    KANHE_TRY(report, check_sources(provider, bundle, options, std::move(report)));
    KANHE_TRY(std::vector<detail::CheckedRenewal> renewals,
              detail::check_renewals(provider, state, checkpoint, bundle.renewals, tally,
                                     std::move(held), report.events));
    report.trusted_cosignatures = tally.trusted_witnesses();
    report.untrusted_cosignatures = tally.untrusted_witnesses();
    report.trusted_timestamp_authorities = tally.trusted_authorities();
    for (const detail::CheckedRenewal& r : renewals) {
        report.renewals.push_back(r.report);
    }

    // The tree heads the log key signed: the checkpoint, each anchor's, and
    // each renewal's, after its rotations.
    const std::uint64_t size = checkpoint.checkpoint.tree_size;
    relied.push_back({SignedObject::checkpoint, std::nullopt, size, std::nullopt, std::nullopt,
                      std::nullopt, checkpoint.envelope.algorithm});
    for (std::size_t n = 0; n < anchors.size(); ++n) {
        relied.push_back({SignedObject::anchor, std::nullopt, anchors[n].checkpoint.tree_size,
                          std::nullopt, n + 1, std::nullopt, anchors[n].envelope.algorithm});
    }
    for (std::size_t n = 0; n < renewals.size(); ++n) {
        for (const auto& [index, algorithm] : renewals[n].rotations) {
            relied.push_back({SignedObject::rotation, index, std::nullopt, std::nullopt,
                              std::nullopt, n + 1, algorithm});
        }
        relied.push_back({SignedObject::renewal, std::nullopt,
                          renewals[n].head.checkpoint.tree_size, std::nullopt, std::nullopt, n + 1,
                          renewals[n].head.envelope.algorithm});
    }
    report.distrust = options.distrust;
    KANHE_TRY(report.distrusted, detail::cover(relied, tally.items(), options.distrust));
    report.set_aside = detail::set_aside_attestations(tally.items());
    KANHE_TRY(report.long_term,
              detail::long_term_status(provider, state, checkpoint, state.log_key_for(size),
                                       renewals, tally.items(), options.distrust));
    return report;
}

} // namespace

SourceStatus source_status_at(Timestamp registered, std::optional<Timestamp> revoked,
                              std::optional<Timestamp> replaced, Timestamp t) noexcept {
    if (t < registered) {
        return SourceStatus::not_yet;
    }
    if (revoked && *revoked <= t) {
        return SourceStatus::revoked;
    }
    if (replaced && *replaced <= t) {
        return SourceStatus::replaced;
    }
    return SourceStatus::live;
}

std::string_view source_status_name(SourceStatus status) noexcept {
    switch (status) {
    case SourceStatus::not_yet:
        return "not yet registered";
    case SourceStatus::live:
        return "live";
    case SourceStatus::revoked:
        return "revoked";
    case SourceStatus::replaced:
        return "replaced";
    }
    return "unknown";
}

Result<crypto::Digest> CheckedProvider::do_digest(crypto::HashAlg alg,
                                                  std::span<const ByteView> parts) const {
    return provider_.digest(alg, parts);
}

Status CheckedProvider::do_verify(const crypto::PublicKey& key, ByteView message,
                                  ByteView signature) const {
    if (std::optional<Status> known = checks_.find(key, message, signature)) {
        return std::move(*known);
    }
    Status outcome = provider_.verify(key, message, signature);
    checks_.checked(key, message, signature, outcome);
    return outcome;
}

Result<crypto::TimestampToken>
CheckedProvider::do_read_timestamp(ByteView token, std::span<const Bytes> trusted_roots) const {
    return provider_.read_timestamp(token, trusted_roots);
}

Result<EvidenceReport> verify_bundle(const crypto::Provider& provider, ByteView encoded,
                                     const VerifyOptions& options) {
    if (options.signatures == nullptr) {
        return detail::verify_bundle_as_given(provider, encoded, options);
    }
    const CheckedProvider checked(provider, *options.signatures);
    return detail::verify_bundle_as_given(checked, encoded, options);
}

Result<EvidenceReport> detail::verify_bundle_as_given(const crypto::Provider& provider,
                                                      ByteView encoded,
                                                      const VerifyOptions& options) {
    KANHE_TRY(EvidenceBundle bundle, decode_bundle(encoded));

    // Genesis fixes the ledger's identity, hash, and keys.
    KANHE_TRY(LogEntry genesis_entry, decode_log_entry(bundle.entries.front().entry));
    KANHE_TRY(SignedStatement genesis, parse_statement(provider, genesis_entry.statement));
    if (genesis.id != genesis_entry.statement_id) {
        return verification_failure("the genesis entry has the wrong statement id");
    }
    if (!genesis_entry.approvals.empty()) {
        return verification_failure("the genesis entry carries no approvals");
    }
    auto state = LedgerState::from_genesis(provider, genesis, genesis_entry.registered_at);
    if (!state) {
        // from_genesis's details are literals: kept as they are.
        return verification_failure(state.error().detail);
    }
    state->replay_bundle();
    state->load_modules_with(options.modules);
    if (options.expected_ledger && *options.expected_ledger != state->ledger_id()) {
        return verification_failure("the bundle comes from a different ledger");
    }

    // The checkpoint every receipt must lead to. Its signature, and the
    // receipts', are checked with the log key in effect at its size, which
    // the replay below learns (the bundle carries every key rotation).
    KANHE_TRY(SignedCheckpoint checkpoint, parse_checkpoint(bundle.checkpoint));
    if (checkpoint.checkpoint.ledger_id != state->ledger_id() ||
        checkpoint.checkpoint.tree_hash != state->hash()) {
        return verification_failure("the checkpoint belongs to a different ledger");
    }

    // Every entry is proven to lead to the checkpoint's root, in order.
    // Receipts share the upper parts of their paths: each part is hashed
    // once (the memo points into the receipts, kept in `included`, which
    // never reallocates).
    std::vector<Included> included;
    included.reserve(bundle.entries.size());
    merkle::InclusionMemo memo;
    std::optional<std::uint64_t> previous_index;
    Timestamp previous_time = 0;
    for (const EvidenceEntry& e : bundle.entries) {
        auto receipt = parse_receipt(e.receipt);
        if (!receipt) {
            return verification_failure("a receipt is malformed");
        }
        auto root = receipt_root(provider, *receipt, e.entry, &memo);
        if (!root || receipt->tree_hash != state->hash() ||
            receipt->proof.tree_size != checkpoint.checkpoint.tree_size ||
            *root != checkpoint.checkpoint.root) {
            return verification_failure("an entry is not proven to be in the checkpointed log");
        }
        const std::uint64_t index = receipt->proof.leaf_index;
        if ((!previous_index && index != 0) || (previous_index && index <= *previous_index)) {
            return verification_failure("entries must start at genesis and ascend by log index");
        }
        KANHE_TRY(LogEntry log_entry, decode_log_entry(e.entry));
        if (log_entry.registered_at < previous_time) {
            return verification_failure("entries go back in time");
        }
        Included item{index, log_entry, genesis, std::nullopt, std::move(*receipt)};
        if (index != 0 && log_entry.is_state_commitment()) {
            auto commitment = parse_state_commitment(provider, log_entry.state_commitment);
            if (!commitment || commitment->id != log_entry.statement_id ||
                commitment->commitment.ledger_id != state->ledger_id() ||
                commitment->commitment.tree_hash != state->hash() ||
                commitment->commitment.tree_size != index) {
                return verification_failure("a state commitment in the bundle does not verify");
            }
            item.commitment = std::move(*commitment);
        } else if (index != 0) {
            KANHE_TRY(item.statement,
                      parse_statement(provider, log_entry.statement, state->hash()));
            if (item.statement.id != log_entry.statement_id) {
                return verification_failure("an entry has the wrong statement id");
            }
            // Its approvals (v0.20), in the entry's order: replay checks it.
            for (const Bytes& approval_bytes : log_entry.approvals) {
                auto approval = parse_approval(approval_bytes);
                if (!approval) {
                    return verification_failure("an approval in the bundle is malformed");
                }
                item.approvals.push_back(std::move(*approval));
            }
        } else if (log_entry != genesis_entry) {
            return verification_failure("the genesis entry is inconsistent");
        }
        previous_index = index;
        previous_time = log_entry.registered_at;
        included.push_back(std::move(item));
    }

    // Replay the included statements under the ledger rules, noting each
    // proof of presence against the credentials of the moment, and what the
    // contract made of each call (on the bundle's instance, or, for a child,
    // on its ancestors).
    std::map<std::uint64_t, PresenceCheck> presence;
    std::map<std::uint64_t, ContractAccept> outcomes;
    // What each statement's approvals counted for (v0.20).
    std::map<std::uint64_t, ApprovalTally> tallies;
    // The algorithms of the presence credentials that signed (v0.21: the
    // signatures step 12 checks): a statement's, and its approvals', by
    // approver.
    std::map<std::uint64_t, crypto::SigAlg> presence_algorithms;
    std::map<std::pair<std::uint64_t, IdKey>, crypto::SigAlg> approval_presence_algorithms;
    auto credential_algorithm = [](const ActorState& actor, const PresenceProof& proof) {
        const auto it = std::ranges::find(actor.presence, proof.credential_id,
                                          &PresenceCredential::credential_id);
        return it == actor.presence.end() ? std::nullopt : std::optional(it->key.algorithm);
    };
    for (const Included& item : included) {
        if (item.index == 0 || item.commitment) {
            continue;
        }
        if (const Statement& s = item.statement.statement; s.presence && s.actor_id) {
            if (const ActorState* signer = state->actor(*s.actor_id)) {
                if (auto check = verify_presence(provider, state->hash(), s, item.statement.kid,
                                                 signer->presence)) {
                    presence[item.index] = std::move(*check);
                    if (const auto alg = credential_algorithm(*signer, *s.presence)) {
                        presence_algorithms[item.index] = *alg;
                    }
                }
            }
        }
        // An approval's proof of presence verifies, or the replay refuses
        // its statement: its credential is the approver's of the moment.
        for (const SignedApproval& approval : item.approvals) {
            const ActorState* approver = state->actor(approval.approval.approver);
            if (approver != nullptr && approval.approval.presence) {
                if (const auto alg = credential_algorithm(*approver, *approval.approval.presence)) {
                    approval_presence_algorithms[{item.index, key_of(approval.approval.approver)}] =
                        *alg;
                }
            }
        }
        // A contract call runs once: what validate ran is the outcome, and
        // apply takes it.
        Validation validation;
        if (!state->validate(provider, item.statement, item.log_entry.registered_at, nullptr,
                             &validation, item.approvals)) {
            return verification_failure(
                "an included statement fails the ledger rules or depends on a missing statement");
        }
        if (const ContractRun* run = validation.run()) {
            if (const ContractAccept* accept = run->accepted()) {
                outcomes.emplace(item.index, *accept);
            }
        }
        if (const ApprovalTally* tally = validation.approvals()) {
            tallies.emplace(item.index, *tally);
        }
        KANHE_CHECK(state->apply(provider, item.statement, item.index, item.log_entry.registered_at,
                                 &validation));
    }

    // Now the keys: the checkpoint and every receipt with the log key in
    // effect at its size, each state commitment with the one at its index.
    // (Receipts against one checkpoint usually share one signature.)
    const crypto::PublicKey& log_key = state->log_key_for(checkpoint.checkpoint.tree_size);
    if (!verify_checkpoint(provider, checkpoint, log_key)) {
        return verification_failure("the checkpoint is not signed by the ledger's log key");
    }
    std::set<std::pair<Bytes, Bytes>> verified;
    for (const Included& item : included) {
        auto seal =
            std::pair(item.receipt.envelope.protected_bytes, item.receipt.envelope.signature);
        if (!verified.contains(seal)) {
            if (!verify_receipt_signature(provider, item.receipt, checkpoint.checkpoint.root,
                                          log_key)) {
                return verification_failure("a receipt is not signed by the ledger's log key");
            }
            verified.insert(std::move(seal));
        }
        if (item.commitment &&
            !verify_state_commitment(provider, *item.commitment, state->log_key_for(item.index))) {
            return verification_failure("a state commitment in the bundle does not verify");
        }
    }

    // The signatures the entries carry, which the steps above relied on, in
    // log order (v0.21, section 11.1): each statement, its proof of
    // presence, its approvals each with its proof, or a state commitment;
    // then its receipt.
    std::vector<detail::ReliedSignature> relied;
    for (const Included& item : included) {
        const std::uint64_t i = item.index;
        if (item.commitment) {
            relied.push_back({SignedObject::state_commitment, i, std::nullopt, std::nullopt,
                              std::nullopt, std::nullopt, item.commitment->envelope.algorithm});
        } else {
            relied.push_back({SignedObject::statement, i, std::nullopt, std::nullopt, std::nullopt,
                              std::nullopt, item.statement.envelope.algorithm});
            if (const auto alg = presence_algorithms.find(i); alg != presence_algorithms.end()) {
                relied.push_back({SignedObject::presence, i, std::nullopt, std::nullopt,
                                  std::nullopt, std::nullopt, alg->second});
            }
            for (const SignedApproval& approval : item.approvals) {
                const Id& approver = approval.approval.approver;
                relied.push_back({SignedObject::approval, i, std::nullopt, approver, std::nullopt,
                                  std::nullopt, approval.envelope.algorithm});
                if (const auto alg = approval_presence_algorithms.find({i, key_of(approver)});
                    alg != approval_presence_algorithms.end()) {
                    relied.push_back({SignedObject::approval_presence, i, std::nullopt, approver,
                                      std::nullopt, std::nullopt, alg->second});
                }
            }
        }
        relied.push_back({SignedObject::receipt, i, checkpoint.checkpoint.tree_size, std::nullopt,
                          std::nullopt, std::nullopt, item.receipt.envelope.algorithm});
    }

    const RecordState* record = state->record(bundle.record);
    const InstanceState* instance = record == nullptr ? state->instance(bundle.record) : nullptr;
    if (record == nullptr && instance == nullptr) {
        return verification_failure("the bundle does not include the record's registration");
    }
    // The events to show: the record's, or the instance's calls; for a child,
    // its ancestors' first, up to each call that created the next generation
    // (v0.7). Replaying them made the child, at its position, from its
    // parent's call: it exists in the replayed state only so.
    const std::vector<std::uint64_t> history =
        record != nullptr ? record->history.to_vector() : instance_events(*state, *instance);

    EvidenceReport report;
    report.ledger_id = state->ledger_id();
    report.organization = state->organization();
    report.hash = state->hash();
    report.checkpoint = checkpoint.checkpoint;
    report.log_key = log_key;
    report.log_key_rotations = state->log_keys().size() - 1;
    report.root_key_rotations = state->root_keys().size() - 1;
    report.record = bundle.record;
    if (record != nullptr) {
        report.record_type = record->record_type;
        report.state = record->state;
        report.revoked = record->revoked;
        if (record->supersedes) {
            report.supersedes = Id(*record->supersedes);
        }
        if (record->superseded_by) {
            report.superseded_by = Id(*record->superseded_by);
        }
    } else {
        const ContractState* contract = state->contract(instance->contract);
        // The deploy is in the bundle: the contract was loaded from it while
        // replaying (entries ascend by index, checked above).
        const auto deploy =
            std::ranges::lower_bound(included, contract->deployed_at_index, {}, &Included::index);
        const auto* body = deploy == included.end() || deploy->index != contract->deployed_at_index
                               ? nullptr
                               : std::get_if<ContractDeployBody>(&deploy->statement.statement.body);
        if (body == nullptr) {
            return verification_failure("the bundle does not include the contract's deploy");
        }
        report.instance = InstanceReport{
            .contract = instance->contract,
            .contract_name = contract->name,
            .language = contract->language,
            .compiler = contract->compiler,
            .code = body->code,
            .interface = body->interface,
            .source = body->source,
            .contract_retired = contract->retired,
            .head = instance->head,
            .state = instance->state,
            .status = instance->status,
            .parties = instance->parties,
            .final = instance->final,
            .created_by = instance->created_by,
            .parent = instance->parent ? std::optional<Id>(instance->parent->id()) : std::nullopt,
            .position = instance->position,
            .depth = instance->depth,
            .ancestors = {},
            .first_own_event = static_cast<std::size_t>(
                std::ranges::lower_bound(history, instance->created_by) - history.begin()),
            .requests = {},
        };
        // Its own requests (v0.8), derived by the replay: the bundle holds
        // every call on the instance, so every request and every answer.
        for (const auto& [key, request] : state->requests()) {
            if (request.instance == instance->id) {
                report.instance->requests.push_back(
                    request_report(request, checkpoint.checkpoint.timestamp));
            }
        }
        for (const InstanceAncestor& a : instance_ancestors(*state, *instance)) {
            AncestorReport ancestor{
                .id = a.instance->id,
                .depth = a.instance->depth,
                .parent =
                    a.instance->parent ? std::optional<Id>(a.instance->parent->id()) : std::nullopt,
                .position = a.instance->position,
                .created_by = a.instance->created_by,
                .until = a.until,
                .events = {},
            };
            for (std::size_t i = 0; i < history.size(); ++i) {
                if (history[i] >= a.instance->created_by && history[i] <= a.until &&
                    std::ranges::binary_search(a.instance->history, history[i])) {
                    ancestor.events.push_back(i);
                }
            }
            report.instance->ancestors.push_back(std::move(ancestor));
        }
        if (instance->status) {
            report.state = *instance->status;
        }
    }

    // Entries ascend by index (checked above): find them by binary search,
    // so a long history costs O(h log n), not O(h n).
    auto included_at = [&](std::uint64_t index) {
        return std::ranges::lower_bound(included, index, {}, &Included::index);
    };
    const RecordRegisterBody* registration = nullptr;
    for (const std::uint64_t index : history) {
        const auto it = included_at(index);
        const Statement& statement = it->statement.statement;
        // The record's own registration; another in its history registered
        // the version that superseded it (v0.10).
        std::optional<Id> new_version;
        std::string detail = event_detail(statement);
        if (const auto* body = std::get_if<RecordRegisterBody>(&statement.body)) {
            if (it->statement.id == bundle.record) {
                registration = body;
                report.metadata = body->metadata;
            } else {
                new_version = it->statement.id;
                detail = body->record_type;
            }
        }
        // The instances a call created (v0.7), and the requests it made
        // (v0.8), by the ids derived from it.
        std::vector<Id> children;
        std::vector<Id> requests;
        if (const auto outcome = outcomes.find(index); outcome != outcomes.end()) {
            for (std::size_t n = 0; n < outcome->second.children.size(); ++n) {
                auto child = child_instance_id(provider, state->hash(), it->statement.id, n);
                if (!child) {
                    return std::unexpected(child.error());
                }
                children.push_back(*child);
            }
            for (std::size_t n = 0; n < outcome->second.requests.size(); ++n) {
                auto request = request_id(provider, state->hash(), it->statement.id, n);
                if (!request) {
                    return std::unexpected(request.error());
                }
                requests.push_back(*request);
            }
        }
        // An answer (v0.8): the request it closed, which the replay made.
        std::optional<RequestReport> answered;
        if (const auto* call = std::get_if<ContractCallBody>(&statement.body);
            call && call->answer) {
            if (const RequestState* request = state->request(call->answer->request)) {
                answered = request_report(*request, checkpoint.checkpoint.timestamp);
            }
        }
        report.events.push_back(RecordEvent{
            .index = index,
            .registered_at = it->log_entry.registered_at,
            .issued_at = statement.issued_at,
            .type = statement.type(),
            .actor = summarize(*state, *statement.actor_id),
            .authority = authority_chain(*state, statement.delegation_id),
            .provenance = statement.provenance,
            .presence = presence.contains(index) ? std::optional(presence.at(index)) : std::nullopt,
            .detail = std::move(detail),
            .contract_call = std::holds_alternative<ContractCallBody>(statement.body)
                                 ? std::optional(std::get<ContractCallBody>(statement.body))
                                 : std::nullopt,
            .outcome = outcomes.contains(index) ? std::optional(outcomes.at(index)) : std::nullopt,
            .children = std::move(children),
            .requests = std::move(requests),
            .answered = std::move(answered),
            .new_version = new_version,
            .existed_by = std::nullopt,
            .approval_rules = {},
            .approvals = {},
        });
        if (const auto tally = tallies.find(index); tally != tallies.end()) {
            report_approvals(*state, tally->second, report.events.back().approval_rules,
                             report.events.back().approvals);
        }
    }

    // Guardian settings (v0.20): each one the bundle holds, in log order,
    // and the one in effect at the checkpoint.
    for (const GuardianSetting& setting : state->guardian_settings()) {
        const auto it = included_at(setting.index);
        GuardianReport g;
        g.index = setting.index;
        g.registered_at = it->log_entry.registered_at;
        g.rule = setting.guardians;
        if (setting.guardians) {
            for (const Id& guardian : setting.guardians->approvers) {
                g.guardians.push_back(summarize(*state, guardian));
            }
        }
        g.guarded = setting.guarded;
        if (const auto tally = tallies.find(setting.index); tally != tallies.end()) {
            report_approvals(*state, tally->second, g.approval_rules, g.approvals);
        }
        report.guardian_settings.push_back(std::move(g));
    }
    if (state->guardians() != nullptr) {
        report.guardians = report.guardian_settings.size() - 1;
    }

    // A claim (v0.14): its terms, and its source as the bundle shows it.
    if (record != nullptr && record->record_type == claim_type && report.metadata) {
        auto claim = decode_claim(*report.metadata);
        const RecordState* source = claim ? state->record(claim->source) : nullptr;
        if (source == nullptr) {
            return verification_failure("a claim's source is not in its evidence");
        }
        EvidenceReport::ClaimReport c;
        c.text = claim_text(*claim);
        c.source_type = source->record_type;
        c.source_status = source->revoked ? "revoked" : source->superseded_by ? "replaced" : "live";
        c.lapsed = claim->until && checkpoint.checkpoint.timestamp > *claim->until;
        c.claim = std::move(*claim);
        report.claim = std::move(c);
    }

    // The record's own events, and the records they name (v0.18, step 7):
    // a claim's source, its local sources, the scripts its events name.
    std::vector<Statement> own_events;
    for (const std::uint64_t index : history) {
        own_events.push_back(included_at(index)->statement.statement);
    }
    const std::vector<Id> related = related_records(own_events, state->ledger_id());
    // A related record's statement, which the bundle must hold.
    auto statement_at = [&](std::uint64_t index) -> const Included* {
        const auto it = included_at(index);
        return it != included.end() && it->index == index ? &*it : nullptr;
    };
    // When a record of the bundle was registered, revoked, and replaced.
    struct Times {
        Timestamp registered = 0;
        std::optional<Timestamp> revoked;
        std::optional<Timestamp> replaced;
        std::optional<Id> replaced_by;
    };
    auto times_of = [&](const RecordState& r) -> std::optional<Times> {
        Times t;
        const Included* registered = statement_at(r.registered_at_index);
        if (registered == nullptr) {
            return std::nullopt;
        }
        t.registered = registered->log_entry.registered_at;
        for (const std::uint64_t index : r.history) {
            const Included* item = statement_at(index);
            if (item == nullptr) {
                return std::nullopt;
            }
            if (std::holds_alternative<RecordRevokeBody>(item->statement.statement.body) &&
                !t.revoked) {
                t.revoked = item->log_entry.registered_at;
            }
        }
        if (r.superseded_by) {
            const Included* item = statement_at(r.superseded_at_index);
            if (item == nullptr) {
                return std::nullopt;
            }
            t.replaced = item->log_entry.registered_at;
            t.replaced_by = Id(*r.superseded_by);
        }
        return t;
    };
    // The scripts its events name (v0.18), each once.
    for (const RecordEvent& event : report.events) {
        if (!event.provenance || !event.provenance->script) {
            continue;
        }
        const Id& id = *event.provenance->script;
        const RecordState* script = state->record(id);
        // Approved before it is named (v0.19): the replay let a script the
        // bundle did not hold yet pass, so the order is checked here.
        if (script != nullptr && script->registered_at_index >= event.index) {
            return verification_failure(
                "an event of the record names a script approved only after it");
        }
        if (std::ranges::contains(report.scripts, id, &ScriptReport::id)) {
            continue;
        }
        const Included* registered =
            script != nullptr ? statement_at(script->registered_at_index) : nullptr;
        const auto* body =
            registered != nullptr
                ? std::get_if<RecordRegisterBody>(&registered->statement.statement.body)
                : nullptr;
        const auto times = script != nullptr ? times_of(*script) : std::nullopt;
        auto decoded = body != nullptr && body->metadata
                           ? decode_script(*body->metadata)
                           : Result<Script>(fail(Errc::not_found, "no script"));
        if (!decoded || !times) {
            return verification_failure("a script the record's events name is not in its evidence");
        }
        report.scripts.push_back(ScriptReport{
            .id = id,
            .script = std::move(*decoded),
            .approved_by = summarize(*state, *registered->statement.statement.actor_id),
            .presence = presence.contains(registered->index)
                            ? std::optional(presence.at(registered->index))
                            : std::nullopt,
            .approved_at = times->registered,
            .withdrawn_at = times->revoked,
        });
    }
    // The sources its registration names (v0.18), in its order: a local
    // one from this bundle, another ledger's from its proof (step 10).
    if (registration != nullptr && !report.events.empty()) {
        for (const Source& source : registration->sources) {
            SourceReport s;
            s.source = source;
            s.record_time = report.events.front().registered_at;
            s.checkpoint_time = checkpoint.checkpoint.timestamp;
            s.local = source.ledger == state->ledger_id();
            if (s.local) {
                const RecordState* r = state->record(source.record);
                const auto times = r != nullptr ? times_of(*r) : std::nullopt;
                if (!times) {
                    return verification_failure("a local source is not in the record's evidence");
                }
                // Registered before the record that names it (v0.19).
                if (r->registered_at_index >= report.events.front().index) {
                    return verification_failure(
                        "a local source is registered only after the record that names it");
                }
                s.provided = true;
                s.type = r->record_type;
                set_statuses(s, times->registered, times->revoked, times->replaced,
                             times->replaced_by);
            }
            report.sources.push_back(std::move(s));
        }
    }

    // Completeness: every involved object's history, as replayed from the
    // bundle, must be exactly the history the checkpoint's state root commits
    // to. A left-out statement (a later revocation, say) shows as a mismatch.
    // The state commitment the ledger appended just before signing the
    // checkpoint: the last entry the checkpoint covers.
    const auto last = std::ranges::find_if(included, [&](const Included& i) {
        return i.commitment && i.index + 1 == checkpoint.checkpoint.tree_size;
    });
    if (last != included.end()) {
        const crypto::Digest* state_root = &last->commitment->commitment.state_root;
        report.state_commitment = last->commitment->commitment;
        // The related records' statements count as events too (each one
        // included: the replayed state knows no other).
        std::vector<Statement> events = own_events;
        for (const Id& id : related) {
            const RecordState* r = state->record(id);
            if (r == nullptr) {
                return verification_failure(
                    "the bundle does not include a record its record's events name");
            }
            for (const std::uint64_t index : r->history.to_vector()) {
                const Included* item = statement_at(index);
                if (item == nullptr) {
                    return verification_failure(
                        "the bundle leaves out a statement of a record its record's events name");
                }
                events.push_back(item->statement.statement);
            }
        }
        std::map<IdKey, const StateProof*> proven;
        for (const StateProof& proof : bundle.state_proofs) {
            if (!proven.emplace(key_of(proof.leaf.id), &proof).second) {
                return verification_failure("a state proof is repeated");
            }
            if (!verify_state_proof(provider, state->hash(), proof, *state_root)) {
                return verification_failure(
                    "a state proof does not match the ledger's state commitment");
            }
        }
        // From v0.20 also the organization, every actor a guardian setting
        // names, and the approver of every approval an included entry
        // carries: their histories, and so the approvals in them, whole.
        std::vector<Id> approvers{state->ledger_id()};
        for (const GuardianSetting& setting : state->guardian_settings()) {
            if (setting.guardians) {
                approvers.insert(approvers.end(), setting.guardians->approvers.begin(),
                                 setting.guardians->approvers.end());
            }
        }
        for (const Included& item : included) {
            for (const SignedApproval& approval : item.approvals) {
                approvers.push_back(approval.approval.approver);
            }
        }
        for (const Id& id : involved_objects(*state, bundle.record, events, related, approvers)) {
            const auto proof = proven.find(key_of(id));
            if (proof == proven.end()) {
                return verification_failure(
                    "the bundle does not prove the complete history of everyone involved");
            }
            const auto replayed = state_leaf(*state, id);
            if (!replayed || *replayed != proof->second->leaf) {
                return verification_failure("the bundle leaves out part of a history it must show "
                                            "in full (for example a revocation)");
            }
        }
        report.complete = true;
    } else if (!bundle.state_proofs.empty()) {
        return verification_failure(
            "state proofs need the state commitment the checkpoint ends with");
    }

    if (instance != nullptr) {
        // An instance has no fields or attachments: its state is public to
        // whoever holds its evidence.
        if (!bundle.disclosures.empty() || !bundle.attachments.empty()) {
            return verification_failure("an instance has no fields or attachments to disclose");
        }
        return finish_report(provider, *state, checkpoint, bundle, included, std::move(relied),
                             options, std::move(report));
    }

    // Leaves are sorted by name, one per name: disclosures must agree (a
    // record committing two leaves of one name could otherwise show each
    // party a different value).
    std::map<std::uint64_t, std::string> disclosed_at;
    for (const FieldDisclosure& disclosure : bundle.disclosures) {
        auto field = verify_disclosure(provider, state->hash(), record->field_root,
                                       record->field_count, disclosure);
        if (!field) {
            return verification_failure("a disclosed field does not match the record's commitment");
        }
        if (!disclosed_at.emplace(disclosure.index, field->name).second) {
            return verification_failure("a field is disclosed twice");
        }
        report.disclosed_fields.push_back(std::move(*field));
    }
    for (auto it = disclosed_at.begin(); it != disclosed_at.end(); ++it) {
        if (const auto next = std::next(it);
            next != disclosed_at.end() && !(it->second < next->second)) {
            return verification_failure("disclosed fields are not in the record's name order");
        }
    }

    if (registration == nullptr) {
        return verification_failure("the bundle does not include the record's registration");
    }
    for (const AttachmentOpening& opening : bundle.attachments) {
        const bool known = std::ranges::any_of(
            registration->attachments, [&](const Attachment& a) { return a.name == opening.name; });
        if (!known) {
            return verification_failure("an attachment opening names no attachment of the record");
        }
    }
    for (const Attachment& attachment : registration->attachments) {
        AttachmentCheck check{attachment.name, attachment.media_type, attachment.size,
                              AttachmentStatus::not_provided};
        const auto opening =
            std::ranges::find(bundle.attachments, attachment.name, &AttachmentOpening::name);
        const auto content = options.attachment_contents.find(attachment.name);
        if (opening != bundle.attachments.end() && content != options.attachment_contents.end()) {
            KANHE_TRY(
                crypto::Digest commitment,
                attachment_commitment(provider, state->hash(), opening->salt, content->second));
            const bool matches = std::ranges::equal(commitment.bytes(), attachment.commitment) &&
                                 content->second.size() == attachment.size;
            check.status = matches ? AttachmentStatus::verified : AttachmentStatus::mismatch;
        }
        report.attachments.push_back(std::move(check));
    }

    return finish_report(provider, *state, checkpoint, bundle, included, std::move(relied), options,
                         std::move(report));
}

} // namespace kanhe::protocol
