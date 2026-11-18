// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include <algorithm>
#include <utility>

#include <kanhe/core/protocol/approvals.hpp>

#include "envelope.hpp"
#include "reader.hpp"

namespace kanhe::protocol {

namespace {

using detail::entry;
using detail::MapReader;

// approval-payload keys.
constexpr std::int64_t key_ledger = 1;
constexpr std::int64_t key_approver = 2;
constexpr std::int64_t key_statement = 3;
constexpr std::int64_t key_approved_at = 4;
constexpr std::int64_t key_presence = 5;

Status check_approval(const Approval& approval) {
    if (approval.ledger.size() != id_size || approval.approver.size() != id_size ||
        approval.statement.size() != id_size) {
        return fail(Errc::malformed, "an approval names a ledger, an approver, and a statement");
    }
    return {};
}

Result<Bytes> approval_bytes(const Approval& approval, bool with_presence) {
    KANHE_CHECK(check_approval(approval));
    cbor::Map map{
        entry(key_ledger, cbor::Value::bytes(approval.ledger.bytes())),
        entry(key_approver, cbor::Value::bytes(approval.approver.bytes())),
        entry(key_statement, cbor::Value::bytes(approval.statement.bytes())),
        entry(key_approved_at, cbor::Value::unsigned_integer(approval.approved_at)),
    };
    if (with_presence && approval.presence) {
        KANHE_TRY(cbor::Value presence, presence_proof_value(*approval.presence));
        map.push_back(entry(key_presence, std::move(presence)));
    }
    return cbor::encode(cbor::Value::map(std::move(map)));
}

} // namespace

Result<Bytes> encode_approval_payload(const Approval& approval) {
    auto encoded = approval_bytes(approval, true);
    if (!encoded) {
        return std::unexpected(Error{Errc::invalid_argument, encoded.error().detail});
    }
    return encoded;
}

Result<Approval> decode_approval_payload(ByteView payload) {
    KANHE_TRY(cbor::Value value, cbor::decode(payload));
    KANHE_TRY(MapReader reader, MapReader::open(value));
    Approval approval;
    KANHE_TRY(approval.ledger, reader.need_id(key_ledger));
    KANHE_TRY(approval.approver, reader.need_id(key_approver));
    KANHE_TRY(approval.statement, reader.need_id(key_statement));
    KANHE_TRY(approval.approved_at, reader.need_uint(key_approved_at));
    if (const cbor::Value* presence = reader.get(key_presence)) {
        KANHE_TRY(approval.presence, presence_proof_from(*presence));
    }
    KANHE_CHECK(reader.finish());
    return approval;
}

Result<SignedApproval> sign_approval(const crypto::Signer& approver,
                                     const crypto::Provider& provider, crypto::HashAlg ledger_hash,
                                     const Approval& approval) {
    if (!is_ledger_hash(ledger_hash)) {
        return fail(Errc::unsupported, "ledger hash must be SHA-256 or SM3");
    }
    KANHE_TRY(Bytes payload, encode_approval_payload(approval));
    KANHE_TRY(Bytes encoded, detail::sign_envelope(approver, provider, ledger_hash, payload,
                                                   approval_content_type));
    if (encoded.size() > max_approval_size) {
        return fail(Errc::limit_exceeded, "an approval is at most 24,576 bytes encoded");
    }
    return parse_approval(encoded);
}

Result<SignedApproval> parse_approval(ByteView encoded) {
    if (encoded.size() > max_approval_size) {
        return fail(Errc::limit_exceeded, "an approval is at most 24,576 bytes encoded");
    }
    KANHE_TRY(detail::Envelope envelope, detail::parse_envelope(encoded, approval_content_type));
    KANHE_TRY(Approval approval, decode_approval_payload(*envelope.message.payload));
    return SignedApproval{
        .encoded = Bytes(encoded.begin(), encoded.end()),
        .envelope = std::move(envelope.message),
        .approval = std::move(approval),
        .kid = envelope.kid,
    };
}

Status verify_approval(const crypto::Provider& provider, crypto::HashAlg ledger_hash,
                       const SignedApproval& approval, const crypto::PublicKey& key) {
    return detail::verify_envelope(provider, ledger_hash,
                                   detail::Envelope{approval.envelope, approval.kid}, key);
}

Result<Bytes> approval_challenge(const crypto::Provider& provider, crypto::HashAlg ledger_hash,
                                 const Approval& approval, const Id& kid) {
    if (kid.size() != id_size) {
        return fail(Errc::invalid_argument, "a key id is 32 bytes");
    }
    if (!is_ledger_hash(ledger_hash)) {
        return fail(Errc::unsupported, "ledger hash must be SHA-256 or SM3");
    }
    KANHE_TRY(Bytes payload, approval_bytes(approval, false));
    KANHE_TRY(crypto::Digest digest,
              provider.digest(ledger_hash, {as_bytes(approval_context), kid.bytes(), payload}));
    return Bytes(digest.bytes().begin(), digest.bytes().end());
}

Result<PresenceCheck> verify_approval_presence(const crypto::Provider& provider,
                                               crypto::HashAlg ledger_hash,
                                               const SignedApproval& approval,
                                               std::span<const PresenceCredential> credentials) {
    if (!approval.approval.presence) {
        return fail(Errc::invalid_argument, "the approval carries no proof of presence");
    }
    KANHE_TRY(Bytes challenge,
              approval_challenge(provider, ledger_hash, approval.approval, approval.kid));
    return verify_presence_proof(provider, challenge, *approval.approval.presence, credentials);
}

Result<std::vector<SignedApproval>> sort_approvals(std::span<const Bytes> approvals) {
    if (approvals.size() > max_approvals) {
        return fail(Errc::limit_exceeded, "a statement travels with at most 32 approvals");
    }
    std::vector<SignedApproval> out;
    out.reserve(approvals.size());
    for (const Bytes& encoded : approvals) {
        KANHE_TRY(SignedApproval approval, parse_approval(encoded));
        out.push_back(std::move(approval));
    }
    std::ranges::sort(out, [](const SignedApproval& a, const SignedApproval& b) {
        return std::ranges::lexicographical_compare(a.approval.approver.bytes(),
                                                    b.approval.approver.bytes());
    });
    const auto twice =
        std::ranges::adjacent_find(out, [](const SignedApproval& a, const SignedApproval& b) {
            return a.approval.approver == b.approval.approver;
        });
    if (twice != out.end()) {
        return fail(Errc::rejected, "an approver approves a statement once");
    }
    return out;
}

std::string_view name(RuleSource source) noexcept {
    switch (source) {
    case RuleSource::delegation:
        return "delegation";
    case RuleSource::guardians:
        return "guardians";
    case RuleSource::new_guardians:
        return "new_guardians";
    }
    return "unknown";
}

} // namespace kanhe::protocol
