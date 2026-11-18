// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// Approvals (spec v0.20) come from whoever submits a statement, and reach
// every verifier inside the log entries of evidence: approval rules (scope
// key 10), guardian settings' bodies, signed approvals and their proofs of
// presence, and the lists of approvals a submission and a log entry carry;
// and approval files, from whoever passes one on, with the parts of a
// submission they carry. Reading any of them must refuse what is not one,
// never crash, and what it accepts must encode back to the same bytes (an
// approval file: to a file read the same).

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <span>
#include <variant>

#include <kanhe/core/cbor.hpp>
#include <kanhe/core/protocol/approval_file.hpp>
#include <kanhe/core/protocol/approvals.hpp>
#include <kanhe/core/protocol/log.hpp>
#include <kanhe/core/protocol/statement.hpp>
#include <kanhe/crypto/openssl.hpp>

namespace protocol = kanhe::protocol;

namespace {

void require(bool condition) {
    if (!condition) {
        std::abort();
    }
}

template <class Encoded>
void require_same(const Encoded& encoded, kanhe::ByteView input) {
    require(encoded.has_value() && std::ranges::equal(*encoded, input));
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    static const kanhe::crypto::openssl::Provider provider;
    const kanhe::ByteView input(data, size);

    // A rule, alone: within its limits, ascending, and the same again.
    if (const auto rule = protocol::decode_approval_rule(input)) {
        require_same(protocol::encode_approval_rule(*rule), input);
        require(rule->needed >= 1 && rule->needed <= rule->approvers.size() &&
                rule->approvers.size() <= protocol::max_rule_approvers);
        require(rule->within >= protocol::min_approval_window &&
                rule->within <= protocol::max_approval_window);
    }

    // A statement payload: a guardian setting, or a grant with a rule.
    if (const auto statement = protocol::decode_payload(input)) {
        require_same(protocol::encode_payload(*statement), input);
        if (const auto* set = std::get_if<protocol::LedgerSetGuardiansBody>(&statement->body)) {
            require(!set->guardians || !set->guardians->without_presence);
            require(set->guardians || !set->guarded);
        }
    }

    // A signed approval: its payload the same again, its challenge, and its
    // proof of presence checked against a credential with the same id.
    if (const auto approval = protocol::parse_approval(input)) {
        require_same(protocol::encode_approval_payload(approval->approval),
                     *approval->envelope.payload);
        for (const auto hash : {kanhe::crypto::HashAlg::sha256, kanhe::crypto::HashAlg::sm3}) {
            require(protocol::approval_challenge(provider, hash, approval->approval, approval->kid)
                        .has_value());
            static_cast<void>(protocol::verify_approval(
                provider, hash, *approval, {kanhe::crypto::SigAlg::ed25519, kanhe::Bytes(32, 7)}));
        }
        if (approval->approval.presence) {
            const protocol::PresenceCredential passkey{
                "localhost",
                approval->approval.presence->credential_id,
                {kanhe::crypto::SigAlg::esp256, kanhe::Bytes(65, 0x04)},
                std::nullopt};
            protocol::PresenceCredential hardware = passkey;
            hardware.rp_id.clear();
            hardware.method = protocol::PresenceMethod::hardware_key;
            hardware.key = {kanhe::crypto::SigAlg::ed25519, kanhe::Bytes(32, 9)};
            for (const auto& credential : {passkey, hardware}) {
                static_cast<void>(
                    protocol::verify_approval_presence(provider, kanhe::crypto::HashAlg::sha256,
                                                       *approval, std::span(&credential, 1)));
            }
        }
    }

    // A list of approvals, as a submission's key 5 or a log entry's: the
    // same again, and in its log entry's order if each one parses.
    if (const auto value = kanhe::cbor::decode(input)) {
        const kanhe::cbor::Value* list = value->as_array() != nullptr ? &*value : value->find(5);
        if (list != nullptr) {
            if (const auto approvals = protocol::approval_list_from(*list)) {
                require(!approvals->empty() && approvals->size() <= protocol::max_approvals);
                require_same(kanhe::cbor::encode(protocol::approval_list_value(*approvals)),
                             *kanhe::cbor::encode(*list));
                if (const auto sorted = protocol::sort_approvals(*approvals)) {
                    for (std::size_t i = 1; i < sorted->size(); ++i) {
                        require(std::ranges::lexicographical_compare(
                            (*sorted)[i - 1].approval.approver.bytes(),
                            (*sorted)[i].approval.approver.bytes()));
                    }
                }
            }
        }
    }

    // A log entry with approvals: the same again.
    if (const auto entry = protocol::decode_log_entry(input)) {
        require_same(protocol::encode_log_entry(*entry), input);
        require(entry->approvals.empty() || !entry->is_state_commitment());
    }

    // A submission's parts: the same again, and at least one.
    if (const auto parts = protocol::decode_submission_parts(input)) {
        require(!parts->empty());
        require_same(protocol::encode_submission_parts(*parts), input);
    }

    // An approval file: its approvals for its statement and ledger, no
    // approver twice; written again (approvals by approver), it reads the
    // same, and a second write is the first.
    if (const auto file = protocol::decode_approval_file(provider, input)) {
        require(file->approvals.size() <= protocol::max_approvals);
        require(file->statement.statement.type() != protocol::StatementType::genesis);
        for (const auto& a : file->approvals) {
            require(a.approval.statement == file->statement.id);
        }
        require(file->fields.empty() || std::holds_alternative<protocol::RecordRegisterBody>(
                                            file->statement.statement.body));
        const auto written = protocol::encode_approval_file(*file);
        require(written.has_value());
        const auto again = protocol::decode_approval_file(provider, *written);
        require(again.has_value() && again->statement.id == file->statement.id &&
                again->approvals.size() == file->approvals.size() &&
                again->fields == file->fields && again->note == file->note &&
                again->parts == file->parts);
        require_same(protocol::encode_approval_file(*again), *written);
    }
    return 0;
}
