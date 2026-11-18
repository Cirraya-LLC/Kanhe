// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <string_view>
#include <vector>

#include <kanhe/core/bytes.hpp>
#include <kanhe/core/cose.hpp>
#include <kanhe/core/crypto.hpp>
#include <kanhe/core/error.hpp>
#include <kanhe/core/protocol/common.hpp>
#include <kanhe/core/protocol/presence.hpp>
#include <kanhe/core/protocol/statement.hpp>

/// Approvals (spec v0.20): an actor's agreement to someone else's statement,
/// which a delegation's approval rule (scope key 10) or the organization's
/// guardians require. An approval is the approver's own COSE_Sign1 over the
/// statement's id, with the protected header
///   { 1: alg, 3: "application/kanhe-approval+cbor", 4: kid }
/// and an empty unprotected header (`approval-payload` in the CDDL). It
/// travels beside the statement, never inside it: in a submission and in the
/// statement's log entry (key 5 of both).
///
/// A person proves presence for an approval with the challenge
///   HASH("Kanhe approval v1" || kid || A)
/// where A is the approval payload encoded without key 5 and kid the
/// approval's: the construction of a statement's, under a context of its
/// own, so that a proof for one is never one for the other.
namespace kanhe::protocol {

inline constexpr std::string_view approval_context = "Kanhe approval v1";

/// What an approval says (`approval-payload`).
struct Approval {
    /// The ledger, and the approver: an actor of that ledger.
    Id ledger;
    Id approver;
    /// The statement approved: its statement_id, which fixes the exact
    /// signed statement (content, signer and key, delegation, issue time,
    /// nonce, and the signer's own proof of presence).
    Id statement;
    /// When the approver approved it, as the approver claims.
    Timestamp approved_at = 0;
    /// The approver's proof of presence over the approval's challenge.
    std::optional<PresenceProof> presence;

    friend bool operator==(const Approval&, const Approval&) = default;
};

/// A signed approval as it travels and is stored.
struct SignedApproval {
    /// The tagged COSE_Sign1 bytes.
    Bytes encoded;
    cose::Sign1 envelope;
    Approval approval;
    /// The signing key's identifier from the protected header.
    Id kid;
};

/// Encodes an approval's payload, refusing what breaks its structural rules.
[[nodiscard]] Result<Bytes> encode_approval_payload(const Approval& approval);
/// Decodes and checks an approval's payload. Rejects unknown keys.
[[nodiscard]] Result<Approval> decode_approval_payload(ByteView payload);

/// Signs an approval with the approver's key; its kid is the key's under
/// `ledger_hash`, the ledger's hash.
[[nodiscard]] Result<SignedApproval> sign_approval(const crypto::Signer& approver,
                                                   const crypto::Provider& provider,
                                                   crypto::HashAlg ledger_hash,
                                                   const Approval& approval);

/// Parses a signed approval: at most 24,576 bytes, the header's shape and
/// content type, the payload. The signature is not verified (see
/// `verify_approval`).
[[nodiscard]] Result<SignedApproval> parse_approval(ByteView encoded);

/// Verifies an approval's signature with `key`, which must be the key its
/// kid names under `ledger_hash`.
[[nodiscard]] Status verify_approval(const crypto::Provider& provider, crypto::HashAlg ledger_hash,
                                     const SignedApproval& approval, const crypto::PublicKey& key);

/// The challenge an approver's proof of presence signs, for the approval
/// signed with the key whose id is `kid`. Any presence proof already in
/// `approval` is ignored.
[[nodiscard]] Result<Bytes> approval_challenge(const crypto::Provider& provider,
                                               crypto::HashAlg ledger_hash,
                                               const Approval& approval, const Id& kid);

/// Verifies an approval's proof of presence against the approver's
/// registered credentials. Fails with Errc::verification_failed if it does
/// not prove presence for this approval and key.
[[nodiscard]] Result<PresenceCheck>
verify_approval_presence(const crypto::Provider& provider, crypto::HashAlg ledger_hash,
                         const SignedApproval& approval,
                         std::span<const PresenceCredential> credentials);

/// Parses signed approvals and puts them in their log entry's order:
/// strictly ascending by approver. Fails if one does not parse, if there are
/// more than 32, or if an approver approves twice.
[[nodiscard]] Result<std::vector<SignedApproval>> sort_approvals(std::span<const Bytes> approvals);

// ---------------------------------------------------------------------------
// What the ledger counts
// ---------------------------------------------------------------------------

/// Where an approval rule that applies to a statement comes from.
enum class RuleSource : std::uint8_t {
    /// A delegation in the signer's chain (scope key 10).
    delegation = 1,
    /// The guardians in effect, for an organization's statement they guard,
    /// or the current guardians of a guardian setting.
    guardians = 2,
    /// The guardians a guardian setting names: they approve it too.
    new_guardians = 3,
};

[[nodiscard]] std::string_view name(RuleSource source) noexcept;

/// An approval rule that applies to a statement.
struct AppliedRule {
    RuleSource source = RuleSource::delegation;
    /// The delegation whose rule it is (for RuleSource::delegation), or the
    /// log index of the guardian setting in effect (RuleSource::guardians;
    /// nullopt for a setting's new guardians).
    std::optional<Id> delegation;
    std::optional<std::uint64_t> setting;
    ApprovalRule rule;

    friend bool operator==(const AppliedRule&, const AppliedRule&) = default;
};

/// An approval as the ledger checked it.
struct ApprovalCheck {
    Id approver;
    Timestamp approved_at = 0;
    /// How the approver proved presence; nullopt: not in person.
    std::optional<PresenceCheck> presence;

    friend bool operator==(const ApprovalCheck&, const ApprovalCheck&) = default;
};

/// How far one rule is met.
struct RuleTally {
    AppliedRule applied;
    /// Its approvers whose approvals count, ascending; the signer among
    /// them if it counts (`signer_counts`).
    std::vector<Id> counted;
    bool signer_counts = false;
    /// The last moment the statement may be registered: its issue time plus
    /// the rule's window (at most 2^64 - 1).
    Timestamp lapses_at = 0;

    /// Approvals still needed (0 once met).
    [[nodiscard]] std::uint64_t missing() const noexcept {
        return counted.size() >= applied.rule.needed ? 0 : applied.rule.needed - counted.size();
    }
    /// Met at `now`: enough count, and the window has not ended.
    [[nodiscard]] bool met(Timestamp now) const noexcept {
        return missing() == 0 && now <= lapses_at;
    }

    friend bool operator==(const RuleTally&, const RuleTally&) = default;
};

/// A statement's approvals, checked as the ledger checks them at a time:
/// every approval valid (one that is not refuses the statement), and each
/// rule that applies with what counts for it.
struct ApprovalTally {
    std::vector<RuleTally> rules;
    /// In the log entry's order: ascending by approver.
    std::vector<ApprovalCheck> approvals;

    /// No rule applies.
    [[nodiscard]] bool none() const noexcept { return rules.empty(); }
    /// Every rule is met at `now`.
    [[nodiscard]] bool met(Timestamp now) const noexcept {
        for (const RuleTally& r : rules) {
            if (!r.met(now)) {
                return false;
            }
        }
        return true;
    }

    friend bool operator==(const ApprovalTally&, const ApprovalTally&) = default;
};

} // namespace kanhe::protocol
