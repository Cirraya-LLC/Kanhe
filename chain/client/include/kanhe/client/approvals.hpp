// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include <nlohmann/json.hpp>

#include <kanhe/client/session.hpp>
#include <kanhe/core/bytes.hpp>
#include <kanhe/core/protocol/approval_file.hpp>
#include <kanhe/core/protocol/approvals.hpp>
#include <kanhe/core/protocol/statement.hpp>

/// Approvals (spec v0.20), as a person's tools give them: a statement held
/// at a server or in a ledger directory, or carried in an approval file, is
/// read, checked against the ledger itself (the directory, or a mirror this
/// machine verified), never against what the server or the file claims, and
/// approved in person with the approver's own key; and statements are sent
/// with the approvals gathered.
namespace kanhe::client {

/// A window in words: "7 days", "12 hours", "90 minutes".
[[nodiscard]] std::string window_text(protocol::Timestamp ms);
/// A window from "7d", "12h", "90m", or "45s": 1 minute to 30 days.
[[nodiscard]] protocol::Timestamp parse_window(std::string_view text, std::string_view what);

/// A rule in words: "2 of Chan Tai Man, Lee Ka Yan, Ho Wing within 7 days".
[[nodiscard]] std::string rule_text(const Session& session, const protocol::ApprovalRule& rule);
/// Where a rule comes from: "the delegation 3fa2c19be0d1", "the guardians",
/// "the new guardians".
[[nodiscard]] std::string rule_source_text(const protocol::AppliedRule& rule);

/// A statement for approval, read and checked against this machine's view
/// of the ledger at its clock.
struct ApprovalReview {
    protocol::ApprovalFile file;
    /// Held at the server or in the directory (else read from a file).
    bool held = false;
    /// Registered already, at this log index.
    std::optional<std::uint64_t> registered;
    /// Why the ledger would refuse the statement now, whatever its
    /// approvals.
    std::optional<std::string> refused;
    /// Issued more than 5 minutes ahead of this machine's clock: not to be
    /// approved unawares.
    bool future = false;
    /// A rule's window has ended by this machine's clock: it can no longer
    /// be registered.
    bool lapsed = false;
    /// The rules that apply, in the order of spec section 5.1.
    std::vector<protocol::AppliedRule> rules;
    /// For each approval of the file, in its order: why it would not count
    /// now, or nullopt if it verifies.
    std::vector<std::optional<std::string>> problems;
    /// The rules counted with the approvals that verify, and the signer.
    protocol::ApprovalTally tally;
    bool signer_verified = false;
    protocol::Timestamp now = 0;
};

/// Checks `file` against the session's ledger at its clock.
[[nodiscard]] ApprovalReview review_approval(Session& session, protocol::ApprovalFile file,
                                             bool held);

/// A held statement's id, from its full id or 8 or more of its first hex
/// digits, among those held (and, with `done`, what became of others).
[[nodiscard]] protocol::Id held_id(Session& session, std::string_view text);
/// The approval file of a statement held at the server, or in the ledger
/// directory, read like any other.
[[nodiscard]] protocol::ApprovalFile fetch_held(Session& session, const protocol::Id& id);
/// Reads an approval file.
[[nodiscard]] protocol::ApprovalFile read_approval_file(const Session& session,
                                                        const std::filesystem::path& path);
void write_approval_file(const protocol::ApprovalFile& file, const std::filesystem::path& path);

/// The statements held for approval, as GET /v1/approvals lists them: at
/// the server (`wait` seconds a long poll), or in the ledger directory.
/// Those `approver` may approve, all without one; `all` adds what became of
/// others in the last 30 days. A hint: give an approval only after
/// reviewing the statement itself.
[[nodiscard]] nlohmann::json list_held(Session& session,
                                       const std::optional<protocol::Id>& approver, bool all,
                                       std::uint64_t wait);

/// A review's statement and approvals as a held statement lists them, from
/// this machine's checks (node::held_json's shape).
[[nodiscard]] nlohmann::json review_json(Session& session, const ApprovalReview& review);

/// Signs an approval of the reviewed statement as the holder of `signer`,
/// proving presence as `presence` says. Refused if the statement would be
/// refused, is registered, or was issued ahead of this machine's clock; if
/// the signer signed it, or no rule names the signer; and without presence
/// where every rule naming the signer needs it.
[[nodiscard]] protocol::SignedApproval approve(Session& session, const crypto::Signer& signer,
                                               const ApprovalReview& review,
                                               const std::optional<PresenceRequest>& presence);

/// What became of an approval given to a held statement.
struct GivenApproval {
    /// Its rules were met: registered, at this log index.
    std::optional<std::uint64_t> registered;
    /// Otherwise, the held statement as it stands.
    nlohmann::json held;
};

/// Gives an approval to a statement held at the server, or in the ledger
/// directory (registering it, with every approval kept, once its rules are
/// met).
[[nodiscard]] GivenApproval give_held(Session& session, const protocol::Id& id,
                                      const protocol::SignedApproval& approval);

/// The approval files of one statement as one: every approval (the latest
/// of an approver's, by its approved-at), and the rest of its submission
/// and its fields from whichever file has them. Refused if they hold
/// different statements, or different parts.
[[nodiscard]] protocol::ApprovalFile
combine_approval_files(std::vector<protocol::ApprovalFile> files);

/// Registers an approval file's statement with its approvals and the rest
/// of its submission.
protocol::Id submit_approved(Session& session, const protocol::ApprovalFile& file);

/// Withdraws a held statement (at the server: an admin token).
void withdraw_held(Session& session, const protocol::Id& id);

} // namespace kanhe::client
