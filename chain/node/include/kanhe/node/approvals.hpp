// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <nlohmann/json.hpp>

#include <kanhe/core/bytes.hpp>
#include <kanhe/core/cbor.hpp>
#include <kanhe/core/crypto.hpp>
#include <kanhe/core/error.hpp>
#include <kanhe/core/protocol/approval_file.hpp>
#include <kanhe/core/protocol/approvals.hpp>
#include <kanhe/core/protocol/record.hpp>
#include <kanhe/core/protocol/state.hpp>
#include <kanhe/node/contracts.hpp>

/// Statements held until their approvals are in (spec v0.20, section 16): a
/// server's, or a ledger directory's for the command line working on it.
/// One person prepares a statement and sends it here; the approvers approve
/// it, each on their own machine, and it is registered with their approvals
/// the moment every rule that applies to it is met. What is held is a hint
/// for people: the ledger checks the statement and its approvals again when
/// it registers them, and whoever holds the signed statement and enough
/// approvals may register it elsewhere until its window ends.
///
/// Files under <ledger>/approvals:
///   held/<statement id>.cbor    a statement held, with what came with it
///                               (`held-statement` below)
///   done/<statement id>.cbor    what became of one (registered, lapsed,
///                               withdrawn, or dropped), kept 30 days without
///                               its fields or the rest of its submission
///
///   held-statement = {
///     1: signed statement, ? 2: submission parts (bstr .cbor submission-parts),
///     ? 3: [+ record-field] (shown to approvers), ? 4: note,
///     ? 5: [+ [approval, presence (0 none, 1 passkey, 2 hardware key), user verified]],
///     6: preparer, 7: held at, 8: lapses at, 9: the signer proved presence, user verified,
///     ? 10: [+ [approver, at]] (declines: hints for the preparer),
///     ? 11: [+ [approver, at, reason]] (approvals dropped: they stopped verifying),
///     ? 12: what became of it (1 registered, 2 lapsed, 3 withdrawn, 4 dropped),
///     ? 13: when, ? 14: its log index (registered), ? 15: why (dropped)
///   }
///
/// The approvals kept are ascending by approver, each checked as the ledger
/// will check it when it was kept, and again whenever the ledger changes.
namespace kanhe::node {

/// A server holds at most this many statements per ledger, each, with what
/// came with it, at most this large; what became of one is kept this long.
inline constexpr std::size_t max_held_statements = 1000;
inline constexpr std::size_t max_held_statement = std::size_t{1} << 20;
inline constexpr protocol::Timestamp held_history = protocol::Timestamp{30} * 86'400'000;

[[nodiscard]] std::filesystem::path
approvals_directory(const std::filesystem::path& ledger_directory);

/// What became of a statement sent for approval.
enum class HeldState : std::uint8_t {
    open = 0,
    registered = 1,
    lapsed = 2,
    withdrawn = 3,
    dropped = 4,
};

[[nodiscard]] std::string_view name(HeldState state) noexcept;

/// An approval as kept: its bytes, and how its approver proved presence
/// when it was last checked.
struct KeptApproval {
    Bytes encoded;
    /// nullopt: not in person.
    std::optional<protocol::PresenceMethod> presence;
    bool user_verified = false;

    friend bool operator==(const KeptApproval&, const KeptApproval&) = default;
};

/// A decline (a hint the preparer sees; nothing goes on the ledger), and an
/// approval that stopped verifying, dropped so that its approver may
/// approve again.
struct HeldDecline {
    protocol::Id approver;
    protocol::Timestamp at = 0;

    friend bool operator==(const HeldDecline&, const HeldDecline&) = default;
};
struct DroppedApproval {
    protocol::Id approver;
    protocol::Timestamp at = 0;
    std::string reason;

    friend bool operator==(const DroppedApproval&, const DroppedApproval&) = default;
};

struct HeldStatement {
    /// The signed statement, as its signer signed it.
    Bytes statement;
    /// The rest of its submission (`submission-parts`), encoded, if any.
    std::optional<Bytes> parts;
    /// A registration's fields, shown to approvers; kept only while held.
    std::vector<protocol::RecordField> fields;
    std::optional<std::string> note;
    /// Ascending by approver.
    std::vector<KeptApproval> approvals;
    /// Who sent it: the API token's name (or "console", "cli").
    std::string preparer;
    protocol::Timestamp held_at = 0;
    /// The earliest end of its rules' windows.
    protocol::Timestamp lapses_at = 0;
    /// The signer proved presence, user-verified: it counts for every rule
    /// that names it.
    bool signer_verified = false;
    std::vector<HeldDecline> declines;
    std::vector<DroppedApproval> dropped;
    HeldState state = HeldState::open;
    /// Once it is no longer held: when, its log index if registered, and why
    /// if dropped.
    protocol::Timestamp ended_at = 0;
    std::optional<std::uint64_t> index;
    std::optional<std::string> reason;

    friend bool operator==(const HeldStatement&, const HeldStatement&) = default;
};

[[nodiscard]] Result<Bytes> encode_held_statement(const HeldStatement& held);
[[nodiscard]] Result<HeldStatement> decode_held_statement(ByteView encoded);

/// The body POST /v1/approvals takes: {1: signed statement, ? 2: submission
/// parts, ? 3: fields, ? 4: note}, keys 2 to 4 as an approval file's 5 to 7.
/// Only `statement`, `parts`, `fields`, and `note` are read and written.
[[nodiscard]] Result<Bytes> encode_hold_request(const HeldStatement& held);
[[nodiscard]] Result<HeldStatement> decode_hold_request(ByteView encoded);

/// A change to the held statements: a file written, or removed (no bytes),
/// by its name under the approvals directory, "held/<id>.cbor" or
/// "done/<id>.cbor". A cluster replicates them as [* [name, file / null]].
using HeldChange = PendingChange;
[[nodiscard]] cbor::Value held_changes_value(std::span<const HeldChange> changes);
[[nodiscard]] Result<std::vector<HeldChange>> decode_held_changes(const cbor::Value& value);

/// Applies changes under <ledger>/approvals: names must be held or done
/// statements', and files must decode for the statement their name gives, or
/// nothing is changed (Errc::malformed). Each file written is synced, then
/// its directory once.
[[nodiscard]] Status apply_held_changes(const std::filesystem::path& ledger_directory,
                                        std::span<const HeldChange> changes);

/// The names (as HeldChange names them) of every held and done statement's
/// file, for a cluster's snapshot.
[[nodiscard]] std::vector<std::string>
held_file_names(const std::filesystem::path& ledger_directory);

/// The statements held, or (`done`) what became of others, in id order;
/// files that do not decode are left out. Any thread: files change
/// atomically.
[[nodiscard]] std::vector<std::pair<protocol::Id, HeldStatement>>
held_statements(const std::filesystem::path& ledger_directory, bool done = false);
[[nodiscard]] std::optional<HeldStatement>
held_statement(const std::filesystem::path& ledger_directory, const protocol::Id& id,
               bool done = false);
/// How many statements are held.
[[nodiscard]] std::size_t held_count(const std::filesystem::path& ledger_directory);

/// The approval file (spec v0.20, section 5.1) for a statement held: its
/// statement, the approvals kept, the rest of its submission, its fields
/// and note.
[[nodiscard]] Result<Bytes> held_approval_file(const crypto::Provider& provider,
                                               crypto::HashAlg hash, const HeldStatement& held);

/// What the desk made of a statement sent for approval, or of an approval.
struct HeldProgress {
    enum class Verdict : std::uint8_t {
        /// Register it now: no rule needs approvals, or every rule is met
        /// with `approvals`.
        ready,
        /// Held until more approvals arrive.
        waiting,
    };
    Verdict verdict = Verdict::waiting;
    protocol::Id id;
    HeldStatement held;
    protocol::ApprovalTally tally;
    /// The approvals to register it with, in their log entry's order.
    std::vector<Bytes> approvals;
    /// The changes to make to the held statements.
    std::vector<HeldChange> changes;
};

/// The logic of held statements. It reads the files under the ledger
/// directory and leaves writing them to the caller (directly, or through a
/// cluster), so it changes nothing itself.
class ApprovalDesk {
public:
    explicit ApprovalDesk(std::filesystem::path ledger_directory);

    /// Takes a statement sent for approval at `now`: `candidate` holds the
    /// statement and what came with it, and the preparer. It must pass every
    /// rule but its approvals, its parts must be ones it takes, and its
    /// fields its own. Ready if it needs no approvals (no rule applies, or
    /// its signer meets every rule), and for one registered already; the
    /// same statement again is answered as it stands. Refused at the limit.
    [[nodiscard]] Result<HeldProgress> hold(const crypto::Provider& provider,
                                            const protocol::LedgerState& state,
                                            HeldStatement candidate, protocol::Timestamp now) const;

    /// Takes one approval of a held statement, checked as the ledger will
    /// check it at `now` (spec section 5.1, checks 3.1 to 3.7): the same
    /// bytes again are a retry; another by an approver it keeps one of is
    /// refused (Errc::rejected). Kept approvals that no longer verify are
    /// dropped first. Ready once every rule is met.
    [[nodiscard]] Result<HeldProgress> approve(const crypto::Provider& provider,
                                               const protocol::LedgerState& state,
                                               const protocol::Id& id, ByteView approval,
                                               protocol::Timestamp now) const;

    /// Withdraws a held statement (Errc::not_found if none is held).
    [[nodiscard]] Result<std::vector<HeldChange>> withdraw(const protocol::Id& id,
                                                           protocol::Timestamp now) const;

    /// Keeps an approver's decline beside a held statement, for its
    /// preparer: the approver must be named by a rule that applies.
    [[nodiscard]] Result<std::vector<HeldChange>>
    decline(const crypto::Provider& provider, const protocol::LedgerState& state,
            const protocol::Id& id, const protocol::Id& approver, protocol::Timestamp now) const;

    /// The statement was registered at `index`: it is held no more.
    [[nodiscard]] std::vector<HeldChange> registered(const protocol::Id& id, std::uint64_t index,
                                                     protocol::Timestamp now) const;

    /// The changes that are due at `now`: statements registered (by anyone),
    /// lapsed, or no longer registrable; with `recheck` (the ledger changed
    /// since the last sweep), kept approvals that stopped verifying,
    /// dropped and listed; and what became of statements more than 30 days
    /// ago, forgotten.
    [[nodiscard]] std::vector<HeldChange> sweep(const crypto::Provider& provider,
                                                const protocol::LedgerState& state,
                                                protocol::Timestamp now, bool recheck) const;

private:
    std::filesystem::path directory_;
};

/// A held statement for people and programs (GET /v1/approvals): its id,
/// what became of it, its type and a summary of its body, its signer and
/// issue time, the rules that apply to it now with what counts for each and
/// what is missing, the approvals kept (approver, approved at, presence, the
/// rules each counts for), when it lapses, its note, declines and dropped
/// approvals. Times are milliseconds since the epoch. A hint: approvers'
/// tools check the statement against the ledger themselves.
[[nodiscard]] nlohmann::json held_json(const crypto::Provider& provider,
                                       const protocol::LedgerState& state, const protocol::Id& id,
                                       const HeldStatement& held);

/// What GET /v1/approvals answers, {"approvals": [...], "time": now}: the
/// statements held under `ledger_directory` (held_json each), those
/// `approver` may approve if one is given; with `all`, also what became of
/// others in the last 30 days (those whose rules name `approver`, if given).
[[nodiscard]] nlohmann::json held_list_json(const crypto::Provider& provider,
                                            const protocol::LedgerState& state,
                                            const std::filesystem::path& ledger_directory,
                                            const std::optional<protocol::Id>& approver, bool all,
                                            protocol::Timestamp now);

/// Whether `approver` may approve the held statement: a rule that applies
/// names it, it is not its signer, and it has not approved it yet.
[[nodiscard]] bool may_approve(const crypto::Provider& provider, const protocol::LedgerState& state,
                               const HeldStatement& held, const protocol::Id& approver);

/// A one-line summary of a statement's body, for lists.
[[nodiscard]] std::string held_summary(const protocol::LedgerState& state,
                                       const protocol::Statement& statement);

} // namespace kanhe::node
