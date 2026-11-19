// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <kanhe/core/crypto.hpp>
#include <kanhe/core/protocol/common.hpp>
#include <kanhe/core/protocol/state.hpp>
#include <kanhe/core/protocol/statement.hpp>
#include <kanhe/ledger/ledger.hpp>

/// A ledger's keys moved to post-quantum signatures in one step (spec v0.21,
/// section 11.1): the log key rotated, then the root key, each signed by the
/// root key in effect, then a checkpoint with the new log key. What is done
/// already is found again from the ledger's state, so the conversion goes on
/// from where it stopped. The command line (ledger long-term) and the web
/// console share these; each signs and sends the rotations its own way.
namespace kanhe::client {

/// One step of the conversion: "rotate-log-key", "rotate-root-key", or
/// "checkpoint", in that order.
struct LongTermStep {
    std::string name;
    /// "planned", "rotated" or "made" (by this run), "done" (before it),
    /// "kept" (post-quantum already), "sent-for-approval", or "failed".
    std::string status = "planned";
    std::optional<crypto::PublicKey> from;
    std::optional<crypto::PublicKey> to;
    /// A key to be generated, not made yet: where it goes (the command
    /// line's --generate).
    std::optional<std::string> to_file;
    std::optional<protocol::Id> statement;
    std::optional<std::uint64_t> index;
    std::optional<std::uint64_t> tree_size;
    std::optional<std::string> error;
};

/// The conversion's three steps for a ledger in `state`, to the new root key
/// and log key given (nullopt: one still to be made, and then the step's
/// `to` is empty). A rotation is "done" if a run before rotated the key to
/// the one given (its `from` is then the key it replaced, if the ledger had
/// one before it), "kept" if the key in effect is post-quantum already, and
/// "planned" otherwise; the checkpoint is "planned".
[[nodiscard]] std::vector<LongTermStep>
plan_long_term(const protocol::LedgerState& state, const std::optional<crypto::PublicKey>& new_root,
               const std::optional<crypto::PublicKey>& new_log);

/// Whether a rotation of `steps` is still planned.
[[nodiscard]] bool long_term_rotates(const std::vector<LongTermStep>& steps);

/// The statement body a planned rotation signs, with the root key in effect:
/// the ledger's new log key, or the organization's new root key. `step.to`
/// must be set.
[[nodiscard]] protocol::Body long_term_body(const protocol::Id& ledger_id,
                                            const LongTermStep& step);

/// Which of the conversion's rotations `statement` is: "rotate-log-key" for a
/// rotation of the ledger's log key, "rotate-root-key" for one of the
/// organization's own root key, each by the organization (or naming no
/// actor); nothing for any other statement.
[[nodiscard]] std::optional<std::string_view>
long_term_rotation(const protocol::Statement& statement, const protocol::Id& ledger_id);

/// The size of the ledger's latest checkpoint if it covers the whole log and
/// is signed by the log key in effect: the conversion's checkpoint is made
/// then. Safe to call beside the ledger's writer.
[[nodiscard]] std::optional<std::uint64_t> long_term_checkpointed(const ledger::Ledger& ledger);

} // namespace kanhe::client
