// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <utility>
#include <variant>
#include <vector>

#include <kanhe/client/long_term.hpp>
#include <kanhe/core/protocol/keys.hpp>
#include <kanhe/node/long_term.hpp>

namespace kanhe::client {

namespace {

/// A rotation's step: rotated, done already (a run before rotated it to the
/// key given), or kept (post-quantum already, another key).
LongTermStep plan_rotation(std::string name, const crypto::PublicKey& current,
                           const std::optional<crypto::PublicKey>& wanted) {
    LongTermStep s;
    s.name = std::move(name);
    s.from = current;
    if (wanted && current == *wanted) {
        s.status = "done";
        s.to = current;
    } else if (node::post_quantum_algorithm(current.algorithm)) {
        s.status = "kept";
        s.to = current;
    } else if (wanted) {
        s.to = wanted;
    }
    return s;
}

/// The key a rotation replaced: the one before the last of `epochs`.
std::optional<crypto::PublicKey> replaced(std::span<const protocol::KeyEpoch> epochs) {
    return epochs.size() >= 2 ? std::optional(epochs[epochs.size() - 2].key) : std::nullopt;
}

} // namespace

std::vector<LongTermStep> plan_long_term(const protocol::LedgerState& state,
                                         const std::optional<crypto::PublicKey>& new_root,
                                         const std::optional<crypto::PublicKey>& new_log) {
    std::vector<LongTermStep> steps;
    steps.push_back(plan_rotation("rotate-log-key", state.log_key(), new_log));
    steps.push_back(plan_rotation("rotate-root-key", state.root_key(), new_root));
    LongTermStep checkpoint;
    checkpoint.name = "checkpoint";
    steps.push_back(std::move(checkpoint));
    // A key rotated before (a resumed run) replaced the one before it.
    if (steps[0].status == "done") {
        steps[0].from = replaced(state.log_keys());
    }
    if (steps[1].status == "done") {
        steps[1].from = replaced(state.root_keys());
    }
    return steps;
}

bool long_term_rotates(const std::vector<LongTermStep>& steps) {
    for (const LongTermStep& s : steps) {
        if (s.name != "checkpoint" && s.status == "planned") {
            return true;
        }
    }
    return false;
}

protocol::Body long_term_body(const protocol::Id& ledger_id, const LongTermStep& step) {
    if (step.name == "rotate-log-key") {
        return protocol::Body{protocol::LedgerRotateLogKeyBody{step.to.value()}};
    }
    return protocol::Body{protocol::ActorRotateKeyBody{ledger_id, step.to.value()}};
}

std::optional<std::string_view> long_term_rotation(const protocol::Statement& statement,
                                                   const protocol::Id& ledger_id) {
    // Signed by the organization, and for an actor-rotate-key, of its own
    // root key (not a person's key).
    if (statement.actor_id && *statement.actor_id != ledger_id) {
        return std::nullopt;
    }
    if (std::holds_alternative<protocol::LedgerRotateLogKeyBody>(statement.body)) {
        return "rotate-log-key";
    }
    if (const auto* body = std::get_if<protocol::ActorRotateKeyBody>(&statement.body);
        body != nullptr && body->actor == ledger_id) {
        return "rotate-root-key";
    }
    return std::nullopt;
}

std::optional<std::uint64_t> long_term_checkpointed(const ledger::Ledger& ledger) {
    std::optional<crypto::PublicKey> log_key;
    ledger.read_state([&](const protocol::LedgerState& state) { log_key = state.log_key(); });
    const auto latest = ledger.latest_checkpoint();
    if (!latest || !log_key || latest->checkpoint.tree_size != ledger.size()) {
        return std::nullopt;
    }
    const auto kid = protocol::key_id(ledger.provider(), ledger.hash(), *log_key);
    if (!kid || latest->kid != *kid) {
        return std::nullopt;
    }
    return latest->checkpoint.tree_size;
}

} // namespace kanhe::client
