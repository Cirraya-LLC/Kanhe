// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <optional>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include <kanhe/core/protocol/common.hpp>
#include <kanhe/core/protocol/statement.hpp>

/// What a person may do on the ledger, in the console's plain words, and
/// the delegation scope that says it. A person approved from the console
/// always acts in person (their passkey's tap).
namespace kanhe::console {

struct Permissions {
    /// Register documents: of these kinds' record types, or of any.
    bool register_documents = false;
    std::optional<std::vector<std::string>> kinds;
    bool endorse = false;
    bool revoke = false;
    /// Create things under rules, act on them, consent, and answer requests:
    /// under these contracts, or any.
    bool act = false;
    std::optional<std::vector<protocol::Id>> contracts;
    /// Deploy and retire rules.
    bool rules = false;
    /// Register people, set their passkeys, and grant and revoke what they
    /// may do (only within what the granter may do).
    bool people = false;
    std::optional<protocol::Timestamp> until;
    /// Needs approvals (spec v0.20): what they sign under the delegation is
    /// registered only once k of these people approve it, within the
    /// window. Without presence, approvals that are not in person count too
    /// (which lets agents and devices approve).
    std::optional<protocol::ApprovalRule> approvals;

    // As read from a delegation (not chosen in the form):
    bool in_person = true;
    bool may_delegate = false;
    /// Statement types the words above do not cover, by name.
    std::vector<std::string> other;
};

/// The record types the protocol's own mechanisms register (consents and
/// access requests, grants, and receipts): a person who may act or register
/// documents may register them too, whatever kinds are chosen.
[[nodiscard]] std::vector<std::string> mechanism_record_types();

/// The scope for `permissions`: in person, delegating only with `people`.
/// Throws std::invalid_argument if it allows nothing.
[[nodiscard]] protocol::Scope scope_of(const Permissions& permissions);
/// The plain words for a delegation's scope.
[[nodiscard]] Permissions permissions_of(const protocol::Scope& scope);

[[nodiscard]] nlohmann::json permissions_json(const Permissions& permissions);
/// From the page's form; nullopt if it is not one.
[[nodiscard]] std::optional<Permissions> parse_permissions(const nlohmann::json& value);
/// What a role is given by default: an admin everything, a member documents
/// and things under rules, a viewer nothing.
[[nodiscard]] Permissions default_permissions(std::string_view role);

/// A delegation's scope as the page and its checks compare it.
[[nodiscard]] nlohmann::json scope_json(const protocol::Scope& scope);

/// An approval rule as the page and its checks compare it: {k, approvers
/// (ids in hex, ascending), within (ms), without_presence}.
[[nodiscard]] nlohmann::json rule_json(const protocol::ApprovalRule& rule);
/// From the page's form ({k, approvers, within, without_presence}), sorted
/// as a scope encodes it; nullopt if it is not one (counts, limits).
[[nodiscard]] std::optional<protocol::ApprovalRule> parse_rule(const nlohmann::json& value);

} // namespace kanhe::console
