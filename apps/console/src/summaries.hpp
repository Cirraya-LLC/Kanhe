// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <nlohmann/json.hpp>

#include <kanhe/core/protocol/state.hpp>
#include <kanhe/core/protocol/statement.hpp>

// What the console says of a statement, for the page to show and to compare
// with what its WebAssembly decodes from the bytes (approve.cpp): before a
// person confirms their own statement, and before they approve someone
// else's (approvals.cpp).
namespace kanhe::console {

/// A statement's type and the fields of its body the page shows and checks,
/// with the names of the actors, records, and contracts it is about.
[[nodiscard]] nlohmann::json describe_statement(const protocol::Statement& statement,
                                                const protocol::LedgerState& state);

/// A registration's terms (a consent's, a claim's, an access record's, or a
/// script's) or, for any other, its public metadata as text names and values
/// (null if it holds anything else): {"metadata": ..., and one of "consent",
/// "claim", "access", "script_approval"}.
[[nodiscard]] nlohmann::json registration_terms(const protocol::RecordRegisterBody& body);

} // namespace kanhe::console
