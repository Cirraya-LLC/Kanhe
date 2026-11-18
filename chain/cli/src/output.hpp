// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <string>

#include <kanhe/client/views.hpp>

#include "json_output.hpp"
#include "support.hpp"

/// Printing: the app library's views, written to standard output.
namespace kanhe::cli {

/// Prints the result of a statement just registered: its id and log index
/// plus `extra` as JSON, or `text`.
int report_submitted(const Args& args, const client::Session& session,
                     const protocol::Id& statement, const Json& extra, const std::string& text);

/// The rules that apply to a statement, counted (spec v0.20): each with its
/// source, k, approvers, window, what counted, what is missing, and when it
/// lapses.
[[nodiscard]] Json tally_json(const client::Session& session, const protocol::ApprovalTally& tally);

/// Prints what was sent for approval instead of registered: where it is,
/// the rules in words and what each still needs, and when it lapses.
void print_sent_for_approval(const Args& args, const client::Session& session,
                             const client::SentForApproval& sent);

} // namespace kanhe::cli
