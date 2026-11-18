// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include "output.hpp"

#include <algorithm>
#include <print>

#include <kanhe/client/approvals.hpp>

namespace kanhe::cli {

int report_submitted(const Args& args, const client::Session& session,
                     const protocol::Id& statement, const Json& extra, const std::string& text) {
    if (args.json()) {
        Json out{{"statement_id", id_json(statement)},
                 {"index", session.state().statement_index(statement).value_or(0)}};
        for (const auto& [key, value] : extra.items()) {
            out[key] = value;
        }
        print_json(out);
    } else {
        std::println("{}", text);
    }
    return 0;
}

Json tally_json(const client::Session& session, const protocol::ApprovalTally& tally) {
    Json rules = Json::array();
    for (const protocol::RuleTally& r : tally.rules) {
        Json approvers = Json::array();
        for (const protocol::Id& a : r.applied.rule.approvers) {
            approvers.push_back(actor_ref(session, a));
        }
        Json counted = Json::array();
        for (const protocol::Id& a : r.counted) {
            counted.push_back(id_json(a));
        }
        rules.push_back(
            {{"source", protocol::name(r.applied.source)},
             {"delegation", r.applied.delegation ? id_json(*r.applied.delegation) : Json(nullptr)},
             {"k", r.applied.rule.needed},
             {"approvers", std::move(approvers)},
             {"within_ms", r.applied.rule.within},
             {"without_presence", r.applied.rule.without_presence},
             {"counted", std::move(counted)},
             {"signer_counts", r.signer_counts},
             {"missing", r.missing()},
             {"lapses_at", iso_time(r.lapses_at)},
             {"summary", client::rule_text(session, r.applied.rule)}});
    }
    return rules;
}

void print_sent_for_approval(const Args& args, const client::Session& session,
                             const client::SentForApproval& sent) {
    protocol::Timestamp lapses = 0;
    for (const protocol::RuleTally& r : sent.tally.rules) {
        lapses = lapses == 0 ? r.lapses_at : std::min(lapses, r.lapses_at);
    }
    const std::string where = sent.file ? "file" : session.remote() ? "server" : "ledger directory";
    if (args.json()) {
        Json out{{"sent_for_approval", true},
                 {"statement_id", id_json(sent.statement)},
                 {"where", where},
                 {"file", sent.file ? Json(sent.file->string()) : Json(nullptr)},
                 {"fields_shown", sent.fields_shown},
                 {"rules", tally_json(session, sent.tally)},
                 {"lapses_at", iso_time(lapses)}};
        if (!sent.held.is_null()) {
            out["held"] = Json::parse(sent.held.dump());
        }
        print_json(out);
        return;
    }
    std::println("sent for approval, not registered yet: statement {}", hex_id(sent.statement));
    if (sent.file) {
        std::println("  written to {}: an approval file for the approvers", sent.file->string());
    } else if (session.remote()) {
        std::println("  held at {}", session.server_url());
    } else {
        std::println("  held in the ledger directory {}", session.directory().string());
    }
    for (const protocol::RuleTally& r : sent.tally.rules) {
        std::string source;
        if (r.applied.source != protocol::RuleSource::delegation || sent.tally.rules.size() > 1) {
            source = " (" + client::rule_source_text(r.applied) + ")";
        }
        std::println("  needs {}{}: {} more{}", client::rule_text(session, r.applied.rule), source,
                     r.missing(), r.signer_counts ? " (you count as one)" : "");
    }
    std::println("  lapses at {}: registered by then, or never", format_time(lapses));
    if (sent.fields_shown) {
        std::println("  its fields travel with it in clear: give it to its approvers only");
    }
    const std::string target = sent.file ? sent.file->string() : short_id(sent.statement);
    std::println("Each approver checks it on their own machine and approves it in person:");
    std::println("  kanhe approval give {}{} --as KEY --presence", target,
                 sent.file || !session.remote() ? "" : " --server " + session.server_url());
    if (sent.file) {
        std::println("then, with every approval in: kanhe approval submit {}", target);
    }
}

} // namespace kanhe::cli
