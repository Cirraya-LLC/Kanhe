// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// Approvals and guardians (spec v0.20): statements held until k of n named
// people approve them, approval files, and the organization's guardians.

#include <algorithm>
#include <cstdio>
#include <filesystem>
#include <format>
#include <print>

#include <kanhe/client/approvals.hpp>
#include <kanhe/core/protocol/approval_file.hpp>

#include "commands.hpp"
#include "output.hpp"

namespace kanhe::cli {

namespace {

/// The command line's JSON of a plain JSON value.
Json ordered(const nlohmann::json& value) {
    return value.is_null() ? Json(nullptr) : Json::parse(value.dump());
}

/// An approval file names a path: one that exists, holds a slash, or ends
/// in .kanheapproval. Anything else is a held statement's id.
bool names_file(const std::string& text) {
    return text.ends_with(protocol::approval_file_extension) ||
           text.find('/') != std::string::npos || std::filesystem::is_regular_file(text);
}

client::ApprovalReview load_review(Session& session, const std::string& what) {
    if (names_file(what)) {
        return client::review_approval(session, client::read_approval_file(session, what), false);
    }
    const protocol::Id id = client::held_id(session, what);
    return client::review_approval(session, client::fetch_held(session, id), true);
}

std::string source_text(const Session& session, const client::ApprovalReview& review,
                        const std::string& what) {
    if (!review.held) {
        return "the approval file " + what;
    }
    return session.remote() ? "held at " + session.server_url()
                            : "held in the ledger directory " + session.directory().string();
}

std::string presence_text(const std::optional<protocol::PresenceCheck>& presence) {
    if (!presence) {
        return "not in person";
    }
    if (presence->method == protocol::PresenceMethod::hardware_key) {
        return "in person (hardware key)";
    }
    return presence->user_verified ? "in person (passkey, user verified)"
                                   : "present (passkey, user not verified)";
}

void print_review(const Session& session, const client::ApprovalReview& review,
                  const std::string& source) {
    const protocol::SignedStatement& s = review.file.statement;
    const protocol::Statement& st = s.statement;
    std::println("statement:     {}", hex_id(s.id));
    std::println("from:          {} (checked here against the ledger)", source);
    std::println("what:          {}", statement_summary(session, s));
    if (st.actor_id) {
        const protocol::ActorState* signer = session.state().actor(*st.actor_id);
        std::println("signer:        {} ({}){}", session.actor_name(*st.actor_id),
                     signer != nullptr ? kind_text(signer->kind) : std::string("unknown"),
                     review.signer_verified ? ", in person"
                     : st.presence          ? ", present but not verified"
                                            : "");
    }
    std::println("delegation:    {}",
                 st.delegation_id ? short_id(*st.delegation_id) : std::string("none"));
    std::println("issued:        {} (as its signer claims){}", format_time(st.issued_at),
                 review.future ? "  AHEAD OF THIS MACHINE'S CLOCK" : "");
    if (review.file.note) {
        std::println("note:          {}", *review.file.note);
    }
    if (!review.file.fields.empty()) {
        std::println("fields:        shown by its preparer, and they give the record's field root");
        for (const protocol::RecordField& f : review.file.fields) {
            std::println("  {}: {}", f.name, verifier::display_value(f.value));
        }
    } else if (std::holds_alternative<protocol::RecordRegisterBody>(st.body)) {
        std::println("fields:        not shown (only their commitment is in the statement)");
    }
    if (review.tally.rules.empty()) {
        std::println("rules:         none applies: it needs no approvals");
    }
    for (const protocol::RuleTally& r : review.tally.rules) {
        std::println("needs:         {} ({}): {} counted{}, {}",
                     client::rule_text(session, r.applied.rule),
                     client::rule_source_text(r.applied), r.counted.size(),
                     r.signer_counts ? " (its signer among them)" : "",
                     r.missing() == 0 ? std::string("met") : std::format("{} more", r.missing()));
        std::println("               lapses {}", format_time(r.lapses_at));
    }
    for (std::size_t i = 0; i < review.file.approvals.size(); ++i) {
        const protocol::Approval& a = review.file.approvals[i].approval;
        if (review.problems[i]) {
            std::println("approval:      {}: DOES NOT COUNT: {}", session.actor_name(a.approver),
                         *review.problems[i]);
            continue;
        }
        const auto check = std::ranges::find(review.tally.approvals, a.approver,
                                             &protocol::ApprovalCheck::approver);
        std::println(
            "approval:      {}, {}, at {} (as claimed)", session.actor_name(a.approver),
            presence_text(check != review.tally.approvals.end() ? check->presence : std::nullopt),
            format_time(a.approved_at));
    }
    if (review.registered) {
        std::println("status:        REGISTERED at entry #{}", *review.registered);
    } else if (review.lapsed) {
        std::println("status:        LAPSED: its window has ended, and it can no longer be "
                     "registered");
    } else if (review.refused) {
        std::println("status:        THE LEDGER WOULD REFUSE IT NOW: {}", *review.refused);
    } else if (review.tally.none()) {
        std::println("status:        it needs no approvals");
    } else if (review.tally.met(review.now)) {
        std::println("status:        every rule is met: it can be registered");
    } else {
        std::println("status:        waiting for approvals");
    }
}

/// What a rule still needs, for people: "1 more of 2 of Chan, Lee, Ho".
std::string missing_text(const Session& session, const protocol::ApprovalTally& tally) {
    std::string out;
    for (const protocol::RuleTally& r : tally.rules) {
        if (r.missing() > 0) {
            out +=
                (out.empty() ? "" : "; ") + std::format("{} more for {}", r.missing(),
                                                        client::rule_text(session, r.applied.rule));
        }
    }
    return out;
}

std::string ms_time(const nlohmann::json& value) {
    return value.is_number_unsigned() ? format_time(value.get<protocol::Timestamp>())
                                      : std::string("-");
}

/// The organization's root key, from --as.
std::unique_ptr<crypto::Signer> root_signer(const Args& args, const Session& session) {
    auto signer = load_signer(args.need("as"), args);
    if (signer->public_key() != session.state().root_key()) {
        throw UsageError{"--as must be the organization's current root key"};
    }
    return signer;
}

std::string guarded_text(const std::optional<std::vector<protocol::StatementType>>& guarded) {
    if (!guarded) {
        return "every statement the organization signs";
    }
    std::string types;
    for (const protocol::StatementType t : *guarded) {
        types += (types.empty() ? "" : ", ") + std::string(protocol::name(t));
    }
    return "the organization's " + types +
           "; and always its key rotations, guardian settings, and statements about a guardian";
}

} // namespace

// ---------------------------------------------------------------------------
// Approvals
// ---------------------------------------------------------------------------

int cmd_approval_list(const Args& args) {
    Session session(args);
    std::optional<protocol::Id> approver;
    if (args.has("mine")) {
        if (args.has("approver")) {
            throw UsageError{"--mine and --approver exclude each other"};
        }
        const crypto::PublicKey key = public_key_of(args.need("as"), args);
        const auto kid =
            unwrap(protocol::key_id(session.provider(), session.state().hash(), key), "key id");
        const protocol::ActorState* me = session.state().actor_by_kid(kid);
        if (me == nullptr) {
            throw CommandError{"this key does not belong to any actor of the ledger"};
        }
        approver = protocol::Id(me->id);
    } else if (const auto a = args.get("approver")) {
        approver = session.actor_id(*a);
    } else if (args.has("as")) {
        throw UsageError{"--as goes with --mine"};
    }
    std::uint64_t wait = 0;
    if (const auto w = args.get("wait")) {
        wait = parse_number(*w, "--wait");
        if (wait > 25) {
            throw UsageError{"--wait is 0 to 25 seconds"};
        }
    }
    const nlohmann::json list = client::list_held(session, approver, args.has("all"), wait);
    if (args.json()) {
        print_json(ordered(list));
        return exit_ok;
    }
    if (list["approvals"].empty()) {
        std::println("{}", approver ? "nothing is held for " + session.actor_name(*approver) +
                                          " to approve"
                                    : std::string("nothing is held for approval"));
        return exit_ok;
    }
    for (const nlohmann::json& item : list["approvals"]) {
        const std::string state = item.value("state", std::string("open"));
        std::string needs;
        for (const nlohmann::json& rule : item.value("rules", nlohmann::json::array())) {
            needs += (needs.empty() ? "" : "; ") +
                     std::format("{} more of {}", rule.value("missing", std::uint64_t{0}),
                                 rule.value("k", std::uint64_t{0}));
        }
        const std::string signer = item.contains("signer") && item["signer"].is_object()
                                       ? item["signer"].value("name", std::string("unknown"))
                                       : std::string("unknown");
        std::println("{}  {:<10} {}  by {}", item.value("id", std::string()).substr(0, 12), state,
                     item.value("summary", std::string()), signer);
        if (state == "open") {
            std::println("              needs {}; lapses {}", needs.empty() ? "none" : needs,
                         ms_time(item.value("lapses_at", nlohmann::json())));
        } else {
            std::println("              {} {}{}", state,
                         ms_time(item.value("ended_at", nlohmann::json())),
                         item.contains("index") && item["index"].is_number()
                             ? std::format(" (entry #{})", item["index"].get<std::uint64_t>())
                             : std::string());
        }
    }
    std::println("This is the server's list: check a statement with kanhe approval show before "
                 "approving it.");
    return exit_ok;
}

int cmd_approval_show(const Args& args) {
    Session session(args);
    const std::string what = args.positional().front();
    const client::ApprovalReview review = load_review(session, what);
    if (args.json()) {
        print_json(ordered(client::review_json(session, review)));
        return exit_ok;
    }
    print_review(session, review, source_text(session, review, what));
    return exit_ok;
}

int cmd_approval_give(const Args& args) {
    Session session(args);
    const std::string what = args.positional().front();
    const bool from_file = names_file(what);
    const client::ApprovalReview review = load_review(session, what);
    const protocol::Id id = review.file.statement.id;
    if (!args.json()) {
        print_review(session, review, source_text(session, review, what));
    }
    const auto signer = load_signer(args.need("as"), args);
    const protocol::ActorState& me = session.actor_for(*signer);
    if (!args.has("yes") && !confirm_on_terminal("Approve statement " + short_id(id) + " as \"" +
                                                 me.display_name + "\"?")) {
        throw CommandError{"not approved"};
    }
    const protocol::SignedApproval approval =
        client::approve(session, *signer, review, presence_request(args));
    if (from_file || args.has("out")) {
        protocol::ApprovalFile file = review.file;
        unwrap(protocol::add_approval(file, approval), "adding the approval to the file");
        const std::filesystem::path out = args.get("out").value_or(what);
        client::write_approval_file(file, out);
        const client::ApprovalReview after = client::review_approval(session, file, false);
        const bool complete = !after.tally.none() && after.tally.met(after.now);
        if (args.json()) {
            print_json({{"approved", true},
                        {"statement_id", id_json(id)},
                        {"approver", actor_ref(session, me.id)},
                        {"file", out.string()},
                        {"complete", complete},
                        {"rules", tally_json(session, after.tally)}});
            return exit_ok;
        }
        std::println("approved statement {} as \"{}\", into {}", hex_id(id), me.display_name,
                     out.string());
        if (complete) {
            std::println("every rule is met: register it with kanhe approval submit {}",
                         out.string());
        } else {
            std::println("still needed: {}", missing_text(session, after.tally));
        }
        return exit_ok;
    }
    const client::GivenApproval given = client::give_held(session, id, approval);
    if (args.json()) {
        print_json({{"approved", true},
                    {"statement_id", id_json(id)},
                    {"approver", actor_ref(session, me.id)},
                    {"registered", given.registered.has_value()},
                    {"index", given.registered ? Json(*given.registered) : Json(nullptr)},
                    {"held", ordered(given.held)}});
        return exit_ok;
    }
    if (given.registered) {
        std::println("approved statement {} as \"{}\": every rule is met, registered at entry #{}",
                     hex_id(id), me.display_name, *given.registered);
    } else {
        std::string needs;
        for (const nlohmann::json& rule : given.held.value("rules", nlohmann::json::array())) {
            if (rule.value("missing", std::uint64_t{0}) > 0) {
                needs += (needs.empty() ? "" : "; ") +
                         std::format("{} more of {}", rule.value("missing", std::uint64_t{0}),
                                     rule.value("k", std::uint64_t{0}));
            }
        }
        std::println("approved statement {} as \"{}\"; still needed: {}", hex_id(id),
                     me.display_name, needs.empty() ? "nothing (registering it)" : needs);
    }
    return exit_ok;
}

int cmd_approval_submit(const Args& args) {
    Session session(args);
    std::vector<protocol::ApprovalFile> files;
    for (const std::string& path : args.positional()) {
        files.push_back(client::read_approval_file(session, path));
    }
    const protocol::ApprovalFile combined = client::combine_approval_files(std::move(files));
    const client::ApprovalReview review = client::review_approval(session, combined, false);
    const protocol::Id id = combined.statement.id;
    if (review.registered) {
        return report_submitted(args, session, id, {{"approvals", nullptr}},
                                std::format("statement {} is registered already, at entry #{}",
                                            hex_id(id), *review.registered));
    }
    if (review.lapsed) {
        throw CommandError{"the statement lapsed: its window has ended, and it can no longer be "
                           "registered"};
    }
    if (review.refused) {
        throw CommandError{"the ledger would refuse the statement now: " + *review.refused};
    }
    // One approval that would not count refuses the statement: left out.
    protocol::ApprovalFile kept = combined;
    kept.approvals.clear();
    for (std::size_t i = 0; i < combined.approvals.size(); ++i) {
        if (review.problems[i] || review.tally.none()) {
            std::println(stderr, "leaving out the approval of \"{}\": {}",
                         session.actor_name(combined.approvals[i].approval.approver),
                         review.problems[i].value_or("no rule asks for it"));
        } else {
            kept.approvals.push_back(combined.approvals[i]);
        }
    }
    if (!review.tally.met(review.now)) {
        throw CommandError{"not every rule is met yet: " + missing_text(session, review.tally)};
    }
    const protocol::Id registered = client::submit_approved(session, kept);
    return report_submitted(
        args, session, registered, {{"approvals", kept.approvals.size()}},
        std::format("registered statement {} at entry #{} with {} approval{}", hex_id(registered),
                    session.state().statement_index(registered).value_or(0), kept.approvals.size(),
                    kept.approvals.size() == 1 ? "" : "s"));
}

int cmd_approval_withdraw(const Args& args) {
    Session session(args);
    const protocol::Id id = client::held_id(session, args.positional().front());
    client::withdraw_held(session, id);
    if (args.json()) {
        print_json({{"withdrawn", id_json(id)}});
    } else {
        std::println("withdrew statement {}: it is held for approval no more (copies held "
                     "elsewhere stay registrable until its window ends)",
                     hex_id(id));
    }
    return exit_ok;
}

// ---------------------------------------------------------------------------
// Guardians
// ---------------------------------------------------------------------------

int cmd_ledger_guardians_set(const Args& args) {
    Session session(args);
    session.always_for_approval();
    protocol::ApprovalRule rule;
    rule.needed = parse_number(args.positional().front(), "K");
    if (rule.needed < 1 || rule.needed > protocol::max_rule_approvers) {
        throw UsageError{"K is 1 to 16"};
    }
    for (const std::string& name : args.all("guardian")) {
        const protocol::Id id = session.actor_id(name);
        const protocol::ActorState& a = *session.state().actor(id);
        if (a.is_organization()) {
            throw UsageError{"the organization is never its own guardian"};
        }
        if (a.revoked) {
            throw CommandError{"\"" + a.display_name + "\" has been revoked"};
        }
        if (a.kind != protocol::ActorKind::person) {
            throw UsageError{"guardians are people, and \"" + a.display_name +
                             "\" is not a person"};
        }
        if (a.presence.empty()) {
            throw CommandError{"\"" + a.display_name +
                               "\" has no passkey or hardware key registered, and a guardian "
                               "approves in person (kanhe presence enroll, then kanhe actor "
                               "set-presence)"};
        }
        if (!std::ranges::contains(rule.approvers, id)) {
            rule.approvers.push_back(id);
        }
    }
    std::ranges::sort(rule.approvers, [](const protocol::Id& a, const protocol::Id& b) {
        return std::ranges::lexicographical_compare(a.bytes(), b.bytes());
    });
    if (rule.approvers.size() > protocol::max_rule_approvers) {
        throw UsageError{"at most 16 guardians"};
    }
    if (rule.needed > rule.approvers.size()) {
        throw UsageError{"K is at most the number of guardians"};
    }
    if (rule.needed == rule.approvers.size() && !args.has("no-spare")) {
        throw UsageError{std::format(
            "with K equal to the number of guardians ({}), one lost key or passkey locks the "
            "organization's guarded statements for good: name at least one guardian more than "
            "K, or give --no-spare",
            rule.approvers.size())};
    }
    rule.within = client::parse_window(args.get("within").value_or("7d"), "--within");
    protocol::LedgerSetGuardiansBody body{rule, std::nullopt};
    if (const std::vector<std::string> guards = args.all("guard"); !guards.empty()) {
        std::vector<protocol::StatementType> types;
        for (const std::string& name : guards) {
            const protocol::StatementType type = parse_statement_type(name);
            if (type == protocol::StatementType::genesis) {
                throw UsageError{"guardians never guard a genesis"};
            }
            if (!std::ranges::contains(types, type)) {
                types.push_back(type);
            }
        }
        std::ranges::sort(types);
        body.guarded = std::move(types);
    }
    const auto signer = root_signer(args, session);
    const protocol::Id id = session.submit(*signer, body, std::nullopt, std::nullopt, std::nullopt);
    return report_submitted(args, session, id, Json::object(), "set the guardians: " + hex_id(id));
}

int cmd_ledger_guardians_show(const Args& args) {
    Session session(args);
    const protocol::LedgerState& state = session.state();
    const protocol::GuardianSetting* in_effect = state.guardians();
    auto guardians_json = [&](const protocol::ApprovalRule& rule) {
        Json list = Json::array();
        for (const protocol::Id& id : rule.approvers) {
            list.push_back(actor_ref(session, id));
        }
        return list;
    };
    auto guards_json = [](const std::optional<std::vector<protocol::StatementType>>& guarded) {
        if (!guarded) {
            return Json(nullptr);
        }
        Json list = Json::array();
        for (const protocol::StatementType t : *guarded) {
            list.push_back(protocol::name(t));
        }
        return list;
    };
    if (args.json()) {
        Json settings = Json::array();
        for (const protocol::GuardianSetting& g : state.guardian_settings()) {
            settings.push_back(
                {{"index", g.index},
                 {"removed", !g.guardians.has_value()},
                 {"k", g.guardians ? Json(g.guardians->needed) : Json(nullptr)},
                 {"within_ms", g.guardians ? Json(g.guardians->within) : Json(nullptr)},
                 {"guardians", g.guardians ? guardians_json(*g.guardians) : Json::array()},
                 {"guards", guards_json(g.guarded)}});
        }
        Json effect = Json(nullptr);
        if (in_effect != nullptr) {
            effect = {{"k", in_effect->guardians->needed},
                      {"of", in_effect->guardians->approvers.size()},
                      {"within_ms", in_effect->guardians->within},
                      {"guardians", guardians_json(*in_effect->guardians)},
                      {"guards", guards_json(in_effect->guarded)},
                      {"index", in_effect->index}};
        }
        print_json({{"in_effect", std::move(effect)}, {"settings", std::move(settings)}});
        return exit_ok;
    }
    if (in_effect == nullptr) {
        std::println("guardians:     none: the organization's root key alone signs its "
                     "statements");
    } else {
        std::println("guardians:     {} (since entry #{})",
                     client::rule_text(session, *in_effect->guardians), in_effect->index);
        std::println("they guard:    {}", guarded_text(in_effect->guarded));
    }
    for (const protocol::GuardianSetting& g : state.guardian_settings()) {
        std::println("  #{:<6} {}", g.index,
                     g.guardians ? "set " + client::rule_text(session, *g.guardians)
                                 : std::string("removed them"));
    }
    return exit_ok;
}

int cmd_ledger_guardians_remove(const Args& args) {
    Session session(args);
    session.always_for_approval();
    if (session.state().guardians() == nullptr) {
        throw UsageError{"no guardians are in effect"};
    }
    const auto signer = root_signer(args, session);
    const protocol::Id id =
        session.submit(*signer, protocol::LedgerSetGuardiansBody{std::nullopt, std::nullopt},
                       std::nullopt, std::nullopt, std::nullopt);
    return report_submitted(args, session, id, Json::object(),
                            "removed the guardians: " + hex_id(id));
}

} // namespace kanhe::cli
