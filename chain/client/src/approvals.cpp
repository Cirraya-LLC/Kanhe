// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include <algorithm>
#include <cctype>
#include <charconv>
#include <limits>
#include <utility>

#include <kanhe/client/approvals.hpp>
#include <kanhe/client/views.hpp>
#include <kanhe/core/protocol/presence.hpp>
#include <kanhe/node/approvals.hpp>
#include <kanhe/verifier/report.hpp>

namespace kanhe::client {

namespace {

constexpr protocol::Timestamp skew_ms = 300'000;

bool before(const protocol::Id& a, const protocol::Id& b) {
    return std::ranges::lexicographical_compare(a.bytes(), b.bytes());
}

/// A submission's parts as the session registers them.
struct Parts {
    std::optional<Bytes> sealed;
    std::vector<Bytes> consents;
    std::vector<node::SealedFile> files;
};

Parts parts_of(const std::optional<protocol::SubmissionParts>& parts) {
    Parts out;
    if (parts) {
        out.sealed = parts->vault;
        out.consents = parts->consents;
        for (const auto& [index, sealed] : parts->files) {
            out.files.push_back({index, sealed});
        }
    }
    return out;
}

bool signer_verified(const Session& session, const protocol::SignedStatement& s) {
    const protocol::ActorState* signer =
        s.statement.actor_id ? session.state().actor(*s.statement.actor_id) : nullptr;
    if (!s.statement.presence || signer == nullptr || signer->kind != protocol::ActorKind::person) {
        return false;
    }
    const auto check = protocol::verify_presence(session.provider(), session.state().hash(),
                                                 s.statement, s.kid, signer->presence);
    return check && check->user_verified;
}

/// The id of a held statement in a list answer, if it has one.
std::string listed_id(const nlohmann::json& item) {
    return item.is_object() && item.contains("id") && item["id"].is_string()
               ? item["id"].get<std::string>()
               : std::string();
}

} // namespace

std::string window_text(protocol::Timestamp ms) {
    struct Unit {
        protocol::Timestamp size;
        const char* name;
    };
    for (const Unit u : {Unit{86'400'000, "day"}, Unit{3'600'000, "hour"}, Unit{60'000, "minute"},
                         Unit{1000, "second"}}) {
        if (ms > 0 && ms % u.size == 0) {
            const protocol::Timestamp n = ms / u.size;
            return std::to_string(n) + " " + u.name + (n == 1 ? "" : "s");
        }
    }
    return std::to_string(ms) + " ms";
}

protocol::Timestamp parse_window(std::string_view text, std::string_view what) {
    const std::string usage =
        std::string(what) + " is 1 minute to 30 days, written like 7d, 12h, or 90m";
    if (text.size() < 2) {
        throw UsageError{usage};
    }
    protocol::Timestamp unit = 0;
    switch (text.back()) {
    case 'd':
        unit = 86'400'000;
        break;
    case 'h':
        unit = 3'600'000;
        break;
    case 'm':
        unit = 60'000;
        break;
    case 's':
        unit = 1000;
        break;
    default:
        throw UsageError{usage};
    }
    const std::string_view digits = text.substr(0, text.size() - 1);
    std::uint64_t n = 0;
    const auto [end, ec] = std::from_chars(digits.data(), digits.data() + digits.size(), n);
    if (ec != std::errc{} || end != digits.data() + digits.size() ||
        n > protocol::max_approval_window / unit) {
        throw UsageError{usage};
    }
    const protocol::Timestamp ms = n * unit;
    if (ms < protocol::min_approval_window || ms > protocol::max_approval_window) {
        throw UsageError{usage};
    }
    return ms;
}

std::string rule_text(const Session& session, const protocol::ApprovalRule& rule) {
    std::string names;
    for (const protocol::Id& id : rule.approvers) {
        names += (names.empty() ? "" : ", ") + session.actor_name(id);
    }
    return std::to_string(rule.needed) + " of " + names + " within " + window_text(rule.within) +
           (rule.without_presence ? ", approvals without presence counting" : "");
}

std::string rule_source_text(const protocol::AppliedRule& rule) {
    switch (rule.source) {
    case protocol::RuleSource::delegation:
        return rule.delegation ? "the delegation " + short_id(*rule.delegation)
                               : std::string("a delegation");
    case protocol::RuleSource::guardians:
        return "the guardians";
    case protocol::RuleSource::new_guardians:
        return "the new guardians";
    }
    return "a rule";
}

ApprovalReview review_approval(Session& session, protocol::ApprovalFile file, bool held) {
    const protocol::LedgerState& state = session.state();
    const protocol::SignedStatement& s = file.statement;
    if (!s.statement.ledger_id || *s.statement.ledger_id != state.ledger_id()) {
        throw ActionError{
            "this statement is for the ledger " +
            (s.statement.ledger_id ? hex_id(*s.statement.ledger_id) : std::string("(none)")) +
            ", not " + hex_id(state.ledger_id()) +
            ": use that ledger's directory "
            "or server"};
    }
    if (s.hash_alg != state.hash()) {
        throw ActionError{"this statement's id is computed with another hash than its ledger's"};
    }
    ApprovalReview out;
    out.held = held;
    out.now = session.now();
    out.registered = state.statement_index(s.id);
    const protocol::Statement& st = s.statement;
    out.future = st.issued_at > out.now && st.issued_at - out.now > skew_ms;
    if (!out.registered) {
        if (auto ok = state.validate_held(session.provider(), s, out.now); !ok) {
            out.refused = std::string(ok.error().detail);
        }
    }
    out.rules = state.approval_rules(st);
    std::vector<protocol::SignedApproval> good;
    for (const protocol::SignedApproval& a : file.approvals) {
        auto alone = state.check_approvals(session.provider(), s, std::span(&a, 1), out.now);
        if (!alone) {
            out.problems.emplace_back(std::string(alone.error().detail));
        } else if (alone->approvals.empty()) {
            out.problems.emplace_back(std::string("it counts for no rule"));
        } else {
            out.problems.emplace_back(std::nullopt);
            good.push_back(a);
        }
    }
    if (auto tally = state.check_approvals(session.provider(), s, good, out.now)) {
        out.tally = std::move(*tally);
    }
    out.lapsed = std::ranges::any_of(
        out.tally.rules, [&](const protocol::RuleTally& r) { return out.now > r.lapses_at; });
    out.signer_verified = signer_verified(session, s);
    out.file = std::move(file);
    return out;
}

nlohmann::json list_held(Session& session, const std::optional<protocol::Id>& approver, bool all,
                         std::uint64_t wait) {
    if (session.remote()) {
        std::string path = std::string("/v1/approvals?state=") + (all ? "all" : "open");
        if (approver) {
            path += "&approver=" + hex_id(*approver);
        }
        if (wait > 0) {
            path += "&wait=" + std::to_string(wait);
        }
        const Bytes body = session.request("GET", path);
        auto parsed = nlohmann::json::parse(body.begin(), body.end(), nullptr, false);
        if (!parsed.is_object() || !parsed.contains("approvals") ||
            !parsed["approvals"].is_array()) {
            throw ActionError{"the server's list of statements held for approval is malformed"};
        }
        return parsed;
    }
    if (wait > 0) {
        throw UsageError{"waiting is for a server: give --server"};
    }
    return node::held_list_json(session.provider(), session.state(), session.directory(), approver,
                                all, session.now());
}

protocol::Id held_id(Session& session, std::string_view text) {
    std::string lower(text);
    std::ranges::transform(lower, lower.begin(), [](unsigned char c) { return std::tolower(c); });
    if (lower.size() == 64) {
        const auto bytes = from_hex(lower);
        if (bytes) {
            if (auto id = protocol::to_id(*bytes)) {
                return *id;
            }
        }
        throw UsageError{"a statement id is 64 hex digits"};
    }
    if (lower.size() < 8) {
        throw UsageError{"give a held statement's id, or at least 8 of its first hex digits"};
    }
    const nlohmann::json list = list_held(session, std::nullopt, true, 0);
    std::optional<std::string> found;
    for (const nlohmann::json& item : list["approvals"]) {
        const std::string id = listed_id(item);
        if (id.starts_with(lower)) {
            if (found && *found != id) {
                throw UsageError{"ambiguous statement id " + std::string(text)};
            }
            found = id;
        }
    }
    if (!found) {
        throw ActionError{"no statement held for approval has the id " + std::string(text)};
    }
    return unwrap(protocol::to_id(unwrap(from_hex(*found), "a statement id")), "a statement id");
}

protocol::ApprovalFile fetch_held(Session& session, const protocol::Id& id) {
    Bytes bytes;
    if (session.remote()) {
        bytes = session.request("GET", "/v1/approvals/" + hex_id(id));
    } else {
        const auto held = node::held_statement(session.directory(), id);
        if (!held) {
            throw ActionError{"no statement is held for approval with the id " + hex_id(id)};
        }
        bytes = unwrap(node::held_approval_file(session.provider(), session.state().hash(), *held),
                       "the held statement");
    }
    auto file = unwrap(protocol::decode_approval_file(session.provider(), bytes),
                       "reading the held statement");
    if (file.statement.id != id) {
        throw ActionError{"the statement held under " + short_id(id) + " is another statement"};
    }
    return file;
}

protocol::ApprovalFile read_approval_file(const Session& session,
                                          const std::filesystem::path& path) {
    const Bytes bytes = read_file(path);
    return unwrap(protocol::decode_approval_file(session.provider(), bytes),
                  "reading the approval file " + path.string());
}

void write_approval_file(const protocol::ApprovalFile& file, const std::filesystem::path& path) {
    // Owner-only: it may hold a registration's fields in clear.
    write_file(path, unwrap(protocol::encode_approval_file(file), "writing the approval file"),
               true);
}

nlohmann::json review_json(Session& session, const ApprovalReview& review) {
    const protocol::SignedStatement& s = review.file.statement;
    node::HeldStatement held;
    held.statement = s.encoded;
    held.fields = review.file.fields;
    held.note = review.file.note;
    held.signer_verified = review.signer_verified;
    for (const protocol::RuleTally& r : review.tally.rules) {
        held.lapses_at = held.lapses_at == 0 ? r.lapses_at : std::min(held.lapses_at, r.lapses_at);
    }
    for (std::size_t i = 0; i < review.file.approvals.size(); ++i) {
        if (review.problems[i]) {
            continue;
        }
        const protocol::SignedApproval& a = review.file.approvals[i];
        node::KeptApproval kept{a.encoded, std::nullopt, false};
        const auto check = std::ranges::find(review.tally.approvals, a.approval.approver,
                                             &protocol::ApprovalCheck::approver);
        if (check != review.tally.approvals.end() && check->presence) {
            kept.presence = check->presence->method;
            kept.user_verified = check->presence->user_verified;
        }
        held.approvals.push_back(std::move(kept));
    }
    nlohmann::json out = node::held_json(session.provider(), session.state(), s.id, held);
    out["state"] = review.registered ? "registered" : "open";
    out["index"] = review.registered ? nlohmann::json(*review.registered) : nlohmann::json(nullptr);
    out["held"] = review.held;
    out["refused"] = review.refused ? nlohmann::json(*review.refused) : nlohmann::json(nullptr);
    out["issued_ahead"] = review.future;
    out["lapsed"] = review.lapsed;
    out["summary"] = statement_summary(session, s);
    out["checked_at"] = review.now;
    nlohmann::json problems = nlohmann::json::array();
    for (std::size_t i = 0; i < review.file.approvals.size(); ++i) {
        if (review.problems[i]) {
            const protocol::Id& approver = review.file.approvals[i].approval.approver;
            problems.push_back(
                {{"approver", {{"id", hex_id(approver)}, {"name", session.actor_name(approver)}}},
                 {"reason", *review.problems[i]}});
        }
    }
    out["not_counted"] = std::move(problems);
    nlohmann::json fields = nlohmann::json::array();
    for (const protocol::RecordField& f : review.file.fields) {
        fields.push_back({{"name", f.name}, {"value", verifier::display_value(f.value)}});
    }
    out["fields"] = std::move(fields);
    return out;
}

protocol::SignedApproval approve(Session& session, const crypto::Signer& signer,
                                 const ApprovalReview& review,
                                 const std::optional<PresenceRequest>& presence) {
    const protocol::ActorState& me = session.actor_for(signer);
    const protocol::SignedStatement& s = review.file.statement;
    if (review.registered) {
        throw ActionError{"this statement is registered already (entry #" +
                          std::to_string(*review.registered) + "): nothing is left to approve"};
    }
    if (review.refused) {
        throw ActionError{"the ledger would refuse this statement now, whatever its approvals: " +
                          *review.refused};
    }
    if (review.future) {
        throw ActionError{"this statement claims to be issued more than 5 minutes ahead of this "
                          "machine's clock: check the clocks before approving it"};
    }
    if (review.lapsed) {
        throw ActionError{"this statement lapsed: its window has ended, and it can no longer be "
                          "registered"};
    }
    if (s.statement.actor_id && *s.statement.actor_id == me.id) {
        throw ActionError{"you signed this statement: you count through it, not by approving it"};
    }
    const protocol::Id my_id = me.id;
    bool named = false;
    bool open = false;
    for (const protocol::AppliedRule& r : review.rules) {
        if (std::ranges::contains(r.rule.approvers, my_id)) {
            named = true;
            open = open || r.rule.without_presence;
        }
    }
    if (!named) {
        throw ActionError{"no approval rule of this statement names \"" + me.display_name + "\""};
    }
    // Held: one approval per approver (a file's is replaced instead).
    for (std::size_t i = 0; review.held && i < review.file.approvals.size(); ++i) {
        if (review.file.approvals[i].approval.approver == my_id && !review.problems[i]) {
            throw ActionError{"you approved this statement already"};
        }
    }
    if (!presence && !open) {
        throw UsageError{"approve in person: add --presence (a passkey) or --presence-key (a "
                         "hardware key)"};
    }
    const crypto::HashAlg hash = session.state().hash();
    protocol::Approval approval{session.state().ledger_id(), my_id, s.id, session.now(),
                                std::nullopt};
    if (presence) {
        const auto kid =
            unwrap(protocol::key_id(session.provider(), hash, signer.public_key()), "the key id");
        const Bytes challenge =
            unwrap(protocol::approval_challenge(session.provider(), hash, approval, kid),
                   "the approval's challenge");
        approval.presence = session.prove(
            me, signer.public_key(), challenge, *presence, "Approve as " + me.display_name,
            "On the ledger of \"" + session.state().organization() + "\", approve:\n" +
                statement_summary(session, s) + "\nstatement " + hex_id(s.id));
    }
    auto signed_approval =
        unwrap(protocol::sign_approval(signer, session.provider(), hash, approval),
               "signing the approval");
    // As the ledger will check it.
    if (auto alone = session.state().check_approvals(session.provider(), s,
                                                     std::span(&signed_approval, 1), session.now());
        !alone) {
        throw ActionError{"the approval would not count: " + std::string(alone.error().detail)};
    }
    return signed_approval;
}

GivenApproval give_held(Session& session, const protocol::Id& id,
                        const protocol::SignedApproval& approval) {
    GivenApproval out;
    if (session.remote()) {
        const Bytes body = session.request("POST", "/v1/approvals/" + hex_id(id), approval.encoded,
                                           "application/cose");
        auto answer = nlohmann::json::parse(body.begin(), body.end(), nullptr, false);
        if (!answer.is_object()) {
            throw ActionError{"the server's answer to the approval is malformed"};
        }
        if (answer.value("status", std::string()) == "waiting") {
            out.held = std::move(answer);
            return out;
        }
        if (!session.await_statement(id)) {
            throw ActionError{"the server registered the statement but does not show it"};
        }
        out.registered = session.state().statement_index(id);
        return out;
    }
    session.require_primary();
    const node::ApprovalDesk desk(session.directory());
    auto progress = unwrap(
        desk.approve(session.provider(), session.state(), id, approval.encoded, session.now()),
        "the approval");
    unwrap(node::apply_held_changes(session.directory(), progress.changes), "keeping the approval");
    if (progress.verdict != node::HeldProgress::Verdict::ready) {
        out.held = node::held_json(session.provider(), session.state(), id, progress.held);
        return out;
    }
    std::optional<protocol::SubmissionParts> parts;
    if (progress.held.parts) {
        parts = unwrap(protocol::decode_submission_parts(*progress.held.parts), "its parts");
    }
    const Parts p = parts_of(parts);
    const auto statement =
        unwrap(protocol::parse_statement(session.provider(), progress.held.statement,
                                         session.state().hash()),
               "the held statement");
    static_cast<void>(
        session.register_signed(statement, p.sealed, p.consents, p.files, progress.approvals));
    out.registered = session.state().statement_index(id);
    if (out.registered) {
        unwrap(node::apply_held_changes(session.directory(),
                                        desk.registered(id, *out.registered, session.now())),
               "noting the statement registered");
    }
    return out;
}

protocol::ApprovalFile combine_approval_files(std::vector<protocol::ApprovalFile> files) {
    if (files.empty()) {
        throw UsageError{"give at least one approval file"};
    }
    protocol::ApprovalFile out = std::move(files.front());
    for (std::size_t i = 1; i < files.size(); ++i) {
        protocol::ApprovalFile& f = files[i];
        if (f.statement.id != out.statement.id) {
            throw ActionError{"the approval files hold different statements (" +
                              short_id(out.statement.id) + " and " + short_id(f.statement.id) +
                              ")"};
        }
        if (f.parts) {
            if (out.parts && *out.parts != *f.parts) {
                throw ActionError{"the approval files carry different parts of the statement's "
                                  "submission"};
            }
            out.parts = std::move(f.parts);
        }
        if (!f.fields.empty()) {
            if (!out.fields.empty() && out.fields != f.fields) {
                throw ActionError{"the approval files show different fields"};
            }
            out.fields = std::move(f.fields);
        }
        if (!out.note) {
            out.note = std::move(f.note);
        }
        for (protocol::SignedApproval& a : f.approvals) {
            const auto same = std::ranges::find_if(out.approvals, [&](const auto& b) {
                return b.approval.approver == a.approval.approver;
            });
            if (same == out.approvals.end()) {
                if (out.approvals.size() >= protocol::max_approvals) {
                    throw ActionError{"the files hold more than 32 approvals together"};
                }
                out.approvals.push_back(std::move(a));
            } else if (a.approval.approved_at > same->approval.approved_at) {
                *same = std::move(a);
            }
        }
    }
    std::ranges::sort(out.approvals, [](const auto& a, const auto& b) {
        return before(a.approval.approver, b.approval.approver);
    });
    return out;
}

protocol::Id submit_approved(Session& session, const protocol::ApprovalFile& file) {
    const Parts p = parts_of(file.parts);
    std::vector<Bytes> approvals;
    for (const protocol::SignedApproval& a : file.approvals) {
        approvals.push_back(a.encoded);
    }
    return session.register_signed(file.statement, p.sealed, p.consents, p.files, approvals);
}

void withdraw_held(Session& session, const protocol::Id& id) {
    if (session.remote()) {
        static_cast<void>(session.request("DELETE", "/v1/approvals/" + hex_id(id)));
        return;
    }
    session.require_primary();
    const node::ApprovalDesk desk(session.directory());
    unwrap(node::apply_held_changes(session.directory(),
                                    unwrap(desk.withdraw(id, session.now()), "withdrawing it")),
           "withdrawing it");
}

} // namespace kanhe::client
