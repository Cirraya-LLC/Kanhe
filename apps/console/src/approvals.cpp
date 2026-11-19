// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// Approvals (spec v0.20): someone else's agreement to a statement. A
// statement whose approval rules need more than its signer is held at the
// node until enough of the people its rules name approve it, each on their
// own device. The console lists what waits for the signed-in person, gives
// the page the statement's signed bytes so that it recomputes the
// statement's id and checks what the console says of it, and signs the
// person's approval with their sealed key after their passkey's tap,
// user-verified, over the approval's own challenge. A decline is only a hint
// for the preparer: nothing goes on the ledger. Contracts' proposals that
// wait for approvals are listed too; approving one is the person's own call
// of `approve`, confirmed as any call. The organization's guardians are set
// here by an owner, signed by the organization, and approved by them.

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <limits>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

#include <nlohmann/json.hpp>

#include <kanhe/client/long_term.hpp>
#include <kanhe/client/records.hpp>
#include <kanhe/client/support.hpp>
#include <kanhe/console/console.hpp>
#include <kanhe/console/people.hpp>
#include <kanhe/console/setup.hpp>
#include <kanhe/core/bytes.hpp>
#include <kanhe/core/cbor.hpp>
#include <kanhe/core/protocol/approvals.hpp>
#include <kanhe/core/protocol/common.hpp>
#include <kanhe/core/protocol/presence.hpp>
#include <kanhe/core/protocol/record.hpp>
#include <kanhe/core/protocol/state.hpp>
#include <kanhe/core/protocol/statement.hpp>
#include <kanhe/node/approvals.hpp>
#include <kanhe/node/contracts.hpp>
#include <kanhe/node/long_term.hpp>

#include "responses.hpp"
#include "summaries.hpp"

namespace kanhe::console {

namespace {

constexpr std::string_view approvals_prefix = "/console/api/approvals/";
constexpr std::size_t max_prepared_approvals = 256;
/// Tools refuse to approve a statement issued further ahead of their clock
/// (spec section 5.1): nobody approves a post-dated one unawares.
constexpr protocol::Timestamp max_ahead = 5 * 60'000;

std::string hex_of(const protocol::Id& id) {
    return to_hex(id.bytes());
}

std::optional<protocol::Id> id_of(std::string_view hex) {
    if (hex.size() != 64) {
        return std::nullopt;
    }
    const auto bytes = from_hex(hex);
    if (!bytes) {
        return std::nullopt;
    }
    auto id = protocol::to_id(*bytes);
    return id ? std::optional(*id) : std::nullopt;
}

std::string text_of(const nlohmann::json& body, std::string_view key) {
    const auto it = body.find(key);
    return it != body.end() && it->is_string() ? it->get<std::string>() : std::string();
}

/// An origin in its canonical form (lower case, no default port), or empty.
std::string canonical_origin(std::string_view origin) {
    const auto parsed = parse_origin(origin);
    return parsed ? parsed->text() : std::string();
}

nlohmann::json actor_json(const protocol::LedgerState& state, const protocol::Id& id) {
    const protocol::ActorState* a = state.actor(id);
    return {{"id", hex_of(id)},
            {"name", a != nullptr ? nlohmann::json(a->display_name) : nlohmann::json()},
            {"kind", a != nullptr && a->kind ? nlohmann::json(static_cast<int>(*a->kind))
                                             : nlohmann::json()}};
}

/// `start` plus `within`, at most 2^64 - 1.
protocol::Timestamp until(protocol::Timestamp start, protocol::Timestamp within) {
    return start > std::numeric_limits<protocol::Timestamp>::max() - within
               ? std::numeric_limits<protocol::Timestamp>::max()
               : start + within;
}

/// A path under /console/api/approvals/: the statement's id, and what
/// follows it ("", "prepare", "approve", "decline").
struct Target {
    protocol::Id id;
    std::string rest;
};

std::optional<Target> target_of(std::string_view path) {
    if (!path.starts_with(approvals_prefix)) {
        return std::nullopt;
    }
    path.remove_prefix(approvals_prefix.size());
    const std::size_t slash = path.find('/');
    const auto id = id_of(path.substr(0, slash));
    if (!id) {
        return std::nullopt;
    }
    return Target{*id, slash == std::string_view::npos ? std::string()
                                                       : std::string(path.substr(slash + 1))};
}

/// The fields shown with a held registration as the page's WebAssembly
/// reads them: a CBOR array of the encoded fields.
std::optional<Bytes> encoded_fields(const std::vector<protocol::RecordField>& fields) {
    if (fields.empty()) {
        return std::nullopt;
    }
    cbor::Array list;
    for (const protocol::RecordField& f : fields) {
        auto leaf = protocol::encode_field(f);
        if (!leaf) {
            return std::nullopt;
        }
        list.push_back(cbor::Value::bytes(std::move(*leaf)));
    }
    auto encoded = cbor::encode(cbor::Value::array(std::move(list)));
    return encoded ? std::optional(std::move(*encoded)) : std::nullopt;
}

/// The approver of each approval a held statement keeps.
std::vector<protocol::Id> kept_approvers(const node::HeldStatement& held) {
    std::vector<protocol::Id> out;
    for (const node::KeptApproval& k : held.approvals) {
        if (auto parsed = protocol::parse_approval(k.encoded)) {
            out.push_back(parsed->approval.approver);
        }
    }
    return out;
}

/// `approve`'s arguments for a proposal (Bo): {"function": NAME,
/// "arguments": ARGS}, matching the first proposal kept with them.
cbor::Value approve_arguments(const std::string& function, const cbor::Value& arguments) {
    cbor::Map entries;
    entries.push_back({cbor::Value::text("function"), cbor::Value::text(function)});
    entries.push_back({cbor::Value::text("arguments"), arguments});
    return cbor::Value::map(std::move(entries));
}

/// What the organization signs, and so waits for its guardians when they
/// guard everything: the console's steps that the organization's root key
/// signs (machines and AI agents, credentials, the machine's certificates
/// and answers), a lost passkey's recovery, and the ledger's new keys for the
/// long term (which they guard whatever they guard).
const std::vector<std::string>& organization_work() {
    static const std::vector<std::string> work{"machines", "credentials", "certificates",
                                               "answers",  "recovery",    "long-term"};
    return work;
}

} // namespace

bool Console::approvals_write_path(const http::Request& request) {
    if (!request.path.starts_with(approvals_prefix)) {
        return false;
    }
    if (request.method == "DELETE") {
        return true;
    }
    return request.method == "POST" &&
           (request.path.ends_with("/approve") || request.path.ends_with("/decline"));
}

nlohmann::json Console::approvals_needed(const protocol::LedgerState& state,
                                         const protocol::Statement& statement,
                                         bool signer_verified) {
    const auto rules = state.approval_rules(statement);
    nlohmann::json list = nlohmann::json::array();
    bool needed = false;
    protocol::Timestamp lapses = std::numeric_limits<protocol::Timestamp>::max();
    for (const protocol::AppliedRule& applied : rules) {
        const protocol::ApprovalRule& rule = applied.rule;
        // The signer counts where the rule names it, in person (or by its
        // signature alone where presence is not needed).
        const bool counts = statement.actor_id &&
                            std::ranges::contains(rule.approvers, *statement.actor_id) &&
                            (signer_verified || rule.without_presence);
        const std::uint64_t missing = rule.needed - (counts && rule.needed > 0 ? 1U : 0U);
        needed = needed || missing > 0;
        lapses = std::min(lapses, until(statement.issued_at, rule.within));
        nlohmann::json approvers = nlohmann::json::array();
        for (const protocol::Id& a : rule.approvers) {
            approvers.push_back(actor_json(state, a));
        }
        list.push_back(
            {{"source", std::string(protocol::name(applied.source))},
             {"delegation",
              applied.delegation ? nlohmann::json(hex_of(*applied.delegation)) : nlohmann::json()},
             {"k", rule.needed},
             {"approvers", std::move(approvers)},
             {"within", rule.within},
             {"without_presence", rule.without_presence},
             {"signer_counts", counts},
             {"missing", missing}});
    }
    return {{"needed", needed},
            {"rules", std::move(list)},
            {"lapses_at", rules.empty() ? protocol::Timestamp{0} : lapses}};
}

nlohmann::json Console::proposals_json(const protocol::LedgerState& state,
                                       const std::optional<protocol::Id>& actor,
                                       const std::optional<protocol::Id>& instance,
                                       const std::string& language) const {
    nlohmann::json out = nlohmann::json::array();
    const protocol::ActorState* me = actor ? state.actor(*actor) : nullptr;
    const protocol::Timestamp now = services_.clock->now();
    // [ACTOR, KIND, PRESENCE], as a contract keeps who proposed and who
    // approved (bo.md 12.5).
    auto who = [&](const cbor::Value& value) {
        const cbor::Array* parts = value.as_array();
        if (parts == nullptr || parts->size() != 3 || (*parts)[0].as_bytes() == nullptr) {
            return nlohmann::json();
        }
        const auto id = protocol::to_id(*(*parts)[0].as_bytes());
        if (!id) {
            return nlohmann::json();
        }
        nlohmann::json j = actor_json(state, *id);
        j["in_person"] = (*parts)[2].as_bool().value_or(false);
        return j;
    };
    for (const auto& [key, i] : state.instances()) {
        const protocol::Id thing(i.id);
        if ((instance && thing != *instance) || i.final) {
            continue;
        }
        const protocol::ContractState* c = state.contract(protocol::Id(i.contract));
        if (c == nullptr || c->language != "bo" || !c->interface.contains("approve")) {
            continue;
        }
        const cbor::Value value = i.state.value();
        const cbor::Value* pending = value.find("pending");
        const cbor::Array* list = pending != nullptr ? pending->as_array() : nullptr;
        if (list == nullptr) {
            continue;
        }
        for (std::size_t n = 0; n < list->size(); ++n) {
            // A contract with requirements of approvals keeps five parts,
            // [FUNCTION, ARGS, AT, BY, APPROVALS]; one whose AI agents only
            // propose, two, [FUNCTION, ARGS] (bo.md 12.5).
            const cbor::Array* p = (*list)[n].as_array();
            if (p == nullptr || (p->size() != 5 && p->size() != 2) ||
                (*p)[0].as_text() == nullptr) {
                continue;
            }
            const bool full = p->size() == 5;
            const std::string function = *(*p)[0].as_text();
            const cbor::Value& arguments = (*p)[1];
            const auto encoded = cbor::encode(arguments);
            if (!encoded) {
                continue;
            }
            nlohmann::json approvals = nlohmann::json::array();
            if (const cbor::Array* given = full ? (*p)[4].as_array() : nullptr) {
                for (const cbor::Value& g : *given) {
                    approvals.push_back(who(g));
                }
            }
            nlohmann::json item{
                {"instance", hex_of(thing)},
                {"contract", hex_of(protocol::Id(i.contract))},
                {"contract_name", c->name ? nlohmann::json(*c->name) : nlohmann::json()},
                {"position", n},
                {"function", function},
                {"arguments", cbor::diagnostic(arguments)},
                {"arguments_cbor", to_hex(*encoded)},
                {"proposed_at",
                 full ? nlohmann::json((*p)[2].as_uint64().value_or(0)) : nlohmann::json()},
                {"by", full ? who((*p)[3]) : nlohmann::json()},
                {"approvals", std::move(approvals)},
                {"may_approve", false},
                {"completes", false}};
            if (me != nullptr && !me->revoked) {
                // The person's own `approve`, run as the ledger will run it.
                protocol::ContractCallBody call;
                call.instance = thing;
                call.head = i.head;
                call.function = "approve";
                call.arguments = approve_arguments(function, arguments);
                protocol::Statement s;
                s.ledger_id = state.ledger_id();
                s.actor_id = *actor;
                s.issued_at = now;
                s.delegation_id =
                    node::choose_delegation(state, *actor, protocol::StatementType::contract_call,
                                            std::nullopt, now, protocol::Id(i.contract), &call);
                s.body = std::move(call);
                if (!s.delegation_id) {
                    item["reason"] = "no delegation lets you act on these rules";
                } else {
                    const nlohmann::json run = dry_run(state, s, *me, language);
                    if (run.value("verdict", "") == "accept") {
                        item["may_approve"] = true;
                        const auto events = run.find("events");
                        item["completes"] =
                            events != run.end() && events->is_array() &&
                            std::ranges::contains(*events, nlohmann::json("approve"));
                    } else {
                        item["reason"] = run.value("reason", std::string());
                        if (run.contains("code")) {
                            item["code"] = run["code"];
                        }
                    }
                }
            }
            out.push_back(std::move(item));
        }
    }
    return out;
}

void Console::keep_follow_up(const std::string& statement, nlohmann::json what) const {
    if (!id_of(statement) || !what.is_object()) {
        return;
    }
    const std::filesystem::path dir = services_.directory / "follow-ups";
    try {
        std::filesystem::create_directories(dir);
        const std::string text = what.dump();
        client::write_file(dir / (statement + ".json"), as_bytes(text), true);
    } catch (const std::exception&) {
        // Done by hand then, as without a console.
    }
}

void Console::follow_up() const {
    const ledger::Ledger* const served = ledger();
    if (served == nullptr) {
        return;
    }
    const std::unique_lock running(follow_mutex_, std::try_to_lock);
    if (!running) {
        return;
    }
    // A key the ledger rotated to takes its key's own name.
    settle_long_term_keys();
    const std::filesystem::path dir = services_.directory / "follow-ups";
    const std::filesystem::path ledger_dir = services_.directory.parent_path();
    const protocol::Timestamp now = services_.clock->now();
    std::error_code ec;
    std::vector<std::filesystem::path> files;
    for (const auto& entry : std::filesystem::directory_iterator(dir, ec)) {
        if (entry.path().extension() == ".json") {
            files.push_back(entry.path());
        }
    }
    std::ranges::sort(files);
    for (const std::filesystem::path& path : files) {
        const auto id = id_of(path.stem().string());
        nlohmann::json what;
        try {
            const Bytes bytes = client::read_file(path);
            what = nlohmann::json::parse(bytes.begin(), bytes.end(), nullptr, false);
        } catch (const std::exception&) {
            what = nlohmann::json();
        }
        if (!id || !what.is_object()) {
            std::filesystem::remove(path, ec);
            continue;
        }
        if (served->statement_index(*id)) {
            // Once, whatever comes of it.
            std::filesystem::remove(path, ec);
            run_follow_up(*id, what);
            continue;
        }
        // Held no more, and not registered (lapsed, withdrawn, dropped), or
        // past its time: nothing follows it.
        const auto until = what.find("until");
        const bool late = until == what.end() || !until->is_number_unsigned() ||
                          now > until->get<protocol::Timestamp>();
        const auto done = node::held_statement(ledger_dir, *id, true);
        if (late || (done && done->state != node::HeldState::registered)) {
            std::filesystem::remove(path, ec);
            const std::lock_guard lock(mutex_);
            recovery_prf_.erase(path.stem().string());
        }
    }
}

void Console::run_follow_up(const protocol::Id& statement, const nlohmann::json& what) const {
    const std::string hex = hex_of(statement);
    const std::string by = text_of(what, "by");
    // Each part on its own: one that fails leaves the others, and is done by
    // hand (console user link, the record's page, Automation).
    if (const auto link = what.find("link"); link != what.end() && link->is_object()) {
        const std::string person = text_of(*link, "user");
        const std::string key = text_of(*link, "key");
        try {
            change_people([&](People& users) {
                if (User* u = users.find(person); u != nullptr && u->actor.empty()) {
                    u->actor = hex;
                    u->key = key;
                }
            });
        } catch (const std::exception&) {
            // Linked by hand then.
        }
    }
    if (const auto type = what.find("certificate"); type != what.end() && type->is_string()) {
        // A certificate's printed fields, from the record's private data.
        if (const ledger::Ledger* served = ledger()) {
            std::optional<client::Vault> vault;
            served->read_state([&](const protocol::LedgerState& state) {
                vault = private_data(state, statement);
            });
            if (vault) {
                publish_certificate(statement, type->get<std::string>(), vault->fields);
            }
        }
    }
    if (const auto recovery = what.find("recovery");
        recovery != what.end() && recovery->is_object()) {
        // A lost passkey's recovery, approved by the guardians: the new
        // passkey as the ledger registered it.
        std::string prf;
        {
            const std::lock_guard lock(mutex_);
            if (const auto it = recovery_prf_.find(hex); it != recovery_prf_.end()) {
                prf = std::move(it->second);
                recovery_prf_.erase(it);
            }
        }
        const ledger::Ledger* served = ledger();
        const auto index = served != nullptr ? served->statement_index(statement) : std::nullopt;
        const auto entry = index ? logged(*index) : std::nullopt;
        const auto* set =
            entry ? std::get_if<protocol::ActorSetPresenceBody>(&entry->statement.body) : nullptr;
        const People people = load_people(services_.directory);
        const User* owner = people.find(text_of(*recovery, "user"));
        if (set != nullptr && set->credentials.size() == 1 && owner != nullptr &&
            owner->actor == hex_of(set->actor)) {
            try {
                static_cast<void>(apply_recovery(owner->name, set->credentials.front(), prf));
            } catch (const std::exception&) {
                // The owner recovers again then.
            }
        }
    }
    if (const auto then = what.find("machine"); then != what.end() && then->is_object()) {
        continue_machine(by, statement, *then);
    }
    if (const auto lt = what.find("long_term"); lt != what.end() && lt->is_object()) {
        // A step of preparing the ledger for the long term: its key settled,
        // and the next step taken by itself if an owner sent it for approval.
        const auto go_on = lt->find("continue");
        try {
            continue_long_term(by, go_on != lt->end() && go_on->is_boolean() && go_on->get<bool>());
        } catch (const std::exception&) {
            // Taken from Settings then.
        }
    }
    if (const std::string activity = text_of(what, "activity"); !activity.empty()) {
        nlohmann::json detail = what.value("detail", nlohmann::json::object());
        if (!detail.is_object()) {
            detail = nlohmann::json::object();
        }
        detail["statement"] = hex;
        try {
            log_activity(by, activity, std::move(detail));
        } catch (const std::exception&) {
            // The ledger has it; the console's log does not.
        }
    }
}

void Console::continue_machine(const std::string& by, const protocol::Id& actor,
                               nlohmann::json intent) const {
    const ledger::Ledger* const served = ledger();
    const People people = load_people(services_.directory);
    const User* owner = people.find(by);
    // Only an owner grants a machine what it may do (the organization signs
    // it), and the owner's tap that sent the registration covered this step.
    if (served == nullptr || !submitter() || owner == nullptr || owner->role != Role::owner ||
        services_.keys == nullptr || !services_.keys->unlocked()) {
        return;
    }
    intent["action"] = "machine.delegate";
    intent["actor"] = hex_of(actor);
    auto step = machine_step(Signed{{}, {}, owner->name, Role::owner}, intent);
    auto* made_step = std::get_if<PersonStep>(&step);
    if (made_step == nullptr || !made_step->as_organization) {
        return;
    }
    protocol::Statement s;
    nlohmann::json needs;
    const protocol::Timestamp now = services_.clock->now();
    served->read_state([&](const protocol::LedgerState& state) {
        for (const auto& [key, candidate] : state.actors()) {
            if (candidate.is_organization() && !candidate.revoked) {
                s.actor_id = protocol::Id(candidate.id);
            }
        }
        s.ledger_id = state.ledger_id();
        s.issued_at = now;
        s.nonce = services_.entropy->bytes<16>();
        s.body = std::move(made_step->body);
        needs = approvals_needed(state, s, false);
    });
    Bytes signed_bytes;
    std::string id;
    try {
        const auto root = services_.keys->open(root_key_name);
        auto made = protocol::sign_statement(root, *services_.provider, served->hash(), s);
        if (!made) {
            return;
        }
        signed_bytes = std::move(made->encoded);
        id = hex_of(made->id);
    } catch (const std::exception&) {
        return;
    }
    const bool waits = needs.value("needed", false);
    const protocol::Timestamp lapses = waits ? needs["lapses_at"].get<protocol::Timestamp>() : 0;
    {
        // The machine's key waits for this step, set up from Automation.
        const std::lock_guard lock(mutex_);
        if (const auto it = handed_.find(hex_of(actor)); it != handed_.end()) {
            it->second.delegation = id;
            it->second.expires = std::max(it->second.expires, lapses);
        }
    }
    const nlohmann::json follow{{"by", by},
                                {"activity", "automation.delegate"},
                                {"detail", {{"user", made_step->person}, {"continued", true}}}};
    Signing signing{
        std::move(signed_bytes), false, {}, [this, follow](const protocol::Id& registered) {
            run_follow_up(registered, follow);
        }};
    if (waits) {
        node::HeldStatement held;
        held.statement = signing.body;
        auto request_body = node::encode_hold_request(held);
        if (!request_body) {
            return;
        }
        signing.hold = std::move(*request_body);
        signing.lapses_at = lapses;
        signing.follow = follow;
    }
    send_signed(std::move(signing), [](const http::Response&) {});
}

http::Response Console::approvals_route(const http::Request& request) const {
    auto signed_in = authenticate(request);
    if (auto* refused = std::get_if<http::Response>(&signed_in)) {
        return std::move(*refused);
    }
    const Signed& signer = std::get<Signed>(signed_in);
    const ledger::Ledger* const served = ledger();
    if (served == nullptr) {
        return error(503, "unavailable", "the console has no ledger yet");
    }
    follow_up();
    const People people = load_people(services_.directory);
    const User* user = people.find(signer.user);
    const auto actor = user != nullptr ? id_of(user->actor) : std::nullopt;
    const std::filesystem::path ledger_dir = services_.directory.parent_path();
    const protocol::Timestamp now = services_.clock->now();
    const auto asked = request.query.find("language");
    const std::string language = asked != request.query.end() && (asked->second == "zh-Hant-HK" ||
                                                                  asked->second == "zh-Hans-CN")
                                     ? asked->second
                                     : std::string("en");

    if (request.path == "/console/api/approvals") {
        if (request.method != "GET") {
            http::Response refused = error(405, "unsupported", "method not allowed");
            refused.headers.emplace_back("Allow", "GET");
            return refused;
        }
        const bool owner = signer.role == Role::owner;
        nlohmann::json waiting = nlohmann::json::array();
        nlohmann::json sent = nlohmann::json::array();
        nlohmann::json proposals = nlohmann::json::array();
        served->read_state([&](const protocol::LedgerState& state) {
            // Statements a rule names them for, which they have not approved.
            for (const auto& [id, held] : node::held_statements(ledger_dir)) {
                if (actor && node::may_approve(*services_.provider, state, held, *actor)) {
                    waiting.push_back(node::held_json(*services_.provider, state, id, held));
                }
            }
            // What they sent (an owner: the organization's too), and what
            // became of it in the last 30 days.
            auto theirs = [&](const node::HeldStatement& held) {
                const auto parsed =
                    protocol::parse_statement(*services_.provider, held.statement, state.hash());
                if (!parsed || !parsed->statement.actor_id) {
                    return false;
                }
                const protocol::Id& by = *parsed->statement.actor_id;
                if (actor && by == *actor) {
                    return true;
                }
                const protocol::ActorState* a = state.actor(by);
                return owner && a != nullptr && a->is_organization();
            };
            for (const bool done : {false, true}) {
                for (const auto& [id, held] : node::held_statements(ledger_dir, done)) {
                    if (done && held.ended_at < now && now - held.ended_at > node::held_history) {
                        continue;
                    }
                    if (theirs(held)) {
                        sent.push_back(node::held_json(*services_.provider, state, id, held));
                    }
                }
            }
            for (nlohmann::json& p : proposals_json(state, actor, std::nullopt, language)) {
                if (p.value("may_approve", false)) {
                    proposals.push_back(std::move(p));
                }
            }
        });
        return json(200, {{"time", now},
                          {"actor", actor ? nlohmann::json(hex_of(*actor)) : nlohmann::json()},
                          {"waiting", std::move(waiting)},
                          {"proposals", std::move(proposals)},
                          {"sent", std::move(sent)}});
    }

    const auto target = target_of(request.path);
    if (!target) {
        return error(400, "invalid_argument", "a held statement's id is 64 hex digits");
    }
    if (target->rest.empty()) {
        if (request.method != "GET") {
            http::Response refused = error(405, "unsupported", "method not allowed");
            refused.headers.emplace_back("Allow", "GET, DELETE");
            return refused;
        }
        auto held = node::held_statement(ledger_dir, target->id);
        if (!held) {
            held = node::held_statement(ledger_dir, target->id, true);
        }
        if (!held) {
            return error(404, "not_found", "no statement is held for approval with this id");
        }
        nlohmann::json view;
        nlohmann::json summary;
        std::string why_not;
        bool mine = false;
        served->read_state([&](const protocol::LedgerState& state) {
            view = node::held_json(*services_.provider, state, target->id, *held);
            const auto parsed =
                protocol::parse_statement(*services_.provider, held->statement, state.hash());
            if (!parsed) {
                why_not = "the statement does not parse";
                return;
            }
            const protocol::Statement& st = parsed->statement;
            summary = describe_statement(st, state);
            summary.update(provenance_summary(state, st));
            // A new post-quantum key of the ledger's: a step of preparing it
            // for the long term (spec v0.21).
            if (const auto which = client::long_term_rotation(st, state.ledger_id())) {
                const auto* log_key = std::get_if<protocol::LedgerRotateLogKeyBody>(&st.body);
                const auto* root_key = std::get_if<protocol::ActorRotateKeyBody>(&st.body);
                const auto* key = log_key != nullptr    ? &log_key->key
                                  : root_key != nullptr ? &root_key->key
                                                        : nullptr;
                if (key != nullptr && node::post_quantum_algorithm(key->algorithm)) {
                    summary["long_term"] = std::string(*which);
                }
            }
            if (const auto* g = std::get_if<protocol::RecordRegisterBody>(&st.body)) {
                // What the page shows of a registration: its terms or public
                // metadata, its files by name, and whether its fields are
                // shown (the page reads those from the bytes).
                summary.update(registration_terms(*g));
                nlohmann::json files = nlohmann::json::array();
                for (const protocol::Attachment& a : g->attachments) {
                    files.push_back(
                        {{"name", a.name}, {"media_type", a.media_type}, {"size", a.size}});
                }
                summary["files"] = std::move(files);
                summary["fields_shown"] = !held->fields.empty();
            } else if (const auto* call = std::get_if<protocol::ContractCallBody>(&st.body)) {
                // The consents a call cites, which the page counts in the bytes.
                summary["consents"] = call->consents.size();
            }
            const protocol::ActorState* by = st.actor_id ? state.actor(*st.actor_id) : nullptr;
            mine = actor && st.actor_id && *st.actor_id == *actor;
            if (by != nullptr && by->is_organization()) {
                summary["by_organization"] = true;
            }
            if (held->state != node::HeldState::open) {
                why_not = "it is held no more: " + std::string(node::name(held->state));
            } else if (!actor) {
                why_not = "this user acts as no one on the ledger yet";
            } else if (mine) {
                why_not = "you signed it: you count through it, not by approving it";
            } else if (std::ranges::contains(kept_approvers(*held), *actor)) {
                why_not = "you approved it already";
            } else if (!node::may_approve(*services_.provider, state, *held, *actor)) {
                why_not = "no approval rule of it names you";
            }
        });
        const auto fields = encoded_fields(held->fields);
        const bool may = why_not.empty() && signer.role != Role::viewer;
        if (why_not.empty() && signer.role == Role::viewer) {
            why_not = "a viewer reads and verifies, and approves nothing";
        }
        return json(200,
                    {{"held", std::move(view)},
                     {"statement", to_base64url(held->statement)},
                     {"fields", fields ? nlohmann::json(to_base64url(*fields)) : nlohmann::json()},
                     {"hash", crypto::cose_id(served->hash())},
                     {"summary", std::move(summary)},
                     {"approver", actor ? nlohmann::json(hex_of(*actor)) : nlohmann::json()},
                     {"may_approve", may},
                     {"why_not", why_not.empty() ? nlohmann::json() : nlohmann::json(why_not)},
                     {"may_withdraw",
                      held->state == node::HeldState::open && signer.role != Role::viewer &&
                          (mine || signer.role == Role::owner || signer.role == Role::admin)}});
    }
    if (target->rest != "prepare") {
        return error(404, "not_found", "no such console route");
    }
    if (request.method != "POST") {
        http::Response refused = error(405, "unsupported", "method not allowed");
        refused.headers.emplace_back("Allow", "POST");
        return refused;
    }
    if (signer.role == Role::viewer) {
        return error(403, "forbidden", "a viewer reads and verifies, and approves nothing");
    }
    if (user == nullptr || !actor || user->key.empty()) {
        return error(409, "conflict",
                     "this user acts as no one on the ledger yet (console user link)");
    }
    if (services_.keys == nullptr || !services_.keys->unlocked()) {
        return error(423, "locked", "the console is locked: unlock it first");
    }
    if (!approval_hooks().give) {
        return error(503, "unavailable", "this console cannot give approvals");
    }
    const std::string origin = std::string(request.header("origin").value_or(""));
    const auto parsed_origin = parse_origin(origin);
    if (!parsed_origin || parsed_origin->host.starts_with('[') ||
        parsed_origin->host.find_first_not_of("0123456789.") == std::string::npos) {
        return error(400, "invalid_argument",
                     "passkeys need the console's name, not an address: open it at its "
                     "localhost or public URL");
    }
    const auto held = node::held_statement(ledger_dir, target->id);
    if (!held) {
        return error(404, "not_found", "no statement is held for approval with this id");
    }
    PreparedApproval prepared;
    std::string problem;
    served->read_state([&](const protocol::LedgerState& state) {
        const protocol::ActorState* me = state.actor(*actor);
        if (me == nullptr || me->revoked) {
            problem = "this user's actor is not on the ledger, or is revoked";
            return;
        }
        if (!me->kind || *me->kind != protocol::ActorKind::person || me->presence.empty()) {
            problem = "approvals here are a person's, in person: register a passkey first";
            return;
        }
        const auto parsed =
            protocol::parse_statement(*services_.provider, held->statement, state.hash());
        if (!parsed) {
            problem = "the held statement does not parse";
            return;
        }
        const protocol::Statement& st = parsed->statement;
        if (st.actor_id && *st.actor_id == *actor) {
            problem = "you signed this statement: you count through it, not by approving it";
            return;
        }
        // As the ledger would take it now, whatever its approvals.
        if (auto taken = state.validate_held(*services_.provider, *parsed, now); !taken) {
            problem = "the ledger would refuse it now, whatever its approvals: " +
                      std::string(taken.error().detail);
            return;
        }
        if (st.issued_at > until(now, max_ahead)) {
            problem = "it claims to be issued more than 5 minutes ahead of this console's clock: "
                      "check the clocks before approving it";
            return;
        }
        bool named = false;
        bool lapsed = false;
        for (const protocol::AppliedRule& r : state.approval_rules(st)) {
            named = named || std::ranges::contains(r.rule.approvers, *actor);
            lapsed = lapsed || now > until(st.issued_at, r.rule.within);
        }
        if (!named) {
            problem = "no approval rule of this statement names " + me->display_name;
            return;
        }
        if (lapsed) {
            problem = "it lapsed: its time for approvals has ended";
            return;
        }
        if (std::ranges::contains(kept_approvers(*held), *actor)) {
            problem = "you approved it already";
            return;
        }
        prepared.approval =
            protocol::Approval{state.ledger_id(), *actor, parsed->id, now, std::nullopt};
        const auto kid = protocol::key_id(*services_.provider, state.hash(), me->key);
        const auto challenge = kid ? protocol::approval_challenge(*services_.provider, state.hash(),
                                                                  prepared.approval, *kid)
                                   : Result<Bytes>(std::unexpected(kid.error()));
        if (!kid || !challenge) {
            problem = "the approval could not be prepared";
            return;
        }
        prepared.kid = *kid;
        prepared.challenge = *challenge;
    });
    if (!problem.empty()) {
        return error(409, "conflict", problem);
    }
    const auto payload = protocol::encode_approval_payload(prepared.approval);
    if (!payload) {
        return error(500, "internal", "the approval could not be encoded");
    }
    prepared.user = signer.user;
    prepared.key = user->key;
    prepared.origin = parsed_origin->text();
    prepared.expires = now + approval_lifetime;
    nlohmann::json allowed = nlohmann::json::array();
    for (const auto& p : user->passkeys) {
        if (p.rp_id == parsed_origin->host) {
            allowed.push_back({{"type", "public-key"}, {"id", to_base64url(p.credential_id)}});
        }
    }
    const std::string challenge = to_base64url(prepared.challenge);
    const std::string kid = to_base64url(prepared.kid.bytes());
    const std::string approver = hex_of(prepared.approval.approver);
    std::string id;
    {
        const std::lock_guard lock(mutex_);
        std::erase_if(prepared_approvals_, [&](const auto& e) { return e.second.expires <= now; });
        if (prepared_approvals_.size() >= max_prepared_approvals) {
            return error(429, "unavailable", "too many approvals are waiting; try again soon");
        }
        id = to_hex(services_.entropy->bytes<8>());
        prepared_approvals_.emplace(id, std::move(prepared));
    }
    return json(200, {{"prepared", id},
                      {"payload", to_base64url(*payload)},
                      {"kid", kid},
                      {"hash", crypto::cose_id(served->hash())},
                      {"statement_id", hex_of(target->id)},
                      {"approver", approver},
                      {"public_key",
                       {{"challenge", challenge},
                        {"rpId", parsed_origin->host},
                        {"allowCredentials", allowed},
                        {"userVerification", "required"},
                        {"timeout", approval_lifetime}}}});
}

void Console::approvals_write(const http::Request& request,
                              std::function<void(http::Response)> respond) const {
    auto signed_in = authenticate(request);
    if (auto* refused = std::get_if<http::Response>(&signed_in)) {
        respond(std::move(*refused));
        return;
    }
    const Signed& signer = std::get<Signed>(signed_in);
    const ledger::Ledger* const served = ledger();
    if (served == nullptr) {
        respond(error(503, "unavailable", "the console has no ledger yet"));
        return;
    }
    const auto target = target_of(request.path);
    if (!target) {
        respond(error(400, "invalid_argument", "a held statement's id is 64 hex digits"));
        return;
    }
    if (signer.role == Role::viewer) {
        respond(error(403, "forbidden", "a viewer reads and verifies, and acts on nothing"));
        return;
    }
    const ApprovalHooks hooks = approval_hooks();
    const People people = load_people(services_.directory);
    const User* user = people.find(signer.user);
    const auto actor = user != nullptr ? id_of(user->actor) : std::nullopt;
    const std::filesystem::path ledger_dir = services_.directory.parent_path();
    const std::string statement_hex = hex_of(target->id);
    const std::string by = signer.user;

    if (request.method == "DELETE") {
        if (!target->rest.empty()) {
            respond(error(404, "not_found", "no such console route"));
            return;
        }
        const auto held = node::held_statement(ledger_dir, target->id);
        if (!held) {
            respond(error(404, "not_found", "no statement is held for approval with this id"));
            return;
        }
        bool mine = false;
        served->read_state([&](const protocol::LedgerState& state) {
            const auto parsed =
                protocol::parse_statement(*services_.provider, held->statement, state.hash());
            mine = parsed && actor && parsed->statement.actor_id == actor;
        });
        if (!mine && signer.role != Role::owner && signer.role != Role::admin) {
            respond(error(403, "forbidden",
                          "only its signer, an owner, or an admin withdraws a statement sent "
                          "for approval"));
            return;
        }
        if (!hooks.withdraw) {
            respond(error(503, "unavailable", "this console cannot withdraw it"));
            return;
        }
        hooks.withdraw(target->id, [this, by, statement_hex,
                                    respond = std::move(respond)](http::Response answer) {
            if (answer.status == 204) {
                log_activity(by, "approvals.withdraw", {{"statement", statement_hex}});
                respond(json(200, {{"withdrawn", statement_hex}}));
                return;
            }
            secure(answer);
            respond(std::move(answer));
        });
        return;
    }
    if (target->rest == "decline") {
        // A hint for whoever prepared it: nothing goes on the ledger.
        if (!actor) {
            respond(error(409, "conflict", "this user acts as no one on the ledger yet"));
            return;
        }
        if (!hooks.decline) {
            respond(error(503, "unavailable", "this console cannot pass a decline on"));
            return;
        }
        hooks.decline(target->id, *actor, [respond = std::move(respond)](http::Response answer) {
            secure(answer);
            respond(std::move(answer));
        });
        return;
    }
    if (target->rest != "approve") {
        respond(error(404, "not_found", "no such console route"));
        return;
    }
    const auto body =
        nlohmann::json::parse(request.body.begin(), request.body.end(), nullptr, false);
    if (!body.is_object()) {
        respond(error(400, "invalid_argument", "the request's body is not a JSON object"));
        return;
    }
    // Taken once: a second tap on the same approval finds nothing.
    std::optional<PreparedApproval> prepared;
    {
        const protocol::Timestamp now = services_.clock->now();
        const std::lock_guard lock(mutex_);
        const auto found = prepared_approvals_.find(text_of(body, "prepared"));
        if (found != prepared_approvals_.end() && found->second.user == signer.user) {
            if (found->second.expires > now) {
                prepared = std::move(found->second);
            }
            prepared_approvals_.erase(found);
        }
    }
    const std::string origin = canonical_origin(request.header("origin").value_or(""));
    if (!prepared || prepared->origin != origin || prepared->approval.statement != target->id) {
        respond(error(404, "not_found", "no approval of yours waits for this statement"));
        return;
    }
    protocol::PresenceProof proof;
    for (auto [key, into] : {std::pair{"credential_id", &proof.credential_id},
                             std::pair{"authenticator_data", &proof.authenticator_data},
                             std::pair{"client_data_json", &proof.client_data_json},
                             std::pair{"signature", &proof.signature}}) {
        auto bytes = from_base64url(text_of(body, key));
        if (!bytes || bytes->empty()) {
            respond(error(400, "invalid_argument",
                          "an approval needs credential_id, authenticator_data, "
                          "client_data_json, and signature (base64url)"));
            return;
        }
        *into = std::move(*bytes);
    }
    if (!hooks.give) {
        respond(error(503, "unavailable", "this console cannot give approvals"));
        return;
    }
    if (services_.keys == nullptr || !services_.keys->unlocked()) {
        respond(error(423, "locked", "the console is locked: unlock it first"));
        return;
    }
    const auto held = node::held_statement(ledger_dir, target->id);
    if (!held) {
        respond(error(404, "not_found", "no statement is held for approval with this id"));
        return;
    }
    protocol::Approval approval = prepared->approval;
    approval.presence = std::move(proof);
    const crypto::HashAlg hash = served->hash();
    std::optional<crypto::PublicKey> current_key;
    std::vector<protocol::PresenceCredential> credentials;
    std::optional<protocol::SignedStatement> statement;
    served->read_state([&](const protocol::LedgerState& state) {
        if (const protocol::ActorState* me = state.actor(approval.approver); me && !me->revoked) {
            current_key = me->key;
            credentials = me->presence;
        }
        if (auto parsed = protocol::parse_statement(*services_.provider, held->statement, hash)) {
            statement = std::move(*parsed);
        }
    });
    if (!current_key || !statement) {
        respond(error(409, "conflict", "this user's actor is not on the ledger, or is revoked"));
        return;
    }
    std::optional<protocol::SignedApproval> signed_approval;
    {
        // The person's key is opened for this one signature, then dropped.
        const auto key = services_.keys->open(prepared->key);
        if (key.public_key() != *current_key) {
            respond(error(409, "conflict", "the console's key is no longer this person's key"));
            return;
        }
        auto made = protocol::sign_approval(key, *services_.provider, hash, approval);
        if (!made) {
            respond(error(500, "internal", "signing the approval failed"));
            return;
        }
        signed_approval = std::move(*made);
    }
    // The tap checked as the ledger checks it: the person's passkey, from
    // this console's page, with the person verified.
    const auto check = protocol::verify_approval_presence(*services_.provider, hash,
                                                          *signed_approval, credentials);
    if (!check) {
        respond(error(403, "forbidden",
                      "the passkey did not approve it: " + std::string(check.error().detail)));
        return;
    }
    if (!check->user_verified || canonical_origin(check->origin) != prepared->origin) {
        respond(error(403, "forbidden",
                      "the passkey did not approve it on this console, with the person verified"));
        return;
    }
    // And as the ledger will count it.
    std::string problem;
    served->read_state([&](const protocol::LedgerState& state) {
        if (auto counted =
                state.check_approvals(*services_.provider, *statement,
                                      std::span(&*signed_approval, 1), services_.clock->now());
            !counted) {
            problem = "the approval would not count: " + std::string(counted.error().detail);
        }
    });
    if (!problem.empty()) {
        respond(error(409, "conflict", problem));
        return;
    }
    hooks.give(target->id, std::move(signed_approval->encoded),
               [this, by, statement_hex, respond = std::move(respond)](http::Response answer) {
                   if (answer.status >= 200 && answer.status < 300) {
                       log_activity(by, "approvals.give", {{"statement", statement_hex}});
                   }
                   if (answer.status == 201) {
                       // Registered with it: what follows it is done on the
                       // poller's thread (this is the ledger's writer's).
                       poll_now();
                   }
                   secure(answer);
                   respond(std::move(answer));
               });
}

std::variant<Console::PersonStep, http::Response>
Console::guardians_step(const Signed& who, const nlohmann::json& intent) const {
    if (who.role != Role::owner) {
        return error(403, "forbidden", "only an owner sets the organization's guardians");
    }
    const ledger::Ledger* const served = ledger();
    if (served == nullptr) {
        return error(503, "unavailable", "the console has no ledger to act on");
    }
    const std::string action = text_of(intent, "action");
    if (action == "guardians.remove") {
        bool any = false;
        served->read_state(
            [&](const protocol::LedgerState& state) { any = state.guardians() != nullptr; });
        if (!any) {
            return error(409, "conflict", "the organization has no guardians to remove");
        }
        PersonStep step{
            protocol::Body{protocol::LedgerSetGuardiansBody{std::nullopt, std::nullopt}}, nullptr,
            "", "guardians.remove"};
        step.as_organization = true;
        return step;
    }
    if (action != "guardians.set") {
        return error(400, "invalid_argument", "the console cannot prepare this action");
    }
    const auto k = intent.find("k");
    const auto named = intent.find("guardians");
    const auto days = intent.find("within_days");
    if (k == intent.end() || !k->is_number_unsigned() || named == intent.end() ||
        !named->is_array() || days == intent.end() || !days->is_number_unsigned()) {
        return error(400, "invalid_argument",
                     "say how many must approve (k), who the guardians are, and within how many "
                     "days");
    }
    protocol::ApprovalRule rule;
    rule.needed = k->get<std::uint64_t>();
    const std::uint64_t within_days = days->get<std::uint64_t>();
    if (within_days < 1 || within_days > 30) {
        return error(400, "invalid_argument", "guardians approve within 1 to 30 days");
    }
    rule.within = within_days * 86'400'000;
    for (const auto& g : *named) {
        const auto id = g.is_string() ? id_of(g.get<std::string>()) : std::nullopt;
        if (!id) {
            return error(400, "invalid_argument", "name each guardian by their actor's id (hex)");
        }
        rule.approvers.push_back(*id);
    }
    std::ranges::sort(rule.approvers, {}, [](const protocol::Id& id) { return hex_of(id); });
    rule.approvers.erase(std::ranges::unique(rule.approvers).begin(), rule.approvers.end());
    if (rule.needed < 1 || rule.needed > protocol::max_rule_approvers ||
        rule.approvers.size() > protocol::max_rule_approvers) {
        return error(400, "invalid_argument", "1 to 16 guardians, 1 to 16 of whom must approve");
    }
    if (rule.approvers.size() < rule.needed) {
        return error(400, "invalid_argument",
                     "name at least as many guardians as must approve, and better one more");
    }
    const auto spare = intent.find("no_spare");
    const bool no_spare = spare != intent.end() && spare->is_boolean() && spare->get<bool>();
    if (rule.approvers.size() == rule.needed && !no_spare) {
        return error(409, "conflict",
                     "with no guardian to spare, one lost passkey or key would stop the "
                     "organization's guarded statements for good: name one more guardian, or "
                     "say that you accept having none to spare");
    }
    // What they guard: everything the organization signs (recommended), or
    // these types; some are guarded whatever the list says.
    std::optional<std::vector<protocol::StatementType>> guarded;
    if (const auto types = intent.find("guarded"); types != intent.end() && !types->is_null()) {
        if (!types->is_array() || types->empty()) {
            return error(400, "invalid_argument",
                         "guarded is null (everything) or a list of statement types");
        }
        std::vector<protocol::StatementType> list;
        for (const auto& t : *types) {
            std::optional<protocol::StatementType> found;
            for (std::uint64_t n = 2; n <= 23 && t.is_string(); ++n) {
                const auto type = protocol::statement_type_from(n);
                if (type && protocol::name(*type) == t.get<std::string>()) {
                    found = type;
                }
            }
            if (!found) {
                return error(400, "invalid_argument",
                             "guarded lists statement types by name, never genesis");
            }
            list.push_back(*found);
        }
        std::ranges::sort(list);
        list.erase(std::ranges::unique(list).begin(), list.end());
        guarded = std::move(list);
    }
    std::string problem;
    served->read_state([&](const protocol::LedgerState& state) {
        for (const protocol::Id& g : rule.approvers) {
            const protocol::ActorState* a = state.actor(g);
            if (a == nullptr || a->revoked || !a->kind || *a->kind != protocol::ActorKind::person) {
                problem = "each guardian is a person of this ledger, not revoked: " +
                          (a != nullptr ? a->display_name : hex_of(g).substr(0, 12) + "...") +
                          " is not";
                return;
            }
        }
    });
    if (!problem.empty()) {
        return error(409, "conflict", problem);
    }
    PersonStep step{protocol::Body{protocol::LedgerSetGuardiansBody{std::move(rule), guarded}},
                    nullptr, "", "guardians.set"};
    step.as_organization = true;
    return step;
}

http::Response Console::guardians_route(const http::Request& request) const {
    auto signed_in = authenticate(request);
    if (auto* refused = std::get_if<http::Response>(&signed_in)) {
        return std::move(*refused);
    }
    const Signed& signer = std::get<Signed>(signed_in);
    if (request.method != "GET") {
        http::Response refused = error(405, "unsupported", "method not allowed");
        refused.headers.emplace_back("Allow", "GET");
        return refused;
    }
    const ledger::Ledger* const served = ledger();
    if (served == nullptr) {
        return error(503, "unavailable", "the console has no ledger yet");
    }
    const People people = load_people(services_.directory);
    const std::filesystem::path ledger_dir = services_.directory.parent_path();
    // The console user each person is, if any.
    auto user_of = [&](const protocol::Id& id) {
        for (const User& u : people.users) {
            if (u.actor == hex_of(id)) {
                return nlohmann::json(u.name);
            }
        }
        return nlohmann::json();
    };
    auto guarded_json = [](const std::optional<std::vector<protocol::StatementType>>& types) {
        if (!types) {
            return nlohmann::json();
        }
        nlohmann::json out = nlohmann::json::array();
        for (const protocol::StatementType t : *types) {
            out.push_back(std::string(protocol::name(t)));
        }
        return out;
    };
    nlohmann::json in_effect;
    nlohmann::json history = nlohmann::json::array();
    nlohmann::json candidates = nlohmann::json::array();
    nlohmann::json waiting = nlohmann::json::array();
    served->read_state([&](const protocol::LedgerState& state) {
        auto rule_view = [&](const protocol::ApprovalRule& rule) {
            nlohmann::json guardians = nlohmann::json::array();
            for (const protocol::Id& g : rule.approvers) {
                nlohmann::json one = actor_json(state, g);
                const protocol::ActorState* a = state.actor(g);
                one["passkeys"] = a != nullptr ? a->presence.size() : 0U;
                one["revoked"] = a == nullptr || a->revoked;
                one["user"] = user_of(g);
                guardians.push_back(std::move(one));
            }
            return nlohmann::json{
                {"k", rule.needed}, {"within", rule.within}, {"guardians", std::move(guardians)}};
        };
        if (const protocol::GuardianSetting* g = state.guardians(); g != nullptr && g->guardians) {
            in_effect = rule_view(*g->guardians);
            in_effect["since"] = g->index;
            in_effect["guarded"] = guarded_json(g->guarded);
        }
        for (const protocol::GuardianSetting& g : state.guardian_settings()) {
            history.push_back({{"index", g.index},
                               {"removed", !g.guardians},
                               {"rule", g.guardians ? rule_view(*g.guardians) : nlohmann::json()},
                               {"guarded", guarded_json(g.guarded)}});
        }
        for (const auto& [key, a] : state.actors()) {
            if (!a.revoked && a.kind && *a.kind == protocol::ActorKind::person) {
                const protocol::Id id(a.id);
                candidates.push_back({{"id", hex_of(id)},
                                      {"name", a.display_name},
                                      {"passkeys", a.presence.size()},
                                      {"user", user_of(id)}});
            }
        }
        // Guardian settings waiting for their approvals.
        for (const auto& [id, held] : node::held_statements(ledger_dir)) {
            const auto parsed =
                protocol::parse_statement(*services_.provider, held.statement, state.hash());
            if (parsed &&
                std::holds_alternative<protocol::LedgerSetGuardiansBody>(parsed->statement.body)) {
                waiting.push_back(node::held_json(*services_.provider, state, id, held));
            }
        }
    });
    nlohmann::json types = nlohmann::json::array();
    for (std::uint64_t n = 2; n <= 23; ++n) {
        if (const auto type = protocol::statement_type_from(n)) {
            types.push_back(std::string(protocol::name(*type)));
        }
    }
    return json(200, {{"in_effect", std::move(in_effect)},
                      {"history", std::move(history)},
                      {"people", std::move(candidates)},
                      {"waiting", std::move(waiting)},
                      {"types", std::move(types)},
                      {"organization_work", organization_work()},
                      {"may_change", signer.role == Role::owner}});
}

} // namespace kanhe::console
