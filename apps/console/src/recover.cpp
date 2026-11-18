// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// A lost passkey, recovered with the recovery code: the code proves the
// owner (it opens the console's keys), a new passkey is made, and the root
// key replaces the owner's passkeys on the ledger with it. The lost ones
// stop signing in, stop proving presence, and stop unlocking the console,
// and the owner's other sessions end. While the organization's guardians
// guard it (spec v0.20), the statement is sent for their approval instead,
// and the console's side of it is done once they have approved it.

#include <algorithm>
#include <cctype>
#include <chrono>
#include <future>
#include <memory>
#include <optional>
#include <ranges>
#include <string>
#include <utility>
#include <variant>
#include <vector>

#include <nlohmann/json.hpp>

#include <kanhe/console/console.hpp>
#include <kanhe/console/setup.hpp>
#include <kanhe/core/bytes.hpp>
#include <kanhe/core/protocol/state.hpp>
#include <kanhe/ledger/storage.hpp>
#include <kanhe/node/approvals.hpp>

#include "responses.hpp"

namespace kanhe::console {

namespace {

std::string field(const nlohmann::json& body, std::string_view key) {
    const auto it = body.find(key);
    return it != body.end() && it->is_string() ? it->get<std::string>() : std::string();
}

std::optional<nlohmann::json> object_of(const http::Request& request) {
    auto body = nlohmann::json::parse(request.body.begin(), request.body.end(), nullptr, false);
    if (!body.is_object()) {
        return std::nullopt;
    }
    return std::optional<nlohmann::json>(std::in_place, std::move(body));
}

std::string lowered(std::string_view text) {
    std::string out(text);
    std::ranges::transform(out, out.begin(),
                           [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return out;
}

/// The owner a recovery is for: the one named, or the only one.
const User* owner_named(const People& people, std::string_view name) {
    if (!name.empty()) {
        const User* user = people.find(name);
        return user != nullptr && user->role == Role::owner ? user : nullptr;
    }
    const User* only = nullptr;
    for (const User& user : people.users) {
        if (user.role == Role::owner) {
            if (only != nullptr) {
                return nullptr;
            }
            only = &user;
        }
    }
    return only;
}

std::optional<protocol::Id> actor_of(const User& user) {
    const auto bytes = from_hex(user.actor);
    if (!bytes) {
        return std::nullopt;
    }
    const auto id = protocol::to_id(*bytes);
    return id ? std::optional(*id) : std::nullopt;
}

/// The organization's actor, if the state has it.
std::optional<protocol::Id> organization_of(const protocol::LedgerState& state) {
    for (const auto& [key, a] : state.actors()) {
        if (a.is_organization()) {
            return protocol::Id(a.id);
        }
    }
    return std::nullopt;
}

} // namespace

http::Response Console::recover_begin(const http::Request& request) const {
    const auto body = object_of(request);
    if (!body) {
        return error(400, "invalid_argument", "the request's body is not a JSON object");
    }
    const std::string origin = lowered(*request.header("origin"));
    const auto parsed = parse_origin(origin);
    if (!parsed || parsed->host.starts_with('[') ||
        parsed->host.find_first_not_of("0123456789.") == std::string::npos) {
        return error(400, "invalid_argument",
                     "passkeys need the console's name, not an address: open it at its "
                     "localhost or public URL");
    }
    KeyStore* keys = services_.keys;
    if (keys == nullptr || !keys->initialized()) {
        return error(409, "conflict", "this console keeps no keys, so it has no recovery code");
    }
    // The code opens the recovery slot, or it is not the code. Each try
    // costs the slot's scrypt: one at a time, and a few wrong ones a minute.
    const protocol::Timestamp now = services_.clock->now();
    {
        const std::lock_guard lock(mutex_);
        std::erase_if(recovery_failures_,
                      [&](protocol::Timestamp t) { return t + recovery_failure_window <= now; });
        if (checking_recovery_ || recovery_failures_.size() >= max_recovery_failures) {
            return error(429, "unavailable",
                         "too many recovery codes were tried: try again in a minute");
        }
        checking_recovery_ = true;
    }
    const bool opened = keys->unlock({SlotKind::recovery, {}}, field(*body, "recovery_code"));
    {
        const std::lock_guard lock(mutex_);
        checking_recovery_ = false;
        if (!opened) {
            recovery_failures_.push_back(now);
        }
    }
    if (!opened) {
        return error(403, "forbidden", "that is not this console's recovery code");
    }
    ready_now();
    const People people = load_people(services_.directory);
    const User* owner = owner_named(people, field(*body, "name"));
    if (owner == nullptr || owner->actor.empty()) {
        return error(404, "not_found", "name the owner whose passkey was lost");
    }
    // Whether the guardians must approve it (spec v0.20), said before the
    // new passkey is made.
    nlohmann::json needs{{"needed", false}, {"rules", nlohmann::json::array()}};
    const auto actor = actor_of(*owner);
    if (const ledger::Ledger* served = ledger(); served != nullptr && actor) {
        served->read_state([&](const protocol::LedgerState& state) {
            protocol::Statement s;
            s.ledger_id = state.ledger_id();
            s.actor_id = organization_of(state);
            s.issued_at = now;
            s.body = protocol::ActorSetPresenceBody{*actor, {}};
            needs = approvals_needed(state, s, false);
        });
    }
    const Bytes challenge = services_.entropy->bytes<32>() | std::ranges::to<Bytes>();
    const auto id = begin({true,
                           challenge,
                           parsed->host,
                           parsed->text(),
                           {},
                           owner->name,
                           services_.clock->now() + ceremony_lifetime,
                           true});
    if (!id) {
        return error(429, "unavailable", "too many passkey requests are waiting; try again soon");
    }
    return json(200, {{"ceremony", *id},
                      {"user", owner->name},
                      {"keys", key_state()},
                      {"approvals", needs},
                      {"public_key",
                       registration_options(challenge, parsed->host, owner->name, {}, true)}});
}

std::variant<Console::Recovery, http::Response>
Console::recovery_plan(const http::Request& request) const {
    const auto body = object_of(request);
    if (!body) {
        return error(400, "invalid_argument", "the request's body is not a JSON object");
    }
    const auto ceremony = take(field(*body, "ceremony"));
    if (!ceremony || !ceremony->recovery ||
        ceremony->origin != lowered(*request.header("origin"))) {
        return error(404, "not_found", "this recovery is unknown or expired; begin again");
    }
    const ledger::Ledger* const served = ledger();
    if (served == nullptr || !submitter()) {
        return error(503, "unavailable", "the console has no ledger to act on");
    }
    if (services_.keys == nullptr || !services_.keys->unlocked()) {
        return error(423, "locked", "the console was locked meanwhile; begin again");
    }
    auto registered = registered_passkey(*body, *ceremony);
    if (auto* refused = std::get_if<http::Response>(&registered)) {
        return std::move(*refused);
    }
    Recovery recovery;
    recovery.passkey = std::get<protocol::PresenceCredential>(std::move(registered));
    if (const std::string prf = field(*body, "prf"); is_prf_output(prf)) {
        recovery.prf = prf;
    }
    const People people = load_people(services_.directory);
    const User* owner = people.find(ceremony->name);
    if (owner == nullptr || owner->role != Role::owner) {
        return error(404, "not_found", "that owner was removed meanwhile");
    }
    const auto actor = actor_of(*owner);
    if (!actor) {
        return error(409, "conflict", "the owner acts as no one on the ledger");
    }
    if (const User* holder = people.owner_of(recovery.passkey.credential_id);
        holder != nullptr && holder->name != owner->name) {
        return error(409, "conflict", "this passkey is someone else's");
    }
    recovery.user = owner->name;
    // The root key replaces the owner's passkeys on the ledger.
    const auto root = services_.keys->open(root_key_name);
    protocol::Statement s;
    std::string problem;
    const crypto::HashAlg hash = served->hash();
    served->read_state([&](const protocol::LedgerState& state) {
        const protocol::ActorState* org = nullptr;
        for (const auto& [id, a] : state.actors()) {
            if (a.is_organization()) {
                org = &a;
            }
        }
        const protocol::ActorState* person = state.actor(*actor);
        if (org == nullptr || org->key != root.public_key()) {
            problem = "the console's root key is no longer the organization's";
        } else if (person == nullptr || person->revoked) {
            problem = "the owner's actor is not on the ledger, or is revoked";
        } else {
            s.ledger_id = state.ledger_id();
            s.actor_id = org->id;
        }
    });
    if (!problem.empty()) {
        return error(409, "conflict", problem);
    }
    s.issued_at = services_.clock->now();
    s.nonce = services_.entropy->bytes<16>();
    s.body = protocol::ActorSetPresenceBody{*actor, {recovery.passkey}};
    // While guardians guard it, it is sent for their approval.
    served->read_state([&](const protocol::LedgerState& state) {
        recovery.needs = approvals_needed(state, s, false);
    });
    recovery.for_approval = recovery.needs.value("needed", false);
    if (recovery.for_approval) {
        if (!approval_hooks().hold) {
            return error(503, "unavailable",
                         "the guardians must approve this, and this console cannot send it to "
                         "them");
        }
        recovery.lapses_at = recovery.needs["lapses_at"].get<protocol::Timestamp>();
    }
    auto made = protocol::sign_statement(root, *services_.provider, hash, s);
    if (!made) {
        return error(500, "internal", "signing failed");
    }
    recovery.statement = std::move(made->encoded);
    return recovery;
}

std::optional<http::Response> Console::apply_recovery(const std::string& user,
                                                      const protocol::PresenceCredential& passkey,
                                                      const std::string& prf) const {
    std::vector<std::string> lost;
    {
        const auto lock = ledger::DirectoryLock::acquire(services_.directory, 2000);
        if (!lock) {
            return error(503, "unavailable",
                         "the ledger has the new passkey, but the console could not record it: "
                         "begin the recovery again");
        }
        People people = load_people(services_.directory);
        User* owner = people.find(user);
        if (owner == nullptr) {
            return error(404, "not_found", "that owner was removed meanwhile");
        }
        for (const protocol::PresenceCredential& p : owner->passkeys) {
            if (p.credential_id != passkey.credential_id) {
                lost.push_back(to_base64url(p.credential_id));
            }
        }
        owner->passkeys = {passkey};
        save_people(services_.directory, people);
    }
    // The lost passkeys unlock nothing any more, and their sessions end.
    for (const std::string& id : lost) {
        static_cast<void>(services_.keys->remove_slot({SlotKind::prf, id}));
    }
    if (!prf.empty() && services_.keys->unlocked()) {
        services_.keys->add_slot({SlotKind::prf, to_base64url(passkey.credential_id)}, prf);
    }
    static_cast<void>(services_.sessions->end_all(user));
    return std::nullopt;
}

http::Response Console::finish_recovery(const Recovery& recovery,
                                        const http::Response& registered) const {
    // POST /v1/statements answers 201 when it registers the statement.
    if (registered.status < 200 || registered.status > 299) {
        http::Response refused = registered;
        secure(refused);
        return refused;
    }
    if (auto refused = apply_recovery(recovery.user, recovery.passkey, recovery.prf)) {
        return std::move(*refused);
    }
    return json(200, {{"session", services_.sessions->create(recovery.user)},
                      {"user", recovery.user},
                      {"role", name_of(Role::owner)},
                      {"keys", key_state()},
                      {"key_slot", !recovery.prf.empty()}});
}

http::Response Console::recover_finish(const http::Request& request) const {
    auto plan = recovery_plan(request);
    if (auto* refused = std::get_if<http::Response>(&plan)) {
        return std::move(*refused);
    }
    // Waits for the ledger's answer, as approve_route does (the node uses
    // the asynchronous handle).
    auto recovery = std::make_shared<const Recovery>(std::get<Recovery>(std::move(plan)));
    return wait_for([this, recovery](std::function<void(http::Response)> respond) {
        send_recovery(recovery, std::move(respond));
    });
}

void Console::send_recovery(std::shared_ptr<const Recovery> recovery,
                            std::function<void(http::Response)> respond) const {
    auto finish = [this, recovery, respond](const http::Response& registered) {
        try {
            respond(finish_recovery(*recovery, registered));
        } catch (const std::exception&) {
            respond(error(500, "internal", "the console could not answer; see its files"));
        }
    };
    if (!recovery->for_approval) {
        submitter()(recovery->statement, false, std::move(finish));
        return;
    }
    // The guardians approve it first: held at the node, registered once
    // they have; the console's side of it follows then (follow_up).
    const ApprovalHooks hooks = approval_hooks();
    node::HeldStatement held;
    held.statement = recovery->statement;
    auto body = node::encode_hold_request(held);
    if (!hooks.hold || !body) {
        respond(error(503, "unavailable", "this console cannot send it for approval"));
        return;
    }
    hooks.hold(std::move(*body), [this, recovery, respond,
                                  finish = std::move(finish)](http::Response answer) {
        if (answer.status != 202) {
            // Registered at once, or refused.
            finish(answer);
            return;
        }
        const auto waiting =
            nlohmann::json::parse(answer.body.begin(), answer.body.end(), nullptr, false);
        const std::string id = waiting.is_object() ? waiting.value("id", "") : std::string();
        keep_follow_up(id, {{"by", recovery->user},
                            {"activity", "recovery.done"},
                            {"recovery", {{"user", recovery->user}}},
                            {"until", recovery->lapses_at}});
        if (!recovery->prf.empty()) {
            const std::lock_guard lock(mutex_);
            recovery_prf_[id] = recovery->prf;
        }
        log_activity(recovery->user, "recovery.held", {{"statement", id}});
        respond(json(202, {{"held", true},
                           {"id", id},
                           {"user", recovery->user},
                           {"approvals", recovery->needs},
                           {"lapses_at", recovery->lapses_at}}));
    });
}

} // namespace kanhe::console
