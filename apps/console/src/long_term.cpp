// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// Evidence for decades (spec v0.21, section 11.1). Settings show the
// ledger's long-term status as GET /v1/status gives it, and prepare a ledger
// made with classical keys for the long term, as `kanhe ledger long-term`
// does and with the same plan (client::plan_long_term): the log key's
// rotation, then the top key's, each to a post-quantum key the console makes
// and keeps sealed, each signed by the organization after an owner's passkey,
// then a checkpoint with the new log key. The node holds the next log key
// ahead of its rotation (served_log_keys), so it signs with it the moment
// the rotation is registered. While guardians guard the rotations, each goes
// for their approval, and the console takes the next step by itself once
// they have approved; whatever stops it, the steps are found again from the
// ledger, so it goes on from where it stopped. A proof file someone brings
// back is renewed with this ledger's newest attested checkpoint.

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <future>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

#include <nlohmann/json.hpp>

#include <kanhe/client/errors.hpp>
#include <kanhe/client/long_term.hpp>
#include <kanhe/client/public_witnesses.hpp>
#include <kanhe/client/renewals.hpp>
#include <kanhe/client/support.hpp>
#include <kanhe/console/console.hpp>
#include <kanhe/console/people.hpp>
#include <kanhe/console/setup.hpp>
#include <kanhe/core/bytes.hpp>
#include <kanhe/core/protocol/evidence.hpp>
#include <kanhe/core/protocol/keys.hpp>
#include <kanhe/core/protocol/log.hpp>
#include <kanhe/core/protocol/state.hpp>
#include <kanhe/core/protocol/statement.hpp>
#include <kanhe/node/approvals.hpp>
#include <kanhe/node/long_term.hpp>
#include <kanhe/node/peers.hpp>
#include <kanhe/verifier/report.hpp>

#include "responses.hpp"

namespace kanhe::console {

namespace {

constexpr std::string_view long_term_prefix = "/console/api/long-term";

std::string hex_of(const protocol::Id& id) {
    return to_hex(id.bytes());
}

std::string text_of(const nlohmann::json& body, std::string_view key) {
    const auto it = body.find(key);
    return it != body.end() && it->is_string() ? it->get<std::string>() : std::string();
}

/// A key the console keeps sealed under `name`, by its public key.
std::optional<crypto::PublicKey> sealed_key(const KeyStore* keys, std::string_view name) {
    if (keys == nullptr) {
        return std::nullopt;
    }
    for (const SealedKeyInfo& k : keys->keys()) {
        if (k.name == name) {
            return k.public_key;
        }
    }
    return std::nullopt;
}

/// The conversion as it stands: its steps (the shared plan, to the
/// console's next keys), and what holds it up.
struct Plan {
    std::vector<client::LongTermStep> steps;
    protocol::Id ledger_id;
    std::optional<crypto::PublicKey> next_log;
    std::optional<crypto::PublicKey> next_root;
    /// The console keeps the top key in effect, sealed as root.
    bool root_kept = false;
    /// The node holds the next log key.
    bool next_log_served = false;
    /// The conversion's rotations waiting for approvals now.
    std::vector<std::pair<std::string, protocol::Id>> held;
    /// Guardians guard the rotations (spec v0.20, section 5.2).
    bool guarded = false;
    /// The ledger rotated its log key or its top key at some time.
    bool rotated = false;
};

Plan plan_now(const ledger::Ledger& served, const KeyStore* keys, const crypto::Provider& provider,
              const std::filesystem::path& ledger_dir,
              const std::vector<crypto::PublicKey>& node_keys) {
    Plan p;
    p.next_log = sealed_key(keys, next_log_key_name);
    p.next_root = sealed_key(keys, next_root_key_name);
    const auto root = sealed_key(keys, root_key_name);
    std::optional<crypto::PublicKey> log_key;
    served.read_state([&](const protocol::LedgerState& state) {
        p.ledger_id = state.ledger_id();
        p.steps = client::plan_long_term(state, p.next_root, p.next_log);
        p.root_kept = root && *root == state.root_key();
        const protocol::GuardianSetting* g = state.guardians();
        p.guarded = g != nullptr && g->guardians.has_value();
        p.rotated = state.log_keys().size() > 1 || state.root_keys().size() > 1;
        log_key = state.log_key();
        for (const auto& [id, held] : node::held_statements(ledger_dir)) {
            const auto parsed = protocol::parse_statement(provider, held.statement, state.hash());
            if (!parsed) {
                continue;
            }
            if (const auto which = client::long_term_rotation(parsed->statement, p.ledger_id)) {
                p.held.emplace_back(std::string(*which), id);
            }
        }
    });
    p.next_log_served = p.next_log && std::ranges::contains(node_keys, *p.next_log);
    // The checkpoint: one signed by the log key in effect, after a rotation.
    // (The node makes one every minute; the conversion's own makes sure.)
    client::LongTermStep& checkpoint = p.steps[2];
    if (const auto latest = served.latest_checkpoint(); latest && log_key) {
        const auto kid = protocol::key_id(provider, served.hash(), *log_key);
        if (kid && latest->kid == *kid) {
            checkpoint.status = "done";
            checkpoint.tree_size = latest->checkpoint.tree_size;
        }
    }
    return p;
}

/// What the conversion does next: a rotation, the checkpoint, or nothing
/// (both keys post-quantum, with a checkpoint by the log key in effect).
std::string next_of(const Plan& p) {
    for (const client::LongTermStep& s : p.steps) {
        if (s.name != "checkpoint" && s.status == "planned") {
            return s.name;
        }
    }
    return p.rotated && p.steps[2].status != "done" ? std::string("checkpoint") : std::string();
}

const client::LongTermStep* planned_rotation(const Plan& p) {
    for (const client::LongTermStep& s : p.steps) {
        if (s.name != "checkpoint" && s.status == "planned") {
            return &s;
        }
    }
    return nullptr;
}

nlohmann::json key_view(const std::optional<crypto::PublicKey>& key) {
    if (!key) {
        return nullptr;
    }
    return {{"algorithm", std::string(crypto::name(key->algorithm))},
            {"post_quantum", node::post_quantum_algorithm(key->algorithm)}};
}

nlohmann::json step_view(const client::LongTermStep& s) {
    nlohmann::json out{{"step", s.name}, {"status", s.status}};
    if (s.name == "checkpoint") {
        out["tree_size"] = s.tree_size ? nlohmann::json(*s.tree_size) : nlohmann::json();
        return out;
    }
    out["from"] = key_view(s.from);
    // A key still to be made is the console's long-term kind.
    out["to"] = s.to ? key_view(s.to)
                     : nlohmann::json{{"algorithm", std::string(crypto::name(long_term_algorithm))},
                                      {"post_quantum", true}};
    return out;
}

/// The words for a step in the console's answers.
std::string step_words(std::string_view step) {
    return step == "rotate-log-key" ? "the ledger's new log key" : "the organization's new top key";
}

/// The console's next top key: sealed once, and kept until the ledger
/// rotated to it (a step prepared and not confirmed leaves it for the next).
std::optional<crypto::PublicKey> next_root_key(KeyStore& keys, std::mutex& making) {
    const std::lock_guard lock(making);
    if (const auto kept = sealed_key(&keys, next_root_key_name)) {
        return kept;
    }
    auto made = crypto::openssl::KeyPair::generate(long_term_algorithm);
    if (!made) {
        return std::nullopt;
    }
    keys.seal(next_root_key_name, *made);
    return made->public_key();
}

/// The largest size of a checkpoint the ledger keeps an attestation of (a
/// witness's cosignature, a time-stamp token, or a network cosignature), at
/// or above `from`: a renewal needs one. Of each kind, the newest thousand.
std::optional<std::uint64_t> newest_attested(const ledger::Ledger& ledger, std::uint64_t from) {
    std::optional<std::uint64_t> best;
    auto consider = [&](std::uint64_t size) {
        if (size >= from && (!best || size > *best)) {
            best = size;
        }
    };
    constexpr std::uint64_t page = 1000;
    const std::uint64_t cosignatures = ledger.cosignature_count();
    if (const auto got = ledger.cosignatures(cosignatures > page ? cosignatures - page : 0,
                                             std::min(cosignatures, page))) {
        for (const ledger::StoredCosignature& c : *got) {
            consider(c.cosignature.checkpoint.tree_size);
        }
    }
    const std::uint64_t timestamps = ledger.timestamp_count();
    if (const auto got = ledger.timestamps(timestamps > page ? timestamps - page : 0,
                                           std::min(timestamps, page))) {
        for (const ledger::StoredTimestamp& t : *got) {
            consider(t.checkpoint.checkpoint.tree_size);
        }
    }
    const std::uint64_t network = ledger.network_cosignature_count();
    if (const auto got = ledger.network_cosignatures(network > page ? network - page : 0,
                                                     std::min(network, page))) {
        for (const ledger::StoredNetworkCosignature& n : *got) {
            consider(n.checkpoint.checkpoint.tree_size);
        }
    }
    return best;
}

/// FILE's name with "-renewed" before its extension.
std::string renewed_name(const std::string& name) {
    const std::filesystem::path file(name);
    const std::string stem = file.stem().string();
    return (stem.empty() ? std::string("proof") : stem) + "-renewed" +
           (file.has_extension() ? file.extension().string() : std::string(".cbor"));
}

} // namespace

nlohmann::json Console::long_term_status() const {
    const ledger::Ledger* const served = ledger();
    if (served == nullptr) {
        return nullptr;
    }
    return long_term_watch_.status(*served, services_.clock->now());
}

void Console::settle_long_term_keys() const {
    const ledger::Ledger* const served = ledger();
    KeyStore* const keys = services_.keys;
    if (served == nullptr || keys == nullptr || !keys->unlocked()) {
        return;
    }
    std::optional<crypto::PublicKey> log_now;
    std::optional<crypto::PublicKey> root_now;
    served->read_state([&](const protocol::LedgerState& state) {
        log_now = state.log_key();
        root_now = state.root_key();
    });
    if (!log_now || !root_now) {
        return;
    }
    const std::lock_guard lock(long_term_mutex_);
    auto settle = [&](std::string_view current, std::string_view next, std::string_view retired,
                      const crypto::PublicKey& in_effect) {
        const auto made = sealed_key(keys, next);
        if (!made || *made != in_effect) {
            return;
        }
        // In this order, so that one stopped halfway is finished next time.
        const auto kept = sealed_key(keys, current);
        if (kept && *kept != *made) {
            keys->seal(retired, keys->open(current));
        }
        if (!kept || *kept != *made) {
            keys->seal(current, keys->open(next));
        }
        static_cast<void>(keys->remove_key(next));
    };
    try {
        settle(log_key_name, next_log_key_name, retired_log_key_name, *log_now);
        settle(root_key_name, next_root_key_name, retired_root_key_name, *root_now);
    } catch (const std::exception&) {
        // Settled at the next call: until then the next key keeps its name.
    }
}

nlohmann::json Console::long_term_view(Role role) const {
    const ledger::Ledger* const served = ledger();
    if (served == nullptr) {
        return nullptr;
    }
    settle_long_term_keys();
    const Plan p = plan_now(*served, services_.keys, *services_.provider,
                            services_.directory.parent_path(), node_log_keys());
    nlohmann::json steps = nlohmann::json::array();
    nlohmann::json remaining = nlohmann::json::array();
    for (const client::LongTermStep& s : p.steps) {
        steps.push_back(step_view(s));
        if (s.status == "planned" && (s.name != "checkpoint" || p.rotated)) {
            remaining.push_back(s.name);
        }
    }
    nlohmann::json held = nlohmann::json::array();
    for (const auto& [step, id] : p.held) {
        held.push_back({{"id", hex_of(id)}, {"step", step}});
    }
    const std::string next = next_of(p);
    const bool locked = services_.keys == nullptr || !services_.keys->unlocked();
    // Why the owner cannot take the next step now, if not.
    std::string why_not;
    if (next.empty()) {
        why_not = "nothing";
    } else if (role != Role::owner) {
        why_not = "owner";
    } else if (locked) {
        why_not = "locked";
    } else if (!p.held.empty()) {
        why_not = "held";
    } else if (next != "checkpoint" && !p.root_kept) {
        why_not = "root";
    } else if (next == "rotate-log-key" && !p.next_log_served) {
        why_not = "restart";
    }
    return {{"status", long_term_status()},
            {"steps", std::move(steps)},
            {"remaining", std::move(remaining)},
            {"next", next.empty() ? nlohmann::json() : nlohmann::json(next)},
            {"held", std::move(held)},
            {"guardians", p.guarded},
            {"may_convert", why_not.empty()},
            {"why_not", why_not.empty() ? nlohmann::json() : nlohmann::json(why_not)}};
}

std::variant<Console::PersonStep, http::Response>
Console::long_term_step(const Signed& who, const nlohmann::json& intent) const {
    if (who.role != Role::owner) {
        return error(403, "forbidden", "only an owner prepares the ledger for the long term");
    }
    if (text_of(intent, "action") != "long-term.convert") {
        return error(400, "invalid_argument", "the console cannot prepare this action");
    }
    const ledger::Ledger* const served = ledger();
    if (served == nullptr) {
        return error(503, "unavailable", "the console has no ledger to act on");
    }
    KeyStore* const keys = services_.keys;
    if (keys == nullptr || !keys->unlocked()) {
        return error(423, "locked", "the console is locked: unlock it first");
    }
    settle_long_term_keys();
    const std::filesystem::path ledger_dir = services_.directory.parent_path();
    Plan p = plan_now(*served, keys, *services_.provider, ledger_dir, node_log_keys());
    if (!p.held.empty()) {
        return error(409, "conflict",
                     step_words(p.held.front().first) +
                         " waits for the guardians' approval (Approvals): approve it, or withdraw "
                         "it, first");
    }
    const client::LongTermStep* step = planned_rotation(p);
    if (step == nullptr) {
        return error(409, "conflict",
                     p.rotated && p.steps[2].status != "done"
                         ? "both keys are post-quantum now: only the checkpoint with the new log "
                           "key remains (POST /console/api/long-term/checkpoint)"
                         : "the top key and the log key are post-quantum already: nothing to "
                           "convert");
    }
    if (!p.root_kept) {
        return error(409, "conflict",
                     "this console does not keep the organization's top key in effect: prepare "
                     "the ledger with kanhe ledger long-term instead");
    }
    std::string activity;
    if (step->name == "rotate-log-key") {
        // Only to a key the node holds already, or it could sign nothing
        // once the rotation is registered.
        if (!p.next_log_served) {
            return error(409, "conflict",
                         "the console's server does not hold the next log key yet: restart the "
                         "console (kanhe-console stop, then kanhe-console open), then try again");
        }
        activity = "long-term.log-key";
    } else {
        if (!p.next_root) {
            if (!next_root_key(*keys, long_term_mutex_)) {
                return error(500, "internal", "making the next top key failed");
            }
            p = plan_now(*served, keys, *services_.provider, ledger_dir, node_log_keys());
            step = planned_rotation(p);
            if (step == nullptr || step->name != "rotate-root-key" || !step->to) {
                return error(409, "conflict", "the ledger changed meanwhile: try again");
            }
        }
        activity = "long-term.root-key";
    }
    if (!step->to) {
        return error(409, "conflict", "the console has no next key for this step yet");
    }
    PersonStep made{client::long_term_body(p.ledger_id, *step), nullptr, "", activity};
    made.as_organization = true;
    return made;
}

void Console::continue_long_term(const std::string& by, bool go_on) const {
    settle_long_term_keys();
    if (!go_on) {
        return;
    }
    const ledger::Ledger* const served = ledger();
    const People people = load_people(services_.directory);
    const User* owner = people.find(by);
    // Only an owner prepares the ledger for the long term, and the owner's
    // tap that sent the first rotation covered the steps that follow it.
    if (served == nullptr || !submitter() || owner == nullptr || owner->role != Role::owner ||
        services_.keys == nullptr || !services_.keys->unlocked()) {
        return;
    }
    Plan p = plan_now(*served, services_.keys, *services_.provider,
                      services_.directory.parent_path(), node_log_keys());
    if (!p.held.empty() || !p.root_kept) {
        return;
    }
    const client::LongTermStep* step = planned_rotation(p);
    if (step == nullptr) {
        // Both keys rotated: the checkpoint with the new log key, made by the
        // node (it answers on its own; the node makes one every minute too).
        if (!client::long_term_checkpointed(*served)) {
            if (const Checkpointer checkpoint = checkpointer()) {
                checkpoint([](const http::Response&) {});
            }
        }
        return;
    }
    if (step->name == "rotate-log-key" && !p.next_log_served) {
        return;
    }
    if (step->name == "rotate-root-key" && !step->to) {
        if (!next_root_key(*services_.keys, long_term_mutex_)) {
            return;
        }
        p = plan_now(*served, services_.keys, *services_.provider,
                     services_.directory.parent_path(), node_log_keys());
        step = planned_rotation(p);
        if (step == nullptr || !step->to) {
            return;
        }
    }
    const std::string activity =
        step->name == "rotate-log-key" ? "long-term.log-key" : "long-term.root-key";
    protocol::Statement s;
    nlohmann::json needs;
    std::optional<crypto::PublicKey> root_in_effect;
    served->read_state([&](const protocol::LedgerState& state) {
        for (const auto& [key, candidate] : state.actors()) {
            if (candidate.is_organization() && !candidate.revoked) {
                s.actor_id = protocol::Id(candidate.id);
            }
        }
        s.ledger_id = state.ledger_id();
        s.issued_at = services_.clock->now();
        s.nonce = services_.entropy->bytes<16>();
        s.body = client::long_term_body(state.ledger_id(), *step);
        needs = approvals_needed(state, s, false);
        root_in_effect = state.root_key();
    });
    Bytes signed_bytes;
    try {
        const auto root = services_.keys->open(root_key_name);
        if (!root_in_effect || root.public_key() != *root_in_effect) {
            return;
        }
        auto made = protocol::sign_statement(root, *services_.provider, served->hash(), s);
        if (!made) {
            return;
        }
        signed_bytes = std::move(made->encoded);
    } catch (const std::exception&) {
        return;
    }
    const bool waits = needs.value("needed", false);
    const nlohmann::json follow{
        {"by", by},
        {"activity", activity},
        {"detail", {{"key", step->name == "rotate-log-key" ? "log" : "top"}, {"continued", true}}},
        {"long_term", {{"continue", true}}}};
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
        signing.lapses_at = needs["lapses_at"].get<protocol::Timestamp>();
        signing.follow = follow;
    }
    send_signed(std::move(signing), [](const http::Response&) {});
}

http::Response Console::renew_route(const Signed& who, const nlohmann::json& body) const {
    const ledger::Ledger* const served = ledger();
    if (served == nullptr) {
        return error(503, "unavailable", "the console has no ledger yet");
    }
    const std::string upload = text_of(body, "upload");
    std::filesystem::path path;
    std::string name;
    {
        const std::lock_guard lock(mutex_);
        const auto it = uploads_.find(upload);
        if (it == uploads_.end() || it->second.user != who.user ||
            it->second.expires <= services_.clock->now()) {
            return error(404, "not_found", "that file is no longer here: choose it again");
        }
        path = it->second.path;
        name = it->second.name;
    }
    const Bytes encoded = client::read_file(path);
    forget_uploads({upload});
    const auto bundle = protocol::decode_bundle(encoded);
    const auto from_ledger = protocol::bundle_ledger_id(encoded);
    if (!bundle || !from_ledger) {
        return error(422, "not_a_proof",
                     "this is not a document's proof file: " +
                         std::string(!bundle ? bundle.error().detail : from_ledger.error().detail));
    }
    protocol::Id own;
    served->read_state([&](const protocol::LedgerState& state) { own = state.ledger_id(); });
    if (*from_ledger != own) {
        return error(409, "other_ledger",
                     "this proof file comes from another ledger (" +
                         hex_of(*from_ledger).substr(0, 12) +
                         "...): only that ledger, or an archive that keeps it, renews it");
    }
    std::uint64_t from = 0;
    try {
        from = client::renewal_start(*bundle);
    } catch (const client::ActionError& e) {
        return error(422, "invalid_argument", e.message);
    }
    // To the latest checkpoint, or to the newest one attested since.
    auto made = served->renewal(from);
    if (!made && made.error().code == Errc::not_found) {
        if (const auto size = newest_attested(*served, from)) {
            made = served->renewal(from, *size);
        }
    }
    if (!made) {
        return error(409, made.error().code == Errc::not_found ? "not_attested" : "conflict",
                     made.error().code == Errc::not_found
                         ? "no checkpoint since this proof file was made has been cosigned by a "
                           "witness or stamped by a time-stamp authority yet: ask a witness to "
                           "witness this ledger (Parties), then try again"
                         : "no renewal from size " + std::to_string(from) + ": " +
                               std::string(made.error().detail));
    }
    // Verified as this console sees it: its parties' witnesses and the
    // public witnesses it asks are the ones it trusts.
    protocol::VerifyOptions options;
    options.expected_ledger = own;
    const std::filesystem::path ledger_dir = services_.directory.parent_path();
    if (const auto peers = node::load_peers(ledger_dir)) {
        for (const node::Peer& peer : *peers) {
            if (peer.witness_key) {
                options.trusted_witnesses.push_back(*peer.witness_key);
            }
        }
    }
    try {
        for (const client::UsedWitness& w : client::load_used_witnesses(ledger_dir)) {
            options.trusted_witnesses.push_back(w.key);
        }
    } catch (const std::exception&) {
        // Its public witnesses then count as untrusted.
    } catch (const client::ActionError&) {
        // The same.
    }
    std::optional<client::Renewed> renewed;
    try {
        renewed.emplace(client::renew_bundle(encoded, std::move(*made), options));
    } catch (const client::ActionError& e) {
        // Most often: the bundle has this ledger's newest attested checkpoint
        // and its attestations already.
        return error(409,
                     e.message.starts_with("the renewal adds nothing") ? "nothing_new" : "conflict",
                     e.message);
    }
    if (!renewed->report) {
        return error(422, "verification_failed",
                     "the renewed proof file does not verify: " +
                         std::string(renewed->report.error().detail));
    }
    const verifier::Json report = verifier::report_json(*renewed->report, true);
    const auto long_term = report.find("long_term");
    const auto checkpoint = protocol::parse_checkpoint(renewed->added.checkpoint);
    if (!checkpoint) {
        return error(500, "internal", "the renewal's checkpoint does not read");
    }
    const std::uint64_t size = checkpoint->checkpoint.tree_size;
    log_activity(who.user, "evidence.renew", {{"from", from}, {"to", size}});
    return json(200,
                {{"file", to_base64url(renewed->bundle)},
                 {"name", renewed_name(name)},
                 {"from_size", from},
                 {"tree_size", size},
                 {"timestamp", verifier::iso_time(checkpoint->checkpoint.timestamp)},
                 {"renewals", bundle->renewals.size() + 1},
                 {"added",
                  {{"key_rotations", renewed->added.rotations.size()},
                   {"cosignatures", renewed->added.cosignatures.size()},
                   {"timestamps", renewed->added.timestamps.size()},
                   {"network_cosignatures", renewed->added.network_cosignatures.size()}}},
                 {"long_term", long_term != report.end() ? nlohmann::json::parse(long_term->dump())
                                                         : nlohmann::json()}});
}

http::Response Console::long_term_route(const http::Request& request) const {
    auto signed_in = authenticate(request);
    if (auto* refused = std::get_if<http::Response>(&signed_in)) {
        return std::move(*refused);
    }
    const Signed& signer = std::get<Signed>(signed_in);
    const ledger::Ledger* const served = ledger();
    if (served == nullptr) {
        return error(503, "unavailable", "the console has no ledger yet");
    }
    const std::string_view rest = std::string_view(request.path).substr(long_term_prefix.size());
    if (rest.empty()) {
        if (request.method != "GET") {
            http::Response refused = error(405, "unsupported", "method not allowed");
            refused.headers.emplace_back("Allow", "GET");
            return refused;
        }
        return json(200, long_term_view(signer.role));
    }
    if (rest != "/checkpoint" && rest != "/renew") {
        return error(404, "not_found", "no such console route");
    }
    if (request.method != "POST") {
        http::Response refused = error(405, "unsupported", "method not allowed");
        refused.headers.emplace_back("Allow", "POST");
        return refused;
    }
    const auto body =
        nlohmann::json::parse(request.body.begin(), request.body.end(), nullptr, false);
    if (!body.is_object()) {
        return error(400, "invalid_argument", "the request's body is not a JSON object");
    }
    if (rest == "/renew") {
        if (signer.role == Role::viewer) {
            return error(403, "forbidden", "a viewer reads and verifies, and renews nothing");
        }
        return renew_route(signer, body);
    }
    // The conversion's checkpoint, with the new log key.
    if (signer.role != Role::owner && signer.role != Role::admin) {
        return error(403, "forbidden", "only an owner or an admin makes the ledger's checkpoint");
    }
    settle_long_term_keys();
    if (!client::long_term_checkpointed(*served)) {
        const Checkpointer checkpoint = checkpointer();
        if (!checkpoint) {
            return error(503, "unavailable", "this console cannot make a checkpoint");
        }
        auto made = std::make_shared<std::promise<http::Response>>();
        auto answered = made->get_future();
        checkpoint([made](http::Response r) { made->set_value(std::move(r)); });
        if (answered.wait_for(std::chrono::seconds(30)) != std::future_status::ready) {
            return error(504, "unavailable", "the ledger did not answer in time");
        }
        const http::Response r = answered.get();
        if (r.status / 100 != 2) {
            const auto answer = nlohmann::json::parse(r.body.begin(), r.body.end(), nullptr, false);
            const std::string message =
                answer.is_object() && answer.contains("error") && answer["error"].is_object()
                    ? answer["error"].value("message", std::string())
                    : std::string();
            return error(503, "unavailable",
                         "the ledger could not make a checkpoint with its log key in effect" +
                             (message.empty() ? std::string() : ": " + message));
        }
        log_activity(signer.user, "long-term.checkpoint", {{"tree_size", served->size()}});
    }
    return json(200, long_term_view(signer.role));
}

} // namespace kanhe::console
