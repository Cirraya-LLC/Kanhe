// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include <algorithm>
#include <charconv>
#include <set>
#include <string>
#include <utility>

#include <kanhe/core/protocol/common.hpp>
#include <kanhe/core/protocol/statement.hpp>
#include <kanhe/node/credentials.hpp>
#include <kanhe/node/responses.hpp>
#include <kanhe/verifier/jcs.hpp>

namespace kanhe::node {

namespace {

constexpr std::string_view status_prefix = "/status/";

http::Response open_response(int status, std::string content_type, std::string_view body) {
    http::Response r;
    r.status = status;
    r.content_type = std::move(content_type);
    r.body.assign(body.begin(), body.end());
    r.headers.emplace_back("access-control-allow-origin", "*");
    r.headers.emplace_back("cache-control", "no-store");
    return r;
}

http::Response open_error(int status, std::string_view code, std::string_view message) {
    http::Response r = error_response(status, code, message);
    r.headers.emplace_back("access-control-allow-origin", "*");
    r.headers.emplace_back("cache-control", "no-store");
    return r;
}

std::optional<std::uint64_t> list_number(std::string_view path) {
    if (!path.starts_with(status_prefix)) {
        return std::nullopt;
    }
    const std::string_view digits = path.substr(status_prefix.size());
    if (digits.empty() || digits.size() > 20 || digits.front() == '0') {
        return std::nullopt;
    }
    std::uint64_t n = 0;
    const auto [end, ec] = std::from_chars(digits.data(), digits.data() + digits.size(), n);
    if (ec != std::errc{} || end != digits.data() + digits.size() || n == 0) {
        return std::nullopt;
    }
    return n;
}

} // namespace

std::vector<CredentialEntry> credential_entries(const protocol::LedgerState& state) {
    std::vector<CredentialEntry> out;
    for (const auto& [key, record] : state.records()) {
        (void)key;
        for (const protocol::Endorsement& e : record.endorsements) {
            const protocol::ActorState* endorser = state.actor(e.actor.id());
            if (endorser == nullptr || !credential_device(state, *endorser)) {
                continue;
            }
            if (const auto entry = verifier::parse_credential_role(e.role)) {
                out.push_back({.record = record.id.id(),
                               .actor = e.actor.id(),
                               .entry = *entry,
                               .index = e.index});
            }
        }
    }
    std::ranges::sort(out, {}, &CredentialEntry::index);
    return out;
}

std::optional<CredentialEntry> credential_entry_of(std::span<const CredentialEntry> entries,
                                                   const protocol::Id& record,
                                                   const protocol::Id& actor) {
    for (const CredentialEntry& e : entries) {
        if (e.record == record && e.actor == actor) {
            return e;
        }
    }
    return std::nullopt;
}

verifier::StatusEntry choose_status_entry(std::span<const CredentialEntry> entries,
                                          ledger::Entropy& entropy) {
    std::uint64_t list = 1;
    for (const CredentialEntry& e : entries) {
        list = std::max(list, e.entry.list);
    }
    for (;; ++list) {
        std::vector<bool> used(verifier::status_list_size, false);
        std::size_t count = 0;
        for (const CredentialEntry& e : entries) {
            if (e.entry.list == list && !used[e.entry.index]) {
                used[e.entry.index] = true;
                ++count;
            }
        }
        if (count == verifier::status_list_size) {
            continue;
        }
        // The k-th free index, k uniform below the number free: rejection
        // sampling on 32 random bits, so that no index is likelier.
        const std::uint64_t free = verifier::status_list_size - count;
        const std::uint64_t limit = (std::uint64_t{1} << 32) - ((std::uint64_t{1} << 32) % free);
        std::uint64_t r = 0;
        do {
            const auto bytes = entropy.bytes<4>();
            r = (std::uint64_t{bytes[0]} << 24) | (std::uint64_t{bytes[1]} << 16) |
                (std::uint64_t{bytes[2]} << 8) | bytes[3];
        } while (r >= limit);
        std::uint64_t k = r % free;
        for (std::uint64_t i = 0; i < verifier::status_list_size; ++i) {
            if (!used[i] && k-- == 0) {
                return {.list = list, .index = i};
            }
        }
    }
}

std::string_view record_status(const protocol::RecordState& record) {
    if (record.revoked) {
        return "revoked";
    }
    return record.superseded_by ? "replaced" : "live";
}

std::vector<std::uint64_t> status_lists(std::span<const CredentialEntry> entries) {
    std::set<std::uint64_t> lists;
    for (const CredentialEntry& e : entries) {
        lists.insert(e.entry.list);
    }
    return {lists.begin(), lists.end()};
}

Bytes status_bits(const protocol::LedgerState& state, std::span<const CredentialEntry> entries,
                  std::uint64_t list) {
    Bytes bits(verifier::status_list_bytes, 0);
    for (const CredentialEntry& e : entries) {
        if (e.entry.list != list) {
            continue;
        }
        const protocol::RecordState* record = state.record(e.record);
        if (record != nullptr && record_status(*record) != "live") {
            verifier::set_status_bit(bits, e.entry.index);
        }
    }
    return bits;
}

bool credential_device(const protocol::LedgerState& state, const protocol::ActorState& actor) {
    if (actor.kind != protocol::ActorKind::device ||
        actor.key.algorithm != crypto::SigAlg::esp256) {
        return false;
    }
    bool any = false;
    for (const auto& [key, d] : state.delegations()) {
        (void)key;
        if (d.grantee != actor.id.id()) {
            continue;
        }
        if (d.scope.statement_types !=
            std::vector<protocol::StatementType>{protocol::StatementType::record_endorse}) {
            return false;
        }
        any = true;
    }
    return any;
}

bool is_credential_key(const protocol::LedgerState& state, const protocol::ActorState& actor) {
    // A key that ever held more than endorsements is never one: what it
    // issued would not count as credentials (credential_entries).
    if (actor.revoked || !credential_device(state, actor)) {
        return false;
    }
    for (const auto& [key, d] : state.delegations()) {
        (void)key;
        if (d.grantee == actor.id.id() && !d.revoked) {
            return true;
        }
    }
    return false;
}

namespace {

/// The log indexes of the statements that gave each key of every unrevoked
/// actor among `entries`' and `also`: its registration and its rotations.
std::vector<std::uint64_t> key_statements(const protocol::LedgerState& state,
                                          std::span<const CredentialEntry> entries,
                                          std::optional<protocol::Id> also) {
    std::vector<protocol::Id> actors;
    for (const CredentialEntry& e : entries) {
        if (!std::ranges::contains(actors, e.actor)) {
            actors.push_back(e.actor);
        }
    }
    if (also && !std::ranges::contains(actors, *also)) {
        actors.push_back(*also);
    }
    std::vector<std::uint64_t> out;
    for (const protocol::Id& id : actors) {
        const protocol::ActorState* actor = state.actor(id);
        if (actor == nullptr || actor->revoked) {
            continue;
        }
        out.push_back(actor->registered_at_index);
        out.insert(out.end(), actor->rotations.begin(), actor->rotations.end());
    }
    return out;
}

/// The ES256 keys the statements at `indexes` registered or rotated to.
Result<std::vector<crypto::PublicKey>>
keys_at(std::span<const std::uint64_t> indexes,
        const std::function<Result<protocol::SignedStatement>(std::uint64_t)>& statement_at) {
    std::vector<crypto::PublicKey> keys;
    for (const std::uint64_t index : indexes) {
        const auto signed_statement = statement_at(index);
        if (!signed_statement) {
            return std::unexpected(signed_statement.error());
        }
        const crypto::PublicKey* key = nullptr;
        if (const auto* body =
                std::get_if<protocol::ActorRegisterBody>(&signed_statement->statement.body)) {
            key = &body->key;
        } else if (const auto* rotation = std::get_if<protocol::ActorRotateKeyBody>(
                       &signed_statement->statement.body)) {
            key = &rotation->key;
        }
        if (key != nullptr && key->algorithm == crypto::SigAlg::esp256) {
            keys.push_back(*key);
        }
    }
    return keys;
}

} // namespace

Result<std::vector<crypto::PublicKey>> credential_keys(
    const protocol::LedgerState& state, std::span<const CredentialEntry> entries,
    std::optional<protocol::Id> also,
    const std::function<Result<protocol::SignedStatement>(std::uint64_t)>& statement_at) {
    return keys_at(key_statements(state, entries, also), statement_at);
}

bool credential_path(std::string_view path) noexcept {
    return path == "/.well-known/did.json" || path == "/did.json" || list_number(path).has_value();
}

std::variant<http::Response, CredentialPlan>
plan_credential_response(const crypto::Provider& provider, const CredentialService& service,
                         const protocol::LedgerState& state, std::string_view path) {
    std::shared_ptr<const crypto::Signer> key = service.key ? service.key() : nullptr;
    std::optional<verifier::BaseUrl> base = service.base ? service.base() : std::nullopt;
    if (key == nullptr || !base) {
        return open_error(404, "not_found", "this server issues no credentials (yet)");
    }
    const auto kid = protocol::key_id(provider, state.hash(), key->public_key());
    const protocol::ActorState* actor = kid ? state.actor_by_kid(*kid) : nullptr;
    if (actor == nullptr || actor->revoked) {
        return open_error(503, "unavailable",
                          "the server's credential key is not an active actor of this ledger");
    }
    if (!credential_device(state, *actor)) {
        return open_error(503, "unavailable",
                          "the server's credential key is not a credential key of this ledger: a "
                          "device whose delegations cover record endorsements and nothing else");
    }
    CredentialPlan plan;
    plan.key = std::move(key);
    plan.base = std::move(*base);
    plan.ledger_id = state.ledger_id();
    plan.hash = state.hash();
    plan.version = state.statement_count();
    const std::vector<CredentialEntry> entries = credential_entries(state);
    if (path == "/.well-known/did.json" || path == "/did.json") {
        plan.key_statements = key_statements(state, entries, actor->id.id());
        return plan;
    }
    const auto list = list_number(path);
    if (!list || !std::ranges::contains(status_lists(entries), *list)) {
        return open_error(404, "not_found", "no credential names that status list");
    }
    plan.list = *list;
    plan.bits = status_bits(state, entries, *list);
    plan.organization = state.organization();
    return plan;
}

http::Response credential_response(
    const crypto::Provider& provider, const CredentialPlan& plan, protocol::Timestamp now,
    const std::function<Result<protocol::SignedStatement>(std::uint64_t)>& statement_at) {
    if (plan.list == 0) {
        const auto keys = keys_at(plan.key_statements, statement_at);
        if (!keys) {
            return open_error(500, "internal", "the credential keys could not be read");
        }
        const auto doc = verifier::did_document(provider, plan.base, *keys, plan.ledger_id);
        const auto text =
            doc ? verifier::jcs(*doc) : Result<std::string>(std::unexpected(doc.error()));
        if (!text) {
            return open_error(500, "internal", "the DID document could not be made");
        }
        return open_response(200, "application/did+json", *text);
    }
    const verifier::Json payload =
        verifier::status_list_json(plan.base, plan.organization, plan.list, plan.bits, now);
    const auto jws = verifier::sign_credential(*plan.key, provider, plan.base.did, payload);
    if (!jws) {
        return open_error(500, "internal", "the status list could not be signed");
    }
    return open_response(200, std::string(verifier::credential_media_type), *jws);
}

std::optional<http::Response> CredentialCache::find(std::string_view path, std::uint64_t version,
                                                    const crypto::PublicKey& key,
                                                    const verifier::BaseUrl& base,
                                                    protocol::Timestamp now) const {
    const std::scoped_lock lock(mutex_);
    const auto it = kept_.find(path);
    if (it == kept_.end()) {
        return std::nullopt;
    }
    const Kept& k = it->second;
    if (k.version != version || k.key != key || k.base != base) {
        return std::nullopt;
    }
    // A list says when it was signed: sign again once that is long ago, or
    // if the clock went back.
    if (k.list && (now < k.made || now - k.made >= credential_list_max_age_ms)) {
        return std::nullopt;
    }
    return k.response;
}

void CredentialCache::keep(std::string_view path, const CredentialPlan& plan,
                           protocol::Timestamp now, const http::Response& response) {
    if (response.status != 200) {
        return;
    }
    const std::scoped_lock lock(mutex_);
    Kept& k = kept_[std::string(path)];
    // Answers made from an older state may finish last: keep the newest.
    if (k.version > plan.version) {
        return;
    }
    k = Kept{.version = plan.version,
             .key = plan.key->public_key(),
             .base = plan.base,
             .list = plan.list != 0,
             .made = now,
             .response = response};
}

} // namespace kanhe::node
