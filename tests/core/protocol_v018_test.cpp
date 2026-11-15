// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// Spec v0.18 vectors (testvectors/protocol-v0.18.json), made apart from this
// implementation: scripts' metadata, where a source stood at a time, and a
// bank's log replayed with every refusal, its records naming the scripts
// they came from and their sources.

#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <utility>
#include <variant>
#include <vector>

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>

#include <kanhe/core/cbor.hpp>
#include <kanhe/core/protocol/evidence.hpp>
#include <kanhe/core/protocol/record_types.hpp>
#include <kanhe/core/protocol/scripts.hpp>
#include <kanhe/core/protocol/state.hpp>
#include <kanhe/core/protocol/state_tree.hpp>
#include <kanhe/crypto/openssl.hpp>

#include "support/vectors.hpp"

namespace protocol = kanhe::protocol;
namespace crypto = kanhe::crypto;
namespace cbor = kanhe::cbor;
using kanhe::to_hex;
using kanhe::test::hex;
using kanhe::test::load_vectors;

namespace {

const crypto::Provider& provider() {
    static const crypto::openssl::Provider instance;
    return instance;
}

std::string text(const nlohmann::json& value) {
    return value.get<std::string>();
}

const nlohmann::json& vectors() {
    static const nlohmann::json document = load_vectors("protocol-v0.18.json");
    return document;
}

protocol::Id id_of(const nlohmann::json& value) {
    return *protocol::to_id(hex(text(value)));
}

std::optional<protocol::Timestamp> optional_time(const nlohmann::json& j, const char* key) {
    return j.contains(key) && !j[key].is_null() ? std::optional(j[key].get<protocol::Timestamp>())
                                                : std::nullopt;
}

protocol::Script script_of(const nlohmann::json& j) {
    protocol::Script s;
    s.name = text(j["name"]);
    s.version = text(j["version"]);
    for (const auto& f : j["files"]) {
        s.files.push_back(
            {text(f["path"]), f["size"].get<std::uint64_t>(), hex(text(f["digest"]))});
    }
    s.deterministic = j["deterministic"].get<bool>();
    if (!j["runtime"].is_null()) {
        s.runtime = text(j["runtime"]);
    }
    return s;
}

std::string status_key(protocol::SourceStatus s) {
    switch (s) {
    case protocol::SourceStatus::not_yet:
        return "not_yet";
    case protocol::SourceStatus::live:
        return "live";
    case protocol::SourceStatus::revoked:
        return "revoked";
    case protocol::SourceStatus::replaced:
        return "replaced";
    }
    return "unknown";
}

} // namespace

TEST_CASE("v0.18 scripts: the seven mechanism types, and metadata read and written",
          "[protocol][vectors][v018]") {
    const auto& types = vectors()["mechanism_types"];
    REQUIRE(protocol::builtin_record_types().size() == types.size());
    for (std::size_t i = 0; i < types.size(); ++i) {
        INFO(text(types[i]["type"]));
        const protocol::RecordType* type = protocol::find_record_type(text(types[i]["type"]));
        REQUIRE(type != nullptr);
        CHECK(protocol::builtin_record_types()[i].name == type->name);
        CHECK(type->initial_state == text(types[i]["initial"]));
        CHECK(type->transitions.size() == types[i]["transitions"].size());
        CHECK(type->roles.empty());
    }
    CHECK(protocol::builtin_record_types()[types.size() - 1].name == protocol::script_type);
    const protocol::RecordType* script = protocol::find_record_type(protocol::script_type);
    REQUIRE(script != nullptr);
    CHECK(script->initial_state == "approved");
    CHECK(script->transitions.empty());

    for (const auto& c : vectors()["script_metadata"]["valid"]) {
        INFO(text(c["metadata"]));
        const auto value = cbor::decode(hex(text(c["metadata"])));
        REQUIRE(value);
        const auto s = protocol::decode_script(*value);
        INFO((s ? std::string() : std::string(s.error().detail)));
        REQUIRE(s);
        CHECK(*s == script_of(c["script"]));
        const auto again = protocol::encode_script(*s);
        REQUIRE(again);
        CHECK(to_hex(*cbor::encode(*again)) == text(c["metadata"]));
    }
    for (const auto& c : vectors()["script_metadata"]["refused"]) {
        INFO(text(c["name"]) + " (" + text(c["why"]) + ")");
        const auto value = cbor::decode(hex(text(c["metadata"])));
        CHECK_FALSE((value && protocol::decode_script(*value)));
    }
}

TEST_CASE("v0.18 sources: where one stood at a time", "[protocol][vectors][v018]") {
    for (const auto& h : vectors()["source_statuses"]) {
        const auto registered = h["registered"].get<protocol::Timestamp>();
        const auto revoked = optional_time(h, "revoked");
        const auto replaced = optional_time(h, "replaced");
        for (const auto& c : h["cases"]) {
            const auto t = c["t"].get<protocol::Timestamp>();
            INFO(t);
            CHECK(status_key(protocol::source_status_at(registered, revoked, replaced, t)) ==
                  text(c["status"]));
        }
    }
}

TEST_CASE("v0.18 scripts and sources: a bank's log replayed, with every refusal in place",
          "[protocol][vectors][v018]") {
    for (const auto& ledger : vectors()["replay"]["ledgers"]) {
        const auto hash = *crypto::hash_alg_from_cose(ledger["hash"].get<std::int64_t>());
        INFO(crypto::name(hash));
        std::vector<protocol::SignedStatement> statements;
        for (const auto& st : ledger["statements"]) {
            auto parsed = protocol::parse_statement(provider(), hex(text(st["encoded"])), hash);
            REQUIRE(parsed);
            statements.push_back(std::move(*parsed));
        }
        CHECK(to_hex(statements.front().id.bytes()) == text(ledger["ledger_id"]));
        std::multimap<std::size_t, const nlohmann::json*> refused;
        for (const auto& st : ledger["refused"]) {
            refused.emplace(st["after"].get<std::size_t>(), &st);
        }
        auto state = protocol::LedgerState::from_genesis(provider(), statements.front());
        REQUIRE(state);
        std::size_t checked = 0;
        auto refusals = [&](std::size_t after) {
            const auto [first, last] = refused.equal_range(after);
            for (auto it = first; it != last; ++it) {
                const nlohmann::json& r = *it->second;
                INFO(text(r["name"]) + " (" + text(r["why"]) + ")");
                auto parsed = protocol::parse_statement(provider(), hex(text(r["encoded"])), hash);
                REQUIRE(parsed);
                CHECK_FALSE(
                    state->validate(provider(), *parsed, r["at"].get<protocol::Timestamp>()));
                ++checked;
            }
        };
        for (std::size_t i = 1; i < statements.size(); ++i) {
            refusals(i);
            const auto& st = ledger["statements"][i];
            INFO(text(st["name"]));
            const auto at = st["registered_at"].get<protocol::Timestamp>();
            const auto valid = state->validate(provider(), statements[i], at);
            INFO((valid ? std::string() : std::string(valid.error().detail)));
            REQUIRE(valid);
            REQUIRE(state->apply(provider(), statements[i], i, at));
        }
        refusals(statements.size());
        CHECK(checked == ledger["refused"].size());

        for (const auto& m : ledger["malformed"]) {
            INFO(text(m["name"]) + " (" + text(m["why"]) + ")");
            CHECK_FALSE(protocol::parse_statement(provider(), hex(text(m["encoded"])), hash));
        }

        for (const auto& expected : ledger["records"]) {
            INFO(text(expected["id"]));
            const protocol::RecordState* record = state->record(id_of(expected["id"]));
            REQUIRE(record != nullptr);
            CHECK(record->record_type == text(expected["type"]));
            CHECK(record->state == text(expected["state"]));
            CHECK(record->revoked == expected["revoked"].get<bool>());
            CHECK(to_hex(record->registrant.bytes()) == text(expected["registrant"]));
            const auto history = record->history.to_vector();
            CHECK(history == expected["history"].get<std::vector<std::uint64_t>>());
            CHECK(record->supersedes.has_value() == !expected["supersedes"].is_null());
            if (record->supersedes) {
                CHECK(to_hex(record->supersedes->bytes()) == text(expected["supersedes"]));
            }
            CHECK(record->superseded_by.has_value() == !expected["superseded_by"].is_null());
            if (record->superseded_by) {
                CHECK(to_hex(record->superseded_by->bytes()) == text(expected["superseded_by"]));
            }

            // The registration names its sources and its script.
            REQUIRE_FALSE(history.empty());
            const protocol::Statement& registration = statements[history.front()].statement;
            const auto* body = std::get_if<protocol::RecordRegisterBody>(&registration.body);
            REQUIRE(body != nullptr);
            REQUIRE(body->sources.size() == expected["sources"].size());
            for (std::size_t s = 0; s < body->sources.size(); ++s) {
                CHECK(to_hex(body->sources[s].ledger.bytes()) == text(expected["sources"][s][0]));
                CHECK(to_hex(body->sources[s].record.bytes()) == text(expected["sources"][s][1]));
            }
            const bool named = registration.provenance && registration.provenance->script;
            CHECK(named == !expected["provenance_script"].is_null());
            if (named) {
                CHECK(to_hex(registration.provenance->script->bytes()) ==
                      text(expected["provenance_script"]));
            }
            CHECK((record->record_type == protocol::script_type) == !expected["script"].is_null());
            if (!expected["script"].is_null()) {
                REQUIRE(body->metadata);
                const auto s = protocol::decode_script(*body->metadata);
                REQUIRE(s);
                CHECK(*s == script_of(expected["script"]));
            }
        }
        for (const auto& s : ledger["scripts"]) {
            const protocol::RecordState* record = state->record(id_of(s));
            REQUIRE(record != nullptr);
            CHECK(record->record_type == protocol::script_type);
        }

        // A record's related records: the local sources its registration
        // names, then the scripts its events' provenance names.
        for (const auto& r : ledger["reports"]) {
            const protocol::RecordState* record = state->record(id_of(r));
            REQUIRE(record != nullptr);
            std::vector<protocol::Statement> events;
            for (const auto index : record->history.to_vector()) {
                events.push_back(statements[index].statement);
            }
            const auto related = protocol::related_records(events, statements.front().id);
            const auto& body = std::get<protocol::RecordRegisterBody>(events.front().body);
            std::vector<protocol::Id> expected;
            for (const auto& source : body.sources) {
                if (source.ledger == statements.front().id) {
                    expected.push_back(source.record);
                }
            }
            expected.push_back(*events.front().provenance->script);
            CHECK(related == expected);
        }

        const auto leaves = protocol::state_leaves(*state);
        REQUIRE(leaves.size() == ledger["state_leaves"].size());
        const auto root = protocol::state_root(provider(), hash, leaves);
        REQUIRE(root);
        CHECK(to_hex(root->bytes()) == text(ledger["state_root"]));
    }
}
