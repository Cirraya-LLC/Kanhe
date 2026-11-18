// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// Spec v0.20 objects: approval rules (scope key 10), guardian settings
// (statement type 9), approvals and their presence challenge, and the
// approvals a log entry carries (key 5), each read and written, and each
// refused for the one rule it breaks; then the vectors of
// testvectors/protocol-v0.20.json, made apart from this implementation: the
// objects, and two logs (SHA-256 and SM3) replayed with every refusal.

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <utility>
#include <variant>
#include <vector>

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>

#include <kanhe/core/cbor.hpp>
#include <kanhe/core/merkle.hpp>
#include <kanhe/core/protocol/approvals.hpp>
#include <kanhe/core/protocol/evidence.hpp>
#include <kanhe/core/protocol/log.hpp>
#include <kanhe/core/protocol/presence.hpp>
#include <kanhe/core/protocol/state.hpp>
#include <kanhe/core/protocol/state_tree.hpp>
#include <kanhe/core/protocol/statement.hpp>
#include <kanhe/crypto/openssl.hpp>

#include "support/authenticator.hpp"
#include "support/vectors.hpp"

namespace protocol = kanhe::protocol;
namespace crypto = kanhe::crypto;
namespace cbor = kanhe::cbor;
using kanhe::Bytes;
using kanhe::Errc;
using protocol::StatementType;

namespace {

const crypto::Provider& provider() {
    static const crypto::openssl::Provider instance;
    return instance;
}

crypto::openssl::KeyPair key(const std::string& name) {
    auto seed = provider().digest(crypto::HashAlg::sha256, kanhe::as_bytes("v0.20 key: " + name));
    REQUIRE(seed);
    auto pair = crypto::openssl::KeyPair::from_ed25519_seed(seed->bytes());
    REQUIRE(pair);
    return std::move(*pair);
}

protocol::Id id(std::uint8_t b) {
    return *protocol::to_id(Bytes(32, b));
}

protocol::ApprovalRule rule(std::uint64_t needed, std::vector<std::uint8_t> approvers,
                            protocol::Timestamp within = 7 * 86'400'000ULL) {
    protocol::ApprovalRule r;
    r.needed = needed;
    for (const std::uint8_t b : approvers) {
        r.approvers.push_back(id(b));
    }
    r.within = within;
    return r;
}

cbor::MapEntry entry(std::int64_t label, cbor::Value value) {
    return {cbor::Value::integer(label), std::move(value)};
}

cbor::Value ids(std::vector<std::uint8_t> bytes) {
    cbor::Array out;
    for (const std::uint8_t b : bytes) {
        out.push_back(cbor::Value::bytes(Bytes(32, b)));
    }
    return cbor::Value::array(std::move(out));
}

Bytes encoded(const cbor::Value& value) {
    auto out = cbor::encode(value);
    REQUIRE(out);
    return *out;
}

Errc decode_error(const cbor::Value& value) {
    const auto decoded = protocol::decode_approval_rule(encoded(value));
    REQUIRE_FALSE(decoded);
    return decoded.error().code;
}

protocol::Statement org_statement(protocol::Body body) {
    protocol::Statement s;
    s.ledger_id = id(1);
    s.actor_id = id(1);
    s.issued_at = 1'794'700'800'000;
    s.nonce = protocol::Nonce{9};
    s.body = std::move(body);
    return s;
}

} // namespace

TEST_CASE("v0.20 approval rules: read and written, within their limits", "[protocol][v020]") {
    const auto r = rule(2, {3, 4, 5});
    const auto bytes = protocol::encode_approval_rule(r);
    REQUIRE(bytes);
    CHECK(*bytes == encoded(cbor::Value::map(
                        {entry(1, cbor::Value::unsigned_integer(2)), entry(2, ids({3, 4, 5})),
                         entry(3, cbor::Value::unsigned_integer(604'800'000))})));
    const auto back = protocol::decode_approval_rule(*bytes);
    REQUIRE(back);
    CHECK(*back == r);

    // Key 4 only when true.
    auto open = r;
    open.without_presence = true;
    const auto open_bytes = protocol::encode_approval_rule(open);
    REQUIRE(open_bytes);
    CHECK(protocol::decode_approval_rule(*open_bytes) == open);
    CHECK(decode_error(
              cbor::Value::map({entry(1, cbor::Value::unsigned_integer(1)), entry(2, ids({3})),
                                entry(3, cbor::Value::unsigned_integer(60'000)),
                                entry(4, cbor::Value::boolean(false))})) == Errc::non_canonical);

    // The limits, at both ends.
    CHECK(protocol::encode_approval_rule(rule(1, {3}, protocol::min_approval_window)));
    CHECK(protocol::encode_approval_rule(rule(1, {3}, protocol::max_approval_window)));
    CHECK(protocol::encode_approval_rule(
        rule(16, {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16})));
    for (const auto& bad :
         {rule(0, {3}), rule(17, {3}), rule(3, {3, 4}),
          rule(1, {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17}), rule(1, {4, 3}),
          rule(1, {3, 3}), rule(1, {3}, protocol::min_approval_window - 1),
          rule(1, {3}, protocol::max_approval_window + 1)}) {
        const auto refused = protocol::encode_approval_rule(bad);
        REQUIRE_FALSE(refused);
        CHECK(refused.error().code == Errc::invalid_argument);
    }
    CHECK(decode_error(cbor::Value::map(
              {entry(1, cbor::Value::unsigned_integer(1)), entry(2, ids({4, 3})),
               entry(3, cbor::Value::unsigned_integer(60'000))})) == Errc::non_canonical);
    CHECK(decode_error(cbor::Value::map(
              {entry(1, cbor::Value::unsigned_integer(2)), entry(2, ids({3})),
               entry(3, cbor::Value::unsigned_integer(60'000))})) == Errc::malformed);
    CHECK(decode_error(cbor::Value::map(
              {entry(1, cbor::Value::unsigned_integer(1)), entry(2, ids({})),
               entry(3, cbor::Value::unsigned_integer(60'000))})) == Errc::malformed);
    CHECK(decode_error(cbor::Value::map(
              {entry(1, cbor::Value::unsigned_integer(1)),
               entry(2, ids({1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17})),
               entry(3, cbor::Value::unsigned_integer(60'000))})) == Errc::malformed);
    CHECK(decode_error(cbor::Value::map(
              {entry(1, cbor::Value::unsigned_integer(1)), entry(2, ids({3})),
               entry(3, cbor::Value::unsigned_integer(59'999))})) == Errc::malformed);
    // No other key.
    CHECK_FALSE(protocol::decode_approval_rule(
        encoded(cbor::Value::map({entry(1, cbor::Value::unsigned_integer(1)), entry(2, ids({3})),
                                  entry(3, cbor::Value::unsigned_integer(60'000)),
                                  entry(5, cbor::Value::unsigned_integer(1))}))));
}

TEST_CASE("v0.20 scopes carry an approval rule, and never type 9", "[protocol][v020]") {
    protocol::Scope scope;
    scope.statement_types = {StatementType::record_register};
    scope.approvals = rule(2, {3, 4, 5});
    auto grant = org_statement(protocol::DelegationGrantBody{id(2), scope});
    const auto payload = protocol::encode_payload(grant);
    REQUIRE(payload);
    const auto back = protocol::decode_payload(*payload);
    REQUIRE(back);
    CHECK(std::get<protocol::DelegationGrantBody>(back->body).scope == scope);

    // A rule that breaks its limits does not encode inside a scope either.
    scope.approvals = rule(4, {3, 4, 5});
    CHECK_FALSE(
        protocol::encode_payload(org_statement(protocol::DelegationGrantBody{id(2), scope})));

    // Setting guardians cannot be delegated.
    protocol::Scope guardians;
    guardians.statement_types = {StatementType::ledger_set_guardians};
    CHECK_FALSE(
        protocol::encode_payload(org_statement(protocol::DelegationGrantBody{id(2), guardians})));
}

TEST_CASE("v0.20 guardian settings: a rule or null, and the types they guard", "[protocol][v020]") {
    CHECK(protocol::statement_type_from(9) == StatementType::ledger_set_guardians);
    CHECK(protocol::name(StatementType::ledger_set_guardians) == "ledger-set-guardians");

    const std::vector<protocol::LedgerSetGuardiansBody> valid{
        {rule(2, {3, 4, 5}), std::nullopt},
        {rule(1, {3, 4}), std::vector<StatementType>{StatementType::actor_rotate_key,
                                                     StatementType::record_register}},
        {rule(1, {3}), std::vector<StatementType>{StatementType::ledger_set_guardians}},
        {std::nullopt, std::nullopt},
    };
    for (const auto& body : valid) {
        const auto s = org_statement(body);
        const auto payload = protocol::encode_payload(s);
        REQUIRE(payload);
        const auto back = protocol::decode_payload(*payload);
        REQUIRE(back);
        CHECK(*back == s);
    }
    // Null removes them: key 1 is null, not absent.
    const auto removal = protocol::encode_payload(
        org_statement(protocol::LedgerSetGuardiansBody{std::nullopt, std::nullopt}));
    REQUIRE(removal);
    const auto removal_value = cbor::decode(*removal);
    REQUIRE(removal_value);
    const cbor::Value* body = removal_value->find(7);
    REQUIRE(body != nullptr);
    REQUIRE(body->find(1) != nullptr);
    CHECK(body->find(1)->is_null());

    auto open = rule(1, {3});
    open.without_presence = true;
    const std::vector<protocol::LedgerSetGuardiansBody> refused{
        {open, std::nullopt}, // in person always
        {std::nullopt, std::vector<StatementType>{StatementType::record_register}}, // list, no rule
        {rule(1, {3}), std::vector<StatementType>{}},                               // an empty list
        {rule(1, {3}), std::vector<StatementType>{StatementType::genesis}},         // never genesis
        {rule(1, {3}), std::vector<StatementType>{StatementType::record_register,
                                                  StatementType::actor_register}}, // unsorted
        {rule(1, {3}), std::vector<StatementType>{StatementType::record_register,
                                                  StatementType::record_register}}, // twice
    };
    for (const auto& b : refused) {
        CHECK_FALSE(protocol::encode_payload(org_statement(b)));
    }

    // Read: a list out of order, an unknown type, or a missing key 1.
    auto payload_with = [](cbor::Value body_value) {
        return encoded(cbor::Value::map(
            {entry(0, cbor::Value::unsigned_integer(1)), entry(1, cbor::Value::unsigned_integer(9)),
             entry(2, cbor::Value::bytes(Bytes(32, 1))), entry(3, cbor::Value::bytes(Bytes(32, 1))),
             entry(5, cbor::Value::unsigned_integer(1'794'700'800'000)),
             entry(6, cbor::Value::bytes(Bytes(16, 9))), entry(7, std::move(body_value))}));
    };
    const auto rule_value = cbor::decode(*protocol::encode_approval_rule(rule(1, {3})));
    REQUIRE(rule_value);
    CHECK(protocol::decode_payload(payload_with(cbor::Value::map({entry(1, *rule_value)}))));
    const auto unsorted = protocol::decode_payload(payload_with(
        cbor::Value::map({entry(1, *rule_value),
                          entry(2, cbor::Value::array({cbor::Value::unsigned_integer(16),
                                                       cbor::Value::unsigned_integer(2)}))})));
    REQUIRE_FALSE(unsorted);
    CHECK(unsorted.error().code == Errc::non_canonical);
    const auto unknown = protocol::decode_payload(payload_with(
        cbor::Value::map({entry(1, *rule_value),
                          entry(2, cbor::Value::array({cbor::Value::unsigned_integer(20)}))})));
    REQUIRE_FALSE(unknown);
    CHECK(unknown.error().code == Errc::unsupported);
    CHECK_FALSE(protocol::decode_payload(payload_with(cbor::Value::map({}))));
}

TEST_CASE("v0.20 approvals: signed over a statement id, apart from every other object",
          "[protocol][v020]") {
    const auto approver = key("chan");
    const auto hash = crypto::HashAlg::sha256;
    const protocol::Approval approval{id(1), id(3), id(7), 1'794'700'800'000, std::nullopt};
    const auto signed_approval = protocol::sign_approval(approver, provider(), hash, approval);
    REQUIRE(signed_approval);
    CHECK(signed_approval->approval == approval);
    CHECK(signed_approval->kid == *protocol::key_id(provider(), hash, approver.public_key()));
    CHECK(protocol::verify_approval(provider(), hash, *signed_approval, approver.public_key()));
    CHECK_FALSE(
        protocol::verify_approval(provider(), hash, *signed_approval, key("lee").public_key()));

    // Its payload: {1: ledger, 2: approver, 3: statement, 4: approved at}.
    const auto payload = protocol::encode_approval_payload(approval);
    REQUIRE(payload);
    CHECK(*payload ==
          encoded(cbor::Value::map({entry(1, cbor::Value::bytes(Bytes(32, 1))),
                                    entry(2, cbor::Value::bytes(Bytes(32, 3))),
                                    entry(3, cbor::Value::bytes(Bytes(32, 7))),
                                    entry(4, cbor::Value::unsigned_integer(1'794'700'800'000))})));
    CHECK(*signed_approval->envelope.payload == *payload);
    const auto parsed = protocol::parse_approval(signed_approval->encoded);
    REQUIRE(parsed);
    CHECK(parsed->approval == approval);

    // Its content type sets it apart: never a statement, nor the reverse.
    CHECK_FALSE(protocol::parse_statement(provider(), signed_approval->encoded, hash));
    const auto statement = protocol::sign_statement(
        approver, provider(), hash, org_statement(protocol::RecordRevokeBody{id(7), std::nullopt}));
    REQUIRE(statement);
    CHECK_FALSE(protocol::parse_approval(statement->encoded));

    // No other key, every key it needs, and at most 24,576 bytes.
    CHECK_FALSE(protocol::decode_approval_payload(encoded(cbor::Value::map(
        {entry(1, cbor::Value::bytes(Bytes(32, 1))), entry(2, cbor::Value::bytes(Bytes(32, 3))),
         entry(3, cbor::Value::bytes(Bytes(32, 7))), entry(4, cbor::Value::unsigned_integer(1)),
         entry(6, cbor::Value::unsigned_integer(1))}))));
    CHECK_FALSE(protocol::decode_approval_payload(encoded(cbor::Value::map(
        {entry(1, cbor::Value::bytes(Bytes(32, 1))), entry(2, cbor::Value::bytes(Bytes(32, 3))),
         entry(4, cbor::Value::unsigned_integer(1))}))));
    CHECK_FALSE(protocol::decode_approval_payload(encoded(cbor::Value::map(
        {entry(1, cbor::Value::bytes(Bytes(31, 1))), entry(2, cbor::Value::bytes(Bytes(32, 3))),
         entry(3, cbor::Value::bytes(Bytes(32, 7))),
         entry(4, cbor::Value::unsigned_integer(1))}))));
    Bytes big = signed_approval->encoded;
    big.resize(protocol::max_approval_size + 1);
    const auto too_big = protocol::parse_approval(big);
    REQUIRE_FALSE(too_big);
    CHECK(too_big.error().code == Errc::limit_exceeded);
}

TEST_CASE("v0.20 an approval's presence challenge is its own", "[protocol][v020][presence]") {
    const auto approver = key("lee");
    const auto token = key("lee's token");
    for (const auto hash : {crypto::HashAlg::sha256, crypto::HashAlg::sm3}) {
        INFO(crypto::name(hash));
        const auto kid = protocol::key_id(provider(), hash, approver.public_key());
        REQUIRE(kid);
        protocol::Approval approval{id(1), id(4), id(7), 1'794'700'800'000, std::nullopt};
        const auto challenge = protocol::approval_challenge(provider(), hash, approval, *kid);
        REQUIRE(challenge);
        // HASH("Kanhe approval v1" || kid || the payload without key 5).
        const auto payload = protocol::encode_approval_payload(approval);
        REQUIRE(payload);
        const auto expected = provider().digest(
            hash, {kanhe::as_bytes(protocol::approval_context), kid->bytes(), *payload});
        REQUIRE(expected);
        CHECK(*challenge == Bytes(expected->bytes().begin(), expected->bytes().end()));

        // A hardware key signs it; the proof does not change it.
        const protocol::PresenceCredential credential{"", Bytes(32, 0x5a), token.public_key(),
                                                      std::string("token"),
                                                      protocol::PresenceMethod::hardware_key};
        approval.presence =
            protocol::PresenceProof{Bytes(32, 0x5a), {}, {}, *token.sign(*challenge)};
        CHECK(protocol::approval_challenge(provider(), hash, approval, *kid) == challenge);
        const auto signed_approval = protocol::sign_approval(approver, provider(), hash, approval);
        REQUIRE(signed_approval);
        const auto check = protocol::verify_approval_presence(provider(), hash, *signed_approval,
                                                              std::span(&credential, 1));
        REQUIRE(check);
        CHECK(check->method == protocol::PresenceMethod::hardware_key);
        CHECK(check->user_verified);

        // The same touch is no statement's: the contexts differ.
        auto statement = org_statement(protocol::RecordRevokeBody{id(7), std::nullopt});
        CHECK(protocol::presence_challenge(provider(), hash, statement, *kid) != challenge);

        // Another approval, another credential: no proof.
        protocol::Approval other = approval;
        other.statement = id(8);
        const auto moved = protocol::sign_approval(approver, provider(), hash, other);
        REQUIRE(moved);
        CHECK_FALSE(protocol::verify_approval_presence(provider(), hash, *moved,
                                                       std::span(&credential, 1)));
        protocol::PresenceCredential stranger = credential;
        stranger.credential_id = Bytes(32, 0x5b);
        CHECK_FALSE(protocol::verify_approval_presence(provider(), hash, *signed_approval,
                                                       std::span(&stranger, 1)));
    }

    // A passkey's assertion over it, user verified or only present.
    auto passkey_key = crypto::openssl::KeyPair::generate(crypto::SigAlg::esp256);
    REQUIRE(passkey_key);
    auto shared = std::make_shared<const crypto::openssl::KeyPair>(std::move(*passkey_key));
    kanhe::test::SoftPasskey passkey;
    passkey.public_key = shared->public_key();
    passkey.key = shared;
    passkey.credential_id = Bytes(16, 3);
    const protocol::PresenceCredential credential{passkey.rp_id, passkey.credential_id,
                                                  passkey.public_key, std::nullopt};
    const auto hash = crypto::HashAlg::sha256;
    const auto kid = protocol::key_id(provider(), hash, approver.public_key());
    REQUIRE(kid);
    for (const std::uint8_t flags : {std::uint8_t{0x05}, std::uint8_t{0x01}}) {
        passkey.flags = flags;
        protocol::Approval approval{id(1), id(4), id(7), 1'794'700'800'000, std::nullopt};
        approval.presence = passkey.sign(
            provider(), *protocol::approval_challenge(provider(), hash, approval, *kid));
        const auto signed_approval = protocol::sign_approval(approver, provider(), hash, approval);
        REQUIRE(signed_approval);
        const auto check = protocol::verify_approval_presence(provider(), hash, *signed_approval,
                                                              std::span(&credential, 1));
        REQUIRE(check);
        CHECK(check->method == protocol::PresenceMethod::webauthn);
        CHECK(check->user_verified == (flags == 0x05));
    }
}

TEST_CASE("v0.20 log entries carry approvals beside a statement, never a commitment",
          "[protocol][v020]") {
    const auto hash = crypto::HashAlg::sha256;
    std::vector<Bytes> approvals;
    for (const std::uint8_t approver : {std::uint8_t{4}, std::uint8_t{3}}) {
        const auto a = protocol::sign_approval(
            key(std::to_string(approver)), provider(), hash,
            protocol::Approval{id(1), id(approver), id(7), 1'794'700'800'000, std::nullopt});
        REQUIRE(a);
        approvals.push_back(a->encoded);
    }
    protocol::LogEntry logged{id(7), 1'794'700'800'000, Bytes{0xd2, 0x84}};
    logged.approvals = approvals;
    const auto bytes = protocol::encode_log_entry(logged);
    REQUIRE(bytes);
    const auto back = protocol::decode_log_entry(*bytes);
    REQUIRE(back);
    CHECK(*back == logged);
    CHECK(protocol::approvers_of(*back) == std::vector<protocol::Id>{id(4), id(3)});

    // In the order of their approvers: the ledger sorts them.
    const auto sorted = protocol::sort_approvals(approvals);
    REQUIRE(sorted);
    REQUIRE(sorted->size() == 2);
    CHECK((*sorted)[0].approval.approver == id(3));
    CHECK((*sorted)[1].approval.approver == id(4));
    const auto twice = protocol::sort_approvals(std::vector<Bytes>{approvals[0], approvals[0]});
    REQUIRE_FALSE(twice);
    CHECK(twice.error().code == Errc::rejected);
    CHECK_FALSE(protocol::sort_approvals(std::vector<Bytes>{Bytes{1, 2, 3}}));

    // Never on a state commitment; never an empty list; at most 32, each at
    // most 24,576 bytes.
    protocol::LogEntry commitment{id(7), 1, {}, Bytes{0xd2}};
    commitment.approvals = approvals;
    CHECK_FALSE(protocol::encode_log_entry(commitment));
    const auto with = [&](cbor::Value list, bool statement = true) {
        return encoded(cbor::Value::map({entry(1, cbor::Value::bytes(Bytes(32, 7))),
                                         entry(2, cbor::Value::unsigned_integer(1)),
                                         entry(statement ? 3 : 4, cbor::Value::bytes(Bytes{0xd2})),
                                         entry(5, std::move(list))}));
    };
    const auto empty = protocol::decode_log_entry(with(cbor::Value::array({})));
    REQUIRE_FALSE(empty);
    CHECK(empty.error().code == Errc::non_canonical);
    CHECK_FALSE(protocol::decode_log_entry(
        with(cbor::Value::array({cbor::Value::bytes(approvals[0])}), false)));
    CHECK_FALSE(
        protocol::decode_log_entry(with(cbor::Value::array({cbor::Value::bytes(Bytes{})}))));
    CHECK_FALSE(protocol::decode_log_entry(
        with(cbor::Value::array({cbor::Value::bytes(Bytes(protocol::max_approval_size + 1, 1))}))));
    CHECK_FALSE(protocol::decode_log_entry(with(cbor::Value::array({cbor::Value::text("x")}))));
    cbor::Array many;
    for (std::size_t i = 0; i <= protocol::max_approvals; ++i) {
        many.push_back(cbor::Value::bytes(approvals[0]));
    }
    CHECK_FALSE(protocol::decode_log_entry(with(cbor::Value::array(many))));
    many.pop_back();
    CHECK(protocol::decode_log_entry(with(cbor::Value::array(std::move(many)))));
}

// ---------------------------------------------------------------------------
// The vectors (testvectors/protocol-v0.20.json)
// ---------------------------------------------------------------------------

namespace {

const nlohmann::json& vectors() {
    static const nlohmann::json document = kanhe::test::load_vectors("protocol-v0.20.json");
    return document;
}

std::string text(const nlohmann::json& value) {
    return value.get<std::string>();
}

Bytes unhex(const nlohmann::json& value) {
    return kanhe::test::hex(text(value));
}

std::string hex_of(const protocol::Id& value) {
    return kanhe::to_hex(value.bytes());
}

std::vector<std::string> hex_list(const std::vector<protocol::Id>& ids) {
    std::vector<std::string> out;
    for (const protocol::Id& i : ids) {
        out.push_back(hex_of(i));
    }
    return out;
}

std::optional<std::vector<std::uint64_t>> listed_types(const nlohmann::json& value) {
    if (value.is_null()) {
        return std::nullopt;
    }
    return value.get<std::vector<std::uint64_t>>();
}

std::optional<std::vector<std::uint64_t>>
held_types(const std::optional<std::vector<StatementType>>& types) {
    if (!types) {
        return std::nullopt;
    }
    std::vector<std::uint64_t> out;
    for (const StatementType t : *types) {
        out.push_back(static_cast<std::uint64_t>(t));
    }
    return out;
}

/// A guardian setting's body read as a ledger reads it: inside a statement
/// payload of type 9. Nothing, if the bytes are not CBOR at all.
std::optional<Bytes> guardians_payload(const Bytes& body) {
    const auto value = cbor::decode(body);
    if (!value) {
        return std::nullopt;
    }
    return encoded(cbor::Value::map(
        {entry(0, cbor::Value::unsigned_integer(1)), entry(1, cbor::Value::unsigned_integer(9)),
         entry(2, cbor::Value::bytes(Bytes(32, 1))), entry(3, cbor::Value::bytes(Bytes(32, 1))),
         entry(5, cbor::Value::unsigned_integer(1'794'700'800'000)),
         entry(6, cbor::Value::bytes(Bytes(16, 9))), entry(7, *value)}));
}

/// The statements whose refusal this implementation makes while reading
/// them: their shape breaks a rule the decoder holds (a scope naming type
/// 9, and a guardian setting's body).
bool refused_on_reading(const std::string& why) {
    return why == "scope" || why == "guardians without presence" || why == "genesis" ||
           why == "null with types";
}

} // namespace

TEST_CASE("v0.20 vectors: approval rules, guardian settings, and approvals read and written",
          "[protocol][vectors][v020]") {
    for (const auto& c : vectors()["approval_rules"]["valid"]) {
        INFO(text(c["rule"]));
        const Bytes bytes = unhex(c["rule"]);
        const auto r = protocol::decode_approval_rule(bytes);
        INFO((r ? std::string() : std::string(r.error().detail)));
        REQUIRE(r);
        CHECK(r->needed == c["k"].get<std::uint64_t>());
        CHECK(hex_list(r->approvers) == c["approvers"].get<std::vector<std::string>>());
        CHECK(r->within == c["within_ms"].get<protocol::Timestamp>());
        CHECK(r->without_presence == c["without_presence"].get<bool>());
        CHECK(protocol::encode_approval_rule(*r) == bytes);
    }
    for (const auto& c : vectors()["approval_rules"]["refused"]) {
        INFO(text(c["name"]) + " (" + text(c["why"]) + ")");
        CHECK_FALSE(protocol::decode_approval_rule(unhex(c["rule"])));
    }

    for (const auto& c : vectors()["guardian_bodies"]["valid"]) {
        INFO(text(c["body"]));
        const Bytes body = unhex(c["body"]);
        const auto payload = guardians_payload(body);
        REQUIRE(payload);
        const auto statement = protocol::decode_payload(*payload);
        INFO((statement ? std::string() : std::string(statement.error().detail)));
        REQUIRE(statement);
        const auto* b = std::get_if<protocol::LedgerSetGuardiansBody>(&statement->body);
        REQUIRE(b != nullptr);
        CHECK(b->guardians.has_value() == !c["removes"].get<bool>());
        CHECK(held_types(b->guarded) == listed_types(c["types"]));
        // Written again, the body is the same bytes.
        const auto again = protocol::encode_payload(*statement);
        REQUIRE(again);
        CHECK(*again == *payload);
    }
    for (const auto& c : vectors()["guardian_bodies"]["refused"]) {
        INFO(text(c["name"]) + " (" + text(c["why"]) + ")");
        const auto payload = guardians_payload(unhex(c["body"]));
        CHECK((!payload || !protocol::decode_payload(*payload)));
    }

    const auto& valid = vectors()["approval_objects"]["valid"];
    const auto approval = protocol::parse_approval(unhex(valid["encoded"]));
    REQUIRE(approval);
    CHECK(*approval->envelope.payload == unhex(valid["payload"]));
    CHECK(protocol::encode_approval_payload(approval->approval) == unhex(valid["payload"]));
    for (const auto& c : vectors()["approval_objects"]["refused"]) {
        INFO(text(c["name"]) + " (" + text(c["why"]) + ")");
        CHECK_FALSE(protocol::parse_approval(unhex(c["encoded"])));
    }
}

TEST_CASE("v0.20 vectors: two logs replayed, with every rule, approval, and refusal in place",
          "[protocol][vectors][v020]") {
    for (const auto& ledger : vectors()["ledgers"]) {
        const auto hash = *crypto::hash_alg_from_cose(ledger["hash"].get<std::int64_t>());
        INFO(crypto::name(hash));
        const auto& entries = ledger["log_entries"];
        const auto& statements = ledger["statements"];
        REQUIRE(entries.size() == statements.size() + 1);
        std::multimap<std::size_t, const nlohmann::json*> refused;
        for (const auto& r : ledger["refused"]) {
            refused.emplace(r["after"].get<std::size_t>(), &r);
        }
        std::optional<protocol::LedgerState> state;
        std::size_t checked = 0;
        auto refusals = [&](std::size_t after) {
            const auto [first, last] = refused.equal_range(after);
            for (auto it = first; it != last; ++it) {
                const nlohmann::json& r = *it->second;
                const std::string why = text(r["why"]);
                INFO(text(r["name"]) + " (" + why + ")");
                ++checked;
                const auto logged = protocol::decode_log_entry(unhex(r["entry"]));
                REQUIRE(logged);
                const auto parsed = protocol::parse_statement(provider(), logged->statement, hash);
                if (refused_on_reading(why) && !parsed) {
                    continue;
                }
                INFO((parsed ? std::string() : std::string(parsed.error().detail)));
                REQUIRE(parsed);
                std::vector<protocol::SignedApproval> approvals;
                for (const Bytes& bytes : logged->approvals) {
                    const auto a = protocol::parse_approval(bytes);
                    REQUIRE(a);
                    approvals.push_back(*a);
                }
                CHECK_FALSE(state->validate(provider(), *parsed, r["at"].get<protocol::Timestamp>(),
                                            nullptr, nullptr, approvals));
            }
        };
        for (std::size_t i = 0; i < statements.size(); ++i) {
            const auto& st = statements[i];
            INFO(text(st["name"]));
            const Bytes entry_bytes = unhex(st["entry"]);
            CHECK(entry_bytes == unhex(entries[i]));
            const auto logged = protocol::decode_log_entry(entry_bytes);
            REQUIRE(logged);
            CHECK(protocol::encode_log_entry(*logged) == entry_bytes);
            const auto parsed = protocol::parse_statement(provider(), logged->statement, hash);
            REQUIRE(parsed);
            CHECK(parsed->encoded == unhex(st["encoded"]));
            CHECK(hex_of(parsed->id) == text(st["statement_id"]));
            const auto at = st["registered_at"].get<protocol::Timestamp>();
            CHECK(logged->registered_at == at);

            // Each approval as its log entry carries it.
            REQUIRE(logged->approvals.size() == st["approvals"].size());
            std::vector<protocol::SignedApproval> approvals;
            for (std::size_t j = 0; j < logged->approvals.size(); ++j) {
                const auto& want = st["approvals"][j];
                CHECK(logged->approvals[j] == unhex(want["encoded"]));
                const auto a = protocol::parse_approval(logged->approvals[j]);
                REQUIRE(a);
                CHECK(*a->envelope.payload == unhex(want["payload"]));
                CHECK(hex_of(a->approval.approver) == text(want["approver"]));
                CHECK(hex_of(a->kid) == text(want["kid"]));
                CHECK(a->approval.presence.has_value() == !want["presence"].is_null());
                if (want.contains("challenge") && !want["challenge"].is_null()) {
                    CHECK(protocol::approval_challenge(provider(), hash, a->approval, a->kid) ==
                          unhex(want["challenge"]));
                }
                approvals.push_back(*a);
            }

            if (i == 0) {
                CHECK(hex_of(parsed->id) == text(ledger["ledger_id"]));
                CHECK(approvals.empty());
                auto genesis = protocol::LedgerState::from_genesis(provider(), *parsed, at);
                REQUIRE(genesis);
                state.emplace(std::move(*genesis));
                continue;
            }
            refusals(i);
            protocol::Validation validation;
            const auto valid =
                state->validate(provider(), *parsed, at, nullptr, &validation, approvals);
            INFO((valid ? std::string() : std::string(valid.error().detail)));
            REQUIRE(valid);

            // The rules that applied, in section 5.1's order, and what
            // counted for each.
            const protocol::ApprovalTally* tally = validation.approvals();
            const auto& rules = st["rules"];
            REQUIRE((tally != nullptr) == !rules.empty());
            if (tally != nullptr) {
                REQUIRE(tally->rules.size() == rules.size());
                for (std::size_t k = 0; k < rules.size(); ++k) {
                    const protocol::RuleTally& got = tally->rules[k];
                    const auto& want = rules[k];
                    CHECK(protocol::name(got.applied.source) == text(want["source"]));
                    CHECK(
                        (got.applied.delegation ? hex_of(*got.applied.delegation)
                                                : std::string()) ==
                        (want["delegation"].is_null() ? std::string() : text(want["delegation"])));
                    CHECK(got.applied.rule.needed == want["k"].get<std::uint64_t>());
                    CHECK(hex_list(got.applied.rule.approvers) ==
                          want["approvers"].get<std::vector<std::string>>());
                    CHECK(got.applied.rule.within == want["within_ms"].get<protocol::Timestamp>());
                    CHECK(got.applied.rule.without_presence ==
                          want["without_presence"].get<bool>());
                    CHECK(got.signer_counts == want["signer_counted"].get<bool>());
                    CHECK(got.counted.size() == want["count"].get<std::size_t>());
                }
                REQUIRE(tally->approvals.size() == approvals.size());
                for (std::size_t j = 0; j < approvals.size(); ++j) {
                    const auto& want = st["approvals"][j];
                    const protocol::ApprovalCheck& got = tally->approvals[j];
                    CHECK(got.presence.has_value() == !want["presence"].is_null());
                    if (got.presence) {
                        CHECK((got.presence->method == protocol::PresenceMethod::hardware_key
                                   ? "hardware-key"
                                   : "webauthn") == text(want["presence"]));
                    }
                    std::vector<std::size_t> counted_for;
                    for (std::size_t k = 0; k < tally->rules.size(); ++k) {
                        if (std::ranges::contains(tally->rules[k].counted, got.approver)) {
                            counted_for.push_back(k);
                        }
                    }
                    CHECK(counted_for == want["counted_for"].get<std::vector<std::size_t>>());
                }
            }
            REQUIRE(state->apply(provider(), *parsed, i, at, &validation));
        }
        refusals(statements.size());
        CHECK(checked == ledger["refused"].size());

        for (const auto& m : ledger["malformed"]) {
            INFO(text(m["name"]) + " (" + text(m["why"]) + ")");
            CHECK_FALSE(protocol::parse_statement(provider(), unhex(m["encoded"]), hash));
        }
        for (const auto& m : ledger["malformed_entries"]) {
            INFO(text(m["name"]) + " (" + text(m["why"]) + ")");
            CHECK_FALSE(protocol::decode_log_entry(unhex(m["entry"])));
        }
        // A genesis entry with approvals reads as a log entry; a ledger and
        // a verifier refuse it (tests/ledger/approvals_test.cpp).
        const auto genesis_with =
            protocol::decode_log_entry(unhex(ledger["genesis_with_approvals"]));
        REQUIRE(genesis_with);
        CHECK_FALSE(genesis_with->approvals.empty());

        // Who is who.
        for (const auto& [name, actor] : ledger["actors"].items()) {
            INFO(name);
            const protocol::ActorState* a = state->actor(*protocol::to_id(unhex(actor)));
            REQUIRE(a != nullptr);
            CHECK(a->display_name == name);
        }
        for (const auto& [name, delegation] : ledger["delegations"].items()) {
            INFO(name);
            CHECK(state->delegation(*protocol::to_id(unhex(delegation))) != nullptr);
        }

        // The guardian settings, in log order, and the guardians in effect.
        const auto settings = state->guardian_settings();
        REQUIRE(settings.size() == ledger["guardian_settings"].size());
        for (std::size_t k = 0; k < settings.size(); ++k) {
            const auto& want = ledger["guardian_settings"][k];
            const protocol::GuardianSetting& got = settings[k];
            CHECK(got.index == want["index"].get<std::uint64_t>());
            CHECK(got.guardians.has_value() == !want["removes"].get<bool>());
            if (got.guardians) {
                CHECK(got.guardians->needed == want["k"].get<std::uint64_t>());
                CHECK(hex_list(got.guardians->approvers) ==
                      want["guardians"].get<std::vector<std::string>>());
                CHECK(got.guardians->within == want["within_ms"].get<protocol::Timestamp>());
            }
            CHECK(held_types(got.guarded) == listed_types(want["types"]));
            CHECK(statements[got.index]["registered_at"].get<protocol::Timestamp>() ==
                  want["registered_at"].get<protocol::Timestamp>());
        }
        const auto& in_effect = ledger["guardians_in_effect"];
        CHECK((state->guardians() == nullptr) == in_effect.is_null());
        if (state->guardians() != nullptr && in_effect.is_object() && in_effect.contains("index")) {
            CHECK(state->guardians()->index == in_effect["index"].get<std::uint64_t>());
        }

        // The state, with the organization's leaf listing the guardian
        // settings, and the commitment and checkpoint over the whole log.
        const auto leaves = protocol::state_leaves(*state);
        REQUIRE(leaves.size() == ledger["state_leaves"].size());
        std::map<std::string, const protocol::StateLeaf*> by_id;
        for (const protocol::StateLeaf& leaf : leaves) {
            by_id.emplace(hex_of(leaf.id), &leaf);
        }
        for (const auto& want : ledger["state_leaves"]) {
            INFO(text(want["id"]));
            const auto found = by_id.find(text(want["id"]));
            REQUIRE(found != by_id.end());
            CHECK(static_cast<int>(found->second->kind) == want["kind"].get<int>());
            CHECK(found->second->history == want["history"].get<std::vector<std::uint64_t>>());
        }
        const auto root = protocol::state_root(provider(), hash, leaves);
        REQUIRE(root);
        CHECK(hex_of(*root) == text(ledger["state_root"]));

        const std::size_t commitment_index = ledger["state_commitment"]["index"].get<std::size_t>();
        REQUIRE(commitment_index == entries.size() - 1);
        const auto commitment_entry = protocol::decode_log_entry(unhex(entries[commitment_index]));
        REQUIRE(commitment_entry);
        REQUIRE(commitment_entry->is_state_commitment());
        const auto commitment =
            protocol::parse_state_commitment(provider(), commitment_entry->state_commitment);
        REQUIRE(commitment);
        CHECK(hex_of(commitment->id) == text(ledger["state_commitment"]["id"]));
        CHECK(protocol::check_state_commitment(provider(), *state, *commitment, commitment_index));

        const auto checkpoint = protocol::parse_checkpoint(unhex(ledger["checkpoint"]));
        REQUIRE(checkpoint);
        CHECK(checkpoint->checkpoint.tree_size == entries.size());
        CHECK(checkpoint->checkpoint.timestamp ==
              ledger["checkpoint_time"].get<protocol::Timestamp>());
        CHECK(protocol::verify_checkpoint(provider(), *checkpoint,
                                          state->log_key_for(checkpoint->checkpoint.tree_size)));
        kanhe::merkle::Tree tree(provider(), hash);
        for (const auto& e : entries) {
            REQUIRE(tree.append(unhex(e)));
        }
        CHECK(*tree.root() == checkpoint->checkpoint.root);
    }
}
