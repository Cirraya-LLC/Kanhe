// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// Spec v0.22 objects: provable values (registration key 8), values read as
// integers in each encoding with their commitments, bounds, statements in
// words, transcripts and their public values, range openings files, and
// range proofs (bundle key 12); then the vectors of
// testvectors/protocol-v0.22.json, made apart from this implementation: a
// registry's log replayed with its refusals, and every bundle verified with
// its options, reaching its verdict and, when verified, the facts its report
// must show. Proofs of system 1 are checked with Longfellow ZK where the
// build has it (KANHE_TEST_RANGE_PROOFS); the cases that need its arithmetic
// are then run, and every proof is also reported as not checked without it.

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <map>
#include <string>
#include <utility>
#include <variant>
#include <vector>

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>

#include <kanhe/core/cbor.hpp>
#include <kanhe/core/protocol/contract_evidence.hpp>
#include <kanhe/core/protocol/evidence.hpp>
#include <kanhe/core/protocol/log.hpp>
#include <kanhe/core/protocol/ranges.hpp>
#include <kanhe/core/protocol/state.hpp>
#include <kanhe/core/protocol/statement.hpp>
#include <kanhe/crypto/openssl.hpp>
#include <kanhe/verifier/report.hpp>
#if defined(KANHE_TEST_RANGE_PROOFS)
#include <kanhe/crypto/longfellow.hpp>
#endif

#include "support/vectors.hpp"

namespace protocol = kanhe::protocol;
namespace crypto = kanhe::crypto;
namespace cbor = kanhe::cbor;
using kanhe::Bytes;
using kanhe::Errc;
using kanhe::to_hex;
using kanhe::test::hex;
using kanhe::test::load_vectors;

namespace {

const crypto::Provider& provider() {
    static const crypto::openssl::Provider instance;
    return instance;
}

const nlohmann::json& vectors() {
    static const nlohmann::json document = load_vectors("protocol-v0.22.json");
    return document;
}

std::string text(const nlohmann::json& value) {
    return value.get<std::string>();
}

protocol::Id id_of(const nlohmann::json& value) {
    auto id = protocol::to_id(hex(text(value)));
    REQUIRE(id);
    return *id;
}

cbor::Value decoded(const nlohmann::json& hex_text) {
    auto value = cbor::decode(hex(text(hex_text)));
    REQUIRE(value);
    return *value;
}

/// A JSON value of the vectors as CBOR: integers, text, arrays, booleans,
/// and null. A JSON integer below -2^63 is one nlohmann reads as floating
/// point: the vectors hold one, -2^63 - 1, out of range whatever it is.
cbor::Value cbor_of(const nlohmann::json& j) {
    if (j.is_null()) {
        return cbor::Value::null();
    }
    if (j.is_boolean()) {
        return cbor::Value::boolean(j.get<bool>());
    }
    if (j.is_number_unsigned()) {
        return cbor::Value::unsigned_integer(j.get<std::uint64_t>());
    }
    if (j.is_number_integer()) {
        return cbor::Value::integer(j.get<std::int64_t>());
    }
    if (j.is_number_float()) {
        REQUIRE(j.get<double>() <= -9.2233720368547758e18);
        return cbor::Value::negative(std::uint64_t{1} << 63);
    }
    if (j.is_string()) {
        return cbor::Value::text(j.get<std::string>());
    }
    REQUIRE(j.is_array());
    cbor::Array items;
    for (const auto& item : j) {
        items.push_back(cbor_of(item));
    }
    return cbor::Value::array(std::move(items));
}

protocol::ProvableEncoding encoding_of(const nlohmann::json& j) {
    auto encoding = protocol::provable_encoding_from(cbor_of(j));
    REQUIRE(encoding);
    return *encoding;
}

/// The report's JSON of an encoding, as the vectors give it.
nlohmann::json encoding_fact(const protocol::ProvableEncoding& e) {
    using Type = protocol::ProvableEncoding::Type;
    nlohmann::json out;
    out["type"] = std::string(protocol::name(e.type));
    out["scale"] = e.type == Type::date ? nlohmann::json(nullptr) : nlohmann::json(e.scale);
    out["currency"] = e.type == Type::money ? nlohmann::json(e.currency) : nlohmann::json(nullptr);
    return out;
}

/// A bundle that decode_bundle reads up to `key` (its entries are only
/// shaped, not checked, when decoded).
Bytes bundle_with(std::int64_t key, cbor::Value value) {
    cbor::Map map{
        {cbor::Value::integer(0), cbor::Value::unsigned_integer(1)},
        {cbor::Value::integer(1), cbor::Value::bytes(Bytes(32, 0))},
        {cbor::Value::integer(2),
         cbor::Value::array(
             {cbor::Value::array({cbor::Value::bytes(Bytes{0}), cbor::Value::bytes(Bytes{0})})})},
        {cbor::Value::integer(3), cbor::Value::bytes(Bytes{0})},
        {cbor::Value::integer(key), std::move(value)},
    };
    auto encoded = cbor::encode(cbor::Value::map(std::move(map)));
    REQUIRE(encoded);
    return *encoded;
}

/// A registration's statement payload with this body (key 7), signed by
/// nobody: what decode_payload reads.
Bytes registration_payload(cbor::Map body) {
    cbor::Map map{
        {cbor::Value::integer(0), cbor::Value::unsigned_integer(1)},
        {cbor::Value::integer(1), cbor::Value::unsigned_integer(16)},
        {cbor::Value::integer(2), cbor::Value::bytes(Bytes(32, 0x11))},
        {cbor::Value::integer(3), cbor::Value::bytes(Bytes(32, 0x22))},
        {cbor::Value::integer(5), cbor::Value::unsigned_integer(1'792'454'820'000)},
        {cbor::Value::integer(6), cbor::Value::bytes(Bytes(16, 0x33))},
        {cbor::Value::integer(7), cbor::Value::map(std::move(body))},
    };
    auto encoded = cbor::encode(cbor::Value::map(std::move(map)));
    REQUIRE(encoded);
    return *encoded;
}

cbor::Map registration_body(std::uint64_t field_count) {
    return {{cbor::Value::integer(1), cbor::Value::text("example.org.certificate/1")},
            {cbor::Value::integer(2), cbor::Value::bytes(Bytes(32, 0x44))},
            {cbor::Value::integer(3), cbor::Value::unsigned_integer(field_count)}};
}

/// As tests/verifiers/conformance.py matches a case's facts: an object
/// matches when each of its keys is in the report with a matching value, a
/// list one of the same length element by element, anything else an equal
/// value.
bool matches(const nlohmann::json& fact, const nlohmann::json& value, const std::string& path,
             std::string& where) {
    if (fact.is_object()) {
        if (!value.is_object()) {
            where = path;
            return false;
        }
        for (const auto& [key, item] : fact.items()) {
            if (!value.contains(key) || !matches(item, value[key], path + "." + key, where)) {
                if (where.empty()) {
                    where = path + "." + key;
                }
                return false;
            }
        }
        return true;
    }
    if (fact.is_array()) {
        if (!value.is_array() || value.size() != fact.size()) {
            where = path;
            return false;
        }
        for (std::size_t i = 0; i < fact.size(); ++i) {
            if (!matches(fact[i], value[i], path + "[" + std::to_string(i) + "]", where)) {
                return false;
            }
        }
        return true;
    }
    if (fact.is_boolean() != value.is_boolean() || fact != value) {
        where = path + ": " + value.dump() + ", not " + fact.dump();
        return false;
    }
    return true;
}

/// This build's system 1, if it has one.
protocol::RangeVerifier system_one() {
#if defined(KANHE_TEST_RANGE_PROOFS)
    return [](kanhe::ByteView c, std::uint64_t lo, std::uint64_t hi, kanhe::ByteView t,
              kanhe::ByteView proof) {
        return crypto::longfellow::verify_range(c, lo, hi, t, proof);
    };
#else
    return {};
#endif
}

/// The options a bundle's vector names, as `kanhe verify` reads them.
protocol::VerifyOptions options_of(const nlohmann::json& o, protocol::RangeVerifier verifier) {
    protocol::VerifyOptions options;
    if (o.contains("ledger_id")) {
        options.expected_ledger = id_of(o["ledger_id"]);
    }
    if (o.contains("range_context")) {
        options.range_context = hex(text(o["range_context"]));
    }
    options.range_verifier = std::move(verifier);
    return options;
}

} // namespace

TEST_CASE("v0.22 provable values: key 8 read, written the same again, and refused",
          "[protocol][vectors][v022]") {
    for (const auto& c : vectors()["provable"]["valid"]) {
        INFO(text(c["name"]));
        const Bytes encoded = hex(text(c["provable"]));
        const auto field_count = c["field_count"].get<std::uint64_t>();
        const auto values = protocol::provable_list_from(*cbor::decode(encoded), field_count);
        INFO((values ? std::string() : std::string(values.error().detail)));
        REQUIRE(values);
        REQUIRE(values->size() == c["entries"].size());
        for (std::size_t i = 0; i < values->size(); ++i) {
            const auto& e = c["entries"][i];
            CHECK((*values)[i].name == text(e["name"]));
            CHECK(encoding_fact((*values)[i].encoding) == e["encoding"]);
            CHECK(to_hex((*values)[i].commitment) == text(e["commitment"]));
        }
        const auto again = protocol::provable_list_value(*values, field_count);
        REQUIRE(again);
        CHECK(*cbor::encode(*again) == encoded);
        // In a registration, read and written the same again.
        cbor::Map body = registration_body(field_count);
        body.push_back({cbor::Value::integer(8), *cbor::decode(encoded)});
        const Bytes payload = registration_payload(std::move(body));
        const auto statement = protocol::decode_payload(payload);
        INFO((statement ? std::string() : std::string(statement.error().detail)));
        REQUIRE(statement);
        const auto* registration = std::get_if<protocol::RecordRegisterBody>(&statement->body);
        REQUIRE(registration != nullptr);
        CHECK(registration->provable == *values);
        CHECK(*protocol::encode_payload(*statement) == payload);
        // One field fewer than entries: refused both ways.
        if (field_count == values->size()) {
            protocol::Statement fewer = *statement;
            std::get<protocol::RecordRegisterBody>(fewer.body).field_count = field_count - 1;
            CHECK_FALSE(protocol::encode_payload(fewer));
        }
    }
    for (const auto& c : vectors()["provable"]["refused"]) {
        INFO(text(c["name"]));
        const auto field_count = c["field_count"].get<std::uint64_t>();
        const cbor::Value value = decoded(c["provable"]);
        CHECK_FALSE(protocol::provable_list_from(value, field_count));
        cbor::Map body = registration_body(field_count);
        body.push_back({cbor::Value::integer(8), value});
        CHECK_FALSE(protocol::decode_payload(registration_payload(std::move(body))));
    }

    // Writing refuses what reading refuses.
    const protocol::ProvableValue age{"age", {}, Bytes(32, 1)};
    CHECK(protocol::check_provable(std::vector{age}, 1));
    CHECK_FALSE(protocol::check_provable({}, 1));
    CHECK_FALSE(protocol::check_provable(std::vector{age}, 0));
    CHECK_FALSE(protocol::check_provable(std::vector{age, age}, 2));
    protocol::ProvableValue bad = age;
    bad.commitment.pop_back();
    CHECK_FALSE(protocol::check_provable(std::vector{bad}, 1));
    bad = age;
    bad.name = std::string(65, 'n');
    CHECK_FALSE(protocol::check_provable(std::vector{bad}, 1));
    bad = age;
    bad.encoding.scale = 19;
    CHECK_FALSE(protocol::check_provable(std::vector{bad}, 1));
    bad = age;
    bad.encoding = {protocol::ProvableEncoding::Type::money, 5, "HKD"};
    CHECK_FALSE(protocol::check_provable(std::vector{bad}, 1));
    bad.encoding = {protocol::ProvableEncoding::Type::money, 2, "HKd"};
    CHECK_FALSE(protocol::check_provable(std::vector{bad}, 1));
    bad.encoding = {protocol::ProvableEncoding::Type::date, 1, ""};
    CHECK_FALSE(protocol::check_provable(std::vector{bad}, 1));
    bad.encoding = {protocol::ProvableEncoding::Type::number, 2, "HKD"};
    CHECK_FALSE(protocol::check_provable(std::vector{bad}, 1));

    // A registration without key 8 encodes as before.
    protocol::RecordRegisterBody plain;
    plain.record_type = "example.org.certificate/1";
    plain.field_root = Bytes(32, 0x44);
    plain.field_count = 2;
    protocol::Statement s;
    s.ledger_id = *protocol::to_id(Bytes(32, 0x11));
    s.actor_id = *protocol::to_id(Bytes(32, 0x22));
    s.issued_at = 1'792'454'820'000;
    s.body = plain;
    const auto without = protocol::encode_payload(s);
    REQUIRE(without);
    CHECK(protocol::decode_payload(*without)->body == s.body);
    plain.provable = {{"b", {protocol::ProvableEncoding::Type::date, 0, ""}, Bytes(32, 2)},
                      {"a", {}, Bytes(32, 3)}};
    s.body = plain;
    CHECK_FALSE(protocol::encode_payload(s)); // not ascending
    std::swap(plain.provable[0], plain.provable[1]);
    s.body = plain;
    const auto with = protocol::encode_payload(s);
    REQUIRE(with);
    CHECK(protocol::decode_payload(*with)->body == s.body);
    CHECK(with->size() > without->size());
}

TEST_CASE("v0.22 values: read as x in each encoding, with v and the commitment",
          "[protocol][vectors][v022]") {
    for (const auto& c : vectors()["values"]) {
        INFO(c["encoding"].dump() + " " + c["value"].dump());
        const auto encoding = encoding_of(c["encoding"]);
        const auto x = protocol::range_bound_x(encoding, cbor_of(c["value"]));
        INFO((x ? std::string() : std::string(x.error().detail)));
        REQUIRE(x);
        CHECK(*x == c["x"].get<std::int64_t>());
        CHECK(std::to_string(protocol::range_v(*x)) == text(c["v"]));
        const auto commitment = protocol::range_commitment(provider(), hex(text(c["salt"])), *x);
        REQUIRE(commitment);
        CHECK(to_hex(*commitment) == text(c["commitment"]));
    }
    // v = x + 2^63, which orders as x does.
    static_assert(protocol::range_v(std::numeric_limits<std::int64_t>::min()) == 0);
    static_assert(protocol::range_v(-1) == (std::uint64_t{1} << 63) - 1);
    static_assert(protocol::range_v(0) == std::uint64_t{1} << 63);
    static_assert(protocol::range_v(std::numeric_limits<std::int64_t>::max()) ==
                  std::numeric_limits<std::uint64_t>::max());
    // The salt is 32 bytes, never a field's 16.
    CHECK(protocol::range_commitment(provider(), Bytes(16, 1), 0).error().code ==
          Errc::invalid_argument);
    // The commitment is SHA-256 over the 14 bytes of domain, s, and BE64(v).
    const Bytes salt(32, 7);
    Bytes message(protocol::range_commitment_domain.begin(),
                  protocol::range_commitment_domain.end());
    message.insert(message.end(), salt.begin(), salt.end());
    const Bytes v{0x80, 0, 0, 0, 0, 0, 0, 0x2a};
    message.insert(message.end(), v.begin(), v.end());
    REQUIRE(message.size() == 54);
    const auto digest = provider().digest(crypto::HashAlg::sha256, message);
    REQUIRE(digest);
    const kanhe::ByteView c = digest->bytes();
    CHECK(Bytes(c.begin(), c.end()) == *protocol::range_commitment(provider(), salt, 42));
}

TEST_CASE("v0.22 bounds: refused in an encoding, each for its rule", "[protocol][vectors][v022]") {
    for (const auto& c : vectors()["bounds"]["refused"]) {
        INFO(text(c["name"]) + ": " + c["encoding"].dump() + " " + c["bound"].dump());
        const auto x = protocol::range_bound_x(encoding_of(c["encoding"]), cbor_of(c["bound"]));
        REQUIRE_FALSE(x);
        CHECK(x.error().code == Errc::malformed);
    }
    // At scale 2, "18.5", "18.50", and "0018.50" are all 1850, the integer 18
    // is 1800, and "-0" is 0.
    const protocol::ProvableEncoding two{protocol::ProvableEncoding::Type::number, 2, ""};
    for (const cbor::Value& v :
         {cbor::Value::text("18.5"), cbor::Value::text("18.50"), cbor::Value::text("0018.50")}) {
        CHECK(protocol::range_bound_x(two, v) == 1850);
    }
    CHECK(protocol::range_bound_x(two, cbor::Value::unsigned_integer(18)) == 1800);
    CHECK(protocol::range_bound_x(two, cbor::Value::text("18")) == 1800);
    CHECK(protocol::range_bound_x(two, cbor::Value::text("-0")) == 0);
    CHECK(protocol::range_bound_x(two, cbor::Value::text("-0.01")) == -1);
    // The ends of the range at scale 0, and one past each.
    const protocol::ProvableEncoding zero{};
    CHECK(protocol::range_bound_x(zero, cbor::Value::text("-9223372036854775808")) ==
          std::numeric_limits<std::int64_t>::min());
    CHECK_FALSE(protocol::range_bound_x(zero, cbor::Value::text("-9223372036854775809")));
    CHECK(protocol::range_bound_x(zero, cbor::Value::text("9223372036854775807")) ==
          std::numeric_limits<std::int64_t>::max());
    CHECK_FALSE(protocol::range_bound_x(zero, cbor::Value::text("9223372036854775808")));
    CHECK_FALSE(protocol::range_bound_x(
        zero, cbor::Value::negative(std::numeric_limits<std::uint64_t>::max())));
    CHECK_FALSE(
        protocol::range_bound_x(zero, cbor::Value::text("99999999999999999999999999999999999999")));
    for (const char* refused : {"-", "1.", ".1", "1.2.3", "1,000", " 1", "1 ", "--1", "0x10"}) {
        INFO(refused);
        CHECK_FALSE(protocol::range_bound_x(zero, cbor::Value::text(refused)));
    }
    // Money's amount at the ends; a date's days at its ends.
    const protocol::ProvableEncoding hkd{protocol::ProvableEncoding::Type::money, 2, "HKD"};
    auto money = [](cbor::Value amount, const char* currency, std::uint64_t scale) {
        return cbor::Value::array(
            {std::move(amount), cbor::Value::text(currency), cbor::Value::unsigned_integer(scale)});
    };
    CHECK(protocol::range_bound_x(hkd, money(cbor::Value::integer(-5), "HKD", 2)) == -5);
    CHECK_FALSE(protocol::range_bound_x(hkd, money(cbor::Value::integer(-5), "HKD", 5)));
    CHECK_FALSE(protocol::range_bound_x(hkd, money(cbor::Value::text("5"), "HKD", 2)));
    CHECK_FALSE(protocol::range_bound_x(
        hkd, money(cbor::Value::negative(std::uint64_t{1} << 63), "HKD", 2)));
    const protocol::ProvableEncoding date{protocol::ProvableEncoding::Type::date, 0, ""};
    CHECK(protocol::range_bound_x(date, cbor::Value::text("0001-01-01")) == -719'162);
    CHECK(protocol::range_bound_x(date, cbor::Value::text("9999-12-31")) == 2'932'896);
    CHECK(protocol::range_bound_x(date, cbor::Value::text("1600-02-29")) == -135'081);
    CHECK_FALSE(protocol::range_bound_x(date, cbor::Value::text("1900-02-29")));
    CHECK_FALSE(protocol::range_bound_x(date, cbor::Value::text("2026-04-31")));
    CHECK_FALSE(protocol::range_bound_x(date, cbor::Value::text("2026-00-10")));
    CHECK_FALSE(protocol::range_bound_x(date, cbor::Value::text("2026-01-1a")));

    // The public values: lo' 0 without a low, hi' 2^64 - 1 without a high,
    // and neither bound, or a low above the high, refused.
    protocol::RangeProof p;
    p.field = "score";
    p.proof = Bytes{1};
    CHECK_FALSE(protocol::range_public_values(zero, p));
    p.low = cbor::Value::integer(-1);
    CHECK(protocol::range_public_values(zero, p) ==
          std::pair{protocol::range_v(-1), std::numeric_limits<std::uint64_t>::max()});
    p.high = cbor::Value::integer(-2);
    CHECK_FALSE(protocol::range_public_values(zero, p));
    p.high = cbor::Value::integer(-1);
    CHECK(protocol::range_public_values(zero, p) ==
          std::pair{protocol::range_v(-1), protocol::range_v(-1)});
    p.low.reset();
    CHECK(protocol::range_public_values(zero, p) ==
          std::pair{std::uint64_t{0}, protocol::range_v(-1)});
    p.high = cbor::Value::text("1.5");
    CHECK_FALSE(protocol::range_public_values(zero, p));
}

TEST_CASE("v0.22 statements in words", "[protocol][vectors][v022]") {
    for (const auto& c : vectors()["words"]) {
        INFO(text(c["text"]));
        protocol::RangeProof p;
        p.field = text(c["field"]);
        if (!c["low"].is_null()) {
            p.low = cbor_of(c["low"]);
        }
        if (!c["high"].is_null()) {
            p.high = cbor_of(c["high"]);
        }
        CHECK(protocol::range_words(encoding_of(c["encoding"]), p) == text(c["text"]));
    }
    // Bounds the encoding does not read are written as they are.
    protocol::RangeProof p;
    p.field = "level";
    p.low = cbor::Value::text("1.5");
    CHECK(protocol::range_words({}, p) == "level is at least \"1.5\"");
}

TEST_CASE("v0.22 transcripts and their public values", "[protocol][vectors][v022]") {
    for (const auto& c : vectors()["transcripts"]) {
        INFO(text(c["field"]) + " " + c["low_bound"].dump() + " " + c["high_bound"].dump());
        const auto encoding = encoding_of(c["encoding"]);
        const auto lo = std::stoull(text(c["low"]));
        const auto hi = std::stoull(text(c["high"]));
        if (!c["low_bound"].is_null() || !c["high_bound"].is_null()) {
            protocol::RangeProof p;
            p.field = text(c["field"]);
            p.proof = Bytes{1};
            if (!c["low_bound"].is_null()) {
                p.low = cbor_of(c["low_bound"]);
            }
            if (!c["high_bound"].is_null()) {
                p.high = cbor_of(c["high_bound"]);
            }
            const auto values = protocol::range_public_values(encoding, p);
            REQUIRE(values);
            CHECK(values->first == lo);
            CHECK(values->second == hi);
        }
        const Bytes context = c["context"].is_null() ? Bytes() : hex(text(c["context"]));
        const Bytes transcript =
            protocol::range_transcript(id_of(c["ledger"]), id_of(c["record"]), text(c["field"]),
                                       hex(text(c["commitment"])), lo, hi, context);
        CHECK(to_hex(transcript) == text(c["transcript"]));
        // It is the deterministic encoding of the array the CDDL gives.
        const auto value = cbor::decode(transcript);
        REQUIRE(value);
        REQUIRE(value->as_array() != nullptr);
        CHECK(value->as_array()->size() == 8);
        CHECK(*value->as_array()->front().as_text() == protocol::range_transcript_label);
        CHECK(*cbor::encode(*value) == transcript);
    }
}

TEST_CASE("v0.22 range openings files: read, written the same again, and refused",
          "[protocol][vectors][v022]") {
    for (const auto& c : vectors()["openings"]["valid"]) {
        const Bytes encoded = hex(text(c["file"]));
        const auto file = protocol::decode_range_openings(encoded);
        INFO((file ? std::string() : std::string(file.error().detail)));
        REQUIRE(file);
        CHECK(to_hex(file->ledger.bytes()) == text(c["ledger"]));
        CHECK(to_hex(file->record.bytes()) == text(c["record"]));
        REQUIRE(file->openings.size() == c["openings"].size());
        for (std::size_t i = 0; i < file->openings.size(); ++i) {
            const auto& o = c["openings"][i];
            const protocol::RangeOpening& opening = file->openings[i];
            CHECK(opening.name == text(o["name"]));
            CHECK(to_hex(opening.salt) == text(o["salt"]));
            CHECK(opening.x == o["x"].get<std::int64_t>());
            CHECK(to_hex(*protocol::range_commitment(provider(), opening.salt, opening.x)) ==
                  text(o["commitment"]));
        }
        const auto again = protocol::encode_range_openings(*file);
        REQUIRE(again);
        CHECK(*again == encoded);
    }
    for (const auto& c : vectors()["openings"]["refused"]) {
        INFO(text(c["name"]));
        CHECK_FALSE(protocol::decode_range_openings(hex(text(c["file"]))));
    }
    // Writing refuses what reading refuses; a file larger than 65,536 bytes
    // is refused unread.
    protocol::RangeOpenings file{
        *protocol::to_id(Bytes(32, 1)), *protocol::to_id(Bytes(32, 2)), {}};
    CHECK_FALSE(protocol::encode_range_openings(file));
    file.openings = {{"b", Bytes(32, 3), 1}, {"a", Bytes(32, 4), 2}};
    CHECK_FALSE(protocol::encode_range_openings(file));
    std::swap(file.openings[0], file.openings[1]);
    const auto ok = protocol::encode_range_openings(file);
    REQUIRE(ok);
    CHECK(*protocol::decode_range_openings(*ok) == file);
    file.openings[0].salt.pop_back();
    CHECK_FALSE(protocol::encode_range_openings(file));
    file.openings[0].salt.push_back(0);
    file.openings[0].x = std::numeric_limits<std::int64_t>::min();
    file.openings[1].x = std::numeric_limits<std::int64_t>::max();
    CHECK(*protocol::decode_range_openings(*protocol::encode_range_openings(file)) == file);
    CHECK(protocol::decode_range_openings(Bytes(protocol::max_range_openings_file + 1, 0))
              .error()
              .code == Errc::limit_exceeded);
}

TEST_CASE("v0.22 range proofs: key 12 read, written the same again, and refused",
          "[protocol][v022]") {
    protocol::RangeProof p;
    p.field = "score";
    p.low = cbor::Value::integer(60);
    p.high = cbor::Value::text("99.5");
    p.proof = Bytes(100, 9);
    p.context = Bytes(16, 1);
    const auto value = protocol::range_proof_value(p);
    REQUIRE(value);
    CHECK(protocol::range_proof_from(*value) == p);
    // In a bundle, too, up to 16.
    protocol::EvidenceBundle bundle;
    bundle.entries.push_back({Bytes{0}, Bytes{0}});
    bundle.record = *protocol::to_id(Bytes(32, 0));
    bundle.checkpoint = Bytes{0};
    bundle.range_proofs.assign(protocol::max_range_proofs, p);
    const auto encoded = protocol::encode_bundle(bundle);
    REQUIRE(encoded);
    CHECK(*protocol::decode_bundle(*encoded) == bundle);
    bundle.range_proofs.push_back(p);
    CHECK_FALSE(protocol::encode_bundle(bundle));
    cbor::Array seventeen(17, *value);
    CHECK_FALSE(protocol::decode_bundle(bundle_with(12, cbor::Value::array(std::move(seventeen)))));
    CHECK_FALSE(protocol::decode_bundle(bundle_with(12, cbor::Value::array({}))));
    CHECK(protocol::decode_bundle(bundle_with(12, cbor::Value::array({*value}))));

    // Each refusal of the CDDL, both ways.
    auto refused = [](protocol::RangeProof q) {
        CHECK_FALSE(protocol::check_range_proof(q));
        CHECK_FALSE(protocol::range_proof_value(q));
    };
    protocol::RangeProof q = p;
    q.low.reset();
    q.high.reset();
    refused(q);
    q = p;
    q.low = cbor::Value::null();
    refused(q);
    q = p;
    q.field.clear();
    refused(q);
    q.field = std::string(65, 'f');
    refused(q);
    q = p;
    q.proof.clear();
    refused(q);
    q.proof.assign(protocol::max_range_proof_size + 1, 1);
    refused(q);
    q = p;
    q.context = Bytes();
    refused(q);
    q.context = Bytes(65, 1);
    refused(q);
    // Read: a map with integer keys 1 to 6, keys 1, 4, and 5 required.
    auto map_of = [&](std::vector<std::pair<std::int64_t, cbor::Value>> entries) {
        cbor::Map map;
        for (auto& [k, v] : entries) {
            map.push_back({cbor::Value::integer(k), std::move(v)});
        }
        return cbor::Value::map(std::move(map));
    };
    CHECK(protocol::range_proof_from(map_of({{1, cbor::Value::text("a")},
                                             {3, cbor::Value::integer(1)},
                                             {4, cbor::Value::unsigned_integer(7)},
                                             {5, cbor::Value::bytes(Bytes{1})}})));
    CHECK_FALSE(protocol::range_proof_from(map_of({{1, cbor::Value::text("a")},
                                                   {3, cbor::Value::integer(1)},
                                                   {4, cbor::Value::integer(-1)},
                                                   {5, cbor::Value::bytes(Bytes{1})}})));
    CHECK_FALSE(protocol::range_proof_from(map_of({{1, cbor::Value::text("a")},
                                                   {3, cbor::Value::integer(1)},
                                                   {4, cbor::Value::integer(1)}})));
    CHECK_FALSE(protocol::range_proof_from(map_of({{1, cbor::Value::text("a")},
                                                   {3, cbor::Value::integer(1)},
                                                   {4, cbor::Value::integer(1)},
                                                   {5, cbor::Value::bytes(Bytes{1})},
                                                   {7, cbor::Value::boolean(true)}})));
    CHECK_FALSE(protocol::range_proof_from(cbor::Value::array({})));
}

TEST_CASE("v0.22 a registry's log: provable values taken, and refused on a mechanism type",
          "[protocol][vectors][v022]") {
    const auto& lg = vectors()["ledger"];
    const auto hash = *crypto::hash_alg_from_cose(lg["hash"].get<std::int64_t>());
    std::vector<protocol::LogEntry> entries;
    for (const auto& e : lg["log_entries"]) {
        auto entry = protocol::decode_log_entry(hex(text(e)));
        REQUIRE(entry);
        entries.push_back(std::move(*entry));
    }
    const auto genesis = protocol::parse_statement(provider(), entries.front().statement);
    REQUIRE(genesis);
    CHECK(to_hex(genesis->id.bytes()) == text(lg["ledger_id"]));
    auto state = protocol::LedgerState::from_genesis(provider(), *genesis);
    REQUIRE(state);
    std::map<std::string, protocol::SignedStatement> registrations;
    for (std::size_t i = 1; i < entries.size(); ++i) {
        if (entries[i].is_state_commitment()) {
            continue;
        }
        auto statement = protocol::parse_statement(provider(), entries[i].statement, hash);
        REQUIRE(statement);
        const auto valid = state->validate(provider(), *statement, entries[i].registered_at);
        INFO((valid ? std::string() : std::string(valid.error().detail)));
        REQUIRE(valid);
        REQUIRE(state->apply(provider(), *statement, i, entries[i].registered_at));
        registrations.emplace(to_hex(statement->id.bytes()), std::move(*statement));
    }
    for (const auto& expected : lg["records"]) {
        INFO(text(expected["id"]));
        const protocol::RecordState* record = state->record(id_of(expected["id"]));
        REQUIRE(record != nullptr);
        CHECK(record->record_type == text(expected["type"]));
        const auto it = registrations.find(text(expected["id"]));
        REQUIRE(it != registrations.end());
        const auto& body = std::get<protocol::RecordRegisterBody>(it->second.statement.body);
        REQUIRE(body.provable.size() == expected["provable"].size());
        for (std::size_t n = 0; n < body.provable.size(); ++n) {
            const auto& e = expected["provable"][n];
            CHECK(body.provable[n].name == text(e["name"]));
            CHECK(encoding_fact(body.provable[n].encoding) == e["encoding"]);
            CHECK(to_hex(body.provable[n].commitment) == text(e["commitment"]));
        }
    }
    for (const auto& r : lg["refused"]) {
        INFO(text(r["name"]) + " (" + text(r["why"]) + ")");
        CHECK(r["after"].get<std::size_t>() == entries.size());
        const auto parsed = protocol::parse_statement(provider(), hex(text(r["encoded"])), hash);
        if (r["malformed"].get<bool>()) {
            CHECK_FALSE(parsed);
            continue;
        }
        REQUIRE(parsed);
        const auto refused =
            state->validate(provider(), *parsed, r["at"].get<protocol::Timestamp>());
        REQUIRE_FALSE(refused);
        CHECK(refused.error().code == Errc::rejected);
    }
}

TEST_CASE("v0.22 evidence: range proofs verified, refused, and not checked, as specified",
          "[protocol][vectors][v022]") {
    const bool system = static_cast<bool>(system_one());
    std::size_t ran = 0;
    for (const auto& c : vectors()["bundles"]) {
        INFO(text(c["name"]) + ": " + text(c["description"]));
        const Bytes evidence = hex(text(c["evidence"]));
        const bool needs = c.contains("range_systems") && !c["range_systems"].empty();
        if (c["kind"] == "contract") {
            const auto report = protocol::verify_contract_evidence(
                provider(), evidence, options_of(c["options"], system_one()));
            CHECK(report.has_value() == c["verified"].get<bool>());
            continue;
        }
        // What decodes, encodes the same again.
        if (const auto bundle = protocol::decode_bundle(evidence)) {
            const auto again = protocol::encode_bundle(*bundle);
            REQUIRE(again);
            CHECK(*again == evidence);
        }
        // Without system 1, every proof is not checked: a case that needs
        // the arithmetic is skipped, and a verified one still verifies.
        const auto bare =
            protocol::verify_bundle(provider(), evidence, options_of(c["options"], {}));
        if (c["verified"].get<bool>()) {
            REQUIRE(bare);
            for (const protocol::RangeProofReport& r : bare->range_proofs) {
                CHECK_FALSE(r.verified);
            }
            const auto json =
                nlohmann::json::parse(kanhe::verifier::report_json(*bare, true).dump());
            for (const auto& r : json["range_proofs"]) {
                CHECK(r["status"] == "not-checked");
            }
            const std::string words = kanhe::verifier::report_text(*bare, true);
            for (const protocol::RangeProofReport& r : bare->range_proofs) {
                CHECK(words.find("  Range proof  " + r.text + ": NOT CHECKED") !=
                      std::string::npos);
            }
        } else if (!needs) {
            CHECK_FALSE(bare);
        }
        if (needs && !system) {
            continue;
        }
        const protocol::VerifyOptions options = options_of(c["options"], system_one());
        const auto report = protocol::verify_bundle(provider(), evidence, options);
        INFO((report ? std::string() : std::string(report.error().detail)));
        REQUIRE(report.has_value() == c["verified"].get<bool>());
        ++ran;
        if (!report) {
            CHECK_FALSE(text(c["rule"]).empty());
            continue;
        }
        const nlohmann::json json =
            nlohmann::json::parse(kanhe::verifier::report_json(*report, true).dump());
        // Always present: empty lists when none.
        REQUIRE(json.contains("provable"));
        REQUIRE(json.contains("range_proofs"));
        nlohmann::json facts = c["facts"];
        if (!system && facts.contains("range_proofs")) {
            for (auto& r : facts["range_proofs"]) {
                r["status"] = "not-checked";
            }
        }
        std::string where;
        CHECK(matches(facts, json, "", where));
        if (!where.empty()) {
            FAIL_CHECK("the report differs at " + where);
        }
        // The text says it too.
        const std::string words = kanhe::verifier::report_text(*report, true);
        for (const protocol::RangeProofReport& r : report->range_proofs) {
            CHECK(words.find("  Range proof  " + r.text +
                             (system ? ": verified" : ": NOT CHECKED")) != std::string::npos);
        }
        if (!report->provable.empty()) {
            CHECK(words.find("  Provable     ") != std::string::npos);
        }
    }
    CHECK(ran > 0);
}

TEST_CASE("v0.22 evidence: a verifier's arithmetic, and a context required", "[protocol][v022]") {
    const nlohmann::json* verified = nullptr;
    const nlohmann::json* with_context = nullptr;
    for (const auto& c : vectors()["bundles"]) {
        if (c["name"] == "range-proofs-three") {
            verified = &c;
        }
        if (c["name"] == "range-proof-context-required") {
            with_context = &c;
        }
    }
    REQUIRE(verified != nullptr);
    REQUIRE(with_context != nullptr);
    const Bytes three = hex(text((*verified)["evidence"]));
    const Bytes salary = hex(text((*with_context)["evidence"]));
    const protocol::Id ledger = id_of((*verified)["options"]["ledger_id"]);

    // The verifier is given each proof's commitment, public values, its
    // transcript, and the proof, in the bundle's order.
    const auto bundle = protocol::decode_bundle(three);
    REQUIRE(bundle);
    REQUIRE(bundle->range_proofs.size() == 3);
    std::vector<std::pair<std::uint64_t, std::uint64_t>> asked;
    std::vector<Bytes> transcripts;
    protocol::VerifyOptions options;
    options.expected_ledger = ledger;
    options.range_verifier = [&](kanhe::ByteView c, std::uint64_t lo, std::uint64_t hi,
                                 kanhe::ByteView t, kanhe::ByteView proof) -> kanhe::Status {
        CHECK(c.size() == 32);
        CHECK(std::ranges::equal(proof, bundle->range_proofs[asked.size()].proof));
        asked.emplace_back(lo, hi);
        transcripts.emplace_back(t.begin(), t.end());
        return {};
    };
    const auto report = protocol::verify_bundle(provider(), three, options);
    REQUIRE(report);
    REQUIRE(asked.size() == 3);
    for (std::size_t i = 0; i < 3; ++i) {
        CHECK(report->range_proofs[i].verified);
        const auto& p = bundle->range_proofs[i];
        const auto value =
            std::ranges::find(report->provable, p.field, &protocol::ProvableValue::name);
        REQUIRE(value != report->provable.end());
        CHECK(asked[i] == *protocol::range_public_values(value->encoding, p));
        CHECK(transcripts[i] == protocol::range_transcript(
                                    ledger, bundle->record, p.field, value->commitment,
                                    asked[i].first, asked[i].second,
                                    p.context ? kanhe::ByteView(*p.context) : kanhe::ByteView()));
    }
    // A proof the arithmetic refuses fails the evidence; a verifier that
    // cannot run says so.
    options.range_verifier = [](kanhe::ByteView, std::uint64_t, std::uint64_t, kanhe::ByteView,
                                kanhe::ByteView) -> kanhe::Status {
        return kanhe::fail(Errc::verification_failed, "no");
    };
    CHECK(protocol::verify_bundle(provider(), three, options).error().code ==
          Errc::verification_failed);
    options.range_verifier = [](kanhe::ByteView, std::uint64_t, std::uint64_t, kanhe::ByteView,
                                kanhe::ByteView) -> kanhe::Status {
        return kanhe::fail(Errc::crypto_failure, "the circuit is not the pinned one");
    };
    CHECK(protocol::verify_bundle(provider(), three, options).error().code == Errc::crypto_failure);

    // A context required: every proof carries exactly it.
    protocol::VerifyOptions required;
    required.expected_ledger = id_of((*with_context)["options"]["ledger_id"]);
    required.range_context = hex(text((*with_context)["options"]["range_context"]));
    CHECK(protocol::verify_bundle(provider(), salary, required));
    CHECK_FALSE(protocol::verify_bundle(provider(), three, required));
    required.range_context->back() ^= 1;
    CHECK_FALSE(protocol::verify_bundle(provider(), salary, required));
    // A bundle without range proofs meets it, and proves nothing.
    auto plain = *protocol::decode_bundle(salary);
    plain.range_proofs.clear();
    const auto none =
        protocol::verify_bundle(provider(), *protocol::encode_bundle(plain), required);
    REQUIRE(none);
    CHECK(none->range_proofs.empty());
    CHECK(none->provable.size() == 3);
}
