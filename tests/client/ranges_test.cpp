// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// Range proofs as an issuer and a holder make them (spec v0.22): encodings as
// the command line writes them, field values read as integers with exact
// arithmetic, bounds as people write them turned into a claim's value forms,
// and openings kept in a record's vault.

#include <array>
#include <cstdint>
#include <limits>
#include <string>
#include <vector>

#include <catch2/catch_test_macros.hpp>

#include <kanhe/client/errors.hpp>
#include <kanhe/client/ranges.hpp>
#include <kanhe/client/records.hpp>
#include <kanhe/core/cbor.hpp>
#include <kanhe/crypto/openssl.hpp>

namespace {

namespace cbor = kanhe::cbor;
namespace client = kanhe::client;
namespace protocol = kanhe::protocol;
using kanhe::Bytes;
using kanhe::UsageError;
using Type = protocol::ProvableEncoding::Type;
using V = cbor::Value;

protocol::ProvableEncoding number(std::uint8_t scale) {
    return {Type::number, scale, ""};
}

protocol::ProvableEncoding money(std::string currency, std::uint8_t scale) {
    return {Type::money, scale, std::move(currency)};
}

protocol::ProvableEncoding date() {
    return {Type::date, 0, ""};
}

constexpr std::int64_t most = std::numeric_limits<std::int64_t>::max();
constexpr std::int64_t least = std::numeric_limits<std::int64_t>::min();

protocol::Id id_of(std::uint8_t byte) {
    return *protocol::to_id(Bytes(32, byte));
}

} // namespace

TEST_CASE("encodings as the command line writes them", "[client][ranges]") {
    CHECK(client::parse_provable_encoding("number") == number(0));
    CHECK(client::parse_provable_encoding("number:0") == number(0));
    CHECK(client::parse_provable_encoding("number:2") == number(2));
    CHECK(client::parse_provable_encoding("number:18") == number(18));
    CHECK(client::parse_provable_encoding("money:HKD:2") == money("HKD", 2));
    CHECK(client::parse_provable_encoding("money:USD:0") == money("USD", 0));
    CHECK(client::parse_provable_encoding("date") == date());
    for (const char* bad :
         {"", "text", "number:19", "number:-1", "number:x", "number:2:3", "money", "money:HKD",
          "money:hkd:2", "money:HK:2", "money:HKD:5", "money::2", "date:1", "Number", "number:"}) {
        INFO(bad);
        CHECK_THROWS_AS(client::parse_provable_encoding(bad), UsageError);
    }
    for (const auto& e : {number(0), number(3), money("EUR", 4), date()}) {
        CHECK(client::parse_provable_encoding(client::provable_encoding_text(e)) == e);
    }
    CHECK(client::provable_encoding_text(money("HKD", 2)) == "money:HKD:2");

    const auto [name, encoding] = client::parse_provable("monthly_salary:money:HKD:2");
    CHECK(name == "monthly_salary");
    CHECK(encoding == money("HKD", 2));
    CHECK(client::parse_provable("born:date").first == "born");
    CHECK_THROWS_AS(client::parse_provable(":date"), UsageError);
    CHECK_THROWS_AS(client::parse_provable("born"), UsageError);
    CHECK_THROWS_AS(client::parse_provable("born:"), UsageError);
}

TEST_CASE("a field's value read as x: numbers", "[client][ranges]") {
    CHECK(client::provable_value_x(number(0), "18") == 18);
    CHECK(client::provable_value_x(number(0), " 1,250 ") == 1250);
    CHECK(client::provable_value_x(number(0), "-3") == -3);
    CHECK(client::provable_value_x(number(0), "007") == 7);
    CHECK(client::provable_value_x(number(2), "18.5") == 1850);
    CHECK(client::provable_value_x(number(2), "18.50") == 1850);
    CHECK(client::provable_value_x(number(2), "18") == 1800);
    CHECK(client::provable_value_x(number(1), "-0.5") == -5);
    CHECK(client::provable_value_x(number(2), "1,234.56") == 123456);
    // The ends of the range, exactly.
    CHECK(client::provable_value_x(number(0), "9223372036854775807") == most);
    CHECK(client::provable_value_x(number(0), "-9223372036854775808") == least);
    CHECK(client::provable_value_x(number(18), "9.223372036854775807") == most);
    CHECK(client::provable_value_x(number(18), "-9.223372036854775808") == least);
    CHECK_THROWS_AS(client::provable_value_x(number(0), "9223372036854775808"), UsageError);
    CHECK_THROWS_AS(client::provable_value_x(number(0), "-9223372036854775809"), UsageError);
    CHECK_THROWS_AS(client::provable_value_x(number(18), "10"), UsageError);
    CHECK_THROWS_AS(client::provable_value_x(number(1), "922337203685477580.8"), UsageError);
    // More decimals than the scale, and what is no number.
    CHECK_THROWS_AS(client::provable_value_x(number(2), "18.505"), UsageError);
    CHECK_THROWS_AS(client::provable_value_x(number(0), "18.5"), UsageError);
    CHECK_THROWS_AS(client::provable_value_x(number(1), "18.50"), UsageError);
    for (const char* bad :
         {"", "abc", "1e3", ".5", "5.", "+5", "1 000", "0x10", "--1", "1.2.3", "HKD 5"}) {
        INFO(bad);
        CHECK_THROWS_AS(client::provable_value_x(number(2), bad), UsageError);
    }
}

TEST_CASE("a field's value read as x: money", "[client][ranges]") {
    CHECK(client::provable_value_x(money("HKD", 2), "HKD 30,000.00") == 3000000);
    CHECK(client::provable_value_x(money("HKD", 2), "HKD 32,000.5") == 3200050);
    CHECK(client::provable_value_x(money("HKD", 2), "30000") == 3000000);
    CHECK(client::provable_value_x(money("HKD", 2), " 30,000.00 ") == 3000000);
    CHECK(client::provable_value_x(money("HKD", 0), "HKD 30,000") == 30000);
    CHECK(client::provable_value_x(money("HKD", 4), "-1.2345") == -12345);
    CHECK_THROWS_AS(client::provable_value_x(money("HKD", 2), "USD 1.00"), UsageError);
    CHECK_THROWS_AS(client::provable_value_x(money("HKD", 2), "HKD 1.005"), UsageError);
    CHECK_THROWS_AS(client::provable_value_x(money("HKD", 0), "HKD 30,000.00"), UsageError);
    CHECK_THROWS_AS(client::provable_value_x(money("HKD", 2), "HKD"), UsageError);
    CHECK_THROWS_AS(client::provable_value_x(money("HKD", 2), "thirty"), UsageError);
    CHECK_THROWS_AS(client::provable_value_x(money("HKD", 4), "HKD 922337203685478"), UsageError);
}

TEST_CASE("a field's value read as x: dates", "[client][ranges]") {
    CHECK(client::provable_value_x(date(), "1970-01-01") == 0);
    CHECK(client::provable_value_x(date(), "1969-12-31") == -1);
    CHECK(client::provable_value_x(date(), "1950-06-15") == -7140);
    CHECK(client::provable_value_x(date(), "2000-02-29") == 11016);
    CHECK(client::provable_value_x(date(), "2008-11-21") == 14204);
    CHECK(client::provable_value_x(date(), "0001-01-01") == -719162);
    CHECK(client::provable_value_x(date(), "9999-12-31") == 2932896);
    CHECK(client::provable_value_x(date(), " 2008-11-21 ") == 14204);
    for (const char* bad :
         {"", "0000-12-31", "2001-02-29", "1900-02-29", "2008-13-01", "2008-00-10", "2008-04-31",
          "2008-11-00", "08-11-21", "2008/11/21", "2008-11-21T00:00:00Z", "21/11/2008"}) {
        INFO(bad);
        CHECK_THROWS_AS(client::provable_value_x(date(), bad), UsageError);
    }
}

TEST_CASE("bounds as people write them, in a claim's value forms", "[client][ranges]") {
    // Numbers: an integer, or a decimal text; zeros beyond the scale dropped.
    CHECK(client::range_bound_value(number(1), "18") == V::integer(18));
    CHECK(client::range_bound_value(number(1), "1,000") == V::integer(1000));
    CHECK(client::range_bound_value(number(1), "-5") == V::integer(-5));
    CHECK(client::range_bound_value(number(1), "18.5") == V::text("18.5"));
    CHECK(client::range_bound_value(number(1), "18.50") == V::text("18.5"));
    CHECK(client::range_bound_value(number(2), "18.50") == V::text("18.50"));
    CHECK(client::range_bound_value(number(1), "0018.5") == V::text("18.5"));
    CHECK(client::range_bound_value(number(0), "18.0") == V::integer(18));
    CHECK(client::range_bound_value(number(1), "-0.5") == V::text("-0.5"));
    CHECK_THROWS_AS(client::range_bound_value(number(1), "18.55"), UsageError);
    CHECK_THROWS_AS(client::range_bound_value(number(0), "9223372036854775808"), UsageError);
    CHECK_THROWS_AS(client::range_bound_value(number(2), "92233720368547758.08"), UsageError);
    CHECK_THROWS_AS(client::range_bound_value(number(2), "eighteen"), UsageError);
    CHECK_THROWS_AS(client::range_bound_value(number(2), ""), UsageError);

    // Money: [amount, currency, scale] in the encoding's.
    const auto hkd = [](std::int64_t amount) {
        return V::array({V::integer(amount), V::text("HKD"), V::unsigned_integer(2)});
    };
    CHECK(client::range_bound_value(money("HKD", 2), "HKD 30,000.00") == hkd(3000000));
    CHECK(client::range_bound_value(money("HKD", 2), "HKD 30,000") == hkd(3000000));
    CHECK(client::range_bound_value(money("HKD", 2), "30000") == hkd(3000000));
    CHECK(client::range_bound_value(money("HKD", 2), "HKD 30,000.000") == hkd(3000000));
    CHECK(client::range_bound_value(money("HKD", 2), "-0.01") == hkd(-1));
    CHECK_THROWS_AS(client::range_bound_value(money("HKD", 2), "USD 30,000.00"), UsageError);
    CHECK_THROWS_AS(client::range_bound_value(money("HKD", 2), "HKD 1.005"), UsageError);

    // Dates: as written, if they are dates.
    CHECK(client::range_bound_value(date(), "2008-11-20") == V::text("2008-11-20"));
    CHECK_THROWS_AS(client::range_bound_value(date(), "2008-02-30"), UsageError);
    CHECK_THROWS_AS(client::range_bound_value(date(), "18"), UsageError);
}

TEST_CASE("a statement to prove, checked as a verifier reads it", "[client][ranges]") {
    const protocol::ProvableValue born{"born", date(), Bytes(32, 7)};
    client::RangeRequest request;
    request.field = "born";
    CHECK_THROWS_AS(client::range_statement(born, request), UsageError);
    request.at_most = "2008-11-21";
    const protocol::RangeProof at_most = client::range_statement(born, request);
    CHECK(at_most.field == "born");
    CHECK_FALSE(at_most.low.has_value());
    CHECK(at_most.high == V::text("2008-11-21"));
    CHECK(at_most.system == protocol::range_system_longfellow);
    CHECK(at_most.proof.empty());
    CHECK_FALSE(at_most.context.has_value());

    request.at_least = "2008-11-22";
    CHECK_THROWS_AS(client::range_statement(born, request), UsageError);
    request.at_least = "1900-01-01";
    const Bytes challenge{1, 2, 3};
    request.context = challenge;
    const protocol::RangeProof between = client::range_statement(born, request);
    CHECK(between.low == V::text("1900-01-01"));
    CHECK(between.context == challenge);
    request.context = Bytes(65, 1);
    CHECK_THROWS_AS(client::range_statement(born, request), UsageError);
    request.context = Bytes();
    CHECK_THROWS_AS(client::range_statement(born, request), UsageError);
}

TEST_CASE("openings kept in a record's vault", "[client][ranges]") {
    const auto key = kanhe::crypto::openssl::HpkeKey::generate();
    REQUIRE(key);
    const protocol::Id ledger = id_of(1);
    const protocol::Id record = id_of(2);
    client::Vault vault;
    vault.fields.push_back(
        {"born", protocol::Salt(std::array<std::uint8_t, 32>{}), V::text("2001-04-02")});

    // Without openings: as vaults were written before them.
    const client::Vault plain = client::open_vault_file(
        client::seal_vault(ledger, record, vault, key->public_key()), ledger, record, &*key);
    CHECK(plain.fields == vault.fields);
    CHECK(plain.openings.empty());

    // With them: read back as written.
    vault.openings.push_back({"born", Bytes(32, 9), 11414});
    vault.openings.push_back({"score", Bytes(32, 10), least});
    const client::Vault kept = client::open_vault_file(
        client::seal_vault(ledger, record, vault, key->public_key()), ledger, record, &*key);
    CHECK(kept.openings == vault.openings);
    CHECK(kept.fields == vault.fields);
}
