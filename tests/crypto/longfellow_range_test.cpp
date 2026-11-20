// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// Zero-knowledge range proofs (Longfellow ZK). Each proof costs tens of
// milliseconds and the circuit a few seconds, more under sanitizers, so each
// test case makes the proofs it needs once.

#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <string_view>
#include <thread>
#include <vector>

#include <catch2/catch_test_macros.hpp>

#include <kanhe/core/bytes.hpp>
#include <kanhe/core/crypto.hpp>
#include <kanhe/crypto/longfellow.hpp>
#include <kanhe/crypto/openssl.hpp>

namespace range = kanhe::crypto::longfellow;
using kanhe::as_bytes;
using kanhe::Bytes;
using kanhe::ByteView;
using kanhe::Errc;
using kanhe::to_hex;

namespace {

constexpr std::uint64_t max64 = std::numeric_limits<std::uint64_t>::max();

Bytes salt(std::uint8_t first) {
    Bytes out(range::range_salt_size);
    for (std::size_t i = 0; i < out.size(); ++i) {
        out[i] = static_cast<std::uint8_t>(first + i);
    }
    return out;
}

Bytes text(std::string_view s) {
    const auto view = as_bytes(s);
    return Bytes(view.begin(), view.end());
}

Bytes commitment(const Bytes& s, std::uint64_t value) {
    auto c = range::range_commitment(s, value);
    REQUIRE(c);
    return *c;
}

Bytes prove(const Bytes& s, std::uint64_t value, std::uint64_t low, std::uint64_t high,
            const Bytes& transcript, std::optional<ByteView> seed = std::nullopt) {
    auto proof = range::prove_range(s, value, low, high, transcript, seed);
    REQUIRE(proof);
    // About 84 KB, and within the verifier's limit.
    CHECK(proof->size() > 60'000);
    CHECK(proof->size() < range::max_range_proof_size);
    return *proof;
}

/// One honest proof, made once per process: v = 1000 in [10, 100000].
struct Honest {
    Bytes salt = ::salt(1);
    std::uint64_t value = 1000;
    std::uint64_t low = 10;
    std::uint64_t high = 100'000;
    Bytes transcript = text("range proof test: ledger, record, field");
    Bytes commitment = ::commitment(salt, value);
    Bytes proof = prove(salt, value, low, high, transcript);
};

const Honest& honest() {
    static const Honest instance;
    return instance;
}

Errc refusal(ByteView c, std::uint64_t low, std::uint64_t high, ByteView transcript,
             ByteView proof) {
    const auto result = range::verify_range(c, low, high, transcript, proof);
    REQUIRE_FALSE(result);
    return result.error().code;
}

} // namespace

TEST_CASE("Range proofs: the circuit is built once and is the pinned one", "[crypto][range]") {
    // From threads at once: the circuit is built once, for all of them.
    std::vector<std::thread> threads;
    std::array<bool, 4> ready{};
    for (std::size_t i = 0; i < ready.size(); ++i) {
        threads.emplace_back(
            [&ready, i] { ready[i] = range::prepare_range_circuit().has_value(); });
    }
    for (auto& t : threads) {
        t.join();
    }
    for (const bool r : ready) {
        CHECK(r);
    }
    CHECK(to_hex(range::range_circuit_id()) ==
          "fc727b6726bd4bfe80b65d044cdb4d393fcc688b5aad0ab4ded3a9619459480a");

    // Serialized, it ends with its id, and reads back to it (range_circuit_bytes
    // reads it back before returning it).
    const auto bytes = range::range_circuit_bytes();
    REQUIRE(bytes);
    CHECK(bytes->size() > 1'000'000);
    const ByteView id = range::range_circuit_id();
    REQUIRE(bytes->size() >= id.size());
    CHECK(Bytes(bytes->end() - static_cast<std::ptrdiff_t>(id.size()), bytes->end()) ==
          Bytes(id.begin(), id.end()));
}

TEST_CASE("Range proofs: a serialized circuit is loaded only if it is the pinned one",
          "[crypto][range]") {
    // As a verifier that does not build the circuit loads it (the browser
    // verifier). With one built already, the bytes are checked, and the
    // circuit in use stays.
    const auto bytes = range::range_circuit_bytes();
    REQUIRE(bytes);
    CHECK(range::load_range_circuit(*bytes));
    const Honest& h = honest();
    CHECK(range::verify_range(h.commitment, h.low, h.high, h.transcript, h.proof));

    // Cut short, empty, or with a byte after it: refused, never aborting.
    const auto code = [](ByteView serialized) {
        const auto loaded = range::load_range_circuit(serialized);
        REQUIRE_FALSE(loaded);
        return loaded.error().code;
    };
    CHECK(code(ByteView(*bytes).first(bytes->size() - 1)) == Errc::malformed);
    CHECK(code(ByteView(*bytes).first(bytes->size() / 2)) == Errc::malformed);
    CHECK(code({}) == Errc::malformed);
    Bytes longer = *bytes;
    longer.push_back(0);
    CHECK(code(longer) == Errc::malformed);
    // Another id after the same terms; another version, a constant, or a
    // term changed: refused. (Not every byte matters: the encoding is
    // malleable, and a file that reads to the pinned id holds the circuit.)
    Bytes renamed = *bytes;
    renamed.back() ^= 1;
    CHECK(code(renamed) == Errc::malformed);
    for (const std::size_t at : {std::size_t{0}, std::size_t{100}, bytes->size() - 40}) {
        CAPTURE(at);
        Bytes changed = *bytes;
        changed[at] ^= 1;
        CHECK(code(changed) == Errc::malformed);
    }
    // The circuit in use is unchanged.
    CHECK(range::verify_range(h.commitment, h.low, h.high, h.transcript, h.proof));
}

TEST_CASE("Range proofs: commitments", "[crypto][range]") {
    // SHA-256("Kanhe range v1" || salt || BE64(value)), the salt 00 01 .. 1f.
    const Bytes s = salt(0);
    CHECK(to_hex(commitment(s, 1000)) ==
          "1d3fb2cb17848a6696907d7bc4f9c2f6ea222d65bd45f1d0d244f6e6cdb66b52");
    // The same message hashed by the OpenSSL provider.
    const kanhe::crypto::openssl::Provider provider;
    const std::array<std::uint8_t, 8> be = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef};
    const auto expected = provider.digest(kanhe::crypto::HashAlg::sha256,
                                          {as_bytes(range::range_commitment_prefix), s, be});
    REQUIRE(expected);
    const ByteView digest = expected->bytes();
    CHECK(commitment(s, 0x0123456789abcdefULL) == Bytes(digest.begin(), digest.end()));
    CHECK(commitment(s, 1000) != commitment(s, 1001));
    CHECK(commitment(s, 1000) != commitment(salt(1), 1000));

    for (const std::size_t size : {0U, 16U, 31U, 33U}) {
        const auto c = range::range_commitment(Bytes(size, 7), 1000);
        REQUIRE_FALSE(c);
        CHECK(c.error().code == Errc::invalid_argument);
    }
}

TEST_CASE("Range proofs: honest proofs verify, at the boundaries", "[crypto][range]") {
    struct Case {
        const char* what;
        std::uint64_t value;
        std::uint64_t low;
        std::uint64_t high;
    };
    const Bytes transcript = text("boundaries");
    for (const Case& c : {
             Case{"inside", 1000, 10, 100'000},
             Case{"value == low", 1'700'000'000'000, 1'700'000'000'000, 1'700'000'005'000},
             Case{"value == high", 1'700'000'005'000, 1'700'000'000'000, 1'700'000'005'000},
             Case{"low = 0, high = 2^64 - 1, value = 2^64 - 1", max64, 0, max64},
             Case{"low = 0 = value", 0, 0, 12'345},
         }) {
        INFO(c.what);
        const Bytes s = salt(static_cast<std::uint8_t>(c.value));
        const Bytes proof = prove(s, c.value, c.low, c.high, transcript);
        CHECK(range::verify_range(commitment(s, c.value), c.low, c.high, transcript, proof));
    }
}

TEST_CASE("Range proofs: the prover refuses false statements and bad arguments",
          "[crypto][range]") {
    const Bytes s = salt(3);
    const Bytes transcript = text("refusals");
    const auto refused = [&](ByteView salt_, std::uint64_t value, std::uint64_t low,
                             std::uint64_t high, ByteView t, std::optional<ByteView> seed) {
        const auto proof = range::prove_range(salt_, value, low, high, t, seed);
        REQUIRE_FALSE(proof);
        return proof.error().code;
    };
    CHECK(refused(s, 9, 10, 100, transcript, std::nullopt) == Errc::invalid_argument);
    CHECK(refused(s, 101, 10, 100, transcript, std::nullopt) == Errc::invalid_argument);
    CHECK(refused(s, 0, 1, max64, transcript, std::nullopt) == Errc::invalid_argument);
    CHECK(refused(s, max64, 0, max64 - 1, transcript, std::nullopt) == Errc::invalid_argument);
    CHECK(refused(s, 50, 100, 10, transcript, std::nullopt) == Errc::invalid_argument);
    CHECK(refused(Bytes(16, 1), 50, 10, 100, transcript, std::nullopt) == Errc::invalid_argument);
    CHECK(refused(Bytes(33, 1), 50, 10, 100, transcript, std::nullopt) == Errc::invalid_argument);
    const Bytes short_seed(16, 2);
    CHECK(refused(s, 50, 10, 100, transcript, ByteView(short_seed)) == Errc::invalid_argument);
    const Bytes long_transcript(range::max_range_transcript_size + 1, 0);
    CHECK(refused(s, 50, 10, 100, long_transcript, std::nullopt) == Errc::limit_exceeded);
}

TEST_CASE("Range proofs: the verifier refuses other statements and tampered proofs",
          "[crypto][range]") {
    const Honest& h = honest();
    REQUIRE(range::verify_range(h.commitment, h.low, h.high, h.transcript, h.proof));

    SECTION("other bounds, those that exclude the value too") {
        const std::array<std::array<std::uint64_t, 2>, 9> bounds = {{
            {h.low + 1, h.high},
            {h.low - 1, h.high},
            {h.low, h.high - 1},
            {h.low, h.high + 1},
            {0, max64},
            {h.value, h.value},
            {h.value + 1, h.high},
            {h.low, h.value - 1},
            {h.high, h.low},
        }};
        for (const auto& [low, high] : bounds) {
            INFO("low " << low << ", high " << high);
            CHECK(refusal(h.commitment, low, high, h.transcript, h.proof) ==
                  Errc::verification_failed);
        }
    }

    SECTION("another commitment") {
        for (const std::size_t at : {0U, 13U, 31U}) {
            Bytes c = h.commitment;
            c[at] ^= 0x01;
            CHECK(refusal(c, h.low, h.high, h.transcript, h.proof) == Errc::verification_failed);
        }
        // Another salt's, and another value's under the same salt.
        CHECK(refusal(commitment(salt(2), h.value), h.low, h.high, h.transcript, h.proof) ==
              Errc::verification_failed);
        CHECK(refusal(commitment(h.salt, h.value + 1), h.low, h.high, h.transcript, h.proof) ==
              Errc::verification_failed);
        CHECK(refusal(Bytes(31, 0), h.low, h.high, h.transcript, h.proof) ==
              Errc::invalid_argument);
    }

    SECTION("another transcript") {
        Bytes longer = h.transcript;
        longer.push_back(0);
        Bytes flipped = h.transcript;
        flipped[0] ^= 0x01;
        for (const Bytes& t : {longer, flipped, Bytes{}}) {
            CHECK(refusal(h.commitment, h.low, h.high, t, h.proof) == Errc::verification_failed);
        }
    }

    SECTION("single bit flips, spread over the proof") {
        const std::size_t n = h.proof.size();
        constexpr std::size_t flips = 48;
        for (std::size_t i = 0; i < flips; ++i) {
            const std::size_t at = i * (n - 1) / (flips - 1);
            Bytes tampered = h.proof;
            tampered[at] ^= static_cast<std::uint8_t>(1U << (i % 8));
            INFO("byte " << at << ", bit " << i % 8);
            const Errc code = refusal(h.commitment, h.low, h.high, h.transcript, tampered);
            CHECK((code == Errc::verification_failed || code == Errc::malformed));
        }
    }

    SECTION("truncated, extended, empty, and too long") {
        const Bytes& p = h.proof;
        const auto cut = [&](std::size_t size) {
            return Bytes(p.begin(), p.begin() + static_cast<std::ptrdiff_t>(size));
        };
        for (const Bytes& bad : {cut(p.size() - 1), cut(p.size() / 2), cut(32), Bytes{}}) {
            CHECK(refusal(h.commitment, h.low, h.high, h.transcript, bad) == Errc::malformed);
        }
        Bytes extended = p;
        extended.push_back(0);
        CHECK(refusal(h.commitment, h.low, h.high, h.transcript, extended) == Errc::malformed);
        // Refused unread past the limit; at the limit, read and refused.
        const Bytes too_long(range::max_range_proof_size + 1, 0);
        CHECK(refusal(h.commitment, h.low, h.high, h.transcript, too_long) == Errc::limit_exceeded);
        const Bytes at_limit(range::max_range_proof_size, 0);
        CHECK(refusal(h.commitment, h.low, h.high, h.transcript, at_limit) == Errc::malformed);
        const Bytes long_transcript(range::max_range_transcript_size + 1, 0);
        CHECK(refusal(h.commitment, h.low, h.high, long_transcript, p) == Errc::limit_exceeded);
    }

    SECTION("from threads at once") {
        std::vector<std::thread> threads;
        std::array<bool, 4> valid{};
        for (std::size_t i = 0; i < valid.size(); ++i) {
            threads.emplace_back([&valid, &h, i] {
                valid[i] = range::verify_range(h.commitment, h.low, h.high, h.transcript, h.proof)
                               .has_value();
            });
        }
        for (auto& t : threads) {
            t.join();
        }
        for (const bool v : valid) {
            CHECK(v);
        }
    }
}

TEST_CASE("Range proofs: seeded proofs are reproducible, others fresh", "[crypto][range]") {
    const Bytes s = salt(9);
    const std::uint64_t value = 77'000;
    const Bytes c = commitment(s, value);
    const Bytes transcript = text("seeded");
    const Bytes seed_a(range::range_seed_size, 0xa5);
    const Bytes seed_b(range::range_seed_size, 0x5a);

    const Bytes seeded = prove(s, value, 1, 100'000, transcript, ByteView(seed_a));
    const Bytes again = prove(s, value, 1, 100'000, transcript, ByteView(seed_a));
    const Bytes b = prove(s, value, 1, 100'000, transcript, ByteView(seed_b));
    CHECK(seeded == again);
    CHECK(seeded != b);
    CHECK(range::verify_range(c, 1, 100'000, transcript, seeded));
    CHECK(range::verify_range(c, 1, 100'000, transcript, b));

    const Bytes fresh1 = prove(s, value, 1, 100'000, transcript);
    const Bytes fresh2 = prove(s, value, 1, 100'000, transcript);
    CHECK(fresh1 != fresh2);
    CHECK(fresh1 != seeded);
    CHECK(range::verify_range(c, 1, 100'000, transcript, fresh2));
}
