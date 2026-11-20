// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// Range openings files (spec v0.22, `.kanheopenings`) come from an issuer to
// a holder, and anyone may hand one to a prover; the range proofs of a
// bundle's key 12, a registration's provable values (key 8), and their bounds
// come with any evidence. Reading each must refuse what is not one, never
// crash, and what it accepts must be written back byte for byte. A proof's
// bounds are read in every encoding, and stated in words, whatever they are.

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>

#include <kanhe/core/cbor.hpp>
#include <kanhe/core/protocol/ranges.hpp>

namespace protocol = kanhe::protocol;

namespace {

void require(bool condition) {
    if (!condition) {
        __builtin_trap();
    }
}

template <class Encoded>
void require_same(const Encoded& encoded, kanhe::ByteView input) {
    require(encoded.has_value() && std::ranges::equal(*encoded, input));
}

void require_same_value(const kanhe::Result<kanhe::cbor::Value>& value, kanhe::ByteView input) {
    require(value.has_value());
    require_same(kanhe::cbor::encode(*value), input);
}

using Type = protocol::ProvableEncoding::Type;
const std::array<protocol::ProvableEncoding, 6> encodings{{
    {Type::number, 0, ""},
    {Type::number, 2, ""},
    {Type::number, 18, ""},
    {Type::money, 2, "HKD"},
    {Type::money, 0, "JPY"},
    {Type::date, 0, ""},
}};

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    const kanhe::ByteView input(data, size);
    if (const auto file = protocol::decode_range_openings(input)) {
        require_same(protocol::encode_range_openings(*file), input);
        require(!file->openings.empty() && file->openings.size() <= 64);
    }
    const auto value = kanhe::cbor::decode(input);
    if (!value) {
        return 0;
    }
    if (const auto proof = protocol::range_proof_from(*value)) {
        require_same_value(protocol::range_proof_value(*proof), input);
        for (const protocol::ProvableEncoding& e : encodings) {
            if (const auto bounds = protocol::range_public_values(e, *proof)) {
                require(bounds->first <= bounds->second);
            }
            require(!protocol::range_words(e, *proof).empty());
        }
    }
    for (const std::uint64_t fields : {std::uint64_t{1}, std::uint64_t{64}}) {
        if (const auto provable = protocol::provable_list_from(*value, fields)) {
            require(!provable->empty() && provable->size() <= fields);
            require_same_value(protocol::provable_list_value(*provable, fields), input);
        }
    }
    if (const auto encoding = protocol::provable_encoding_from(*value)) {
        require_same_value(protocol::provable_encoding_value(*encoding), input);
    }
    // As a bound: x within int64 whatever the encoding, and lo' <= hi' for
    // the bound at both ends.
    for (const protocol::ProvableEncoding& e : encodings) {
        if (const auto x = protocol::range_bound_x(e, *value)) {
            protocol::RangeProof proof;
            proof.field = "f";
            proof.low = *value;
            proof.high = *value;
            const auto bounds = protocol::range_public_values(e, proof);
            require(bounds && bounds->first == protocol::range_v(*x) &&
                    bounds->second == bounds->first);
        }
    }
    return 0;
}
