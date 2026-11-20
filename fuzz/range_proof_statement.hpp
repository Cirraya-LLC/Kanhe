// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// The statement range_proof_fuzz checks proofs against, and make_seeds proves.

#pragma once

#include <cstdint>
#include <string_view>

#include <kanhe/core/bytes.hpp>

namespace kanhe::fuzz::range_statement {

inline constexpr std::uint64_t value = 1'700'000'000'000;
inline constexpr std::uint64_t low = 1'000'000'000'000;
inline constexpr std::uint64_t high = 2'000'000'000'000;
inline constexpr std::string_view transcript = "range_proof_fuzz statement";

inline Bytes salt() {
    return Bytes(32, 0x5a);
}

} // namespace kanhe::fuzz::range_statement
