// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// The part of the range proofs that calls into Longfellow ZK (engine.cpp),
// behind plain types: the only translation unit that includes the library's
// headers. Its callers (range.cpp) have checked every argument's size and the
// statement already.

#pragma once

#include <array>
#include <cstdint>

#include <kanhe/core/bytes.hpp>
#include <kanhe/core/error.hpp>

namespace kanhe::crypto::longfellow::engine {

using Block = std::array<std::uint8_t, 32>;

/// The public statement: C, low, and high.
struct Statement {
    Block commitment{};
    std::uint64_t low = 0;
    std::uint64_t high = 0;
};

/// The pinned circuit id.
extern const Block pinned_circuit_id;

/// Builds the circuit once per process (thread-safe) and checks its id.
[[nodiscard]] Status ready();

/// The circuit, serialized, read back and checked.
[[nodiscard]] Result<Bytes> circuit_bytes();

/// Proves `statement` for the salt and value (low <= value <= high, and the
/// commitment theirs). `seed` is null for fresh randomness.
[[nodiscard]] Result<Bytes> prove(const Statement& statement, const Block& salt,
                                  std::uint64_t value, ByteView transcript, const Block* seed);

/// Verifies a proof of `statement` (its size checked already).
[[nodiscard]] Status verify(const Statement& statement, ByteView transcript, ByteView proof);

} // namespace kanhe::crypto::longfellow::engine
