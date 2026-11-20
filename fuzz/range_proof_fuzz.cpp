// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// Feeds arbitrary bytes, as a proof, to the zero-knowledge range proof
// verifier (Longfellow ZK) against a fixed statement. It must refuse them, or
// accept a valid proof, without aborting, crashing, or hanging; and a proof it
// accepts must not hold for another statement. Its seeds (make_seeds) are
// proofs of the statement, so mutations reach every part of the proof's
// reader and of the verifier's checks.

#include <cstddef>
#include <cstdint>

#include <kanhe/core/bytes.hpp>
#include <kanhe/crypto/longfellow.hpp>

#include "range_proof_statement.hpp"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    namespace range = kanhe::crypto::longfellow;
    namespace statement = kanhe::fuzz::range_statement;
    static const kanhe::Bytes commitment = [] {
        auto c = range::range_commitment(statement::salt(), statement::value);
        if (!c) {
            __builtin_trap();
        }
        return *c;
    }();
    const auto transcript = kanhe::as_bytes(statement::transcript);
    const kanhe::ByteView proof(data, size);
    if (range::verify_range(commitment, statement::low, statement::high, transcript, proof)) {
        // Bound to its statement: not valid for a narrower range around the
        // same value.
        if (range::verify_range(commitment, statement::low + 1, statement::high, transcript,
                                proof)) {
            __builtin_trap();
        }
    }
    return 0;
}
