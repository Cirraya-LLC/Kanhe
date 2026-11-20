// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// The range proofs' interface: arguments and statements checked, then the
// engine (engine.cpp) called.

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>

#include <openssl/evp.h>

#include <kanhe/crypto/longfellow.hpp>

#include "engine.hpp"

namespace kanhe::crypto::longfellow {
namespace {

engine::Block to_block(ByteView bytes) {
    engine::Block block{};
    std::copy(bytes.begin(), bytes.end(), block.begin());
    return block;
}

/// SHA-256("Kanhe range v1" || salt || BE64(value)).
Result<engine::Block> commit(const engine::Block& salt, std::uint64_t value) {
    std::array<std::uint8_t, range_commitment_prefix.size() + range_salt_size + 8> message{};
    auto out =
        std::copy(range_commitment_prefix.begin(), range_commitment_prefix.end(), message.begin());
    out = std::copy(salt.begin(), salt.end(), out);
    for (unsigned j = 0; j < 8; ++j) {
        *out++ = static_cast<std::uint8_t>(value >> (56U - 8U * j));
    }
    engine::Block digest{};
    unsigned int size = 0;
    const bool ok = EVP_Digest(message.data(), message.size(), digest.data(), &size, EVP_sha256(),
                               nullptr) == 1 &&
                    size == digest.size();
    secure_wipe(message);
    if (!ok) {
        return fail(Errc::crypto_failure, "SHA-256 failed");
    }
    return digest;
}

} // namespace

Result<Bytes> range_commitment(ByteView salt, std::uint64_t value) {
    if (salt.size() != range_salt_size) {
        return fail(Errc::invalid_argument, "a range commitment's salt must be 32 bytes");
    }
    engine::Block block = to_block(salt);
    const auto digest = commit(block, value);
    secure_wipe(block);
    if (!digest) {
        return std::unexpected(digest.error());
    }
    return Bytes(digest->begin(), digest->end());
}

Result<Bytes> prove_range(ByteView salt, std::uint64_t value, std::uint64_t low, std::uint64_t high,
                          ByteView transcript, std::optional<ByteView> seed) {
    if (salt.size() != range_salt_size) {
        return fail(Errc::invalid_argument, "a range proof's salt must be 32 bytes");
    }
    if (seed && seed->size() != range_seed_size) {
        return fail(Errc::invalid_argument, "a range proof's seed must be 32 bytes");
    }
    if (transcript.size() > max_range_transcript_size) {
        return fail(Errc::limit_exceeded, "a range proof's transcript is at most 1 MiB");
    }
    if (value < low || value > high) {
        return fail(Errc::invalid_argument, "the value is outside the range");
    }
    engine::Block block = to_block(salt);
    const auto commitment = commit(block, value);
    if (!commitment) {
        secure_wipe(block);
        return std::unexpected(commitment.error());
    }
    const engine::Statement statement{*commitment, low, high};
    engine::Block seed_block{};
    if (seed) {
        seed_block = to_block(*seed);
    }
    auto proof = engine::prove(statement, block, value, transcript, seed ? &seed_block : nullptr);
    secure_wipe(block);
    secure_wipe(seed_block);
    return proof;
}

Status verify_range(ByteView commitment, std::uint64_t low, std::uint64_t high, ByteView transcript,
                    ByteView proof) {
    if (commitment.size() != range_commitment_size) {
        return fail(Errc::invalid_argument, "a range commitment is 32 bytes");
    }
    if (transcript.size() > max_range_transcript_size) {
        return fail(Errc::limit_exceeded, "a range proof's transcript is at most 1 MiB");
    }
    if (proof.size() > max_range_proof_size) {
        return fail(Errc::limit_exceeded, "a range proof is at most 256 KiB");
    }
    if (low > high) {
        return fail(Errc::verification_failed, "the range is empty");
    }
    return engine::verify(engine::Statement{to_block(commitment), low, high}, transcript, proof);
}

ByteView range_circuit_id() noexcept {
    return engine::pinned_circuit_id;
}

Status prepare_range_circuit() {
    return engine::ready();
}

Status load_range_circuit(ByteView serialized) {
    return engine::load(serialized);
}

Result<Bytes> range_circuit_bytes() {
    return engine::circuit_bytes();
}

} // namespace kanhe::crypto::longfellow
