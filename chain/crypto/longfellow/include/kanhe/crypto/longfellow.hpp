// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string_view>

#include <kanhe/core/bytes.hpp>
#include <kanhe/core/error.hpp>

/// Zero-knowledge range proofs over a salted SHA-256 commitment, with Google's
/// Longfellow ZK library: sumcheck and Ligero over GF(2^128), hash-based, with
/// no trusted setup.
///
/// The one statement proved:
///
///     C = SHA-256("Kanhe range v1" || s || BE64(v))   and   low <= v <= high
///
/// where v, low, and high are unsigned 64-bit integers, C, low, and high are
/// public, and the 32-byte salt s and the value v stay private. The message is
/// 54 bytes, one SHA-256 block. A one-sided statement uses low = 0 or
/// high = 2^64 - 1, so one circuit serves every statement.
///
/// The circuit is built from code, once per process, on first use (about
/// 0.4 s and 47 MB at its peak in an optimized build) and shared by the prover
/// and the verifier. It is checked against its pinned id: if the circuit built
/// differs from the pinned one, every call that needs it fails with
/// `Errc::crypto_failure`.
///
/// The proof system's parameters are those of Longfellow's version 7: Ligero
/// with rate 7 and 132 queries, the LCH14 Reed-Solomon code, and transcript
/// version 7. A proof is about 84 KB; proving takes about 45 ms and verifying
/// about 10 ms in an optimized build. Every function here is thread-safe.
namespace kanhe::crypto::longfellow {

inline constexpr std::size_t range_salt_size = 32;
inline constexpr std::size_t range_commitment_size = 32;
inline constexpr std::size_t range_seed_size = 32;
inline constexpr std::size_t range_circuit_id_size = 32;

/// Proofs longer than this are refused before they are read.
inline constexpr std::size_t max_range_proof_size = 256 * 1024;

/// The longest transcript accepted (the bytes a proof is bound to).
inline constexpr std::size_t max_range_transcript_size = 1024 * 1024;

/// The commitment's domain-separation prefix, 14 bytes of ASCII.
inline constexpr std::string_view range_commitment_prefix = "Kanhe range v1";

/// C = SHA-256("Kanhe range v1" || salt || BE64(value)), 32 bytes. Fails with
/// `Errc::invalid_argument` if the salt is not 32 bytes.
[[nodiscard]] Result<Bytes> range_commitment(ByteView salt, std::uint64_t value);

/// A proof that the value committed to with `salt` lies in [low, high].
///
/// `transcript` is the Fiat-Shamir transcript's initial bytes: they bind the
/// proof to its context (what was committed to, where, and why), and the
/// verifier must supply the same bytes. The proof is about 84 KB.
///
/// The prover's randomness is what makes the proof zero-knowledge. Without
/// `seed`, it comes from OpenSSL's CSPRNG, fresh for every proof. With a
/// 32-byte `seed`, it is the AES-256-CTR keystream under the seed (zero IV),
/// so the same inputs give the same proof with the same version of the
/// library. That is for test vectors only: whoever knows the seed can recover
/// the salt and the value from the proof.
///
/// Fails with `Errc::invalid_argument` if the salt or the seed is not 32
/// bytes or the value lies outside [low, high] (an empty range included),
/// `Errc::limit_exceeded` if the transcript is longer than
/// `max_range_transcript_size`, and `Errc::crypto_failure` if the circuit does
/// not match its pinned id or the prover fails.
[[nodiscard]] Result<Bytes> prove_range(ByteView salt, std::uint64_t value, std::uint64_t low,
                                        std::uint64_t high, ByteView transcript,
                                        std::optional<ByteView> seed = std::nullopt);

/// Verifies a proof that the value committed to in `commitment` lies in
/// [low, high], for `transcript`. The whole proof must be read, with nothing
/// left over. Malformed input never aborts: it fails.
///
/// Fails with `Errc::invalid_argument` if the commitment is not 32 bytes,
/// `Errc::limit_exceeded` if the transcript is longer than
/// `max_range_transcript_size` or the proof longer than
/// `max_range_proof_size` (the proof unread), `Errc::malformed` if the proof
/// does not parse or has bytes left over, `Errc::verification_failed` if the
/// range is empty or the proof does not verify, and `Errc::crypto_failure` if
/// the circuit does not match its pinned id.
[[nodiscard]] Status verify_range(ByteView commitment, std::uint64_t low, std::uint64_t high,
                                  ByteView transcript, ByteView proof);

/// The circuit's pinned id (32 bytes): Longfellow's circuit id, a SHA-256 of
/// the circuit's field, dimensions, and terms, which every proof's transcript
/// absorbs.
[[nodiscard]] ByteView range_circuit_id() noexcept;

/// Builds the circuit now, if it has not been built, and checks it against its
/// pinned id; a server calls this when it starts, instead of paying for it on
/// its first proof. Fails with `Errc::crypto_failure` on a mismatch.
[[nodiscard]] Status prepare_range_circuit();

/// The circuit in Longfellow's serialized form (about 2 MB), for verifiers
/// that load a circuit instead of building it. It is read back, and its id
/// recomputed, before it is returned. Fails with `Errc::crypto_failure` if the
/// circuit does not match its pinned id.
[[nodiscard]] Result<Bytes> range_circuit_bytes();

} // namespace kanhe::crypto::longfellow
