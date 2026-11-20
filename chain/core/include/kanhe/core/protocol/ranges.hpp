// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <kanhe/core/bytes.hpp>
#include <kanhe/core/cbor.hpp>
#include <kanhe/core/crypto.hpp>
#include <kanhe/core/error.hpp>
#include <kanhe/core/protocol/common.hpp>

/// Range proofs (spec v0.22, sections 6, 11, and 11.3): a registration's
/// provable values (key 8 of `record-register-body`), each a field's value
/// read as an integer x and committed to apart from the field's leaf; the
/// range proofs a record's evidence bundle carries (key 12), each a
/// zero-knowledge proof that one provable value lies within bounds; and
/// range openings files, which hold the values and salts a prover needs.
///
/// Everything but a proof's arithmetic is here: the shapes, the encodings and
/// the integers they read, the bounds, the public values, the commitment, the
/// transcript, and the words. The arithmetic of system 1 (Longfellow ZK) is a
/// `RangeVerifier` a verifier is given: the core links no proof system.
namespace kanhe::protocol {

/// Section 6: how a provable value is read as an integer x.
struct ProvableEncoding {
    enum class Type { number, money, date };
    Type type = Type::number;
    std::uint8_t scale = 0; // number 0..18, money 0..4, date 0
    std::string currency;   // money only: [A-Z]{3}; empty otherwise
    friend bool operator==(const ProvableEncoding&, const ProvableEncoding&) = default;
};

/// "number", "money", or "date".
[[nodiscard]] std::string_view name(ProvableEncoding::Type type) noexcept;

/// One entry of a registration's key 8.
struct ProvableValue {
    std::string name; // 1..64 bytes
    ProvableEncoding encoding;
    Bytes commitment; // 32 bytes
    friend bool operator==(const ProvableValue&, const ProvableValue&) = default;
};

/// Limits of key 8 (section 6).
inline constexpr std::size_t max_provable_values = 64;
inline constexpr std::size_t max_provable_name = 64;
inline constexpr std::uint8_t max_number_scale = 18;
inline constexpr std::uint8_t max_money_scale = 4;
/// The size of a provable value's salt s, and of its commitment.
inline constexpr std::size_t range_salt_size = 32;
inline constexpr std::size_t range_commitment_size = 32;

/// The commitment's 14 bytes of domain, and the transcript's first element.
inline constexpr std::string_view range_commitment_domain = "Kanhe range v1";
inline constexpr std::string_view range_transcript_label = "kanhe.range/1";

/// An encoding as key 8 writes it (`provable-encoding`), and back, with its
/// parameters' ranges checked (Errc::malformed).
[[nodiscard]] Result<cbor::Value> provable_encoding_value(const ProvableEncoding& encoding);
[[nodiscard]] Result<ProvableEncoding> provable_encoding_from(const cbor::Value& value);

/// Key 8's shape (section 6): 1 to 64 entries, names of 1 to 64 bytes
/// strictly ascending by their UTF-8 bytes, no more entries than
/// `field_count`, each encoding of its form, each commitment 32 bytes. Fails
/// with Errc::malformed (Errc::limit_exceeded for more than 64).
[[nodiscard]] Status check_provable(std::span<const ProvableValue> values,
                                    std::uint64_t field_count);
/// Key 8 as a registration encodes it, and back; both check its shape.
[[nodiscard]] Result<cbor::Value> provable_list_value(std::span<const ProvableValue> values,
                                                      std::uint64_t field_count);
[[nodiscard]] Result<std::vector<ProvableValue>> provable_list_from(const cbor::Value& value,
                                                                    std::uint64_t field_count);

/// The system numbers (section 11.3); only 1 is defined.
inline constexpr std::uint64_t range_system_longfellow = 1;

/// Limits of a bundle's key 12 (section 11.3).
inline constexpr std::size_t max_range_proofs = 16;
inline constexpr std::size_t max_range_proof_size = 262'144;
inline constexpr std::size_t max_range_context = 64;

/// One proof of a bundle's key 12.
struct RangeProof {
    std::string field;
    std::optional<cbor::Value> low; // in the claim value forms of the encoding
    std::optional<cbor::Value> high;
    std::uint64_t system = range_system_longfellow;
    Bytes proof;                  // 1..262144 bytes
    std::optional<Bytes> context; // 1..64 bytes
    friend bool operator==(const RangeProof&, const RangeProof&) = default;
};

/// A range proof as key 12 holds it (`range-proof`), and back: the CDDL's
/// shape (a field of 1 to 64 bytes, a low, a high, or both, neither null, a
/// proof of 1 to 262,144 bytes, a context of 1 to 64), checked both ways
/// (Errc::malformed). Bounds are checked against their provable's encoding
/// only when the proof is verified (section 11, step 13).
[[nodiscard]] Status check_range_proof(const RangeProof& proof);
[[nodiscard]] Result<cbor::Value> range_proof_value(const RangeProof& proof);
[[nodiscard]] Result<RangeProof> range_proof_from(const cbor::Value& value);

/// One opening (section 6): what the issuer keeps, and a holder is given.
struct RangeOpening {
    std::string name;
    Bytes salt; // 32 bytes
    std::int64_t x = 0;
    friend bool operator==(const RangeOpening&, const RangeOpening&) = default;
};

/// A range openings file (`.kanheopenings`, at most 65,536 bytes).
struct RangeOpenings {
    Id ledger;
    Id record;
    std::vector<RangeOpening> openings; // 1..64, names strictly ascending
    friend bool operator==(const RangeOpenings&, const RangeOpenings&) = default;
};
inline constexpr std::size_t max_range_openings_file = 65536;
/// The file's bytes (`range-openings`), and back: 1 to 64 openings, names of
/// 1 to 64 bytes strictly ascending, 32-byte salts, at most 65,536 bytes.
/// Fails with Errc::malformed, or Errc::limit_exceeded for a larger file.
[[nodiscard]] Result<Bytes> encode_range_openings(const RangeOpenings&);
[[nodiscard]] Result<RangeOpenings> decode_range_openings(ByteView);

/// v = x + 2^63.
[[nodiscard]] constexpr std::uint64_t range_v(std::int64_t x) noexcept {
    return static_cast<std::uint64_t>(x) ^ (std::uint64_t{1} << 63);
}
/// A bound (claim value form) read in `encoding`, as section 11.3 reads it:
/// refused (Errc::malformed, a message saying why) when not of the encoding's
/// form, of another currency or scale, with too many decimals, or out of range.
[[nodiscard]] Result<std::int64_t> range_bound_x(const ProvableEncoding&, const cbor::Value& bound);
/// The public values of a proof: [lo', hi']. Its bounds are read with
/// `range_bound_x`; a proof without either, or whose low is above its high,
/// is refused (Errc::malformed).
[[nodiscard]] Result<std::pair<std::uint64_t, std::uint64_t>>
range_public_values(const ProvableEncoding&, const RangeProof&);
/// C = SHA-256("Kanhe range v1" || salt || BE64(range_v(x))), through `provider`.
/// Fails with Errc::invalid_argument unless the salt is 32 bytes.
[[nodiscard]] Result<Bytes> range_commitment(const crypto::Provider&, ByteView salt,
                                             std::int64_t x);
/// T, the deterministic-CBOR transcript (section 11.3).
[[nodiscard]] Bytes range_transcript(const Id& ledger, const Id& record, std::string_view field,
                                     ByteView commitment, std::uint64_t lo, std::uint64_t hi,
                                     ByteView context);
/// The statement in words: "F is at least L", "F is at most H", "F is between L and H".
/// A bound not of the encoding's form is written in CBOR diagnostic notation.
[[nodiscard]] std::string range_words(const ProvableEncoding&, const RangeProof&);

/// What a verifier calls for system 1's arithmetic: ok when the proof verifies.
/// Empty: the verifier does not implement system 1 (proofs are "not checked").
using RangeVerifier = std::function<Status(ByteView commitment, std::uint64_t lo, std::uint64_t hi,
                                           ByteView transcript, ByteView proof)>;

} // namespace kanhe::protocol
