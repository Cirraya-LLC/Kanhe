// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string_view>

#include <kanhe/core/bytes.hpp>
#include <kanhe/core/cbor.hpp>
#include <kanhe/core/crypto.hpp>
#include <kanhe/core/error.hpp>

/// Types shared by the Kanhe protocol objects. The normative
/// definition of every structure is spec/kanhe.cddl.
namespace kanhe::protocol {

inline constexpr std::uint64_t protocol_version = 1;
/// The specification revision this implementation follows (spec/README.md).
inline constexpr std::string_view spec_revision = "v0.21";

/// Identifiers (statement, ledger, actor, key) are digests under the ledger's
/// hash algorithm. Ledgers use SHA-256 or SM3, so identifiers are 32
/// bytes.
inline constexpr std::size_t id_size = 32;
using Id = crypto::Digest;

/// Unix time in milliseconds.
using Timestamp = std::uint64_t;

using Nonce = std::array<std::uint8_t, 16>;

/// The size of the salts issuers make for record fields and attachments
/// (spec section 6, v0.21): Grover's algorithm searches a 16-byte salt in
/// about 2^64 steps per guessed value, a 32-byte one in about 2^128.
inline constexpr std::size_t salt_size = 32;

/// A record field's or an attachment's salt (spec section 6): 16 or 32
/// bytes, kept inline. Verifiers accept both (v0.21), so records issued
/// with 16-byte salts still open; issuers make `salt_size` bytes. A
/// contiguous range of bytes, so it is a ByteView wherever one is taken.
/// Statement nonces stay `Nonce`, 16 bytes.
class Salt {
public:
    static constexpr std::size_t max_size = 32;

    /// 16 zero bytes, as a default Nonce was.
    Salt() noexcept : size_(16) {}
    // NOLINTNEXTLINE(google-explicit-constructor): fresh bytes of either size.
    Salt(const std::array<std::uint8_t, 16>& bytes) noexcept;
    // NOLINTNEXTLINE(google-explicit-constructor)
    Salt(const std::array<std::uint8_t, 32>& bytes) noexcept;

    /// Fails with Errc::malformed unless `bytes` is 16 or 32 bytes.
    [[nodiscard]] static Result<Salt> from_bytes(ByteView bytes);
    /// True for the sizes a salt may have: 16 and 32.
    [[nodiscard]] static constexpr bool valid_size(std::size_t size) noexcept {
        return size == 16 || size == 32;
    }

    [[nodiscard]] ByteView bytes() const noexcept { return {data_.data(), size_}; }
    [[nodiscard]] const std::uint8_t* data() const noexcept { return data_.data(); }
    [[nodiscard]] std::size_t size() const noexcept { return size_; }
    [[nodiscard]] const std::uint8_t* begin() const noexcept { return data_.data(); }
    [[nodiscard]] const std::uint8_t* end() const noexcept { return data_.data() + size_; }

    /// Bytes beyond the size are always zero, so this compares the bytes.
    friend bool operator==(const Salt&, const Salt&) = default;

private:
    std::array<std::uint8_t, max_size> data_{};
    std::uint8_t size_;
};

inline constexpr std::string_view statement_content_type = "application/kanhe-statement+cbor";
inline constexpr std::string_view checkpoint_content_type = "application/kanhe-checkpoint+cbor";
inline constexpr std::string_view cosignature_content_type = "application/kanhe-cosignature+cbor";
/// An approval of a statement (spec v0.20), signed by the approver's key.
inline constexpr std::string_view approval_content_type = "application/kanhe-approval+cbor";

/// At most this many approvals travel beside one statement, in a submission
/// and in its log entry (spec v0.20), each at most this many bytes encoded.
inline constexpr std::size_t max_approvals = 32;
inline constexpr std::size_t max_approval_size = 24'576;

/// True for the hash algorithms a ledger may use: SHA-256 and SM3.
[[nodiscard]] bool is_ledger_hash(crypto::HashAlg alg) noexcept;

/// Encodes a public key as [alg, key].
[[nodiscard]] cbor::Value encode_public_key(const crypto::PublicKey& key);

/// Decodes [alg, key], checking that the algorithm is known and the key has
/// the algorithm's size.
[[nodiscard]] Result<crypto::PublicKey> decode_public_key(const cbor::Value& value);

/// The key identifier used as COSE kid: HASH(deterministic-CBOR([alg, key])).
[[nodiscard]] Result<Id> key_id(const crypto::Provider& provider, crypto::HashAlg alg,
                                const crypto::PublicKey& key);

/// Checks that `bytes` has the identifier size and wraps it.
[[nodiscard]] Result<Id> to_id(ByteView bytes);

} // namespace kanhe::protocol
