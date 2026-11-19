// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include "envelope.hpp"

#include <string>

#include <kanhe/core/protocol/log.hpp>

namespace kanhe::protocol::detail {

namespace {

/// `parse_envelope`, and with `iat` also `parse_dated_envelope`.
Result<Envelope> parse_with(ByteView encoded, std::string_view content_type,
                            std::optional<std::uint64_t>* iat) {
    auto message = cose::parse(encoded);
    if (!message) {
        return std::unexpected(message.error());
    }
    const cbor::Map* protected_map = message->protected_header.as_map();
    // A dated cosignature's time (v0.21): CWT claims holding iat alone.
    std::size_t expected = 3;
    if (const cbor::Value* claims = message->protected_header.find(label_cwt_claims);
        claims != nullptr && iat != nullptr) {
        const cbor::Map* map = claims->as_map();
        const bool only_iat =
            map != nullptr && map->size() == 1 &&
            (*map)[0].key.as_uint64() == static_cast<std::uint64_t>(cwt_claim_iat);
        const auto seconds = only_iat ? (*map)[0].value.as_uint64() : std::nullopt;
        if (!seconds) {
            return fail(Errc::malformed,
                        "a cosignature's CWT claims (header 15) must hold exactly iat (6), an "
                        "unsigned integer");
        }
        *iat = *seconds;
        expected = 4;
    }
    if (protected_map == nullptr || protected_map->size() != expected) {
        return fail(Errc::malformed, "protected header must be exactly {alg, content type, kid}");
    }
    const cbor::Value* type = message->protected_header.find(cose::label_content_type);
    const cbor::Value* kid = message->protected_header.find(cose::label_kid);
    if (type == nullptr || kid == nullptr) {
        return fail(Errc::malformed, "protected header must be exactly {alg, content type, kid}");
    }
    const std::string* type_text = type->as_text();
    if (type_text == nullptr || *type_text != content_type) {
        return fail(Errc::malformed, "unexpected content type");
    }
    const Bytes* kid_bytes = kid->as_bytes();
    if (kid_bytes == nullptr) {
        return fail(Errc::malformed, "kid must be a byte string");
    }
    auto kid_id = to_id(*kid_bytes);
    if (!kid_id) {
        return std::unexpected(kid_id.error());
    }
    const cbor::Map* unprotected = message->unprotected_header.as_map();
    if (unprotected == nullptr || !unprotected->empty()) {
        return fail(Errc::malformed, "unprotected header must be empty");
    }
    if (!message->payload) {
        return fail(Errc::malformed, "payload must be attached");
    }
    return Envelope{std::move(*message), *kid_id};
}

} // namespace

Result<Bytes> sign_envelope(const crypto::Signer& signer, const crypto::Provider& provider,
                            crypto::HashAlg hash, ByteView payload, std::string_view content_type,
                            std::optional<std::uint64_t> iat) {
    auto kid = key_id(provider, hash, signer.public_key());
    if (!kid) {
        return std::unexpected(kid.error());
    }
    cose::SignOptions options;
    options.protected_header = {
        {cbor::Value::integer(cose::label_content_type),
         cbor::Value::text(std::string(content_type))},
        {cbor::Value::integer(cose::label_kid), cbor::Value::bytes(kid->bytes())},
    };
    if (iat) {
        options.protected_header.push_back(
            {cbor::Value::integer(label_cwt_claims),
             cbor::Value::map(
                 {{cbor::Value::integer(cwt_claim_iat), cbor::Value::unsigned_integer(*iat)}})});
    }
    return cose::sign(signer, payload, options);
}

Result<Envelope> parse_envelope(ByteView encoded, std::string_view content_type) {
    return parse_with(encoded, content_type, nullptr);
}

Result<Envelope> parse_dated_envelope(ByteView encoded, std::string_view content_type,
                                      std::optional<std::uint64_t>& iat) {
    iat.reset();
    return parse_with(encoded, content_type, &iat);
}

Status verify_envelope(const crypto::Provider& provider, crypto::HashAlg hash,
                       const Envelope& envelope, const crypto::PublicKey& key) {
    auto expected = key_id(provider, hash, key);
    if (!expected) {
        return std::unexpected(expected.error());
    }
    if (*expected != envelope.kid) {
        return fail(Errc::verification_failed, "key does not match the kid in the header");
    }
    return cose::verify(provider, envelope.message, key);
}

} // namespace kanhe::protocol::detail
