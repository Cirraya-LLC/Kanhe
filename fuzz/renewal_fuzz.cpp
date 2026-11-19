// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// Long-term evidence (spec v0.21) comes from whoever holds a bundle: a
// renewal a ledger's server or an archive answers (GET /v1/renewal), the
// renewals a bundle carries (key 11), and a witness's cosignature with its
// time (the CWT claims of its protected header, label 15); and a verifier's
// --distrust options from whoever types them. Reading any of them must refuse
// what is not one, never crash, and what it accepts must encode back to the
// same bytes. A bundle with renewals is verified too, with and without
// distrusting an algorithm.

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <span>
#include <string>

#include <kanhe/core/protocol/evidence.hpp>
#include <kanhe/core/protocol/log.hpp>
#include <kanhe/crypto/openssl.hpp>

namespace protocol = kanhe::protocol;

namespace {

void require(bool condition) {
    if (!condition) {
        std::abort();
    }
}

template <class Encoded>
void require_same(const Encoded& encoded, kanhe::ByteView input) {
    require(encoded.has_value() && std::ranges::equal(*encoded, input));
}

void require_bounds(const protocol::Renewal& r) {
    require(!r.cosignatures.empty() || !r.timestamps.empty() || !r.network_cosignatures.empty());
    require(r.consistency.size() <= 65 && r.rotations.size() <= protocol::max_key_rotations);
    for (const auto& rotation : r.rotations) {
        require(rotation.path.size() <= 65);
    }
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    static const kanhe::crypto::openssl::Provider provider;
    const kanhe::ByteView input(data, size);

    // A renewal alone: within the CDDL's bounds, and the same again.
    if (const auto renewal = protocol::decode_renewal(input)) {
        require_bounds(*renewal);
        require_same(protocol::encode_renewal(*renewal), input);
    }

    // A bundle's renewals: each one written alone reads back the same, and
    // the bundle verifies or not without crashing, distrust or none.
    if (const auto bundle = protocol::decode_bundle(input)) {
        require(bundle->renewals.size() <= protocol::max_renewals);
        for (const protocol::Renewal& r : bundle->renewals) {
            require_bounds(r);
            const auto alone = protocol::encode_renewal(r);
            require(alone.has_value());
            const auto again = protocol::decode_renewal(*alone);
            require(again.has_value() && *again == r);
        }
        if (!bundle->renewals.empty()) {
            protocol::VerifyOptions options;
            static_cast<void>(protocol::verify_bundle(provider, input, options));
            options.distrust = {{kanhe::crypto::SignatureFamily::ed25519, 1'800'000'000'000},
                                {kanhe::crypto::SignatureFamily::ml_dsa_65, 0}};
            if (const auto report = protocol::verify_bundle(provider, input, options)) {
                require(report->renewals.size() == bundle->renewals.size());
                require(!report->long_term.post_quantum() ||
                        !report->long_term.attested_by.empty());
            }
        }
    }

    // A cosignature, dated or not: a time only with exactly {6: iat}, and
    // the header then of four parameters.
    if (const auto cosignature = protocol::parse_cosignature(input)) {
        const auto* header = cosignature->envelope.protected_header.as_map();
        require(header != nullptr && header->size() == (cosignature->witness_time ? 4U : 3U));
        const auto* claims =
            cosignature->envelope.protected_header.find(protocol::label_cwt_claims);
        require((claims != nullptr) == cosignature->witness_time.has_value());
        if (claims != nullptr) {
            require(claims->find(protocol::cwt_claim_iat)->as_uint64() ==
                    cosignature->witness_time);
        }
        static_cast<void>(protocol::verify_cosignature(
            provider, *cosignature, {kanhe::crypto::SigAlg::ed25519, kanhe::Bytes(32, 7)}));
    }
    // A checkpoint never carries a time.
    if (const auto checkpoint = protocol::parse_checkpoint(input)) {
        require(!checkpoint->witness_time &&
                checkpoint->envelope.protected_header.as_map()->size() == 3);
    }

    // --distrust ALG@YYYY-MM-DD, as typed: each algorithm once, in order,
    // from 1970 on, at midnight.
    const std::string text(reinterpret_cast<const char*>(data), size);
    if (const auto parsed = protocol::parse_distrust(std::span(&text, 1))) {
        require(!parsed->empty() && parsed->size() <= 5);
        for (std::size_t i = 0; i < parsed->size(); ++i) {
            require((*parsed)[i].after % 86'400'000 == 0);
            require(i == 0 || (*parsed)[i - 1].algorithm < (*parsed)[i].algorithm);
        }
    }
    return 0;
}
