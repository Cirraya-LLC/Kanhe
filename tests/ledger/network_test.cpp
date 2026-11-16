// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// Open-network witnesses' cosignatures in evidence anchors (spec v0.13): a
// verifier counts those of witnesses it trusts, by their verifier keys, as
// it counts its own witnesses', each witness once; it refuses one that does
// not verify, and any in an SM3 ledger's bundle.

#include <cstdint>
#include <optional>

#include <catch2/catch_test_macros.hpp>

#include <kanhe/core/protocol/evidence.hpp>
#include <kanhe/core/protocol/network.hpp>

#include "support/ledger_world.hpp"
#include "support/network_witness.hpp"

namespace {

using namespace kanhe::test;
using kanhe::Bytes;
using kanhe::Errc;
namespace network = kanhe::protocol::network;

constexpr std::uint64_t seen = 1'794'000'000;

kanhe::Result<protocol::EvidenceReport> verify(const protocol::EvidenceBundle& bundle,
                                               const protocol::VerifyOptions& options) {
    auto encoded = protocol::encode_bundle(bundle);
    REQUIRE(encoded);
    REQUIRE(*protocol::decode_bundle(*encoded) == bundle);
    return protocol::verify_bundle(provider(), *encoded, options);
}

protocol::VerifyOptions trusting(std::initializer_list<const NetworkWitness*> witnesses) {
    protocol::VerifyOptions options;
    for (const NetworkWitness* w : witnesses) {
        options.trusted_network_witnesses.push_back(w->vkey());
    }
    return options;
}

} // namespace

TEST_CASE("a verifier counts trusted network witnesses' cosignatures of anchors", "[network]") {
    World w;
    const protocol::Id record =
        w.ok(w.org(), w.statement(w.org_id(), std::nullopt, w.record_body(document_type)));
    auto checkpoint = w.ledger().checkpoint(w.log_key());
    REQUIRE(checkpoint);
    auto bundle = w.ledger().export_evidence(w.log_key(), record);
    REQUIRE(bundle);
    const auto& at = checkpoint->checkpoint;
    const std::string origin = network::origin(w.ledger().id());

    const NetworkWitness ed("witness.example/ed25519");
    const NetworkWitness ml("witness.example/ml-dsa-44", true);
    const NetworkWitness stranger("witness.example/stranger");
    bundle->anchors.push_back(protocol::Anchor{
        .checkpoint = checkpoint->encoded,
        .timestamps = {},
        .consistency = {},
        .network_cosignatures = {ed.cosign(origin, at.tree_size, at.root, seen),
                                 ml.cosign(origin, at.tree_size, at.root, seen + 1),
                                 stranger.cosign(origin, at.tree_size, at.root, seen)},
    });

    auto report = verify(*bundle, trusting({&ed, &ml}));
    REQUIRE(report);
    CHECK(report->trusted_cosignatures == 2);
    CHECK(report->untrusted_cosignatures == 1);
    REQUIRE(report->network_cosignatures.size() == 3);
    CHECK(report->network_cosignatures[0] ==
          protocol::NetworkCosignatureCheck{"witness.example/ed25519", at.tree_size, seen, true});
    CHECK(report->network_cosignatures[1].time == seen + 1);
    CHECK_FALSE(report->network_cosignatures[2].trusted);

    // Trusting none: all counted, none relied on.
    report = verify(*bundle, {});
    REQUIRE(report);
    CHECK(report->trusted_cosignatures == 0);
    CHECK(report->untrusted_cosignatures == 3);

    // One witness in two anchors is still one witness.
    auto twice = *bundle;
    twice.anchors.push_back(twice.anchors[0]);
    report = verify(twice, trusting({&ed, &ml}));
    REQUIRE(report);
    CHECK(report->trusted_cosignatures == 2);

    auto failure = [&](const protocol::EvidenceBundle& b, const protocol::VerifyOptions& options) {
        auto r = verify(b, options);
        REQUIRE_FALSE(r);
        return r.error().code;
    };
    // A trusted witness's cosignature of another size, or with its time
    // changed, fails the evidence; an untrusted one's is only counted.
    auto other = *bundle;
    other.anchors[0].network_cosignatures[0] = ed.cosign(origin, at.tree_size + 1, at.root, seen);
    CHECK(failure(other, trusting({&ed})) == Errc::verification_failed);
    CHECK(verify(other, {}));
    other = *bundle;
    other.anchors[0].network_cosignatures[1].bytes[11] ^= 0x01;
    CHECK(failure(other, trusting({&ml})) == Errc::verification_failed);
    // Of another ledger's origin.
    other = *bundle;
    other.anchors[0].network_cosignatures[0] =
        ed.cosign("cirraya.com/kanhe/" + std::string(64, '0'), at.tree_size, at.root, seen);
    CHECK(failure(other, trusting({&ed})) == Errc::verification_failed);

    // Two trusted keys with one name and one 4-byte key ID (made here; by
    // chance, rare): the cosignature is the one's it verifies with, whichever
    // comes first, and each key that verifies one is a witness of its own.
    const NetworkWitness lookalike("witness.example/ed25519");
    network::VerifierKey same_id = lookalike.vkey();
    same_id.id = ed.vkey().id;
    protocol::VerifyOptions both;
    both.trusted_network_witnesses = {same_id, ed.vkey()};
    other = *bundle;
    other.anchors[0].network_cosignatures.resize(1);
    report = verify(other, both);
    REQUIRE(report);
    CHECK(report->trusted_cosignatures == 1);
    both.trusted_network_witnesses = {same_id};
    CHECK(failure(other, both) == Errc::verification_failed);
}

TEST_CASE("an anchor holds tokens or network cosignatures, and SM3 ledgers none of the latter",
          "[network]") {
    World w(crypto::HashAlg::sm3);
    const protocol::Id record =
        w.ok(w.org(), w.statement(w.org_id(), std::nullopt, w.record_body(document_type)));
    auto checkpoint = w.ledger().checkpoint(w.log_key());
    REQUIRE(checkpoint);
    auto bundle = w.ledger().export_evidence(w.log_key(), record);
    REQUIRE(bundle);
    const NetworkWitness ed("witness.example/ed25519");
    const auto& at = checkpoint->checkpoint;
    bundle->anchors.push_back(protocol::Anchor{
        .checkpoint = checkpoint->encoded,
        .timestamps = {},
        .consistency = {},
        .network_cosignatures = {ed.cosign(network::origin(w.ledger().id()), at.tree_size, at.root,
                                           seen)},
    });
    auto refused = verify(*bundle, trusting({&ed}));
    REQUIRE_FALSE(refused);
    CHECK(refused.error().code == Errc::verification_failed);

    // An anchor with neither does not encode, nor decode.
    bundle->anchors[0].network_cosignatures.clear();
    CHECK(protocol::encode_bundle(*bundle).error().code == Errc::invalid_argument);
}
