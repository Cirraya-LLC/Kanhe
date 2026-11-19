// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// Spec v0.21 objects: field and attachment salts of 16 or 32 bytes, renewals
// read and written, dated cosignatures (the CWT claims of their protected
// header), and the distrust option; then the vectors of
// testvectors/protocol-v0.21.json, made apart from this implementation: the
// archive ledger's renewal parts, and every bundle verified with its
// options, reaching its verdict and, when verified, the facts its report
// must show (renewals, the long-term status, distrusted signatures with what
// covers each), compared with the JSON report as both verifiers give it.

#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <string>
#include <utility>
#include <vector>

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>

#include <kanhe/core/cbor.hpp>
#include <kanhe/core/cose.hpp>
#include <kanhe/core/merkle.hpp>
#include <kanhe/core/protocol/evidence.hpp>
#include <kanhe/core/protocol/log.hpp>
#include <kanhe/core/protocol/network.hpp>
#include <kanhe/core/protocol/record.hpp>
#include <kanhe/crypto/openssl.hpp>
#include <kanhe/verifier/report.hpp>

#include "support/vectors.hpp"

namespace protocol = kanhe::protocol;
namespace crypto = kanhe::crypto;
namespace cbor = kanhe::cbor;
using kanhe::Bytes;
using kanhe::test::hex;
using kanhe::test::load_vectors;

namespace {

const crypto::Provider& provider() {
    static const crypto::openssl::Provider instance;
    return instance;
}

const nlohmann::json& vectors() {
    static const nlohmann::json document = load_vectors("protocol-v0.21.json");
    return document;
}

std::string text(const nlohmann::json& value) {
    return value.get<std::string>();
}

/// A bundle that decode_bundle reads up to `key` (its entries are only
/// shaped, not checked, when decoded).
Bytes bundle_with(std::int64_t key, cbor::Value value) {
    cbor::Map map{
        {cbor::Value::integer(0), cbor::Value::unsigned_integer(1)},
        {cbor::Value::integer(1), cbor::Value::bytes(Bytes(32, 0))},
        {cbor::Value::integer(2),
         cbor::Value::array(
             {cbor::Value::array({cbor::Value::bytes(Bytes{0}), cbor::Value::bytes(Bytes{0})})})},
        {cbor::Value::integer(3), cbor::Value::bytes(Bytes{0})},
        {cbor::Value::integer(key), std::move(value)},
    };
    auto encoded = cbor::encode(cbor::Value::map(std::move(map)));
    REQUIRE(encoded);
    return *encoded;
}

cbor::Value decoded(const nlohmann::json& hex_text) {
    auto value = cbor::decode(hex(text(hex_text)));
    REQUIRE(value);
    return *value;
}

/// The options a bundle's vector names, as `kanhe verify` reads them.
protocol::VerifyOptions options_of(const nlohmann::json& o) {
    protocol::VerifyOptions options;
    if (o.contains("ledger_id")) {
        options.expected_ledger = *protocol::to_id(hex(text(o["ledger_id"])));
    }
    for (const auto& w : o.value("witnesses", nlohmann::json::array())) {
        auto key = protocol::decode_public_key(decoded(w));
        REQUIRE(key);
        options.trusted_witnesses.push_back(*key);
    }
    for (const auto& v : o.value("witness_vkeys", nlohmann::json::array())) {
        auto key = protocol::network::parse_verifier_key(provider(), text(v));
        REQUIRE(key);
        options.trusted_network_witnesses.push_back(*key);
    }
    for (const auto& pem : o.value("tsa_roots", nlohmann::json::array())) {
        const std::string root = text(pem);
        auto roots = crypto::openssl::read_certificates(kanhe::as_bytes(root));
        REQUIRE(roots);
        options.trusted_timestamp_roots.insert(options.trusted_timestamp_roots.end(),
                                               roots->begin(), roots->end());
    }
    if (o.contains("attachments")) {
        for (const auto& [name, content] : o["attachments"].items()) {
            options.attachment_contents[name] = hex(text(content));
        }
    }
    std::vector<std::string> distrust;
    for (const auto& d : o.value("distrust", nlohmann::json::array())) {
        distrust.push_back(text(d));
    }
    auto parsed = protocol::parse_distrust(distrust);
    REQUIRE(parsed);
    options.distrust = std::move(*parsed);
    return options;
}

/// As tests/verifiers/conformance.py matches a case's facts: an object
/// matches when each of its keys is in the report with a matching value, a
/// list one of the same length element by element, anything else an equal
/// value.
bool matches(const nlohmann::json& fact, const nlohmann::json& value, const std::string& path,
             std::string& where) {
    if (fact.is_object()) {
        if (!value.is_object()) {
            where = path;
            return false;
        }
        for (const auto& [key, item] : fact.items()) {
            if (!value.contains(key) || !matches(item, value[key], path + "." + key, where)) {
                if (where.empty()) {
                    where = path + "." + key;
                }
                return false;
            }
        }
        return true;
    }
    if (fact.is_array()) {
        if (!value.is_array() || value.size() != fact.size()) {
            where = path;
            return false;
        }
        for (std::size_t i = 0; i < fact.size(); ++i) {
            if (!matches(fact[i], value[i], path + "[" + std::to_string(i) + "]", where)) {
                return false;
            }
        }
        return true;
    }
    if (fact.is_boolean() != value.is_boolean() || fact != value) {
        where = path + ": " + value.dump() + ", not " + fact.dump();
        return false;
    }
    return true;
}

/// A cosignature by `key` of `checkpoint`, with these CWT claims (label 15)
/// in its protected header, however malformed.
Bytes cosignature_with(const crypto::Signer& key, const protocol::Checkpoint& checkpoint,
                       cbor::Value claims) {
    auto kid = protocol::key_id(provider(), checkpoint.tree_hash, key.public_key());
    REQUIRE(kid);
    auto payload = protocol::encode_checkpoint(checkpoint);
    REQUIRE(payload);
    kanhe::cose::SignOptions options;
    options.protected_header = {
        {cbor::Value::integer(kanhe::cose::label_content_type),
         cbor::Value::text(std::string(protocol::cosignature_content_type))},
        {cbor::Value::integer(kanhe::cose::label_kid), cbor::Value::bytes(kid->bytes())},
        {cbor::Value::integer(protocol::label_cwt_claims), std::move(claims)},
    };
    auto signed_bytes = kanhe::cose::sign(key, *payload, options);
    REQUIRE(signed_bytes);
    return *signed_bytes;
}

} // namespace

TEST_CASE("v0.21 salts: fields and attachments with 16 or 32 bytes, and no other size",
          "[protocol][vectors][v021]") {
    const auto& fields = vectors()["salts"]["field_leaves"];
    for (const auto& c : fields["valid"]) {
        const Bytes leaf = hex(text(c["leaf"]));
        const auto field = protocol::decode_field(leaf);
        REQUIRE(field);
        CHECK(field->salt.size() == c["salt_size"].get<std::size_t>());
        const auto again = protocol::encode_field(*field);
        REQUIRE(again);
        CHECK(*again == leaf);
    }
    for (const auto& c : fields["refused"]) {
        INFO(text(c["name"]));
        CHECK_FALSE(protocol::decode_field(hex(text(c["leaf"]))));
    }
    const auto& openings = vectors()["salts"]["attachment_openings"];
    for (const auto& c : openings["valid"]) {
        const auto bundle =
            protocol::decode_bundle(bundle_with(6, cbor::Value::array({decoded(c["opening"])})));
        REQUIRE(bundle);
        REQUIRE(bundle->attachments.size() == 1);
        CHECK(bundle->attachments[0].salt.size() == c["salt_size"].get<std::size_t>());
    }
    for (const auto& c : openings["refused"]) {
        INFO(text(c["name"]));
        CHECK_FALSE(
            protocol::decode_bundle(bundle_with(6, cbor::Value::array({decoded(c["opening"])}))));
    }

    // The salt itself: 16 or 32 bytes, and an attachment's commitment over
    // either, as HASH(salt || content).
    CHECK(protocol::Salt().size() == 16);
    CHECK_FALSE(protocol::Salt::from_bytes(Bytes(15, 1)));
    CHECK_FALSE(protocol::Salt::from_bytes(Bytes(17, 1)));
    CHECK_FALSE(protocol::Salt::from_bytes(Bytes(33, 1)));
    for (const std::size_t size : {std::size_t{16}, std::size_t{32}}) {
        const Bytes bytes(size, 7);
        const auto salt = protocol::Salt::from_bytes(bytes);
        REQUIRE(salt);
        CHECK(Bytes(salt->begin(), salt->end()) == bytes);
        const Bytes content{'a', 'b', 'c'};
        Bytes salted = bytes;
        salted.insert(salted.end(), content.begin(), content.end());
        const auto commitment =
            protocol::attachment_commitment(provider(), crypto::HashAlg::sha256, *salt, content);
        REQUIRE(commitment);
        CHECK(*commitment == *provider().digest(crypto::HashAlg::sha256, salted));
    }
    const protocol::Salt issued = std::array<std::uint8_t, protocol::salt_size>{};
    CHECK(issued.size() == 32);
    CHECK(issued != protocol::Salt());
}

TEST_CASE("v0.21 renewals: read, written the same again, and refused",
          "[protocol][vectors][v021]") {
    const auto& renewals = vectors()["renewals"];
    for (const auto& c : renewals["valid"]) {
        INFO(text(c["name"]));
        const Bytes encoded = hex(text(c["renewal"]));
        const auto renewal = protocol::decode_renewal(encoded);
        INFO((renewal ? std::string() : std::string(renewal.error().detail)));
        REQUIRE(renewal);
        CHECK((!renewal->cosignatures.empty() || !renewal->timestamps.empty() ||
               !renewal->network_cosignatures.empty()));
        const auto again = protocol::encode_renewal(*renewal);
        REQUIRE(again);
        CHECK(*again == encoded);
        // In a bundle, too.
        const auto bundle =
            protocol::decode_bundle(bundle_with(11, cbor::Value::array({decoded(c["renewal"])})));
        REQUIRE(bundle);
        REQUIRE(bundle->renewals.size() == 1);
        CHECK(bundle->renewals[0] == *renewal);
    }
    for (const auto& c : renewals["refused"]) {
        INFO(text(c["name"]));
        const Bytes encoded = hex(text(c["renewal"]));
        CHECK_FALSE(protocol::decode_renewal(encoded));
        if (const auto value = cbor::decode(encoded)) {
            CHECK_FALSE(protocol::decode_bundle(bundle_with(11, cbor::Value::array({*value}))));
        }
    }
    for (const auto& c : renewals["bundle_lists_refused"]) {
        INFO(text(c["name"]));
        CHECK_FALSE(protocol::decode_bundle(bundle_with(11, decoded(c["renewals"]))));
    }

    // Writing refuses what reading refuses.
    protocol::Renewal bare;
    bare.checkpoint = Bytes{1, 2, 3};
    CHECK_FALSE(protocol::encode_renewal(bare));
    bare.cosignatures = {Bytes{4}};
    CHECK(protocol::encode_renewal(bare));
    protocol::Renewal long_proof = bare;
    long_proof.consistency.assign(66, *crypto::Digest::from_bytes(Bytes(32, 9)));
    CHECK_FALSE(protocol::encode_renewal(long_proof));
    protocol::Renewal short_hash = bare;
    short_hash.consistency = {*crypto::Digest::from_bytes(Bytes(31, 9))};
    CHECK_FALSE(protocol::encode_renewal(short_hash));
    protocol::Renewal bad_name = bare;
    bad_name.network_cosignatures = {{"a name", Bytes(12, 0)}};
    CHECK_FALSE(protocol::encode_renewal(bad_name));
    protocol::EvidenceBundle many;
    many.entries.push_back({Bytes{0}, Bytes{0}});
    many.record = *protocol::to_id(Bytes(32, 0));
    many.checkpoint = Bytes{0};
    many.renewals.assign(protocol::max_renewals + 1, bare);
    CHECK_FALSE(protocol::encode_bundle(many));
    many.renewals.resize(protocol::max_renewals);
    const auto encoded = protocol::encode_bundle(many);
    REQUIRE(encoded);
    const auto back = protocol::decode_bundle(*encoded);
    REQUIRE(back);
    CHECK(*back == many);
}

TEST_CASE("v0.21 dated cosignatures: the witness's time in the protected header",
          "[protocol][v021]") {
    auto seed = provider().digest(crypto::HashAlg::sha256, kanhe::as_bytes("v0.21 witness"));
    REQUIRE(seed);
    auto witness = crypto::openssl::KeyPair::from_ed25519_seed(seed->bytes());
    REQUIRE(witness);
    protocol::Checkpoint checkpoint;
    checkpoint.ledger_id = *protocol::to_id(Bytes(32, 0x11));
    checkpoint.tree_size = 10;
    checkpoint.root = *crypto::Digest::from_bytes(Bytes(32, 0x22));
    checkpoint.timestamp = 1'792'454'941'000;

    // Undated, as before: exactly {alg, content type, kid}.
    const auto undated = protocol::cosign_checkpoint(*witness, provider(), checkpoint);
    REQUIRE(undated);
    CHECK_FALSE(undated->witness_time);
    CHECK(undated->envelope.protected_header.as_map()->size() == 3);
    const auto read_undated = protocol::parse_cosignature(undated->encoded);
    REQUIRE(read_undated);
    CHECK_FALSE(read_undated->witness_time);

    // Dated: {15: {6: iat}} too, signed with the rest, and read back.
    const std::uint64_t iat = 1'793'491'200; // 2026-11-01
    const auto dated = protocol::cosign_checkpoint(*witness, provider(), checkpoint, iat);
    REQUIRE(dated);
    CHECK(dated->witness_time == iat);
    CHECK(dated->envelope.protected_header.as_map()->size() == 4);
    const cbor::Value* claims = dated->envelope.protected_header.find(protocol::label_cwt_claims);
    REQUIRE(claims != nullptr);
    CHECK(claims->find(protocol::cwt_claim_iat)->as_uint64() == iat);
    const auto read_dated = protocol::parse_cosignature(dated->encoded);
    REQUIRE(read_dated);
    CHECK(read_dated->witness_time == iat);
    CHECK(read_dated->checkpoint == checkpoint);
    CHECK(protocol::verify_cosignature(provider(), *read_dated, witness->public_key()));
    // The time is signed: the undated cosignature is another signature.
    CHECK(dated->envelope.signature != undated->envelope.signature);
    // The largest time, too: seconds, never milliseconds.
    const auto latest = protocol::cosign_checkpoint(*witness, provider(), checkpoint,
                                                    std::numeric_limits<std::uint64_t>::max());
    REQUIRE(latest);
    CHECK(protocol::parse_cosignature(latest->encoded)->witness_time ==
          std::numeric_limits<std::uint64_t>::max());

    // Only exactly {6: an unsigned integer} at label 15, whoever signs.
    auto claims_of = [](std::vector<std::pair<cbor::Value, cbor::Value>> entries) {
        cbor::Map map;
        for (auto& [k, v] : entries) {
            map.push_back({std::move(k), std::move(v)});
        }
        return cbor::Value::map(std::move(map));
    };
    const auto good =
        cosignature_with(*witness, checkpoint,
                         claims_of({{cbor::Value::integer(6), cbor::Value::unsigned_integer(5)}}));
    REQUIRE(protocol::parse_cosignature(good));
    CHECK(protocol::parse_cosignature(good)->witness_time == 5);
    for (cbor::Value bad : {
             claims_of({{cbor::Value::integer(6), cbor::Value::text("2026-11-01")}}),
             claims_of({{cbor::Value::integer(6), cbor::Value::integer(-1)}}),
             claims_of({{cbor::Value::integer(1), cbor::Value::text("witness")},
                        {cbor::Value::integer(6), cbor::Value::unsigned_integer(5)}}),
             claims_of({{cbor::Value::integer(7), cbor::Value::unsigned_integer(5)}}),
             claims_of({{cbor::Value::text("6"), cbor::Value::unsigned_integer(5)}}),
             claims_of({}),
             cbor::Value::unsigned_integer(5),
             cbor::Value::array({cbor::Value::unsigned_integer(5)}),
         }) {
        INFO(cbor::diagnostic(bad));
        CHECK_FALSE(protocol::parse_cosignature(cosignature_with(*witness, checkpoint, bad)));
    }
    // A checkpoint never carries a time: its header stays exactly three.
    kanhe::cose::SignOptions options;
    auto kid = protocol::key_id(provider(), checkpoint.tree_hash, witness->public_key());
    REQUIRE(kid);
    options.protected_header = {
        {cbor::Value::integer(kanhe::cose::label_content_type),
         cbor::Value::text(std::string(protocol::checkpoint_content_type))},
        {cbor::Value::integer(kanhe::cose::label_kid), cbor::Value::bytes(kid->bytes())},
        {cbor::Value::integer(protocol::label_cwt_claims),
         claims_of({{cbor::Value::integer(6), cbor::Value::unsigned_integer(5)}})},
    };
    const auto signed_checkpoint =
        kanhe::cose::sign(*witness, *protocol::encode_checkpoint(checkpoint), options);
    REQUIRE(signed_checkpoint);
    CHECK_FALSE(protocol::parse_checkpoint(*signed_checkpoint));
}

TEST_CASE("v0.21 distrust: ALG@YYYY-MM-DD read, and refused", "[protocol][vectors][v021]") {
    const auto& d = vectors()["distrust_options"];
    for (const auto& c : d["valid"]) {
        INFO(c["options"].dump());
        const auto parsed = protocol::parse_distrust(c["options"].get<std::vector<std::string>>());
        REQUIRE(parsed);
        REQUIRE(parsed->size() == c["algorithms"].size());
        for (std::size_t i = 0; i < parsed->size(); ++i) {
            CHECK(crypto::name((*parsed)[i].algorithm) == text(c["algorithms"][i]["algorithm"]));
            CHECK(kanhe::verifier::iso_time((*parsed)[i].after) ==
                  text(c["algorithms"][i]["after"]));
        }
    }
    for (const auto& c : d["refused"]) {
        INFO(text(c["name"]));
        const auto parsed = protocol::parse_distrust(c["options"].get<std::vector<std::string>>());
        REQUIRE_FALSE(parsed);
        CHECK(parsed.error().code == kanhe::Errc::invalid_argument);
    }
    // Times are Unix times: from 1970.
    CHECK_FALSE(protocol::parse_distrust(std::vector<std::string>{"ed25519@1969-12-31"}));
    const auto epoch = protocol::parse_distrust(std::vector<std::string>{"ed25519@1970-01-01"});
    REQUIRE(epoch);
    CHECK(epoch->front().after == 0);
    const auto leap = protocol::parse_distrust(std::vector<std::string>{"sm2@2028-02-29"});
    REQUIRE(leap);
    CHECK(kanhe::verifier::iso_time(leap->front().after) == "2028-02-29T00:00:00.000Z");
    CHECK_FALSE(protocol::parse_distrust(std::vector<std::string>{"sm2@2027-02-29"}));
    CHECK_FALSE(protocol::parse_distrust(std::vector<std::string>{"sm2@2027-13-01"}));
    CHECK_FALSE(protocol::parse_distrust(std::vector<std::string>{"sm2@@2027-01-01"}));
    CHECK_FALSE(protocol::parse_distrust(std::vector<std::string>{"@2027-01-01"}));
    CHECK_FALSE(protocol::parse_distrust(std::vector<std::string>{"sm2@2027-1-01"}));
}

TEST_CASE("v0.21 renewals: a server's parts, against the archive ledger's checkpoints",
          "[protocol][vectors][v021]") {
    const auto& lg = vectors()["ledger"];
    const auto hash = *crypto::hash_alg_from_cose(lg["hash"].get<std::int64_t>());
    std::vector<Bytes> entries;
    for (const auto& e : lg["entries"]) {
        entries.push_back(hex(text(e)));
    }
    const auto first = protocol::parse_checkpoint(hex(text(lg["checkpoints"][0])));
    const auto second = protocol::parse_checkpoint(hex(text(lg["checkpoints"][1])));
    REQUIRE(first);
    REQUIRE(second);
    CHECK(first->checkpoint.tree_size == lg["renewal_from"].get<std::uint64_t>());
    CHECK(second->checkpoint.tree_size == lg["renewal_size"].get<std::uint64_t>());
    std::vector<crypto::Digest> proof;
    for (const auto& h : lg["consistency"]) {
        proof.push_back(*crypto::Digest::from_bytes(hex(text(h))));
    }
    CHECK(kanhe::merkle::verify_consistency(provider(), hash, first->checkpoint.tree_size,
                                            second->checkpoint.tree_size, first->checkpoint.root,
                                            second->checkpoint.root, proof));
    protocol::Renewal renewal;
    renewal.checkpoint = second->encoded;
    renewal.consistency = proof;
    for (const auto& r : lg["rotation_proofs"]) {
        protocol::KeyRotationProof rotation;
        rotation.index = r[0].get<std::uint64_t>();
        rotation.entry = hex(text(r[1]));
        for (const auto& h : r[2]) {
            rotation.path.push_back(*crypto::Digest::from_bytes(hex(text(h))));
        }
        CHECK(rotation.entry == entries.at(rotation.index));
        auto leaf = kanhe::merkle::leaf_hash(provider(), hash, rotation.entry);
        REQUIRE(leaf);
        CHECK(kanhe::merkle::verify_inclusion(provider(), hash, *leaf, rotation.index,
                                              second->checkpoint.tree_size, rotation.path,
                                              second->checkpoint.root));
        renewal.rotations.push_back(std::move(rotation));
    }
    CHECK(renewal.rotations.size() == lg["rotations"].size());
    // Ed25519, then ML-DSA-65.
    CHECK(first->envelope.algorithm == crypto::SigAlg::ed25519);
    CHECK(second->envelope.algorithm == crypto::SigAlg::ml_dsa_65);
    // A renewal needs an attestation to be written; with one, it reads back.
    CHECK_FALSE(protocol::encode_renewal(renewal));
    renewal.cosignatures.push_back(Bytes{0x01});
    const auto encoded = protocol::encode_renewal(renewal);
    REQUIRE(encoded);
    const auto back = protocol::decode_renewal(*encoded);
    REQUIRE(back);
    CHECK(*back == renewal);
}

TEST_CASE("v0.21 evidence: renewals, the long-term status, and distrust, as specified",
          "[protocol][vectors][v021]") {
    for (const auto& c : vectors()["bundles"]) {
        INFO(text(c["name"]) + ": " + text(c["description"]));
        const Bytes evidence = hex(text(c["evidence"]));
        // What decodes, encodes the same again.
        if (const auto bundle = protocol::decode_bundle(evidence)) {
            const auto again = protocol::encode_bundle(*bundle);
            REQUIRE(again);
            CHECK(*again == evidence);
        }
        const protocol::VerifyOptions options = options_of(c["options"]);
        const auto report = protocol::verify_bundle(provider(), evidence, options);
        INFO((report ? std::string() : std::string(report.error().detail)));
        REQUIRE(report.has_value() == c["verified"].get<bool>());
        if (!report) {
            CHECK_FALSE(text(c["rule"]).empty());
            continue;
        }
        const nlohmann::json json = nlohmann::json::parse(
            kanhe::verifier::report_json(*report, options.expected_ledger.has_value()).dump());
        std::string where;
        CHECK(matches(c["facts"], json, "", where));
        if (!where.empty()) {
            FAIL_CHECK("the report differs at " + where);
        }
        // The report's text says it too.
        const std::string words =
            kanhe::verifier::report_text(*report, options.expected_ledger.has_value());
        CHECK(words.find(report->long_term.post_quantum()
                             ? "Post-quantum since"
                             : "Renew before 2030-01-01") != std::string::npos);
    }
}
