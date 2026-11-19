// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// Renewals over HTTP (spec v0.21, sections 11.1 and 16): GET
// /v1/renewal?from=N[&size=M] takes no token and answers the renewal that
// takes evidence of size N to the latest checkpoint, or the one of size M:
// that checkpoint, the consistency proof from N, every rotation of the root
// key or the log key between the two sizes with its path in the newer tree,
// and every cosignature kept beside the checkpoint. Appended to a bundle it
// verifies, and an ML-DSA witness's dated cosignature makes the bundle's
// long-term status post-quantum. Sizes that are not positive or out of order
// answer 400; a size with no checkpoint, or one nothing attests, 404.

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <optional>
#include <string>
#include <thread>
#include <unistd.h>
#include <utility>

#include <catch2/catch_test_macros.hpp>

#include <kanhe/core/protocol/evidence.hpp>
#include <kanhe/core/protocol/log.hpp>
#include <kanhe/core/protocol/statement.hpp>
#include <kanhe/node/api.hpp>
#include <kanhe/node/client.hpp>
#include <kanhe/node/server.hpp>
#include <kanhe/verifier/report.hpp>

#include "support/ledger_world.hpp"

namespace {

using namespace kanhe::test;
namespace node = kanhe::node;
namespace verifier = kanhe::verifier;
using kanhe::Bytes;

std::filesystem::path fresh_directory() {
    static int counter = 0;
    const auto dir =
        std::filesystem::temp_directory_path() /
        ("kanhe-renewal-test-" + std::to_string(::getpid()) + "-" + std::to_string(counter++));
    std::filesystem::remove_all(dir);
    std::filesystem::create_directories(dir);
    return dir;
}

class Running {
public:
    explicit Running(node::Application& app) : server_(app, options()) {
        REQUIRE(server_.listen());
        thread_ = std::thread([this] { server_.run(); });
    }
    Running(const Running&) = delete;
    Running& operator=(const Running&) = delete;
    ~Running() {
        server_.stop();
        thread_.join();
    }
    /// A client with no token: the route is open.
    [[nodiscard]] node::Client client() const {
        node::ClientOptions o;
        o.timeout = std::chrono::seconds(15);
        return node::Client(*node::Url::parse("http://127.0.0.1:" + std::to_string(server_.port())),
                            o);
    }

private:
    static node::ServerOptions options() {
        node::ServerOptions o;
        o.port = 0;
        o.request_timeout = std::chrono::seconds(10);
        return o;
    }
    node::Server server_;
    std::thread thread_;
};

KeyPair ml_dsa() {
    auto made = KeyPair::generate(crypto::SigAlg::ml_dsa_65);
    REQUIRE(made);
    return std::move(*made);
}

/// A ledger begun with classical keys, whose record's evidence was exported
/// at size `exported`. Then its log key and its root key were rotated to
/// ML-DSA-65, checkpointed (size `unattested`, which nothing attests), and,
/// after one more record, checkpointed again (size `latest`) and cosigned by
/// a witness whose key is ML-DSA-65, dated `witnessed_at`.
struct Archive {
    std::filesystem::path dir = fresh_directory();
    ledger::ManualClock clock{t0};
    ledger::SeededEntropy entropy{83};
    KeyPair org = key("renewal org");
    std::shared_ptr<const KeyPair> log_key = std::make_shared<const KeyPair>(key("renewal log"));
    KeyPair pq_log = ml_dsa();
    KeyPair pq_root = ml_dsa();
    KeyPair witness = ml_dsa();
    protocol::Id id;
    protocol::Id record;
    Bytes bundle;
    std::uint64_t exported = 0;
    std::uint64_t unattested = 0;
    std::uint64_t latest = 0;
    std::uint64_t witnessed_at = (t0 + 3'600'000) / 1000;

    Archive() {
        auto fs = ledger::PosixFileSystem::open_directory(dir);
        REQUIRE(fs);
        protocol::Statement genesis;
        genesis.issued_at = clock.now();
        genesis.nonce = entropy.bytes<16>();
        genesis.body = protocol::GenesisBody{crypto::HashAlg::sha256, "Renewal Archive",
                                             org.public_key(), log_key->public_key()};
        auto signed_genesis =
            protocol::sign_statement(org, provider(), crypto::HashAlg::sha256, genesis);
        REQUIRE(signed_genesis);
        auto ledger = ledger::Ledger::create(*fs, clock, provider(), signed_genesis->encoded);
        REQUIRE(ledger);
        id = ledger->id();
        auto ok = [&](const KeyPair& signer, protocol::Body body) {
            protocol::Statement st;
            st.ledger_id = id;
            st.actor_id = id;
            st.issued_at = clock.now();
            st.nonce = entropy.bytes<16>();
            st.body = std::move(body);
            auto signed_statement =
                protocol::sign_statement(signer, provider(), crypto::HashAlg::sha256, st);
            REQUIRE(signed_statement);
            auto r = ledger->submit(signed_statement->encoded);
            INFO((r ? std::string() : std::string(r.error().detail)));
            REQUIRE(r);
            clock.advance(1000);
            return r->statement_id;
        };
        auto document = [] {
            return protocol::RecordRegisterBody{document_type, Bytes(32, 0x42), 3, {},
                                                std::nullopt,  std::nullopt,    {}};
        };
        record = ok(org, document());
        REQUIRE(ledger->checkpoint(*log_key));
        auto evidence = ledger->export_evidence(*log_key, record);
        REQUIRE(evidence);
        auto encoded = protocol::encode_bundle(*evidence);
        REQUIRE(encoded);
        bundle = std::move(*encoded);
        exported = ledger->latest_checkpoint()->checkpoint.tree_size;

        ok(org, protocol::LedgerRotateLogKeyBody{pq_log.public_key()});
        ok(org, protocol::ActorRotateKeyBody{id, pq_root.public_key()});
        auto rotated = ledger->checkpoint(pq_log);
        REQUIRE(rotated);
        unattested = rotated->checkpoint.tree_size;

        ok(pq_root, document());
        clock.advance(60'000);
        auto made = ledger->checkpoint(pq_log);
        REQUIRE(made);
        latest = made->checkpoint.tree_size;
        auto cosignature =
            protocol::cosign_checkpoint(witness, provider(), made->checkpoint, witnessed_at);
        REQUIRE(cosignature);
        REQUIRE(ledger->add_cosignature(cosignature->encoded, witness.public_key()));
    }
    Archive(const Archive&) = delete;
    Archive& operator=(const Archive&) = delete;
    ~Archive() { std::filesystem::remove_all(dir); }

    std::unique_ptr<node::LedgerApi> api() {
        // No log key: a renewal is made of what the ledger keeps, and signs
        // nothing.
        node::ApiOptions o;
        o.directory = dir;
        o.clock = &clock;
        auto opened = node::LedgerApi::open(o, provider());
        REQUIRE(opened);
        return std::move(*opened);
    }
};

node::http::ClientResponse get(const node::Client& c, const std::string& path) {
    auto r = c.request("GET", path);
    REQUIRE(r);
    return std::move(*r);
}

protocol::Renewal renewal_of(const node::http::ClientResponse& r) {
    REQUIRE(r.status == 200);
    auto renewal = protocol::decode_renewal(r.body);
    REQUIRE(renewal);
    return std::move(*renewal);
}

std::uint64_t size_of(const protocol::Renewal& renewal) {
    auto checkpoint = protocol::parse_checkpoint(renewal.checkpoint);
    REQUIRE(checkpoint);
    return checkpoint->checkpoint.tree_size;
}

} // namespace

TEST_CASE("a renewal takes evidence to the latest attested checkpoint, with no token",
          "[node][renewal]") {
    Archive a;
    auto api = a.api();
    Running server(*api);
    const auto anyone = server.client();

    const auto answer = get(anyone, "/v1/renewal?from=" + std::to_string(a.exported));
    CHECK(answer.header("content-type") == "application/cbor");
    const protocol::Renewal renewal = renewal_of(answer);
    CHECK(size_of(renewal) == a.latest);
    CHECK_FALSE(renewal.consistency.empty());
    // Both rotations, in log order, each proven in the newer tree.
    REQUIRE(renewal.rotations.size() == 2);
    CHECK(renewal.rotations[0].index >= a.exported);
    CHECK(renewal.rotations[0].index < renewal.rotations[1].index);
    CHECK(renewal.rotations[1].index < a.latest);
    REQUIRE(renewal.cosignatures.size() == 1);
    CHECK(renewal.timestamps.empty());
    CHECK(renewal.network_cosignatures.empty());
    const auto cosignature = protocol::parse_cosignature(renewal.cosignatures[0]);
    REQUIRE(cosignature);
    CHECK(cosignature->witness_time == std::optional<std::uint64_t>(a.witnessed_at));

    // To the same checkpoint by its size.
    CHECK(get(anyone, "/v1/renewal?from=" + std::to_string(a.exported) +
                          "&size=" + std::to_string(a.latest))
              .body == answer.body);

    // Appended, the bundle verifies, and the ML-DSA witness it trusts makes
    // its long-term status post-quantum, by the renewal.
    auto bundle = protocol::decode_bundle(a.bundle);
    REQUIRE(bundle);
    bundle->renewals.push_back(renewal);
    auto renewed = protocol::encode_bundle(*bundle);
    REQUIRE(renewed);
    protocol::VerifyOptions options;
    options.expected_ledger = a.id;
    options.trusted_witnesses.push_back(a.witness.public_key());
    const auto report = protocol::verify_bundle(provider(), *renewed, options);
    INFO((report ? std::string() : std::string(report.error().detail)));
    REQUIRE(report);
    CHECK(report->checkpoint.tree_size == a.exported);
    auto j = verifier::report_json(*report, true);
    CHECK(j["renewals"].size() == 1);
    CHECK(j["long_term"]["post_quantum"] == true);
    CHECK(j["long_term"]["checkpoint"]["tree_size"] == a.latest);
    CHECK(j["long_term"]["checkpoint"]["renewal"] == 1);
    // Without trusting the witness, nothing post-quantum is relied on.
    options.trusted_witnesses.clear();
    const auto untrusting = protocol::verify_bundle(provider(), *renewed, options);
    REQUIRE(untrusting);
    CHECK(verifier::report_json(*untrusting, true)["long_term"]["post_quantum"] == false);

    // A renewal from the latest size repeats its checkpoint: no proof, no
    // rotations.
    const protocol::Renewal again =
        renewal_of(get(anyone, "/v1/renewal?from=" + std::to_string(a.latest)));
    CHECK(size_of(again) == a.latest);
    CHECK(again.consistency.empty());
    CHECK(again.rotations.empty());
    CHECK(again.cosignatures.size() == 1);
}

TEST_CASE("the renewal route refuses sizes it cannot answer for", "[node][renewal]") {
    Archive a;
    auto api = a.api();
    Running server(*api);
    const auto anyone = server.client();
    auto status = [&](const std::string& query) {
        return get(anyone, "/v1/renewal" + query).status;
    };
    const std::string exported = std::to_string(a.exported);
    const std::string latest = std::to_string(a.latest);

    // Not positive integers, or out of order: 400.
    CHECK(status("") == 400);
    CHECK(status("?from=0") == 400);
    CHECK(status("?from=x") == 400);
    CHECK(status("?from=-3") == 400);
    CHECK(status("?size=" + latest) == 400);
    CHECK(status("?from=" + exported + "&size=0") == 400);
    CHECK(status("?from=" + exported + "&size=many") == 400);
    CHECK(status("?from=" + latest + "&size=" + exported) == 400);
    // No checkpoint of that size; the latest smaller than from; a checkpoint
    // nothing attests (the bundle's own, and the one after the rotations): 404.
    CHECK(status("?from=" + exported + "&size=" + std::to_string(a.latest + 5)) == 404);
    CHECK(status("?from=" + exported + "&size=" + std::to_string(a.exported + 1)) == 404);
    CHECK(status("?from=" + std::to_string(a.latest + 1)) == 404);
    CHECK(status("?from=" + exported + "&size=" + std::to_string(a.unattested)) == 404);
    CHECK(status("?from=" + exported + "&size=" + exported) == 404);
    const auto refused =
        get(anyone, "/v1/renewal?from=" + exported + "&size=" + std::to_string(a.unattested));
    const auto message = node::error_message_of(refused.body);
    REQUIRE(message);
    CHECK(message->find("attested") != std::string::npos);
    // Only GET.
    auto posted = anyone.request("POST", "/v1/renewal?from=" + exported);
    REQUIRE(posted);
    CHECK(posted->status == 405);
}
