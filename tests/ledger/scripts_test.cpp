// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// Scripts and sources (spec v0.18): a script is approved by a person in
// person; a record names the script it came from and the records it was
// made from; its evidence carries both, says where each source stood when
// the record was made and at the checkpoint, and checks the proofs of
// sources on other ledgers.

#include <algorithm>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <catch2/catch_test_macros.hpp>

#include <kanhe/core/protocol/evidence.hpp>
#include <kanhe/core/protocol/presence.hpp>
#include <kanhe/core/protocol/scripts.hpp>

#include "support/authenticator.hpp"
#include "support/ledger_world.hpp"

using namespace kanhe::test;
using kanhe::Bytes;
using kanhe::Errc;
namespace cbor = kanhe::cbor;

namespace {

const std::string book_type = "example.org.loan-book/1";
const std::string report_type = "example.org.report/1";

protocol::Script risk_model(std::string version = "3.2") {
    protocol::Script s;
    s.name = "risk-model";
    s.version = std::move(version);
    s.files = {{"model/weights.json", 48213, Bytes(32, 0x9a)}, {"run.py", 1204, Bytes(32, 0xac)}};
    s.deterministic = true;
    s.runtime = "python 3.12";
    return s;
}

SoftPasskey passkey(std::uint8_t id, std::uint8_t flags = 0x05) {
    auto key = KeyPair::generate(crypto::SigAlg::esp256);
    REQUIRE(key);
    auto shared = std::make_shared<const KeyPair>(std::move(*key));
    SoftPasskey p;
    p.public_key = shared->public_key();
    p.key = shared;
    p.credential_id = Bytes(16, id);
    p.flags = flags;
    return p;
}

/// A bank's ledger: the organization registers a person, Alice, with a
/// passkey, and a device; Alice may approve scripts, the device may
/// register records.
struct Bank {
    World w;
    KeyPair alice_key = key("alice");
    KeyPair device_key = key("risk engine");
    SoftPasskey alice_passkey = passkey(1);
    protocol::Id alice;
    protocol::Id alice_delegation;
    protocol::Id device;
    protocol::Id device_delegation;

    explicit Bank(const std::string& name = "Example Bank") : w(crypto::HashAlg::sha256, name) {
        alice = w.register_actor(w.org(), w.org_id(), std::nullopt, protocol::ActorKind::person,
                                 alice_key);
        protocol::PresenceCredential credential{alice_passkey.rp_id, alice_passkey.credential_id,
                                                alice_passkey.public_key,
                                                std::string("Alice's passkey")};
        w.ok(w.org(), w.statement(w.org_id(), std::nullopt,
                                  protocol::ActorSetPresenceBody{alice, {credential}}));
        alice_delegation =
            w.grant(w.org(), w.org_id(), std::nullopt, alice,
                    scope({StatementType::record_register, StatementType::record_revoke}));
        device = w.register_actor(w.org(), w.org_id(), std::nullopt, protocol::ActorKind::device,
                                  device_key);
        device_delegation =
            w.grant(w.org(), w.org_id(), std::nullopt, device,
                    scope({StatementType::record_register, StatementType::record_revoke}));
    }

    protocol::RecordRegisterBody script_body(const protocol::Script& script) {
        auto body = w.record_body(std::string(protocol::script_type));
        body.metadata = *protocol::encode_script(script);
        return body;
    }

    /// Alice's statement, in person with `with` if given.
    protocol::Statement by_alice(protocol::Body body, const SoftPasskey* with) {
        auto s = w.statement(alice, alice_delegation, std::move(body));
        if (with != nullptr) {
            const auto kid = protocol::key_id(provider(), w.hash(), alice_key.public_key());
            s.presence = with->sign(provider(),
                                    *protocol::presence_challenge(provider(), w.hash(), s, *kid));
        }
        return s;
    }

    protocol::Id approve(const protocol::Script& script) {
        return w.ok(alice_key, by_alice(script_body(script), &alice_passkey));
    }

    protocol::Id book() {
        return w.ok(device_key, w.statement(device, device_delegation, w.record_body(book_type)));
    }

    /// The device's report, from `sources`, by `script`.
    protocol::Statement report(std::vector<protocol::Source> sources,
                               std::optional<protocol::Id> script) {
        auto body = w.record_body(report_type);
        body.sources = std::move(sources);
        auto s = w.statement(device, device_delegation, std::move(body));
        if (script) {
            s.provenance = protocol::Provenance{};
            s.provenance->script = *script;
        }
        return s;
    }

    protocol::Source local(const protocol::Id& record) { return {w.ledger().id(), record}; }

    void revoke(const protocol::Id& record) {
        w.ok(device_key, w.statement(device, device_delegation,
                                     protocol::RecordRevokeBody{record, "withdrawn"}));
    }

    protocol::EvidenceBundle exported(const protocol::Id& record) {
        REQUIRE(w.ledger().checkpoint(w.log_key()));
        auto bundle = w.ledger().export_evidence(w.log_key(), record);
        REQUIRE(bundle);
        return std::move(*bundle);
    }
};

kanhe::Result<protocol::EvidenceReport> verify(const protocol::EvidenceBundle& bundle) {
    const protocol::VerifyOptions options;
    return protocol::verify_bundle(provider(), *protocol::encode_bundle(bundle), options);
}

} // namespace

TEST_CASE("a script is approved by a person, in person, and only so", "[scripts][ledger]") {
    Bank b;
    const auto script = risk_model();

    // Not by the organization, not by a device, not by a key alone, not
    // without user verification.
    CHECK(b.w.rejected(b.w.org(), b.w.statement(b.w.org_id(), std::nullopt,
                                                b.script_body(script))) == Errc::rejected);
    CHECK(b.w.rejected(b.device_key, b.w.statement(b.device, b.device_delegation,
                                                   b.script_body(script))) == Errc::rejected);
    CHECK(b.w.rejected(b.alice_key, b.by_alice(b.script_body(script), nullptr)) == Errc::rejected);
    const SoftPasskey present_only = [&] {
        SoftPasskey p = b.alice_passkey;
        p.flags = 0x01;
        return p;
    }();
    CHECK(b.w.rejected(b.alice_key, b.by_alice(b.script_body(script), &present_only)) ==
          Errc::rejected);

    // Its metadata is checked: a path that climbs out is refused.
    auto climbing = script;
    climbing.files = {{"../run.py", 1, Bytes(32, 1)}};
    auto body = b.w.record_body(std::string(protocol::script_type));
    body.metadata = cbor::Value::map(
        {{cbor::Value::text("name"), cbor::Value::text("risk-model")},
         {cbor::Value::text("version"), cbor::Value::text("3.2")},
         {cbor::Value::text("files"),
          cbor::Value::array(
              {cbor::Value::array({cbor::Value::text("../run.py"), cbor::Value::unsigned_integer(1),
                                   cbor::Value::bytes(Bytes(32, 1))})})},
         {cbor::Value::text("deterministic"), cbor::Value::boolean(true)}});
    CHECK(b.w.rejected(b.alice_key, b.by_alice(std::move(body), &b.alice_passkey)) ==
          Errc::malformed);
    CHECK_FALSE(protocol::encode_script(climbing));

    const auto approved = b.approve(script);
    const auto* record = b.w.ledger().state().record(approved);
    REQUIRE(record != nullptr);
    CHECK(record->record_type == protocol::script_type);
    CHECK(record->state == "approved");

    // A script takes no endorsement, and no sources.
    CHECK(b.w.rejected(b.w.org(), b.w.statement(b.w.org_id(), std::nullopt,
                                                protocol::RecordEndorseBody{
                                                    approved, "witness"})) == Errc::rejected);
    auto sourced = b.script_body(risk_model("3.3"));
    sourced.sources = {b.local(b.book())};
    CHECK(b.w.rejected(b.alice_key, b.by_alice(std::move(sourced), &b.alice_passkey)) ==
          Errc::rejected);
}

TEST_CASE("a record names the script it came from and the records it was made from",
          "[scripts][ledger]") {
    Bank b;
    const auto script = b.approve(risk_model());
    const auto november = b.book();
    const auto december = b.book();
    const protocol::Source elsewhere{*protocol::to_id(Bytes(32, 0x5e)),
                                     *protocol::to_id(Bytes(32, 0x5f))};

    // The script must be one, and live; a local source must exist, be
    // generic, live, and the newest version; another ledger's is not
    // looked up.
    CHECK(b.w.rejected(b.device_key, b.report({}, november)) == Errc::rejected);
    CHECK(b.w.rejected(b.device_key, b.report({}, *protocol::to_id(Bytes(32, 3)))) ==
          Errc::not_found);
    CHECK(b.w.rejected(b.device_key, b.report({b.local(*protocol::to_id(Bytes(32, 4)))}, script)) ==
          Errc::not_found);
    CHECK(b.w.rejected(b.device_key, b.report({b.local(script)}, script)) == Errc::rejected);
    const auto made = b.w.ok(b.device_key, b.report({b.local(november), elsewhere}, script));
    CHECK(b.w.ledger().state().record(made)->state == "registered");

    b.revoke(november);
    CHECK(b.w.rejected(b.device_key, b.report({b.local(november)}, script)) == Errc::rejected);
    auto newer = b.w.record_body(book_type);
    newer.supersedes = december;
    b.w.ok(b.device_key, b.w.statement(b.device, b.device_delegation, std::move(newer)));
    CHECK(b.w.rejected(b.device_key, b.report({b.local(december)}, script)) == Errc::rejected);

    // A withdrawn script names nothing more.
    b.w.ok(b.alice_key, b.by_alice(protocol::RecordRevokeBody{script, "superseded"}, nullptr));
    CHECK(b.w.rejected(b.device_key, b.report({}, script)) == Errc::rejected);
}

TEST_CASE("a record's evidence carries its script and its sources, and what became of them",
          "[scripts][evidence]") {
    Bank b;
    const auto script_id = b.approve(risk_model());
    const auto book = b.book();
    const protocol::Source elsewhere{*protocol::to_id(Bytes(32, 0x5e)),
                                     *protocol::to_id(Bytes(32, 0x5f))};
    const auto made = b.w.ok(b.device_key, b.report({b.local(book), elsewhere}, script_id));
    // An unrelated record, which the report's bundle does not need.
    b.book();

    auto bundle = b.exported(made);
    auto report = verify(bundle);
    INFO((report ? std::string() : std::string(report.error().detail)));
    REQUIRE(report);
    REQUIRE(report->complete);
    REQUIRE(report->scripts.size() == 1);
    const auto& s = report->scripts.front();
    CHECK(s.id == script_id);
    CHECK(s.script == risk_model());
    CHECK(s.approved_by.id == b.alice);
    CHECK(s.approved_by.kind == protocol::ActorKind::person);
    REQUIRE(s.presence);
    CHECK(s.presence->user_verified);
    CHECK(s.presence->label == "Alice's passkey");
    CHECK_FALSE(s.withdrawn_at);

    REQUIRE(report->sources.size() == 2);
    const auto& local = report->sources[0];
    CHECK(local.source == b.local(book));
    CHECK(local.local);
    CHECK(local.provided);
    CHECK(local.type == book_type);
    CHECK(local.at_record == protocol::SourceStatus::live);
    CHECK(local.at_checkpoint == protocol::SourceStatus::live);
    CHECK_FALSE(local.changed_at);
    const auto& remote = report->sources[1];
    CHECK(remote.source == elsewhere);
    CHECK_FALSE(remote.local);
    CHECK_FALSE(remote.provided);
    CHECK(remote.type.empty());

    // The book revoked and the script withdrawn since: the evidence says so,
    // and when.
    b.revoke(book);
    b.w.ok(b.alice_key, b.by_alice(protocol::RecordRevokeBody{script_id, "superseded"}, nullptr));
    bundle = b.exported(made);
    report = verify(bundle);
    REQUIRE(report);
    REQUIRE(report->complete);
    CHECK(report->sources[0].at_record == protocol::SourceStatus::live);
    CHECK(report->sources[0].at_checkpoint == protocol::SourceStatus::revoked);
    CHECK(report->sources[0].changed_at);
    CHECK(report->scripts.front().withdrawn_at);

    // Neither the script's nor the source's history can be left out.
    for (const auto& id : {script_id, book}) {
        auto short_of = bundle;
        std::erase_if(short_of.state_proofs,
                      [&](const protocol::StateProof& p) { return p.leaf.id == id; });
        CHECK_FALSE(verify(short_of));
    }
}

TEST_CASE("a source on another ledger is proven by that ledger's own evidence",
          "[scripts][evidence]") {
    Bank lender("Example Bank");
    Bank registry("Land Registry");
    const auto title = registry.book();
    const auto other_title = registry.book();
    const auto title_proof = *protocol::encode_bundle(registry.exported(title));
    const auto other_proof = *protocol::encode_bundle(registry.exported(other_title));

    const auto script = lender.approve(risk_model());
    const protocol::Source remote{registry.w.ledger().id(), title};
    const auto made = lender.w.ok(lender.device_key, lender.report({remote}, script));
    auto bundle = lender.exported(made);
    bundle.source_proofs = {title_proof};
    auto report = verify(bundle);
    INFO((report ? std::string() : std::string(report.error().detail)));
    REQUIRE(report);
    REQUIRE(report->sources.size() == 1);
    const auto& s = report->sources.front();
    CHECK_FALSE(s.local);
    CHECK(s.provided);
    CHECK(s.type == book_type);
    CHECK(s.organization == "Land Registry");
    CHECK_FALSE(s.trust_node);
    CHECK(s.at_checkpoint == protocol::SourceStatus::live);

    // The proof of a record it does not name, the same proof twice, bytes
    // that are no bundle, and a proof that carries proofs are refused.
    auto refused = [&](std::vector<Bytes> proofs) {
        auto b = bundle;
        b.source_proofs = std::move(proofs);
        return !verify(b);
    };
    CHECK(refused({other_proof}));
    CHECK(refused({title_proof, title_proof}));
    CHECK(refused({Bytes{0x01, 0x02}}));
    auto nested = registry.exported(title);
    nested.source_proofs = {other_proof};
    CHECK(refused({*protocol::encode_bundle(nested)}));
    // A proof of a record on this very ledger is not of another ledger's.
    CHECK(refused({*protocol::encode_bundle(lender.exported(script))}));

    // It round-trips.
    const auto encoded = protocol::encode_bundle(bundle);
    REQUIRE(encoded);
    const auto decoded = protocol::decode_bundle(*encoded);
    REQUIRE(decoded);
    CHECK(decoded->source_proofs == bundle.source_proofs);
}
