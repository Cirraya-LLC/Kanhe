// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// Writes valid inputs for the fuzz targets, to start their corpora from:
// random bytes rarely get past a signature, so the deeper checks (evidence
// replay, access rules, backup restore, passkey registration) are reached
// from real objects mutated, not from nothing. The contract interpreter and
// the contract parsers start from testvectors/vm-v1.json, protocol-v0.6.json,
// protocol-v0.7.json (children), and protocol-v0.8.json (requests and
// answers), and so does the Bo runtime's CBOR reader
// (contract inputs and outputs). The Merkle proof verifiers start from
// testvectors/merkle-sha256.json. A registrar's pending calls
// (node/contracts.hpp) and invitation codes (client/peers.hpp) are built here
// as CBOR, without the node or the client library. The Bo pack reader starts
// from the official packs.
//
//   make_seeds DIR    writes DIR/<target>/<name> for each target

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <format>
#include <fstream>
#include <limits>
#include <optional>
#include <print>
#include <span>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

#include <nlohmann/json.hpp>

#if defined(KANHE_HAVE_BO_FRONT)
#include <kanhe/bo/pack.hpp>
#include <kanhe/bo/source.hpp>
#include <kanhe/bo/stdlib.hpp>
#include <kanhe/bo/vocab.hpp>
#endif
#include <kanhe/core/bytes.hpp>
#include <kanhe/core/cbor.hpp>
#include <kanhe/core/cose.hpp>
#include <kanhe/core/merkle.hpp>
#include <kanhe/core/protocol/access.hpp>
#include <kanhe/core/protocol/approval_file.hpp>
#include <kanhe/core/protocol/approvals.hpp>
#include <kanhe/core/protocol/common.hpp>
#include <kanhe/core/protocol/contract_evidence.hpp>
#include <kanhe/core/protocol/contracts.hpp>
#include <kanhe/core/protocol/evidence.hpp>
#include <kanhe/core/protocol/exchange.hpp>
#include <kanhe/core/protocol/memberships.hpp>
#include <kanhe/core/protocol/network.hpp>
#include <kanhe/core/protocol/presence.hpp>
#include <kanhe/core/protocol/record.hpp>
#include <kanhe/core/protocol/scripts.hpp>
#include <kanhe/core/protocol/statement.hpp>
#include <kanhe/crypto/openssl.hpp>
#include <kanhe/ledger/backup.hpp>
#include <kanhe/ledger/ledger.hpp>
#include <kanhe/verifier/credentials.hpp>
#include <kanhe/verifier/gzip.hpp>
#include <kanhe/verifier/jcs.hpp>

#include "support/timestamp_authority.hpp"

namespace {

using namespace kanhe;

template <class T>
T must(Result<T> result, const char* what) {
    if (!result) {
        throw std::runtime_error(std::string(what) + ": " + std::string(result.error().detail));
    }
    if constexpr (!std::is_void_v<T>) {
        return std::move(*result);
    }
}

class Seeds {
public:
    explicit Seeds(std::filesystem::path root) : root_(std::move(root)) {}
    void write(const std::string& target, const std::string& name, ByteView bytes) const {
        const auto dir = root_ / target;
        std::filesystem::create_directories(dir);
        std::ofstream out(dir / name, std::ios::binary);
        out.write(reinterpret_cast<const char*>(bytes.data()),
                  static_cast<std::streamsize>(bytes.size()));
    }
    void write(const std::string& target, const std::string& name, std::string_view text) const {
        write(target, name, as_bytes(text));
    }

private:
    std::filesystem::path root_;
};

/// A ledger with a document (fields and an attachment), an access
/// request and a grant, checkpointed: the objects the protocol fuzzers
/// verify.
void ledger_seeds(const Seeds& seeds) {
    const crypto::openssl::Provider provider;
    const auto hash = crypto::HashAlg::sha256;
    auto org = must(crypto::openssl::KeyPair::generate(crypto::SigAlg::ed25519), "key");
    auto log = must(crypto::openssl::KeyPair::generate(crypto::SigAlg::ed25519), "key");
    ledger::ManualClock clock(1'791'244'800'000);
    ledger::SeededEntropy entropy(1);
    ledger::MemoryFileSystem fs;

    protocol::Statement genesis;
    genesis.issued_at = clock.now();
    genesis.nonce = entropy.bytes<16>();
    genesis.body = protocol::GenesisBody{hash, "Seed Org", org.public_key(), log.public_key()};
    const auto signed_genesis =
        must(protocol::sign_statement(org, provider, hash, genesis), "sign");
    auto ledger =
        must(ledger::Ledger::create(fs, clock, provider, signed_genesis.encoded), "create");
    const crypto::Signer* root = &org;
    auto submit = [&](protocol::Body body) {
        protocol::Statement s;
        s.ledger_id = ledger.id();
        s.actor_id = ledger.id();
        s.issued_at = clock.now();
        s.nonce = entropy.bytes<16>();
        s.body = std::move(body);
        const auto signed_statement =
            must(protocol::sign_statement(*root, provider, hash, s), "sign");
        seeds.write("protocol_parse_fuzz", "statement-" + std::to_string(ledger.size()),
                    signed_statement.encoded);
        return must(ledger.submit(signed_statement.encoded), "submit").statement_id;
    };

    const protocol::Nonce salt{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    const Bytes report{'r', 'e', 'p', 'o', 'r', 't'};
    const auto commitment =
        must(protocol::commit_fields(provider, hash,
                                     {{"price", salt, cbor::Value::text("1200")},
                                      {"result", salt, cbor::Value::text("pass")}}),
             "fields");
    const auto attachment =
        must(protocol::attachment_commitment(provider, hash, salt, report), "attachment");
    const auto document = submit(protocol::RecordRegisterBody{
        "example.document/1",
        Bytes(commitment.root.bytes().begin(), commitment.root.bytes().end()),
        commitment.leaves.size(),
        {{"report.pdf", "application/pdf", report.size(),
          Bytes(attachment.bytes().begin(), attachment.bytes().end())}},
        std::nullopt,
        std::nullopt,
        {}});

    const protocol::AccessRequest request{ledger.id(),
                                          document,
                                          "seed",
                                          clock.now() + 86'400'000,
                                          Bytes(32, 7),
                                          std::vector<std::string>{"result"},
                                          std::vector<std::string>{"report.pdf"},
                                          std::nullopt};
    const auto request_metadata = must(protocol::encode_access_request(request), "request");
    seeds.write("access_parse_fuzz", "request", must(cbor::encode(request_metadata), "encode"));
    // A request for a condition (spec v0.15): no key, no fields.
    protocol::AccessRequest question = request;
    question.recipient = {};
    question.fields = std::nullopt;
    question.attachments = std::nullopt;
    question.condition =
        std::vector<protocol::ClaimTerm>{{"result", "=", "text", cbor::Value::text("pass")}};
    seeds.write(
        "access_parse_fuzz", "question",
        must(cbor::encode(must(protocol::encode_access_request(question), "question")), "encode"));
    auto access_fields =
        must(protocol::commit_fields(provider, hash, {{"note", salt, cbor::Value::text("x")}}),
             "fields");
    auto access_record = [&](std::string_view type, cbor::Value metadata) {
        return submit(protocol::RecordRegisterBody{
            std::string(type),
            Bytes(access_fields.root.bytes().begin(), access_fields.root.bytes().end()),
            1,
            {},
            std::move(metadata),
            std::nullopt,
            {}});
    };
    const auto request_id = access_record(protocol::access_request_type, request_metadata);
    const protocol::AccessGrant grant{ledger.id(),    request_id,    document,         {"result"},
                                      {"report.pdf"}, request.until, request.recipient};
    const auto grant_metadata = must(protocol::encode_access_grant(grant), "grant");
    seeds.write("access_parse_fuzz", "grant", must(cbor::encode(grant_metadata), "encode"));
    const auto grant_id = access_record(protocol::access_grant_type, grant_metadata);
    const protocol::AccessReceipt receipt{ledger.id(), grant_id, Bytes(32, 9)};
    seeds.write(
        "access_parse_fuzz", "receipt",
        must(cbor::encode(must(protocol::encode_access_receipt(receipt), "receipt")), "encode"));

    must(ledger.checkpoint(log), "checkpoint");
    const auto latest = *ledger.latest_checkpoint();
    seeds.write("protocol_parse_fuzz", "checkpoint", latest.encoded);
    seeds.write("cose_parse_fuzz", "checkpoint", latest.encoded);
    seeds.write("protocol_parse_fuzz", "receipt", must(ledger.receipt(log, 1), "receipt"));
    for (std::uint64_t i = 0; i < ledger.size(); ++i) {
        seeds.write("protocol_parse_fuzz", "entry-" + std::to_string(i),
                    must(ledger.entry(i), "entry"));
    }

    // A time-stamp authority's token over the checkpoint (v0.11): the
    // evidence below carries it as an anchor.
    const test::TimestampAuthority authority;
    const auto stamped = must(provider.digest(hash, *latest.envelope.payload), "digest");
    must(ledger.add_timestamp(authority.token(hash, stamped.bytes(), clock.now()),
                              latest.checkpoint.tree_size),
         "timestamp");

    // Evidence: plain, with a disclosure and an opening, and of the access
    // records (what check_access_* take).
    auto bundle = must(ledger.export_evidence(log, document), "export");
    const Bytes plain = must(protocol::encode_bundle(bundle), "encode");
    seeds.write("protocol_parse_fuzz", "bundle", plain);
    // A bundle carrying another ledger's evidence as a source proof (v0.18).
    auto sourced = bundle;
    sourced.source_proofs = {plain};
    seeds.write("protocol_parse_fuzz", "bundle-source-proof",
                must(protocol::encode_bundle(sourced), "encode"));
    bundle.disclosures.push_back(
        must(protocol::disclose_field(provider, hash, commitment, "result"), "disclose"));
    bundle.attachments.push_back({"report.pdf", salt});
    const Bytes disclosed = must(protocol::encode_bundle(bundle), "encode");
    seeds.write("protocol_parse_fuzz", "bundle-disclosed", disclosed);
    seeds.write("protocol_parse_fuzz", "bundle-request",
                must(protocol::encode_bundle(must(ledger.export_evidence(log, request_id), "e")),
                     "encode"));
    const Bytes grant_bundle =
        must(protocol::encode_bundle(must(ledger.export_evidence(log, grant_id), "e")), "encode");
    seeds.write("protocol_parse_fuzz", "bundle-grant", grant_bundle);
    seeds.write(
        "access_parse_fuzz", "delivery",
        must(protocol::encode_delivery({grant_bundle, Bytes(32, 1), Bytes(48, 2)}), "delivery"));
    seeds.write("access_parse_fuzz", "delivery-contents",
                must(protocol::encode_delivery_contents({disclosed, {{"report.pdf", report}}}),
                     "contents"));

    // Key rotations (spec v0.4): a bundle and a cosign request that carry
    // them, and backups signed with the newest log key.
    const auto log2 = must(crypto::openssl::KeyPair::generate(crypto::SigAlg::ed25519), "key");
    const auto root2 = must(crypto::openssl::KeyPair::generate(crypto::SigAlg::ed25519), "key");
    const std::uint64_t witnessed = ledger.latest_checkpoint()->checkpoint.tree_size;
    submit(protocol::LedgerRotateLogKeyBody{log2.public_key()});
    submit(protocol::ActorRotateKeyBody{ledger.id(), root2.public_key()});
    root = &root2;
    submit(protocol::RecordRegisterBody{
        "other/1",
        Bytes(commitment.root.bytes().begin(), commitment.root.bytes().end()),
        commitment.leaves.size(),
        {},
        std::nullopt,
        std::nullopt,
        {}});
    must(ledger.checkpoint(log2), "checkpoint");
    seeds.write(
        "protocol_parse_fuzz", "bundle-rotated",
        must(protocol::encode_bundle(must(ledger.export_evidence(log2, document), "e")), "encode"));
    seeds.write(
        "protocol_parse_fuzz", "cosign-request-rotated",
        must(protocol::encode_cosign_request(must(ledger.cosign_request(witnessed), "request")),
             "encode"));
    // A relay message: {1: to, 2: from, 3: id, 4: [enc, ciphertext], 6: until},
    // signed by the sender's log key over the relay's context.
    {
        cose::SignOptions options;
        constexpr std::string_view context = "Kanhe relay message v1";
        options.external_aad =
            ByteView(reinterpret_cast<const std::uint8_t*>(context.data()), context.size());
        const Bytes payload = must(
            cbor::encode(cbor::Value::map(
                {{cbor::Value::integer(1), cbor::Value::bytes(ledger.id().bytes())},
                 {cbor::Value::integer(2), cbor::Value::bytes(ledger.id().bytes())},
                 {cbor::Value::integer(3), cbor::Value::bytes(Bytes(16, 7))},
                 {cbor::Value::integer(4), cbor::Value::array({cbor::Value::bytes(Bytes(32, 1)),
                                                               cbor::Value::bytes(Bytes(48, 2))})},
                 {cbor::Value::integer(6), cbor::Value::unsigned_integer(1'800'000'060'000)}})),
            "encode");
        seeds.write("relay_message_fuzz", "message",
                    must(cose::sign(log2, payload, options), "sign"));
    }
    // A public witness's registration: the genesis entry and a cosign
    // request from size 0, through the rotations ({1: entry, 2: request}).
    seeds.write(
        "witness_registration_fuzz", "registration",
        must(cbor::encode(cbor::Value::map(
                 {{cbor::Value::integer(1), cbor::Value::bytes(must(ledger.entry(0), "genesis"))},
                  {cbor::Value::integer(2),
                   cbor::Value::bytes(must(
                       protocol::encode_cosign_request(must(ledger.cosign_request(0), "request")),
                       "encode"))}})),
             "encode"));

    // Backups, signed and not.
    for (const bool sign : {true, false}) {
        std::ostringstream out;
        const std::vector<ledger::BackupFile> files{{"api-tokens", Bytes{'{', '}'}}};
        must(
            ledger::write_backup(ledger, provider, files, clock.now(), out, sign ? &log2 : nullptr),
            "backup");
        seeds.write("backup_restore_fuzz", sign ? "signed" : "unsigned", out.str());
    }
}

/// One organization's ledger in memory, for the contract seeds.
struct Org {
    crypto::openssl::Provider provider;
    crypto::openssl::KeyPair root =
        must(crypto::openssl::KeyPair::generate(crypto::SigAlg::ed25519), "key");
    crypto::openssl::KeyPair log =
        must(crypto::openssl::KeyPair::generate(crypto::SigAlg::ed25519), "key");
    ledger::ManualClock clock{1'791'244'800'000};
    ledger::SeededEntropy entropy;
    ledger::MemoryFileSystem fs;
    std::optional<ledger::Ledger> ledger;

    Org(const std::string& name, std::uint64_t seed) : entropy(seed) {
        protocol::Statement genesis;
        genesis.issued_at = clock.now();
        genesis.nonce = entropy.bytes<16>();
        genesis.body = protocol::GenesisBody{crypto::HashAlg::sha256, name, root.public_key(),
                                             log.public_key()};
        const auto signed_genesis = must(
            protocol::sign_statement(root, provider, crypto::HashAlg::sha256, genesis), "sign");
        ledger.emplace(
            must(ledger::Ledger::create(fs, clock, provider, signed_genesis.encoded), "create"));
    }

    [[nodiscard]] const protocol::Id& id() const { return ledger->id(); }

    /// Signs and registers a statement by the organization; returns it.
    protocol::SignedStatement submit(protocol::Body body) {
        protocol::Statement s;
        s.ledger_id = ledger->id();
        s.actor_id = ledger->id();
        s.issued_at = clock.now();
        s.nonce = entropy.bytes<16>();
        s.body = std::move(body);
        auto signed_statement =
            must(protocol::sign_statement(root, provider, crypto::HashAlg::sha256, s), "sign");
        must(ledger->submit(signed_statement.encoded), "submit");
        clock.advance(1000);
        return signed_statement;
    }

    protocol::Id record(std::string_view type, cbor::Value metadata) {
        const auto fields = must(protocol::commit_fields(provider, crypto::HashAlg::sha256,
                                                         {{"contract", protocol::Nonce{},
                                                           cbor::Value::text("PO-0815")}}),
                                 "fields");
        return submit(protocol::RecordRegisterBody{
                          std::string(type),
                          Bytes(fields.root.bytes().begin(), fields.root.bytes().end()),
                          1,
                          {},
                          std::move(metadata),
                          std::nullopt,
                          {}})
            .id;
    }

    Bytes evidence(const protocol::Id& record) {
        must(ledger->checkpoint(log), "checkpoint");
        return must(protocol::encode_bundle(must(ledger->export_evidence(log, record), "export")),
                    "encode");
    }
};

/// A passkey registration as a browser returns it: [length][attestation
/// object][client data], for the challenge and site the fuzzer uses.
void webauthn_seed(const Seeds& seeds) {
    const crypto::openssl::Provider provider;
    const auto passkey = must(crypto::openssl::KeyPair::generate(crypto::SigAlg::esp256), "key");
    const Bytes& point = passkey.public_key().bytes; // 0x04 || x || y
    Bytes auth_data;
    const auto rp = must(provider.digest(crypto::HashAlg::sha256, as_bytes("localhost")), "hash");
    auth_data.insert(auth_data.end(), rp.bytes().begin(), rp.bytes().end());
    auth_data.push_back(0x41);                    // user present, credential attested
    auth_data.insert(auth_data.end(), 4 + 16, 0); // counter, AAGUID
    const Bytes credential_id(16, 0xc1);
    auth_data.push_back(0);
    auth_data.push_back(static_cast<std::uint8_t>(credential_id.size()));
    auth_data.insert(auth_data.end(), credential_id.begin(), credential_id.end());
    const Bytes cose_key = must(
        cbor::encode(cbor::Value::map(
            {{cbor::Value::integer(1), cbor::Value::integer(2)},
             {cbor::Value::integer(3), cbor::Value::integer(-7)},
             {cbor::Value::integer(-1), cbor::Value::integer(1)},
             {cbor::Value::integer(-2), cbor::Value::bytes(ByteView(point).subspan(1, 32))},
             {cbor::Value::integer(-3), cbor::Value::bytes(ByteView(point).subspan(33, 32))}})),
        "cose key");
    auth_data.insert(auth_data.end(), cose_key.begin(), cose_key.end());
    const Bytes attestation =
        must(cbor::encode(cbor::Value::map(
                 {{cbor::Value::text("fmt"), cbor::Value::text("none")},
                  {cbor::Value::text("attStmt"), cbor::Value::map({})},
                  {cbor::Value::text("authData"), cbor::Value::bytes(auth_data)}})),
             "attestation");
    const std::string client_data = R"({"type":"webauthn.create","challenge":")" +
                                    to_base64url(Bytes(32, 0x5a)) +
                                    R"(","origin":"http://localhost:8765","crossOrigin":false})";
    Bytes input{static_cast<std::uint8_t>(attestation.size() >> 8U),
                static_cast<std::uint8_t>(attestation.size())};
    input.insert(input.end(), attestation.begin(), attestation.end());
    input.insert(input.end(), client_data.begin(), client_data.end());
    must(protocol::credential_from_registration(provider, attestation, as_bytes(client_data),
                                                Bytes(32, 0x5a), "localhost", std::nullopt),
         "the seed registration must be valid");
    seeds.write("webauthn_registration_fuzz", "registration", input);
}

/// A pending call as a registrar holds it (node/contracts.hpp): with
/// `progress`, the proposer, the ledgers missing, and a consent held.
cbor::Value pending_call(bool progress) {
    using cbor::Value;
    cbor::Map map{{Value::integer(1), Value::bytes(Bytes(32, 0x11))},
                  {Value::integer(2), Value::unsigned_integer(7)},
                  {Value::integer(3), Value::text("sign")},
                  {Value::integer(4), Value::array({Value::bytes(Bytes{0x82, 0x01, 0xa0})})},
                  {Value::integer(5), Value::text("PO-2026-17")},
                  {Value::integer(6), Value::unsigned_integer(1'791'849'600'000)}};
    if (progress) {
        map.push_back({Value::integer(7), Value::text("staff")});
        map.push_back({Value::integer(8), Value::array({Value::bytes(Bytes(32, 0x22))})});
        map.push_back({Value::integer(9),
                       Value::array({Value::array({Value::bytes(Bytes(32, 0x33)),
                                                   Value::bytes(Bytes{0xa1, 0x00, 0x01})})})});
    }
    return Value::map(std::move(map));
}

/// A pending call's file name: "<instance>-<head>-<id>.cbor".
std::string pending_name() {
    return to_hex(Bytes(32, 0x11)) + "-7-" + to_hex(Bytes(32, 0x44)) + ".cbor";
}

void pending_call_seeds(const Seeds& seeds) {
    using cbor::Value;
    seeds.write("pending_call_fuzz", "proposal", must(cbor::encode(pending_call(false)), "encode"));
    seeds.write("pending_call_fuzz", "pending", must(cbor::encode(pending_call(true)), "encode"));
    seeds.write("pending_call_fuzz", "name", pending_name());
    seeds.write(
        "pending_call_fuzz", "changes",
        must(cbor::encode(Value::array(
                 {Value::array({Value::text(pending_name()),
                                Value::bytes(must(cbor::encode(pending_call(true)), "encode"))}),
                  Value::array({Value::text(pending_name()), Value::null()})})),
             "encode"));
}

/// Raft entries and snapshot objects, as a cluster member receives them:
/// [kind][CBOR] (see cluster_entry_fuzz).
void record_file_seeds(const Seeds& seeds) {
    // A sealed file the size of a 5-byte attachment, alone and in a list.
    const auto sealed = cbor::Value::map(
        {{cbor::Value::integer(1), cbor::Value::unsigned_integer(1)},
         {cbor::Value::integer(2),
          cbor::Value::array({cbor::Value::unsigned_integer(32), cbor::Value::unsigned_integer(1),
                              cbor::Value::unsigned_integer(2)})},
         {cbor::Value::integer(3), cbor::Value::bytes(Bytes(32, 7))},
         {cbor::Value::integer(4), cbor::Value::bytes(Bytes(21, 9))}});
    const Bytes file = must(cbor::encode(sealed), "encode");
    seeds.write("record_files_fuzz", "sealed", file);
    seeds.write(
        "record_files_fuzz", "list",
        must(cbor::encode(cbor::Value::array(
                 {cbor::Value::array({cbor::Value::unsigned_integer(0), cbor::Value::bytes(file)}),
                  cbor::Value::array(
                      {cbor::Value::unsigned_integer(1), cbor::Value::bytes(file)})})),
             "encode"));
}

void form_seeds(const Seeds& seeds) {
    // The first byte picks a sheet (even) or a source (odd).
    seeds.write("bo_form_fuzz", "sheet",
                std::string(1, '\0') +
                    R"({"sheet": 1, "kind": "rules", "contract": "Lending", "parties": ["owner"],
 "thing": {"name": "Item", "fields": [{"name": "name", "type": "text"},
                                      {"name": "holder", "type": "owner"}]},
 "actions": [{"action": "lend", "by": "owner", "to": "counterparty", "from": ["active"],
              "to_state": "lent", "set": [{"name": "holder", "value": "counterparty"}]},
             {"action": "bring_back", "by": "holder", "from": ["lent"], "to_state": "active",
              "set": [{"name": "holder", "value": "owner"}]}],
 "tests": [{"name": "\"lent\"", "steps": [
   {"party": "owner", "action": "create", "with": [{"name": "name", "value": "\"X\""}]},
   {"party": "owner", "action": "lend", "to": "friend", "expect": "lent"}]}]})");
    seeds.write("bo_form_fuzz", "source",
                std::string("\x01") + "contract Sync\nparties we, partner\n\nthing Record\n"
                                      "  note text\n\ncan share by we\n  active -> shared\n"
                                      "  request sync to partner with note = note within 1 day\n"
                                      "\nwhen sync done\n  -> synced\n");
    // Lists nested where a piece of text goes, within the default input size.
    seeds.write("bo_form_fuzz", "nested",
                std::string(1, '\0') + R"({"sheet": 1, "kind": "rules", "contract": )" +
                    std::string(1900, '[') + std::string(1900, ']') + "}");
}

void exchange_seeds(const Seeds& seeds) {
    protocol::ExchangeFile file;
    file.home = protocol::Id::from_bytes(Bytes(32, 0x11)).value();
    file.instance = protocol::Id::from_bytes(Bytes(32, 0x22)).value();
    file.head = 7;
    file.function = "lend";
    file.arguments = cbor::Value::map(
        {{cbor::Value::text("counterparty"), cbor::Value::bytes(Bytes(32, 0x33))}});
    file.evidence = Bytes{1, 2, 3};
    file.needs.push_back(protocol::Id::from_bytes(Bytes(32, 0x33)).value());
    file.note = "Lend it to me, please";
    seeds.write("exchange_file_fuzz", "proposal",
                must(protocol::encode_exchange_file(file), "proposal"));
    file.kind = protocol::ExchangeKind::consent;
    file.needs.clear();
    file.note.reset();
    seeds.write("exchange_file_fuzz", "consent",
                must(protocol::encode_exchange_file(file), "consent"));
}

void calls_seeds(const Seeds& seeds) {
    // The first byte picks the values' JSON (even) or one value (odd).
    seeds.write("bo_calls_fuzz", "values",
                std::string(1, '\0') +
                    R"({"cost": "HKD 1_250.50", "starts": "2027年1月6日", "weight": "3 噸",
 "urgent": true, "tags": ["fragile"], "note": "by hand", "count": "500萬",
 "we": "1111111111111111111111111111111111111111111111111111111111111111",
 "buyer": "2222222222222222222222222222222222222222222222222222222222222222"})");
    seeds.write("bo_calls_fuzz", "money", std::string("\x01") + "500萬港元");
    seeds.write("bo_calls_fuzz", "duration", std::string("\x01") + "3 個月");
    // Lists nested deeper than a value's two levels.
    seeds.write("bo_calls_fuzz", "nested",
                std::string(1, '\0') + R"({"tags": )" + std::string(1900, '[') +
                    std::string(1900, ']') + "}");
}

void cluster_seeds(const Seeds& seeds) {
    using cbor::Value;
    auto write = [&](const std::string& name, std::uint8_t kind, const Value& value) {
        Bytes input{kind};
        const Bytes encoded = must(cbor::encode(value), "encode");
        input.insert(input.end(), encoded.begin(), encoded.end());
        seeds.write("cluster_entry_fuzz", name, input);
    };
    write("batch", 0,
          Value::array({Value::unsigned_integer(1), Value::unsigned_integer(1'791'244'800'000),
                        Value::unsigned_integer(1), Value::array({Value::bytes(Bytes(40, 0xd2))}),
                        Value::array({Value::array(
                            {Value::unsigned_integer(0), Value::bytes(Bytes{0xa0})})})}));
    // Kind 2 is reserved (spec v0.9 removed the native asset actions' consents): ignored.
    write("batch-reserved-kind", 0,
          Value::array({Value::unsigned_integer(1), Value::unsigned_integer(1'791'244'800'000),
                        Value::unsigned_integer(1), Value::array({Value::bytes(Bytes(40, 0xd2))}),
                        Value::array({Value::array({Value::unsigned_integer(0),
                                                    Value::bytes(Bytes{0x81, 0x41, 0x00}),
                                                    Value::unsigned_integer(2)})})}));
    write("batch-contract-consents", 0,
          Value::array({Value::unsigned_integer(1), Value::unsigned_integer(1'791'244'800'000),
                        Value::unsigned_integer(1), Value::array({Value::bytes(Bytes(40, 0xd2))}),
                        Value::array({Value::array({Value::unsigned_integer(0),
                                                    Value::bytes(Bytes{0x81, 0x41, 0x00}),
                                                    Value::unsigned_integer(3)})})}));
    const Bytes pending = must(cbor::encode(pending_call(true)), "encode");
    write("pending", 2,
          Value::array(
              {Value::unsigned_integer(4),
               Value::array({Value::array({Value::text(pending_name()), Value::bytes(pending)}),
                             Value::array({Value::text(pending_name()), Value::null()})})}));
    write("checkpoint", 1,
          Value::array({Value::unsigned_integer(2), Value::null(), Value::bytes(Bytes(60, 0xd2))}));
    write("cosignature", 2,
          Value::array({Value::unsigned_integer(3), Value::bytes(Bytes(60, 0xd2)),
                        Value::array({Value::integer(-19), Value::bytes(Bytes(32, 7))})}));
    write("snapshot-header", 3,
          Value::array({Value::bytes(Bytes(32, 1)), Value::unsigned_integer(5),
                        Value::unsigned_integer(1)}));
    write("snapshot-entries", 4, Value::array({Value::bytes(Bytes(20, 3))}));
    write("snapshot-files", 5,
          Value::array({Value::array({Value::bytes(Bytes(32, 4)), Value::bytes(Bytes{0xa0})}),
                        Value::array({Value::bytes(Bytes(32, 5)), Value::bytes(Bytes{0x81, 0x40}),
                                      Value::unsigned_integer(2)}),
                        Value::array({Value::bytes(Bytes(32, 6)), Value::bytes(Bytes{0x81, 0x40}),
                                      Value::unsigned_integer(3)}),
                        Value::array({Value::text(pending_name()), Value::bytes(pending),
                                      Value::unsigned_integer(4)})}));
    write("snapshot-extras", 5, Value::array({Value::array({}), Value::array({})}));
}

void text_seeds(const Seeds& seeds) {
    // A kind sheet, as the Kinds screen writes one.
    seeds.write(
        "kind_sheet_fuzz", "photo",
        R"({"sheet": 1, "kind": "document", "type": "example.org.photo/1",)"
        R"( "name": "Photo", "description": "A photo and where it was taken",)"
        R"( "fields": [{"name": "place", "label": "Place", "type": "text", "required": true},)"
        R"( {"name": "taken", "type": "date", "private": false},)"
        R"( {"name": "price", "type": "number"}, {"name": "framed", "type": "yes-no"}],)"
        R"( "files": "required", "keep_files": true, "printed": ["place", "taken"]})");
    // A table of certificates as a spreadsheet exports it, and a template.
    seeds.write("certificate_table_fuzz", "table",
                "\xEF\xBB\xBFName,Date,count\r\n\"Chan, Tai Man\",2026-11-10,3\r\n"
                "\"say \"\"hi\"\"\",,\r\n");
    seeds.write("certificate_table_fuzz", "template",
                "<h1>{{kind}}</h1>{{fields}}<p>{{ name }} {{field.date}}</p>{{qr}}");
    // Paths a restore may write, and some it may not.
    const std::string id(64, 'a');
    seeds.write("sealed_backup_fuzz", "users", "console/users.json");
    seeds.write("sealed_backup_fuzz", "inbox", "access/inbox/" + id + ".cbor");
    seeds.write("sealed_backup_fuzz", "slot", "console/slots/passkey-AbC_9-x.p8");
    seeds.write("sealed_backup_fuzz", "kept", "vault/files/" + id + "/12.cbor");
    seeds.write("sealed_backup_fuzz", "escape", "console/keys/../../etc.sealed");
    // A sealed backup's shape, its fields empty.
    seeds.write(
        "sealed_backup_fuzz", "sealed",
        kanhe::cbor::encode(
            kanhe::cbor::Value::map(
                {{kanhe::cbor::Value::integer(1), kanhe::cbor::Value::text("kanhe-sealed-backup")},
                 {kanhe::cbor::Value::integer(2), kanhe::cbor::Value::integer(1)},
                 {kanhe::cbor::Value::integer(3), kanhe::cbor::Value::bytes(Bytes(32, 7))},
                 {kanhe::cbor::Value::integer(4), kanhe::cbor::Value::unsigned_integer(1)},
                 {kanhe::cbor::Value::integer(5), kanhe::cbor::Value::bytes(Bytes(8, 1))},
                 {kanhe::cbor::Value::integer(6), kanhe::cbor::Value::bytes(Bytes(32, 2))},
                 {kanhe::cbor::Value::integer(7), kanhe::cbor::Value::bytes(Bytes(48, 3))}}))
            .value());
    seeds.write("console_request_fuzz", "page",
                "GET /console/ HTTP/1.1\r\nHost: localhost:7470\r\n\r\n");
    seeds.write("console_request_fuzz", "session",
                "GET /console/api/session HTTP/1.1\r\nHost: 127.0.0.1:7470\r\n"
                "Authorization: Bearer khs_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\r\n\r\n");
    seeds.write("console_request_fuzz", "sign-out",
                "DELETE /console/api/session HTTP/1.1\r\nHost: [::1]:7470\r\n"
                "Origin: http://[::1]:7470\r\n"
                "Authorization: bearer khs_BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB\r\n\r\n");
    seeds.write(
        "console_request_fuzz", "enroll",
        "POST /console/api/enroll/begin HTTP/1.1\r\nHost: localhost:7470\r\n"
        "Origin: http://localhost:7470\r\nContent-Length: 73\r\n\r\n"
        "{\"code\":\"khi_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\",\"name\":\"Alice\"}");
    seeds.write("console_request_fuzz", "sign-in",
                "POST /console/api/sign-in/finish HTTP/1.1\r\nHost: localhost:7470\r\n"
                "Origin: http://localhost:7470\r\nContent-Length: 106\r\n\r\n"
                "{\"ceremony\":\"00\",\"credential_id\":\"AA\",\"authenticator_data\":\"AA\","
                "\"client_data_json\":\"e30\",\"signature\":\"AA\"}");
    seeds.write("console_request_fuzz", "start",
                "GET /console/api/start HTTP/1.1\r\nHost: localhost:7470\r\n\r\n");
    seeds.write("console_request_fuzz", "settings",
                "POST /console/api/settings HTTP/1.1\r\nHost: localhost:7470\r\n"
                "Origin: http://localhost:7470\r\n"
                "Authorization: Bearer khs_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\r\n"
                "Content-Length: 48\r\n\r\n"
                "{\"language\":\"en\",\"backup_folder\":\"/tmp/backups\"}");
    seeds.write("console_request_fuzz", "recover",
                "POST /console/api/recover/begin HTTP/1.1\r\nHost: localhost:7470\r\n"
                "Origin: http://localhost:7470\r\nContent-Length: 52\r\n\r\n"
                "{\"recovery_code\":\"abcd efgh ijkl mnop qrst uvwx yz\"}");
    seeds.write(
        "console_request_fuzz", "script",
        "GET /console/api/scripts/" + std::string(64, 'a') +
            " HTTP/1.1\r\nHost: localhost:7470\r\n"
            "Authorization: Bearer khs_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\r\n\r\n");
    seeds.write("console_request_fuzz", "sources",
                "GET /console/api/sources?type=example.org.photo/1 HTTP/1.1\r\n"
                "Host: localhost:7470\r\n\r\n");
    seeds.write("console_request_fuzz", "source-proofs",
                "POST /console/api/records/source-proofs HTTP/1.1\r\nHost: localhost:7470\r\n"
                "Origin: http://localhost:7470\r\nContent-Length: 15\r\n\r\n{\"upload\":\"00\"}");
    // Approvals and guardians (spec v0.20): read with a session, changed
    // only from the console's own page.
    seeds.write(
        "console_request_fuzz", "approvals",
        "GET /console/api/approvals?language=zh-Hant-HK HTTP/1.1\r\nHost: localhost:7470\r\n"
        "Authorization: Bearer khs_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\r\n\r\n");
    seeds.write("console_request_fuzz", "approval",
                "GET /console/api/approvals/" + std::string(64, 'a') +
                    " HTTP/1.1\r\nHost: localhost:7470\r\n\r\n");
    seeds.write("console_request_fuzz", "approval-prepare",
                "POST /console/api/approvals/" + std::string(64, 'b') +
                    "/prepare HTTP/1.1\r\nHost: localhost:7470\r\n"
                    "Origin: http://localhost:7470\r\nContent-Length: 2\r\n\r\n{}");
    seeds.write("console_request_fuzz", "approval-approve",
                "POST /console/api/approvals/" + std::string(64, 'c') +
                    "/approve HTTP/1.1\r\nHost: localhost:7470\r\n"
                    "Origin: http://localhost:7470\r\nContent-Length: 36\r\n\r\n"
                    "{\"prepared\":\"00\",\"signature\":\"AAAA\"}");
    seeds.write("console_request_fuzz", "approval-withdraw",
                "DELETE /console/api/approvals/" + std::string(64, 'd') +
                    " HTTP/1.1\r\nHost: localhost:7470\r\nOrigin: http://localhost:7470\r\n\r\n");
    seeds.write("console_request_fuzz", "guardians",
                "GET /console/api/guardians HTTP/1.1\r\nHost: localhost:7470\r\n\r\n");
    seeds.write("console_request_fuzz", "rebinding",
                "GET /console/ HTTP/1.1\r\nHost: attacker.example:7470\r\n"
                "Origin: https://attacker.example\r\n\r\n");
    seeds.write("http_parse_fuzz", "get",
                "GET /v1/entries?start=0&count=10 HTTP/1.1\r\nHost: ledger\r\n"
                "Authorization: Bearer kht_x\r\n\r\n");
    seeds.write("http_parse_fuzz", "post",
                "POST /v1/statements HTTP/1.1\r\nHost: ledger\r\nContent-Type: application/cose\r\n"
                "Content-Length: 5\r\nExpect: 100-continue\r\n\r\nhello");
    seeds.write("http_parse_fuzz", "pipelined",
                "GET /healthz HTTP/1.1\r\nHost: a\r\n\r\nHEAD /healthz HTTP/1.1\r\nHost: a\r\n"
                "Connection: close\r\n\r\n");
    seeds.write("http_parse_fuzz", "chunked-response",
                "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nabcd\r\n0\r\n\r\n");
    seeds.write("http_parse_fuzz", "response",
                "HTTP/1.1 404 Not Found\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}");
    seeds.write("http_parse_fuzz", "requests-poll",
                "GET /v1/requests?state=open&kind=notify,http.post&after=12&limit=50&wait=25 "
                "HTTP/1.1\r\nHost: ledger\r\nAuthorization: Bearer kht_x\r\n\r\n");
    seeds.write("http_parse_fuzz", "requests-instance",
                "GET /v1/requests?state=all&instance=" + std::string(64, 'a') +
                    "&contract=" + std::string(64, '0') + " HTTP/1.1\r\nHost: ledger\r\n\r\n");
    seeds.write("http_parse_fuzz", "contracts-due",
                "GET /v1/contracts/due?at=1792022400000&grace=900&keeper=" + std::string(64, 'b') +
                    "&start=7&limit=2000 HTTP/1.1\r\nHost: ledger\r\n\r\n");
    // The connector protocol: the first byte chooses the direction (even:
    // from a connector, odd: to it).
    const std::string request(64, 'a');
    const std::string other(64, 'b');
    seeds.write("connector_line_fuzz", "ready",
                std::string(1, '\0') +
                    R"({"type":"ready","protocol":1,"name":"webhook","version":"0.1",)"
                    R"("kinds":["notify","http.post"]})");
    seeds.write("connector_line_fuzz", "outcome-done",
                std::string(1, '\0') + R"({"type":"outcome","id":")" + request +
                    R"(","status":"done","result":{"ref":"N-1","amount":1250,"ok":true,)"
                    R"("lines":[1,-2,null]},"response":"eyJvayI6dHJ1ZX0"})");
    seeds.write("connector_line_fuzz", "outcome-retry",
                std::string(1, '\0') + R"({"type":"outcome","id":")" + request +
                    R"(","status":"retry","reason":"unavailable","retry_after_ms":2000})");
    seeds.write("connector_line_fuzz", "log",
                std::string(1, '\0') + R"({"type":"log","level":"warn","message":"slow","id":")" +
                    request + R"("})");
    seeds.write("connector_line_fuzz", "hello",
                std::string(1, '\1') +
                    R"({"type":"hello","protocol":1,"connector":"hook","config":{"url":)"
                    R"("https://example.com/hook","timeout":10},"secrets":{"hook-key":"k"}})");
    seeds.write("connector_line_fuzz", "perform",
                std::string(1, '\1') + R"({"type":"perform","id":")" + request +
                    R"(","kind":"notify","params":{"about":"welcome"},)"
                    R"("params_cbor":"a16561626f75746777656c636f6d65","deadline":1800000000000,)"
                    R"("asked_at":1799000000000,"home":")" +
                    other + R"(","contract":")" + other + R"(","instance":")" + other +
                    R"(","reply":"result","attempt":2,"timeout_ms":30000})");
    seeds.write("connector_line_fuzz", "cancel",
                std::string(1, '\1') + R"({"type":"cancel","id":")" + request +
                    R"(","reason":"answered"})");
    // An executor's config and state files (executor_state_fuzz): the first
    // byte chooses the reader (0 config, 1 journal entry, 2 cursor, 3 sealed
    // secret, sealed to another key than the fuzzer's).
    seeds.write(
        "executor_state_fuzz", "config",
        std::string(1, '\0') +
            R"({"actor":"ad2b642072ec3bf0f7ec67acbd7cfb8a9591c792570204f328553e7714b6f206",)"
            R"("connectors":[{"args":["/usr/local/bin/notify"],"concurrency":4,"kinds":["notify"],)"
            R"("name":"n)"
            R"(otices","program":"/bin/sh","secrets":["notify-token"],"timeout":10,"type":")"
            R"(command"},{"kinds":["http.post"],"name":"hook","secret":"hook-key","timeo)"
            R"(ut":30,"type":"webhook","url":"https://hooks.example.com/ledger"}],"delegati)"
            R"(on":"121c8bce2e0e28889ccf8ef5349609a6adc5139c28c96ece04c2a80d2ace9954","ledg)"
            R"(er_id":"9b7b02745f0a609a0fdf7ca3562b0a803641d9cdc7fb708c4b9ca816f8f82cf9","v)"
            R"(ersion":1})");
    seeds.write(
        "executor_state_fuzz", "entry",
        std::string(1, '\1') +
            R"({"answered_by":null,"answered_status":null,"asked_at":1792355896652,"attempt)"
            R"(s":1,"connector":"notices","contract":"79a2e9893ce98db050f5e07884f1bfd3b5db8)"
            R"(030a4e76a3351bb7883fca16768","deadline":1792442296652,"digest":"df609e5b1cb9)"
            R"(a24d1fe22390ca0be19ac7d30e49c73681325a9c151a7b29e08d","failures":0,"first_se)"
            R"(en":1792355896661,"head":6,"index":8,"instance":"7eac7697cc4709a495c963f20f6)"
            R"(33c3059060a965524ae24a5580bbca24ec269","kind":"notify","next_at":0,"note":"")"
            R"(,"params":"a262746f58209b7b02745f0a609a0fdf7ca3562b0a803641d9cdc7fb708c4b9ca)"
            R"(816f8f82cf9676d657373616765626869","reason":null,"reply":"result","request":)"
            R"("e526fc7e4bba9f9a0c68ae72097eb49362e5ed47b2e5d9cc1560808051f4fe44","response)"
            R"(":"7b22726573756c74223a20224e2d6535323666633765227d0a","result":"6a4e2d65353)"
            R"(23666633765","salt":"412fed8ce7f14c97ad80d38901316f41","stage":"answered","s)"
            R"(tatement":"d284584ca301320378206170706c69636174696f6e2f6b616e68652d737)"
            R"(46174656d656e742b63626f7204582015aa39bc1685dcb52f561fd46107f7d7eb1bfb1f2e8dd)"
            R"(dae5ae5fa496db2d413a059011da8000101160258209b7b02745f0a609a0fdf7ca3562b0a803)"
            R"(641d9cdc7fb708c4b9ca816f8f82cf9035820ad2b642072ec3bf0f7ec67acbd7cfb8a9591c79)"
            R"(2570204f328553e7714b6f206045820121c8bce2e0e28889ccf8ef5349609a6adc5139c28c96)"
            R"(ece04c2a80d2ace9954051b000001a150bc8d860650e32ddaab59d176484d05dc1f584388ce0)"
            R"(7a50258207eac7697cc4709a495c963f20f633c3059060a965524ae24a5580bbca24ec269036)"
            R"(6726573756c7404a266726573756c746a4e2d653532366663376568726573706f6e73655820d)"
            R"(f609e5b1cb9a24d1fe22390ca0be19ac7d30e49c73681325a9c151a7b29e08d050608825820e)"
            R"(526fc7e4bba9f9a0c68ae72097eb49362e5ed47b2e5d9cc1560808051f4fe44015840372268d)"
            R"(74814100af5a223854ed5bd811be3bba9618a8d167ec37b4db3e7096327dfb0c629dd50b5b4e)"
            R"(26c2f8b71815a2273959065d71a4a61301babfbbeed04","statement_id":"c374ca2442e79)"
            R"(a5f2c6ce07055b360262b9c9f095133defca679739cee2bcb20","status":"done","update)"
            R"(d":1792355896718})");
    seeds.write("executor_state_fuzz", "cursor",
                std::string(1, '\2') + R"({"after":9,"server":"http://127.0.0.1:8080"})");
    const auto sealed_body =
        must(from_hex("a40101028318200102035820bac16c9f9381ae30de93b8468bf7ec3c52ee911122d933a960f7"
                      "e9815647720f04581c371435ad80bbb1cab639e63f9e93910b17926d111ce26c4d1cc0212f"),
             "a sealed secret");
    Bytes sealed_secret{3};
    sealed_secret.insert(sealed_secret.end(), sealed_body.begin(), sealed_body.end());
    seeds.write("executor_state_fuzz", "sealed", sealed_secret);
    seeds.write("pkcs11_uri_fuzz", "key",
                "pkcs11:token=Kanhe;object=alice;type=private?module-path=/usr/lib/"
                "softhsm/libsofthsm2.so&pin-source=file:/run/pin");
    seeds.write("pkcs11_uri_fuzz", "sm2",
                "pkcs11:serial=0123;id=%01%02;slot-id=0?module-path=/opt/ukey.so&"
                "x-sm2-mechanism=0x80000001");
}

} // namespace

/// Every module of the interpreter's vectors, valid and refused: they cover
/// each instruction, trap, and validation rule. And the code of the Bo
/// conformance contracts: what the interpreter runs most, in the sequences
/// it fuses.
void vm_seeds(const Seeds& seeds) {
    std::ifstream in(KANHE_TESTVECTORS_DIR "/vm-v1.json");
    if (!in) {
        throw std::runtime_error("cannot read vm-v1.json");
    }
    const auto doc = nlohmann::json::parse(in);
    std::size_t n = 0;
    for (const auto& module : doc.at("modules")) {
        const auto wasm = must(from_hex(module.at("wasm").get<std::string>()), "module");
        seeds.write("vm_fuzz", std::format("module-{:03}", n++), ByteView(wasm));
    }
    std::ifstream bo_in(KANHE_TESTVECTORS_DIR "/bo-v1.json");
    if (!bo_in) {
        throw std::runtime_error("cannot read bo-v1.json");
    }
    const auto bo = nlohmann::json::parse(bo_in);
    for (const auto& contract : bo.at("contracts")) {
        const auto wasm = must(from_hex(contract.at("code").get<std::string>()), "code");
        seeds.write("vm_fuzz", "bo-" + contract.at("name").get<std::string>(), ByteView(wasm));
    }
    // Real contract inputs and outputs, states in them.
    n = 0;
    for (const auto& contract : bo.at("contracts")) {
        for (const auto& run : contract.at("runs")) {
            for (const char* part : {"input", "output"}) {
                const auto bytes = must(from_hex(run.at(part).get<std::string>()), part);
                if (!bytes.empty()) {
                    seeds.write("cbor_validate_fuzz", std::format("bo-{}-{:04}", part, n++),
                                ByteView(bytes));
                }
            }
        }
    }
}

/// Contract outputs (every verdict) and consent metadata from the v0.6
/// vectors, and real contract evidence: the vectors' test contract deployed,
/// an instance created, and a call with a supplier's consent.
void contract_seeds(const Seeds& seeds) {
    std::ifstream in(KANHE_TESTVECTORS_DIR "/protocol-v0.6.json");
    if (!in) {
        throw std::runtime_error("cannot read protocol-v0.6.json");
    }
    const auto doc = nlohmann::json::parse(in);
    const auto& ledger = doc.at("ledgers").at(0);
    std::size_t n = 0;
    for (const auto& run : ledger.at("runs")) {
        const auto output = must(from_hex(run.at("output").get<std::string>()), "output");
        // The Bo runtime reads contract inputs (and any CBOR): both as seeds.
        const auto input = must(from_hex(run.at("input").get<std::string>()), "input");
        seeds.write("bo_runtime_fuzz", std::format("input-{:02}", n), ByteView(input));
        seeds.write("bo_runtime_fuzz", std::format("output-{:02}", n), ByteView(output));
        seeds.write("contract_parse_fuzz", std::format("output-{:02}", n++), ByteView(output));
    }
    n = 0;
    for (const auto& consent : ledger.at("consents")) {
        const auto metadata = must(from_hex(consent.at("metadata").get<std::string>()), "consent");
        seeds.write("contract_parse_fuzz", std::format("consent-{:02}", n++), ByteView(metadata));
    }

    Org home("Seed Contract Home", 21);
    Org supplier("Seed Contract Supplier", 22);
    protocol::ContractDeployBody deploy;
    deploy.code = must(from_hex(doc.at("contract").get<std::string>()), "contract");
    deploy.interface = {{"propose", protocol::FunctionKind::create},
                        {"sign", protocol::FunctionKind::call}};
    deploy.language = "wasm";
    deploy.compiler = "hand-assembled 1";
    const auto deployed = home.submit(deploy);
    seeds.write("protocol_parse_fuzz", "statement-contract-deploy", deployed.encoded);

    // The test contract writes the content of byte-string arguments.
    auto arguments = [](const protocol::ContractOutput& output) {
        return cbor::Value::bytes(must(protocol::encode_contract_output(output), "output"));
    };
    protocol::ContractCallBody create;
    create.contract = deployed.id;
    create.function = "propose";
    create.arguments =
        arguments(protocol::ContractAccept{*cbor::Encoded::encode(cbor::Value::text("draft")),
                                           "proposed",
                                           protocol::Parties{{"supplier", supplier.id()}},
                                           {},
                                           false,
                                           {},
                                           {}});
    const auto created = home.submit(create);
    seeds.write("protocol_parse_fuzz", "statement-contract-create", created.encoded);

    protocol::ContractCallBody sign;
    sign.instance = created.id;
    sign.function = "sign";
    sign.arguments =
        arguments(protocol::ContractAccept{*cbor::Encoded::encode(cbor::Value::text("signed")),
                                           "effective",
                                           std::nullopt,
                                           {},
                                           false,
                                           {},
                                           {}});
    sign.head = home.ledger->state().instance(created.id)->head;
    const auto digest = must(
        protocol::contract_arguments_digest(home.provider, crypto::HashAlg::sha256, sign.arguments),
        "digest");
    const auto consent_metadata =
        must(protocol::encode_contract_consent({home.id(), created.id, "sign", digest, *sign.head,
                                                home.clock.now() + 86'400'000, std::nullopt}),
             "consent");
    const protocol::Id record = supplier.record(protocol::contract_consent_type, consent_metadata);
    Bytes bundle = supplier.evidence(record);
    sign.consents.push_back({supplier.id(),
                             record,
                             must(home.provider.digest(crypto::HashAlg::sha256, bundle), "hash"),
                             {}});
    const auto signed_call = home.submit(sign);
    seeds.write("protocol_parse_fuzz", "statement-contract-call", signed_call.encoded);
    const Bytes evidence =
        must(protocol::encode_contract_evidence({home.evidence(created.id), {std::move(bundle)}}),
             "evidence");
    must(protocol::verify_contract_evidence(home.provider, evidence),
         "the seed evidence must verify");
    seeds.write("contract_parse_fuzz", "evidence", evidence);
    // The home's state as a snapshot holds it: actors, records, a contract
    // (the same code as the fuzzer's), and an instance with its calls.
    seeds.write("state_snapshot_fuzz", "contract-home",
                must(home.ledger->state().encode(), "state"));
    seeds.write("state_snapshot_fuzz", "supplier",
                must(supplier.ledger->state().encode(), "state"));

    // Diagnostic notation, as the command line takes contract arguments; and
    // CBOR, whose rendering must parse back.
    seeds.write("diagnostic_fuzz", "arguments", cbor::diagnostic(sign.arguments));
    seeds.write("diagnostic_fuzz", "typed",
                std::string_view(R"([<<[2, [h'0102']]>>, {1: "a", "b": [true, null, -1]}, )"
                                 R"(1(1700000000), "é😀", h'00 ff'])"));
    seeds.write("diagnostic_fuzz", "statement", signed_call.encoded);
}

/// Instances created by a call (v0.7): outputs with children (accepted and
/// malformed), inputs of calls on children (instance view key 6), and the
/// contract evidence of children, ancestors and their consents included,
/// from protocol-v0.7.json (both hashes).
void child_seeds(const Seeds& seeds) {
    std::ifstream in(KANHE_TESTVECTORS_DIR "/protocol-v0.7.json");
    if (!in) {
        throw std::runtime_error("cannot read protocol-v0.7.json");
    }
    const auto doc = nlohmann::json::parse(in);
    const crypto::openssl::Provider provider;
    std::size_t n = 0;
    std::size_t e = 0;
    for (const auto& ledger : doc.at("ledgers")) {
        for (const auto& run : ledger.at("runs")) {
            const auto output = must(from_hex(run.at("output").get<std::string>()), "output");
            const auto input = must(from_hex(run.at("input").get<std::string>()), "input");
            seeds.write("contract_parse_fuzz", std::format("child-output-{:02}", n),
                        ByteView(output));
            seeds.write("bo_runtime_fuzz", std::format("child-input-{:02}", n++), ByteView(input));
        }
        for (const auto& [what, evidence] : ledger.at("evidence").items()) {
            const auto encoded =
                must(from_hex(evidence.at("contract_evidence").get<std::string>()), "evidence");
            must(protocol::verify_contract_evidence(provider, encoded),
                 "the vectors' child evidence must verify");
            seeds.write("contract_parse_fuzz", std::format("child-evidence-{:02}", e++),
                        ByteView(encoded));
        }
    }
}

/// Requests and answers (v0.8): outputs that make requests (accepted and
/// malformed), answers' inputs (key 9), statements with answers and with
/// scope keys 8 and 9 (well formed and malformed), and the contract evidence
/// of instances with requests, from protocol-v0.8.json (both hashes).
void request_seeds(const Seeds& seeds) {
    std::ifstream in(KANHE_TESTVECTORS_DIR "/protocol-v0.8.json");
    if (!in) {
        throw std::runtime_error("cannot read protocol-v0.8.json");
    }
    const auto doc = nlohmann::json::parse(in);
    const crypto::openssl::Provider provider;
    std::size_t n = 0;
    std::size_t s = 0;
    std::size_t e = 0;
    for (const auto& ledger : doc.at("ledgers")) {
        for (const auto& run : ledger.at("runs")) {
            const auto output = must(from_hex(run.at("output").get<std::string>()), "output");
            const auto input = must(from_hex(run.at("input").get<std::string>()), "input");
            seeds.write("contract_parse_fuzz", std::format("request-output-{:03}", n),
                        ByteView(output));
            seeds.write("bo_runtime_fuzz", std::format("request-input-{:03}", n++),
                        ByteView(input));
        }
        // Statements that answer or carry scope keys 8 and 9, as payloads
        // and signed; the refused ones too, malformed or not.
        for (const char* list : {"statements", "refused"}) {
            for (const auto& st : ledger.at(list)) {
                const auto payload = must(from_hex(st.at("payload").get<std::string>()), "payload");
                const auto value = must(cbor::decode(payload), "payload CBOR");
                const cbor::Value* type = value.find(1);
                const cbor::Value* body = value.find(7);
                const bool answer = type != nullptr && type->as_uint64() == 22U &&
                                    body != nullptr && body->find(8) != nullptr;
                const cbor::Value* scope =
                    type != nullptr && type->as_uint64() == 5U && body != nullptr ? body->find(2)
                                                                                  : nullptr;
                const bool scoped =
                    scope != nullptr && (scope->find(8) != nullptr || scope->find(9) != nullptr);
                if (!answer && !scoped) {
                    continue;
                }
                const auto encoded =
                    must(from_hex(st.at("encoded").get<std::string>()), "statement");
                seeds.write("protocol_parse_fuzz", std::format("request-payload-{:03}", s),
                            ByteView(payload));
                seeds.write("protocol_parse_fuzz", std::format("request-statement-{:03}", s++),
                            ByteView(encoded));
            }
        }
        for (const auto& [what, evidence] : ledger.at("evidence").items()) {
            const auto encoded =
                must(from_hex(evidence.at("contract_evidence").get<std::string>()), "evidence");
            must(protocol::verify_contract_evidence(provider, encoded),
                 "the vectors' request evidence must verify");
            seeds.write("contract_parse_fuzz", std::format("request-evidence-{:02}", e++),
                        ByteView(encoded));
        }
    }
}

/// The generic core (v0.9) and versions (v0.10): every statement of
/// protocol-v0.9.json and protocol-v0.10.json, as a payload and signed, the
/// refused ones too: type-20 bodies, a scope naming type 20, and a short id
/// in key 6 (which must not parse), registrations under the reserved prefix
/// and versions the rules refuse (which parse; the ledger refuses them).
void generic_seeds(const Seeds& seeds) {
    std::size_t s = 0;
    for (const char* file : {"/protocol-v0.9.json", "/protocol-v0.10.json"}) {
        std::ifstream in(std::string(KANHE_TESTVECTORS_DIR) + file);
        if (!in) {
            throw std::runtime_error(std::string("cannot read ") + (file + 1));
        }
        const auto doc = nlohmann::json::parse(in);
        for (const auto& ledger : doc.at("ledgers")) {
            for (const char* list : {"statements", "refused"}) {
                for (const auto& st : ledger.at(list)) {
                    const auto payload =
                        must(from_hex(st.at("payload").get<std::string>()), "payload");
                    const auto encoded =
                        must(from_hex(st.at("encoded").get<std::string>()), "statement");
                    seeds.write("protocol_parse_fuzz", std::format("generic-payload-{:03}", s),
                                ByteView(payload));
                    seeds.write("protocol_parse_fuzz", std::format("generic-statement-{:03}", s++),
                                ByteView(encoded));
                }
            }
        }
    }
}

/// The official language packs, as written and as CBOR (a source bundle
/// embeds packs as CBOR); Bo sources, for the lexer, the parser, and the
/// checker: the goldens, the spec's examples among them, in each language.
void bo_seeds(const Seeds& seeds) {
#if defined(KANHE_HAVE_BO_FRONT)
    for (const bo::PackText& text : bo::official_pack_texts()) {
        seeds.write("bo_pack_fuzz", std::string(text.id) + ".pack", text.text);
    }
    for (const bo::Pack& pack : bo::official_packs()) {
        seeds.write("bo_pack_fuzz", pack.id + ".cbor", pack.canonical);
    }
    std::vector<std::filesystem::path> cases;
    for (const auto& entry : std::filesystem::directory_iterator(KANHE_BO_GOLDEN_DIR)) {
        if (std::filesystem::exists(entry.path() / "source.bo")) {
            cases.push_back(entry.path());
        }
    }
    std::ranges::sort(cases);
    for (const auto& path : cases) {
        std::ifstream in(path / "source.bo", std::ios::binary);
        std::stringstream text;
        text << in.rdbuf();
        seeds.write("bo_lex_fuzz", path.filename().string() + ".bo", text.str());
        seeds.write("bo_parse_fuzz", path.filename().string() + ".bo", text.str());
        seeds.write("bo_check_fuzz", path.filename().string() + ".bo", text.str());
    }
    // The formatter's cases (bo_parse_fuzz formats every source it reads):
    // layout, words with arguments on either side, numbers and dates.
    for (const auto& entry : std::filesystem::directory_iterator(
             std::filesystem::path(KANHE_BO_GOLDEN_DIR) / "format")) {
        std::ifstream in(entry.path() / "source.bo", std::ios::binary);
        std::stringstream text;
        text << in.rdbuf();
        seeds.write("bo_parse_fuzz", "format-" + entry.path().filename().string() + ".bo",
                    text.str());
    }
    // The compiled agreement in four spellings, whose model explains with
    // requirements, choices, and a refusal (bo_check_fuzz writes the text).
    for (const auto& entry : std::filesystem::directory_iterator(
             std::filesystem::path(KANHE_BO_GOLDEN_DIR) / "build")) {
        std::ifstream in(entry.path() / "source.bo", std::ios::binary);
        std::stringstream text;
        text << in.rdbuf();
        seeds.write("bo_check_fuzz", "build-" + entry.path().filename().string() + ".bo",
                    text.str());
    }
    // Test blocks (bo test): the tests' own cases, the agreement's and the
    // demo's tests among the sources above.
    for (const auto& entry :
         std::filesystem::directory_iterator(std::filesystem::path(KANHE_BO_GOLDEN_DIR) / "test")) {
        if (!std::filesystem::exists(entry.path() / "source.bo")) {
            continue;
        }
        std::ifstream in(entry.path() / "source.bo", std::ios::binary);
        std::stringstream text;
        text << in.rdbuf();
        seeds.write("bo_parse_fuzz", "test-" + entry.path().filename().string() + ".bo",
                    text.str());
        seeds.write("bo_check_fuzz", "test-" + entry.path().filename().string() + ".bo",
                    text.str());
    }

    // The examples' contracts (examples/): a supply agreement, and a
    // receivable split down a supply chain, with their tests.
    for (const std::string_view demo : {"supply-agreement", "multi-tier-split"}) {
        std::ifstream in(
            std::filesystem::path(KANHE_BO_GOLDEN_DIR).parent_path().parent_path().parent_path() /
                "examples" / demo / (std::string(demo) + ".bo"),
            std::ios::binary);
        std::stringstream text;
        text << in.rdbuf();
        seeds.write("bo_parse_fuzz", "demo-" + std::string(demo) + ".bo", text.str());
        seeds.write("bo_check_fuzz", "demo-" + std::string(demo) + ".bo", text.str());
    }

    // The standard library (one file for the core and one for
    // each vocabulary pack with terms), and a contract that declares
    // all its actions: built-in actions with their terms.
    for (const bo::StandardFile& file : bo::standard_library().files) {
        const std::string name = "stdlib-" + std::string(bo::vocab_name(file.pack)) + ".bo";
        seeds.write("bo_parse_fuzz", name, file.source);
        seeds.write("bo_check_fuzz", name, file.source);
    }
    seeds.write("bo_check_fuzz", "stdlib-showcase.bo", bo::standard_showcase());

    // Deploys' source bundles: each golden source (the compiled agreement in
    // four spellings among them) with the official packs, under SHA-256 and
    // SM3; one with a company's pack embedded; a .boc of the agreement (its
    // code from bo-v1.json); compiler strings.
    const crypto::openssl::Provider provider;
    const bo::PackSetRead official = bo::make_pack_set({});
    if (!official.set) {
        throw std::runtime_error("the official packs");
    }
    for (const auto& entry : std::filesystem::directory_iterator(
             std::filesystem::path(KANHE_BO_GOLDEN_DIR) / "build")) {
        cases.push_back(entry.path());
    }
    std::ranges::sort(cases);
    Bytes agreement_bundle;
    for (const auto& path : cases) {
        std::ifstream in(path / "source.bo", std::ios::binary);
        std::stringstream text;
        text << in.rdbuf();
        for (const crypto::HashAlg hash : {crypto::HashAlg::sha256, crypto::HashAlg::sm3}) {
            // Sources that are not UTF-8 make no bundle.
            const auto bundle =
                bo::make_source_bundle(text.str(), 1, *official.set, provider, hash);
            if (!bundle) {
                continue;
            }
            const Bytes bytes = must(bo::encode_source_bundle(*bundle), "bundle");
            seeds.write("bo_source_fuzz",
                        std::format("{}-{}", path.filename().string(), crypto::name(hash)),
                        ByteView(bytes));
            if (path.filename() == "agreement-en" && hash == crypto::HashAlg::sha256) {
                agreement_bundle = bytes;
            }
        }
    }
    std::string keywords;
    for (const auto& [id, word] : bo::english_pack().keywords) {
        keywords += (keywords.empty() ? "" : ", ") +
                    std::format("\"{}\": \"{}\"", id, word.spellings.front());
    }
    const bo::PackRead company =
        bo::read_pack(R"({"format": 1, "id": "acme-terms", "version": 3, "language": "en-x-acme", )"
                      R"("name": "Acme terms", "official": false, "edition": 1, )"
                      R"("reading": {"separation": "spaces"}, "keywords": {)" +
                      keywords + R"(}, "vocabulary": {"role.supplier": "vendor"}})");
    if (!company.pack) {
        throw std::runtime_error("the company pack");
    }
    const bo::PackSetRead with_company = bo::make_pack_set({*company.pack});
    if (!with_company.set) {
        throw std::runtime_error("the company pack with the official ones");
    }
    const auto embedded =
        must(bo::make_source_bundle("contract Supply\nparties we, vendor\nthing Order\n  amount "
                                    "HKD\ncan countersign by vendor\n  proposed -> signed\n",
                                    1, *with_company.set, provider, crypto::HashAlg::sha256),
             "bundle");
    seeds.write("bo_source_fuzz", "embedded-pack",
                ByteView(must(bo::encode_source_bundle(embedded), "bundle")));

    // Vocabulary packs: the official files, current and carried, as
    // written and as CBOR; users' packs (the example's, the goldens'); and a
    // bundle that embeds one (key 7).
    for (const bo::VocabularyText& text : bo::official_vocabulary_texts()) {
        seeds.write("bo_vocab_fuzz", std::format("{}-{}.vocab", text.id, text.version), text.text);
        const bo::VocabularyPack* pack = bo::find_vocabulary_pack(text.id, text.version);
        seeds.write("bo_vocab_fuzz", std::format("{}-{}.cbor", text.id, text.version),
                    pack->canonical);
    }
    const std::filesystem::path events =
        std::filesystem::path(KANHE_BO_GOLDEN_DIR) / ".." / ".." / ".." / "examples" / "events";
    std::vector<bo::VocabularyHandle> users;
    for (const std::filesystem::path& file :
         {events / "events.vocab",
          std::filesystem::path(KANHE_BO_GOLDEN_DIR) / "check-vocab" / "alpha.vocab",
          std::filesystem::path(KANHE_BO_GOLDEN_DIR) / "check-vocab" / "beta.vocab"}) {
        std::ifstream in(file, std::ios::binary);
        std::stringstream text;
        text << in.rdbuf();
        seeds.write("bo_vocab_fuzz", file.filename().string(), text.str());
        const bo::VocabularyRead read = bo::read_vocabulary_pack(text.str());
        if (read.pack == nullptr) {
            throw std::runtime_error("the vocabulary pack " + file.string());
        }
        seeds.write("bo_vocab_fuzz", file.stem().string() + ".cbor", read.pack->canonical);
        if (file.filename() == "events.vocab") {
            users.push_back(read.pack);
        }
    }
    // A user's pack with an attaching rule of its own (預留座位: reserve +
    // seat), which the lexer reads with the pack's words.
    seeds.write("bo_vocab_fuzz", "attach.vocab",
                R"({"format": 1, "id": "seats", "version": 1, "edition": 1,
 "concepts": {"act.reserve": {"category": "action"},
              "field.seat": {"category": "field", "type": "text"}},
 "languages": {"en": {"name": "seats", "words": {"act.reserve": "reserve", "field.seat": "seat"}},
               "zh-Hant-HK": {"name": "訂座", "words": {"act.reserve": "預留", "field.seat": "座位"},
                              "attach": [{"word": "act.reserve", "before": ["field"]}]}}})");
    const bo::PackSetRead with_events = bo::make_pack_set({}, bo::Officials::current, users);
    if (!with_events.set) {
        throw std::runtime_error("the events pack with the official ones");
    }
    std::ifstream tickets(events / "tickets.bo", std::ios::binary);
    std::stringstream tickets_text;
    tickets_text << tickets.rdbuf();
    const auto with_vocabulary =
        must(bo::make_source_bundle(tickets_text.str(), 1, *with_events.set, provider,
                                    crypto::HashAlg::sha256),
             "bundle");
    seeds.write("bo_source_fuzz", "embedded-vocabulary",
                ByteView(must(bo::encode_source_bundle(with_vocabulary), "bundle")));

    std::ifstream vectors(KANHE_TESTVECTORS_DIR "/bo-v1.json");
    if (!vectors) {
        throw std::runtime_error("cannot read bo-v1.json");
    }
    const auto doc = nlohmann::json::parse(vectors);
    bo::BuiltContract built;
    built.code = must(from_hex(doc.at("contracts").at(0).at("code").get<std::string>()), "code");
    built.interface = {{"amend", protocol::FunctionKind::call},
                       {"close", protocol::FunctionKind::call},
                       {"countersign", protocol::FunctionKind::call},
                       {"create", protocol::FunctionKind::create},
                       {"sign", protocol::FunctionKind::call}};
    built.compiler = "kanhe-bo 0.0.1; codegen 1; edition 1";
    built.source = agreement_bundle;
    built.name = "Agreement";
    seeds.write("bo_source_fuzz", "agreement.boc", ByteView(must(bo::encode_built(built), "boc")));
    seeds.write("bo_source_fuzz", "compiler", built.compiler);
    // Bundles deployed with earlier releases of the official packs (version
    // 1, before vocabulary packs, with no key 6; version 2, before
    // temperatures and field defaults), which open with the packs carried
    // for them.
    for (const auto& contract : doc.at("contracts")) {
        std::size_t n = 0;
        for (const auto& earlier : contract.value("earlier", nlohmann::json::array())) {
            const Bytes bundle = must(from_hex(earlier.at("bundle").get<std::string>()), "bundle");
            seeds.write("bo_source_fuzz",
                        std::format("earlier-{}-{}", contract.at("name").get<std::string>(), ++n),
                        ByteView(bundle));
        }
    }
#else
    static_cast<void>(seeds);
#endif
}

/// Open-network witnesses' verifier keys and answers, from the v0.13
/// vectors (network_parse_fuzz).
void network_seeds(const Seeds& seeds) {
    std::ifstream in(KANHE_TESTVECTORS_DIR "/protocol-v0.13.json");
    if (!in) {
        throw std::runtime_error("cannot read protocol-v0.13.json");
    }
    const auto doc = nlohmann::json::parse(in);
    std::string answer;
    std::size_t n = 0;
    for (const auto& c : doc.at("cases")) {
        seeds.write("network_parse_fuzz", std::format("vkey-{}", n++),
                    as_bytes(c.at("vkey").get<std::string>()));
        answer += protocol::network::signature_line(
            {c.at("cosigner").get<std::string>(),
             must(from_hex(c.at("bytes").get<std::string>()), "bytes")});
    }
    seeds.write("network_parse_fuzz", "note-vkey",
                as_bytes(doc.at("note_vkey").get<std::string>()));
    seeds.write("network_parse_fuzz", "answer", as_bytes(answer));
    seeds.write("network_parse_fuzz", "size", as_bytes(std::string_view("15\n")));
    seeds.write("network_parse_fuzz", "base64",
                as_bytes(doc.at("c2sp_example").at("signature").get<std::string>()));
}

/// What a time-stamp authority answers, and the certificates a verifier
/// trusts (timestamp_fuzz: the first byte chooses the reader).
/// A claim's metadata (spec v0.14): every operator once.
void claim_seeds(const Seeds& seeds) {
    using V = cbor::Value;
    const auto term = [](std::string field, std::string op, std::string type, V value) {
        return V::array({V::text(std::move(field)), V::text(std::move(op)),
                         V::text(std::move(type)), std::move(value)});
    };
    const auto money = [](std::int64_t amount) {
        return V::array({V::integer(amount), V::text("HKD"), V::unsigned_integer(2)});
    };
    const V claim =
        V::map({{V::text("source"), V::bytes(Bytes(32, 5))},
                {V::text("condition"),
                 V::array({term("salary", ">", "money", money(3000000)),
                           term("age", ">=", "number", V::integer(18)),
                           term("score", "<", "number", V::text("9.5")),
                           term("born", "<=", "date", V::text("2008-11-10")),
                           term("name", "=", "text", V::text("Chan Tai Man")),
                           term("team", "!=", "text", V::text("B")),
                           term("pay", "between", "money", V::array({money(1), money(2)})),
                           term("grade", "in", "text", V::array({V::text("A"), V::text("B")})),
                           term("email", "exists", "text", V::null())})},
                {V::text("holds"), V::boolean(true)},
                {V::text("as_of"), V::unsigned_integer(1'791'244'800'000)},
                {V::text("until"), V::unsigned_integer(1'793'836'800'000)},
                {V::text("subject"), V::text("Chan Tai Man")}});
    seeds.write("claim_fuzz", "every-operator", must(cbor::encode(claim), "encode"));
    // claim_check_fuzz: [condition, data]; the numbers below -2^63 once
    // crashed the check.
    const V below = V::negative(std::uint64_t{1} << 63);
    const V check = V::array(
        {*claim.find(V::text("condition")), V::map({{V::text("salary"), V::text("HKD 32,000.50")},
                                                    {V::text("age"), V::integer(21)},
                                                    {V::text("score"), V::text("9")},
                                                    {V::text("born"), V::text("2001-01-01")},
                                                    {V::text("name"), V::text("Chan Tai Man")},
                                                    {V::text("pay"), V::integer(150)},
                                                    {V::text("grade"), V::text("A")}})});
    seeds.write("claim_check_fuzz", "every-operator", must(cbor::encode(check), "encode"));
    const V low = V::array(
        {V::array({term("balance", ">", "number", below),
                   term("debt", "<", "money",
                        V::array({below, V::text("HKD"), V::unsigned_integer(2)}))}),
         V::map({{V::text("balance"), V::negative(std::numeric_limits<std::uint64_t>::max())},
                 {V::text("debt"), V::text("HKD 1.00")}})});
    seeds.write("claim_check_fuzz", "below-int64", must(cbor::encode(low), "encode"));
}

/// A membership's metadata (spec v0.16): every key, then only those needed.
void membership_seeds(const Seeds& seeds) {
    kanhe::protocol::Membership m;
    m.member = must(kanhe::protocol::to_id(Bytes(32, 5)), "id");
    m.name = "Kowloon Example School";
    m.verified = true;
    m.registration = "12345678";
    m.jurisdiction = "CN-44";
    m.until = 1'825'891'200'000;
    seeds.write(
        "membership_fuzz", "every-key",
        must(cbor::encode(must(kanhe::protocol::encode_membership(m), "encode")), "encode"));
    kanhe::protocol::Membership person;
    person.member = m.member;
    person.kind = kanhe::protocol::MemberKind::person;
    person.name = "Chan";
    seeds.write(
        "membership_fuzz", "self-declared",
        must(cbor::encode(must(kanhe::protocol::encode_membership(person), "encode")), "encode"));
}

/// A script's metadata (spec v0.18): every key; and a statement whose
/// provenance names a script, registering a record from two sources.
void script_seeds(const Seeds& seeds) {
    kanhe::protocol::Script s;
    s.name = "risk-model";
    s.version = "3.2";
    s.files = {{"model/weights.json", 48213, Bytes(32, 0x9a)}, {"run.py", 1204, Bytes(32, 0xac)}};
    s.deterministic = true;
    s.runtime = "python 3.12";
    seeds.write("script_fuzz", "every-key",
                must(cbor::encode(must(kanhe::protocol::encode_script(s), "encode")), "encode"));

    const auto id = [](std::uint8_t b) {
        return must(kanhe::protocol::to_id(Bytes(32, b)), "id");
    };
    kanhe::protocol::Statement st;
    st.ledger_id = id(1);
    st.actor_id = id(2);
    st.delegation_id = id(3);
    st.issued_at = 1'794'700'800'000;
    kanhe::protocol::RecordRegisterBody body{"example.org.report/1", Bytes(32, 0x42), 3, {},
                                             std::nullopt,           std::nullopt,    {}};
    body.sources = {{id(1), id(4)}, {id(5), id(6)}};
    st.body = std::move(body);
    st.provenance = kanhe::protocol::Provenance{};
    st.provenance->script = id(7);
    seeds.write("protocol_parse_fuzz", "payload-sources",
                must(kanhe::protocol::encode_payload(st), "encode"));
}

/// Approvals (spec v0.20): a ledger where a delegation needs one of two
/// people, one of whom approves in person with a hardware key, and the
/// evidence of a record registered with that approval. Rules, guardian
/// settings, the approval, its list, a submission, and the log entry go to
/// the approval target; the entry and the bundle to the parser's.
void approval_seeds(const Seeds& seeds) {
    const crypto::openssl::Provider provider;
    const auto hash = crypto::HashAlg::sha256;
    auto org = must(crypto::openssl::KeyPair::generate(crypto::SigAlg::ed25519), "key");
    auto log = must(crypto::openssl::KeyPair::generate(crypto::SigAlg::ed25519), "key");
    auto clerk = must(crypto::openssl::KeyPair::generate(crypto::SigAlg::ed25519), "key");
    auto chan = must(crypto::openssl::KeyPair::generate(crypto::SigAlg::ed25519), "key");
    auto lee = must(crypto::openssl::KeyPair::generate(crypto::SigAlg::ed25519), "key");
    auto token = must(crypto::openssl::KeyPair::generate(crypto::SigAlg::ed25519), "key");
    ledger::ManualClock clock(1'791'244'800'000);
    ledger::SeededEntropy entropy(3);
    ledger::MemoryFileSystem fs;

    protocol::Statement genesis;
    genesis.issued_at = clock.now();
    genesis.nonce = entropy.bytes<16>();
    genesis.body = protocol::GenesisBody{hash, "Seed Org", org.public_key(), log.public_key()};
    const auto signed_genesis =
        must(protocol::sign_statement(org, provider, hash, genesis), "sign");
    auto ledger =
        must(ledger::Ledger::create(fs, clock, provider, signed_genesis.encoded), "create");
    auto statement = [&](const protocol::Id& actor, std::optional<protocol::Id> delegation,
                         protocol::Body body) {
        protocol::Statement st;
        st.ledger_id = ledger.id();
        st.actor_id = actor;
        st.delegation_id = std::move(delegation);
        st.issued_at = clock.now();
        st.nonce = entropy.bytes<16>();
        st.body = std::move(body);
        return st;
    };
    auto submit = [&](const crypto::Signer& signer, const protocol::Statement& st,
                      std::span<const Bytes> approvals = {}) {
        const auto signed_statement =
            must(protocol::sign_statement(signer, provider, hash, st), "sign");
        const auto id =
            must(ledger.submit(signed_statement.encoded, approvals), "submit").statement_id;
        clock.advance(1000);
        return id;
    };
    auto person = [&](const crypto::openssl::KeyPair& key, const char* name) {
        return submit(org, statement(ledger.id(), std::nullopt,
                                     protocol::ActorRegisterBody{protocol::ActorKind::person, name,
                                                                 key.public_key(), std::nullopt,
                                                                 std::nullopt}));
    };
    const protocol::Id chan_id = person(chan, "Chan Tai Man");
    const protocol::Id lee_id = person(lee, "Lee Ka Yan");
    const protocol::Id clerk_id = person(clerk, "Wong Siu Ming");
    const Bytes credential_id(32, 0x5a);
    submit(org, statement(ledger.id(), std::nullopt,
                          protocol::ActorSetPresenceBody{
                              chan_id,
                              {protocol::PresenceCredential{
                                  "", credential_id, token.public_key(), std::string("token"),
                                  protocol::PresenceMethod::hardware_key}}}));

    protocol::ApprovalRule rule;
    rule.needed = 1;
    rule.approvers = {chan_id, lee_id};
    std::ranges::sort(rule.approvers, [](const protocol::Id& a, const protocol::Id& b) {
        return std::ranges::lexicographical_compare(a.bytes(), b.bytes());
    });
    rule.within = 7 * 86'400'000ULL;
    seeds.write("approval_fuzz", "rule", must(protocol::encode_approval_rule(rule), "encode"));
    protocol::ApprovalRule open = rule;
    open.without_presence = true;
    seeds.write("approval_fuzz", "rule-without-presence",
                must(protocol::encode_approval_rule(open), "encode"));

    protocol::Scope scope;
    scope.statement_types = {protocol::StatementType::record_register};
    scope.approvals = rule;
    const protocol::Id grant = submit(
        org, statement(ledger.id(), std::nullopt, protocol::DelegationGrantBody{clerk_id, scope}));

    // The clerk's record, approved by Chan in person.
    const auto record =
        statement(clerk_id, grant,
                  protocol::RecordRegisterBody{
                      "example.org.po/1", Bytes(32, 0x42), 3, {}, std::nullopt, std::nullopt, {}});
    const auto signed_record =
        must(protocol::sign_statement(clerk, provider, hash, record), "sign");
    protocol::Approval approval{ledger.id(), chan_id, signed_record.id, clock.now(), std::nullopt};
    const auto chan_kid = must(protocol::key_id(provider, hash, chan.public_key()), "kid");
    const Bytes challenge =
        must(protocol::approval_challenge(provider, hash, approval, chan_kid), "challenge");
    approval.presence =
        protocol::PresenceProof{credential_id, {}, {}, must(token.sign(challenge), "sign")};
    const auto signed_approval =
        must(protocol::sign_approval(chan, provider, hash, approval), "sign");
    seeds.write("approval_fuzz", "approval", signed_approval.encoded);
    seeds.write("approval_fuzz", "approval-payload",
                must(protocol::encode_approval_payload(approval), "encode"));
    const std::vector<Bytes> approvals{signed_approval.encoded};
    seeds.write("approval_fuzz", "list",
                must(cbor::encode(protocol::approval_list_value(approvals)), "encode"));
    seeds.write("approval_fuzz", "submission",
                must(cbor::encode(cbor::Value::map(
                         {{cbor::Value::integer(1), cbor::Value::bytes(signed_record.encoded)},
                          {cbor::Value::integer(5), protocol::approval_list_value(approvals)}})),
                     "encode"));
    // Its approval file, with the approval, a note, and a registration's
    // fields (a record of its own, whose root they give) and parts.
    protocol::ApprovalFile file;
    file.statement = signed_record;
    file.approvals = {signed_approval};
    file.note = "for the seed";
    seeds.write("approval_fuzz", "approval-file",
                must(protocol::encode_approval_file(file), "encode"));
    std::vector<protocol::RecordField> fields{
        {"amount", entropy.bytes<16>(), cbor::Value::text("1200")},
        {"payee", entropy.bytes<16>(), cbor::Value::text("Lee Ka Yan")}};
    const auto commitment = must(protocol::commit_fields(provider, hash, fields), "commit");
    const auto shown = must(
        protocol::sign_statement(
            clerk, provider, hash,
            statement(clerk_id, grant,
                      protocol::RecordRegisterBody{
                          "example.org.form/1",
                          Bytes(commitment.root.bytes().begin(), commitment.root.bytes().end()),
                          commitment.leaves.size(),
                          {{"scan.pdf", "application/pdf", 3, Bytes(32, 0x24)}},
                          std::nullopt,
                          std::nullopt,
                          {}})),
        "sign");
    protocol::ApprovalFile with_fields;
    with_fields.statement = shown;
    with_fields.fields = commitment.fields;
    with_fields.parts = protocol::SubmissionParts{Bytes(40, 0x11), {}, {{0, Bytes(19, 0x22)}}};
    seeds.write("approval_fuzz", "approval-file-fields",
                must(protocol::encode_approval_file(with_fields), "encode"));
    seeds.write("approval_fuzz", "submission-parts",
                must(protocol::encode_submission_parts(*with_fields.parts), "encode"));
    // A hold request (POST /v1/approvals), and the held file it becomes with
    // Chan's approval kept, written by hand: the node is not linked here.
    seeds.write("held_fuzz", "hold-request",
                must(cbor::encode(cbor::Value::map(
                         {{cbor::Value::integer(1), cbor::Value::bytes(signed_record.encoded)},
                          {cbor::Value::integer(4), cbor::Value::text("for the seed")}})),
                     "encode"));
    seeds.write("held_fuzz", "held",
                must(cbor::encode(cbor::Value::map(
                         {{cbor::Value::integer(1), cbor::Value::bytes(signed_record.encoded)},
                          {cbor::Value::integer(5),
                           cbor::Value::array({cbor::Value::array(
                               {cbor::Value::bytes(signed_approval.encoded),
                                cbor::Value::unsigned_integer(2), cbor::Value::boolean(true)})})},
                          {cbor::Value::integer(6), cbor::Value::text("staff")},
                          {cbor::Value::integer(7), cbor::Value::unsigned_integer(clock.now())},
                          {cbor::Value::integer(8),
                           cbor::Value::unsigned_integer(clock.now() + 7 * 86'400'000ULL)},
                          {cbor::Value::integer(9), cbor::Value::boolean(false)}})),
                     "encode"));
    seeds.write("held_fuzz", "changes",
                must(cbor::encode(cbor::Value::array({cbor::Value::array(
                         {cbor::Value::text("held/" + to_hex(signed_record.id.bytes()) + ".cbor"),
                          cbor::Value::null()})})),
                     "encode"));
    const auto registered = must(ledger.submit(signed_record.encoded, approvals), "submit");
    clock.advance(1000);
    const Bytes entry = must(ledger.entry(registered.index), "entry");
    seeds.write("approval_fuzz", "log-entry", entry);
    seeds.write("protocol_parse_fuzz", "log-entry-approvals", entry);

    // Guardian settings: the two people guarding everything, or a list of
    // types; and their removal.
    const protocol::LedgerSetGuardiansBody guardians{rule, std::nullopt};
    const auto setting = statement(ledger.id(), std::nullopt, guardians);
    seeds.write("approval_fuzz", "guardian-setting",
                must(protocol::encode_payload(setting), "encode"));
    protocol::LedgerSetGuardiansBody listed{
        rule, std::vector<protocol::StatementType>{protocol::StatementType::actor_register,
                                                   protocol::StatementType::record_register}};
    seeds.write(
        "approval_fuzz", "guardian-setting-listed",
        must(protocol::encode_payload(statement(ledger.id(), std::nullopt, listed)), "encode"));
    seeds.write("approval_fuzz", "guardian-removal",
                must(protocol::encode_payload(
                         statement(ledger.id(), std::nullopt,
                                   protocol::LedgerSetGuardiansBody{std::nullopt, std::nullopt})),
                     "encode"));

    must(ledger.checkpoint(log), "checkpoint");
    const auto bundle = must(ledger.export_evidence(log, registered.statement_id), "export");
    seeds.write("protocol_parse_fuzz", "bundle-approvals",
                must(protocol::encode_bundle(bundle), "encode"));
}

/// A published record's file: one disclosed field, then none and untimed
/// (a request to publish).
void published_seeds(const Seeds& seeds) {
    const auto record = cbor::Value::bytes(Bytes(32, 5));
    const auto disclosure = cbor::Value::array(
        {cbor::Value::bytes(Bytes(40, 7)), cbor::Value::unsigned_integer(2),
         cbor::Value::array({cbor::Value::bytes(Bytes(32, 1)), cbor::Value::bytes(Bytes(32, 2))})});
    seeds.write(
        "published_fuzz", "file",
        must(cbor::encode(cbor::Value::map(
                 {{cbor::Value::integer(1), record},
                  {cbor::Value::integer(2), cbor::Value::array({disclosure})},
                  {cbor::Value::integer(3), cbor::Value::unsigned_integer(1'791'244'800'000)}})),
             "encode"));
    seeds.write(
        "published_fuzz", "request",
        must(cbor::encode(cbor::Value::map({{cbor::Value::integer(1), record},
                                            {cbor::Value::integer(2), cbor::Value::array({})}})),
             "encode"));
}

/// A credential, signed; a status list; a base URL; a role; GZIP of ours and
/// of another encoder (Python's, one dynamic block).
void credential_seeds(const Seeds& seeds) {
    const crypto::openssl::Provider provider;
    const auto key = must(crypto::openssl::KeyPair::generate(crypto::SigAlg::esp256), "key");
    const auto base = *kanhe::verifier::parse_base_url("https://ledger.example.com");
    kanhe::verifier::CredentialContent c;
    c.base = base;
    c.organization = "Example College";
    c.name = "Diploma";
    c.registered_at = 1'791'244'800'000;
    c.subject = {{"name", "Chan Siu Ming"}, {"year", 2026}};
    c.entry = {.list = 1, .index = 94'567};
    c.token = "AAAAAAAAAAAAAAAAAAAAAA";
    c.ledger = *kanhe::protocol::to_id(Bytes(32, 1));
    c.record = *kanhe::protocol::to_id(Bytes(32, 2));
    const auto credential = must(kanhe::verifier::sign_credential(
                                     key, provider, base.did, kanhe::verifier::credential_json(c)),
                                 "sign");
    seeds.write("credential_fuzz", "credential", as_bytes(credential));
    Bytes bits(kanhe::verifier::status_list_bytes, 0);
    kanhe::verifier::set_status_bit(bits, 94'567);
    seeds.write("credential_fuzz", "status-list",
                as_bytes(kanhe::verifier::encode_status_list(bits)));
    seeds.write("credential_fuzz", "base-url",
                as_bytes(std::string_view("https://example.com:8443/kanhe")));
    seeds.write("credential_fuzz", "role", as_bytes(std::string_view("credential/1/94567")));
    seeds.write("gzip_fuzz", "status-list", ByteView(kanhe::verifier::gzip_compress(bits)));
    seeds.write("gzip_fuzz", "python",
                ByteView(must(kanhe::from_hex(
                                  "1f8b08000000000002ffedced109c3300c45d155b49ab15f1d11552e92edac1f"
                                  "434ad2150afabc0f818ea05418b1fb4021b96ac2f8c5ab0db959793a1b0ab473"
                                  "12ca4d0415bf53e18fb477a283bbc2fd6e4c5e2719a4c39cb53e43de122b794f"
                                  "7df8370cb3edebd59e74c35d12cc60063398c10c66308319cc6006f3af982781"
                                  "0c05166b0c0000"),
                              "hex")));
}

void timestamp_seeds(const Seeds& seeds) {
    const test::TimestampAuthority authority;
    const std::array<std::uint8_t, 32> imprint{};
    const std::uint64_t at = 1'791'244'800'000;
    auto choosing = [](std::uint8_t reader, ByteView bytes) {
        Bytes out{reader};
        out.insert(out.end(), bytes.begin(), bytes.end());
        return out;
    };
    const Bytes request =
        must(crypto::openssl::timestamp_request(crypto::HashAlg::sha256, imprint, 1), "request");
    seeds.write("timestamp_fuzz", "token",
                ByteView(choosing(0, authority.token(crypto::HashAlg::sha256, imprint, at))));
    seeds.write("timestamp_fuzz", "response",
                ByteView(choosing(1, authority.respond(request, at))));
    seeds.write("timestamp_fuzz", "certificate",
                ByteView(choosing(2, as_bytes(authority.root_pem()))));
}

/// A credential issued on a ledger and what checking it takes, as
/// credential_verify_fuzz reads them ("CREDENTIAL\nDID DOCUMENT\nSTATUS
/// LIST\n" and the evidence): a college's credential key (a device with an
/// ES256 key, delegated endorsements only) endorses a diploma as status
/// entry 1/94567; the diploma's evidence as of a checkpoint, two of its
/// three fields disclosed; the college's DID document and status list. With
/// both, either, and neither. And the key as a JWK, the evidence as CBOR.
void credential_evidence_seeds(const Seeds& seeds) {
    namespace verifier = kanhe::verifier;
    const auto hash = crypto::HashAlg::sha256;
    Org college("Example College", 41);
    const auto device = must(crypto::openssl::KeyPair::generate(crypto::SigAlg::esp256), "key");
    const protocol::Id device_id =
        college
            .submit(protocol::ActorRegisterBody{protocol::ActorKind::device, "Credentials",
                                                device.public_key(), std::nullopt, std::nullopt})
            .id;
    protocol::Scope scope;
    scope.statement_types = {protocol::StatementType::record_endorse};
    const protocol::Id delegation =
        college.submit(protocol::DelegationGrantBody{device_id, scope}).id;
    const auto fields =
        must(protocol::commit_fields(
                 college.provider, hash,
                 {{"name", college.entropy.bytes<16>(), cbor::Value::text("Chan Siu Ming")},
                  {"programme", college.entropy.bytes<16>(), cbor::Value::text("Nursing")},
                  {"grades", college.entropy.bytes<16>(), cbor::Value::text("A, A, B")}}),
             "fields");
    const protocol::Id record =
        college
            .submit(protocol::RecordRegisterBody{
                "example.org.diploma/1",
                Bytes(fields.root.bytes().begin(), fields.root.bytes().end()),
                fields.leaves.size(),
                {},
                cbor::Value::map({{cbor::Value::text("note"), cbor::Value::bytes(Bytes{1})},
                                  {cbor::Value::text("year"), cbor::Value::integer(2026)}}),
                std::nullopt,
                {}})
            .id;

    const verifier::StatusEntry entry{.list = 1, .index = 94'567};
    protocol::Statement endorsement;
    endorsement.ledger_id = college.id();
    endorsement.actor_id = device_id;
    endorsement.delegation_id = delegation;
    endorsement.issued_at = college.clock.now();
    endorsement.nonce = college.entropy.bytes<16>();
    endorsement.body = protocol::RecordEndorseBody{record, verifier::credential_role(entry)};
    must(college.ledger->submit(
             must(protocol::sign_statement(device, college.provider, hash, endorsement), "sign")
                 .encoded),
         "submit");
    college.clock.advance(1000);

    must(college.ledger->checkpoint(college.log), "checkpoint");
    auto bundle = must(college.ledger->export_evidence(college.log, record), "export");
    for (const char* name : {"name", "programme"}) {
        bundle.disclosures.push_back(
            must(protocol::disclose_field(college.provider, hash, fields, name), "disclose"));
    }
    const Bytes evidence = must(protocol::encode_bundle(bundle), "encode");

    const auto base = *verifier::parse_base_url("https://ledger.example.com");
    const std::vector<std::string> metadata{"year"};
    const auto content = verifier::credential_content(
        must(protocol::verify_bundle(college.provider, evidence), "verify"), base,
        "AAAAAAAAAAAAAAAAAAAAAA", entry, metadata, std::string("Diploma in Nursing"));
    if (!content) {
        throw std::runtime_error("credential: " + content.error());
    }
    const std::string credential =
        must(verifier::sign_credential(device, college.provider, base.did,
                                       verifier::credential_json(*content)),
             "sign");
    const std::string did_document =
        must(verifier::did_document(college.provider, base,
                                    std::vector<crypto::PublicKey>{device.public_key()},
                                    college.id()),
             "DID document")
            .dump();
    // Nothing revoked: the diploma is live.
    const Bytes bits(verifier::status_list_bytes, 0);
    const std::string status_list =
        must(verifier::sign_credential(
                 device, college.provider, base.did,
                 verifier::status_list_json(base, "Example College", 1, bits, college.clock.now())),
             "sign");

    auto write = [&](const std::string& name, const std::string& lines) {
        Bytes input(lines.begin(), lines.end());
        input.insert(input.end(), evidence.begin(), evidence.end());
        seeds.write("credential_verify_fuzz", name, ByteView(input));
    };
    write("verified", credential + "\n" + did_document + "\n" + status_list + "\n");
    write("did-document", credential + "\n" + did_document + "\n\n");
    write("status-list", credential + "\n\n" + status_list + "\n");
    write("evidence-only", credential + "\n\n\n");
    seeds.write("credential_fuzz", "jwk",
                as_bytes(must(verifier::jcs(must(verifier::public_jwk(device.public_key()), "jwk")),
                              "jcs")));
    seeds.write("cbor_decode_fuzz", "evidence", evidence);
}

/// Invitation codes as `peer invite` writes them (khp_ and the base64url of
/// their CBOR, client/peers.hpp): one with a URL, a token, and a witness key;
/// one that gives a relay instead of a URL.
void invitation_seeds(const Seeds& seeds) {
    const auto witness = must(crypto::openssl::KeyPair::generate(crypto::SigAlg::ed25519), "key");
    const cbor::Value ledger = cbor::Value::bytes(Bytes(32, 0x5a));
    const cbor::Value organization = cbor::Value::text("Example Supplier Ltd");
    const cbor::Value token = cbor::Value::text("kht_Q2hhbiBTaXUgTWluZyBzdXBwbGllcg");
    auto write = [&](const std::string& name, cbor::Map map) {
        const Bytes encoded = must(cbor::encode(cbor::Value::map(std::move(map))), "encode");
        seeds.write("invitation_fuzz", name, as_bytes("khp_" + to_base64url(encoded)));
        seeds.write("cbor_decode_fuzz", "invitation-" + name, encoded);
    };
    write("direct", {{cbor::Value::integer(1), cbor::Value::integer(1)},
                     {cbor::Value::integer(2), ledger},
                     {cbor::Value::integer(3), organization},
                     {cbor::Value::integer(4), cbor::Value::text("https://ledger.example.com")},
                     {cbor::Value::integer(5), token},
                     {cbor::Value::integer(6), protocol::encode_public_key(witness.public_key())}});
    write("relayed",
          {{cbor::Value::integer(1), cbor::Value::integer(1)},
           {cbor::Value::integer(2), ledger},
           {cbor::Value::integer(3), organization},
           {cbor::Value::integer(5), token},
           {cbor::Value::integer(7),
            cbor::Value::map(
                {{cbor::Value::integer(1), cbor::Value::text("https://relay.example.com")},
                 {cbor::Value::integer(2), cbor::Value::bytes(Bytes(32, 7))},
                 {cbor::Value::integer(3), protocol::encode_public_key(witness.public_key())}})}});
}

/// Searches and reports as the HTTP API's query parameters give them, a
/// NAME=VALUE a line, over the records of search_query_fuzz's index (a
/// student and a year in each one's metadata) and over instances: each
/// parses as one of the four kinds.
void search_query_seeds(const Seeds& seeds) {
    const std::array<std::pair<std::string_view, std::string_view>, 6> queries{{
        {"records", "type=example.form/1\nmeta.year.min=2025\nmeta.student=李明 1\nlimit=2\n"
                    "order=old"},
        {"records-text", "q=李明\nrevoked=any\ncurrent=1\nsince=2026-01-01\n"
                         "until=2026-12-31T23:59:59Z"},
        {"records-registrant",
         "registrant=0000000000000000000000000000000000000000000000000000000000000000\n"
         "revoked=no\nlimit=1000\norder=new"},
        {"record-report", "by=type,state,month\nutc_offset=+08:00\ntype=example.form/1"},
        {"instances", "status=active\nfinal=0\nfield.amount.min=100\n"
                      "changed_since=2026-11-01T00:00:00Z\nlimit=10"},
        {"instance-report", "by=contract,state,week\nsum=amount\nutc_offset=-05:00"},
    }};
    for (const auto& [name, query] : queries) {
        seeds.write("search_query_fuzz", std::string(name), as_bytes(query));
    }
}

/// Every proof of testvectors/merkle-sha256.json, as merkle_verify_fuzz
/// reads one: the index, the old size, and the new size (8 bytes each,
/// big-endian), the leaf's hash, the old and the new root, and the proof.
/// An inclusion proof takes the empty tree as the old one; a consistency
/// proof, the first leaf.
void merkle_seeds(const Seeds& seeds) {
    std::ifstream in(KANHE_TESTVECTORS_DIR "/merkle-sha256.json");
    if (!in) {
        throw std::runtime_error("cannot read merkle-sha256.json");
    }
    const auto doc = nlohmann::json::parse(in);
    const crypto::openssl::Provider provider;
    const auto& entries = doc.at("entries");
    const auto& roots = doc.at("roots");
    auto hex = [](const nlohmann::json& value) {
        return must(from_hex(value.get<std::string>()), "hex");
    };
    auto leaf = [&](std::uint64_t index) {
        const Bytes entry = hex(entries.at(static_cast<std::size_t>(index)));
        const auto digest =
            must(merkle::leaf_hash(provider, crypto::HashAlg::sha256, entry), "leaf");
        const ByteView bytes = digest.bytes();
        return Bytes(bytes.begin(), bytes.end());
    };
    auto input = [&](std::uint64_t index, std::uint64_t old_size, std::uint64_t new_size,
                     const Bytes& leaf_hash, const nlohmann::json& proof) {
        Bytes out;
        for (const std::uint64_t n : {index, old_size, new_size}) {
            for (unsigned i = 0; i < 8; ++i) {
                out.push_back(static_cast<std::uint8_t>(n >> (56U - 8U * i)));
            }
        }
        for (const Bytes& part : {leaf_hash, hex(roots.at(static_cast<std::size_t>(old_size))),
                                  hex(roots.at(static_cast<std::size_t>(new_size)))}) {
            out.insert(out.end(), part.begin(), part.end());
        }
        for (const auto& step : proof) {
            const Bytes digest = hex(step);
            out.insert(out.end(), digest.begin(), digest.end());
        }
        return out;
    };
    std::size_t n = 0;
    for (const auto& v : doc.at("inclusion")) {
        const auto index = v.at("index").get<std::uint64_t>();
        seeds.write(
            "merkle_verify_fuzz", std::format("inclusion-{:03}", n++),
            input(index, 0, v.at("tree_size").get<std::uint64_t>(), leaf(index), v.at("proof")));
    }
    n = 0;
    for (const auto& v : doc.at("consistency")) {
        seeds.write("merkle_verify_fuzz", std::format("consistency-{:03}", n++),
                    input(0, v.at("old_size").get<std::uint64_t>(),
                          v.at("new_size").get<std::uint64_t>(), leaf(0), v.at("proof")));
    }
}

int main(int argc, char** argv) {
    if (argc != 2) {
        std::println(stderr, "usage: make_seeds DIR");
        return 1;
    }
    try {
        const Seeds seeds(argv[1]);
        ledger_seeds(seeds);
        timestamp_seeds(seeds);
        network_seeds(seeds);
        webauthn_seed(seeds);
        cluster_seeds(seeds);
        pending_call_seeds(seeds);
        record_file_seeds(seeds);
        published_seeds(seeds);
        credential_seeds(seeds);
        credential_evidence_seeds(seeds);
        invitation_seeds(seeds);
        search_query_seeds(seeds);
        merkle_seeds(seeds);
        claim_seeds(seeds);
        membership_seeds(seeds);
        script_seeds(seeds);
        approval_seeds(seeds);
        form_seeds(seeds);
        calls_seeds(seeds);
        exchange_seeds(seeds);
        text_seeds(seeds);
        vm_seeds(seeds);
        contract_seeds(seeds);
        child_seeds(seeds);
        request_seeds(seeds);
        generic_seeds(seeds);
        bo_seeds(seeds);
    } catch (const std::exception& e) {
        std::println(stderr, "error: {}", e.what());
        return 1;
    }
    return 0;
}
