// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// Records as W3C Verifiable Credentials (spec/credentials.md): JCS, GZIP,
// base URLs and their did:web, status entries and lists, and a credential
// issued on a ledger and verified against its record's evidence, with every
// way it can lie.

#include <fstream>
#include <string>
#include <vector>

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>

#include <kanhe/core/protocol/evidence.hpp>
#include <kanhe/core/protocol/record.hpp>
#include <kanhe/node/credentials.hpp>
#include <kanhe/node/published.hpp>
#include <kanhe/verifier/credentials.hpp>
#include <kanhe/verifier/gzip.hpp>
#include <kanhe/verifier/jcs.hpp>

#include "support/ledger_world.hpp"

using namespace kanhe::test;
using kanhe::Bytes;
using kanhe::ByteView;
using verifier_json = kanhe::verifier::Json;
namespace verifier = kanhe::verifier;
namespace node = kanhe::node;

namespace {

using V = cbor::Value;

/// Python's gzip.compress of 3,179 bytes of words, at level 9: one dynamic
/// block (another encoder's output).
constexpr std::string_view python_gzip =
    "1f8b08000000000002ffedced109c3300c45d155b49ab15f1d11552e92edac1f434ad2150afabc0f818ea05418"
    "b1fb4021b96ac2f8c5ab0db959793a1b0ab47312ca4d0415bf53e18fb477a283bbc2fd6e4c5e2719a4c39cb53e"
    "43de122b794f7df8370cb3edebd59e74c35d12cc60063398c10c66308319cc6006f3af9827810c05166b0c0000";
constexpr std::string_view python_text_sha256 =
    "fb6279acbac87550e049ecc07760d0f08b8b814492f2b53a353ad86f376a52dc";

/// A college's ledger: a credential key (a device with an ES256 key whose
/// delegation allows endorsements only), and a diploma with three fields,
/// two of them published.
struct College {
    World w{crypto::HashAlg::sha256, "Example College"};
    KeyPair device = std::move(*KeyPair::generate(crypto::SigAlg::esp256));
    protocol::Id device_id;
    protocol::Id delegation;
    protocol::FieldCommitment fields;
    protocol::Id record;
    verifier::BaseUrl base = *verifier::parse_base_url("https://ledger.example.com");
    std::string token = "AAAAAAAAAAAAAAAAAAAAAA";

    College() {
        protocol::ActorRegisterBody body{protocol::ActorKind::device, "Credentials",
                                         device.public_key(), std::nullopt, std::nullopt};
        device_id = w.ok(w.org(), w.statement(w.org_id(), std::nullopt, body));
        delegation = w.grant(w.org(), w.org_id(), std::nullopt, device_id,
                             scope({StatementType::record_endorse}));
        fields = *protocol::commit_fields(provider(), w.hash(),
                                          {{"name", w.nonce(), V::text("Chan Siu Ming")},
                                           {"programme", w.nonce(), V::text("Nursing")},
                                           {"grades", w.nonce(), V::text("A, A, B")}});
        protocol::RecordRegisterBody r{
            "example.org.diploma/1",
            Bytes(fields.root.bytes().begin(), fields.root.bytes().end()),
            fields.leaves.size(),
            {},
            V::map({{V::text("note"), V::bytes(Bytes{1})}, {V::text("year"), V::integer(2026)}}),
            std::nullopt,
            {}};
        record = w.ok(w.org(), w.statement(w.org_id(), std::nullopt, r));
    }

    void endorse(const verifier::StatusEntry& entry, const KeyPair& key) {
        w.ok(key,
             w.statement(device_id, delegation,
                         protocol::RecordEndorseBody{record, verifier::credential_role(entry)}));
    }

    /// The published address's evidence: the record's, as of a new
    /// checkpoint, with name and programme disclosed.
    Bytes evidence() {
        REQUIRE(w.ledger().checkpoint(w.log_key()));
        auto bundle = w.ledger().export_evidence(w.log_key(), record);
        REQUIRE(bundle);
        for (const char* name : {"name", "programme"}) {
            bundle->disclosures.push_back(
                *protocol::disclose_field(provider(), w.hash(), fields, name));
        }
        return *protocol::encode_bundle(*bundle);
    }

    protocol::EvidenceReport report(ByteView bundle) {
        auto r = protocol::verify_bundle(provider(), bundle);
        REQUIRE(r);
        return *r;
    }

    verifier_json payload(ByteView bundle, const verifier::StatusEntry& entry,
                          std::vector<std::string> metadata = {"year"}) {
        auto content = verifier::credential_content(report(bundle), base, token, entry, metadata,
                                                    std::string("Diploma in Nursing"));
        INFO((content ? std::string() : content.error()));
        REQUIRE(content);
        return verifier::credential_json(*content);
    }

    std::string sign(const verifier_json& payload, const KeyPair& key) {
        auto jws = verifier::sign_credential(key, provider(), base.did, payload);
        REQUIRE(jws);
        return *jws;
    }

    verifier::CredentialReport check(const std::string& credential, ByteView bundle,
                                     verifier::CredentialOptions options = {}) {
        auto r = verifier::verify_credential(provider(), credential, bundle, options);
        INFO((r ? std::string() : std::string(r.error().detail)));
        REQUIRE(r);
        return *r;
    }

    std::vector<node::CredentialEntry> entries() {
        return node::credential_entries(w.ledger().state());
    }

    std::string status_list(const KeyPair& key) {
        const auto e = entries();
        const Bytes bits = node::status_bits(w.ledger().state(), e, 1);
        return sign(verifier::status_list_json(base, "Example College", 1, bits, t0), key);
    }
};

/// A compact JWS with its payload replaced by `payload` (bytes as given).
std::string with_payload(const std::string& jws, std::string_view payload) {
    const auto first = jws.find('.');
    const auto second = jws.find('.', first + 1);
    return jws.substr(0, first) + "." + kanhe::to_base64url(kanhe::as_bytes(payload)) +
           jws.substr(second);
}

} // namespace

TEST_CASE("JCS: members by UTF-16 code units, shortest escapes, integers only", "[credentials]") {
    verifier_json j = verifier_json::object();
    j["b"] = 1;
    j["a"] = verifier_json::array({"x\n\x1f/\xc3\xa9", true, nullptr, -5});
    j["\xef\xbd\x9e"] = 0;     // U+FF5E: after U+1F600 in UTF-16, before it by code point
    j["\xf0\x9f\x98\x80"] = 0; // U+1F600
    const auto out = verifier::jcs(j);
    REQUIRE(out);
    CHECK(*out == "{\"a\":[\"x\\n\\u001f/\xc3\xa9\",true,null,-5],\"b\":1,\"\xf0\x9f\x98\x80\":0,"
                  "\"\xef\xbd\x9e\":0}");
    CHECK(verifier::jcs(verifier_json(verifier::max_json_integer)));
    CHECK_FALSE(verifier::jcs(verifier_json(verifier::max_json_integer + 1)));
    CHECK_FALSE(verifier::jcs(verifier_json(1.5)));
    CHECK(verifier::parse_jcs(*out));
    CHECK_FALSE(verifier::parse_jcs("{\"b\":1,\"a\":2}"));
    CHECK_FALSE(verifier::parse_jcs("{\"a\":1,\"a\":2}"));
    CHECK_FALSE(verifier::parse_jcs("{\"a\": 1}"));
    CHECK_FALSE(verifier::parse_jcs("{\"a\":\"\\u0041\"}"));
    CHECK_FALSE(verifier::parse_jcs("{\"a\":1e2}"));
}

TEST_CASE("GZIP: ours round-trips small, others' decompress, damage fails", "[credentials]") {
    Bytes bits(verifier::status_list_bytes, 0);
    verifier::set_status_bit(bits, 0);
    verifier::set_status_bit(bits, 94'567);
    verifier::set_status_bit(bits, verifier::status_list_size - 1);
    CHECK(bits[0] == 0x80);
    CHECK(bits.back() == 0x01);
    const Bytes z = verifier::gzip_compress(bits);
    CHECK(z.size() < 200);
    const auto back = verifier::gzip_decompress(z, 1 << 20);
    REQUIRE(back);
    CHECK(*back == bits);
    for (const std::uint64_t i :
         {std::uint64_t{0}, std::uint64_t{94'567}, std::uint64_t{131'071}}) {
        CHECK(verifier::status_bit(bits, i));
    }
    CHECK_FALSE(verifier::status_bit(bits, 1));
    // Every length of run, and none at all.
    for (const std::size_t n : {0UZ, 1UZ, 2UZ, 3UZ, 4UZ, 258UZ, 259UZ, 260UZ, 261UZ, 1000UZ}) {
        const Bytes data(n, 7);
        const auto again = verifier::gzip_decompress(verifier::gzip_compress(data), 1 << 20);
        REQUIRE(again);
        CHECK(*again == data);
    }
    const auto other = verifier::gzip_decompress(*kanhe::from_hex(python_gzip), 1 << 20);
    REQUIRE(other);
    CHECK(other->size() == 3179);
    CHECK(kanhe::to_hex(provider().digest(crypto::HashAlg::sha256, *other)->bytes()) ==
          python_text_sha256);

    Bytes damaged = z;
    damaged[damaged.size() - 5] ^= 1; // the CRC
    CHECK_FALSE(verifier::gzip_decompress(damaged, 1 << 20));
    Bytes longer = z;
    longer.push_back(0);
    CHECK_FALSE(verifier::gzip_decompress(longer, 1 << 20));
    CHECK_FALSE(verifier::gzip_decompress(ByteView(z).first(z.size() - 1), 1 << 20));
    CHECK_FALSE(verifier::gzip_decompress(z, 1000)); // past the limit
    Bytes flagged = z;
    flagged[3] = 0x20;
    CHECK_FALSE(verifier::gzip_decompress(flagged, 1 << 20));

    const std::string encoded = verifier::encode_status_list(bits);
    CHECK(encoded.starts_with("uH4sI"));
    const auto decoded = verifier::decode_status_list(encoded);
    REQUIRE(decoded);
    CHECK(*decoded == bits);
    CHECK_FALSE(verifier::decode_status_list(encoded.substr(1)));
    CHECK_FALSE(verifier::decode_status_list(
        "u" + kanhe::to_base64url(verifier::gzip_compress(Bytes(100, 0)))));
}

TEST_CASE("a base URL and its did:web", "[credentials]") {
    const auto plain = verifier::parse_base_url("https://ledger.example.com/");
    REQUIRE(plain);
    CHECK(plain->url == "https://ledger.example.com");
    CHECK(plain->did == "did:web:ledger.example.com");
    CHECK(plain->did_document_url == "https://ledger.example.com/.well-known/did.json");
    const auto pathed = verifier::parse_base_url("https://example.com:8443/kanhe/college");
    REQUIRE(pathed);
    CHECK(pathed->did == "did:web:example.com%3A8443:kanhe:college");
    CHECK(pathed->did_document_url == "https://example.com:8443/kanhe/college/did.json");
    CHECK(verifier::parse_base_url("http://127.0.0.1:8080"));
    CHECK(verifier::parse_base_url("http://localhost:8080"));
    for (const char* bad :
         {"http://example.com", "https://1.2.3.4", "https://Example.com", "https://a..b",
          "ftp://example.com", "https://example.com:0", "https://example.com:65536",
          "https://example.com/a/../b", "https://example.com/a b", "https://", "example.com"}) {
        INFO(bad);
        CHECK_FALSE(verifier::parse_base_url(bad));
    }
}

TEST_CASE("status entries in endorsement roles", "[credentials]") {
    CHECK(verifier::credential_role({.list = 1, .index = 94'567}) == "credential/1/94567");
    const auto e = verifier::parse_credential_role("credential/2/0");
    REQUIRE(e);
    CHECK(*e == verifier::StatusEntry{.list = 2, .index = 0});
    for (const char* bad :
         {"credential/0/1", "credential/01/1", "credential/1/01", "credential/1/131072",
          "credential/1/", "credential/1", "credential/1/2/3", "credentials/1/2", "reviewer"}) {
        INFO(bad);
        CHECK_FALSE(verifier::parse_credential_role(bad));
    }
}

TEST_CASE("a credential issued on the ledger verifies against its evidence", "[credentials]") {
    College c;
    const verifier::StatusEntry entry{.list = 1, .index = 94'567};
    c.endorse(entry, c.device);
    const Bytes bundle = c.evidence();
    const verifier_json payload = c.payload(bundle, entry);
    CHECK(payload["credentialSubject"] ==
          verifier_json{{"name", "Chan Siu Ming"}, {"programme", "Nursing"}, {"year", 2026}});
    CHECK(payload["issuer"]["id"] == "did:web:ledger.example.com");
    CHECK(payload["credentialStatus"]["id"] == "https://ledger.example.com/status/1#94567");
    const std::string credential = c.sign(payload, c.device);

    const auto jws = verifier::parse_jws(credential);
    REQUIRE(jws);
    CHECK(jws->header ==
          verifier_json{{"alg", "ES256"},
                        {"cty", "vc"},
                        {"kid", "did:web:ledger.example.com#" +
                                    *verifier::jwk_thumbprint(provider(), c.device.public_key())},
                        {"typ", "vc+jwt"}});
    CHECK(verifier::verify_jws(provider(), *jws, c.device.public_key()));

    const auto doc = verifier::did_document(
        provider(), c.base, std::vector<crypto::PublicKey>{c.device.public_key()}, c.w.org_id());
    REQUIRE(doc);
    verifier::CredentialOptions options;
    options.did_document = doc->dump();
    options.status_list = c.status_list(c.device);
    const auto r = c.check(credential, bundle, options);
    INFO(r.problems.size());
    CHECK(r.verified());
    CHECK(r.record_status == "live");
    CHECK(r.key_actor == c.device_id);
    CHECK(r.status_list_bit == false);
    CHECK(r.evidence.complete);
    CHECK(verifier::credential_report_json(r, false)["verified"] == true);
    CHECK(verifier::credential_report_text(r, false).starts_with("VERIFIED"));

    const auto addresses = verifier::credential_addresses(credential);
    REQUIRE(addresses);
    CHECK(addresses->evidence == "https://ledger.example.com/c/" + c.token);
    CHECK(addresses->did_document == "https://ledger.example.com/.well-known/did.json");
    CHECK(addresses->status_list == "https://ledger.example.com/status/1");

    // The ledger shows it: its entry, list 1's bit clear until revoked.
    const auto entries = c.entries();
    REQUIRE(entries.size() == 1);
    CHECK(entries[0].entry == entry);
    CHECK(entries[0].actor == c.device_id);
    CHECK(node::is_credential_key(c.w.ledger().state(), *c.w.ledger().state().actor(c.device_id)));
    CHECK_FALSE(
        node::is_credential_key(c.w.ledger().state(), *c.w.ledger().state().actor(c.w.org_id())));
    ledger::SeededEntropy entropy(3);
    for (int i = 0; i < 50; ++i) {
        CHECK(node::choose_status_entry(entries, entropy) != entry);
    }

    // Revoked: the list says so, and a list made before disagrees.
    const std::string before = options.status_list.value();
    c.w.ok(c.w.org(), c.w.statement(c.w.org_id(), std::nullopt,
                                    protocol::RecordRevokeBody{c.record, "issued in error"}));
    const Bytes revoked = c.evidence();
    options.status_list = c.status_list(c.device);
    const auto rr = c.check(credential, revoked, options);
    CHECK(rr.verified());
    CHECK(rr.record_status == "revoked");
    CHECK(rr.status_list_bit == true);
    options.status_list = before;
    const auto hidden = c.check(credential, revoked, options);
    CHECK_FALSE(hidden.verified());
    REQUIRE(hidden.status_list_problems.size() == 1);
    CHECK(hidden.status_list_problems[0].find("ledger says the record is revoked") !=
          std::string::npos);
    // No credential for a revoked record.
    CHECK_FALSE(
        verifier::credential_content(c.report(revoked), c.base, c.token, entry, {}, std::nullopt));
}

TEST_CASE("a credential that lies is found out", "[credentials]") {
    College c;
    const verifier::StatusEntry entry{.list = 1, .index = 7};
    c.endorse(entry, c.device);
    const Bytes bundle = c.evidence();
    const verifier_json payload = c.payload(bundle, entry);
    auto problems = [&](const std::string& credential) {
        return c.check(credential, bundle).problems;
    };
    auto mentions = [](const std::vector<std::string>& list, std::string_view what) {
        return std::ranges::any_of(
            list, [&](const std::string& p) { return p.find(what) != std::string::npos; });
    };

    // Signed by a key that did not endorse the record.
    const KeyPair stranger = std::move(*KeyPair::generate(crypto::SigAlg::esp256));
    CHECK(mentions(problems(c.sign(payload, stranger)), "signature"));
    // Another status entry than its endorsement's.
    verifier_json other = payload;
    other["credentialStatus"]["id"] = "https://ledger.example.com/status/1#8";
    other["credentialStatus"]["statusListIndex"] = "8";
    CHECK(mentions(problems(c.sign(other, c.device)), "credential/1/8"));
    // A sealed field claimed.
    other = payload;
    other["credentialSubject"]["grades"] = "A, A, A";
    CHECK(mentions(problems(c.sign(other, c.device)), "grades = A, A, A"));
    // A disclosed field changed, a number as text.
    other = payload;
    other["credentialSubject"]["year"] = "2026";
    CHECK(mentions(problems(c.sign(other, c.device)), "year = 2026"));
    // Another issuer's name, another date.
    other = payload;
    other["issuer"]["name"] = "Example University";
    CHECK(mentions(problems(c.sign(other, c.device)), "Example University"));
    other = payload;
    other["validFrom"] = "2026-01-01T00:00:00.000Z";
    CHECK(mentions(problems(c.sign(other, c.device)), "registered at"));

    // Not this profile: refused before anything else.
    const std::string good = c.sign(payload, c.device);
    auto refused = [&](const std::string& credential) {
        return !verifier::verify_credential(provider(), credential, bundle, {});
    };
    CHECK(refused(with_payload(good, payload.dump(1)))); // not JCS
    other = payload;
    other["evidence"][0]["id"] = "https://ledger.example.org/c/" + c.token;
    CHECK(refused(c.sign(other, c.device))); // another base URL than the issuer's
    other = payload;
    other["credentialStatus"]["statusListCredential"] = "https://ledger.example.com/lists/1";
    other["credentialStatus"]["id"] = "https://ledger.example.com/lists/1#7";
    CHECK(refused(c.sign(other, c.device))); // a list elsewhere
    other = payload;
    other["extra"] = true;
    CHECK(refused(c.sign(other, c.device))); // a member not defined
    other = payload;
    other["credentialSubject"]["id"] = "did:example:1";
    CHECK(refused(c.sign(other, c.device)));         // a subject id
    CHECK(refused(good.substr(0, good.rfind('.')))); // two parts
    CHECK(refused("a.b.c"));
    verifier::CredentialOptions pinned;
    pinned.verify.expected_ledger = *protocol::to_id(Bytes(32, 1));
    CHECK_FALSE(verifier::verify_credential(provider(), good, bundle, pinned));

    // The DID document must name this key and this ledger.
    verifier::CredentialOptions options;
    options.did_document =
        verifier::did_document(provider(), c.base,
                               std::vector<crypto::PublicKey>{stranger.public_key()}, c.w.org_id())
            ->dump();
    CHECK_FALSE(c.check(good, bundle, options).verified());
    options.did_document =
        verifier::did_document(provider(), c.base,
                               std::vector<crypto::PublicKey>{c.device.public_key()},
                               *protocol::to_id(Bytes(32, 1)))
            ->dump();
    const auto wrong_ledger = c.check(good, bundle, options);
    CHECK(mentions(wrong_ledger.did_document_problems, "ledger"));
    // A status list signed by a stranger.
    options = {};
    options.status_list = c.status_list(stranger);
    CHECK(mentions(c.check(good, bundle, options).status_list_problems, "not signed"));
}

TEST_CASE("a credential key that rotates keeps its credentials verifying", "[credentials]") {
    College c;
    const verifier::StatusEntry entry{.list = 1, .index = 3};
    c.endorse(entry, c.device);
    const KeyPair rotated = std::move(*KeyPair::generate(crypto::SigAlg::esp256));
    c.w.ok(c.device,
           c.w.statement(c.device_id, std::nullopt,
                         protocol::ActorRotateKeyBody{c.device_id, rotated.public_key()}));
    const Bytes bundle = c.evidence();
    const verifier_json payload = c.payload(bundle, entry);
    CHECK(c.check(c.sign(payload, c.device), bundle).verified()); // signed before the rotation
    CHECK(c.check(c.sign(payload, rotated), bundle).verified());  // and again after it

    // The DID document lists both keys, ordered by thumbprint.
    const auto keys = node::credential_keys(
        c.w.ledger().state(), c.entries(), std::nullopt,
        [&](std::uint64_t index) -> kanhe::Result<protocol::SignedStatement> {
            const auto entry_bytes = c.w.ledger().entry(index);
            const auto log_entry = protocol::decode_log_entry(*entry_bytes);
            return protocol::parse_statement(provider(), log_entry->statement, c.w.hash());
        });
    REQUIRE(keys);
    REQUIRE(keys->size() == 2);
    const auto doc = verifier::did_document(provider(), c.base, *keys, c.w.org_id());
    REQUIRE(doc);
    const auto& methods = (*doc)["verificationMethod"];
    REQUIRE(methods.size() == 2);
    CHECK(methods[0]["id"].get<std::string>() < methods[1]["id"].get<std::string>());
}

TEST_CASE("a credential is issued from complete evidence that shows its key as it is now",
          "[credentials]") {
    College c;
    const verifier::StatusEntry entry{.list = 1, .index = 5};
    c.endorse(entry, c.device);
    const Bytes bundle = c.evidence();
    // Evidence that does not prove the complete history could leave out a
    // revocation: no credential from it.
    auto partial = c.report(bundle);
    REQUIRE(partial.complete);
    partial.complete = false;
    const auto refused =
        verifier::credential_content(partial, c.base, c.token, entry, {}, std::nullopt);
    REQUIRE_FALSE(refused);
    CHECK(refused.error().find("complete history") != std::string::npos);

    // The credential key rotates after the checkpoint that covers its
    // endorsement: the record's evidence must now reach the rotation, which
    // shows the key the next credential is signed with.
    const auto latest = c.w.ledger().latest_checkpoint();
    REQUIRE(latest);
    const KeyPair rotated = std::move(*KeyPair::generate(crypto::SigAlg::esp256));
    c.w.ok(c.device,
           c.w.statement(c.device_id, std::nullopt,
                         protocol::ActorRotateKeyBody{c.device_id, rotated.public_key()}));
    const auto last = node::last_index_about(c.w.ledger().state(), c.record);
    REQUIRE(last);
    CHECK(*last == c.w.ledger().size() - 1);
    CHECK(latest->checkpoint.tree_size <= *last);
    const Bytes fresh = c.evidence();
    CHECK(c.check(c.sign(c.payload(fresh, entry), rotated), fresh).verified());
    CHECK_FALSE(node::last_index_about(c.w.ledger().state(), c.device_id));
}

TEST_CASE("a status list signed by another of the issuer's credential keys", "[credentials]") {
    College c;
    const verifier::StatusEntry entry{.list = 1, .index = 11};
    c.endorse(entry, c.device);
    // A second credential key, the server's, which signs the lists.
    const KeyPair server = std::move(*KeyPair::generate(crypto::SigAlg::esp256));
    const protocol::Id server_id =
        c.w.ok(c.w.org(), c.w.statement(c.w.org_id(), std::nullopt,
                                        protocol::ActorRegisterBody{protocol::ActorKind::device,
                                                                    "Server", server.public_key(),
                                                                    std::nullopt, std::nullopt}));
    c.w.grant(c.w.org(), c.w.org_id(), std::nullopt, server_id,
              scope({StatementType::record_endorse}));
    const Bytes bundle = c.evidence();
    const std::string credential = c.sign(c.payload(bundle, entry), c.device);
    verifier::CredentialOptions options;
    options.status_list = c.status_list(server);
    // Without the DID document, only a device that endorsed the record vouches
    // for a list.
    const auto alone = c.check(credential, bundle, options);
    REQUIRE(alone.status_list_problems.size() == 1);
    CHECK(alone.status_list_problems[0].find("not signed by a device that endorsed") !=
          std::string::npos);
    // With the issuer's DID document, which lists both keys, either signs its lists.
    options.did_document = verifier::did_document(provider(), c.base,
                                                  std::vector<crypto::PublicKey>{
                                                      c.device.public_key(), server.public_key()},
                                                  c.w.org_id())
                               ->dump();
    const auto both = c.check(credential, bundle, options);
    CHECK(both.verified());
    CHECK(both.status_list_bit == false);
    // A key the document does not list does not.
    const KeyPair stranger = std::move(*KeyPair::generate(crypto::SigAlg::esp256));
    options.status_list = c.status_list(stranger);
    const auto foreign = c.check(credential, bundle, options);
    REQUIRE(foreign.status_list_problems.size() == 1);
    CHECK(foreign.status_list_problems[0].find("a key the issuer's DID document lists") !=
          std::string::npos);
    // Whoever signed it, a list whose bit disagrees with the ledger is found out.
    const std::string before = c.status_list(server);
    c.w.ok(c.w.org(), c.w.statement(c.w.org_id(), std::nullopt,
                                    protocol::RecordRevokeBody{c.record, "issued in error"}));
    const Bytes revoked = c.evidence();
    options.status_list = before;
    const auto stale = c.check(credential, revoked, options);
    CHECK_FALSE(stale.verified());
    CHECK(stale.status_list_problems.size() == 1);
    options.status_list = c.status_list(server);
    CHECK(c.check(credential, revoked, options).verified());
}

TEST_CASE("only a credential key's endorsements are entries, keys, and bits", "[credentials]") {
    College c;
    const verifier::StatusEntry entry{.list = 1, .index = 7};
    c.endorse(entry, c.device);
    // A member of staff, with an ES256 key and the right to endorse, and a
    // device that may also register records: neither is a credential key,
    // whatever role it writes.
    const KeyPair staff = std::move(*KeyPair::generate(crypto::SigAlg::esp256));
    const protocol::Id staff_id =
        c.w.ok(c.w.org(), c.w.statement(c.w.org_id(), std::nullopt,
                                        protocol::ActorRegisterBody{protocol::ActorKind::person,
                                                                    "Staff", staff.public_key(),
                                                                    std::nullopt, std::nullopt}));
    const protocol::Id staff_may = c.w.grant(c.w.org(), c.w.org_id(), std::nullopt, staff_id,
                                             scope({StatementType::record_endorse}));
    const KeyPair broad = std::move(*KeyPair::generate(crypto::SigAlg::esp256));
    const protocol::Id broad_id =
        c.w.ok(c.w.org(), c.w.statement(c.w.org_id(), std::nullopt,
                                        protocol::ActorRegisterBody{protocol::ActorKind::device,
                                                                    "Scanner", broad.public_key(),
                                                                    std::nullopt, std::nullopt}));
    const protocol::Id broad_may =
        c.w.grant(c.w.org(), c.w.org_id(), std::nullopt, broad_id,
                  scope({StatementType::record_register, StatementType::record_endorse}));
    // Another record, endorsed with the diploma's own entry, then revoked:
    // it must not set the diploma's bit.
    protocol::RecordRegisterBody other{
        "example.org.diploma/1",
        Bytes(c.fields.root.bytes().begin(), c.fields.root.bytes().end()),
        c.fields.leaves.size(),
        {},
        V::map({{V::text("year"), V::integer(2025)}}),
        std::nullopt,
        {}};
    const protocol::Id other_id =
        c.w.ok(c.w.org(), c.w.statement(c.w.org_id(), std::nullopt, other));
    c.w.ok(staff,
           c.w.statement(staff_id, staff_may,
                         protocol::RecordEndorseBody{other_id, verifier::credential_role(entry)}));
    c.w.ok(broad, c.w.statement(broad_id, broad_may,
                                protocol::RecordEndorseBody{c.record, "credential/1/9"}));
    c.w.ok(c.w.org(),
           c.w.statement(c.w.org_id(), std::nullopt, protocol::RecordRevokeBody{other_id, "test"}));

    const auto& state = c.w.ledger().state();
    CHECK(node::credential_device(state, *state.actor(c.device_id)));
    CHECK_FALSE(node::credential_device(state, *state.actor(staff_id)));
    CHECK_FALSE(node::credential_device(state, *state.actor(broad_id)));
    CHECK_FALSE(node::is_credential_key(state, *state.actor(broad_id)));
    const auto entries = c.entries();
    REQUIRE(entries.size() == 1);
    CHECK(entries[0].actor == c.device_id);
    CHECK_FALSE(verifier::status_bit(node::status_bits(state, entries, 1), 7));
    const auto keys = node::credential_keys(
        state, entries, std::nullopt,
        [&](std::uint64_t index) -> kanhe::Result<protocol::SignedStatement> {
            const auto entry_bytes = c.w.ledger().entry(index);
            const auto log_entry = protocol::decode_log_entry(*entry_bytes);
            return protocol::parse_statement(provider(), log_entry->statement, c.w.hash());
        });
    REQUIRE(keys);
    REQUIRE(keys->size() == 1);
    CHECK(keys->front() == c.device.public_key());
}

TEST_CASE("what cannot be a claim is named", "[credentials]") {
    College c;
    const Bytes bundle = c.evidence();
    const auto report = c.report(bundle);
    const verifier::StatusEntry entry{.list = 1, .index = 1};
    auto refusal = [&](std::vector<std::string> metadata) {
        const auto content =
            verifier::credential_content(report, c.base, c.token, entry, metadata, std::nullopt);
        REQUIRE_FALSE(content);
        return content.error();
    };
    CHECK(refusal({"note"}).find("note holds neither text") != std::string::npos);
    CHECK(refusal({"colour"}).find("no entry colour") != std::string::npos);
    CHECK_FALSE(
        verifier::credential_content(report, c.base, c.token, entry, {}, std::string(257, 'a')));
    CHECK(verifier::claim_name_problem("id"));
    CHECK(verifier::claim_name_problem("type"));
    CHECK(verifier::claim_name_problem("@context"));
    CHECK_FALSE(verifier::claim_name_problem("name"));
    CHECK(verifier::claim_value(V::integer(verifier::max_json_integer)));
    CHECK_FALSE(verifier::claim_value(V::integer(verifier::max_json_integer + 1)));
    CHECK_FALSE(verifier::claim_value(V::bytes(Bytes{1})));
    CHECK(*verifier::claim_value(V::boolean(true)) == true);
}

TEST_CASE("credential answers are planned under the lock and kept while nothing changes",
          "[credentials]") {
    College c;
    c.endorse({.list = 1, .index = 8}, c.device);
    // Not owned: the college keeps its device key.
    const std::shared_ptr<const crypto::Signer> key(std::shared_ptr<void>(), &c.device);
    node::CredentialService service{.key = [&] { return key; },
                                    .base = [&] { return std::optional(c.base); }};
    const auto statement_at = [&](std::uint64_t index) -> kanhe::Result<protocol::SignedStatement> {
        const auto entry_bytes = c.w.ledger().entry(index);
        const auto log_entry = protocol::decode_log_entry(*entry_bytes);
        return protocol::parse_statement(provider(), log_entry->statement, c.w.hash());
    };
    const auto plan_of = [&](std::string_view path) {
        auto planned =
            node::plan_credential_response(provider(), service, c.w.ledger().state(), path);
        REQUIRE(std::holds_alternative<node::CredentialPlan>(planned));
        return std::get<node::CredentialPlan>(std::move(planned));
    };
    const auto answer = [&](const node::CredentialPlan& plan) {
        auto r = node::credential_response(provider(), plan, t0, statement_at);
        REQUIRE(r.status == 200);
        return r;
    };

    // What the answer is made from, read from the state.
    const node::CredentialPlan list = plan_of("/status/1");
    CHECK(list.version == c.w.ledger().state().statement_count());
    CHECK(list.list == 1);
    CHECK_FALSE(verifier::status_bit(list.bits, 8));
    const node::CredentialPlan did = plan_of("/.well-known/did.json");
    CHECK(did.list == 0);
    CHECK(did.key_statements.size() == 1); // the device's registration
    // Errors are answered at once.
    const auto none =
        node::plan_credential_response(provider(), service, c.w.ledger().state(), "/status/2");
    REQUIRE(std::holds_alternative<kanhe::node::http::Response>(none));
    CHECK(std::get<kanhe::node::http::Response>(none).status == 404);

    node::CredentialCache cache;
    const auto signed_list = answer(list);
    cache.keep("/status/1", list, t0, signed_list);
    const auto& pub = c.device.public_key();
    const auto kept = cache.find("/status/1", list.version, pub, c.base, t0 + 1'000);
    REQUIRE(kept);
    CHECK(kept->body == signed_list.body);
    // Signed again a minute on, or if the clock went back.
    CHECK_FALSE(
        cache.find("/status/1", list.version, pub, c.base, t0 + node::credential_list_max_age_ms));
    CHECK_FALSE(cache.find("/status/1", list.version, pub, c.base, t0 - 1));
    // Not for another state, key, base URL, or path.
    CHECK_FALSE(cache.find("/status/1", list.version + 1, pub, c.base, t0));
    const KeyPair other = std::move(*KeyPair::generate(crypto::SigAlg::esp256));
    CHECK_FALSE(cache.find("/status/1", list.version, other.public_key(), c.base, t0));
    CHECK_FALSE(cache.find("/status/1", list.version, pub,
                           *verifier::parse_base_url("https://other.example.com"), t0));
    CHECK_FALSE(cache.find("/did.json", list.version, pub, c.base, t0));
    // A DID document holds no time: kept until the state changes.
    cache.keep("/.well-known/did.json", did, t0, answer(did));
    CHECK(cache.find("/.well-known/did.json", did.version, pub, c.base,
                     t0 + 10 * node::credential_list_max_age_ms));
    // Errors are not kept.
    kanhe::node::http::Response error;
    error.status = 503;
    cache.keep("/status/3", list, t0, error);
    CHECK_FALSE(cache.find("/status/3", list.version, pub, c.base, t0));

    // A revocation is a new state: a new plan, with the bit set. An answer
    // from the older state that finishes last is not kept over it.
    c.w.ok(c.w.org(), c.w.statement(c.w.org_id(), std::nullopt,
                                    protocol::RecordRevokeBody{c.record, "issued in error"}));
    CHECK_FALSE(cache.find("/status/1", c.w.ledger().state().statement_count(), pub, c.base, t0));
    const node::CredentialPlan revoked = plan_of("/status/1");
    CHECK(revoked.version == list.version + 1);
    CHECK(verifier::status_bit(revoked.bits, 8));
    const auto revoked_list = answer(revoked);
    cache.keep("/status/1", revoked, t0, revoked_list);
    cache.keep("/status/1", list, t0, signed_list);
    const auto newest = cache.find("/status/1", revoked.version, pub, c.base, t0);
    REQUIRE(newest);
    CHECK(newest->body == revoked_list.body);
}

TEST_CASE("a full status list moves on to the next", "[credentials]") {
    std::vector<node::CredentialEntry> entries;
    for (std::uint64_t i = 0; i < verifier::status_list_size; ++i) {
        entries.push_back(
            {.record = {}, .actor = {}, .entry = {.list = 1, .index = i}, .index = i});
    }
    ledger::SeededEntropy entropy(1);
    CHECK(node::choose_status_entry(entries, entropy).list == 2);
    entries.pop_back();
    CHECK(node::choose_status_entry(entries, entropy) ==
          verifier::StatusEntry{.list = 1, .index = verifier::status_list_size - 1});
}

TEST_CASE("the credential test vectors, made apart from this code", "[credentials][vectors]") {
    std::ifstream file(KANHE_TESTVECTORS_DIR "/credentials-v1.json");
    REQUIRE(file);
    const auto v = nlohmann::json::parse(file);
    auto key_of = [](const std::string& hex) {
        return crypto::PublicKey{crypto::SigAlg::esp256, *kanhe::from_hex(hex)};
    };
    for (const auto& c : v["jcs"]) {
        CHECK(*verifier::jcs(verifier_json(c["value"])) == c["jcs"].get<std::string>());
    }
    for (const auto& text : v["jcs_refused"]) {
        INFO(text.get<std::string>());
        CHECK_FALSE(verifier::parse_jcs(text.get<std::string>()));
    }
    for (const auto& t : v["thumbprints"]) {
        const auto key = key_of(t["key"]);
        CHECK(*verifier::jwk_thumbprint(provider(), key) == t["thumbprint"].get<std::string>());
        CHECK(*verifier::jcs(*verifier::public_jwk(key)) ==
              *verifier::jcs(verifier_json(t["jwk"])));
        CHECK(*verifier::jwk_key(verifier_json(t["jwk"])) == key);
    }
    for (const auto& b : v["base_urls"]) {
        const auto base = verifier::parse_base_url(b["url"].get<std::string>());
        REQUIRE(base);
        CHECK(base->url == b["base"].get<std::string>());
        CHECK(base->did == b["did"].get<std::string>());
        CHECK(base->did_document_url == b["did_document"].get<std::string>());
    }
    for (const auto& url : v["base_urls_refused"]) {
        INFO(url.get<std::string>());
        CHECK_FALSE(verifier::parse_base_url(url.get<std::string>()));
    }
    for (const auto& r : v["roles"]) {
        const auto entry = verifier::parse_credential_role(r["role"].get<std::string>());
        REQUIRE(entry);
        CHECK(entry->list == r["list"].get<std::uint64_t>());
        CHECK(entry->index == r["index"].get<std::uint64_t>());
        CHECK(verifier::credential_role(*entry) == r["role"].get<std::string>());
    }
    for (const auto& role : v["roles_refused"]) {
        INFO(role.get<std::string>());
        CHECK_FALSE(verifier::parse_credential_role(role.get<std::string>()));
    }
    for (const auto& c : v["credentials"]) {
        INFO(c["description"].get<std::string>());
        const auto& in = c["content"];
        verifier::CredentialContent content;
        content.base = *verifier::parse_base_url(in["base"].get<std::string>());
        content.organization = in["organization"].get<std::string>();
        if (!in["name"].is_null()) {
            content.name = in["name"].get<std::string>();
        }
        content.registered_at = in["registered_at"].get<protocol::Timestamp>();
        for (const auto& claim : in["subject"]) {
            content.subject.emplace_back(claim[0].get<std::string>(), verifier_json(claim[1]));
        }
        content.entry = {.list = in["list"].get<std::uint64_t>(),
                         .index = in["index"].get<std::uint64_t>()};
        content.token = in["token"].get<std::string>();
        content.ledger = *protocol::to_id(*kanhe::from_hex(in["ledger"].get<std::string>()));
        content.record = *protocol::to_id(*kanhe::from_hex(in["record"].get<std::string>()));
        CHECK(*verifier::jcs(verifier::credential_json(content)) ==
              c["payload"].get<std::string>());
        const auto jws = verifier::parse_jws(c["jws"].get<std::string>());
        REQUIRE(jws);
        CHECK(*verifier::jcs(jws->header) == c["header"].get<std::string>());
        CHECK(*verifier::jcs(jws->payload) == c["payload"].get<std::string>());
        CHECK(verifier::verify_jws(provider(), *jws, key_of(c["key"])));
        CHECK(jws->kid ==
              content.base.did + "#" + *verifier::jwk_thumbprint(provider(), key_of(c["key"])));
        CHECK(verifier::credential_addresses(c["jws"].get<std::string>()));
    }
    for (const auto& d : v["did_documents"]) {
        INFO(d["description"].get<std::string>());
        std::vector<crypto::PublicKey> keys;
        for (const auto& k : d["keys"]) {
            keys.push_back(key_of(k));
        }
        const auto doc = verifier::did_document(
            provider(), *verifier::parse_base_url(d["base"].get<std::string>()), keys,
            *protocol::to_id(*kanhe::from_hex(d["ledger"].get<std::string>())));
        REQUIRE(doc);
        CHECK(*verifier::jcs(*doc) == d["document"].get<std::string>());
    }
    for (const auto& s : v["status_lists"]) {
        INFO(s["description"].get<std::string>());
        const auto bits = verifier::decode_status_list(s["encoded"].get<std::string>());
        REQUIRE(bits);
        CHECK(kanhe::to_hex(provider().digest(crypto::HashAlg::sha256, *bits)->bytes()) ==
              s["sha256"].get<std::string>());
        for (const auto& i : s["set"]) {
            CHECK(verifier::status_bit(*bits, i.get<std::uint64_t>()));
        }
    }
    for (const auto& s : v["status_lists_refused"]) {
        INFO(s["why"].get<std::string>());
        CHECK_FALSE(verifier::decode_status_list(s["encoded"].get<std::string>()));
    }
}
