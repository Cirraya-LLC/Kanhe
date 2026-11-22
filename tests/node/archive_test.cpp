// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// Archives (spec section 16, "Archives"): another server keeps a member's
// ledger, a replica with commitments and public metadata only, and the
// newest verified evidence of each record it published, fetched again only
// when the record changed and kept only if newer, dropped when the member
// takes it down. The archive serves the kept evidence with a renewal from
// its copy appended, while the member is gone too. An archive token reaches
// what a replica copies and the list of published records, nothing else.
// Re-attestation asks public witnesses and never moves one the member uses,
// so the member's own requests go on as before.

#include <atomic>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <thread>
#include <unistd.h>
#include <utility>
#include <vector>

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>

#include <kanhe/client/public_witness.hpp>
#include <kanhe/client/public_witnesses.hpp>
#include <kanhe/core/protocol/evidence.hpp>
#include <kanhe/core/protocol/log.hpp>
#include <kanhe/core/protocol/statement.hpp>
#include <kanhe/ledger/storage.hpp>
#include <kanhe/node/api.hpp>
#include <kanhe/node/archive.hpp>
#include <kanhe/node/client.hpp>
#include <kanhe/node/published.hpp>
#include <kanhe/node/replica.hpp>
#include <kanhe/node/responses.hpp>
#include <kanhe/node/server.hpp>
#include <kanhe/node/tokens.hpp>

#include "support/ledger_world.hpp"

namespace {

using namespace kanhe::test;
namespace node = kanhe::node;
namespace client = kanhe::client;
using kanhe::Bytes;
using kanhe::Errc;
using kanhe::to_hex;
using json = nlohmann::json;

std::filesystem::path fresh_directory(const std::string& what) {
    static int counter = 0;
    const auto dir = std::filesystem::temp_directory_path() /
                     ("kanhe-archive-test-" + what + "-" + std::to_string(::getpid()) + "-" +
                      std::to_string(counter++));
    std::filesystem::remove_all(dir);
    std::filesystem::create_directories(dir);
    return dir;
}

/// Answers through `api`, unless `instead` answers first (a member's server
/// that misbehaves).
class Forwarding final : public node::Application {
public:
    explicit Forwarding(node::Application& api) : api_(api) {}
    void handle(node::http::Request request, std::string peer, Respond respond) override {
        if (instead) {
            if (auto answer = instead(request)) {
                respond(std::move(*answer));
                return;
            }
        }
        api_.handle(std::move(request), std::move(peer), std::move(respond));
    }
    void tick() override { api_.tick(); }
    void stopping() override { api_.stopping(); }
    void stop() override { api_.stop(); }

    std::function<std::optional<node::http::Response>(const node::http::Request&)> instead;

private:
    node::Application& api_;
};

/// A public witness as `serve --witness-public` runs one, alone.
class WitnessApp final : public node::Application {
public:
    WitnessApp(std::filesystem::path dir, std::shared_ptr<const kanhe::crypto::Signer> key)
        : witness_(std::move(dir), std::move(key), "test-witness",
                   client::PublicWitnessLimits{100, 100, 0}) {}
    void handle(node::http::Request request, std::string peer, Respond respond) override {
        auto answer = witness_.handle(request, peer, ledger::SystemClock{}.now());
        respond(answer ? std::move(*answer)
                       : node::error_response(404, "not_found", "no such route"));
    }

private:
    client::PublicWitness witness_;
};

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
    [[nodiscard]] std::string url() const {
        return "http://127.0.0.1:" + std::to_string(server_.port());
    }
    [[nodiscard]] node::Client client(std::optional<std::string> token = std::nullopt) const {
        node::ClientOptions o;
        o.timeout = std::chrono::seconds(15);
        o.bearer_token = std::move(token);
        return node::Client(*node::Url::parse(url()), o);
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

constexpr std::string_view archive_token = "kht_archive-token-for-the-tests";
constexpr std::string_view admin_token = "kht_admin-token-for-the-tests";

/// A member's ledger on disk: a record, checkpointed and published, and an
/// archive token and an admin token for its server.
struct Member {
    std::filesystem::path dir = fresh_directory("member");
    ledger::ManualClock clock{t0};
    ledger::SeededEntropy entropy{91};
    KeyPair org = key("archive member org");
    std::shared_ptr<const KeyPair> log_key =
        std::make_shared<const KeyPair>(key("archive member log"));
    protocol::Id id;
    protocol::Id record;
    std::string token;

    Member() {
        auto fs = ledger::PosixFileSystem::open_directory(dir);
        REQUIRE(fs);
        protocol::Statement genesis;
        genesis.issued_at = clock.now();
        genesis.nonce = entropy.bytes<16>();
        genesis.body = protocol::GenesisBody{crypto::HashAlg::sha256, "Archived Member",
                                             org.public_key(), log_key->public_key()};
        auto signed_genesis =
            protocol::sign_statement(org, provider(), crypto::HashAlg::sha256, genesis);
        REQUIRE(signed_genesis);
        auto created = ledger::Ledger::create(*fs, clock, provider(), signed_genesis->encoded);
        REQUIRE(created);
        id = created->id();
        record = submit(*created, document());
        REQUIRE(created->checkpoint(*log_key));
        auto published = node::publish_record(dir, record, {}, entropy, clock);
        REQUIRE(published);
        token = published->token;
        REQUIRE(node::save_tokens(
            dir, {node::ApiToken{"archive", static_cast<node::Scopes>(node::Scope::archive),
                                 node::token_hash(provider(), archive_token), clock.now()},
                  node::ApiToken{
                      "admin",
                      static_cast<node::Scopes>(static_cast<node::Scopes>(node::Scope::admin) |
                                                static_cast<node::Scopes>(node::Scope::read)),
                      node::token_hash(provider(), admin_token), clock.now()}}));
    }
    Member(const Member&) = delete;
    Member& operator=(const Member&) = delete;
    ~Member() { std::filesystem::remove_all(dir); }

    static protocol::Body document() {
        return protocol::RecordRegisterBody{document_type, Bytes(32, 0x42), 3, {},
                                            std::nullopt,  std::nullopt,    {}};
    }

    protocol::Id submit(ledger::Ledger& ledger, protocol::Body body) {
        protocol::Statement st;
        st.ledger_id = id;
        st.actor_id = id;
        st.issued_at = clock.now();
        st.nonce = entropy.bytes<16>();
        st.body = std::move(body);
        auto signed_statement =
            protocol::sign_statement(org, provider(), crypto::HashAlg::sha256, st);
        REQUIRE(signed_statement);
        auto r = ledger.submit(signed_statement->encoded);
        INFO((r ? std::string() : std::string(r.error().detail)));
        REQUIRE(r);
        clock.advance(1000);
        return r->statement_id;
    }

    /// Changes the ledger on disk, under its lock, as another process would
    /// while its server runs.
    void change(const std::function<void(ledger::Ledger&)>& f) {
        auto lock = ledger::DirectoryLock::acquire(dir);
        REQUIRE(lock);
        auto fs = ledger::PosixFileSystem::open_directory(dir);
        REQUIRE(fs);
        auto opened = ledger::Ledger::open(*fs, clock, provider());
        REQUIRE(opened);
        f(*opened);
    }

    std::unique_ptr<node::LedgerApi> api() {
        node::ApiOptions o;
        o.directory = dir;
        o.clock = &clock;
        o.log_keys.push_back(log_key);
        auto opened = node::LedgerApi::open(o, provider());
        REQUIRE(opened);
        return std::move(*opened);
    }
};

node::ArchiveSource source_of(const Running& server) {
    return {server.url(), std::string(archive_token), std::nullopt};
}

protocol::EvidenceReport verified(const Bytes& bundle, const protocol::Id& ledger) {
    protocol::VerifyOptions options;
    options.expected_ledger = ledger;
    auto report = protocol::verify_bundle(provider(), bundle, options);
    INFO((report ? std::string() : std::string(report.error().detail)));
    REQUIRE(report);
    return std::move(*report);
}

int status_of(const node::Client& c, std::string_view method, const std::string& path) {
    auto r = c.request(method, path);
    REQUIRE(r);
    return r->status;
}

} // namespace

TEST_CASE("an archive's files read back as written, and damaged ones are refused",
          "[node][archive]") {
    const auto dir = fresh_directory("files");
    auto config = node::load_archive_config(dir);
    REQUIRE(config);
    CHECK(*config == node::ArchiveConfig{});
    CHECK(config->sync_interval == std::chrono::seconds(3600));
    CHECK(config->attest_interval == std::chrono::seconds(365LL * 86'400));

    node::ArchiveConfig set;
    set.witnesses.push_back({"https://witness.example.org", "pq", key("witness").public_key()});
    set.authorities.push_back("http://tsa.example.org/tsa");
    set.sync_interval = std::chrono::seconds(600);
    set.attest_interval = std::chrono::seconds(30LL * 86'400);
    REQUIRE(node::save_archive_config(dir, set));
    CHECK(*node::load_archive_config(dir) == set);
    // Bounds.
    auto twice = set;
    twice.authorities.push_back(twice.authorities.front());
    CHECK_FALSE(node::save_archive_config(dir, twice));
    auto fast = set;
    fast.sync_interval = std::chrono::seconds(1);
    CHECK_FALSE(node::save_archive_config(dir, fast));
    auto not_web = set;
    not_web.witnesses.front().url = "ftp://witness.example.org";
    CHECK_FALSE(node::save_archive_config(dir, not_web));
    CHECK_FALSE(node::parse_archive_config(kanhe::as_bytes(std::string("{\"version\": 2}"))));
    CHECK_FALSE(node::parse_archive_config(
        kanhe::as_bytes(std::string("{\"version\": 1, \"witnesses\": [{\"url\": 1}]}"))));

    node::ArchiveState state;
    state.source = "https://member.example.org";
    state.created = t0;
    state.organization = "Member";
    state.size = 12;
    state.checkpoint_time = t0 + 5;
    state.last_sync = t0 + 6;
    state.last_try = t0 + 7;
    state.unreachable_since = t0 + 8;
    state.attested_at = t0 + 9;
    state.last_attest = t0 + 10;
    state.attest_problems = {"witness x: busy"};
    state.cursors = {3, 2, 1};
    state.own = {std::string(64, 'a')};
    state.published_problems = {"listing: refused"};
    REQUIRE(node::save_archive_state(dir, state));
    const auto read = node::load_archive_state(dir);
    REQUIRE(read);
    CHECK(*read == state);
    CHECK_FALSE(node::parse_archive_state(kanhe::as_bytes(std::string("{\"version\": 1}"))));
    CHECK_FALSE(node::parse_archive_state(kanhe::as_bytes(
        std::string("{\"version\": 1, \"source\": \"x\", \"last_sync\": \"yesterday\"}"))));

    // Due times.
    node::ArchiveConfig hourly;
    CHECK(node::next_sync(state, hourly) == t0 + 7 + 3'600'000);
    // The later of: the newest attestation's age, and a sync interval after
    // the last round.
    CHECK(node::next_attestation(state, hourly) == t0 + 9 + 365LL * 86'400'000);
    node::ArchiveState never;
    CHECK(node::next_sync(never, hourly) == 0);
    CHECK(node::next_attestation(never, hourly) == 0);
    never.last_attest = t0;
    CHECK(node::next_attestation(never, hourly) == t0 + 3'600'000);

    // The list a member gives: tokens once each, records as ids.
    const std::string listed = R"([{"token": "AAAAAAAAAAAAAAAAAAAAAA", "record": ")" +
                               std::string(64, 'b') + R"(", "published_at": 5}])";
    const auto list = node::parse_published_list(kanhe::as_bytes(listed));
    REQUIRE(list);
    REQUIRE(list->size() == 1);
    CHECK(list->front().token == "AAAAAAAAAAAAAAAAAAAAAA");
    for (const std::string& bad :
         {std::string("{}"), std::string("[1]"),
          std::string(R"([{"token": "../x", "record": ")") + std::string(64, 'b') + "\"}]",
          std::string(R"([{"token": "AAAAAAAAAAAAAAAAAAAAAA", "record": "BB"}])"),
          std::string(R"([{"token": "AAAAAAAAAAAAAAAAAAAAAA", "record": ")") +
              std::string(64, 'B') + "\"}]",
          listed.substr(0, listed.size() - 1) + "," + listed.substr(1)}) {
        INFO(bad);
        CHECK_FALSE(node::parse_published_list(kanhe::as_bytes(bad)));
    }
    std::string many = "[";
    for (std::size_t i = 0; i <= node::max_archived_published; ++i) {
        many += i == 0 ? "1" : ",1";
    }
    many += "]";
    const auto too_many = node::parse_published_list(kanhe::as_bytes(many));
    REQUIRE_FALSE(too_many);
    CHECK(too_many.error().code == Errc::limit_exceeded);
    std::filesystem::remove_all(dir);
}

TEST_CASE("a backup holds an archive's files and nothing else", "[node][archive]") {
    const std::string hex(64, 'a');
    for (const std::string& ok :
         {std::string("archive/config.json"), "archive/" + hex + "/archive.json",
          "archive/" + hex + "/token", "archive/" + hex + "/ca.pem",
          "archive/" + hex + "/kept.json", "archive/" + hex + "/ledger.backup.0",
          "archive/" + hex + "/ledger.backup.12",
          "archive/" + hex + "/published/AAAAAAAAAAAAAAAAAAAAAA.cbor"}) {
        INFO(ok);
        CHECK(node::archive_backup_path_allowed(ok));
    }
    for (const std::string& refused :
         {std::string("archive/x.json"), "archive/" + hex + "/statements",
          "archive/" + hex + "/lock", "archive/" + std::string(64, 'A') + "/token",
          "archive/" + hex + "/ledger.backup.01", "archive/" + hex + "/ledger.backup.",
          "archive/" + hex + "/published/../token", "archive/" + hex + "/../token",
          "archive/" + hex + "token", "archive/" + hex.substr(1) + "/token"}) {
        INFO(refused);
        CHECK_FALSE(node::archive_backup_path_allowed(refused));
    }
}

TEST_CASE("an archive token reaches what a replica copies and the published list, no more",
          "[node][archive]") {
    Member m;
    auto api = m.api();
    Running server(*api);
    const auto archive = server.client(std::string(archive_token));
    for (const char* path :
         {"/v1/status", "/v1/entries?start=0&count=1", "/v1/checkpoints?start=0&count=10",
          "/v1/cosignatures?start=0&count=10", "/v1/timestamps?start=0&count=10",
          "/v1/network-cosignatures?start=0&count=10", "/v1/published"}) {
        INFO(path);
        CHECK(status_of(archive, "GET", path) == 200);
    }
    const std::string record = to_hex(m.record.bytes());
    for (const std::string& path : std::vector<std::string>{
             "/metrics", "/v1/genesis", "/v1/vault/public-key", "/v1/vault/records/" + record,
             "/v1/evidence/" + record, "/v1/state/" + record, "/v1/statements/" + record,
             "/v1/inclusion?index=0&size=1", "/v1/receipts/0", "/v1/contracts"}) {
        INFO(path);
        CHECK(status_of(archive, "GET", path) == 403);
    }
    for (const char* path :
         {"/v1/statements", "/v1/checkpoint", "/v1/published", "/v1/cosignatures"}) {
        INFO(path);
        CHECK(status_of(archive, "POST", path) == 403);
    }
    CHECK(status_of(archive, "DELETE", "/v1/published/" + m.token) == 403);

    // The list: tokens and records, without the fields an admin sees.
    auto listed = archive.request("GET", "/v1/published");
    REQUIRE(listed);
    const auto list = json::parse(listed->body.begin(), listed->body.end());
    REQUIRE(list.size() == 1);
    CHECK(list[0]["token"] == m.token);
    CHECK(list[0]["record"] == record);
    CHECK_FALSE(list[0].contains("fields"));
    auto admin = server.client(std::string(admin_token)).request("GET", "/v1/published");
    REQUIRE(admin);
    CHECK(json::parse(admin->body.begin(), admin->body.end())[0].contains("fields"));
    CHECK(node::parse_published_list(listed->body));
}

TEST_CASE("a sync reads the member's attestations from where it left off", "[node][archive]") {
    Member m;
    auto api = m.api();
    Running server(*api);
    const auto primary = server.client(std::string(archive_token));
    const auto dir = fresh_directory("cursors");
    ledger::SystemClock clock;
    auto fs = ledger::PosixFileSystem::open_directory(dir);
    REQUIRE(fs);
    auto replica = node::create_replica(primary, *fs, clock, provider(), m.id);
    REQUIRE(replica);
    node::SyncOptions options;
    options.vault = false;
    options.from = node::AttestationCursors{};
    auto first = node::sync_replica(primary, *replica, dir, {}, options);
    REQUIRE(first);
    CHECK(first->next == node::AttestationCursors{});

    // The replica keeps a cosignature of its own; then the member gets one.
    const KeyPair own_witness = key("archive's own witness");
    const KeyPair member_witness = key("member's witness");
    const auto latest = replica->latest_checkpoint();
    REQUIRE(latest);
    auto own = protocol::cosign_checkpoint(own_witness, provider(), latest->checkpoint, t0 / 1000);
    REQUIRE(own);
    REQUIRE(replica->add_cosignature(own->encoded, own_witness.public_key()));
    m.change([&](ledger::Ledger& l) {
        auto cosigned = protocol::cosign_checkpoint(member_witness, provider(),
                                                    l.latest_checkpoint()->checkpoint, t0 / 1000);
        REQUIRE(cosigned);
        REQUIRE(l.add_cosignature(cosigned->encoded, member_witness.public_key()));
    });
    // Counted from the replica's own list, the member's would be skipped:
    // read from the cursor, it is taken.
    options.from = first->next;
    auto second = node::sync_replica(primary, *replica, dir, {}, options);
    REQUIRE(second);
    CHECK(second->cosignatures == 1);
    CHECK(second->next.cosignatures == 1);
    CHECK(replica->cosignature_count() == 2);
    REQUIRE(replica->last_cosigned(member_witness.public_key()));
    CHECK(replica->last_cosigned(member_witness.public_key())->has_value());
    std::filesystem::remove_all(dir);
}

TEST_CASE("an archive keeps a ledger and its published evidence, and serves it after the member "
          "is gone",
          "[node][archive]") {
    Member m;
    auto api = m.api();
    auto forwarding = std::make_unique<Forwarding>(*api);
    auto server = std::make_unique<Running>(*forwarding);
    const auto trust = fresh_directory("trust");
    ledger::SystemClock clock;

    // Of exactly that ledger: another id is refused, and nothing stays.
    auto wrong =
        node::ArchivedLedger::create(trust, m.record, source_of(*server), clock, provider());
    REQUIRE_FALSE(wrong);
    CHECK(wrong.error().code == Errc::verification_failed);
    CHECK(node::archived_ledgers(trust).empty());
    CHECK_FALSE(std::filesystem::exists(node::archive_path(trust, m.record)));
    // A token the member does not know is refused too.
    auto refused = node::ArchivedLedger::create(
        trust, m.id, {server->url(), "kht_unknown", std::nullopt}, clock, provider());
    REQUIRE_FALSE(refused);
    CHECK(refused.error().code == Errc::rejected);

    auto created = node::ArchivedLedger::create(trust, m.id, source_of(*server), clock, provider());
    INFO((created ? std::string() : std::string(created.error().detail)));
    REQUIRE(created);
    auto& [archive, report] = *created;
    CHECK(report.synced);
    CHECK(report.published.listed);
    CHECK(report.published.kept == 1);
    CHECK(node::archived_ledgers(trust) == std::vector<protocol::Id>{m.id});
    CHECK_FALSE(node::ArchivedLedger::create(trust, m.id, source_of(*server), clock, provider()));
    // No sealed data, and the token kept owner-only.
    CHECK_FALSE(std::filesystem::exists(archive->directory() / "vault"));
    const auto perms = std::filesystem::status(archive->directory() / "token").permissions();
    CHECK((perms & (std::filesystem::perms::group_all | std::filesystem::perms::others_all)) ==
          std::filesystem::perms::none);
    auto state = node::load_archive_state(archive->directory());
    REQUIRE(state);
    CHECK(state->organization == "Archived Member");
    CHECK(state->size == archive->replica().size());

    auto kept = archive->published_bundle(m.token);
    REQUIRE(kept);
    const auto first = verified(*kept, m.id);
    CHECK(first.record == m.record);
    CHECK_FALSE(first.revoked);
    CHECK(protocol::decode_bundle(*kept)->renewals.empty());
    const auto missing = archive->published_bundle("AAAAAAAAAAAAAAAAAAAAAA");
    REQUIRE_FALSE(missing);
    CHECK(missing.error().code == Errc::not_found);

    // Unchanged, the record is not fetched again.
    auto again = archive->sync();
    REQUIRE(again);
    CHECK(again->synced);
    CHECK(again->published.fetched == 0);
    CHECK(again->published.unchanged == 1);

    // The member grows, and a witness cosigns its new checkpoint: the kept
    // evidence is served with a renewal to it from the archive's copy.
    const KeyPair witness = key("member's witness");
    m.change([&](ledger::Ledger& l) {
        m.submit(l, Member::document());
        auto made = l.checkpoint(*m.log_key);
        REQUIRE(made);
        auto cosigned =
            protocol::cosign_checkpoint(witness, provider(), made->checkpoint, t0 / 1000 + 60);
        REQUIRE(cosigned);
        REQUIRE(l.add_cosignature(cosigned->encoded, witness.public_key()));
    });
    REQUIRE(archive->sync());
    const std::uint64_t witnessed = archive->replica().size();
    auto renewed = archive->published_bundle(m.token);
    REQUIRE(renewed);
    const auto bundle = protocol::decode_bundle(*renewed);
    REQUIRE(bundle);
    REQUIRE(bundle->renewals.size() == 1);
    CHECK(protocol::parse_checkpoint(bundle->renewals[0].checkpoint)->checkpoint.tree_size ==
          archive->replica().size());
    const auto renewed_report = verified(*renewed, m.id);
    CHECK(renewed_report.renewals.size() == 1);
    CHECK(renewed_report.checkpoint.tree_size == first.checkpoint.tree_size);

    // Endorsed: fetched again, verified, and kept in place of the one before.
    m.change([&](ledger::Ledger& l) {
        m.submit(l, protocol::RecordEndorseBody{m.record, "reviewer"});
        REQUIRE(l.checkpoint(*m.log_key));
    });
    auto endorsed = archive->sync();
    REQUIRE(endorsed);
    CHECK(endorsed->published.fetched == 1);
    CHECK(endorsed->published.kept == 1);
    const auto second = verified(*archive->published_bundle(m.token), m.id);
    CHECK(second.checkpoint.tree_size > first.checkpoint.tree_size);

    // A server that answers older evidence than kept is not believed, nor
    // one that answers another record's.
    const Bytes old_bundle = *kept;
    m.change([&](ledger::Ledger& l) {
        m.submit(l, protocol::RecordEndorseBody{m.record, "auditor"});
        REQUIRE(l.checkpoint(*m.log_key));
    });
    forwarding->instead = [&](const node::http::Request& r) -> std::optional<node::http::Response> {
        if (r.path == "/c/" + m.token) {
            node::http::Response old;
            old.content_type = "application/cbor";
            old.body = old_bundle;
            return old;
        }
        return std::nullopt;
    };
    auto older = archive->sync();
    REQUIRE(older);
    CHECK(older->published.kept == 0);
    REQUIRE_FALSE(older->published.problems.empty());
    CHECK(older->published.problems.front().find("older") != std::string::npos);
    CHECK(verified(*archive->published_bundle(m.token), m.id).checkpoint.tree_size ==
          second.checkpoint.tree_size);
    Bytes other_record;
    m.change([&](ledger::Ledger& l) {
        const protocol::Id other = m.submit(l, Member::document());
        REQUIRE(l.checkpoint(*m.log_key));
        auto evidence = l.export_evidence(*m.log_key, other);
        REQUIRE(evidence);
        other_record = *protocol::encode_bundle(*evidence);
    });
    forwarding->instead = [&](const node::http::Request& r) -> std::optional<node::http::Response> {
        if (r.path == "/c/" + m.token) {
            node::http::Response other;
            other.content_type = "application/cbor";
            other.body = other_record;
            return other;
        }
        return std::nullopt;
    };
    auto another = archive->sync();
    REQUIRE(another);
    CHECK(another->published.kept == 0);
    REQUIRE_FALSE(another->published.problems.empty());
    CHECK(another->published.problems.front().find("another record") != std::string::npos);
    forwarding->instead = nullptr;

    // Revoked: fetched again, and the kept evidence says so.
    m.change([&](ledger::Ledger& l) {
        m.submit(l, protocol::RecordRevokeBody{m.record, std::string("withdrawn")});
        REQUIRE(l.checkpoint(*m.log_key));
    });
    auto after = archive->sync();
    REQUIRE(after);
    CHECK(after->published.fetched == 1);
    CHECK(after->published.kept == 1);
    CHECK(verified(*archive->published_bundle(m.token), m.id).revoked);

    // Taken down by the member: dropped here too.
    REQUIRE(node::unpublish(m.dir, m.token));
    auto down = archive->sync();
    REQUIRE(down);
    CHECK(down->published.removed == 1);
    CHECK_FALSE(archive->published_bundle(m.token));
    REQUIRE(node::load_kept(archive->directory()));
    CHECK(node::load_kept(archive->directory())->empty());

    // Published again, then the member's server is gone: the sync says so,
    // and what is kept is still served.
    ledger::SeededEntropy entropy(5);
    auto republished = node::publish_record(m.dir, m.record, {}, entropy, m.clock);
    REQUIRE(republished);
    REQUIRE(archive->sync());
    REQUIRE(archive->published_bundle(republished->token));
    server.reset();
    auto gone = archive->sync();
    REQUIRE(gone);
    CHECK_FALSE(gone->synced);
    CHECK(gone->code == Errc::unavailable);
    state = node::load_archive_state(archive->directory());
    REQUIRE(state);
    CHECK(state->unreachable_since.has_value());
    CHECK_FALSE(state->last_error.empty());
    CHECK(verified(*archive->published_bundle(republished->token), m.id).revoked);
    const auto status = node::archives_status(trust, clock.now());
    REQUIRE(status);
    CHECK((*status)["count"] == 1);
    CHECK((*status)["unreachable"] == 1);
    CHECK((*status)["witnesses_post_quantum"] == false);

    // The service answers the archive's routes, for anyone.
    node::ArchiveService service(trust, provider());
    node::http::Request get;
    get.method = "GET";
    const std::string base = "/a/" + to_hex(m.id.bytes());
    get.path = base + "/c/" + republished->token;
    auto answer = service.handle(get);
    REQUIRE(answer);
    CHECK(answer->status == 200);
    CHECK(std::ranges::find(answer->headers,
                            std::pair<std::string, std::string>("Access-Control-Allow-Origin",
                                                                "*")) != answer->headers.end());
    CHECK(verified(answer->body, m.id).record == m.record);
    get.path = base + "/v1/checkpoint";
    REQUIRE(service.handle(get));
    CHECK(protocol::parse_checkpoint(service.handle(get)->body));
    get.path = base + "/v1/renewal";
    get.query = {{"from", std::to_string(first.checkpoint.tree_size)},
                 {"size", std::to_string(witnessed)}};
    answer = service.handle(get);
    REQUIRE(answer);
    CHECK(answer->status == 200);
    CHECK(protocol::decode_renewal(answer->body));
    get.query = {{"old", "1"}, {"new", std::to_string(archive->replica().size())}};
    get.path = base + "/v1/consistency";
    CHECK(service.handle(get)->status == 200);
    get.query.clear();
    get.path = "/a/" + std::string(64, 'c') + "/v1/checkpoint";
    CHECK(service.handle(get)->status == 404);
    get.path = base + "/v1/entries";
    CHECK(service.handle(get)->status == 404);
    get.path = "/v1/status";
    CHECK_FALSE(service.handle(get));
    get.method = "POST";
    get.path = base + "/v1/checkpoint";
    CHECK(service.handle(get)->status == 405);
    json status_body = json::object();
    service.status(status_body);
    CHECK(status_body["archives"]["count"] == 1);

    // Removed: nothing left.
    REQUIRE(node::remove_archive(trust, m.id));
    CHECK(node::archived_ledgers(trust).empty());
    CHECK_FALSE(node::archives_status(trust, clock.now()));
    std::filesystem::remove_all(trust);
}

TEST_CASE("re-attestation never moves a witness the member uses", "[node][archive]") {
    Member m;
    auto api = m.api();
    Running server(*api);
    const auto witness_dir = fresh_directory("witness");
    auto witness_key =
        std::make_shared<const KeyPair>(*KeyPair::generate(crypto::SigAlg::ml_dsa_65));
    WitnessApp witness_app(witness_dir, witness_key);
    Running witness(witness_app);
    const client::UsedWitness used{"test-witness", witness.url(), witness_key->public_key(), 0};
    const node::ArchiveConfig config{{{witness.url(), "test-witness", witness_key->public_key()}},
                                     {},
                                     std::chrono::seconds(3600),
                                     std::chrono::seconds(365LL * 86'400)};

    // The member registers with the witness, which cosigns its checkpoint.
    m.change([&](ledger::Ledger& l) {
        const Bytes cosignature =
            client::register_with_witness(l, witness.url(), witness_key->public_key());
        REQUIRE(l.add_cosignature(cosignature, witness_key->public_key()));
    });
    const auto trust = fresh_directory("trust-witness");
    ledger::SystemClock clock;
    auto created = node::ArchivedLedger::create(trust, m.id, source_of(server), clock, provider());
    REQUIRE(created);
    auto& archive = created->first;
    const std::uint64_t cosignatures = archive->replica().cosignature_count();
    CHECK(cosignatures == 1);

    // Not due: the member's cosignature is fresh.
    auto not_due = archive->attest(config, false);
    REQUIRE(not_due);
    CHECK_FALSE(not_due->due);
    // Forced: the witness has cosigned the latest checkpoint already (a
    // ledger keeps one cosignature per witness and checkpoint): it is not
    // asked, and nothing moves.
    auto again = archive->attest(config, true);
    REQUIRE(again);
    CHECK(again->due);
    REQUIRE(again->outcomes.size() == 1);
    INFO(again->outcomes[0].problem);
    CHECK(again->outcomes[0].already);
    CHECK_FALSE(again->outcomes[0].attested);
    CHECK(archive->replica().cosignature_count() == cosignatures);

    // The member checkpoints again, and the archive syncs before the member
    // asks the witness: the archive does not move it.
    m.change([&](ledger::Ledger& l) {
        m.submit(l, Member::document());
        REQUIRE(l.checkpoint(*m.log_key));
    });
    REQUIRE(archive->sync());
    auto left = archive->attest(config, true);
    REQUIRE(left);
    REQUIRE(left->outcomes.size() == 1);
    CHECK_FALSE(left->outcomes[0].attested);
    CHECK(left->outcomes[0].problem.find("never moves") != std::string::npos);
    // ...so the member's own request goes on as before.
    m.change([&](ledger::Ledger& l) {
        const auto cosignature = client::ask_witness(l, used);
        REQUIRE(cosignature);
        REQUIRE(l.add_cosignature(*cosignature, witness_key->public_key()));
        m.submit(l, Member::document());
        REQUIRE(l.checkpoint(*m.log_key));
        const auto next = client::ask_witness(l, used);
        REQUIRE(next);
        REQUIRE(l.add_cosignature(*next, witness_key->public_key()));
    });
    REQUIRE(archive->sync());
    auto later = archive->attest(config, true);
    REQUIRE(later);
    CHECK(later->outcomes[0].already);
    // And a witness the member does not use is registered and moved.
    const auto other_dir = fresh_directory("other-witness");
    auto other_key = std::make_shared<const KeyPair>(key("other witness"));
    WitnessApp other_app(other_dir, other_key);
    Running other(other_app);
    const node::ArchiveConfig both{{{witness.url(), "test-witness", witness_key->public_key()},
                                    {other.url(), "other", other_key->public_key()}},
                                   {},
                                   std::chrono::seconds(3600),
                                   std::chrono::seconds(365LL * 86'400)};
    auto registered = archive->attest(both, true);
    REQUIRE(registered);
    REQUIRE(registered->outcomes.size() == 2);
    CHECK(registered->outcomes[0].already);
    INFO(registered->outcomes[1].problem);
    CHECK(registered->outcomes[1].attested == archive->replica().size());
    CHECK(registered->outcomes[1].registered);
    m.change([&](ledger::Ledger& l) {
        m.submit(l, Member::document());
        REQUIRE(l.checkpoint(*m.log_key));
    });
    REQUIRE(archive->sync());
    auto moved = archive->attest(both, true);
    REQUIRE(moved);
    // The member's witness is left to the member; the other is moved on.
    CHECK(moved->outcomes[0].problem.find("never moves") != std::string::npos);
    INFO(moved->outcomes[1].problem);
    CHECK(moved->outcomes[1].attested == archive->replica().size());
    CHECK_FALSE(moved->outcomes[1].registered);
    // Kept beside the checkpoint, in the archive's renewals.
    const auto renewal = archive->replica().renewal(archive->replica().size());
    REQUIRE(renewal);
    CHECK(renewal->cosignatures.size() == 1);
    std::filesystem::remove_all(trust);
    std::filesystem::remove_all(witness_dir);
    std::filesystem::remove_all(other_dir);
}
