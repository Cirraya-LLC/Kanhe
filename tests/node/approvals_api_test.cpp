// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// Statements held for approval at a server (spec v0.20, section 16): POST
// /v1/approvals holds one until its rules are met, or registers it at once
// if it needs no approvals; GET lists them (for an approver, with what
// became of others, as a long poll); GET /v1/approvals/ID answers the
// approval file; POST /v1/approvals/ID takes one approval, checked as the
// ledger will, and registers the statement with the one that completes its
// rules; DELETE withdraws it. Held statements lapse with their windows, are
// dropped once they could no longer be registered, keep a list of the
// approvals that stopped verifying, and outlive a restart. A submission
// carries approvals in key 5.

#include <algorithm>
#include <atomic>
#include <chrono>
#include <filesystem>
#include <functional>
#include <future>
#include <memory>
#include <optional>
#include <string>
#include <thread>
#include <unistd.h>
#include <vector>

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>

#include <kanhe/core/protocol/approval_file.hpp>
#include <kanhe/core/protocol/approvals.hpp>
#include <kanhe/core/protocol/log.hpp>
#include <kanhe/core/protocol/presence.hpp>
#include <kanhe/core/protocol/record.hpp>
#include <kanhe/node/api.hpp>
#include <kanhe/node/approvals.hpp>
#include <kanhe/node/client.hpp>
#include <kanhe/node/server.hpp>
#include <kanhe/node/tokens.hpp>

#include "support/ledger_world.hpp"

namespace {

using namespace kanhe::test;
namespace node = kanhe::node;
using kanhe::Bytes;
using json = nlohmann::json;
using namespace std::chrono_literals;

/// The server's clock, which a test moves on (shared with the writer).
class TestClock final : public ledger::Clock {
public:
    explicit TestClock(protocol::Timestamp start) : now_(start) {}
    [[nodiscard]] protocol::Timestamp now() override { return now_.load(); }
    void advance(protocol::Timestamp ms) { now_.fetch_add(ms); }

private:
    std::atomic<protocol::Timestamp> now_;
};

std::filesystem::path fresh_directory() {
    static int counter = 0;
    const auto dir =
        std::filesystem::temp_directory_path() /
        ("kanhe-approvals-test-" + std::to_string(::getpid()) + "-" + std::to_string(counter++));
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
    [[nodiscard]] node::Client client(const std::string& token) const {
        node::ClientOptions o;
        o.bearer_token = token;
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

struct Person {
    std::string name;
    KeyPair key;
    KeyPair token;
    Bytes credential;
    protocol::Id id;
};

Person person(const std::string& name, std::uint8_t credential) {
    return Person{name, key(name), key(name + "'s token"), Bytes(32, credential), {}};
}

protocol::PresenceCredential token_credential(const Person& p) {
    return {"", p.credential, p.token.public_key(), std::string("token"),
            protocol::PresenceMethod::hardware_key};
}

bool before(const protocol::Id& a, const protocol::Id& b) {
    return std::ranges::lexicographical_compare(a.bytes(), b.bytes());
}

std::string hex_id(const protocol::Id& id) {
    return kanhe::to_hex(id.bytes());
}

/// An office: Wong Siu Ming, a clerk whose records need 2 of Chan, Lee, and
/// Ho within 7 days; Pat, whose records need none. Each person has a
/// hardware key to prove presence with. Tokens: staff (read, submit), an
/// admin, and a reader.
struct Office {
    std::filesystem::path dir = fresh_directory();
    TestClock clock{t0};
    ledger::SeededEntropy entropy{61};
    KeyPair org = key("approvals office org");
    std::shared_ptr<const KeyPair> log_key =
        std::make_shared<const KeyPair>(key("approvals office log"));
    Person clerk = person("Wong Siu Ming", 1);
    Person chan = person("Chan Tai Man", 2);
    Person lee = person("Lee Ka Yan", 3);
    Person ho = person("Ho Wing", 4);
    Person pat = person("Pat", 5);
    protocol::Id id;
    protocol::Id clerk_delegation;
    protocol::Id free_delegation;
    std::string staff = "staff-token-0123456789";
    std::string admin = "admin-token-0123456789";
    std::string reader = "reader-token-0123456789";

    Office() {
        auto fs = ledger::PosixFileSystem::open_directory(dir);
        REQUIRE(fs);
        protocol::Statement genesis;
        genesis.issued_at = clock.now();
        genesis.nonce = entropy.bytes<16>();
        genesis.body = protocol::GenesisBody{crypto::HashAlg::sha256, "Approvals Office",
                                             org.public_key(), log_key->public_key()};
        auto signed_genesis =
            protocol::sign_statement(org, provider(), crypto::HashAlg::sha256, genesis);
        REQUIRE(signed_genesis);
        auto ledger = ledger::Ledger::create(*fs, clock, provider(), signed_genesis->encoded);
        REQUIRE(ledger);
        id = ledger->id();
        auto ok = [&](protocol::Body body) {
            auto r = ledger->submit(sign(org, id, std::nullopt, std::move(body)).encoded);
            INFO((r ? std::string() : std::string(r.error().detail)));
            REQUIRE(r);
            clock.advance(1000);
            return r->statement_id;
        };
        for (Person* p : {&clerk, &chan, &lee, &ho, &pat}) {
            p->id =
                ok(protocol::ActorRegisterBody{protocol::ActorKind::person, p->name,
                                               p->key.public_key(), std::nullopt, std::nullopt});
            ok(protocol::ActorSetPresenceBody{p->id, {token_credential(*p)}});
        }
        auto ruled =
            scope({StatementType::record_register}, std::vector<std::string>{document_type});
        protocol::ApprovalRule rule;
        rule.needed = 2;
        rule.approvers = {chan.id, lee.id, ho.id};
        std::ranges::sort(rule.approvers, before);
        rule.within = 7 * day;
        ruled.approvals = rule;
        clerk_delegation = ok(protocol::DelegationGrantBody{clerk.id, ruled});
        free_delegation = ok(
            protocol::DelegationGrantBody{pat.id, scope({StatementType::record_register},
                                                        std::vector<std::string>{document_type})});
        REQUIRE(ledger->checkpoint(*log_key));
        auto s = [](node::Scope scope) {
            return static_cast<node::Scopes>(scope);
        };
        REQUIRE(node::save_tokens(
            dir,
            {{"staff", static_cast<node::Scopes>(s(node::Scope::read) | s(node::Scope::submit)),
              node::token_hash(provider(), staff), t0},
             {"admin",
              static_cast<node::Scopes>(s(node::Scope::read) | s(node::Scope::submit) |
                                        s(node::Scope::admin)),
              node::token_hash(provider(), admin), t0},
             {"reader", s(node::Scope::read), node::token_hash(provider(), reader), t0}}));
    }
    Office(const Office&) = delete;
    Office& operator=(const Office&) = delete;
    ~Office() { std::filesystem::remove_all(dir); }

    protocol::SignedStatement sign(const KeyPair& signer, const protocol::Id& actor,
                                   std::optional<protocol::Id> delegation, protocol::Body body,
                                   const Person* in_person = nullptr) {
        protocol::Statement st;
        st.ledger_id = id;
        st.actor_id = actor;
        st.delegation_id = std::move(delegation);
        st.issued_at = clock.now();
        st.nonce = entropy.bytes<16>();
        st.body = std::move(body);
        if (in_person != nullptr) {
            const auto kid =
                protocol::key_id(provider(), crypto::HashAlg::sha256, signer.public_key());
            REQUIRE(kid);
            const auto challenge =
                protocol::presence_challenge(provider(), crypto::HashAlg::sha256, st, *kid);
            REQUIRE(challenge);
            st.presence = protocol::PresenceProof{
                in_person->credential, {}, {}, *in_person->token.sign(*challenge)};
        }
        auto signed_statement =
            protocol::sign_statement(signer, provider(), crypto::HashAlg::sha256, st);
        REQUIRE(signed_statement);
        return std::move(*signed_statement);
    }

    protocol::SignedStatement record(const Person& who, const protocol::Id& delegation) {
        return sign(who.key, who.id, delegation,
                    protocol::RecordRegisterBody{
                        document_type, Bytes(32, 0x42), 3, {}, std::nullopt, std::nullopt, {}});
    }

    /// `p`'s approval of `statement`, signed with `signing` (its key by
    /// default), in person with its hardware key unless not.
    Bytes approve(const Person& p, const protocol::Id& statement, bool in_person = true,
                  const KeyPair* signing = nullptr) {
        const KeyPair& with = signing != nullptr ? *signing : p.key;
        protocol::Approval a{id, p.id, statement, clock.now(), std::nullopt};
        const auto kid = protocol::key_id(provider(), crypto::HashAlg::sha256, with.public_key());
        REQUIRE(kid);
        if (in_person) {
            const auto challenge =
                protocol::approval_challenge(provider(), crypto::HashAlg::sha256, a, *kid);
            REQUIRE(challenge);
            a.presence = protocol::PresenceProof{p.credential, {}, {}, *p.token.sign(*challenge)};
        }
        auto signed_approval =
            protocol::sign_approval(with, provider(), crypto::HashAlg::sha256, a);
        REQUIRE(signed_approval);
        return signed_approval->encoded;
    }

    std::unique_ptr<node::LedgerApi> api() {
        node::ApiOptions o;
        o.directory = dir;
        o.log_keys = {log_key};
        o.clock = &clock;
        auto opened = node::LedgerApi::open(o, provider());
        REQUIRE(opened);
        return std::move(*opened);
    }
};

Bytes hold_request(const protocol::SignedStatement& s,
                   std::vector<protocol::RecordField> fields = {}) {
    node::HeldStatement held;
    held.statement = s.encoded;
    held.fields = std::move(fields);
    auto encoded = node::encode_hold_request(held);
    REQUIRE(encoded);
    return std::move(*encoded);
}

node::http::ClientResponse get(const node::Client& c, const std::string& path) {
    auto r = c.request("GET", path);
    REQUIRE(r);
    return std::move(*r);
}

node::http::ClientResponse post(const node::Client& c, const std::string& path, const Bytes& body,
                                std::string_view type = "application/cose") {
    auto r = c.request("POST", path, body, type);
    REQUIRE(r);
    return std::move(*r);
}

node::http::ClientResponse hold(const node::Client& c, const Bytes& body) {
    return post(c, "/v1/approvals", body, "application/cbor");
}

node::http::ClientResponse withdraw(const node::Client& c, const std::string& path) {
    auto r = c.request("DELETE", path);
    REQUIRE(r);
    return std::move(*r);
}

json body_json(const node::http::ClientResponse& r) {
    return json::parse(r.body.begin(), r.body.end());
}

/// Waits up to ten seconds for `done` (the server sweeps every two).
bool eventually(const std::function<bool()>& done) {
    for (int i = 0; i < 100; ++i) {
        if (done()) {
            return true;
        }
        std::this_thread::sleep_for(100ms);
    }
    return false;
}

/// The held statement listed with `id` (state=all), if any.
std::optional<json> listed(const node::Client& c, const std::string& id) {
    for (const json& item : body_json(get(c, "/v1/approvals?state=all"))["approvals"]) {
        if (item["id"] == id) {
            return std::optional<json>(std::in_place, item);
        }
    }
    return std::nullopt;
}

} // namespace

TEST_CASE("a statement held for approval is registered with the approval that completes its "
          "rules",
          "[node][approvals]") {
    Office office;
    const auto api = office.api();
    const Running running(*api);
    const auto staff = running.client(office.staff);
    const auto statement = office.record(office.clerk, office.clerk_delegation);
    const std::string id = hex_id(statement.id);

    // Alone, it is refused: its delegation's rule needs two approvals.
    CHECK(post(staff, "/v1/statements", statement.encoded).status == 409);

    // Held: its rules, what is missing, and when it lapses.
    auto held = hold(staff, hold_request(statement));
    REQUIRE(held.status == 202);
    json body = body_json(held);
    CHECK(body["id"] == id);
    CHECK(body["state"] == "open");
    CHECK(body["type"] == "record-register");
    CHECK(body["signer"]["name"] == "Wong Siu Ming");
    REQUIRE(body["rules"].size() == 1);
    CHECK(body["rules"][0]["source"] == "delegation");
    CHECK(body["rules"][0]["delegation"] == hex_id(office.clerk_delegation));
    CHECK(body["rules"][0]["k"] == 2);
    CHECK(body["rules"][0]["approvers"].size() == 3);
    CHECK(body["rules"][0]["within_ms"] == 7 * day);
    CHECK(body["rules"][0]["without_presence"] == false);
    CHECK(body["missing"] == json::array({2}));
    CHECK(body["lapses_at"] == statement.statement.issued_at + 7 * day);
    CHECK(body["preparer"] == "staff");
    // Sent again: answered as it stands.
    CHECK(hold(staff, hold_request(statement)).status == 202);

    // Listed, for those who may approve it; never for its signer.
    CHECK(body_json(get(staff, "/v1/approvals"))["approvals"].size() == 1);
    CHECK(body_json(get(staff, "/v1/approvals?approver=" + hex_id(office.chan.id)))["approvals"]
              .size() == 1);
    CHECK(body_json(get(staff, "/v1/approvals?approver=" + hex_id(office.clerk.id)))["approvals"]
              .empty());
    CHECK(body_json(get(staff, "/v1/approvals?approver=" + hex_id(office.pat.id)))["approvals"]
              .empty());
    for (const std::string query : {"state=some", "wait=26", "approver=12", "since=3"}) {
        CHECK(get(staff, "/v1/approvals?" + query).status == 400);
    }

    // Its approval file: the statement, no approval yet.
    auto file = get(staff, "/v1/approvals/" + id);
    REQUIRE(file.status == 200);
    auto decoded = protocol::decode_approval_file(provider(), file.body);
    REQUIRE(decoded);
    CHECK(decoded->statement.id == statement.id);
    CHECK(decoded->approvals.empty());
    CHECK(get(staff, "/v1/approvals/" + std::string(64, 'a')).status == 404);
    CHECK(get(staff, "/v1/approvals/xyz").status == 400);

    // One approval: one more needed. The same bytes again are a retry;
    // another of Chan's is refused.
    const Bytes chan = office.approve(office.chan, statement.id);
    auto first = post(staff, "/v1/approvals/" + id, chan);
    REQUIRE(first.status == 202);
    CHECK(body_json(first)["missing"] == json::array({1}));
    REQUIRE(body_json(first)["approvals"].size() == 1);
    CHECK(body_json(first)["approvals"][0]["presence"] == "hardware-key");
    CHECK(body_json(first)["approvals"][0]["user_verified"] == true);
    CHECK(body_json(first)["approvals"][0]["counts_for"] == json::array({0}));
    CHECK(post(staff, "/v1/approvals/" + id, chan).status == 202);
    office.clock.advance(1000);
    CHECK(post(staff, "/v1/approvals/" + id, office.approve(office.chan, statement.id)).status ==
          409);
    // Refused: an actor no rule names, an approval without presence, one of
    // another statement, and from a reader's token.
    CHECK(post(staff, "/v1/approvals/" + id, office.approve(office.pat, statement.id)).status ==
          409);
    CHECK(post(staff, "/v1/approvals/" + id, office.approve(office.lee, statement.id, false))
              .status == 409);
    const auto other = office.record(office.clerk, office.clerk_delegation);
    CHECK(post(staff, "/v1/approvals/" + id, office.approve(office.lee, other.id)).status == 409);
    CHECK(post(running.client(office.reader), "/v1/approvals/" + id,
               office.approve(office.lee, statement.id))
              .status == 403);
    CHECK(post(staff, "/v1/approvals/" + id, Bytes{0x01, 0x02}).status == 400);

    // The second completes the rule: registered with both, by approver.
    auto completed = post(staff, "/v1/approvals/" + id, office.approve(office.lee, statement.id));
    REQUIRE(completed.status == 201);
    CHECK(body_json(completed)["statement_id"] == id);
    const std::uint64_t index = body_json(completed)["index"].get<std::uint64_t>();
    auto entry_bytes = api->ledger().entry(index);
    REQUIRE(entry_bytes);
    auto entry = protocol::decode_log_entry(*entry_bytes);
    REQUIRE(entry);
    CHECK(entry->statement_id == statement.id);
    REQUIRE(entry->approvals.size() == 2);
    auto sorted = protocol::sort_approvals(entry->approvals);
    REQUIRE(sorted);
    std::vector<protocol::Id> approvers{office.chan.id, office.lee.id};
    std::ranges::sort(approvers, before);
    CHECK((*sorted)[0].approval.approver == approvers[0]);
    CHECK((*sorted)[1].approval.approver == approvers[1]);
    CHECK(std::ranges::equal(entry->approvals[0], (*sorted)[0].encoded));

    // Held no more: what became of it is listed, with its log index.
    CHECK(eventually([&] { return body_json(get(staff, "/v1/approvals"))["approvals"].empty(); }));
    REQUIRE(eventually([&] {
        const auto item = listed(staff, id);
        return item && (*item)["state"] == "registered";
    }));
    CHECK((*listed(staff, id))["index"] == index);
    CHECK(get(staff, "/v1/approvals/" + id).status == 404);
}

TEST_CASE("statements are held only as the ledger would take them, and lapse or are withdrawn",
          "[node][approvals]") {
    Office office;
    const auto api = office.api();
    const Running running(*api);
    const auto staff = running.client(office.staff);
    const auto admin = running.client(office.admin);

    // One no rule applies to is registered at once.
    const auto free = office.record(office.pat, office.free_delegation);
    CHECK(hold(staff, hold_request(free)).status == 201);
    CHECK(api->ledger().state().statement_index(free.id).has_value());

    // Refused: what the ledger refuses whatever its approvals (the clerk
    // under Pat's delegation), what is no hold request, and a reader's.
    CHECK(hold(staff, hold_request(office.record(office.clerk, office.free_delegation))).status ==
          409);
    CHECK(hold(staff, Bytes{0xa1, 0x09, 0x01}).status == 400);
    CHECK(hold(staff, Bytes{0x01}).status == 400);
    CHECK(hold(running.client(office.reader),
               hold_request(office.record(office.clerk, office.clerk_delegation)))
              .status == 403);

    // Fields shown are every field of the record, and give its field root.
    std::vector<protocol::RecordField> fields{
        {"amount", office.entropy.bytes<16>(), cbor::Value::text("1200")},
        {"payee", office.entropy.bytes<16>(), cbor::Value::text("Lee Ka Yan")}};
    auto commitment = protocol::commit_fields(provider(), crypto::HashAlg::sha256, fields);
    REQUIRE(commitment);
    const auto shown =
        office.sign(office.clerk.key, office.clerk.id, office.clerk_delegation,
                    protocol::RecordRegisterBody{
                        document_type,
                        Bytes(commitment->root.bytes().begin(), commitment->root.bytes().end()),
                        commitment->leaves.size(),
                        {},
                        std::nullopt,
                        std::nullopt,
                        {}});
    auto altered = commitment->fields;
    altered[0].value = cbor::Value::text("9999");
    CHECK(hold(staff, hold_request(shown, altered)).status == 422);
    CHECK(hold(staff, hold_request(shown, {commitment->fields[0]})).status == 409);
    auto with_fields = hold(staff, hold_request(shown, commitment->fields));
    REQUIRE(with_fields.status == 202);
    CHECK(body_json(with_fields)["fields_shown"] == true);
    auto file = protocol::decode_approval_file(
        provider(), get(staff, "/v1/approvals/" + hex_id(shown.id)).body);
    REQUIRE(file);
    CHECK(file->fields == commitment->fields);

    // Withdrawn: by an admin's token, once.
    const std::string path = "/v1/approvals/" + hex_id(shown.id);
    CHECK(withdraw(staff, path).status == 403);
    CHECK(withdraw(admin, path).status == 204);
    CHECK(withdraw(admin, path).status == 404);
    CHECK(post(staff, path, office.approve(office.chan, shown.id)).status == 404);
    const auto withdrawn = listed(staff, hex_id(shown.id));
    REQUIRE(withdrawn);
    CHECK((*withdrawn)["state"] == "withdrawn");
    // Its fields went with it.
    CHECK((*withdrawn)["fields_shown"] == false);

    // Past its window, it is held no more.
    const auto late = office.record(office.clerk, office.clerk_delegation);
    REQUIRE(hold(staff, hold_request(late)).status == 202);
    office.clock.advance(7 * day + 60'000);
    REQUIRE(eventually([&] {
        const auto item = listed(staff, hex_id(late.id));
        return item && (*item)["state"] == "lapsed";
    }));
    CHECK(post(staff, "/v1/approvals/" + hex_id(late.id), office.approve(office.chan, late.id))
              .status == 404);
}

TEST_CASE("an approval that stops verifying is dropped and listed, and its approver approves "
          "again",
          "[node][approvals]") {
    Office office;
    const auto api = office.api();
    const Running running(*api);
    const auto staff = running.client(office.staff);
    const auto statement = office.record(office.clerk, office.clerk_delegation);
    const std::string id = hex_id(statement.id);
    REQUIRE(hold(staff, hold_request(statement)).status == 202);
    REQUIRE(post(staff, "/v1/approvals/" + id, office.approve(office.chan, statement.id)).status ==
            202);

    // Chan rotates its own key, in person: its approval dies with the old one.
    const KeyPair fresh = key("Chan Tai Man's new key");
    const auto rotation =
        office.sign(office.chan.key, office.chan.id, std::nullopt,
                    protocol::ActorRotateKeyBody{office.chan.id, fresh.public_key()}, &office.chan);
    REQUIRE(post(staff, "/v1/statements", rotation.encoded).status == 201);
    REQUIRE(eventually([&] {
        const auto item = listed(staff, id);
        return item && (*item)["approvals"].empty() && (*item)["dropped"].size() == 1;
    }));
    const auto item = listed(staff, id);
    CHECK((*item)["dropped"][0]["approver"]["id"] == hex_id(office.chan.id));
    CHECK((*item)["missing"] == json::array({2}));

    // Approved again with the new key, and by Ho: registered.
    REQUIRE(
        post(staff, "/v1/approvals/" + id, office.approve(office.chan, statement.id, true, &fresh))
            .status == 202);
    CHECK(post(staff, "/v1/approvals/" + id, office.approve(office.ho, statement.id)).status ==
          201);
}

TEST_CASE("a submission carries a statement's approvals in key 5", "[node][approvals]") {
    Office office;
    const auto api = office.api();
    const Running running(*api);
    const auto staff = running.client(office.staff);
    const auto statement = office.record(office.clerk, office.clerk_delegation);
    const std::vector<Bytes> approvals{office.approve(office.ho, statement.id),
                                       office.approve(office.chan, statement.id)};
    auto submission = [](const protocol::SignedStatement& s, const std::vector<Bytes>& list) {
        auto encoded = cbor::encode(
            cbor::Value::map({{cbor::Value::integer(1), cbor::Value::bytes(s.encoded)},
                              {cbor::Value::integer(5), protocol::approval_list_value(list)}}));
        REQUIRE(encoded);
        return std::move(*encoded);
    };
    // One approval is not enough; an approval no rule asks for refuses it.
    CHECK(post(staff, "/v1/statements", submission(statement, {approvals[0]}),
               node::submission_content_type)
              .status == 409);
    const auto free = office.record(office.pat, office.free_delegation);
    CHECK(post(staff, "/v1/statements", submission(free, {office.approve(office.chan, free.id)}),
               node::submission_content_type)
              .status == 409);
    // Not a list of approvals: refused before anything else.
    auto bad = cbor::encode(
        cbor::Value::map({{cbor::Value::integer(1), cbor::Value::bytes(statement.encoded)},
                          {cbor::Value::integer(5), cbor::Value::text("approvals")}}));
    REQUIRE(bad);
    CHECK(post(staff, "/v1/statements", *bad, node::submission_content_type).status == 400);

    // Both: registered, kept in its log entry by approver.
    auto registered = post(staff, "/v1/statements", submission(statement, approvals),
                           node::submission_content_type);
    REQUIRE(registered.status == 201);
    auto entry_bytes = api->ledger().entry(body_json(registered)["index"].get<std::uint64_t>());
    REQUIRE(entry_bytes);
    auto entry = protocol::decode_log_entry(*entry_bytes);
    REQUIRE(entry);
    REQUIRE(entry->approvals.size() == 2);
    auto first = protocol::parse_approval(entry->approvals[0]);
    auto second = protocol::parse_approval(entry->approvals[1]);
    REQUIRE(first);
    REQUIRE(second);
    CHECK(before(first->approval.approver, second->approval.approver));
}

TEST_CASE("a long poll of the held statements ends once one is held, and they outlive a restart",
          "[node][approvals]") {
    Office office;
    const auto statement = office.record(office.clerk, office.clerk_delegation);
    const std::string id = hex_id(statement.id);
    {
        const auto api = office.api();
        const Running running(*api);
        const auto staff = running.client(office.staff);
        auto waiting = std::async(std::launch::async, [&] {
            const auto t = std::chrono::steady_clock::now();
            auto r = staff.request("GET", "/v1/approvals?wait=10");
            return std::pair(std::move(r), std::chrono::steady_clock::now() - t);
        });
        std::this_thread::sleep_for(300ms);
        CHECK(waiting.wait_for(0ms) == std::future_status::timeout);
        REQUIRE(hold(staff, hold_request(statement)).status == 202);
        auto [result, waited] = waiting.get();
        REQUIRE(result);
        REQUIRE(result->status == 200);
        CHECK(body_json(*result)["approvals"].size() == 1);
        CHECK(waited < 5s);
        REQUIRE(
            post(staff, "/v1/approvals/" + id, office.approve(office.lee, statement.id)).status ==
            202);
    }
    // Restarted: still held, with its approval.
    const auto api = office.api();
    const Running running(*api);
    const auto staff = running.client(office.staff);
    const json list = body_json(get(staff, "/v1/approvals"));
    REQUIRE(list["approvals"].size() == 1);
    CHECK(list["approvals"][0]["approvals"].size() == 1);
    CHECK(list["approvals"][0]["approvals"][0]["approver"]["name"] == "Lee Ka Yan");
    CHECK(post(staff, "/v1/approvals/" + id, office.approve(office.ho, statement.id)).status ==
          201);
}
