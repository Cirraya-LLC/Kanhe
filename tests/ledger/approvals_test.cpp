// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// Approvals and guardians (spec v0.20): a delegation that needs k of n named
// people to approve each statement under it, every rule in a chain, the
// signer counting; the organization's guardians, set by the new ones,
// changed by both sets, removed, guarding everything or a list and always
// the keys and themselves; approvers' keys protected; and the evidence,
// which carries every approver whole and the guardians in effect.

#include <algorithm>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>

#include <kanhe/core/merkle.hpp>
#include <kanhe/core/protocol/approvals.hpp>
#include <kanhe/core/protocol/evidence.hpp>
#include <kanhe/core/protocol/presence.hpp>
#include <kanhe/core/protocol/witness.hpp>
#include <kanhe/verifier/report.hpp>

#include "support/authenticator.hpp"
#include "support/ledger_world.hpp"
#include "support/vectors.hpp"

using namespace kanhe::test;
using kanhe::Bytes;
using kanhe::Errc;

namespace {

/// A person with a hardware key (a token, unlocked with its PIN) to prove
/// presence with.
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

SoftPasskey touch_only(std::uint8_t id) {
    auto generated = KeyPair::generate(crypto::SigAlg::esp256);
    REQUIRE(generated);
    auto shared = std::make_shared<const KeyPair>(std::move(*generated));
    SoftPasskey p;
    p.public_key = shared->public_key();
    p.key = shared;
    p.credential_id = Bytes(16, id);
    p.flags = 0x01; // present, not verified
    return p;
}

/// How an approver approves.
enum class Way : std::uint8_t {
    in_person, ///< with its hardware key: user-verified
    key_only,  ///< its signing key alone
    touch,     ///< a passkey that saw someone, not who
};

bool before(const protocol::Id& a, const protocol::Id& b) {
    return std::ranges::lexicographical_compare(a.bytes(), b.bytes());
}

/// An office: a clerk whose records need 2 of Chan, Lee, and Ho within 7
/// days; Pat and Quinn, people too; Ho also has a passkey that only reports
/// presence.
struct Office {
    World w;
    Person clerk = person("Wong Siu Ming", 1);
    Person chan = person("Chan Tai Man", 2);
    Person lee = person("Lee Ka Yan", 3);
    Person ho = person("Ho Wing", 4);
    Person pat = person("Pat", 5);
    Person quinn = person("Quinn", 6);
    SoftPasskey ho_touch = touch_only(7);
    protocol::Id clerk_delegation;

    Office() {
        for (Person* p : {&clerk, &chan, &lee, &ho, &pat, &quinn}) {
            enrol(*p);
        }
        protocol::PresenceCredential touch{ho_touch.rp_id, ho_touch.credential_id,
                                           ho_touch.public_key, std::string("passkey")};
        w.ok(w.org(), w.statement(w.org_id(), std::nullopt,
                                  protocol::ActorSetPresenceBody{
                                      ho.id, {token_credential(ho), std::move(touch)}}));
        clerk_delegation = grant(clerk, named(2, {&chan, &lee, &ho}));
    }

    void enrol(Person& p) {
        p.id = w.ok(w.org(), w.statement(w.org_id(), std::nullopt,
                                         protocol::ActorRegisterBody{protocol::ActorKind::person,
                                                                     p.name, p.key.public_key(),
                                                                     std::nullopt, std::nullopt}));
        w.ok(w.org(), w.statement(w.org_id(), std::nullopt,
                                  protocol::ActorSetPresenceBody{p.id, {token_credential(p)}}));
    }

    static protocol::ApprovalRule named(std::uint64_t k, std::vector<const Person*> people,
                                        protocol::Timestamp within = 7 * day) {
        protocol::ApprovalRule rule;
        rule.needed = k;
        for (const Person* p : people) {
            rule.approvers.push_back(p->id);
        }
        std::ranges::sort(rule.approvers, before);
        rule.within = within;
        return rule;
    }

    protocol::Id grant(const Person& to, std::optional<protocol::ApprovalRule> rule,
                       std::vector<StatementType> types = {StatementType::record_register}) {
        auto s = scope(std::move(types), std::vector<std::string>{document_type});
        s.approvals = std::move(rule);
        return w.grant(w.org(), w.org_id(), std::nullopt, to.id, std::move(s));
    }

    protocol::SignedStatement sign(const KeyPair& signer, const protocol::Statement& s) {
        auto out = protocol::sign_statement(signer, provider(), w.hash(), s);
        REQUIRE(out);
        return std::move(*out);
    }

    /// The statement with the person's proof of presence, user-verified.
    protocol::Statement in_person(const Person& p, protocol::Statement s) {
        const auto kid = protocol::key_id(provider(), w.hash(), p.key.public_key());
        REQUIRE(kid);
        const auto challenge = protocol::presence_challenge(provider(), w.hash(), s, *kid);
        REQUIRE(challenge);
        s.presence = protocol::PresenceProof{p.credential, {}, {}, *p.token.sign(*challenge)};
        return s;
    }

    protocol::SignedStatement record(const std::string& type = document_type) {
        return sign(clerk.key, w.statement(clerk.id, clerk_delegation, w.record_body(type)));
    }

    Bytes approve(const Person& p, const protocol::Id& statement, Way way = Way::in_person,
                  std::optional<protocol::Timestamp> at = std::nullopt,
                  std::optional<protocol::Id> on_ledger = std::nullopt) {
        protocol::Approval a{on_ledger.value_or(w.org_id()), p.id, statement,
                             at.value_or(w.clock().now()), std::nullopt};
        const auto kid = protocol::key_id(provider(), w.hash(), p.key.public_key());
        REQUIRE(kid);
        const auto challenge = protocol::approval_challenge(provider(), w.hash(), a, *kid);
        REQUIRE(challenge);
        if (way == Way::in_person) {
            a.presence = protocol::PresenceProof{p.credential, {}, {}, *p.token.sign(*challenge)};
        } else if (way == Way::touch) {
            a.presence = ho_touch.sign(provider(), *challenge);
        }
        auto signed_approval = protocol::sign_approval(p.key, provider(), w.hash(), a);
        REQUIRE(signed_approval);
        return signed_approval->encoded;
    }

    Bytes approve(const Person& p, const protocol::SignedStatement& s, Way way = Way::in_person) {
        return approve(p, s.id, way);
    }

    kanhe::Result<ledger::Registration> submit(const protocol::SignedStatement& s,
                                               const std::vector<Bytes>& approvals) {
        auto r = w.ledger().submit(s.encoded, approvals);
        if (r) {
            w.clock().advance(1000);
        }
        return r;
    }

    protocol::Id ok(const protocol::SignedStatement& s, const std::vector<Bytes>& approvals) {
        auto r = submit(s, approvals);
        INFO((r ? std::string() : std::string(r.error().detail)));
        REQUIRE(r);
        CHECK(r->newly_registered);
        return r->statement_id;
    }

    Errc refused(const protocol::SignedStatement& s, const std::vector<Bytes>& approvals) {
        auto r = submit(s, approvals);
        REQUIRE_FALSE(r);
        return r.error().code;
    }

    /// The organization's statement, signed with `root`.
    protocol::SignedStatement by_org(protocol::Body body, const KeyPair* root = nullptr) {
        return sign(root != nullptr ? *root : w.org(),
                    w.statement(w.org_id(), std::nullopt, std::move(body)));
    }

    /// Guardians set: `rule`, approved by `approvers` of the new ones.
    void set_guardians(const protocol::ApprovalRule& rule, std::vector<const Person*> approvers,
                       std::optional<std::vector<StatementType>> guarded = std::nullopt) {
        const auto s = by_org(protocol::LedgerSetGuardiansBody{rule, std::move(guarded)});
        std::vector<Bytes> approvals;
        for (const Person* p : approvers) {
            approvals.push_back(approve(*p, s));
        }
        ok(s, approvals);
    }

    /// Every approval of `people`, in person, of `s`.
    std::vector<Bytes> all(const protocol::SignedStatement& s, std::vector<const Person*> people) {
        std::vector<Bytes> out;
        for (const Person* p : people) {
            out.push_back(approve(*p, s));
        }
        return out;
    }

    protocol::EvidenceBundle exported(const protocol::Id& record, const KeyPair* log = nullptr) {
        REQUIRE(w.ledger().checkpoint(log != nullptr ? *log : w.log_key()));
        auto bundle = w.ledger().export_evidence(log != nullptr ? *log : w.log_key(), record);
        REQUIRE(bundle);
        return std::move(*bundle);
    }
};

kanhe::Result<protocol::EvidenceReport> verify(const protocol::EvidenceBundle& bundle) {
    return protocol::verify_bundle(provider(), *protocol::encode_bundle(bundle));
}

std::uint64_t leaf_of(const protocol::EvidenceEntry& e) {
    return protocol::parse_receipt(e.receipt)->proof.leaf_index;
}

/// The bundle a dishonest operator holding the log key could make: the
/// entry at `index` replaced, the tree, every receipt, and the checkpoint
/// made again. Only the replay can catch it.
protocol::EvidenceBundle reforged_with(World& w, const protocol::EvidenceBundle& bundle,
                                       std::uint64_t index, const Bytes& replacement,
                                       const KeyPair& log_key) {
    const auto checkpoint = protocol::parse_checkpoint(bundle.checkpoint);
    REQUIRE(checkpoint);
    const std::uint64_t size = checkpoint->checkpoint.tree_size;
    kanhe::merkle::Tree tree(provider(), w.hash());
    for (std::uint64_t i = 0; i < size; ++i) {
        const auto entry = w.ledger().entry(i);
        REQUIRE(entry);
        REQUIRE(tree.append(i == index ? replacement : *entry));
    }
    const auto root = tree.root(size);
    REQUIRE(root);
    protocol::Checkpoint c = checkpoint->checkpoint;
    c.root = *root;
    const auto signed_checkpoint = protocol::sign_checkpoint(log_key, provider(), c);
    REQUIRE(signed_checkpoint);
    protocol::EvidenceBundle out = bundle;
    out.checkpoint = signed_checkpoint->encoded;
    out.cosignatures.clear();
    out.anchors.clear();
    for (protocol::EvidenceEntry& e : out.entries) {
        const std::uint64_t leaf = leaf_of(e);
        if (leaf == index) {
            e.entry = replacement;
        }
        const auto path = tree.inclusion_proof(leaf, size);
        REQUIRE(path);
        const auto receipt = protocol::issue_receipt(log_key, provider(), w.hash(), *root,
                                                     protocol::InclusionProof{size, leaf, *path});
        REQUIRE(receipt);
        e.receipt = *receipt;
    }
    return out;
}

} // namespace

TEST_CASE("a statement under a rule is registered with k approvals, not fewer",
          "[approvals][ledger]") {
    Office o;
    const auto first = o.record();
    CHECK(o.refused(first, {o.approve(o.chan, first)}) == Errc::rejected);
    CHECK(o.refused(first, {}) == Errc::rejected);
    // In any order: the ledger keeps them ascending by approver.
    const auto id = o.ok(first, {o.approve(o.lee, first), o.approve(o.chan, first)});
    const auto index = o.w.ledger().statement_index(id);
    REQUIRE(index);
    const auto entry = protocol::decode_log_entry(*o.w.ledger().entry(*index));
    REQUIRE(entry);
    const auto approvers = protocol::approvers_of(*entry);
    REQUIRE(approvers.size() == 2);
    CHECK(before(approvers[0], approvers[1]));
    // Submitted again, it is found as it is.
    const auto again = o.w.ledger().submit(first.encoded);
    REQUIRE(again);
    CHECK_FALSE(again->newly_registered);

    // More than k is fine; every one must verify.
    const auto second = o.record();
    o.ok(second, o.all(second, {&o.chan, &o.lee, &o.ho}));

    // The rules that apply, and the tally a server would show.
    const auto third = o.record();
    const auto& state = o.w.ledger().state();
    const auto rules = state.approval_rules(third.statement);
    REQUIRE(rules.size() == 1);
    CHECK(rules[0].source == protocol::RuleSource::delegation);
    CHECK(rules[0].delegation == o.clerk_delegation);
    std::vector<protocol::SignedApproval> one{*protocol::parse_approval(o.approve(o.ho, third))};
    const auto tally = state.check_approvals(provider(), third, one, o.w.clock().now());
    REQUIRE(tally);
    REQUIRE(tally->rules.size() == 1);
    CHECK(tally->rules[0].missing() == 1);
    CHECK(tally->rules[0].lapses_at == third.statement.issued_at + 7 * day);
    CHECK_FALSE(tally->met(o.w.clock().now()));
    // Held statements are checked on every rule but approvals.
    CHECK(state.validate_held(provider(), third, o.w.clock().now()));
    CHECK_FALSE(state.validate(provider(), third, o.w.clock().now()));
}

TEST_CASE("approvals lapse when the rule's window from the issue time ends",
          "[approvals][ledger]") {
    Office o;
    const auto late = o.record();
    auto approvals = o.all(late, {&o.chan, &o.lee});
    o.w.clock().advance(7 * day + 1);
    CHECK(o.refused(late, approvals) == Errc::rejected);

    const auto on_time = o.record();
    approvals = o.all(on_time, {&o.chan, &o.lee});
    o.w.clock().advance(7 * day);
    o.ok(on_time, approvals);
}

TEST_CASE("an approval is a named, unrevoked approver's, with its current key, for this "
          "statement, once",
          "[approvals][ledger][security]") {
    Office o;
    SECTION("not an approver, and not the signer") {
        const auto s = o.record();
        CHECK(o.refused(s, {o.approve(o.chan, s), o.approve(o.pat, s)}) == Errc::rejected);
        CHECK(o.refused(s, {o.approve(o.chan, s), o.approve(o.clerk, s)}) == Errc::rejected);
    }
    SECTION("for another statement, or another ledger") {
        const auto s = o.record();
        const auto other = o.record();
        CHECK(o.refused(s, {o.approve(o.chan, s), o.approve(o.lee, other)}) == Errc::rejected);
        CHECK(o.refused(s, {o.approve(o.chan, s),
                            o.approve(o.lee, s.id, Way::in_person, std::nullopt,
                                      *protocol::to_id(Bytes(32, 0xee)))}) == Errc::rejected);
    }
    SECTION("twice") {
        const auto s = o.record();
        const auto chan = o.approve(o.chan, s);
        CHECK(o.refused(s, {chan, chan}) == Errc::rejected);
        CHECK(o.refused(s, {chan, o.approve(o.chan, s)}) == Errc::rejected);
    }
    SECTION("a time outside the statement's window") {
        const auto s = o.record();
        const protocol::Timestamp issued = s.statement.issued_at;
        const protocol::Timestamp skew = protocol::max_clock_skew_ms;
        CHECK(o.refused(s, {o.approve(o.chan, s), o.approve(o.lee, s.id, Way::in_person,
                                                            issued - skew - 1)}) == Errc::rejected);
        CHECK(o.refused(s, {o.approve(o.chan, s), o.approve(o.lee, s.id, Way::in_person,
                                                            o.w.clock().now() + skew + 1)}) ==
              Errc::rejected);
        o.ok(s, {o.approve(o.chan, s), o.approve(o.lee, s.id, Way::in_person, issued - skew)});
    }
    SECTION("revoked before the statement is registered") {
        const auto s = o.record();
        auto approvals = o.all(s, {&o.chan, &o.lee});
        o.w.ok(o.w.org(), o.w.statement(o.w.org_id(), std::nullopt,
                                        protocol::ActorRevokeBody{o.lee.id, "left"}));
        CHECK(o.refused(s, approvals) == Errc::rejected);
        o.ok(s, o.all(s, {&o.chan, &o.ho}));
    }
    SECTION("its key rotated before the statement is registered") {
        const auto s = o.record();
        auto approvals = o.all(s, {&o.chan, &o.lee});
        // Lee fears the key was stolen and rotates it, in person.
        KeyPair fresh = key("lee 2");
        o.w.ok(o.lee.key, o.in_person(o.lee, o.w.statement(o.lee.id, std::nullopt,
                                                           protocol::ActorRotateKeyBody{
                                                               o.lee.id, fresh.public_key()})));
        o.lee.key = std::move(fresh);
        CHECK(o.refused(s, approvals) == Errc::rejected);
        o.ok(s, o.all(s, {&o.chan, &o.lee}));
    }
    SECTION("out of order in a log entry") {
        const auto s = o.record();
        std::vector<protocol::SignedApproval> approvals;
        for (const Person* p : {&o.chan, &o.lee}) {
            approvals.push_back(*protocol::parse_approval(o.approve(*p, s)));
        }
        std::ranges::sort(approvals, [](const auto& a, const auto& b) {
            return before(b.approval.approver, a.approval.approver);
        });
        const auto& state = o.w.ledger().state();
        const auto now = o.w.clock().now();
        CHECK_FALSE(state.validate(provider(), s, now, nullptr, nullptr, approvals));
        std::ranges::reverse(approvals);
        CHECK(state.validate(provider(), s, now, nullptr, nullptr, approvals));
    }
}

TEST_CASE("an approval counts only in person and verified, and one that counts nowhere refuses",
          "[approvals][ledger][presence]") {
    Office o;
    const auto s = o.record();
    CHECK(o.refused(s, {o.approve(o.chan, s), o.approve(o.lee, s, Way::key_only)}) ==
          Errc::rejected);
    CHECK(o.refused(s, {o.approve(o.chan, s), o.approve(o.ho, s, Way::touch)}) == Errc::rejected);
    // Even beside enough that count.
    CHECK(o.refused(s, {o.approve(o.chan, s), o.approve(o.lee, s),
                        o.approve(o.ho, s, Way::touch)}) == Errc::rejected);
    o.ok(s, {o.approve(o.chan, s), o.approve(o.ho, s)});
}

TEST_CASE("a statement no rule applies to carries no approvals", "[approvals][ledger]") {
    Office o;
    const auto plain = o.grant(o.pat, std::nullopt);
    const auto s =
        o.sign(o.pat.key, o.w.statement(o.pat.id, plain, o.w.record_body(document_type)));
    CHECK(o.refused(s, {o.approve(o.chan, s)}) == Errc::rejected);
    const auto org = o.by_org(o.w.record_body(document_type));
    CHECK(o.refused(org, {o.approve(o.chan, org)}) == Errc::rejected);
    o.ok(s, {});
    o.ok(org, {});
}

TEST_CASE("approvals without presence count where the rule allows: agents and devices",
          "[approvals][ledger]") {
    Office o;
    Person agent = person("reviewer", 9);
    agent.id = o.w.register_actor(o.w.org(), o.w.org_id(), std::nullopt, protocol::ActorKind::agent,
                                  agent.key, o.chan.id);
    Person device = person("checker", 10);
    device.id = o.w.register_actor(o.w.org(), o.w.org_id(), std::nullopt,
                                   protocol::ActorKind::device, device.key);
    // Without key 4, a rule names people only.
    const auto people_only = Office::named(2, {&agent, &device});
    auto people_scope = scope({StatementType::record_register});
    people_scope.approvals = people_only;
    CHECK(o.w.rejected(o.w.org(), o.w.statement(o.w.org_id(), std::nullopt,
                                                protocol::DelegationGrantBody{
                                                    o.pat.id, people_scope})) == Errc::rejected);
    auto machines = people_only;
    machines.without_presence = true;
    const auto delegation = o.grant(o.pat, machines);
    const auto s =
        o.sign(o.pat.key, o.w.statement(o.pat.id, delegation, o.w.record_body(document_type)));
    CHECK(o.refused(s, {o.approve(agent, s, Way::key_only)}) == Errc::rejected);
    // An agent proves no presence.
    CHECK(o.refused(s, {o.approve(agent, s, Way::in_person),
                        o.approve(device, s, Way::key_only)}) == Errc::rejected);
    o.ok(s, {o.approve(agent, s, Way::key_only), o.approve(device, s, Way::key_only)});
}

TEST_CASE("the signer counts when the rule names it and it proves presence",
          "[approvals][ledger]") {
    Office o;
    const auto strict = o.grant(o.chan, Office::named(2, {&o.chan, &o.lee}));
    const auto by_key =
        o.sign(o.chan.key, o.w.statement(o.chan.id, strict, o.w.record_body(document_type)));
    CHECK(o.refused(by_key, {o.approve(o.lee, by_key)}) == Errc::rejected);
    const auto present = o.sign(
        o.chan.key,
        o.in_person(o.chan, o.w.statement(o.chan.id, strict, o.w.record_body(document_type))));
    // The signer never approves its own statement: it counts through it.
    CHECK(o.refused(present, {o.approve(o.chan, present), o.approve(o.lee, present)}) ==
          Errc::rejected);
    const auto tally = o.w.ledger().state().check_approvals(
        provider(), present, std::vector{*protocol::parse_approval(o.approve(o.lee, present))},
        o.w.clock().now());
    REQUIRE(tally);
    CHECK(tally->rules[0].signer_counts);
    CHECK(tally->met(o.w.clock().now()));
    o.ok(present, {o.approve(o.lee, present)});

    // Under key 4 its signature suffices, and so does an approver's key.
    auto loose_rule = Office::named(2, {&o.chan, &o.lee});
    loose_rule.without_presence = true;
    const auto loose = o.grant(o.chan, loose_rule);
    const auto s =
        o.sign(o.chan.key, o.w.statement(o.chan.id, loose, o.w.record_body(document_type)));
    o.ok(s, {o.approve(o.lee, s, Way::key_only)});
}

TEST_CASE("every rule in the chain applies, nearest first", "[approvals][ledger]") {
    Office o;
    // The organization to Pat (1 of Chan), Pat to Quinn (1 of Lee).
    auto upper = scope({StatementType::delegation_grant, StatementType::record_register},
                       std::vector<std::string>{document_type}, true);
    upper.approvals = Office::named(1, {&o.chan});
    const auto pat_delegation = o.w.grant(o.w.org(), o.w.org_id(), std::nullopt, o.pat.id, upper);
    auto lower = scope({StatementType::record_register}, std::vector<std::string>{document_type});
    lower.approvals = Office::named(1, {&o.lee});
    // Pat's grant is a statement under Pat's rule too.
    const auto grant =
        o.sign(o.pat.key, o.w.statement(o.pat.id, pat_delegation,
                                        protocol::DelegationGrantBody{o.quinn.id, lower}));
    CHECK(o.refused(grant, {}) == Errc::rejected);
    const auto quinn_delegation = o.ok(grant, {o.approve(o.chan, grant)});

    const auto s = o.sign(
        o.quinn.key, o.w.statement(o.quinn.id, quinn_delegation, o.w.record_body(document_type)));
    const auto rules = o.w.ledger().state().approval_rules(s.statement);
    REQUIRE(rules.size() == 2);
    CHECK(rules[0].delegation == quinn_delegation);
    CHECK(rules[1].delegation == pat_delegation);
    CHECK(o.refused(s, {o.approve(o.lee, s)}) == Errc::rejected);
    CHECK(o.refused(s, {o.approve(o.chan, s)}) == Errc::rejected);
    o.ok(s, {o.approve(o.chan, s), o.approve(o.lee, s)});
}

TEST_CASE("guardians are set by the new ones, changed by both sets, and removed",
          "[approvals][guardians][ledger]") {
    Office o;
    const auto three = Office::named(2, {&o.chan, &o.lee, &o.ho});
    const auto first = o.by_org(protocol::LedgerSetGuardiansBody{three, std::nullopt});
    CHECK(o.refused(first, {o.approve(o.chan, first)}) == Errc::rejected);
    o.ok(first, o.all(first, {&o.chan, &o.lee}));
    REQUIRE(o.w.ledger().state().guardians() != nullptr);
    CHECK(o.w.ledger().state().guardians()->guardians == three);
    // The organization's leaf lists it.
    const auto* org = o.w.ledger().state().actor(o.w.org_id());
    REQUIRE(org != nullptr);
    CHECK(org->guardian_updates.size() == 1);

    // Everything the organization signs is guarded now; delegated work is not.
    const auto record = o.by_org(o.w.record_body(document_type));
    CHECK(o.refused(record, {}) == Errc::rejected);
    o.ok(record, o.all(record, {&o.lee, &o.ho}));
    const auto clerk = o.record();
    o.ok(clerk, o.all(clerk, {&o.chan, &o.lee}));

    // Changing them: two of the current and two of the new; Ho, in both,
    // approves once and counts in both.
    const auto next = Office::named(2, {&o.ho, &o.pat, &o.quinn});
    const auto change = o.by_org(protocol::LedgerSetGuardiansBody{next, std::nullopt});
    const auto rules = o.w.ledger().state().approval_rules(change.statement);
    REQUIRE(rules.size() == 2);
    CHECK(rules[0].source == protocol::RuleSource::guardians);
    CHECK(rules[1].source == protocol::RuleSource::new_guardians);
    CHECK(o.refused(change, o.all(change, {&o.chan, &o.lee})) == Errc::rejected);
    CHECK(o.refused(change, o.all(change, {&o.pat, &o.quinn})) == Errc::rejected);
    o.ok(change, o.all(change, {&o.chan, &o.ho, &o.pat}));
    CHECK(o.w.ledger().state().guardians()->guardians == next);

    // Removing them: two of the current.
    const auto removal = o.by_org(protocol::LedgerSetGuardiansBody{std::nullopt, std::nullopt});
    CHECK(o.refused(removal, o.all(removal, {&o.chan, &o.lee})) == Errc::rejected);
    o.ok(removal, o.all(removal, {&o.pat, &o.quinn}));
    CHECK(o.w.ledger().state().guardians() == nullptr);
    CHECK(o.w.ledger().state().guardian_settings().size() == 3);
    o.ok(o.by_org(o.w.record_body(document_type)), {});
    // Nothing left to remove.
    const auto again = o.by_org(protocol::LedgerSetGuardiansBody{std::nullopt, std::nullopt});
    CHECK(o.refused(again, {}) == Errc::rejected);

    // Only the organization sets them.
    CHECK(o.w.rejected(o.chan.key, o.w.statement(o.chan.id, std::nullopt,
                                                 protocol::LedgerSetGuardiansBody{
                                                     three, std::nullopt})) == Errc::rejected);
}

TEST_CASE("guardians may guard a list of types, and always the keys and themselves",
          "[approvals][guardians][ledger][security]") {
    Office o;
    o.set_guardians(Office::named(1, {&o.chan, &o.lee}), {&o.chan},
                    std::vector<StatementType>{StatementType::actor_register});
    // Not listed: no approvals.
    o.ok(o.by_org(o.w.record_body(document_type)), {});
    o.ok(o.by_org(protocol::ActorRevokeBody{o.quinn.id, "left"}), {});
    // Listed.
    const auto actor = o.by_org(protocol::ActorRegisterBody{
        protocol::ActorKind::person, "Sam", key("sam").public_key(), std::nullopt, std::nullopt});
    CHECK(o.refused(actor, {}) == Errc::rejected);
    o.ok(actor, {o.approve(o.lee, actor)});

    // Always: a guardian's credentials, key, and revocation.
    const auto presence =
        o.by_org(protocol::ActorSetPresenceBody{o.chan.id, {token_credential(o.chan)}});
    CHECK(o.refused(presence, {}) == Errc::rejected);
    o.ok(presence, {o.approve(o.lee, presence)});
    KeyPair chan2 = key("chan 2");
    const auto rotate = o.by_org(protocol::ActorRotateKeyBody{o.chan.id, chan2.public_key()});
    CHECK(o.refused(rotate, {}) == Errc::rejected);
    o.ok(rotate, {o.approve(o.lee, rotate)});
    o.chan.key = std::move(chan2);
    const auto revoke = o.by_org(protocol::ActorRevokeBody{o.lee.id, "retired"});
    CHECK(o.w.ledger().state().guarded(revoke.statement));
    CHECK(o.refused(revoke, {}) == Errc::rejected);

    // The log key and the root key.
    const KeyPair log2 = key("log 2");
    const auto log = o.by_org(protocol::LedgerRotateLogKeyBody{log2.public_key()});
    CHECK(o.refused(log, {}) == Errc::rejected);
    o.ok(log, {o.approve(o.chan, log)});
    const KeyPair root2 = key("root 2");
    const auto root = o.by_org(protocol::ActorRotateKeyBody{o.w.org_id(), root2.public_key()});
    CHECK(o.refused(root, {}) == Errc::rejected);
    o.ok(root, {o.approve(o.chan, root)});
    // And the guardians themselves.
    const auto change = o.by_org(
        protocol::LedgerSetGuardiansBody{Office::named(1, {&o.chan}), std::nullopt}, &root2);
    CHECK(o.refused(change, {}) == Errc::rejected);
    o.ok(change, {o.approve(o.chan, change)});
}

TEST_CASE("only an approver or the organization changes an approver's key or credentials",
          "[approvals][ledger][security]") {
    Office o;
    Person admin = person("admin", 20);
    o.enrol(admin);
    auto admin_scope = scope({StatementType::actor_rotate_key, StatementType::actor_set_presence,
                              StatementType::actor_revoke});
    const auto delegation = o.w.grant(o.w.org(), o.w.org_id(), std::nullopt, admin.id, admin_scope);
    auto by_admin = [&](protocol::Body body) {
        return o.w.statement(admin.id, delegation, std::move(body));
    };
    CHECK(o.w.ledger().state().protected_approver(o.chan.id));
    CHECK_FALSE(o.w.ledger().state().protected_approver(o.pat.id));
    CHECK(o.w.rejected(admin.key, by_admin(protocol::ActorRotateKeyBody{
                                      o.chan.id, key("chan 2").public_key()})) == Errc::rejected);
    CHECK(o.w.rejected(admin.key, by_admin(protocol::ActorSetPresenceBody{
                                      o.lee.id, {token_credential(admin)}})) == Errc::rejected);
    // Not an approver: the administrator may.
    o.w.ok(admin.key, by_admin(protocol::ActorRotateKeyBody{o.pat.id, key("pat 2").public_key()}));
    // Revoking an approver stays open.
    o.w.ok(admin.key, by_admin(protocol::ActorRevokeBody{o.ho.id, "left"}));
    // The approver itself, in person, and the organization.
    o.w.ok(o.chan.key,
           o.in_person(o.chan, o.w.statement(o.chan.id, std::nullopt,
                                             protocol::ActorRotateKeyBody{
                                                 o.chan.id, key("chan 3").public_key()})));
    o.w.ok(o.w.org(),
           o.w.statement(o.w.org_id(), std::nullopt,
                         protocol::ActorRotateKeyBody{o.lee.id, key("lee 2").public_key()}));
    // Once no unrevoked delegation's rule names them, they are no longer
    // protected.
    o.w.ok(o.w.org(), o.w.statement(o.w.org_id(), std::nullopt,
                                    protocol::DelegationRevokeBody{o.clerk_delegation, "ended"}));
    CHECK_FALSE(o.w.ledger().state().protected_approver(o.lee.id));
    o.w.ok(admin.key, by_admin(protocol::ActorRotateKeyBody{o.lee.id, key("lee 3").public_key()}));
}

TEST_CASE("a guardian is revoked only by the organization, never below k",
          "[approvals][guardians][ledger][security]") {
    Office o;
    o.set_guardians(Office::named(2, {&o.chan, &o.lee, &o.ho}), {&o.chan, &o.lee});
    Person admin = person("admin", 20);
    // Registering the administrator is guarded too.
    const auto enrol =
        o.by_org(protocol::ActorRegisterBody{protocol::ActorKind::person, admin.name,
                                             admin.key.public_key(), std::nullopt, std::nullopt});
    admin.id = o.ok(enrol, o.all(enrol, {&o.chan, &o.lee}));
    auto revoking = scope({StatementType::actor_revoke});
    const auto grant = o.by_org(protocol::DelegationGrantBody{admin.id, revoking});
    const auto delegation = o.ok(grant, o.all(grant, {&o.chan, &o.lee}));
    CHECK(o.w.rejected(admin.key, o.w.statement(admin.id, delegation,
                                                protocol::ActorRevokeBody{o.ho.id, "left"})) ==
          Errc::rejected);

    // Ho approves his own revocation: approvals are checked before it.
    const auto ho_out = o.by_org(protocol::ActorRevokeBody{o.ho.id, "left"});
    o.ok(ho_out, o.all(ho_out, {&o.chan, &o.ho}));
    // Then only Chan and Lee remain, and k is 2.
    const auto lee_out = o.by_org(protocol::ActorRevokeBody{o.lee.id, "left"});
    CHECK(o.refused(lee_out, o.all(lee_out, {&o.chan, &o.lee})) == Errc::rejected);
    // A revoked guardian stays named.
    CHECK(std::ranges::contains(o.w.ledger().state().guardians()->guardians->approvers, o.ho.id));
}

TEST_CASE("evidence carries every approval, every approver whole, and the guardians",
          "[approvals][guardians][evidence]") {
    Office o;
    o.set_guardians(Office::named(2, {&o.chan, &o.lee, &o.ho}), {&o.chan, &o.lee});
    const auto s = o.record();
    const auto record = o.ok(s, o.all(s, {&o.lee, &o.chan}));
    auto bundle = o.exported(record);
    auto report = verify(bundle);
    REQUIRE(report);
    CHECK(report->complete);
    REQUIRE(report->events.size() == 1);
    const auto& event = report->events.front();
    REQUIRE(event.approval_rules.size() == 1);
    CHECK(event.approval_rules[0].source == protocol::RuleSource::delegation);
    CHECK(event.approval_rules[0].counted.size() == 2);
    CHECK_FALSE(event.approval_rules[0].signer_counted);
    REQUIRE(event.approvals.size() == 2);
    for (const auto& a : event.approvals) {
        REQUIRE(a.presence);
        CHECK(a.presence->method == protocol::PresenceMethod::hardware_key);
    }
    CHECK(before(event.approvals[0].approver.id, event.approvals[1].approver.id));
    REQUIRE(report->guardians);
    REQUIRE(report->guardian_settings.size() == 1);
    CHECK(report->guardian_settings[0].approvals.size() == 2);
    CHECK(report->guardian_settings[0].guardians.size() == 3);
    // Every approver and guardian is proven whole.
    for (const Person* p : {&o.chan, &o.lee, &o.ho}) {
        CHECK(std::ranges::any_of(bundle.state_proofs, [&](const protocol::StateProof& proof) {
            return proof.leaf.id == p->id;
        }));
    }
    // The report says so in its words and fields.
    const auto json = kanhe::verifier::report_json(*report, false);
    CHECK(json["events"][0]["approvals"].size() == 2);
    REQUIRE(json["events"][0]["approvals"][0]["counted_for"].size() == 1);
    CHECK(json["events"][0]["approvals"][0]["counted_for"][0] == 0);
    CHECK(json["events"][0]["rules"][0]["source"] == "delegation");
    CHECK(json["events"][0]["rules"][0]["k"] == 2);
    CHECK(json["events"][0]["rules"][0]["count"] == 2);
    CHECK(json["guardians"]["in_effect"]["k"] == 2);
    CHECK(json["guardians"]["in_effect"]["guardians"].size() == 3);
    CHECK(json["guardians"]["in_effect"]["guards"].is_null());
    CHECK(json["guardians"]["settings"][0]["rules"][0]["source"] == "new_guardians");
    const std::string text = kanhe::verifier::report_text(*report, false);
    CHECK(text.find("approved by \"Chan Tai Man\"") != std::string::npos);
    CHECK(text.find("Guardians    2 of 3 must approve") != std::string::npos);

    // An approver revoked since: its revocation cannot be left out.
    const auto revoke = o.by_org(protocol::ActorRevokeBody{o.lee.id, "left"});
    const auto revoked = o.ok(revoke, o.all(revoke, {&o.chan, &o.ho}));
    bundle = o.exported(record);
    report = verify(bundle);
    REQUIRE(report);
    CHECK(report->complete);
    CHECK(std::ranges::any_of(report->events.front().approvals,
                              [](const auto& a) { return a.approver.revoked; }));
    const std::uint64_t revoked_at = *o.w.ledger().statement_index(revoked);
    auto short_of = bundle;
    std::erase_if(short_of.entries,
                  [&](const protocol::EvidenceEntry& e) { return leaf_of(e) == revoked_at; });
    REQUIRE(short_of.entries.size() + 1 == bundle.entries.size());
    CHECK_FALSE(verify(short_of));

    // The ledger replays its approvals when it opens, and a snapshot keeps
    // the guardians and the rules' approvers.
    auto reopened = ledger::Ledger::open(o.w.fs(), o.w.clock(), provider(), {false});
    REQUIRE(reopened);
    CHECK(reopened->state().guardian_settings().size() == 1);
    REQUIRE(o.w.ledger().write_snapshot());
    auto from_snapshot = ledger::Ledger::open(o.w.fs(), o.w.clock(), provider());
    REQUIRE(from_snapshot);
    CHECK(from_snapshot->opened_from_snapshot());
    for (const auto* state : {&reopened->state(), &from_snapshot->state()}) {
        REQUIRE(state->guardians() != nullptr);
        CHECK(state->guardians()->guardians == o.w.ledger().state().guardians()->guardians);
        CHECK(state->protected_approver(o.chan.id));
        CHECK_FALSE(state->protected_approver(o.pat.id));
        CHECK(state->actor(o.w.org_id())->guardian_updates ==
              o.w.ledger().state().actor(o.w.org_id())->guardian_updates);
    }
}

TEST_CASE("a guarded rotation without its approvals fails replay, and a witness ignores them",
          "[approvals][guardians][evidence][witness]") {
    Office o;
    o.set_guardians(Office::named(2, {&o.chan, &o.lee, &o.ho}), {&o.chan, &o.lee});
    const KeyPair root2 = key("root 2");
    const auto rotation = o.by_org(protocol::ActorRotateKeyBody{o.w.org_id(), root2.public_key()});
    const auto rotated = o.ok(rotation, o.all(rotation, {&o.chan, &o.lee}));
    const KeyPair log2 = key("log 2");
    const auto log_rotation = o.by_org(protocol::LedgerRotateLogKeyBody{log2.public_key()}, &root2);
    o.ok(log_rotation, o.all(log_rotation, {&o.chan, &o.ho}));
    const auto s = o.record();
    const auto record = o.ok(s, o.all(s, {&o.chan, &o.lee}));

    // A witness follows both rotations, their approvals ignored.
    REQUIRE(o.w.ledger().checkpoint(log2));
    const auto keys = protocol::keys_from_genesis(provider(), *o.w.ledger().entry(0));
    REQUIRE(keys);
    protocol::WitnessedLog witnessed;
    witnessed.ledger_id = keys->ledger_id;
    witnessed.log_key = keys->log_key();
    witnessed.root_key = keys->root_key;
    witnessed.tree_hash = keys->hash;
    const auto request = o.w.ledger().cosign_request(0);
    REQUIRE(request);
    REQUIRE(request->rotations.size() == 2);
    CHECK_FALSE(protocol::decode_log_entry(request->rotations[0].entry)->approvals.empty());
    const auto cosigned = protocol::check_cosign_request(provider(), witnessed, *request);
    REQUIRE(cosigned);
    CHECK(cosigned->log.log_key == log2.public_key());

    // Evidence made again by whoever holds the log key: as it is, it
    // verifies; with the root rotation's approvals taken off, it does not.
    auto bundle = o.w.ledger().export_evidence(log2, record);
    REQUIRE(bundle);
    REQUIRE(verify(*bundle));
    const std::uint64_t index = *o.w.ledger().statement_index(rotated);
    auto entry = protocol::decode_log_entry(*o.w.ledger().entry(index));
    REQUIRE(entry);
    REQUIRE(entry->approvals.size() == 2);
    // (The forger signs with the log key in effect at the checkpoint.)
    World& w = o.w;
    const auto same = reforged_with(w, *bundle, index, *protocol::encode_log_entry(*entry), log2);
    CHECK(verify(same));
    entry->approvals.clear();
    const auto bare = reforged_with(w, *bundle, index, *protocol::encode_log_entry(*entry), log2);
    const auto refused = verify(bare);
    REQUIRE_FALSE(refused);
    CHECK(refused.error().code == Errc::verification_failed);
    // One approval for another statement fails it too.
    entry->approvals = {o.approve(o.chan, rotation), o.approve(o.lee, s)};
    std::ranges::sort(entry->approvals, [](const Bytes& a, const Bytes& b) {
        return before(protocol::parse_approval(a)->approval.approver,
                      protocol::parse_approval(b)->approval.approver);
    });
    CHECK_FALSE(
        verify(reforged_with(w, *bundle, index, *protocol::encode_log_entry(*entry), log2)));
}

TEST_CASE("the v0.20 vectors' logs replay in a ledger; a genesis with approvals does not",
          "[approvals][guardians][ledger][vectors]") {
    const nlohmann::json vectors = load_vectors("protocol-v0.20.json");
    for (const auto& v : vectors["ledgers"]) {
        INFO(v["hash"].get<std::int64_t>());
        const auto& entries = v["log_entries"];
        ledger::MemoryFileSystem fs;
        ledger::ManualClock clock(v["checkpoint_time"].get<protocol::Timestamp>() + 1000);
        auto replica = ledger::Ledger::create_replica(fs, clock, provider(),
                                                      hex(entries[0].get<std::string>()));
        REQUIRE(replica);
        std::vector<Bytes> rest;
        for (std::size_t i = 1; i < entries.size(); ++i) {
            rest.push_back(hex(entries[i].get<std::string>()));
        }
        const auto appended = replica->append_entries(rest);
        INFO((appended ? std::string() : std::string(appended.error().detail)));
        REQUIRE(appended);
        CHECK(replica->size() == entries.size());
        REQUIRE(replica->store_checkpoint(hex(v["checkpoint"].get<std::string>())));
        CHECK(replica->state().guardian_settings().size() == v["guardian_settings"].size());
        // Opened again, it replays them all.
        auto reopened = ledger::Ledger::open(fs, clock, provider(), {false});
        REQUIRE(reopened);
        CHECK(reopened->size() == entries.size());

        ledger::MemoryFileSystem other;
        CHECK_FALSE(ledger::Ledger::create_replica(
            other, clock, provider(), hex(v["genesis_with_approvals"].get<std::string>())));
    }
}
