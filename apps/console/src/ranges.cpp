// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// Range proofs in the console (spec v0.22). A record whose kind marks
// values provable commits to each apart (documents.cpp), its openings kept
// in the vault. From here, an owner or an admin hands a record's openings to
// the holder its values belong to, as a range openings file, checked
// against the registration first; and whoever may read the record's private
// data proves from the vault that one of its values lies within bounds,
// without showing it: the record's evidence with the proofs added, verified
// before it is offered, as `kanhe evidence prove` makes it.

#include <algorithm>
#include <cstddef>
#include <exception>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

#include <nlohmann/json.hpp>

#include <kanhe/client/ranges.hpp>
#include <kanhe/client/records.hpp>
#include <kanhe/client/support.hpp>
#include <kanhe/console/console.hpp>
#include <kanhe/core/bytes.hpp>
#include <kanhe/core/protocol/evidence.hpp>
#include <kanhe/core/protocol/ranges.hpp>
#include <kanhe/core/protocol/record.hpp>
#include <kanhe/core/protocol/state.hpp>
#include <kanhe/verifier/report.hpp>

#include "responses.hpp"

namespace kanhe::console {

namespace {

constexpr std::string_view records_prefix = "/console/api/records/";
constexpr std::string_view openings_suffix = "/openings";

std::optional<protocol::Id> id_of(std::string_view hex) {
    const auto bytes = from_hex(hex);
    if (!bytes) {
        return std::nullopt;
    }
    const auto id = protocol::to_id(*bytes);
    return id ? std::optional(*id) : std::nullopt;
}

/// The record named by `hex`, or why not.
std::variant<protocol::Id, http::Response> record_of(std::string_view hex) {
    if (auto id = id_of(hex)) {
        return *id;
    }
    return error(400, "invalid_argument", "name the record by its full id (hex)");
}

/// The fields a body names under `key`: a list of text, each once; none
/// when absent.
std::variant<std::vector<std::string>, http::Response> names_in(const nlohmann::json& body,
                                                                std::string_view key) {
    std::vector<std::string> out;
    const auto it = body.find(key);
    if (it == body.end() || it->is_null()) {
        return out;
    }
    if (!it->is_array() || !std::ranges::all_of(*it, [](const auto& v) { return v.is_string(); })) {
        return error(400, "invalid_argument", "\"" + std::string(key) + "\" names fields");
    }
    for (const auto& v : *it) {
        if (std::ranges::contains(out, v.get<std::string>())) {
            return error(400, "invalid_argument", v.get<std::string>() + " is named twice");
        }
        out.push_back(v.get<std::string>());
    }
    return out;
}

/// A bound as people typed it: absent if missing, null, or blank.
std::variant<std::optional<std::string>, http::Response> bound_of(const nlohmann::json& range,
                                                                  std::string_view key) {
    const auto it = range.find(key);
    if (it == range.end() || it->is_null()) {
        return std::optional<std::string>();
    }
    if (!it->is_string()) {
        return error(400, "invalid_argument",
                     "a bound is text, as people write it: 18, 30000.00, 2008-11-20");
    }
    const std::string text = it->get<std::string>();
    if (std::ranges::all_of(text, [](unsigned char c) { return c == ' ' || c == '\t'; })) {
        return std::optional<std::string>();
    }
    return std::optional(text);
}

} // namespace

http::Response Console::openings_route(const http::Request& request) const {
    auto who = authenticate(request);
    if (auto* refused = std::get_if<http::Response>(&who)) {
        return std::move(*refused);
    }
    const Signed& signer = std::get<Signed>(who);
    if (request.method != "POST") {
        http::Response refused = error(405, "unsupported", "method not allowed");
        refused.headers.emplace_back("Allow", "POST");
        return refused;
    }
    if (signer.role != Role::owner && signer.role != Role::admin) {
        return error(403, "forbidden",
                     "only an owner or an admin hands out a record's openings: they hold its "
                     "values");
    }
    const ledger::Ledger* const served = ledger();
    if (served == nullptr) {
        return services_.keys != nullptr && services_.keys->initialized() &&
                       !services_.keys->unlocked()
                   ? error(423, "locked", "the console is locked: unlock it first")
                   : error(503, "unavailable", "the console has no ledger yet");
    }
    const std::string_view path = request.path;
    auto named = record_of(path.substr(
        records_prefix.size(),
        path.size() - std::min(path.size(), records_prefix.size() + openings_suffix.size())));
    if (auto* refused = std::get_if<http::Response>(&named)) {
        return std::move(*refused);
    }
    const protocol::Id id = std::get<protocol::Id>(named);
    const auto body =
        nlohmann::json::parse(request.body.begin(), request.body.end(), nullptr, false);
    if (!body.is_object()) {
        return error(400, "invalid_argument", "the request's body is not a JSON object");
    }
    auto fields = names_in(body, "fields");
    if (auto* refused = std::get_if<http::Response>(&fields)) {
        return std::move(*refused);
    }
    std::optional<http::Response> answer;
    std::optional<protocol::RangeOpenings> openings;
    served->read_state([&](const protocol::LedgerState& state) {
        const protocol::RecordState* r = state.record(id);
        if (r == nullptr) {
            answer = error(404, "not_found", "no such record on this ledger");
            return;
        }
        const auto registered = registration(state, id);
        if (!registered) {
            answer = error(409, "conflict", "the record's registration cannot be read");
            return;
        }
        if (registered->provable.empty()) {
            answer = error(409, "no_provable",
                           "this document has no values that can be proven: its kind marked "
                           "none when it was registered");
            return;
        }
        const auto vault = private_data(state, id);
        if (!vault) {
            answer = services_.keys == nullptr || !services_.keys->unlocked()
                         ? error(423, "locked", "the console is locked: unlock it first")
                         : error(409, "conflict", "the record's private data is not here");
            return;
        }
        try {
            // Each opening checked against its commitment in the
            // registration: a file whose openings were not the record's
            // would prove nothing.
            openings =
                client::vault_openings(*services_.provider, state.ledger_id(), id, *registered,
                                       *vault, std::get<std::vector<std::string>>(fields));
        } catch (const client::UsageError& e) {
            answer = error(400, "invalid_argument", e.message);
        } catch (const client::ActionError& e) {
            answer = error(409, "conflict", e.message);
        }
    });
    if (answer) {
        return std::move(*answer);
    }
    auto encoded = protocol::encode_range_openings(*openings);
    if (!encoded) {
        return error(500, "internal", "the openings could not be encoded");
    }
    nlohmann::json names = nlohmann::json::array();
    for (const protocol::RangeOpening& o : openings->openings) {
        names.push_back(o.name);
    }
    const std::string hex = to_hex(id.bytes());
    log_activity(signer.user, "record.openings", {{"record", hex}, {"fields", names}});
    return download(std::move(*encoded), "openings-" + hex.substr(0, 12) + ".kanheopenings",
                    "application/cbor");
}

void Console::prove_route(const http::Request& request, Respond respond) const {
    auto who = authenticate(request);
    if (auto* refused = std::get_if<http::Response>(&who)) {
        respond(std::move(*refused));
        return;
    }
    const Signed signer = std::get<Signed>(who);
    const ledger::Ledger* const served = ledger();
    const Evidence source = evidence();
    if (served == nullptr || !source) {
        respond(error(503, "unavailable", "the console has no ledger to prove anything from"));
        return;
    }
    if (!client::range_proofs_built()) {
        respond(error(501, "unsupported",
                      "this console was built without range proofs: it cannot make them"));
        return;
    }
    const auto body =
        nlohmann::json::parse(request.body.begin(), request.body.end(), nullptr, false);
    if (!body.is_object()) {
        respond(error(400, "invalid_argument", "the request's body is not a JSON object"));
        return;
    }
    auto named = record_of(body.value("record", ""));
    if (auto* refused = std::get_if<http::Response>(&named)) {
        respond(std::move(*refused));
        return;
    }
    const protocol::Id id = std::get<protocol::Id>(named);
    // What to prove: one statement per value, each with a least value, a
    // greatest, or both, as people write them.
    std::vector<client::RangeRequest> asked;
    const auto ranges = body.find("ranges");
    if (ranges == body.end() || !ranges->is_array() || ranges->empty() ||
        ranges->size() > protocol::max_range_proofs) {
        respond(error(400, "invalid_argument",
                      "say what to prove: \"ranges\", 1 to 16 of {field, at_least, at_most}"));
        return;
    }
    for (const auto& range : *ranges) {
        if (!range.is_object() || !range.contains("field") || !range["field"].is_string()) {
            respond(error(400, "invalid_argument",
                          "a range names its field: {field, at_least, at_most}"));
            return;
        }
        client::RangeRequest one;
        one.field = range["field"].get<std::string>();
        if (std::ranges::contains(asked, one.field, &client::RangeRequest::field)) {
            respond(error(400, "invalid_argument",
                          one.field + " is named twice: a proof file proves each value once"));
            return;
        }
        for (auto [key, into] :
             {std::pair{"at_least", &one.at_least}, std::pair{"at_most", &one.at_most}}) {
            auto bound = bound_of(range, key);
            if (auto* refused = std::get_if<http::Response>(&bound)) {
                respond(std::move(*refused));
                return;
            }
            *into = std::get<std::optional<std::string>>(std::move(bound));
        }
        if (!one.at_least && !one.at_most) {
            respond(error(400, "bad_bounds",
                          "say what to prove of " + one.field +
                              ": at least a value, at most a value, or both"));
            return;
        }
        asked.push_back(std::move(one));
    }
    // A relying party's challenge, which every proof then carries; none if
    // absent or blank.
    if (const auto context = body.find("context"); context != body.end() && !context->is_null()) {
        const std::string text = context->is_string() ? context->get<std::string>() : "-";
        if (!text.empty()) {
            const auto bytes = from_hex(text);
            if (!bytes || bytes->empty() || bytes->size() > protocol::max_range_context) {
                respond(error(400, "bad_challenge",
                              "a challenge code is 1 to 64 bytes, written in hex (2 to 128 "
                              "digits 0-9 and a-f)"));
                return;
            }
            for (client::RangeRequest& one : asked) {
                one.context = *bytes;
            }
        }
    }

    // Each statement checked, and each opening taken from the vault and
    // checked against the registration, before the node builds the bundle.
    std::optional<http::Response> answer;
    std::vector<std::pair<protocol::RangeProof, protocol::RangeOpening>> statements;
    std::optional<protocol::Id> own;
    served->read_state([&](const protocol::LedgerState& state) {
        own = state.ledger_id();
        const protocol::RecordState* r = state.record(id);
        if (r == nullptr) {
            answer = error(404, "not_found", "no such record on this ledger");
            return;
        }
        if (!may_read_private(signer, state, *r)) {
            answer = error(403, "forbidden",
                           "you may not prove this record's values: they are its private data");
            return;
        }
        const auto registered = registration(state, id);
        if (!registered) {
            answer = error(409, "conflict", "the record's registration cannot be read");
            return;
        }
        if (registered->provable.empty()) {
            answer = error(409, "no_provable",
                           "this document has no values that can be proven: its kind marked "
                           "none when it was registered");
            return;
        }
        std::vector<std::string> fields;
        for (const client::RangeRequest& one : asked) {
            fields.push_back(one.field);
        }
        try {
            std::vector<protocol::RangeProof> proofs;
            std::vector<protocol::ProvableEncoding> encodings;
            for (const client::RangeRequest& one : asked) {
                const auto provable = std::ranges::find(registered->provable, one.field,
                                                        &protocol::ProvableValue::name);
                if (provable == registered->provable.end()) {
                    answer = error(400, "invalid_argument",
                                   one.field + " is not one of this document's provable values");
                    return;
                }
                try {
                    proofs.push_back(client::range_statement(*provable, one));
                } catch (const client::UsageError& e) {
                    answer = error(400, "bad_bounds", e.message);
                    return;
                }
                encodings.push_back(provable->encoding);
            }
            const auto vault = private_data(state, id);
            if (!vault) {
                answer = services_.keys == nullptr || !services_.keys->unlocked()
                             ? error(423, "locked", "the console is locked: unlock it first")
                             : error(409, "conflict", "the record's private data is not here");
                return;
            }
            const protocol::RangeOpenings openings = client::vault_openings(
                *services_.provider, state.ledger_id(), id, *registered, *vault, fields);
            for (std::size_t i = 0; i < proofs.size(); ++i) {
                const auto opening = std::ranges::find(openings.openings, proofs[i].field,
                                                       &protocol::RangeOpening::name);
                const auto values = protocol::range_public_values(encodings[i], proofs[i]);
                const std::uint64_t v = protocol::range_v(opening->x);
                // A value outside the bounds cannot be proven within them.
                if (!values || v < values->first || v > values->second) {
                    answer = error(422, "not_within",
                                   "no proof can be made that " +
                                       protocol::range_words(encodings[i], proofs[i]) +
                                       ": the value is not within those bounds");
                    return;
                }
                statements.emplace_back(std::move(proofs[i]), *opening);
            }
        } catch (const client::UsageError& e) {
            answer = error(400, "invalid_argument", e.message);
        } catch (const client::ActionError& e) {
            answer = error(409, "conflict", e.message);
        }
    });
    if (answer) {
        respond(std::move(*answer));
        return;
    }
    const std::string user = signer.user;
    source(id, [this, id, ledger_id = *own, user, statements = std::move(statements),
                respond = std::move(respond)](Result<Bytes> encoded) mutable {
        if (!encoded) {
            respond(error(503, "unavailable", encoded.error().detail));
            return;
        }
        // Proving takes a while: off the ledger's writer.
        tasks_.run([this, id, ledger_id, user, statements = std::move(statements),
                    bundle = std::move(*encoded), respond = std::move(respond)]() mutable {
            try {
                protocol::VerifyOptions options;
                options.expected_ledger = ledger_id;
                const auto record = client::provable_record(bundle, options);
                if (!record) {
                    respond(error(503, "unavailable",
                                  "the ledger's evidence does not verify: " +
                                      std::string(record.error().detail)));
                    return;
                }
                std::optional<protocol::EvidenceReport> report;
                nlohmann::json words = nlohmann::json::array();
                for (auto& [statement, opening] : statements) {
                    client::Proved proved = client::add_range_proof(
                        bundle, *record, std::move(statement), opening, options);
                    // Verified, as any verifier will check it, before it is
                    // offered.
                    if (!proved.report) {
                        respond(error(500, "internal",
                                      "the proof made does not verify: " +
                                          std::string(proved.report.error().detail)));
                        return;
                    }
                    bundle = std::move(proved.bundle);
                    report = std::move(*proved.report);
                }
                for (const protocol::RangeProofReport& p : report->range_proofs) {
                    words.push_back(p.text);
                }
                const verifier::Json full = verifier::report_json(*report, true);
                const std::string hex = to_hex(id.bytes());
                log_activity(user, "evidence.prove", {{"record", hex}, {"proved", words}});
                nlohmann::json out = {{"file", to_base64url(bundle)},
                                      {"name", "proof-" + hex.substr(0, 12) + ".cbor"},
                                      {"size", bundle.size()}};
                for (const char* key : {"provable", "range_proofs"}) {
                    const auto it = full.find(key);
                    out[key] = it != full.end() ? nlohmann::json::parse(it->dump())
                                                : nlohmann::json::array();
                }
                respond(json(200, out));
            } catch (const client::UsageError& e) {
                respond(error(400, "invalid_argument", e.message));
            } catch (const client::ActionError& e) {
                respond(error(409, "conflict", e.message));
            } catch (const std::exception&) {
                respond(error(500, "internal", "the proof could not be made"));
            }
        });
    });
}

} // namespace kanhe::console
