// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// The web console's own checks, in the browser: before a person's passkey
// confirms a statement, the page decodes the bytes it will sign with the
// core (not the console's description of them) and computes their presence
// challenge itself, so a tampered answer cannot obtain a tap for something
// else. A registration's fields and files are recomputed from what the
// person typed and chose. Before a person approves someone else's statement
// (spec v0.20), the page recomputes that statement's id from its bytes, the
// fields shown with it, and the approval's own challenge. Exported as plain
// C functions; strings are JSON, freed with kanhe_free.

#include <algorithm>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <emscripten/emscripten.h>
#include <optional>
#include <string>
#include <variant>
#include <vector>

#include <kanhe/core/bytes.hpp>
#include <kanhe/core/cbor.hpp>
#include <kanhe/core/crypto.hpp>
#include <kanhe/core/protocol/access.hpp>
#include <kanhe/core/protocol/approval_file.hpp>
#include <kanhe/core/protocol/approvals.hpp>
#include <kanhe/core/protocol/claims.hpp>
#include <kanhe/core/protocol/common.hpp>
#include <kanhe/core/protocol/contract_evidence.hpp>
#include <kanhe/core/protocol/contracts.hpp>
#include <kanhe/core/protocol/evidence.hpp>
#include <kanhe/core/protocol/presence.hpp>
#include <kanhe/core/protocol/record.hpp>
#include <kanhe/core/protocol/scripts.hpp>
#include <kanhe/core/protocol/statement.hpp>
#include <kanhe/crypto/openssl.hpp>
#include <kanhe/verifier/report.hpp>

namespace {

using namespace kanhe;
using verifier::Json;

const crypto::openssl::Provider& provider() {
    static const crypto::openssl::Provider instance;
    return instance;
}

char* to_c_string(const Json& value) {
    const std::string text = value.dump(-1, ' ', false, Json::error_handler_t::replace);
    char* out = static_cast<char*>(std::malloc(text.size() + 1));
    if (out != nullptr) {
        std::memcpy(out, text.c_str(), text.size() + 1);
    }
    return out;
}

Json hex_or_null(const std::optional<protocol::Id>& id) {
    return id ? Json(to_hex(id->bytes())) : Json();
}

Json names_or_null(const std::optional<std::vector<std::string>>& names) {
    return names ? Json(*names) : Json();
}

/// An access request's, grant's, or receipt's terms, from the bytes (the
/// console's own description is compared with these).
Json access_terms(std::string_view type, const cbor::Value& metadata) {
    if (type == protocol::access_request_type) {
        if (const auto r = protocol::decode_access_request(metadata)) {
            return {{"kind", "request"},
                    {"ledger", to_hex(r->ledger.bytes())},
                    {"record", to_hex(r->record.bytes())},
                    {"purpose", r->purpose},
                    {"until", r->until},
                    {"fields", names_or_null(r->fields)},
                    {"attachments", names_or_null(r->attachments)},
                    {"recipient", to_hex(r->recipient)},
                    {"condition",
                     r->condition ? Json(protocol::condition_text(*r->condition)) : Json()}};
        }
    } else if (type == protocol::access_grant_type) {
        if (const auto g = protocol::decode_access_grant(metadata)) {
            return {{"kind", "grant"},
                    {"ledger", to_hex(g->ledger.bytes())},
                    {"request", to_hex(g->request.bytes())},
                    {"record", to_hex(g->record.bytes())},
                    {"fields", g->fields},
                    {"attachments", g->attachments},
                    {"until", g->until},
                    {"recipient", to_hex(g->recipient)}};
        }
    } else if (type == protocol::access_receipt_type) {
        if (const auto r = protocol::decode_access_receipt(metadata)) {
            return {{"kind", "receipt"},
                    {"ledger", to_hex(r->ledger.bytes())},
                    {"grant", to_hex(r->grant.bytes())},
                    {"delivery", to_hex(r->delivery)}};
        }
    }
    return Json();
}

/// An approval rule (spec v0.20), as the console's summary writes it.
Json rule_json(const protocol::ApprovalRule& rule) {
    Json approvers = Json::array();
    for (const protocol::Id& a : rule.approvers) {
        approvers.push_back(to_hex(a.bytes()));
    }
    return {{"k", rule.needed},
            {"approvers", approvers},
            {"within", rule.within},
            {"without_presence", rule.without_presence}};
}

/// A delegation's scope, as the console's summary writes it.
Json scope_json(const protocol::Scope& scope) {
    Json types = Json::array();
    for (const protocol::StatementType t : scope.statement_types) {
        types.push_back(std::string(protocol::name(t)));
    }
    Json contracts;
    if (scope.contracts) {
        contracts = Json::array();
        for (const protocol::Id& c : *scope.contracts) {
            contracts.push_back(to_hex(c.bytes()));
        }
    }
    auto optional_list = [](const std::optional<std::vector<std::string>>& list) {
        return list ? Json(*list) : Json();
    };
    return {{"types", types},
            {"record_types", optional_list(scope.record_types)},
            {"contracts", contracts},
            {"functions", optional_list(scope.functions)},
            {"request_kinds", optional_list(scope.request_kinds)},
            {"not_before", scope.not_before ? Json(*scope.not_before) : Json()},
            {"not_after", scope.not_after ? Json(*scope.not_after) : Json()},
            {"may_delegate", scope.may_delegate},
            {"require_presence", scope.require_presence},
            {"approvals", scope.approvals ? rule_json(*scope.approvals) : Json()}};
}

/// What a statement says, for the person about to approve it: its type and
/// signer, and the fields of the actions the console prepares.
Json describe(const protocol::Statement& s) {
    Json out{{"ok", true},
             {"type", std::string(protocol::name(protocol::type_of(s.body)))},
             {"ledger", hex_or_null(s.ledger_id)},
             {"actor", hex_or_null(s.actor_id)},
             {"delegation", hex_or_null(s.delegation_id)},
             {"issued_at", s.issued_at},
             // The script its provenance names (v0.18), which the page
             // compares with the one it shows.
             {"script", hex_or_null(s.provenance ? s.provenance->script : std::nullopt)}};
    if (const auto* e = std::get_if<protocol::RecordEndorseBody>(&s.body)) {
        out["record"] = to_hex(e->record.bytes());
        out["role"] = e->role;
    } else if (const auto* r = std::get_if<protocol::RecordRevokeBody>(&s.body)) {
        out["record"] = to_hex(r->record.bytes());
        out["reason"] = r->reason ? Json(*r->reason) : Json();
    } else if (const auto* g = std::get_if<protocol::RecordRegisterBody>(&s.body)) {
        out["record_type"] = g->record_type;
        out["field_count"] = g->field_count;
        out["field_root"] = to_hex(g->field_root);
        out["supersedes"] = g->supersedes ? Json(to_hex(g->supersedes->bytes())) : Json();
        Json attachments = Json::array();
        for (const protocol::Attachment& a : g->attachments) {
            attachments.push_back({{"name", a.name},
                                   {"media_type", a.media_type},
                                   {"size", a.size},
                                   {"commitment", to_hex(a.commitment)}});
        }
        out["attachments"] = attachments;
        // The records it was made from (v0.18).
        Json sources = Json::array();
        for (const protocol::Source& source : g->sources) {
            sources.push_back({{"ledger", to_hex(source.ledger.bytes())},
                               {"record", to_hex(source.record.bytes())}});
        }
        out["sources"] = sources;
        // A script's approval (v0.18): its files' digests, which the page
        // compares with those it computed from the files.
        if (g->record_type == protocol::script_type && g->metadata) {
            if (const auto script = protocol::decode_script(*g->metadata)) {
                Json files = Json::array();
                for (const protocol::ScriptFile& f : script->files) {
                    files.push_back(
                        {{"path", f.path}, {"size", f.size}, {"digest", to_hex(f.digest)}});
                }
                out["script_approval"] = {
                    {"name", script->name},
                    {"version", script->version},
                    {"files", files},
                    {"deterministic", script->deterministic},
                    {"runtime", script->runtime ? Json(*script->runtime) : Json()}};
            }
        }
        // A contract consent's terms, which the page compares with the
        // proposal it shows.
        if (g->record_type == protocol::contract_consent_type && g->metadata) {
            if (const auto consent = protocol::decode_contract_consent(*g->metadata)) {
                out["consent"] = {{"ledger", to_hex(consent->ledger.bytes())},
                                  {"instance", to_hex(consent->instance.bytes())},
                                  {"function", consent->function},
                                  {"arguments", to_hex(consent->arguments.bytes())},
                                  {"head", consent->head},
                                  {"until", consent->until}};
            }
        }
        if (g->metadata) {
            if (Json terms = access_terms(g->record_type, *g->metadata); !terms.is_null()) {
                out["access"] = std::move(terms);
            }
        }
        // A claim's terms (v0.14), which the page compares with what it
        // asked to confirm.
        if (g->record_type == protocol::claim_type && g->metadata) {
            if (const auto claim = protocol::decode_claim(*g->metadata)) {
                out["claim"] = {{"source", to_hex(claim->source.bytes())},
                                {"text", protocol::claim_text(*claim)},
                                {"holds", claim->holds},
                                {"subject", claim->subject ? Json(*claim->subject) : Json()},
                                {"as_of", claim->as_of},
                                {"until", claim->until ? Json(*claim->until) : Json()},
                                {"answers", claim->answers
                                                ? Json(to_hex(claim->answers->second.bytes()))
                                                : Json()}};
            }
        }
        // Public metadata as the console writes it: text names and values.
        Json metadata = Json::object();
        if (g->metadata) {
            const cbor::Map* map = g->metadata->as_map();
            if (map == nullptr) {
                metadata = Json();
            } else {
                for (const auto& entry : *map) {
                    const std::string* key = entry.key.as_text();
                    const std::string* value = entry.value.as_text();
                    if (key == nullptr || value == nullptr) {
                        metadata = Json();
                        break;
                    }
                    metadata[*key] = *value;
                }
            }
        }
        out["metadata"] = metadata;
    } else if (const auto* d = std::get_if<protocol::ContractDeployBody>(&s.body)) {
        out["name"] = d->name ? Json(*d->name) : Json();
        out["language"] = d->language;
        out["code_size"] = d->code.size();
        const auto digest = provider().digest(crypto::HashAlg::sha256, d->code);
        out["code_sha256"] = digest ? Json(to_hex(digest->bytes())) : Json();
        Json functions = Json::array();
        for (const auto& [name, kind] : d->interface) {
            functions.push_back(name);
        }
        out["functions"] = functions;
    } else if (const auto* r = std::get_if<protocol::ContractRetireBody>(&s.body)) {
        out["contract"] = to_hex(r->contract.bytes());
        out["reason"] = r->reason ? Json(*r->reason) : Json();
    } else if (const auto* a = std::get_if<protocol::ActorRegisterBody>(&s.body)) {
        // A person, agent, or device the ledger learns, with its key.
        out["kind"] = static_cast<int>(a->kind);
        out["display_name"] = a->display_name;
        out["key"] = to_hex(a->key.bytes);
        out["responsible"] = a->responsible ? Json(to_hex(a->responsible->bytes())) : Json();
        out["model"] = a->agent && a->agent->model ? Json(*a->agent->model) : Json();
    } else if (const auto* p = std::get_if<protocol::ActorSetPresenceBody>(&s.body)) {
        // The passkeys that prove an actor's presence (the actor is the
        // statement's subject; "actor" is its signer).
        out["subject"] = to_hex(p->actor.bytes());
        Json credentials = Json::array();
        for (const protocol::PresenceCredential& c : p->credentials) {
            credentials.push_back({{"rp_id", c.rp_id},
                                   {"credential_id", to_base64url(c.credential_id)},
                                   {"label", c.label ? Json(*c.label) : Json()}});
        }
        out["credentials"] = credentials;
    } else if (const auto* g = std::get_if<protocol::DelegationGrantBody>(&s.body)) {
        out["grantee"] = to_hex(g->grantee.bytes());
        out["scope"] = scope_json(g->scope);
    } else if (const auto* v = std::get_if<protocol::DelegationRevokeBody>(&s.body)) {
        out["delegation"] = to_hex(v->delegation.bytes());
        out["reason"] = v->reason ? Json(*v->reason) : Json();
    } else if (const auto* rotated = std::get_if<protocol::ActorRotateKeyBody>(&s.body)) {
        // An actor's new key (the organization's root key, when the actor is
        // the ledger).
        out["subject"] = to_hex(rotated->actor.bytes());
        out["key"] = to_hex(rotated->key.bytes);
    } else if (const auto* revoked = std::get_if<protocol::ActorRevokeBody>(&s.body)) {
        out["subject"] = to_hex(revoked->actor.bytes());
        out["reason"] = revoked->reason ? Json(*revoked->reason) : Json();
    } else if (const auto* log_key = std::get_if<protocol::LedgerRotateLogKeyBody>(&s.body)) {
        out["key"] = to_hex(log_key->key.bytes);
    } else if (const auto* guardians = std::get_if<protocol::LedgerSetGuardiansBody>(&s.body)) {
        // The guardians (spec v0.20), or none; and what they guard (null:
        // everything the organization signs).
        out["guardians"] = guardians->guardians ? rule_json(*guardians->guardians) : Json();
        Json guarded;
        if (guardians->guarded) {
            guarded = Json::array();
            for (const protocol::StatementType t : *guardians->guarded) {
                guarded.push_back(std::string(protocol::name(t)));
            }
        }
        out["guarded"] = guarded;
    } else if (const auto* moved = std::get_if<protocol::RecordTransitionBody>(&s.body)) {
        out["record"] = to_hex(moved->record.bytes());
        out["from_state"] = moved->from_state;
        out["to_state"] = moved->to_state;
    } else if (const auto* c = std::get_if<protocol::ContractCallBody>(&s.body)) {
        // A creation names its contract, an action its instance and head; an
        // answer its request and status. The arguments as the page shows them.
        out["function"] = c->function;
        out["contract"] = c->contract ? Json(to_hex(c->contract->bytes())) : Json();
        out["instance"] = c->instance ? Json(to_hex(c->instance->bytes())) : Json();
        out["head"] = c->head ? Json(*c->head) : Json();
        out["arguments"] = cbor::diagnostic(c->arguments);
        out["consents"] = c->consents.size();
        if (c->answer) {
            out["request"] = to_hex(c->answer->request.bytes());
            out["status"] = static_cast<int>(c->answer->status);
        }
    }
    return out;
}

/// A field's salt: 16 or 32 bytes (spec v0.21), base64url.
std::optional<protocol::Salt> salt_of(const std::string& text) {
    const auto bytes = from_base64url(text);
    auto salt = bytes ? protocol::Salt::from_bytes(*bytes)
                      : Result<protocol::Salt>(std::unexpected(bytes.error()));
    if (!salt) {
        return std::nullopt;
    }
    return *salt;
}

} // namespace

extern "C" {

EMSCRIPTEN_KEEPALIVE char* kanhe_describe_payload(const std::uint8_t* payload, std::size_t size) {
    const auto statement = protocol::decode_payload(ByteView(payload, size));
    if (!statement) {
        return to_c_string({{"ok", false}, {"error", statement.error().detail}});
    }
    return to_c_string(describe(*statement));
}

/// The presence challenge of a payload signed with the key `kid` on a ledger
/// whose hash is `hash` (its COSE id), as base64url.
EMSCRIPTEN_KEEPALIVE char* kanhe_presence_challenge(const std::uint8_t* payload, std::size_t size,
                                                    const std::uint8_t* kid, std::size_t kid_size,
                                                    int hash) {
    const auto statement = protocol::decode_payload(ByteView(payload, size));
    const auto alg = crypto::hash_alg_from_cose(hash);
    const auto id = protocol::to_id(ByteView(kid, kid_size));
    if (!statement || !alg || !id) {
        return to_c_string({{"ok", false}, {"error", "not a payload, a key id, or a hash"}});
    }
    const auto challenge = protocol::presence_challenge(provider(), *alg, *statement, *id);
    if (!challenge) {
        return to_c_string({{"ok", false}, {"error", challenge.error().detail}});
    }
    return to_c_string({{"ok", true}, {"challenge", to_base64url(*challenge)}});
}

/// A statement someone else signed, waiting for approvals (spec v0.20): its
/// id recomputed from the signed bytes (the hash of exactly what its signer
/// signed, which an approval names), its key id, and what it says. With
/// `fields` (a CBOR array of encoded record fields; empty for none), the
/// fields shown to approvers, checked against the registration's field root
/// and count, as text where they are text. A ledger's hash is its COSE id.
EMSCRIPTEN_KEEPALIVE char* kanhe_statement_id(const std::uint8_t* signed_statement,
                                              std::size_t size, const std::uint8_t* fields,
                                              std::size_t fields_size, int hash) {
    const auto alg = crypto::hash_alg_from_cose(hash);
    if (!alg) {
        return to_c_string({{"ok", false}, {"error", "not a hash"}});
    }
    const auto parsed =
        protocol::parse_statement(provider(), ByteView(signed_statement, size), *alg);
    if (!parsed) {
        return to_c_string({{"ok", false}, {"error", parsed.error().detail}});
    }
    if (std::holds_alternative<protocol::GenesisBody>(parsed->statement.body)) {
        return to_c_string({{"ok", false}, {"error", "a genesis takes no approvals"}});
    }
    Json out{{"ok", true},
             {"id", to_hex(parsed->id.bytes())},
             {"kid", to_hex(parsed->kid.bytes())},
             {"statement", describe(parsed->statement)},
             {"fields", Json()}};
    if (fields_size == 0) {
        return to_c_string(out);
    }
    const auto list = cbor::decode(ByteView(fields, fields_size));
    const cbor::Array* items = list ? list->as_array() : nullptr;
    if (items == nullptr) {
        return to_c_string({{"ok", false}, {"error", "the fields shown are not a list"}});
    }
    std::vector<protocol::RecordField> shown;
    for (const cbor::Value& item : *items) {
        const Bytes* leaf = item.as_bytes();
        auto field = leaf != nullptr
                         ? protocol::decode_field(*leaf)
                         : Result<protocol::RecordField>(fail(Errc::malformed, "not a field"));
        if (!field) {
            return to_c_string({{"ok", false}, {"error", field.error().detail}});
        }
        shown.push_back(std::move(*field));
    }
    if (auto checked = protocol::check_shown_fields(provider(), *alg, parsed->statement, shown);
        !checked) {
        return to_c_string({{"ok", false}, {"error", checked.error().detail}});
    }
    Json named = Json::array();
    for (const protocol::RecordField& f : shown) {
        const std::string* text = f.value.as_text();
        named.push_back({{"name", f.name},
                         {"value", text != nullptr ? *text : cbor::diagnostic(f.value)},
                         {"text", text != nullptr}});
    }
    out["fields"] = std::move(named);
    return to_c_string(out);
}

/// The challenge of an approval's proof of presence (spec v0.20),
/// HASH("Kanhe approval v1" || kid || A), A the approval's payload without
/// its proof, computed with the core from the payload the console prepared
/// for the key `kid`; with what the payload says (its ledger, approver, and
/// statement), which the page compares with the statement it shows.
EMSCRIPTEN_KEEPALIVE char* kanhe_approval_challenge(const std::uint8_t* payload, std::size_t size,
                                                    const std::uint8_t* kid, std::size_t kid_size,
                                                    int hash) {
    const auto approval = protocol::decode_approval_payload(ByteView(payload, size));
    const auto alg = crypto::hash_alg_from_cose(hash);
    const auto id = protocol::to_id(ByteView(kid, kid_size));
    if (!approval || !alg || !id) {
        return to_c_string(
            {{"ok", false}, {"error", "not an approval's payload, a key id, or a hash"}});
    }
    if (approval->presence) {
        return to_c_string({{"ok", false}, {"error", "the payload carries a proof already"}});
    }
    const auto challenge = protocol::approval_challenge(provider(), *alg, *approval, *id);
    if (!challenge) {
        return to_c_string({{"ok", false}, {"error", challenge.error().detail}});
    }
    return to_c_string({{"ok", true},
                        {"challenge", to_base64url(*challenge)},
                        {"ledger", to_hex(approval->ledger.bytes())},
                        {"approver", to_hex(approval->approver.bytes())},
                        {"statement", to_hex(approval->statement.bytes())},
                        {"approved_at", approval->approved_at}});
}

/// The root of a record's fields, from what the person typed and the salts
/// the console chose: {"hash": COSE id, "fields": [{"name", "value",
/// "salt"}]}, values as text. So the page knows the registration commits to
/// exactly what it shows.
EMSCRIPTEN_KEEPALIVE char* kanhe_field_root(const char* request, std::size_t size) {
    const auto j = Json::parse(request, request + size, nullptr, false);
    const auto alg = j.is_object() && j.contains("hash") && j["hash"].is_number_integer()
                         ? crypto::hash_alg_from_cose(j["hash"].get<int>())
                         : std::nullopt;
    if (!alg || !j.contains("fields") || !j["fields"].is_array()) {
        return to_c_string({{"ok", false}, {"error", "send {hash, fields}"}});
    }
    std::vector<protocol::RecordField> fields;
    for (const auto& f : j["fields"]) {
        if (!f.is_object() || !f.contains("name") || !f["name"].is_string() ||
            !f.contains("value") || !f["value"].is_string() || !f.contains("salt") ||
            !f["salt"].is_string()) {
            return to_c_string({{"ok", false}, {"error", "a field is {name, value, salt}"}});
        }
        const auto salt = salt_of(f["salt"].get<std::string>());
        if (!salt) {
            return to_c_string({{"ok", false}, {"error", "a salt is 16 or 32 bytes, base64url"}});
        }
        fields.push_back({f["name"].get<std::string>(), *salt,
                          cbor::Value::text(f["value"].get<std::string>())});
    }
    const auto commitment = protocol::commit_fields(provider(), *alg, std::move(fields));
    if (!commitment) {
        return to_c_string({{"ok", false}, {"error", commitment.error().detail}});
    }
    return to_c_string({{"ok", true},
                        {"root", to_hex(commitment->root.bytes())},
                        {"count", commitment->leaves.size()}});
}

/// An attachment's commitment over the file's bytes and its salt.
EMSCRIPTEN_KEEPALIVE char* kanhe_attachment_commitment(const std::uint8_t* content,
                                                       std::size_t size, const std::uint8_t* salt,
                                                       std::size_t salt_size, int hash) {
    const auto alg = crypto::hash_alg_from_cose(hash);
    // 16 or 32 bytes (spec v0.21).
    if (!alg || !protocol::Salt::valid_size(salt_size)) {
        return to_c_string({{"ok", false}, {"error", "not a salt or a hash"}});
    }
    const auto digest = protocol::attachment_commitment(provider(), *alg, ByteView(salt, salt_size),
                                                        ByteView(content, size));
    if (!digest) {
        return to_c_string({{"ok", false}, {"error", digest.error().detail}});
    }
    return to_c_string({{"ok", true}, {"commitment", to_hex(digest->bytes())}});
}

/// A file's digest under a ledger's hash (its COSE id), as hex: what a
/// script's approval names for each of its files (v0.18).
EMSCRIPTEN_KEEPALIVE char* kanhe_digest(const std::uint8_t* content, std::size_t size, int hash) {
    const auto alg = crypto::hash_alg_from_cose(hash);
    if (!alg) {
        return to_c_string({{"ok", false}, {"error", "not a hash"}});
    }
    const auto digest = provider().digest(*alg, ByteView(content, size));
    if (!digest) {
        return to_c_string({{"ok", false}, {"error", digest.error().detail}});
    }
    return to_c_string({{"ok", true}, {"digest", to_hex(digest->bytes())}});
}

/// Verifying a proof, as `kanhe verify` and the standalone page do: the
/// files it may check, given one by one since the last reset, then the
/// proof, a record's evidence or a contract instance's.
namespace {
protocol::VerifyOptions proof_options;
} // namespace

EMSCRIPTEN_KEEPALIVE void kanhe_proof_reset() {
    proof_options = {};
}

EMSCRIPTEN_KEEPALIVE void kanhe_proof_attachment(const std::uint8_t* name, std::size_t name_size,
                                                 const std::uint8_t* data, std::size_t size) {
    proof_options.attachment_contents[std::string(reinterpret_cast<const char*>(name), name_size)] =
        Bytes(data, data + size);
}

/// `ledger` is the expected ledger id in hex, or empty.
EMSCRIPTEN_KEEPALIVE char* kanhe_proof_verify(const std::uint8_t* bundle, std::size_t size,
                                              const std::uint8_t* ledger, std::size_t ledger_size) {
    try {
        protocol::VerifyOptions options = proof_options;
        if (ledger_size > 0) {
            const auto bytes =
                from_hex(std::string(reinterpret_cast<const char*>(ledger), ledger_size));
            const auto id = bytes ? protocol::to_id(*bytes)
                                  : Result<protocol::Id>(fail(Errc::malformed, "not hex"));
            if (!id) {
                return to_c_string(
                    {{"verified", false}, {"error", "the ledger id is 64 hex digits"}});
            }
            options.expected_ledger = *id;
        }
        const bool checked = options.expected_ledger.has_value();
        const ByteView input(bundle, size);
        if (protocol::decode_contract_evidence(input)) {
            const auto report = protocol::verify_contract_evidence(provider(), input, options);
            if (!report) {
                return to_c_string(
                    {{"verified", false}, {"kind", "contract"}, {"error", report.error().detail}});
            }
            Json out = verifier::contract_report_json(*report, checked);
            out["kind"] = "contract";
            return to_c_string(out);
        }
        const auto report = protocol::verify_bundle(provider(), input, options);
        if (!report) {
            return to_c_string(
                {{"verified", false}, {"kind", "record"}, {"error", report.error().detail}});
        }
        Json out = verifier::report_json(*report, checked);
        out["kind"] = "record";
        return to_c_string(out);
    } catch (const std::exception& e) {
        return to_c_string(
            {{"verified", false}, {"error", std::string("internal error: ") + e.what()}});
    }
}

EMSCRIPTEN_KEEPALIVE void kanhe_free(char* text) {
    std::free(text);
}

} // extern "C"
