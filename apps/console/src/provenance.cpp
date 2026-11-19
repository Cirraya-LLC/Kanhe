// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// Where a record came from (spec v0.18). Scripts: an owner or an admin
// approves one version of a script, in person, by its files' digests (the
// browser computes them and sends only paths, sizes, and digests, never the
// files), and withdraws it by revoking its record; both with a passkey tap,
// as every approval (approve.cpp). Sources: a registration names the records
// it was made from, on this ledger or another, and the script it came from;
// a record's page shows each source as it stood when the record was made and
// as it stands now, and the script with its approval. A source on another
// ledger is shown from the proof kept here (that ledger's evidence of it),
// if one is.

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

#include <nlohmann/json.hpp>

#include <kanhe/client/support.hpp>
#include <kanhe/console/console.hpp>
#include <kanhe/console/kinds.hpp>
#include <kanhe/console/people.hpp>
#include <kanhe/core/bytes.hpp>
#include <kanhe/core/protocol/evidence.hpp>
#include <kanhe/core/protocol/log.hpp>
#include <kanhe/core/protocol/record.hpp>
#include <kanhe/core/protocol/record_types.hpp>
#include <kanhe/core/protocol/scripts.hpp>
#include <kanhe/core/protocol/state.hpp>
#include <kanhe/node/sources.hpp>

#include "responses.hpp"

namespace kanhe::console {

namespace {

constexpr std::string_view scripts_path = "/console/api/scripts";
constexpr std::string_view records_prefix = "/console/api/records/";
constexpr std::string_view proofs_suffix = "/source-proofs";
/// At most this many records the form offers as sources, newest first.
constexpr std::size_t source_limit = 500;
/// A script's note (how it was reviewed) and a withdrawal's reason.
constexpr std::size_t max_note = 1000;

std::string hex_of(const protocol::Id& id) {
    return to_hex(id.bytes());
}

std::string short_of(const protocol::Id& id) {
    return hex_of(id).substr(0, 12);
}

std::optional<protocol::Id> id_of(std::string_view hex) {
    const auto bytes = from_hex(hex);
    if (!bytes) {
        return std::nullopt;
    }
    const auto id = protocol::to_id(*bytes);
    return id ? std::optional(*id) : std::nullopt;
}

std::string text_of(const nlohmann::json& body, std::string_view key) {
    const auto it = body.find(key);
    return it != body.end() && it->is_string() ? it->get<std::string>() : std::string();
}

nlohmann::json actor_view(const protocol::LedgerState& state, const protocol::Id& id) {
    const protocol::ActorState* a = state.actor(id);
    return {{"id", hex_of(id)},
            {"name", a != nullptr ? nlohmann::json(a->display_name) : nlohmann::json()}};
}

/// Why there is no ledger to read: locked (the API opens once unlocked), or
/// not there yet.
http::Response no_ledger(const KeyStore* keys) {
    if (keys != nullptr && keys->initialized() && !keys->unlocked()) {
        return error(423, "locked", "the console is locked: unlock it first");
    }
    return error(503, "unavailable", "the console has no ledger yet");
}

http::Response only(std::string_view method) {
    http::Response refused = error(405, "unsupported", "method not allowed");
    refused.headers.emplace_back("Allow", std::string(method));
    return refused;
}

/// The index of the statement that revoked `record`: the last of its
/// history but the registration of a newer version (a revoked record may
/// still be superseded, and nothing else follows its revocation).
std::optional<std::uint64_t> revocation_index(const protocol::RecordState& record) {
    if (!record.revoked) {
        return std::nullopt;
    }
    for (std::size_t i = record.history.size(); i > 0; --i) {
        const std::uint64_t index = record.history[i - 1];
        if (!record.superseded_by || index != record.superseded_at_index) {
            return index;
        }
    }
    return std::nullopt;
}

std::string_view status_key(protocol::SourceStatus status) {
    switch (status) {
    case protocol::SourceStatus::not_yet:
        return "not_yet";
    case protocol::SourceStatus::live:
        return "live";
    case protocol::SourceStatus::revoked:
        return "revoked";
    case protocol::SourceStatus::replaced:
        return "replaced";
    }
    return "live";
}

/// Where a source on another ledger stood when a record of this one was
/// registered (`record_time`) and at its proof's checkpoint, from the
/// proof's events (as the verifier says it, section 11, step 10).
struct Standing {
    protocol::SourceStatus then = protocol::SourceStatus::live;
    protocol::SourceStatus now = protocol::SourceStatus::live;
    std::optional<protocol::Timestamp> changed_at;
    std::optional<protocol::Id> replaced_by;
};

Standing standing_of(const protocol::EvidenceReport& report, protocol::Timestamp record_time) {
    std::optional<protocol::Timestamp> revoked;
    std::optional<protocol::Timestamp> replaced;
    std::optional<protocol::Id> replaced_by;
    for (const protocol::RecordEvent& e : report.events) {
        if (e.type == protocol::StatementType::record_revoke && !revoked) {
            revoked = e.registered_at;
        }
        if (e.new_version && !replaced) {
            replaced = e.registered_at;
            replaced_by = e.new_version;
        }
    }
    const protocol::Timestamp registered =
        report.events.empty() ? protocol::Timestamp{0} : report.events.front().registered_at;
    Standing out;
    out.then = protocol::source_status_at(registered, revoked, replaced, record_time);
    out.now =
        protocol::source_status_at(registered, revoked, replaced, report.checkpoint.timestamp);
    if (out.now == protocol::SourceStatus::revoked) {
        out.changed_at = revoked;
    } else if (out.now == protocol::SourceStatus::replaced) {
        out.changed_at = replaced;
        out.replaced_by = replaced_by;
    }
    return out;
}

/// The name of the console's kind of `type`, if it has one.
nlohmann::json kind_name(const std::vector<Kind>& kinds, const std::string& type) {
    const auto kind = std::ranges::find(kinds, type, &Kind::type);
    return kind != kinds.end() ? nlohmann::json(kind->name) : nlohmann::json();
}

} // namespace

nlohmann::json script_terms(const cbor::Value& metadata) {
    const auto script = protocol::decode_script(metadata);
    if (!script) {
        return nullptr;
    }
    nlohmann::json files = nlohmann::json::array();
    for (const protocol::ScriptFile& f : script->files) {
        files.push_back({{"path", f.path}, {"size", f.size}, {"digest", to_hex(f.digest)}});
    }
    return {{"name", script->name},
            {"version", script->version},
            {"files", std::move(files)},
            {"deterministic", script->deterministic},
            {"runtime", script->runtime ? nlohmann::json(*script->runtime) : nlohmann::json()}};
}

std::optional<Console::Logged> Console::logged(std::uint64_t index) const {
    const ledger::Ledger* served = ledger();
    if (served == nullptr) {
        return std::nullopt;
    }
    const crypto::HashAlg hash = served->hash();
    std::optional<Logged> out;
    static_cast<void>(served->visit_entry(index, [&](ByteView bytes) {
        const auto entry = protocol::decode_log_entry(bytes);
        if (!entry || entry->is_state_commitment()) {
            return;
        }
        auto parsed = protocol::parse_statement(*services_.provider, entry->statement, hash);
        if (parsed) {
            out = Logged{std::move(parsed->statement), entry->registered_at};
        }
    }));
    return out;
}

nlohmann::json Console::script_view(const protocol::LedgerState& state,
                                    const protocol::RecordState& record) const {
    if (record.record_type != protocol::script_type) {
        return nullptr;
    }
    const auto approval = logged(record.registered_at_index);
    const auto* body =
        approval ? std::get_if<protocol::RecordRegisterBody>(&approval->statement.body) : nullptr;
    nlohmann::json terms =
        body != nullptr && body->metadata ? script_terms(*body->metadata) : nlohmann::json();
    if (terms.is_null()) {
        return nullptr;
    }
    // How the approver proved presence: always in person (the ledger
    // refuses a script otherwise), with a passkey or a hardware key.
    nlohmann::json in_person;
    if (const auto& proof = approval->statement.presence) {
        in_person = "passkey";
        if (const protocol::ActorState* person = state.actor(protocol::Id(record.registrant))) {
            for (const protocol::PresenceCredential& c : person->presence) {
                if (c.credential_id == proof->credential_id &&
                    c.method == protocol::PresenceMethod::hardware_key) {
                    in_person = "hardware-key";
                }
            }
        }
    }
    nlohmann::json withdrawn_at;
    nlohmann::json reason;
    if (const auto index = revocation_index(record)) {
        if (const auto withdrawal = logged(*index)) {
            withdrawn_at = withdrawal->registered_at;
            if (const auto* revoke =
                    std::get_if<protocol::RecordRevokeBody>(&withdrawal->statement.body);
                revoke != nullptr && revoke->reason) {
                reason = *revoke->reason;
            }
        }
    }
    terms["id"] = hex_of(protocol::Id(record.id));
    terms["status"] = record.revoked ? "withdrawn" : "approved";
    terms["approved_by"] = actor_view(state, protocol::Id(record.registrant));
    terms["approved_at"] = approval->registered_at;
    terms["in_person"] = in_person;
    terms["withdrawn_at"] = withdrawn_at;
    terms["withdraw_reason"] = reason;
    terms["index"] = record.registered_at_index;
    return terms;
}

http::Response Console::scripts_route(const http::Request& request) const {
    auto who = authenticate(request);
    if (auto* refused = std::get_if<http::Response>(&who)) {
        return std::move(*refused);
    }
    const Signed& signer = std::get<Signed>(who);
    if (request.method != "GET") {
        return only("GET");
    }
    const ledger::Ledger* const served = ledger();
    if (served == nullptr) {
        return no_ledger(services_.keys);
    }
    const std::string_view rest = std::string_view(request.path).substr(scripts_path.size());
    if (!rest.empty()) {
        // One script, for its page.
        const auto id = rest.starts_with('/') ? id_of(rest.substr(1)) : std::nullopt;
        if (!id) {
            return rest.starts_with('/')
                       ? error(400, "invalid_argument", "a script's id is 64 hex digits")
                       : error(404, "not_found", "no such console route");
        }
        nlohmann::json view;
        served->read_state([&](const protocol::LedgerState& state) {
            if (const protocol::RecordState* r = state.record(*id)) {
                view = script_view(state, *r);
            }
        });
        if (view.is_null()) {
            return error(404, "not_found", "no such script on this ledger");
        }
        view["may_withdraw"] = (signer.role == Role::owner || signer.role == Role::admin) &&
                               view["status"] == "approved";
        // The browser checks files against it under the ledger's hash.
        const crypto::HashAlg hash = served->hash();
        view["hash"] = {{"name", std::string(crypto::name(hash))}, {"cose", crypto::cose_id(hash)}};
        return json(200, view);
    }
    nlohmann::json scripts = nlohmann::json::array();
    crypto::HashAlg hash = served->hash();
    served->read_state([&](const protocol::LedgerState& state) {
        std::vector<const protocol::RecordState*> found;
        for (const auto& [key, r] : state.records()) {
            if (r.record_type == protocol::script_type) {
                found.push_back(&r);
            }
        }
        std::ranges::sort(found, std::greater{}, &protocol::RecordState::registered_at_index);
        for (const protocol::RecordState* r : found) {
            if (nlohmann::json view = script_view(state, *r); !view.is_null()) {
                scripts.push_back(std::move(view));
            }
        }
    });
    return json(
        200,
        {{"scripts", std::move(scripts)},
         // The browser computes each file's digest under it.
         {"hash", {{"name", std::string(crypto::name(hash))}, {"cose", crypto::cose_id(hash)}}},
         {"may_approve", signer.role == Role::owner || signer.role == Role::admin},
         {"locked", services_.keys == nullptr || !services_.keys->unlocked()}});
}

http::Response Console::sources_route(const http::Request& request) const {
    auto who = authenticate(request);
    if (auto* refused = std::get_if<http::Response>(&who)) {
        return std::move(*refused);
    }
    if (request.method != "GET") {
        return only("GET");
    }
    const ledger::Ledger* const served = ledger();
    if (served == nullptr) {
        return no_ledger(services_.keys);
    }
    const auto type = request.query.find("type");
    const std::vector<Kind> kinds = load_kinds(services_.directory);
    nlohmann::json records = nlohmann::json::array();
    nlohmann::json scripts = nlohmann::json::array();
    bool more = false;
    served->read_state([&](const protocol::LedgerState& state) {
        // As the ledger takes a local source: a record of a generic type,
        // neither revoked nor superseded.
        std::vector<const protocol::RecordState*> live;
        std::vector<const protocol::RecordState*> approved;
        for (const auto& [key, r] : state.records()) {
            if (r.record_type == protocol::script_type && !r.revoked) {
                approved.push_back(&r);
            }
            if (r.revoked || r.superseded_by ||
                protocol::find_record_type(r.record_type) != nullptr ||
                (type != request.query.end() && r.record_type != type->second)) {
                continue;
            }
            live.push_back(&r);
        }
        std::ranges::sort(live, std::greater{}, &protocol::RecordState::registered_at_index);
        more = live.size() > source_limit;
        live.resize(std::min(live.size(), source_limit));
        for (const protocol::RecordState* r : live) {
            records.push_back({{"id", hex_of(protocol::Id(r->id))},
                               {"type", r->record_type},
                               {"kind", kind_name(kinds, r->record_type)},
                               {"index", r->registered_at_index},
                               {"registrant", actor_view(state, protocol::Id(r->registrant))}});
        }
        std::ranges::sort(approved, std::greater{}, &protocol::RecordState::registered_at_index);
        for (const protocol::RecordState* r : approved) {
            const nlohmann::json view = script_view(state, *r);
            if (!view.is_null()) {
                scripts.push_back({{"id", view["id"]},
                                   {"name", view["name"]},
                                   {"version", view["version"]},
                                   {"deterministic", view["deterministic"]},
                                   {"runtime", view["runtime"]}});
            }
        }
    });
    return json(200,
                {{"records", std::move(records)}, {"more", more}, {"scripts", std::move(scripts)}});
}

std::variant<std::pair<protocol::RecordRegisterBody, Draft>, http::Response>
Console::script_draft(const nlohmann::json& intent) const {
    auto bad = [](const std::string& message) {
        return error(400, "invalid_argument", message);
    };
    protocol::Script script;
    script.name = text_of(intent, "name");
    script.version = text_of(intent, "version");
    if (script.name.empty() || script.name.size() > protocol::max_script_name) {
        return bad("a script's name is 1 to 128 bytes, such as monthly-report");
    }
    if (script.version.empty() || script.version.size() > protocol::max_script_version) {
        return bad("a script's version is 1 to 64 bytes, such as 1.0");
    }
    if (const std::string runtime = text_of(intent, "runtime"); !runtime.empty()) {
        if (runtime.size() > protocol::max_script_runtime) {
            return bad("what runs a script is at most 128 bytes, such as python 3.12");
        }
        script.runtime = runtime;
    }
    if (const auto it = intent.find("deterministic"); it != intent.end() && !it->is_null()) {
        if (!it->is_boolean()) {
            return bad("deterministic is true or false");
        }
        script.deterministic = it->get<bool>();
    }
    const auto files = intent.find("files");
    if (files == intent.end() || !files->is_array() || files->empty() ||
        files->size() > protocol::max_script_files) {
        return bad("a script names 1 to 256 files: [{\"path\", \"size\", \"digest\"}]");
    }
    for (const auto& f : *files) {
        if (!f.is_object()) {
            return bad("a script's file is {\"path\", \"size\", \"digest\"}");
        }
        const std::string path = text_of(f, "path");
        if (!protocol::valid_script_path(path)) {
            return bad("a script's file is named by its path in the script's folder, with \"/\" "
                       "between its parts and no \"..\", such as src/main.py: " +
                       path);
        }
        const auto size = f.find("size");
        if (size == f.end() || !size->is_number_unsigned()) {
            return bad("a script's file gives its size in bytes: " + path);
        }
        const auto digest = from_hex(text_of(f, "digest"));
        if (!digest || digest->size() != protocol::id_size) {
            return bad("a file's digest is 64 hex digits, its content's hash under the ledger's "
                       "hash: " +
                       path);
        }
        script.files.push_back({path, size->get<std::uint64_t>(), *digest});
    }
    // In the order the ledger takes them: ascending by their paths' bytes.
    std::ranges::sort(script.files, {}, &protocol::ScriptFile::path);
    for (std::size_t i = 1; i < script.files.size(); ++i) {
        if (script.files[i].path == script.files[i - 1].path) {
            return bad("a script names each file once: " + script.files[i].path);
        }
    }
    const auto metadata = protocol::encode_script(script);
    if (!metadata) {
        return bad(std::string(metadata.error().detail));
    }
    std::string note = text_of(intent, "note");
    if (note.size() > max_note) {
        return bad("a note is at most 1000 bytes");
    }
    // Its one field, kept sealed with the approval, as the command line
    // keeps it: how it was reviewed.
    std::vector<protocol::RecordField> fields;
    fields.push_back({"reviewed", services_.entropy->bytes<protocol::salt_size>(),
                      cbor::Value::text(note.empty() ? std::string("approved") : note)});
    const auto commitment =
        protocol::commit_fields(*services_.provider, ledger()->hash(), std::move(fields));
    if (!commitment) {
        return bad(std::string(commitment.error().detail));
    }
    protocol::RecordRegisterBody body;
    body.record_type = std::string(protocol::script_type);
    body.field_root = Bytes(commitment->root.bytes().begin(), commitment->root.bytes().end());
    body.field_count = commitment->leaves.size();
    body.metadata = *metadata;
    Draft draft;
    draft.vault.fields = commitment->fields;
    return std::pair(std::move(body), std::move(draft));
}

std::variant<protocol::RecordRevokeBody, http::Response>
Console::script_withdrawal(const nlohmann::json& intent) const {
    const auto id = id_of(text_of(intent, "script"));
    if (!id) {
        return error(400, "invalid_argument", "name the script by its full id (hex)");
    }
    const std::string reason = text_of(intent, "reason");
    if (reason.size() > max_note) {
        return error(400, "invalid_argument", "a reason is at most 1000 bytes");
    }
    std::optional<http::Response> refused;
    ledger()->read_state([&](const protocol::LedgerState& state) {
        const protocol::RecordState* r = state.record(*id);
        if (r == nullptr || r->record_type != protocol::script_type) {
            refused = error(404, "not_found", "no such script on this ledger");
        } else if (r->revoked) {
            refused = error(409, "conflict", "that script was withdrawn already");
        }
    });
    if (refused) {
        return std::move(*refused);
    }
    return protocol::RecordRevokeBody{*id, reason.empty() ? std::nullopt : std::optional(reason)};
}

std::optional<std::string> Console::provenance_draft(const nlohmann::json& intent,
                                                     const std::string& user,
                                                     protocol::RecordRegisterBody& body,
                                                     Draft& draft) const {
    // The sources named: this ledger's records by their ids, another
    // ledger's by its id and the record's.
    struct Named {
        std::optional<protocol::Id> ledger;
        protocol::Id record;
    };
    std::vector<Named> named;
    if (const auto it = intent.find("sources"); it != intent.end() && !it->is_null()) {
        if (!it->is_array()) {
            return std::string("sources are a list: [{\"record\": ID}, {\"ledger\": ID, "
                               "\"record\": ID}]");
        }
        if (it->size() > protocol::max_sources) {
            return std::string("a record names at most 64 sources");
        }
        for (const auto& s : *it) {
            if (!s.is_object()) {
                return std::string("a source is {\"record\": ID}, with its \"ledger\" if another");
            }
            const auto record = id_of(text_of(s, "record"));
            if (!record) {
                return std::string("name each source's record by its full id (hex)");
            }
            std::optional<protocol::Id> ledger;
            if (const std::string l = text_of(s, "ledger"); !l.empty()) {
                ledger = id_of(l);
                if (!ledger) {
                    return std::string("a source's ledger is named by its full id (hex)");
                }
            }
            named.push_back({ledger, *record});
        }
    }
    std::optional<protocol::Id> script;
    if (const std::string s = text_of(intent, "script"); !s.empty()) {
        script = id_of(s);
        if (!script) {
            return std::string("name the script by its full id (hex)");
        }
    }
    std::vector<std::string> proofs;
    if (const auto it = intent.find("source_proofs"); it != intent.end() && !it->is_null()) {
        if (!it->is_array() ||
            !std::ranges::all_of(*it, [](const auto& v) { return v.is_string(); })) {
            return std::string("source proofs are the uploads' ids");
        }
        for (const auto& v : *it) {
            proofs.push_back(v.get<std::string>());
        }
    }
    if (named.empty() && !script && proofs.empty()) {
        return std::nullopt;
    }
    // Checked as the ledger checks them, with what it says in words.
    std::vector<protocol::Source> sources;
    std::optional<std::string> problem;
    protocol::Id own;
    ledger()->read_state([&](const protocol::LedgerState& state) {
        own = state.ledger_id();
        for (const Named& n : named) {
            const protocol::Source source{n.ledger.value_or(own), n.record};
            if (std::ranges::contains(sources, source)) {
                problem = "a source is named twice: " + short_of(n.record);
                return;
            }
            sources.push_back(source);
            if (source.ledger != own) {
                continue;
            }
            const protocol::RecordState* r = state.record(n.record);
            if (r == nullptr) {
                problem = "no record " + short_of(n.record) + " on this ledger to name as a source";
            } else if (protocol::find_record_type(r->record_type) != nullptr) {
                problem = "a source is a document of a kind, not one of the protocol's own records "
                          "(" +
                          r->record_type + ")";
            } else if (r->revoked) {
                problem = "the source " + short_of(n.record) + " was revoked: name a live record";
            } else if (r->superseded_by) {
                problem = "the source " + short_of(n.record) +
                          " was replaced by a newer version: name the latest one";
            }
            if (problem) {
                return;
            }
        }
        if (script) {
            const protocol::RecordState* r = state.record(*script);
            if (r == nullptr || r->record_type != protocol::script_type) {
                problem = "no such script on this ledger";
            } else if (r->revoked) {
                problem = "that script was withdrawn: records can no longer name it";
            }
        }
    });
    if (problem) {
        return problem;
    }
    // Each proof the evidence of one source on another ledger, as that
    // ledger gave it; kept with the record once it is registered.
    for (const std::string& upload : proofs) {
        std::filesystem::path path;
        {
            const std::lock_guard lock(mutex_);
            const auto it = uploads_.find(upload);
            if (it != uploads_.end() && it->second.user == user &&
                it->second.expires > services_.clock->now()) {
                path = it->second.path;
            }
        }
        if (path.empty()) {
            return std::string("a proof file is no longer here: choose it again");
        }
        auto checked =
            node::check_source_proof(*services_.provider, client::read_file(path), sources, own);
        if (!checked) {
            return "a source's proof does not hold: " + std::string(checked.error().detail);
        }
        if (std::ranges::any_of(draft.source_proofs,
                                [&](const auto& p) { return p.first == checked->source; })) {
            return std::string("two proofs of one source were given");
        }
        draft.source_proofs.emplace_back(checked->source, std::move(checked->proof));
        draft.proof_uploads.push_back(upload);
    }
    body.sources = std::move(sources);
    draft.script = script;
    return std::nullopt;
}

nlohmann::json Console::provenance_summary(const protocol::LedgerState& state,
                                           const protocol::Statement& statement) const {
    nlohmann::json out{{"script", nullptr}};
    if (statement.provenance && statement.provenance->script) {
        const protocol::Id& id = *statement.provenance->script;
        out["script"] = hex_of(id);
        if (const protocol::RecordState* r = state.record(id)) {
            if (const nlohmann::json view = script_view(state, *r); !view.is_null()) {
                out["script_name"] =
                    view["name"].get<std::string>() + " " + view["version"].get<std::string>();
            }
        }
    }
    if (const auto* g = std::get_if<protocol::RecordRegisterBody>(&statement.body)) {
        const std::vector<Kind> kinds = load_kinds(services_.directory);
        nlohmann::json sources = nlohmann::json::array();
        for (const protocol::Source& s : g->sources) {
            const bool local = s.ledger == state.ledger_id();
            nlohmann::json j{
                {"ledger", hex_of(s.ledger)}, {"record", hex_of(s.record)}, {"local", local}};
            if (local) {
                const protocol::RecordState* r = state.record(s.record);
                j["type"] = r != nullptr ? nlohmann::json(r->record_type) : nlohmann::json();
                j["kind"] = r != nullptr ? kind_name(kinds, r->record_type) : nlohmann::json();
            } else {
                const std::string party = ledger_name(state, s.ledger);
                j["party"] = party.empty() ? nlohmann::json() : nlohmann::json(party);
            }
            sources.push_back(std::move(j));
        }
        out["sources"] = std::move(sources);
    }
    if (const auto* v = std::get_if<protocol::RecordRevokeBody>(&statement.body)) {
        if (const protocol::RecordState* r = state.record(v->record)) {
            if (const nlohmann::json view = script_view(state, *r); !view.is_null()) {
                out["withdraws"] = {{"name", view["name"]}, {"version", view["version"]}};
            }
        }
    }
    return out;
}

nlohmann::json Console::made_from(const protocol::LedgerState& state,
                                  const protocol::RecordState& record,
                                  const protocol::RecordRegisterBody& body) const {
    const auto registration = logged(record.registered_at_index);
    nlohmann::json out{{"registered_at", registration ? nlohmann::json(registration->registered_at)
                                                      : nlohmann::json()},
                       {"script", nullptr},
                       {"sources", nlohmann::json::array()},
                       {"stale", false}};
    if (registration && registration->statement.provenance &&
        registration->statement.provenance->script) {
        const protocol::Id& id = *registration->statement.provenance->script;
        nlohmann::json script{{"id", hex_of(id)}};
        if (const protocol::RecordState* r = state.record(id)) {
            if (nlohmann::json view = script_view(state, *r); !view.is_null()) {
                script = std::move(view);
            }
        }
        out["script"] = std::move(script);
    }
    auto time_at = [&](std::uint64_t index) {
        const auto entry = logged(index);
        return entry ? nlohmann::json(entry->registered_at) : nlohmann::json();
    };
    const std::vector<Kind> kinds = load_kinds(services_.directory);
    bool stale = false;
    for (const protocol::Source& s : body.sources) {
        const bool local = s.ledger == state.ledger_id();
        nlohmann::json j{{"ledger", hex_of(s.ledger)},
                         {"record", hex_of(s.record)},
                         {"local", local},
                         {"type", nullptr},
                         {"at_record", nullptr},
                         {"now", nullptr},
                         {"changed_at", nullptr},
                         {"replaced_by", nullptr}};
        if (!local) {
            // Filled in from the proof kept here, if any (add_kept_proofs).
            const std::string party = ledger_name(state, s.ledger);
            j["party"] = party.empty() ? nlohmann::json() : nlohmann::json(party);
            j["proof_kept"] = false;
            j["organization"] = nullptr;
            j["as_of"] = nullptr;
            out["sources"].push_back(std::move(j));
            continue;
        }
        const protocol::RecordState* source = state.record(s.record);
        if (source == nullptr) {
            // Not on this ledger (the ledger refused that when the record
            // was registered; shown as it is).
            j["now"] = "unknown";
            out["sources"].push_back(std::move(j));
            continue;
        }
        j["type"] = source->record_type;
        j["kind"] = kind_name(kinds, source->record_type);
        // By log position, exactly: where it stood just before this
        // record's registration, and where it stands now.
        const auto revoked = revocation_index(*source);
        const auto replaced =
            source->superseded_by ? std::optional(source->superseded_at_index) : std::nullopt;
        auto at = [&](std::uint64_t index) -> std::string_view {
            if (index < source->registered_at_index) {
                return "not_yet";
            }
            if (revoked && *revoked < index) {
                return "revoked";
            }
            if (replaced && *replaced < index) {
                return "replaced";
            }
            return "live";
        };
        j["at_record"] = std::string(at(record.registered_at_index));
        j["now"] = source->revoked ? "revoked" : source->superseded_by ? "replaced" : "live";
        if (revoked) {
            j["changed_at"] = time_at(*revoked);
        } else if (replaced) {
            j["changed_at"] = time_at(*replaced);
            j["replaced_by"] = to_hex(source->superseded_by->bytes());
        }
        stale = stale || source->revoked || source->superseded_by.has_value();
        out["sources"].push_back(std::move(j));
    }
    out["stale"] = stale;
    return out;
}

void Console::add_kept_proofs(nlohmann::json& made, const protocol::Id& record,
                              const std::vector<protocol::Source>& sources,
                              const protocol::Id& ledger) const {
    if (std::ranges::none_of(sources,
                             [&](const protocol::Source& s) { return s.ledger != ledger; })) {
        return;
    }
    const protocol::Timestamp record_time =
        made["registered_at"].is_number() ? made["registered_at"].get<protocol::Timestamp>() : 0;
    bool stale = made["stale"].get<bool>();
    for (const node::KeptSourceProof& kept :
         node::kept_source_proofs(services_.directory.parent_path(), record)) {
        nlohmann::json* entry = nullptr;
        for (nlohmann::json& s : made["sources"]) {
            if (!s["local"].get<bool>() && s["ledger"] == hex_of(kept.source.ledger) &&
                s["record"] == hex_of(kept.source.record)) {
                entry = &s;
            }
        }
        if (entry == nullptr) {
            continue;
        }
        nlohmann::json& j = *entry;
        j["proof_kept"] = true;
        // Checked again as the evidence checks it, with no trust of its own:
        // that ledger's statements, complete at its checkpoint.
        const auto checked =
            node::check_source_proof(*services_.provider, kept.proof, sources, ledger);
        if (!checked) {
            j["proof_problem"] = std::string(checked.error().detail);
            continue;
        }
        const protocol::EvidenceReport& report = checked->report;
        const Standing standing = standing_of(report, record_time);
        j["organization"] = report.organization;
        j["type"] = report.record_type;
        j["at_record"] = std::string(status_key(standing.then));
        j["now"] = std::string(status_key(standing.now));
        j["as_of"] = report.checkpoint.timestamp;
        j["changed_at"] =
            standing.changed_at ? nlohmann::json(*standing.changed_at) : nlohmann::json();
        j["replaced_by"] =
            standing.replaced_by ? nlohmann::json(hex_of(*standing.replaced_by)) : nlohmann::json();
        stale = stale || standing.now == protocol::SourceStatus::revoked ||
                standing.now == protocol::SourceStatus::replaced;
    }
    made["stale"] = stale;
}

http::Response Console::source_proof_route(const http::Request& request) const {
    auto who = authenticate(request);
    if (auto* refused = std::get_if<http::Response>(&who)) {
        return std::move(*refused);
    }
    const Signed& signer = std::get<Signed>(who);
    if (request.method != "POST") {
        return only("POST");
    }
    if (signer.role == Role::viewer) {
        return error(403, "forbidden", "a viewer reads and verifies, and keeps nothing");
    }
    const ledger::Ledger* const served = ledger();
    if (served == nullptr) {
        return no_ledger(services_.keys);
    }
    const std::string_view path = request.path;
    if (path.size() < records_prefix.size() + proofs_suffix.size()) {
        return error(404, "not_found", "no such console route");
    }
    const auto id = id_of(path.substr(records_prefix.size(),
                                      path.size() - records_prefix.size() - proofs_suffix.size()));
    if (!id) {
        return error(400, "invalid_argument", "a record's id is 64 hex digits");
    }
    const auto body =
        nlohmann::json::parse(request.body.begin(), request.body.end(), nullptr, false);
    const std::string upload = body.is_object() ? text_of(body, "upload") : std::string();
    std::filesystem::path file;
    {
        const std::lock_guard lock(mutex_);
        const auto it = uploads_.find(upload);
        if (it != uploads_.end() && it->second.user == signer.user &&
            it->second.expires > services_.clock->now()) {
            file = it->second.path;
        }
    }
    if (file.empty()) {
        return error(404, "not_found", "that file is no longer here: choose it again");
    }
    std::optional<http::Response> refused;
    std::vector<protocol::Source> sources;
    protocol::Id own;
    served->read_state([&](const protocol::LedgerState& state) {
        own = state.ledger_id();
        const protocol::RecordState* r = state.record(*id);
        if (r == nullptr) {
            refused = error(404, "not_found", "no such record on this ledger");
            return;
        }
        if (!may_read_private(signer, state, *r)) {
            refused =
                error(403, "forbidden", "you may not change what this record's proof carries");
            return;
        }
        if (const auto registered = registration(state, *id)) {
            sources = registered->sources;
        }
    });
    if (refused) {
        return std::move(*refused);
    }
    if (std::ranges::none_of(sources, [&](const protocol::Source& s) { return s.ledger != own; })) {
        return error(409, "conflict", "this record names no source on another ledger");
    }
    const auto checked =
        node::check_source_proof(*services_.provider, client::read_file(file), sources, own);
    if (!checked) {
        return error(422, "refused",
                     "the proof does not hold: " + std::string(checked.error().detail));
    }
    if (const auto kept = node::keep_source_proof(services_.directory.parent_path(), *id,
                                                  checked->source, checked->proof);
        !kept) {
        return error(500, "internal",
                     "the proof could not be kept: " + std::string(kept.error().detail));
    }
    forget_uploads({upload});
    log_activity(signer.user, "sources.prove",
                 {{"record", hex_of(*id)},
                  {"ledger", hex_of(checked->source.ledger)},
                  {"source", hex_of(checked->source.record)}});
    return json(200, {{"kept",
                       {{"ledger", hex_of(checked->source.ledger)},
                        {"record", hex_of(checked->source.record)},
                        {"organization", checked->report.organization},
                        {"type", checked->report.record_type}}}});
}

} // namespace kanhe::console
