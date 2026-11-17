// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// Scripts (spec v0.18): a person approves, in person, one version of a
// script by its files' digests; records name the script they came from
// (--script), and their evidence shows what it was and who approved it.

#include <algorithm>
#include <filesystem>
#include <map>
#include <optional>
#include <print>
#include <string>
#include <system_error>
#include <vector>

#include <kanhe/core/protocol/scripts.hpp>

#include "commands.hpp"
#include "output.hpp"
#include "records.hpp"

namespace kanhe::cli {

namespace {

/// A script on the ledger: its record, its metadata, and its approval.
struct Listed {
    const protocol::RecordState* record;
    protocol::Script script;
};

std::vector<Listed> scripts(const client::Session& session) {
    std::vector<Listed> out;
    for (const auto& [key, record] : session.state().records()) {
        if (record.record_type != protocol::script_type) {
            continue;
        }
        const auto body = client::registration_of(session, protocol::Id(record.id));
        if (auto script = body.metadata
                              ? protocol::decode_script(*body.metadata)
                              : Result<protocol::Script>(fail(Errc::malformed, "no metadata"))) {
            out.push_back({&record, std::move(*script)});
        }
    }
    return out;
}

Listed find_script(const client::Session& session, const std::string& text) {
    const protocol::Id id = session.record_id(text);
    auto all = scripts(session);
    const auto found = std::ranges::find_if(
        all, [&](const Listed& s) { return protocol::Id(s.record->id) == id; });
    if (found == all.end()) {
        throw CommandError{"no script " + hex_id(id)};
    }
    return *found;
}

Json script_json(const client::Session& session, const Listed& s) {
    Json files = Json::array();
    for (const protocol::ScriptFile& f : s.script.files) {
        files.push_back({{"path", f.path}, {"size", f.size}, {"digest", to_hex(f.digest)}});
    }
    const protocol::RecordState& r = *s.record;
    const protocol::SignedStatement approval = session.statement(r.registered_at_index);
    std::optional<std::string> method;
    if (const protocol::ActorState* person =
            approval.statement.actor_id ? session.state().actor(*approval.statement.actor_id)
                                        : nullptr;
        person != nullptr && approval.statement.presence) {
        for (const protocol::PresenceCredential& c : person->presence) {
            if (c.credential_id == approval.statement.presence->credential_id) {
                method = c.method == protocol::PresenceMethod::hardware_key ? "hardware-key"
                                                                            : "webauthn";
            }
        }
    }
    Json out{{"script", id_json(protocol::Id(r.id))},
             {"name", s.script.name},
             {"version", s.script.version},
             {"files", std::move(files)},
             {"deterministic", s.script.deterministic},
             {"runtime", s.script.runtime ? Json(*s.script.runtime) : Json(nullptr)},
             {"status", r.revoked ? "withdrawn" : "approved"},
             {"approved_by", actor_ref(session, r.registrant)},
             {"approved_at", iso_time(session.log_entry(r.registered_at_index).registered_at)},
             {"presence", method ? Json(*method) : Json(nullptr)},
             {"withdrawn_at", nullptr}};
    if (r.revoked) {
        const std::vector<std::uint64_t> history = r.history.to_vector();
        out["withdrawn_at"] = iso_time(session.log_entry(history.back()).registered_at);
    }
    return out;
}

/// A file argument as a script's path: relative, below the root, with "/"
/// between segments.
std::string script_path(const std::filesystem::path& relative, const std::string& given) {
    const std::string path = relative.lexically_normal().generic_string();
    if (relative.is_absolute() || !protocol::valid_script_path(path)) {
        throw UsageError{"a script's file is named by a path below --root (default: the current "
                         "directory), without \"..\": " +
                         given};
    }
    return path;
}

/// The files the arguments name, by their paths below `root`: a directory
/// adds every file under it, leaving out hidden ones (names starting with a
/// dot).
std::map<std::string, std::filesystem::path> collect(const std::filesystem::path& root,
                                                     const std::vector<std::string>& given) {
    std::map<std::string, std::filesystem::path> out;
    auto add = [&](const std::filesystem::path& relative, const std::string& as_given) {
        const std::string path = script_path(relative, as_given);
        if (!out.emplace(path, root / relative).second) {
            throw UsageError{"a script names each file once: " + path};
        }
    };
    for (const std::string& item : given) {
        const std::filesystem::path relative(item);
        const std::filesystem::path full = root / relative;
        std::error_code ec;
        if (std::filesystem::is_directory(full, ec)) {
            std::filesystem::recursive_directory_iterator it(full, ec);
            for (; !ec && it != std::filesystem::recursive_directory_iterator(); it.increment(ec)) {
                const std::string name = it->path().filename().string();
                if (name.starts_with(".")) {
                    if (it->is_directory(ec)) {
                        it.disable_recursion_pending();
                    }
                    continue;
                }
                if (it->is_regular_file(ec)) {
                    add(relative / it->path().lexically_relative(full), item);
                }
            }
            if (ec) {
                throw CommandError{"cannot read " + full.string() + ": " + ec.message()};
            }
        } else if (std::filesystem::is_regular_file(full, ec)) {
            add(relative, item);
        } else {
            throw UsageError{"no such file: " + full.string()};
        }
    }
    return out;
}

protocol::ScriptFile file_of(const client::Session& session, const std::string& path,
                             const std::filesystem::path& full) {
    const Bytes content = read_file(full);
    const auto digest = unwrap(session.provider().digest(session.state().hash(), content),
                               "hashing " + full.string());
    return {path, content.size(), Bytes(digest.bytes().begin(), digest.bytes().end())};
}

} // namespace

int cmd_script_approve(const Args& args) {
    Session session(args);
    const auto& given = args.positional();
    if (!args.has("presence") && !args.has("presence-key")) {
        throw UsageError{"a script is approved in person: give --presence (a passkey) or "
                         "--presence-key (a hardware key)"};
    }
    protocol::Script script;
    script.name = given[0];
    script.version = given[1];
    const std::filesystem::path root = args.get("root").value_or(".");
    for (const auto& [path, full] :
         collect(root, std::vector<std::string>(given.begin() + 2, given.end()))) {
        script.files.push_back(file_of(session, path, full));
    }
    script.deterministic = args.has("deterministic");
    script.runtime = args.get("runtime");
    const auto metadata = protocol::encode_script(script);
    if (!metadata) {
        throw UsageError{std::string(metadata.error().detail)};
    }
    IssueRequest request;
    request.record_type = std::string(protocol::script_type);
    request.metadata_value = *metadata;
    // How it was reviewed, kept sealed with the approval.
    request.fields = {{"reviewed", args.get("note").value_or("approved")}};
    request.delegation = args.get("delegation");
    request.provenance = session.provenance(args);
    request.presence = presence_request(args);
    const protocol::Id id = issue_record(session, *load_signer(args.need("as"), args), request);
    const Listed listed{session.state().record(id), script};
    return report_submitted(args, session, id, {{"script", script_json(session, listed)}},
                            std::format("approved script {} {} ({} file{}{}): {}", script.name,
                                        script.version, script.files.size(),
                                        script.files.size() == 1 ? "" : "s",
                                        script.deterministic ? ", deterministic" : "", hex_id(id)));
}

int cmd_script_list(const Args& args) {
    Session session(args);
    const auto name = args.get("name");
    Json out = Json::array();
    for (const Listed& s : scripts(session)) {
        if ((name && s.script.name != *name) || (s.record->revoked && !args.has("all"))) {
            continue;
        }
        if (args.json()) {
            out.push_back(script_json(session, s));
            continue;
        }
        std::println("{}  {:<9} {} {}  {} file{}  by {}", short_id(protocol::Id(s.record->id)),
                     s.record->revoked ? "withdrawn" : "approved", s.script.name, s.script.version,
                     s.script.files.size(), s.script.files.size() == 1 ? "" : "s",
                     session.actor_name(s.record->registrant));
    }
    if (args.json()) {
        print_json(out);
    }
    return exit_ok;
}

int cmd_script_show(const Args& args) {
    Session session(args);
    const Listed s = find_script(session, args.positional().front());
    const Json j = script_json(session, s);
    if (args.json()) {
        print_json(j);
        return exit_ok;
    }
    std::println("script:        {}", hex_id(protocol::Id(s.record->id)));
    std::println("name:          {} {}", s.script.name, s.script.version);
    std::println("deterministic: {}", s.script.deterministic ? "yes" : "no");
    if (s.script.runtime) {
        std::println("runtime:       {}", *s.script.runtime);
    }
    std::println("approved by:   {}, in person{}, at {}", session.actor_name(s.record->registrant),
                 j["presence"].is_null() ? "" : " (" + j["presence"].get<std::string>() + ")",
                 format_time(session.log_entry(s.record->registered_at_index).registered_at));
    if (s.record->revoked) {
        std::println("WITHDRAWN:     at {}", j["withdrawn_at"].get<std::string>());
    }
    for (const protocol::ScriptFile& f : s.script.files) {
        std::println("file:          {}  {} bytes  {}", f.path, f.size, to_hex(f.digest));
    }
    return exit_ok;
}

int cmd_script_revoke(const Args& args) {
    Session session(args);
    const Listed s = find_script(session, args.positional().front());
    const protocol::Id id(s.record->id);
    const protocol::Id revoked =
        session.submit(args, protocol::RecordRevokeBody{id, args.get("reason")});
    return report_submitted(args, session, revoked, {{"script", id_json(id)}},
                            "withdrew script " + s.script.name + " " + s.script.version + " (" +
                                hex_id(id) + "): records can no longer name it");
}

int cmd_script_check(const Args& args) {
    Session session(args);
    const Listed s = find_script(session, args.positional().front());
    const std::filesystem::path root =
        args.positional().size() > 1 ? std::filesystem::path(args.positional()[1]) : ".";
    Json files = Json::array();
    std::size_t differ = 0;
    for (const protocol::ScriptFile& f : s.script.files) {
        const std::string status =
            script_file_status(session.provider(), session.state().hash(), root, f);
        if (status != "same") {
            ++differ;
        }
        files.push_back({{"path", f.path}, {"status", status}});
        if (!args.json()) {
            std::println("{:<8} {}", status, f.path);
        }
    }
    if (args.json()) {
        print_json({{"script", id_json(protocol::Id(s.record->id))},
                    {"directory", root.string()},
                    {"same", differ == 0},
                    {"withdrawn", s.record->revoked},
                    {"files", std::move(files)}});
    } else if (differ == 0) {
        std::println("{} matches script {} {} as approved{}", root.string(), s.script.name,
                     s.script.version, s.record->revoked ? " (since withdrawn)" : "");
    } else {
        std::println("{} of {} files differ from script {} {} as approved", differ,
                     s.script.files.size(), s.script.name, s.script.version);
    }
    return differ == 0 ? exit_ok : exit_not_verified;
}

} // namespace kanhe::cli
