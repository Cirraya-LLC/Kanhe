// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include <algorithm>
#include <array>
#include <string>

#include <kanhe/core/protocol/claims.hpp>
#include <kanhe/core/protocol/scripts.hpp>

#include "reader.hpp"

namespace kanhe::protocol {

namespace {

/// A text value of 1 to `max_size` bytes under `key`, if there is one.
const std::string* text_of(const cbor::Value& metadata, std::string_view key,
                           std::size_t max_size) {
    const cbor::Value* v = metadata.find(key);
    const std::string* text = v != nullptr ? v->as_text() : nullptr;
    return text != nullptr && !text->empty() && text->size() <= max_size ? text : nullptr;
}

} // namespace

bool valid_script_path(std::string_view path) noexcept {
    if (path.empty() || path.size() > max_script_path) {
        return false;
    }
    std::size_t start = 0;
    while (true) {
        const std::size_t slash = path.find('/', start);
        const std::string_view segment =
            path.substr(start, slash == std::string_view::npos ? path.npos : slash - start);
        if (segment.empty() || segment == "." || segment == "..") {
            return false;
        }
        if (slash == std::string_view::npos) {
            return true;
        }
        start = slash + 1;
    }
}

Result<Script> decode_script(const cbor::Value& metadata) {
    const cbor::Map* map = metadata.as_map();
    if (map == nullptr) {
        return fail(Errc::malformed, "a script's metadata is a map");
    }
    constexpr std::array<std::string_view, 5> known{"name", "version", "files", "deterministic",
                                                    "runtime"};
    for (const cbor::MapEntry& e : *map) {
        const std::string* key = e.key.as_text();
        if (key == nullptr || !std::ranges::contains(known, std::string_view(*key))) {
            return fail(Errc::malformed, "a script's metadata has an unknown key");
        }
    }
    Script out;
    const std::string* name = text_of(metadata, "name", max_script_name);
    if (name == nullptr) {
        return fail(Errc::malformed, "a script's name is 1 to 128 bytes");
    }
    out.name = *name;
    const std::string* version = text_of(metadata, "version", max_script_version);
    if (version == nullptr) {
        return fail(Errc::malformed, "a script's version is 1 to 64 bytes");
    }
    out.version = *version;
    const cbor::Value* files = metadata.find("files");
    const cbor::Array* list = files != nullptr ? files->as_array() : nullptr;
    if (list == nullptr || list->empty() || list->size() > max_script_files) {
        return fail(Errc::malformed, "a script has 1 to 256 files");
    }
    for (const cbor::Value& item : *list) {
        const cbor::Array* f = item.as_array();
        if (f == nullptr || f->size() != 3) {
            return fail(Errc::malformed, "a script's file is [path, size, digest]");
        }
        const std::string* path = (*f)[0].as_text();
        const auto size = (*f)[1].as_uint64();
        const Bytes* digest = (*f)[2].as_bytes();
        if (path == nullptr || !valid_script_path(*path)) {
            return fail(Errc::malformed,
                        "a script's file path is 1 to 1024 bytes, relative, with no empty, "
                        "\".\", or \"..\" segment");
        }
        if (!size) {
            return fail(Errc::malformed, "a script's file size is an unsigned integer");
        }
        if (digest == nullptr || digest->size() != id_size) {
            return fail(Errc::malformed, "a script's file digest is 32 bytes");
        }
        if (!out.files.empty() && !(out.files.back().path < *path)) {
            return fail(Errc::malformed, "a script's files ascend strictly by path");
        }
        out.files.push_back({*path, *size, *digest});
    }
    const cbor::Value* deterministic = metadata.find("deterministic");
    if (deterministic == nullptr || !deterministic->as_bool()) {
        return fail(Errc::malformed, "a script says whether it is deterministic");
    }
    out.deterministic = *deterministic->as_bool();
    if (metadata.find("runtime") != nullptr) {
        const std::string* runtime = text_of(metadata, "runtime", max_script_runtime);
        if (runtime == nullptr) {
            return fail(Errc::malformed, "a script's runtime is 1 to 128 bytes");
        }
        out.runtime = *runtime;
    }
    return out;
}

Result<cbor::Value> encode_script(const Script& script) {
    cbor::Array files;
    for (const ScriptFile& f : script.files) {
        files.push_back(
            cbor::Value::array({cbor::Value::text(f.path), cbor::Value::unsigned_integer(f.size),
                                cbor::Value::bytes(f.digest)}));
    }
    cbor::Map map{
        {cbor::Value::text("name"), cbor::Value::text(script.name)},
        {cbor::Value::text("version"), cbor::Value::text(script.version)},
        {cbor::Value::text("files"), cbor::Value::array(std::move(files))},
        {cbor::Value::text("deterministic"), cbor::Value::boolean(script.deterministic)},
    };
    if (script.runtime) {
        map.push_back({cbor::Value::text("runtime"), cbor::Value::text(*script.runtime)});
    }
    cbor::Value value = cbor::Value::map(std::move(map));
    if (auto checked = decode_script(value); !checked) {
        return std::unexpected(Error{Errc::invalid_argument, checked.error().detail});
    }
    return value;
}

std::vector<Id> related_records(std::span<const Statement> events, const Id& ledger) {
    std::vector<Id> out;
    auto add = [&](const Id& id) {
        if (!std::ranges::contains(out, id)) {
            out.push_back(id);
        }
    };
    if (const auto source = claim_source(events)) {
        add(*source);
    }
    // The record's own registration is its first event; a later one in its
    // history registered the version that superseded it (v0.10), whose
    // sources are that version's.
    if (!events.empty()) {
        if (const auto* r = std::get_if<RecordRegisterBody>(&events.front().body)) {
            for (const Source& s : r->sources) {
                if (s.ledger == ledger) {
                    add(s.record);
                }
            }
        }
    }
    for (const Statement& statement : events) {
        if (statement.provenance && statement.provenance->script) {
            add(*statement.provenance->script);
        }
    }
    return out;
}

} // namespace kanhe::protocol
