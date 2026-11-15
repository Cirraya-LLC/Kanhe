// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include <kanhe/core/bytes.hpp>
#include <kanhe/core/cbor.hpp>
#include <kanhe/core/error.hpp>
#include <kanhe/core/protocol/common.hpp>
#include <kanhe/core/protocol/statement.hpp>

/// Where a record came from (spec v0.18, section 6): a `kanhe.script/1`
/// record is the organization's approval of one version of a script, by its
/// files' digests, given by a person in person; a statement's provenance
/// may name it (key 5); a registration may name its sources (key 7).
namespace kanhe::protocol {

inline constexpr std::string_view script_type = "kanhe.script/1";
inline constexpr std::size_t max_script_files = 256;
inline constexpr std::size_t max_script_path = 1024;
inline constexpr std::size_t max_script_name = 128;
inline constexpr std::size_t max_script_version = 64;
inline constexpr std::size_t max_script_runtime = 128;

struct ScriptFile {
    std::string path;
    std::uint64_t size = 0;
    /// The ledger's hash of the content: 32 bytes.
    Bytes digest;

    friend bool operator==(const ScriptFile&, const ScriptFile&) = default;
};

struct Script {
    std::string name;
    std::string version;
    /// Strictly ascending by the paths' bytes.
    std::vector<ScriptFile> files;
    bool deterministic = false;
    std::optional<std::string> runtime;

    friend bool operator==(const Script&, const Script&) = default;
};

/// Whether a script file's path is allowed: 1 to 1024 bytes, relative,
/// segments separated by "/", each non-empty and neither "." nor "..".
[[nodiscard]] bool valid_script_path(std::string_view path) noexcept;

/// Reads a script's metadata, checking its shape as the ledger does; other
/// keys are refused.
[[nodiscard]] Result<Script> decode_script(const cbor::Value& metadata);
/// The metadata of `script` (checked: what it encodes decodes).
[[nodiscard]] Result<cbor::Value> encode_script(const Script& script);

/// The records a record's own events name (spec section 11, step 7), whose
/// statements its evidence carries as events too: a claim's source (v0.14),
/// the local sources its own registration (the first event) names (v0.18;
/// `ledger` is this ledger's id), and the scripts its events' provenance
/// names (v0.18). Each once, in that order, first named first.
[[nodiscard]] std::vector<Id> related_records(std::span<const Statement> events, const Id& ledger);

} // namespace kanhe::protocol
