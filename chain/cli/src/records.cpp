// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include "records.hpp"

#include <algorithm>

namespace kanhe::cli {

crypto::openssl::HpkeKey load_hpke_key(const std::filesystem::path& path, const Args& args) {
    return client::load_hpke_key(path, [&] { return passphrase(args, path.string()); });
}

crypto::openssl::HpkeKey load_vault_key(const client::Session& session, const Args& args) {
    const std::filesystem::path path = args.has("vault-key")
                                           ? std::filesystem::path(*args.get("vault-key"))
                                           : default_vault_key_path(session);
    if (!std::filesystem::exists(path)) {
        throw CommandError{"no vault key at " + path.string() + "; pass --vault-key FILE"};
    }
    auto key = load_hpke_key(path, args);
    const Bytes expected = vault_public_key(session);
    if (!std::ranges::equal(key.public_key(), expected)) {
        throw CommandError{path.string() + " is not this ledger's vault key"};
    }
    return key;
}

Vault read_vault(const client::Session& session, const protocol::Id& record, const Args& args) {
    return client::read_vault(session, record, [&] { return load_vault_key(session, args); });
}

/// A source as --source names it: RECORD on this ledger (a full id or a
/// prefix), or LEDGER:RECORD, both full ids, on another.
protocol::Source parse_source(const client::Session& session, const std::string& text) {
    const auto colon = text.find(':');
    if (colon == std::string::npos) {
        return {session.state().ledger_id(), session.record_id(text)};
    }
    auto id = [&](std::string_view part) {
        const auto bytes = from_hex(part);
        const auto parsed =
            bytes ? protocol::to_id(*bytes) : Result<protocol::Id>(std::unexpected(bytes.error()));
        if (!parsed) {
            throw UsageError{"--source is RECORD, or LEDGER:RECORD with both full hex ids: " +
                             text};
        }
        return *parsed;
    };
    const protocol::Id ledger = id(std::string_view(text).substr(0, colon));
    if (ledger == session.state().ledger_id()) {
        return {ledger, session.record_id(text.substr(colon + 1))};
    }
    return {ledger, id(std::string_view(text).substr(colon + 1))};
}

} // namespace kanhe::cli
