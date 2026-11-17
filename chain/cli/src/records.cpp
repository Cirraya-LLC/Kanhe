// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include "records.hpp"

#include <algorithm>
#include <system_error>

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

protocol::VerifyOptions verify_options(const Args& args) {
    protocol::VerifyOptions options;
    if (const auto ledger_id = args.get("ledger-id")) {
        const auto bytes = from_hex(*ledger_id);
        if (!bytes) {
            throw UsageError{"--ledger-id must be the full hex ledger id"};
        }
        options.expected_ledger = unwrap(protocol::to_id(*bytes), "ledger id");
    }
    for (const std::string& path : args.all("witness")) {
        options.trusted_witnesses.push_back(load_public_key(path));
    }
    options.trusted_timestamp_roots = client::load_certificates(args.all("tsa-root"));
    options.trusted_network_witnesses = client::network_witness_keys(args.all("witness-vkey"));
    for (const std::string& item : args.all("attachment")) {
        auto [name, path] = split_pair(item, "--attachment");
        options.attachment_contents[name] = read_file(path);
    }
    // Trust nodes (spec v0.16): named here, never by the evidence.
    for (const std::string& item : args.all("trust-node")) {
        auto [ledger_text, name] = split_pair(item, "--trust-node");
        const auto bytes = from_hex(ledger_text);
        const auto id =
            bytes ? protocol::to_id(*bytes) : Result<protocol::Id>(std::unexpected(bytes.error()));
        if (!id || name.empty()) {
            throw UsageError{"--trust-node is LEDGER=NAME: the trust node's full hex ledger id, "
                             "and the name to give it"};
        }
        if (std::ranges::any_of(options.trust_nodes,
                                [&](const protocol::TrustNode& n) { return n.ledger == *id; })) {
            throw UsageError{"--trust-node names each trust node once"};
        }
        options.trust_nodes.push_back({*id, name});
    }
    return options;
}

std::string script_file_status(const crypto::Provider& provider, crypto::HashAlg hash,
                               const std::filesystem::path& root,
                               const protocol::ScriptFile& file) {
    const std::filesystem::path full = root / file.path;
    std::error_code ec;
    if (!std::filesystem::is_regular_file(full, ec)) {
        return "missing";
    }
    const Bytes content = read_file(full);
    const auto digest = unwrap(provider.digest(hash, content), "hashing " + full.string());
    return content.size() == file.size && std::ranges::equal(digest.bytes(), file.digest)
               ? "same"
               : "changed";
}

} // namespace kanhe::cli
