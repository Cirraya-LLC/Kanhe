// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <filesystem>
#include <string>

#include <kanhe/client/records.hpp>
#include <kanhe/core/protocol/evidence.hpp>
#include <kanhe/core/protocol/scripts.hpp>

#include "support.hpp"

/// The vault's keys from options and passphrases.
namespace kanhe::cli {

/// Loads the vault private key from --vault-key (default <ledger>/vault.key)
/// and checks that it matches the ledger's vault public key.
[[nodiscard]] crypto::openssl::HpkeKey load_vault_key(const client::Session& session,
                                                      const Args& args);
/// Loads a vault private key file (asking for its passphrase if needed).
[[nodiscard]] crypto::openssl::HpkeKey load_hpke_key(const std::filesystem::path& path,
                                                     const Args& args);
/// Reads a record's private data, loading the vault key (--vault-key) only if
/// the file is sealed.
[[nodiscard]] Vault read_vault(const client::Session& session, const protocol::Id& record,
                               const Args& args);

/// A source as --source names it (spec v0.18): RECORD on this ledger (a full
/// id or a prefix), or LEDGER:RECORD, both full ids, on another.
[[nodiscard]] protocol::Source parse_source(const client::Session& session,
                                            const std::string& text);

/// A verifier's trust, from verify's options: --ledger-id, --witness,
/// --witness-vkey, --tsa-root, --attachment, and --trust-node (those a
/// command takes).
[[nodiscard]] protocol::VerifyOptions verify_options(const Args& args);

/// A script's file below `root`, against its approval (spec v0.18): "same"
/// (that size and hash under `hash`, the ledger's), "changed", or
/// "missing".
[[nodiscard]] std::string script_file_status(const crypto::Provider& provider, crypto::HashAlg hash,
                                             const std::filesystem::path& root,
                                             const protocol::ScriptFile& file);

} // namespace kanhe::cli
