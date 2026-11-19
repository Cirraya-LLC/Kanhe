// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <filesystem>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <kanhe/console/keystore.hpp>
#include <kanhe/core/crypto.hpp>
#include <kanhe/core/protocol/common.hpp>
#include <kanhe/core/protocol/statement.hpp>
#include <kanhe/ledger/environment.hpp>

/// A first run for one person: a new ledger whose owner is that person,
/// acting in person. The console makes every key and seals it: the root key
/// (used here and for recovery only), the log key, and the owner's own key.
/// For records that must verify for decades, the root key, the log key, and
/// the console's witness key are ML-DSA-65 (spec v0.21, section 11.1);
/// otherwise Ed25519, as are the owner's and the machine's keys either way.
/// The root key registers the owner, the owner's passkey, and the owner's
/// delegation: every statement type but the ledger's own key rotations, may
/// delegate, and requires presence. Then the owner does everything else, one
/// passkey tap per statement.
namespace kanhe::console {

/// The sealed keys' names (and the vault key, sealed apart: KeyStore).
inline constexpr std::string_view root_key_name = "root";
inline constexpr std::string_view log_key_name = "log";
inline constexpr std::string_view owner_key_name = "owner";
/// The console's machine: a device of the ledger, registered at the first
/// run with a delegation for contract calls only, that the node runs as the
/// ledger's registrar (recording calls once the consents they wait for are
/// in) and keeper (firing time rules, expiring requests) while unlocked.
inline constexpr std::string_view machine_key_name = "machine";
/// The console's credential key (ES256), once an owner turns credentials on:
/// a device that endorses certificates as the W3C credentials it signs
/// (spec/credentials.md).
inline constexpr std::string_view credential_key_name = "credentials";
inline constexpr std::string_view machine_name = "console";
/// The console's witness of its parties' ledgers: it cosigns their
/// checkpoints when they extend what it cosigned before. Not on the ledger;
/// its public key goes in the console's invitation codes.
inline constexpr std::string_view witness_key_name = "witness";

/// Moving a ledger made with classical keys to post-quantum ones (spec v0.21,
/// section 11.1; Settings, "Keep records verifiable for decades"): the next
/// log key and the next root key, ML-DSA-65, sealed under these names until
/// the ledger has rotated to them; then each takes its key's own name, and
/// the key it replaced is kept under the retired name.
inline constexpr std::string_view next_log_key_name = "log-next";
inline constexpr std::string_view next_root_key_name = "root-next";
inline constexpr std::string_view retired_log_key_name = "log-retired";
inline constexpr std::string_view retired_root_key_name = "root-retired";
/// The algorithm of the console's long-term keys.
inline constexpr crypto::SigAlg long_term_algorithm = crypto::SigAlg::ml_dsa_65;

/// The witness key's public key, made and sealed first if the console has
/// none (a console set up before it had one). Needs only the node key's
/// public key.
[[nodiscard]] crypto::PublicKey witness_public_key(KeyStore& keys);

/// The log keys the console's node signs with: the sealed log key, and,
/// while it is classical, the next one (post-quantum, made and sealed first
/// if the console has none), held ahead of the rotation to it so that the
/// node signs with it the moment that rotation is registered, as a server
/// holds both across a rotation (serve --log-key OLD --log-key NEW). None
/// without a sealed log key. Needs the store unlocked.
[[nodiscard]] std::vector<std::shared_ptr<const crypto::Signer>> served_log_keys(KeyStore& keys);

struct SetUp {
    /// The ledger directory, which holds no ledger yet.
    std::filesystem::path ledger;
    /// The owner's name, which is also the organization's (a nickname works).
    std::string name;
    /// The owner's passkey.
    protocol::PresenceCredential passkey;
    /// The passkey's PRF output, if it has one: its own slot, so that signing
    /// in with it unlocks the console.
    std::optional<std::string> prf;
    /// An unlock passphrase, for consoles that start unattended.
    std::optional<std::string> passphrase;
    /// Whether its records must verify for decades: then the root key, the
    /// log key, and the witness key are post-quantum (ML-DSA-65).
    bool long_term = false;
};

struct FirstRun {
    /// Shown once: it unlocks the keys if every passkey is lost.
    std::string recovery_code;
    protocol::Id ledger;
    protocol::Id owner;
    /// The console's machine actor (registrar and keeper).
    protocol::Id machine;
};

/// The statement types of the owner's delegation.
[[nodiscard]] protocol::Scope owner_scope();
/// The machine's delegation: contract calls only, on every contract, without
/// presence; it delegates nothing.
[[nodiscard]] protocol::Scope machine_scope();

/// Makes the console's keys, the ledger, and its owner, and records the
/// owner as the console's user (owner role, linked to the actor). Leaves
/// `keys` unlocked. Throws if the directory holds a ledger or the console's
/// keys exist.
[[nodiscard]] FirstRun set_up(const SetUp& request, KeyStore& keys, ledger::Entropy& entropy);

/// Whether the directory holds a ledger.
[[nodiscard]] bool has_ledger(const std::filesystem::path& directory);

} // namespace kanhe::console
