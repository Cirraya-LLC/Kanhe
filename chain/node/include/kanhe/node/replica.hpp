// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <cstdint>
#include <filesystem>
#include <functional>
#include <optional>
#include <string>

#include <kanhe/core/crypto.hpp>
#include <kanhe/core/error.hpp>
#include <kanhe/ledger/ledger.hpp>
#include <kanhe/node/client.hpp>

/// Replicas: verified copies of a ledger, pulled from its primary's API. A
/// replica re-validates every entry with the ledger's rules, rebuilds the
/// tree itself, and checks every checkpoint against it, so a primary (or
/// anyone in between) cannot hand it a history that is not the ledger's.
namespace kanhe::node {

/// The `replica` file in a replica's ledger directory.
struct ReplicaInfo {
    /// The primary's API URL.
    std::string source;
    /// CA certificates to trust for the primary, if not the system's.
    std::optional<std::string> ca_file;
    protocol::Timestamp created = 0;
    std::optional<protocol::Timestamp> last_sync;
};

[[nodiscard]] Result<std::optional<ReplicaInfo>>
read_replica_info(const std::filesystem::path& directory);
[[nodiscard]] Status write_replica_info(const std::filesystem::path& directory,
                                        const ReplicaInfo& info);

/// Where a sync reads the primary's lists of attestations from: an index in
/// each list of the primary's (GET /v1/cosignatures, /v1/timestamps,
/// /v1/network-cosignatures).
struct AttestationCursors {
    std::uint64_t cosignatures = 0;
    std::uint64_t timestamps = 0;
    std::uint64_t network_cosignatures = 0;

    friend bool operator==(const AttestationCursors&, const AttestationCursors&) = default;
};

struct SyncReport {
    std::uint64_t entries = 0;
    std::uint64_t checkpoints = 0;
    std::uint64_t cosignatures = 0;
    std::uint64_t timestamps = 0;
    std::uint64_t network_cosignatures = 0;
    std::uint64_t vault_files = 0;
    /// The replica's size afterwards, and the primary's when asked.
    std::uint64_t size = 0;
    std::uint64_t primary_size = 0;
    /// Where the next sync reads the primary's attestations from.
    AttestationCursors next = {};
};

/// What a sync takes beyond the checkpoints and their entries.
struct SyncOptions {
    /// Also the entries no checkpoint covers yet, each re-validated (a
    /// command line client's mirror shows what was just submitted). A later
    /// checkpoint must then agree with them, or the next sync fails: a
    /// primary that rewrote them is caught. Replicas never take them.
    bool tail = false;
    /// The sealed vault data of new records (a client fetches it when it
    /// needs it instead).
    bool vault = true;
    /// Where to read the primary's attestations from, instead of the
    /// replica's own counts: for a replica that keeps attestations of its
    /// own beside the primary's (an archive, archive.hpp), whose counts then
    /// run ahead of the primary's lists. The report's `next` says where the
    /// next sync goes on. Reading one again keeps nothing twice.
    std::optional<AttestationCursors> from = std::nullopt;
};

/// Creates a replica in `fs`, which must hold no ledger, from the
/// primary's first log entry; with `expected`, only of that ledger
/// (Errc::verification_failed otherwise).
[[nodiscard]] Result<ledger::Ledger>
create_replica(const Client& primary, ledger::FileSystem& fs, ledger::Clock& clock,
               const crypto::Provider& provider,
               const std::optional<protocol::Id>& expected = std::nullopt);

/// Brings `replica` up to the primary's latest checkpoint: each new
/// checkpoint is checked on its own (log key, order), then the entries it
/// covers are fetched and must lead to its root before any is taken (and
/// each is re-validated as it is). Entries no checkpoint covers yet are not
/// copied, so a replica holds only what the log key signed, and trails the
/// primary by its checkpoint interval. Then witness cosignatures (from at
/// most 64 witnesses), time-stamp tokens over the checkpoints it holds, and
/// the sealed vault data of records new since the
/// last sync (written under `directory`/vault, the key last; all of it again
/// after the vault key changed). Everything taken so far stays if it
/// fails. Fails with Errc::verification_failed if the primary's history is
/// not this ledger's, or was rolled back; Errc::rejected if the primary
/// refuses the token; Errc::unavailable if it cannot be reached.
[[nodiscard]] Result<SyncReport>
sync_replica(const Client& primary, ledger::Ledger& replica, const std::filesystem::path& directory,
             const std::function<void(const SyncReport&)>& progress = {},
             const SyncOptions& options = {});

/// The primary's /v1/status, parsed: its ledger id (hex) and size.
struct PrimaryStatus {
    std::string ledger_id;
    std::uint64_t size = 0;
    std::optional<std::uint64_t> checkpoint_size;
};
[[nodiscard]] Result<PrimaryStatus> primary_status(const Client& primary);

} // namespace kanhe::node
