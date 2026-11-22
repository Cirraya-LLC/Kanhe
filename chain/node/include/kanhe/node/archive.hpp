// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <stop_token>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <nlohmann/json.hpp>

#include <kanhe/core/bytes.hpp>
#include <kanhe/core/crypto.hpp>
#include <kanhe/core/error.hpp>
#include <kanhe/core/protocol/common.hpp>
#include <kanhe/core/protocol/id_map.hpp>
#include <kanhe/ledger/environment.hpp>
#include <kanhe/ledger/ledger.hpp>
#include <kanhe/ledger/storage.hpp>
#include <kanhe/node/client.hpp>
#include <kanhe/node/http.hpp>
#include <kanhe/node/replica.hpp>

/// Archives (spec section 16, "Archives"; informative): a server keeps other
/// ledgers, its members' typically, so that their published records and
/// renewals are still answered once their own servers are gone. An archived
/// ledger is a replica (commitments and public metadata, never sealed data),
/// the newest verified bundle of each record its owner published, and this
/// archive's own attestations of its checkpoints, kept beside them as a
/// replica keeps the owner's:
///
///   <ledger>/archive/config.json         witnesses, time-stamp authorities, intervals
///   <ledger>/archive/<member>/           the member's replica (its ledger files)
///     archive.json                       its source, status, and where syncs go on
///     token                              the member's archive token (owner-only)
///     ca.pem                             CA certificates for its server, if given
///     kept.json                          the kept bundles: token, record, size, time
///     published/<token>.cbor             each kept bundle, as the member served it
///     ledger.backup.N                    after a restore: the replica, until opened
///
/// An archive holds no log key of the member's, so it makes no evidence: it
/// serves the bundles it kept, each with a renewal from the archive's copy
/// appended, as of the bundle's checkpoint. Network cosignatures need the
/// member's note key: an archive renews none.
namespace kanhe::node {

/// A public witness an archive asks to cosign the ledgers it keeps, its key
/// as its GET /v1/witness gave it when it was configured.
struct ArchiveWitness {
    std::string url;
    std::string name;
    crypto::PublicKey key;

    friend bool operator==(const ArchiveWitness&, const ArchiveWitness&) = default;
};

struct ArchiveConfig {
    std::vector<ArchiveWitness> witnesses;
    /// Time-stamp authorities' URLs (RFC 3161 over HTTP).
    std::vector<std::string> authorities;
    std::chrono::seconds sync_interval{3600};
    std::chrono::seconds attest_interval{365LL * 86'400};

    friend bool operator==(const ArchiveConfig&, const ArchiveConfig&) = default;
};

/// At most this many witnesses, and authorities, an archive asks.
inline constexpr std::size_t max_archive_attesters = 8;
/// Bounds of the intervals.
inline constexpr std::chrono::seconds min_sync_interval{10};
inline constexpr std::chrono::seconds max_sync_interval{30LL * 86'400};
inline constexpr std::chrono::seconds min_attest_interval{60};
inline constexpr std::chrono::seconds max_attest_interval{3650LL * 86'400};
/// At most this many published records a member lists to its archive.
inline constexpr std::size_t max_archived_published = 100'000;
/// At most this many of its own attestations an archive remembers making.
inline constexpr std::size_t max_own_attestations = 4096;

[[nodiscard]] std::filesystem::path archive_root(const std::filesystem::path& ledger);
[[nodiscard]] std::filesystem::path archive_path(const std::filesystem::path& ledger,
                                                 const protocol::Id& member);

/// config.json; the defaults if there is none. Errc::malformed if damaged.
[[nodiscard]] Result<ArchiveConfig> parse_archive_config(ByteView file);
[[nodiscard]] Result<ArchiveConfig> load_archive_config(const std::filesystem::path& ledger);
/// Refuses more than 8 witnesses or authorities, one listed twice, a URL
/// that is not http(s), or an interval out of its bounds.
[[nodiscard]] Status save_archive_config(const std::filesystem::path& ledger,
                                         const ArchiveConfig& config);

/// An archived ledger's archive.json.
struct ArchiveState {
    /// The member's API URL.
    std::string source;
    protocol::Timestamp created = 0;
    /// As of the last sync that reached it: the member's name, the replica's
    /// size, and its latest checkpoint's time.
    std::string organization;
    std::uint64_t size = 0;
    std::optional<protocol::Timestamp> checkpoint_time;
    /// The last sync that succeeded, and the last one tried, with its error
    /// ("" if it succeeded); since when the member's server cannot be
    /// reached, if it cannot.
    std::optional<protocol::Timestamp> last_sync;
    std::optional<protocol::Timestamp> last_try;
    std::string last_error;
    std::optional<protocol::Timestamp> unreachable_since;
    /// The newest attestation of the latest checkpoint (a witness's dated
    /// cosignature, an undated one by the checkpoint's time, a token, a
    /// network cosignature), and the last round of re-attestation, with
    /// what did not work in it.
    std::optional<protocol::Timestamp> attested_at;
    std::optional<protocol::Timestamp> last_attest;
    std::vector<std::string> attest_problems;
    /// Where the next sync reads the member's attestations from.
    AttestationCursors cursors;
    /// SHA-256 (hex) of the cosignatures and tokens this archive asked for
    /// itself, newest last: the others came from the member.
    std::vector<std::string> own;
    /// What the last refresh of the published records could not do.
    std::vector<std::string> published_problems;

    friend bool operator==(const ArchiveState&, const ArchiveState&) = default;
};

[[nodiscard]] Result<ArchiveState> parse_archive_state(ByteView file);
[[nodiscard]] Result<ArchiveState> load_archive_state(const std::filesystem::path& directory);
[[nodiscard]] Status save_archive_state(const std::filesystem::path& directory,
                                        const ArchiveState& state);

/// A bundle kept for a published record.
struct KeptBundle {
    std::string token;
    protocol::Id record;
    /// Its checkpoint's size and time.
    std::uint64_t size = 0;
    protocol::Timestamp time = 0;

    friend bool operator==(const KeptBundle&, const KeptBundle&) = default;
};

/// kept.json; none if there is none. Errc::malformed if damaged.
[[nodiscard]] Result<std::vector<KeptBundle>> parse_kept(ByteView file);
[[nodiscard]] Result<std::vector<KeptBundle>> load_kept(const std::filesystem::path& directory);

/// A published record as a member's GET /v1/published lists it to an archive.
struct PublishedListing {
    std::string token;
    protocol::Id record;

    friend bool operator==(const PublishedListing&, const PublishedListing&) = default;
};

/// GET /v1/published's answer: a JSON array of objects, each with a valid
/// "token" and a "record" id in hex (other members are ignored), each token
/// once; at most 100,000. Errc::malformed or Errc::limit_exceeded otherwise.
[[nodiscard]] Result<std::vector<PublishedListing>> parse_published_list(ByteView body);

/// The ledgers archived here, ascending: the directories named by a ledger
/// id in 64 lower-case hex digits that hold an archive.json.
[[nodiscard]] std::vector<protocol::Id> archived_ledgers(const std::filesystem::path& ledger);

/// What a refresh of the published records did.
struct PublishedRefresh {
    /// The member's list was fetched (only then are tokens it no longer
    /// lists dropped), and how many it listed.
    bool listed = false;
    std::size_t listing = 0;
    std::size_t fetched = 0;
    std::size_t kept = 0;
    std::size_t unchanged = 0;
    std::size_t removed = 0;
    std::vector<std::string> problems;
};

struct ArchiveSyncReport {
    /// Whether the sync reached the member and took what it served; else
    /// its error (static text, as an error's detail is), and its code
    /// (Errc::unavailable: the member's server could not be reached).
    bool synced = false;
    std::string_view error;
    Errc code = Errc::unavailable;
    SyncReport replica;
    PublishedRefresh published;
};

/// What a witness, or an authority, did in a round of re-attestation.
struct AttesterOutcome {
    /// "witness" or "authority".
    std::string kind;
    std::string name;
    std::string url;
    /// The size it attested now, if it did.
    std::optional<std::uint64_t> attested;
    /// The ledger registered with the witness by this round.
    bool registered = false;
    /// It has cosigned the latest checkpoint already, by the ledger's asking
    /// or this archive's (a ledger keeps one cosignature per witness and
    /// checkpoint): it is not asked.
    bool already = false;
    /// Why it did not, if it did not.
    std::string problem;
};

struct AttestReport {
    /// Whether a round was due (or forced) and made.
    bool due = false;
    std::uint64_t size = 0;
    std::optional<protocol::Timestamp> attested_at;
    /// When the next round is due.
    std::optional<protocol::Timestamp> next;
    std::vector<AttesterOutcome> outcomes;
};

/// Where a member's archive token and server are, for `ArchivedLedger::create`.
struct ArchiveSource {
    std::string url;
    std::string token;
    /// CA certificates (PEM) to trust for it, kept beside the archive.
    std::optional<Bytes> ca_pem;
};

/// An archived ledger, opened: its replica, which one thread writes (sync,
/// attest, refresh) while any number read it (the routes).
class ArchivedLedger {
public:
    /// Opens the archive of `member` (restoring its replica from a backup's
    /// copy first, if that is what it holds), waiting up to `lock_ms` for
    /// its directory. Errc::not_found if it is not archived here.
    [[nodiscard]] static Result<std::unique_ptr<ArchivedLedger>>
    open(const std::filesystem::path& ledger, const protocol::Id& member, ledger::Clock& clock,
         const crypto::Provider& provider, std::uint64_t lock_ms = 60'000);

    /// Archives `member`: a replica of exactly that ledger from `source`,
    /// then its first sync. Fails, leaving nothing behind, if the source
    /// serves another ledger (Errc::verification_failed), refuses the token
    /// (Errc::rejected), or cannot be reached; Errc::rejected if `member` is
    /// archived already.
    [[nodiscard]] static Result<std::pair<std::unique_ptr<ArchivedLedger>, ArchiveSyncReport>>
    create(const std::filesystem::path& ledger, const protocol::Id& member,
           const ArchiveSource& source, ledger::Clock& clock, const crypto::Provider& provider);

    ArchivedLedger(const ArchivedLedger&) = delete;
    ArchivedLedger& operator=(const ArchivedLedger&) = delete;
    ~ArchivedLedger();

    [[nodiscard]] const protocol::Id& id() const noexcept;
    [[nodiscard]] const std::filesystem::path& directory() const noexcept;
    [[nodiscard]] const ledger::Ledger& replica() const noexcept;

    /// Under the directory's lock: what another process wrote, then a sync
    /// from the member (with the cursors kept), then the published records
    /// refreshed; the state written either way. A member that cannot be
    /// reached is noted, not an error: the result fails only for this
    /// archive's own files. `stop` abandons it.
    [[nodiscard]] Result<ArchiveSyncReport> sync(const std::atomic<bool>* stop = nullptr,
                                                 std::uint64_t lock_ms = 60'000);
    /// Under the lock: re-attests the latest checkpoint if its newest
    /// attestation is older than the interval (or `force`): a cosignature
    /// from each witness configured that has not cosigned it (a ledger keeps
    /// one per witness and checkpoint), a fresh token from each authority,
    /// each checked and kept beside the checkpoint. A witness the member
    /// itself has cosign its checkpoints is never moved: it is asked only to
    /// cosign the latest checkpoint when that is of the size it cosigned
    /// last; one that has cosigned a later checkpoint than this archive
    /// holds is reported, not forced.
    [[nodiscard]] Result<AttestReport> attest(const ArchiveConfig& config, bool force,
                                              const std::atomic<bool>* stop = nullptr,
                                              std::uint64_t lock_ms = 60'000);
    /// Under the lock, unless `lock_ms` is 0 and another holds it: picks up
    /// what another process wrote. True if anything new was picked up.
    [[nodiscard]] Result<bool> refresh(std::uint64_t lock_ms = 0);

    /// GET /a/{ledger}/REST for this archived ledger, from any thread:
    /// /v1/checkpoint[?size=N], /v1/consistency?old=&new=,
    /// /v1/renewal?from=N[&size=M], /c/TOKEN.
    [[nodiscard]] http::Response answer(const http::Request& request, std::string_view rest) const;

    /// The kept bundle published under `token`, with one renewal from this
    /// archive's copy appended when that adds a newer checkpoint or an
    /// attestation the bundle lacks (to the latest attested checkpoint, if
    /// the bundle carries fewer than 64). Errc::not_found if none is kept.
    [[nodiscard]] Result<Bytes> published_bundle(std::string_view token) const;

    /// The newest attestation of the latest checkpoint, read afresh.
    [[nodiscard]] std::optional<protocol::Timestamp> newest_attestation() const;

    struct Impl;

private:
    explicit ArchivedLedger(std::unique_ptr<Impl> impl) noexcept;
    std::unique_ptr<Impl> impl_;
};

/// Removes the archive of `member` (its replica and everything kept),
/// under its lock. Errc::not_found if it is not archived here.
[[nodiscard]] Status remove_archive(const std::filesystem::path& ledger,
                                    const protocol::Id& member);

/// The `archives` object of `kanhe status` and GET /v1/status, from the
/// archives' files; none if nothing is archived here:
///   {"count", "unreachable": how many members cannot be reached,
///    "oldest_sync": the least recent last sync (ISO 8601, null if none
///    synced), "next_attestation": the earliest round due, "witnesses",
///    "authorities": how many are configured, "witnesses_post_quantum":
///    whether one has an ML-DSA key, "advice": [sentences]}
[[nodiscard]] std::optional<nlohmann::json> archives_status(const std::filesystem::path& ledger,
                                                            protocol::Timestamp now);

/// When the archived ledger whose state is `state` is due to sync, and to
/// be re-attested, with `config`.
[[nodiscard]] protocol::Timestamp next_sync(const ArchiveState& state, const ArchiveConfig& config);
[[nodiscard]] protocol::Timestamp next_attestation(const ArchiveState& state,
                                                   const ArchiveConfig& config);

/// Whether a backup may write `path` (relative to the ledger directory, '/'
/// separators): an archive's config, state, token, CA file, kept bundles
/// and their list, or its replica's backup.
[[nodiscard]] bool archive_backup_path_allowed(std::string_view path);
/// What a backup of the ledger at `ledger` holds of its archives: those
/// files, each archived ledger's replica as a backup of its own in 8 MiB
/// pieces (`ledger.backup.N`, restored when the archive is next opened),
/// read under each one's lock. In a fixed order.
[[nodiscard]] Result<std::vector<std::pair<std::string, Bytes>>>
archive_backup_files(const std::filesystem::path& ledger, ledger::Clock& clock,
                     const crypto::Provider& provider);

/// Archives as a server keeps them: every archived ledger found in the
/// ledger directory, opened and served (`handle`), and synced and
/// re-attested at their intervals by `run`, on a thread of its own, never
/// in a request's path. Ledgers archived or removed by another process
/// while it runs are picked up within seconds.
class ArchiveService {
public:
    /// `say` gets a line for each change worth telling (a member that
    /// cannot be reached, a round of re-attestation), if given.
    ArchiveService(std::filesystem::path ledger, const crypto::Provider& provider,
                   std::function<void(const std::string&)> say = {});
    ArchiveService(const ArchiveService&) = delete;
    ArchiveService& operator=(const ArchiveService&) = delete;
    ~ArchiveService();

    /// Answers GET /a/{ledger}/... (CORS for any origin, never cached, JSON
    /// errors; 404 for a ledger not archived here); nothing for other paths.
    [[nodiscard]] std::optional<http::Response> handle(const http::Request& request) const;
    /// Adds `archives` to a status answer, when something is archived here.
    void status(nlohmann::json& status) const;
    /// Opens what was archived since and drops what was removed.
    void rescan();
    /// Syncs and re-attests each archived ledger when due, picks up what
    /// other processes wrote, every few seconds, until `stop`.
    void run(const std::stop_token& stop);

private:
    struct Entry;
    [[nodiscard]] std::shared_ptr<Entry> find(const protocol::Id& member) const;

    std::filesystem::path ledger_;
    const crypto::Provider& provider_;
    std::function<void(const std::string&)> say_;
    mutable ledger::SystemClock clock_;
    std::atomic<bool> stopping_{false};
    mutable std::mutex mutex_;
    std::map<protocol::IdKey, std::shared_ptr<Entry>> entries_;
};

} // namespace kanhe::node
