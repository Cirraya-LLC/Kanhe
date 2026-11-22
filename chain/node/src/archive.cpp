// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include <algorithm>
#include <charconv>
#include <condition_variable>
#include <format>
#include <fstream>
#include <set>
#include <sstream>
#include <system_error>

#include <kanhe/core/cbor.hpp>
#include <kanhe/core/protocol/evidence.hpp>
#include <kanhe/core/protocol/log.hpp>
#include <kanhe/core/protocol/witness.hpp>
#include <kanhe/ledger/backup.hpp>
#include <kanhe/node/archive.hpp>
#include <kanhe/node/long_term.hpp>
#include <kanhe/node/published.hpp>
#include <kanhe/node/responses.hpp>
#include <kanhe/node/timestamps.hpp>
#include <kanhe/verifier/report.hpp>

#include "files.hpp"

namespace kanhe::node {

namespace {

using json = nlohmann::json;

constexpr std::string_view state_file = "archive.json";
constexpr std::string_view token_file = "token";
constexpr std::string_view ca_file = "ca.pem";
constexpr std::string_view kept_file = "kept.json";
/// A restored archive's replica, as a backup of its own in pieces
/// (ledger.backup.0, .1, ...): a backup's items are at most 16 MiB.
constexpr std::string_view backup_file = "ledger.backup.";
constexpr std::size_t backup_piece = std::size_t{8} << 20;
/// Kept bundles larger than this stay out of backups (an item's limit).
constexpr std::size_t most_backed_up_bundle = std::size_t{15} << 20;
constexpr std::string_view published_folder = "published";

/// A page of the replica's lists.
constexpr std::uint64_t page = 1000;
/// Answers a witness gives are small.
constexpr std::size_t witness_body = 64 * 1024;

std::string hex(const protocol::Id& id) {
    return to_hex(id.bytes());
}

/// A ledger id in 64 lower-case hex digits, as archives' paths name them.
std::optional<protocol::Id> id_of(std::string_view text) {
    if (text.size() != 64 || !std::ranges::all_of(text, [](char c) {
            return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
        })) {
        return std::nullopt;
    }
    const auto bytes = from_hex(text);
    if (!bytes) {
        return std::nullopt;
    }
    auto id = protocol::to_id(*bytes);
    return id ? std::optional(*id) : std::nullopt;
}

std::string sha256_hex(const crypto::Provider& provider, ByteView bytes) {
    const auto digest = provider.digest(crypto::HashAlg::sha256, bytes);
    return digest ? to_hex(digest->bytes()) : std::string();
}

bool web_url(std::string_view url) {
    return (url.starts_with("https://") || url.starts_with("http://")) && Url::parse(url);
}

std::string key_hex(const crypto::PublicKey& key) {
    const auto encoded = cbor::encode(protocol::encode_public_key(key));
    return encoded ? to_hex(*encoded) : std::string();
}

std::optional<crypto::PublicKey> key_from_hex(std::string_view text) {
    const auto bytes = from_hex(text);
    if (!bytes) {
        return std::nullopt;
    }
    const auto value = cbor::decode(*bytes);
    if (!value) {
        return std::nullopt;
    }
    auto key = protocol::decode_public_key(*value);
    return key ? std::optional(std::move(*key)) : std::nullopt;
}

json document_of(ByteView file) {
    return json::parse(file.begin(), file.end(), nullptr, false);
}

/// An optional time (ms): absent or null is none; anything else must be one.
bool read_time(const json& object, const char* name, std::optional<protocol::Timestamp>& out) {
    const auto it = object.find(name);
    if (it == object.end() || it->is_null()) {
        out.reset();
        return true;
    }
    if (!it->is_number_unsigned()) {
        return false;
    }
    out = it->get<protocol::Timestamp>();
    return true;
}

bool read_count(const json& object, const char* name, std::uint64_t& out) {
    const auto it = object.find(name);
    if (it == object.end()) {
        out = 0;
        return true;
    }
    if (!it->is_number_unsigned()) {
        return false;
    }
    out = it->get<std::uint64_t>();
    return true;
}

bool read_text(const json& object, const char* name, std::string& out) {
    const auto it = object.find(name);
    if (it == object.end()) {
        out.clear();
        return true;
    }
    if (!it->is_string()) {
        return false;
    }
    out = it->get<std::string>();
    return true;
}

bool read_texts(const json& object, const char* name, std::vector<std::string>& out,
                std::size_t most) {
    out.clear();
    const auto it = object.find(name);
    if (it == object.end()) {
        return true;
    }
    if (!it->is_array() || it->size() > most) {
        return false;
    }
    for (const json& item : *it) {
        if (!item.is_string()) {
            return false;
        }
        out.push_back(item.get<std::string>());
    }
    return true;
}

json time_json(const std::optional<protocol::Timestamp>& t) {
    return t ? json(*t) : json(nullptr);
}

std::filesystem::path backup_piece_path(const std::filesystem::path& directory, std::size_t n) {
    return directory / (std::string(backup_file) + std::to_string(n));
}

/// "ledger.backup.N", N a number without leading zeros.
bool backup_piece_name(std::string_view name) {
    if (!name.starts_with(backup_file)) {
        return false;
    }
    const std::string_view n = name.substr(backup_file.size());
    return !n.empty() && n.size() <= 6 && (n.size() == 1 || n.front() != '0') &&
           std::ranges::all_of(n, [](char c) { return c >= '0' && c <= '9'; });
}

/// The pieces of a restored replica, joined; none if there are none.
std::optional<std::string> joined_backup(const std::filesystem::path& directory) {
    std::error_code ec;
    if (!std::filesystem::exists(backup_piece_path(directory, 0), ec)) {
        return std::nullopt;
    }
    std::string out;
    for (std::size_t n = 0; std::filesystem::exists(backup_piece_path(directory, n), ec); ++n) {
        auto bytes = detail::read_file(backup_piece_path(directory, n));
        if (!bytes) {
            return std::nullopt;
        }
        out.append(bytes->begin(), bytes->end());
    }
    return out;
}

void remove_backup_pieces(const std::filesystem::path& directory) {
    std::error_code ec;
    for (std::size_t n = 0; std::filesystem::remove(backup_piece_path(directory, n), ec); ++n) {
    }
}

std::optional<std::uint64_t> number(const http::Request& r, std::string_view name) {
    const auto it = r.query.find(name);
    if (it == r.query.end()) {
        return std::nullopt;
    }
    std::uint64_t value = 0;
    const std::string& text = it->second;
    const auto [ptr, ec] = std::from_chars(text.data(), text.data() + text.size(), value);
    if (ec != std::errc{} || ptr != text.data() + text.size() || text.empty()) {
        return std::nullopt;
    }
    return value;
}

http::Response binary(std::string_view content_type, Bytes body) {
    http::Response r;
    r.content_type = std::string(content_type);
    r.body = std::move(body);
    return r;
}

/// Removes a replica's ledger files, which a failed restore may have left.
void remove_ledger_files(const std::filesystem::path& directory) {
    std::error_code ec;
    for (const char* name : {"statements", "checkpoints", "cosignatures", "timestamps",
                             "network-cosignatures", "snapshot-a", "snapshot-b"}) {
        std::filesystem::remove(directory / name, ec);
        std::filesystem::remove(directory / (std::string(name) + ".synced"), ec);
    }
}

Status lock_failure(const Error& error) {
    if (error.code == Errc::rejected) {
        return fail(Errc::rejected, "the archive is in use by another process; try again");
    }
    return std::unexpected(error);
}

} // namespace

// ---- files -------------------------------------------------------------------

std::filesystem::path archive_root(const std::filesystem::path& ledger) {
    return ledger / "archive";
}

std::filesystem::path archive_path(const std::filesystem::path& ledger,
                                   const protocol::Id& member) {
    return archive_root(ledger) / hex(member);
}

Result<ArchiveConfig> parse_archive_config(ByteView file) {
    const json document = document_of(file);
    auto malformed = [] {
        return fail(Errc::malformed, "the archives' config.json is malformed");
    };
    if (document.is_discarded() || !document.is_object() || !document.contains("version") ||
        !document["version"].is_number_unsigned() ||
        document["version"].get<std::uint64_t>() != 1) {
        return malformed();
    }
    ArchiveConfig config;
    if (const auto it = document.find("witnesses"); it != document.end()) {
        if (!it->is_array() || it->size() > max_archive_attesters) {
            return malformed();
        }
        for (const json& w : *it) {
            if (!w.is_object() || !w.contains("url") || !w["url"].is_string() ||
                !w.contains("key") || !w["key"].is_string()) {
                return malformed();
            }
            ArchiveWitness witness;
            witness.url = w["url"].get<std::string>();
            if (!read_text(w, "name", witness.name)) {
                return malformed();
            }
            const auto key = key_from_hex(w["key"].get<std::string>());
            if (!key || !web_url(witness.url)) {
                return malformed();
            }
            witness.key = *key;
            config.witnesses.push_back(std::move(witness));
        }
    }
    if (!read_texts(document, "authorities", config.authorities, max_archive_attesters) ||
        !std::ranges::all_of(config.authorities, web_url)) {
        return malformed();
    }
    std::uint64_t sync = 0;
    std::uint64_t attest = 0;
    if (!read_count(document, "sync_interval", sync) ||
        !read_count(document, "attest_interval", attest)) {
        return malformed();
    }
    if (sync != 0) {
        config.sync_interval = std::chrono::seconds(sync);
    }
    if (attest != 0) {
        config.attest_interval = std::chrono::seconds(attest);
    }
    if (config.sync_interval < min_sync_interval || config.sync_interval > max_sync_interval ||
        config.attest_interval < min_attest_interval ||
        config.attest_interval > max_attest_interval) {
        return malformed();
    }
    return config;
}

Result<ArchiveConfig> load_archive_config(const std::filesystem::path& ledger) {
    auto bytes = detail::read_file(archive_root(ledger) / "config.json");
    if (!bytes) {
        if (bytes.error().code == Errc::not_found) {
            return ArchiveConfig{};
        }
        return std::unexpected(bytes.error());
    }
    return parse_archive_config(*bytes);
}

Status save_archive_config(const std::filesystem::path& ledger, const ArchiveConfig& config) {
    if (config.witnesses.size() > max_archive_attesters ||
        config.authorities.size() > max_archive_attesters) {
        return fail(Errc::limit_exceeded, "an archive asks at most 8 witnesses and 8 authorities");
    }
    if (config.sync_interval < min_sync_interval || config.sync_interval > max_sync_interval) {
        return fail(Errc::invalid_argument, "the sync interval is 10 seconds to 30 days");
    }
    if (config.attest_interval < min_attest_interval ||
        config.attest_interval > max_attest_interval) {
        return fail(Errc::invalid_argument, "the attestation interval is 1 minute to 3650 days");
    }
    std::set<std::string> urls;
    json witnesses = json::array();
    for (const ArchiveWitness& w : config.witnesses) {
        if (!web_url(w.url) || !urls.insert(w.url).second) {
            return fail(Errc::invalid_argument, "each witness is an http(s) URL, listed once");
        }
        witnesses.push_back({{"url", w.url}, {"name", w.name}, {"key", key_hex(w.key)}});
    }
    urls.clear();
    for (const std::string& a : config.authorities) {
        if (!web_url(a) || !urls.insert(a).second) {
            return fail(Errc::invalid_argument,
                        "each time-stamp authority is an http(s) URL, listed once");
        }
    }
    const json document{{"version", 1},
                        {"witnesses", witnesses},
                        {"authorities", config.authorities},
                        {"sync_interval", config.sync_interval.count()},
                        {"attest_interval", config.attest_interval.count()}};
    std::error_code ec;
    std::filesystem::create_directories(archive_root(ledger), ec);
    std::filesystem::permissions(archive_root(ledger), std::filesystem::perms::owner_all,
                                 std::filesystem::perm_options::replace, ec);
    const std::string text = document.dump(2) + "\n";
    return detail::write_file(archive_root(ledger) / "config.json", as_bytes(text), true);
}

Result<ArchiveState> parse_archive_state(ByteView file) {
    const json document = document_of(file);
    auto malformed = [] {
        return fail(Errc::malformed, "an archive's archive.json is malformed");
    };
    if (document.is_discarded() || !document.is_object() || !document.contains("version") ||
        !document["version"].is_number_unsigned() ||
        document["version"].get<std::uint64_t>() != 1 || !document.contains("source") ||
        !document["source"].is_string()) {
        return malformed();
    }
    ArchiveState s;
    s.source = document["source"].get<std::string>();
    std::optional<protocol::Timestamp> created;
    if (!read_time(document, "created", created) ||
        !read_text(document, "organization", s.organization) ||
        !read_count(document, "size", s.size) ||
        !read_time(document, "checkpoint_time", s.checkpoint_time) ||
        !read_time(document, "last_sync", s.last_sync) ||
        !read_time(document, "last_try", s.last_try) ||
        !read_text(document, "last_error", s.last_error) ||
        !read_time(document, "unreachable_since", s.unreachable_since) ||
        !read_time(document, "attested_at", s.attested_at) ||
        !read_time(document, "last_attest", s.last_attest) ||
        !read_texts(document, "attest_problems", s.attest_problems, 64) ||
        !read_texts(document, "own", s.own, max_own_attestations) ||
        !read_texts(document, "published_problems", s.published_problems, 64)) {
        return malformed();
    }
    s.created = created.value_or(0);
    if (const auto it = document.find("cursors"); it != document.end()) {
        if (!it->is_object() || !read_count(*it, "cosignatures", s.cursors.cosignatures) ||
            !read_count(*it, "timestamps", s.cursors.timestamps) ||
            !read_count(*it, "network_cosignatures", s.cursors.network_cosignatures)) {
            return malformed();
        }
    }
    return s;
}

Result<ArchiveState> load_archive_state(const std::filesystem::path& directory) {
    auto bytes = detail::read_file(directory / state_file);
    if (!bytes) {
        return std::unexpected(bytes.error());
    }
    return parse_archive_state(*bytes);
}

Status save_archive_state(const std::filesystem::path& directory, const ArchiveState& s) {
    const json document{{"version", 1},
                        {"source", s.source},
                        {"created", s.created},
                        {"organization", s.organization},
                        {"size", s.size},
                        {"checkpoint_time", time_json(s.checkpoint_time)},
                        {"last_sync", time_json(s.last_sync)},
                        {"last_try", time_json(s.last_try)},
                        {"last_error", s.last_error},
                        {"unreachable_since", time_json(s.unreachable_since)},
                        {"attested_at", time_json(s.attested_at)},
                        {"last_attest", time_json(s.last_attest)},
                        {"attest_problems", s.attest_problems},
                        {"cursors",
                         {{"cosignatures", s.cursors.cosignatures},
                          {"timestamps", s.cursors.timestamps},
                          {"network_cosignatures", s.cursors.network_cosignatures}}},
                        {"own", s.own},
                        {"published_problems", s.published_problems}};
    const std::string text = document.dump(2) + "\n";
    return detail::write_file(directory / state_file, as_bytes(text), true);
}

Result<std::vector<KeptBundle>> parse_kept(ByteView file) {
    const json document = document_of(file);
    auto malformed = [] {
        return fail(Errc::malformed, "an archive's kept.json is malformed");
    };
    if (document.is_discarded() || !document.is_object() || !document.contains("version") ||
        !document["version"].is_number_unsigned() ||
        document["version"].get<std::uint64_t>() != 1 || !document.contains("bundles") ||
        !document["bundles"].is_array() || document["bundles"].size() > max_archived_published) {
        return malformed();
    }
    std::vector<KeptBundle> out;
    std::set<std::string> tokens;
    for (const json& b : document["bundles"]) {
        if (!b.is_object() || !b.contains("token") || !b["token"].is_string() ||
            !b.contains("record") || !b["record"].is_string() || !b.contains("size") ||
            !b["size"].is_number_unsigned() || !b.contains("time") ||
            !b["time"].is_number_unsigned()) {
            return malformed();
        }
        KeptBundle kept;
        kept.token = b["token"].get<std::string>();
        const auto record = id_of(b["record"].get<std::string>());
        if (!record || !valid_published_token(kept.token) || !tokens.insert(kept.token).second) {
            return malformed();
        }
        kept.record = *record;
        kept.size = b["size"].get<std::uint64_t>();
        kept.time = b["time"].get<protocol::Timestamp>();
        out.push_back(std::move(kept));
    }
    return out;
}

Result<std::vector<KeptBundle>> load_kept(const std::filesystem::path& directory) {
    auto bytes = detail::read_file(directory / kept_file);
    if (!bytes) {
        if (bytes.error().code == Errc::not_found) {
            return std::vector<KeptBundle>{};
        }
        return std::unexpected(bytes.error());
    }
    return parse_kept(*bytes);
}

namespace {

Status save_kept(const std::filesystem::path& directory, const std::vector<KeptBundle>& kept) {
    json bundles = json::array();
    for (const KeptBundle& k : kept) {
        bundles.push_back(
            {{"token", k.token}, {"record", hex(k.record)}, {"size", k.size}, {"time", k.time}});
    }
    const std::string text = json{{"version", 1}, {"bundles", bundles}}.dump(2) + "\n";
    return detail::write_file(directory / kept_file, as_bytes(text), false);
}

} // namespace

Result<std::vector<PublishedListing>> parse_published_list(ByteView body) {
    const json document = document_of(body);
    if (document.is_discarded() || !document.is_array()) {
        return fail(Errc::malformed, "the member's list of published records is malformed");
    }
    if (document.size() > max_archived_published) {
        return fail(Errc::limit_exceeded,
                    "the member lists more published records than an archive keeps (100,000)");
    }
    std::vector<PublishedListing> out;
    std::set<std::string> tokens;
    for (const json& item : document) {
        if (!item.is_object() || !item.contains("token") || !item["token"].is_string() ||
            !item.contains("record") || !item["record"].is_string()) {
            return fail(Errc::malformed, "the member's list of published records is malformed");
        }
        PublishedListing listing;
        listing.token = item["token"].get<std::string>();
        const auto record = id_of(item["record"].get<std::string>());
        if (!record || !valid_published_token(listing.token) ||
            !tokens.insert(listing.token).second) {
            return fail(Errc::malformed, "the member's list of published records is malformed");
        }
        listing.record = *record;
        out.push_back(std::move(listing));
    }
    return out;
}

std::vector<protocol::Id> archived_ledgers(const std::filesystem::path& ledger) {
    std::vector<protocol::Id> out;
    std::error_code ec;
    for (const auto& entry : std::filesystem::directory_iterator(archive_root(ledger), ec)) {
        std::error_code status_ec;
        if (!entry.is_directory(status_ec)) {
            continue;
        }
        if (const auto id = id_of(entry.path().filename().string());
            id && std::filesystem::exists(entry.path() / state_file, status_ec)) {
            out.push_back(*id);
        }
    }
    std::ranges::sort(out, [](const protocol::Id& a, const protocol::Id& b) {
        return std::ranges::lexicographical_compare(a.bytes(), b.bytes());
    });
    return out;
}

protocol::Timestamp next_sync(const ArchiveState& state, const ArchiveConfig& config) {
    const auto interval = static_cast<protocol::Timestamp>(config.sync_interval.count()) * 1000;
    return state.last_try ? *state.last_try + interval : 0;
}

protocol::Timestamp next_attestation(const ArchiveState& state, const ArchiveConfig& config) {
    // Due once the newest attestation is older than the interval; a round
    // that attested nothing is tried again a sync interval later.
    const auto interval = static_cast<protocol::Timestamp>(config.attest_interval.count()) * 1000;
    const auto retry = static_cast<protocol::Timestamp>(config.sync_interval.count()) * 1000;
    const protocol::Timestamp by_age = state.attested_at ? *state.attested_at + interval : 0;
    const protocol::Timestamp by_round = state.last_attest ? *state.last_attest + retry : 0;
    return std::max(by_age, by_round);
}

// ---- an archived ledger --------------------------------------------------------

struct ArchivedLedger::Impl {
    std::filesystem::path directory;
    protocol::Id member;
    ledger::Clock* clock = nullptr;
    const crypto::Provider* provider = nullptr;
    // The file system first: the replica, which reads through it, goes first.
    std::unique_ptr<ledger::PosixFileSystem> fs;
    std::optional<ledger::Ledger> replica;

    // The largest attested size, read as attestations arrive (any thread).
    mutable std::mutex watch_mutex;
    mutable std::uint64_t cosignatures_read = 0;
    mutable std::uint64_t timestamps_read = 0;
    mutable std::uint64_t network_read = 0;
    mutable std::optional<std::uint64_t> attested_size;

    [[nodiscard]] Result<Client> client(const ArchiveState& state,
                                        const std::atomic<bool>* stop) const;
    ArchiveSyncReport sync_locked(ArchiveState& state, const std::atomic<bool>* stop);
    PublishedRefresh refresh_published(const Client& member_server, const std::atomic<bool>* stop);
    void note_replica(ArchiveState& state) const;
    [[nodiscard]] std::optional<protocol::Timestamp> newest_attestation() const;
    [[nodiscard]] std::optional<std::uint64_t> latest_attested() const;
    AttesterOutcome ask_witness(const ArchiveWitness& witness, std::set<std::string>& own,
                                std::vector<std::string>& made, const std::atomic<bool>* stop);
    AttesterOutcome ask_authority(const std::string& url, std::set<std::string>& own,
                                  std::vector<std::string>& made, const std::atomic<bool>* stop);
};

ArchivedLedger::ArchivedLedger(std::unique_ptr<Impl> impl) noexcept : impl_(std::move(impl)) {}
ArchivedLedger::~ArchivedLedger() = default;

const protocol::Id& ArchivedLedger::id() const noexcept {
    return impl_->member;
}

const std::filesystem::path& ArchivedLedger::directory() const noexcept {
    return impl_->directory;
}

const ledger::Ledger& ArchivedLedger::replica() const noexcept {
    return *impl_->replica;
}

Result<Client> ArchivedLedger::Impl::client(const ArchiveState& state,
                                            const std::atomic<bool>* stop) const {
    auto url = Url::parse(state.source);
    if (!url) {
        return std::unexpected(url.error());
    }
    auto token = detail::read_file(directory / token_file);
    if (!token) {
        return fail(Errc::not_found, "the archive keeps no token for the member's server");
    }
    std::string text(token->begin(), token->end());
    while (!text.empty() && (text.back() == '\n' || text.back() == '\r' || text.back() == ' ')) {
        text.pop_back();
    }
    ClientOptions options;
    options.bearer_token = std::move(text);
    options.stop = stop;
    options.timeout = std::chrono::seconds(30);
    options.max_body = protocol::max_bundle_size;
    std::error_code ec;
    if (std::filesystem::exists(directory / ca_file, ec)) {
        options.ca_file = directory / ca_file;
    }
    return Client(std::move(*url), std::move(options));
}

void ArchivedLedger::Impl::note_replica(ArchiveState& state) const {
    state.size = replica->size();
    state.organization = replica->state().organization();
    const auto latest = replica->latest_checkpoint();
    state.checkpoint_time =
        latest ? std::optional(latest->checkpoint.timestamp) : std::optional<protocol::Timestamp>();
    state.attested_at = newest_attestation();
}

std::optional<protocol::Timestamp> ArchivedLedger::Impl::newest_attestation() const {
    const auto latest = replica->latest_checkpoint();
    if (!latest) {
        return std::nullopt;
    }
    // The latest checkpoint's newest attestation; with none, the newest of
    // any (a ledger that grows without witnesses is attested once an
    // interval, at whatever checkpoint is latest then).
    const std::uint64_t size = latest->checkpoint.tree_size;
    std::optional<protocol::Timestamp> of_latest;
    std::optional<protocol::Timestamp> of_any;
    auto note = [&](std::uint64_t at, protocol::Timestamp time) {
        of_any = std::max(of_any.value_or(0), time);
        if (at == size) {
            of_latest = std::max(of_latest.value_or(0), time);
        }
    };
    for (std::uint64_t at = 0; at < replica->cosignature_count(); at += page) {
        const auto got = replica->cosignatures(at, page);
        if (!got || got->empty()) {
            break;
        }
        for (const ledger::StoredCosignature& c : *got) {
            const protocol::SignedCheckpoint& s = c.cosignature;
            note(s.checkpoint.tree_size,
                 s.witness_time ? *s.witness_time * 1000 : s.checkpoint.timestamp);
        }
    }
    for (std::uint64_t at = 0; at < replica->timestamp_count(); at += page) {
        const auto got = replica->timestamps(at, page);
        if (!got || got->empty()) {
            break;
        }
        for (const ledger::StoredTimestamp& t : *got) {
            if (const auto token = provider->read_timestamp(t.token, {})) {
                note(t.checkpoint.checkpoint.tree_size, token->time);
            }
        }
    }
    for (std::uint64_t at = 0; at < replica->network_cosignature_count(); at += page) {
        const auto got = replica->network_cosignatures(at, page);
        if (!got || got->empty()) {
            break;
        }
        for (const ledger::StoredNetworkCosignature& n : *got) {
            note(n.checkpoint.checkpoint.tree_size, n.time * 1000);
        }
    }
    return of_latest ? of_latest : of_any;
}

std::optional<std::uint64_t> ArchivedLedger::Impl::latest_attested() const {
    const std::lock_guard lock(watch_mutex);
    auto note = [this](std::uint64_t size) {
        attested_size = std::max(attested_size.value_or(0), size);
    };
    while (cosignatures_read < replica->cosignature_count()) {
        const auto got = replica->cosignatures(cosignatures_read, page);
        if (!got || got->empty()) {
            break;
        }
        cosignatures_read += got->size();
        for (const ledger::StoredCosignature& c : *got) {
            note(c.cosignature.checkpoint.tree_size);
        }
    }
    while (timestamps_read < replica->timestamp_count()) {
        const auto got = replica->timestamps(timestamps_read, page);
        if (!got || got->empty()) {
            break;
        }
        timestamps_read += got->size();
        for (const ledger::StoredTimestamp& t : *got) {
            note(t.checkpoint.checkpoint.tree_size);
        }
    }
    while (network_read < replica->network_cosignature_count()) {
        const auto got = replica->network_cosignatures(network_read, page);
        if (!got || got->empty()) {
            break;
        }
        network_read += got->size();
        for (const ledger::StoredNetworkCosignature& n : *got) {
            note(n.checkpoint.checkpoint.tree_size);
        }
    }
    return attested_size;
}

ArchiveSyncReport ArchivedLedger::Impl::sync_locked(ArchiveState& state,
                                                    const std::atomic<bool>* stop) {
    ArchiveSyncReport out;
    const protocol::Timestamp now = clock->now();
    state.last_try = now;
    auto server = client(state, stop);
    if (!server) {
        out.error = server.error().detail;
        out.code = server.error().code;
        state.last_error = out.error;
        return out;
    }
    SyncOptions options;
    options.vault = false; // commitments and public metadata, never sealed data
    options.from = state.cursors;
    auto synced = sync_replica(*server, *replica, directory, {}, options);
    if (!synced) {
        out.error = synced.error().detail;
        out.code = synced.error().code;
        state.last_error = out.error;
        if (stop != nullptr && stop->load()) {
            // Stopped here, not refused there.
        } else if (out.code == Errc::unavailable) {
            if (!state.unreachable_since) {
                state.unreachable_since = now;
            }
        } else {
            state.unreachable_since.reset();
        }
        note_replica(state);
        return out;
    }
    out.synced = true;
    out.replica = *synced;
    state.cursors = synced->next;
    state.last_sync = now;
    state.last_error.clear();
    state.unreachable_since.reset();
    out.published = refresh_published(*server, stop);
    state.published_problems = out.published.problems;
    if (state.published_problems.size() > 64) {
        state.published_problems.resize(64);
    }
    note_replica(state);
    return out;
}

PublishedRefresh ArchivedLedger::Impl::refresh_published(const Client& server,
                                                         const std::atomic<bool>* stop) {
    PublishedRefresh out;
    auto problem = [&out](std::string text) {
        if (out.problems.size() < 64) {
            out.problems.push_back(std::move(text));
        }
    };
    auto listed = server.request("GET", "/v1/published");
    if (!listed) {
        problem(std::format("listing the published records: {}", listed.error().detail));
        return out;
    }
    if (listed->status == 401 || listed->status == 403) {
        problem("the member's server does not list its published records to this archive's "
                "token (it needs the archive scope)");
        return out;
    }
    if (listed->status != 200) {
        problem(std::format("listing the published records: status {}", listed->status));
        return out;
    }
    auto listing = parse_published_list(listed->body);
    if (!listing) {
        problem(std::string(listing.error().detail));
        return out;
    }
    out.listing = listing->size();
    auto kept_list = load_kept(directory);
    if (!kept_list) {
        problem(std::string(kept_list.error().detail));
        return out;
    }
    std::map<std::string, KeptBundle, std::less<>> kept;
    for (KeptBundle& k : *kept_list) {
        kept.emplace(k.token, std::move(k));
    }
    const std::filesystem::path folder = directory / published_folder;
    std::error_code ec;
    std::filesystem::create_directories(folder, ec);
    bool whole = true;
    bool wrote = false;
    for (const PublishedListing& l : *listing) {
        if (stop != nullptr && stop->load()) {
            whole = false;
            break;
        }
        const auto found = kept.find(l.token);
        if (found != kept.end()) {
            if (found->second.record != l.record) {
                problem("the member lists " + l.token +
                        " for another record than before: the bundle kept stays");
                continue;
            }
            // Fetched again only once the record changed since the kept
            // bundle's checkpoint.
            const auto last = last_index_about(replica->state(), l.record);
            if (!last || *last < found->second.size) {
                ++out.unchanged;
                continue;
            }
        }
        auto fetched = server.request("GET", "/c/" + l.token);
        if (!fetched) {
            problem(std::format("fetching {}: {}", l.token, fetched.error().detail));
            if (fetched.error().code == Errc::unavailable) {
                whole = false;
                break;
            }
            continue;
        }
        if (fetched->status == 404) {
            continue; // taken down since it was listed
        }
        if (fetched->status != 200) {
            problem(std::format("fetching {}: status {}", l.token, fetched->status));
            continue;
        }
        ++out.fetched;
        protocol::VerifyOptions verify;
        verify.expected_ledger = member;
        const auto report = protocol::verify_bundle(*provider, fetched->body, verify);
        if (!report) {
            problem(std::format("the evidence at {} does not verify: {}", l.token,
                                report.error().detail));
            continue;
        }
        if (report->record != l.record) {
            problem("the evidence at " + l.token + " is of another record than listed");
            continue;
        }
        const std::uint64_t size = report->checkpoint.tree_size;
        if (found != kept.end() && size <= found->second.size) {
            // Never back: an older answer (a cache in between) is not kept.
            if (size < found->second.size) {
                problem("the member answered " + l.token + " as of an older checkpoint than kept");
            } else {
                ++out.unchanged;
            }
            continue;
        }
        // The bundle's history must be this archive's copy's.
        if (replica->size() >= size) {
            const auto root = replica->root(size);
            if (!root || *root != report->checkpoint.root) {
                problem("the evidence at " + l.token +
                        " is of another history than this archive's copy of the ledger");
                continue;
            }
        }
        if (auto s = detail::write_file(folder / (l.token + ".cbor"), fetched->body, false, false);
            !s) {
            problem(std::format("keeping {}: {}", l.token, s.error().detail));
            continue;
        }
        wrote = true;
        kept[l.token] = KeptBundle{l.token, l.record, size, report->checkpoint.timestamp};
        ++out.kept;
    }
    out.listed = whole;
    if (whole) {
        // What the member no longer lists, it took down.
        std::set<std::string, std::less<>> listed_tokens;
        for (const PublishedListing& l : *listing) {
            listed_tokens.insert(l.token);
        }
        for (auto it = kept.begin(); it != kept.end();) {
            if (listed_tokens.contains(it->first)) {
                ++it;
                continue;
            }
            std::filesystem::remove(folder / (it->first + ".cbor"), ec);
            it = kept.erase(it);
            ++out.removed;
            wrote = true;
        }
    }
    if (wrote) {
        detail::sync_directory(folder);
    }
    std::vector<KeptBundle> list;
    for (auto& [token, k] : kept) {
        list.push_back(std::move(k));
    }
    if (auto s = save_kept(directory, list); !s) {
        problem(std::format("writing kept.json: {}", s.error().detail));
    }
    return out;
}

Result<std::unique_ptr<ArchivedLedger>> ArchivedLedger::open(const std::filesystem::path& ledger,
                                                             const protocol::Id& member,
                                                             ledger::Clock& clock,
                                                             const crypto::Provider& provider,
                                                             std::uint64_t lock_ms) {
    const std::filesystem::path directory = archive_path(ledger, member);
    std::error_code ec;
    if (!std::filesystem::exists(directory / state_file, ec)) {
        return fail(Errc::not_found, "that ledger is not archived here");
    }
    auto lock = ledger::DirectoryLock::acquire(directory, lock_ms);
    if (!lock) {
        return std::unexpected(lock_failure(lock.error()).error());
    }
    // A restored archive holds its replica as a backup until first opened.
    if (!std::filesystem::exists(directory / "statements", ec) &&
        std::filesystem::exists(backup_piece_path(directory, 0), ec)) {
        const auto whole = joined_backup(directory);
        auto fs = ledger::PosixFileSystem::open_directory(directory);
        if (!whole || !fs) {
            return fail(Errc::unavailable, "cannot read the archive's restored copy");
        }
        std::istringstream in(*whole, std::ios::binary);
        auto summary = ledger::restore_backup(
            in, *fs, clock, provider, [](const ledger::BackupFile&) -> Status {
                return fail(Errc::rejected, "an archived ledger's copy holds no files");
            });
        if (!summary || summary->ledger_id != member) {
            remove_ledger_files(directory);
            return fail(Errc::verification_failed,
                        summary ? "the archive's restored copy is of another ledger"
                                : "the archive's restored copy does not restore");
        }
        remove_backup_pieces(directory);
    }
    auto fs = ledger::PosixFileSystem::open_directory(directory);
    if (!fs) {
        return std::unexpected(fs.error());
    }
    auto impl = std::make_unique<Impl>();
    impl->directory = directory;
    impl->member = member;
    impl->clock = &clock;
    impl->provider = &provider;
    impl->fs = std::make_unique<ledger::PosixFileSystem>(std::move(*fs));
    auto opened = ledger::Ledger::open(*impl->fs, clock, provider);
    if (!opened) {
        return std::unexpected(opened.error());
    }
    if (opened->id() != member) {
        return fail(Errc::verification_failed, "the archive holds another ledger than its name");
    }
    impl->replica.emplace(std::move(*opened));
    return std::unique_ptr<ArchivedLedger>(new ArchivedLedger(std::move(impl)));
}

Result<std::pair<std::unique_ptr<ArchivedLedger>, ArchiveSyncReport>>
ArchivedLedger::create(const std::filesystem::path& ledger, const protocol::Id& member,
                       const ArchiveSource& source, ledger::Clock& clock,
                       const crypto::Provider& provider) {
    const std::filesystem::path root = archive_root(ledger);
    const std::filesystem::path directory = archive_path(ledger, member);
    std::error_code ec;
    if (std::filesystem::exists(directory / state_file, ec)) {
        return fail(Errc::rejected, "that ledger is archived here already");
    }
    auto url = Url::parse(source.url);
    if (!url) {
        return fail(Errc::invalid_argument, "the source is the member's server: http(s)://HOST");
    }
    std::filesystem::create_directories(root, ec);
    std::filesystem::permissions(root, std::filesystem::perms::owner_all,
                                 std::filesystem::perm_options::replace, ec);
    // A half-made archive (an add that stopped) is begun again.
    std::filesystem::remove_all(directory, ec);
    std::filesystem::create_directories(directory, ec);
    if (ec) {
        return fail(Errc::unavailable, "cannot create the archive's directory");
    }
    std::filesystem::permissions(directory, std::filesystem::perms::owner_all,
                                 std::filesystem::perm_options::replace, ec);
    // Nothing is left behind unless it all works.
    struct Cleanup {
        std::filesystem::path directory;
        bool keep = false;
        ~Cleanup() {
            if (!keep) {
                std::error_code e;
                std::filesystem::remove_all(directory, e);
            }
        }
    } cleanup{directory};
    auto lock = ledger::DirectoryLock::acquire(directory);
    if (!lock) {
        return std::unexpected(lock.error());
    }
    if (auto s = detail::write_file(directory / token_file, as_bytes(source.token + "\n"), true);
        !s) {
        return std::unexpected(s.error());
    }
    if (source.ca_pem) {
        if (auto s = detail::write_file(directory / ca_file, *source.ca_pem, true); !s) {
            return std::unexpected(s.error());
        }
    }
    ArchiveState state;
    state.source = url->to_string();
    state.created = clock.now();
    auto impl = std::make_unique<Impl>();
    impl->directory = directory;
    impl->member = member;
    impl->clock = &clock;
    impl->provider = &provider;
    auto fs = ledger::PosixFileSystem::open_directory(directory);
    if (!fs) {
        return std::unexpected(fs.error());
    }
    impl->fs = std::make_unique<ledger::PosixFileSystem>(std::move(*fs));
    auto server = impl->client(state, nullptr);
    if (!server) {
        return std::unexpected(server.error());
    }
    // Of exactly that ledger: its genesis is pinned before anything is kept.
    auto created = create_replica(*server, *impl->fs, clock, provider, member);
    if (!created) {
        return std::unexpected(created.error());
    }
    impl->replica.emplace(std::move(*created));
    ArchiveSyncReport report = impl->sync_locked(state, nullptr);
    if (!report.synced) {
        return fail(report.code, report.error);
    }
    if (auto s = save_archive_state(directory, state); !s) {
        return std::unexpected(s.error());
    }
    cleanup.keep = true;
    return std::pair{std::unique_ptr<ArchivedLedger>(new ArchivedLedger(std::move(impl))),
                     std::move(report)};
}

Result<ArchiveSyncReport> ArchivedLedger::sync(const std::atomic<bool>* stop,
                                               std::uint64_t lock_ms) {
    auto lock = ledger::DirectoryLock::acquire(impl_->directory, lock_ms);
    if (!lock) {
        return std::unexpected(lock_failure(lock.error()).error());
    }
    if (auto picked = impl_->replica->refresh(*impl_->fs, true); !picked) {
        return std::unexpected(picked.error());
    }
    auto state = load_archive_state(impl_->directory);
    if (!state) {
        return std::unexpected(state.error());
    }
    ArchiveSyncReport report = impl_->sync_locked(*state, stop);
    if (auto s = save_archive_state(impl_->directory, *state); !s) {
        return std::unexpected(s.error());
    }
    return report;
}

Result<bool> ArchivedLedger::refresh(std::uint64_t lock_ms) {
    if (!impl_->replica->outdated()) {
        return false;
    }
    auto lock = ledger::DirectoryLock::acquire(impl_->directory, lock_ms);
    if (!lock) {
        return false; // busy: the next time
    }
    auto picked = impl_->replica->refresh(*impl_->fs, true);
    if (!picked) {
        return std::unexpected(picked.error());
    }
    return picked->entries + picked->checkpoints + picked->cosignatures + picked->timestamps +
               picked->network_cosignatures >
           0;
}

std::optional<protocol::Timestamp> ArchivedLedger::newest_attestation() const {
    return impl_->newest_attestation();
}

// ---- re-attestation ------------------------------------------------------------

AttesterOutcome ArchivedLedger::Impl::ask_witness(const ArchiveWitness& witness,
                                                  std::set<std::string>& own,
                                                  std::vector<std::string>& made,
                                                  const std::atomic<bool>* stop) {
    AttesterOutcome out;
    out.kind = "witness";
    out.name = witness.name;
    out.url = witness.url;
    const auto latest = replica->latest_checkpoint();
    const std::uint64_t size = latest->checkpoint.tree_size;
    // What this archive knows of the witness's history with the ledger: the
    // largest size it cosigned, and whether the member has it cosign (a
    // cosignature by it that this archive did not ask for).
    std::optional<std::uint64_t> known;
    bool member_uses = false;
    bool cosigned_latest = false;
    std::set<std::string> held;
    for (std::uint64_t at = 0; at < replica->cosignature_count(); at += page) {
        const auto got = replica->cosignatures(at, page);
        if (!got || got->empty()) {
            break;
        }
        for (const ledger::StoredCosignature& c : *got) {
            if (c.witness != witness.key) {
                continue;
            }
            known = std::max(known.value_or(0), c.cosignature.checkpoint.tree_size);
            cosigned_latest = cosigned_latest || c.cosignature.checkpoint == latest->checkpoint;
            std::string digest = sha256_hex(*provider, c.encoded);
            if (!own.contains(digest)) {
                member_uses = true;
            }
            held.insert(std::move(digest));
        }
    }
    if (cosigned_latest) {
        // A ledger keeps one cosignature per witness and checkpoint: a new
        // one would not be kept. Nothing is asked, and nothing moves.
        out.already = true;
        return out;
    }
    const bool again = known && *known == size;
    if (!again && member_uses) {
        // Moving it would break the member's next request, which starts
        // from the size the member saw it cosign.
        out.problem = std::format(
            "the ledger's own server has this witness cosign its checkpoints, and it has not "
            "cosigned the latest one (size {}) as far as this archive knows: an archive never "
            "moves a witness the ledger uses",
            size);
        return out;
    }
    auto url = Url::parse(witness.url);
    if (!url) {
        out.problem = "not a witness URL";
        return out;
    }
    ClientOptions options;
    options.max_body = witness_body;
    options.timeout = std::chrono::seconds(30);
    options.stop = stop;
    const Client client(std::move(*url), options);
    auto post = [&](std::uint64_t old, bool registering) -> Result<http::ClientResponse> {
        auto request = replica->cosign_request(old);
        if (!request) {
            return std::unexpected(request.error());
        }
        auto encoded = protocol::encode_cosign_request(*request);
        if (!encoded) {
            return std::unexpected(encoded.error());
        }
        if (!registering) {
            return client.request("POST", "/v1/witness/cosign", *encoded, "application/cbor");
        }
        // A public witness's registration (public_witness.hpp): {1: genesis
        // entry, 2: cosign request}.
        auto genesis = replica->entry(0);
        if (!genesis) {
            return std::unexpected(genesis.error());
        }
        auto body = cbor::encode(
            cbor::Value::map({{cbor::Value::integer(1), cbor::Value::bytes(std::move(*genesis))},
                              {cbor::Value::integer(2), cbor::Value::bytes(std::move(*encoded))}}));
        if (!body) {
            return std::unexpected(body.error());
        }
        return client.request("POST", "/v1/witness/register", *body, "application/cbor");
    };
    bool registering = !known;
    auto answer = post(known.value_or(0), registering);
    if (answer && answer->status == 404 && !registering) {
        // It no longer follows the ledger (and the member does not use it).
        registering = true;
        answer = post(0, true);
    }
    if (!answer) {
        out.problem = std::format("asking it: {}", answer.error().detail);
        return out;
    }
    if (answer->status / 100 != 2) {
        const std::string message =
            error_message_of(answer->body).value_or(std::format("status {}", answer->status));
        switch (answer->status) {
        case 409:
            out.problem = "it has cosigned a later checkpoint of this ledger than this archive "
                          "holds (the ledger, or another archive, asked it since): not forced";
            break;
        case 422:
            out.problem = "it refuses: " + message;
            break;
        case 429:
        case 503:
            out.problem = "it asks to wait (" + message + "): asked again at the next round";
            break;
        default:
            out.problem = std::format("it answered status {}: {}", answer->status, message);
            break;
        }
        return out;
    }
    if (auto kept = replica->add_cosignature(answer->body, witness.key); !kept) {
        out.problem = std::format("its cosignature does not verify with its key as configured "
                                  "(did its key change? kanhe archive config --witness URL): {}",
                                  kept.error().detail);
        return out;
    }
    // The same bytes as one held (the witness dated both in the same
    // second) attest nothing anew, and stay whose they were.
    const std::string digest = sha256_hex(*provider, answer->body);
    if (held.contains(digest)) {
        out.problem = "it answered a cosignature this archive holds already: asked again at the "
                      "next round";
        return out;
    }
    own.insert(digest);
    made.push_back(digest);
    out.attested = size;
    out.registered = registering && answer->status == 201;
    return out;
}

AttesterOutcome ArchivedLedger::Impl::ask_authority(const std::string& url,
                                                    std::set<std::string>& own,
                                                    std::vector<std::string>& made,
                                                    const std::atomic<bool>* stop) {
    AttesterOutcome out;
    out.kind = "authority";
    out.name = url;
    out.url = url;
    const auto latest = replica->latest_checkpoint();
    ClientOptions options;
    options.timeout = std::chrono::seconds(30);
    options.max_body = witness_body;
    options.stop = stop;
    auto token = request_timestamp(*provider, url, replica->hash(), *latest, options);
    if (!token) {
        out.problem = std::format("it gave no token: {}", token.error().detail);
        return out;
    }
    if (auto kept = replica->add_timestamp(*token, latest->checkpoint.tree_size); !kept) {
        out.problem = std::format("its token is not kept: {}", kept.error().detail);
        return out;
    }
    if (const auto read = provider->read_timestamp(*token, {})) {
        out.name = read->authority;
    }
    const std::string digest = sha256_hex(*provider, *token);
    own.insert(digest);
    made.push_back(digest);
    out.attested = latest->checkpoint.tree_size;
    return out;
}

Result<AttestReport> ArchivedLedger::attest(const ArchiveConfig& config, bool force,
                                            const std::atomic<bool>* stop, std::uint64_t lock_ms) {
    auto lock = ledger::DirectoryLock::acquire(impl_->directory, lock_ms);
    if (!lock) {
        return std::unexpected(lock_failure(lock.error()).error());
    }
    if (auto picked = impl_->replica->refresh(*impl_->fs, true); !picked) {
        return std::unexpected(picked.error());
    }
    auto state = load_archive_state(impl_->directory);
    if (!state) {
        return std::unexpected(state.error());
    }
    AttestReport report;
    const auto latest = impl_->replica->latest_checkpoint();
    if (!latest) {
        return fail(Errc::not_found, "the archive holds no checkpoint of the ledger yet");
    }
    report.size = latest->checkpoint.tree_size;
    state->attested_at = impl_->newest_attestation();
    const protocol::Timestamp now = impl_->clock->now();
    if (!force && now < next_attestation(*state, config)) {
        report.attested_at = state->attested_at;
        report.next = next_attestation(*state, config);
        if (auto s = save_archive_state(impl_->directory, *state); !s) {
            return std::unexpected(s.error());
        }
        return report;
    }
    report.due = true;
    std::set<std::string> own(state->own.begin(), state->own.end());
    std::vector<std::string> made;
    for (const ArchiveWitness& w : config.witnesses) {
        if (stop != nullptr && stop->load()) {
            break;
        }
        report.outcomes.push_back(impl_->ask_witness(w, own, made, stop));
    }
    for (const std::string& a : config.authorities) {
        if (stop != nullptr && stop->load()) {
            break;
        }
        report.outcomes.push_back(impl_->ask_authority(a, own, made, stop));
    }
    state->own.insert(state->own.end(), made.begin(), made.end());
    if (state->own.size() > max_own_attestations) {
        state->own.erase(state->own.begin(),
                         state->own.begin() +
                             static_cast<std::ptrdiff_t>(state->own.size() - max_own_attestations));
    }
    state->last_attest = now;
    state->attest_problems.clear();
    for (const AttesterOutcome& o : report.outcomes) {
        if (!o.problem.empty() && state->attest_problems.size() < 64) {
            state->attest_problems.push_back(
                std::format("{} {}: {}", o.kind, o.name.empty() ? o.url : o.name, o.problem));
        }
    }
    impl_->note_replica(*state);
    report.attested_at = state->attested_at;
    report.next = next_attestation(*state, config);
    if (auto s = save_archive_state(impl_->directory, *state); !s) {
        return std::unexpected(s.error());
    }
    return report;
}

// ---- serving ---------------------------------------------------------------------

Result<Bytes> ArchivedLedger::published_bundle(std::string_view token) const {
    if (!valid_published_token(token)) {
        return fail(Errc::not_found, "nothing is kept at that address");
    }
    auto bytes =
        detail::read_file(impl_->directory / published_folder / (std::string(token) + ".cbor"));
    if (!bytes) {
        return fail(Errc::not_found, "nothing is kept at that address");
    }
    auto bundle = protocol::decode_bundle(*bytes);
    if (!bundle) {
        return fail(Errc::malformed, "the bundle kept at that address is damaged");
    }
    if (bundle->renewals.size() >= protocol::max_renewals) {
        return bytes;
    }
    const Bytes& last =
        bundle->renewals.empty() ? bundle->checkpoint : bundle->renewals.back().checkpoint;
    const auto parsed = protocol::parse_checkpoint(last);
    if (!parsed) {
        return bytes;
    }
    const std::uint64_t from = parsed->checkpoint.tree_size;
    const ledger::Ledger& replica = *impl_->replica;
    const auto target = impl_->latest_attested();
    // The renewal comes from this archive's copy, which must hold the
    // bundle's history: the same root at its size.
    if (!target || *target < from || replica.size() < from) {
        return bytes;
    }
    const auto root = replica.root(from);
    if (!root || *root != parsed->checkpoint.root) {
        return bytes;
    }
    auto renewal = replica.renewal(from, *target);
    if (!renewal) {
        return bytes;
    }
    // What the bundle holds already attests nothing anew.
    std::set<Bytes> held(bundle->cosignatures.begin(), bundle->cosignatures.end());
    std::vector<protocol::network::NoteSignature> notes;
    for (const protocol::Anchor& a : bundle->anchors) {
        held.insert(a.timestamps.begin(), a.timestamps.end());
        notes.insert(notes.end(), a.network_cosignatures.begin(), a.network_cosignatures.end());
    }
    for (const protocol::Renewal& r : bundle->renewals) {
        held.insert(r.cosignatures.begin(), r.cosignatures.end());
        held.insert(r.timestamps.begin(), r.timestamps.end());
        notes.insert(notes.end(), r.network_cosignatures.begin(), r.network_cosignatures.end());
    }
    std::erase_if(renewal->cosignatures, [&](const Bytes& b) { return held.contains(b); });
    std::erase_if(renewal->timestamps, [&](const Bytes& b) { return held.contains(b); });
    std::erase_if(renewal->network_cosignatures, [&](const protocol::network::NoteSignature& n) {
        return std::ranges::contains(notes, n);
    });
    if (renewal->cosignatures.empty() && renewal->timestamps.empty() &&
        renewal->network_cosignatures.empty()) {
        return bytes; // it would add nothing
    }
    bundle->renewals.push_back(std::move(*renewal));
    auto encoded = protocol::encode_bundle(*bundle);
    if (!encoded) {
        return bytes;
    }
    return std::move(*encoded);
}

http::Response ArchivedLedger::answer(const http::Request& r, std::string_view rest) const {
    const ledger::Ledger& replica = *impl_->replica;
    if (rest == "/v1/checkpoint") {
        if (r.query.contains("size")) {
            const auto size = number(r, "size");
            if (!size) {
                return error_response(400, "invalid_argument", "size must be a number");
            }
            auto found = replica.checkpoints_of_size(*size);
            if (!found) {
                return error_response(found.error());
            }
            if (found->empty()) {
                return error_response(404, "not_found", "no checkpoint of this size");
            }
            return binary("application/cose", std::move(found->back().encoded));
        }
        auto latest = replica.latest_checkpoint();
        if (!latest) {
            return error_response(404, "not_found", "no checkpoint yet");
        }
        return binary("application/cose", std::move(latest->encoded));
    }
    if (rest == "/v1/consistency") {
        const auto old_size = number(r, "old");
        const auto new_size = number(r, "new");
        if (!old_size || !new_size || *old_size == 0 || *old_size > *new_size ||
            *new_size > replica.size()) {
            return error_response(400, "invalid_argument",
                                  "old and new must be sizes with 0 < old <= new <= size");
        }
        auto proof = replica.consistency_proof(*old_size, *new_size);
        if (!proof) {
            return error_response(proof.error());
        }
        cbor::Array digests;
        for (const crypto::Digest& d : *proof) {
            digests.push_back(cbor::Value::bytes(d.bytes()));
        }
        auto encoded = cbor::encode(cbor::Value::array(std::move(digests)));
        if (!encoded) {
            return error_response(encoded.error());
        }
        return binary("application/cbor", std::move(*encoded));
    }
    if (rest == "/v1/renewal") {
        const auto from = number(r, "from");
        if (!from || *from == 0) {
            return error_response(400, "invalid_argument", "from must be a positive integer");
        }
        std::optional<std::uint64_t> size;
        if (r.query.contains("size")) {
            size = number(r, "size");
            if (!size || *size == 0) {
                return error_response(400, "invalid_argument", "size must be a positive integer");
            }
            if (*from > *size) {
                return error_response(400, "invalid_argument", "from must not be above size");
            }
        }
        auto made = replica.renewal(*from, size);
        if (!made) {
            return error_response(made.error());
        }
        auto encoded = protocol::encode_renewal(*made);
        if (!encoded) {
            return error_response(encoded.error());
        }
        return binary("application/cbor", std::move(*encoded));
    }
    if (rest.starts_with("/c/") && rest.size() > 3 && rest.find('/', 3) == std::string_view::npos) {
        auto bundle = published_bundle(rest.substr(3));
        if (!bundle) {
            return error_response(bundle.error());
        }
        return binary("application/cbor", std::move(*bundle));
    }
    return error_response(404, "not_found", "no such route");
}

// ---- removal, status, and backups ---------------------------------------------

Status remove_archive(const std::filesystem::path& ledger, const protocol::Id& member) {
    const std::filesystem::path directory = archive_path(ledger, member);
    std::error_code ec;
    if (!std::filesystem::is_directory(directory, ec)) {
        return fail(Errc::not_found, "that ledger is not archived here");
    }
    auto lock = ledger::DirectoryLock::acquire(directory, 60'000);
    if (!lock) {
        return lock_failure(lock.error());
    }
    std::filesystem::remove_all(directory, ec);
    if (ec) {
        return fail(Errc::unavailable, "cannot remove the archive's directory");
    }
    return {};
}

std::optional<json> archives_status(const std::filesystem::path& ledger, protocol::Timestamp now) {
    const auto members = archived_ledgers(ledger);
    if (members.empty()) {
        return std::nullopt;
    }
    json advice = json::array();
    auto config = load_archive_config(ledger);
    if (!config) {
        advice.push_back("The archives' config.json is damaged: set it again (kanhe archive "
                         "config).");
        config = ArchiveConfig{};
    }
    std::size_t unreachable = 0;
    std::optional<protocol::Timestamp> oldest_sync;
    std::optional<protocol::Timestamp> next;
    const bool attesters = !config->witnesses.empty() || !config->authorities.empty();
    for (const protocol::Id& m : members) {
        const auto state = load_archive_state(archive_path(ledger, m));
        if (!state) {
            continue;
        }
        if (state->unreachable_since) {
            ++unreachable;
        }
        const protocol::Timestamp synced = state->last_sync.value_or(0);
        oldest_sync = std::min(oldest_sync.value_or(synced), synced);
        if (attesters) {
            const protocol::Timestamp due = next_attestation(*state, *config);
            next = std::min(next.value_or(due), due);
        }
    }
    const bool post_quantum = std::ranges::any_of(config->witnesses, [](const ArchiveWitness& w) {
        return post_quantum_algorithm(w.key.algorithm);
    });
    if (!attesters) {
        advice.push_back("No witness or time-stamp authority is configured for the archives: "
                         "nothing re-attests the ledgers kept (kanhe archive config --witness URL "
                         "--tsa URL).");
    } else if (config->witnesses.empty()) {
        advice.push_back("No witness is configured for the archives: their re-attestations are "
                         "tokens alone. Add a witness whose key is ML-DSA (kanhe archive config "
                         "--witness URL).");
    } else if (!post_quantum) {
        advice.push_back("Every witness configured for the archives has a classical key: their "
                         "cosignatures last only as long as the classical algorithms. Add one "
                         "whose key is ML-DSA (kanhe archive config --witness URL).");
    }
    if (unreachable > 0) {
        advice.push_back(std::format("{} of the ledgers kept cannot be reached at their servers: "
                                     "they are served as last synced.",
                                     unreachable));
    }
    static_cast<void>(now);
    json out{{"count", members.size()},
             {"unreachable", unreachable},
             {"oldest_sync", oldest_sync && *oldest_sync > 0
                                 ? json(verifier::iso_time(*oldest_sync))
                                 : json(nullptr)},
             {"next_attestation", next ? json(verifier::iso_time(*next)) : json(nullptr)},
             {"witnesses", config->witnesses.size()},
             {"authorities", config->authorities.size()},
             {"witnesses_post_quantum", post_quantum},
             {"advice", advice}};
    return std::optional<json>(std::in_place, std::move(out));
}

bool archive_backup_path_allowed(std::string_view path) {
    constexpr std::string_view prefix = "archive/";
    if (path == "archive/config.json") {
        return true;
    }
    if (!path.starts_with(prefix) || path.size() < prefix.size() + 66) {
        return false;
    }
    const std::string_view rest = path.substr(prefix.size());
    if (!id_of(rest.substr(0, 64)) || rest[64] != '/') {
        return false;
    }
    const std::string_view name = rest.substr(65);
    if (name == state_file || name == token_file || name == ca_file || name == kept_file ||
        backup_piece_name(name)) {
        return true;
    }
    constexpr std::string_view published = "published/";
    return name.starts_with(published) && name.ends_with(".cbor") &&
           valid_published_token(name.substr(published.size(), name.size() - published.size() - 5));
}

Result<std::vector<std::pair<std::string, Bytes>>>
archive_backup_files(const std::filesystem::path& ledger, ledger::Clock& clock,
                     const crypto::Provider& provider) {
    std::vector<std::pair<std::string, Bytes>> out;
    const auto members = archived_ledgers(ledger);
    if (members.empty()) {
        return out;
    }
    auto add = [&](const std::filesystem::path& file, const std::string& relative) -> Status {
        auto bytes = detail::read_file(file);
        if (!bytes) {
            return bytes.error().code == Errc::not_found ? Status{}
                                                         : Status(std::unexpected(bytes.error()));
        }
        out.emplace_back(relative, std::move(*bytes));
        return {};
    };
    if (auto s = add(archive_root(ledger) / "config.json", "archive/config.json"); !s) {
        return std::unexpected(s.error());
    }
    for (const protocol::Id& m : members) {
        const std::filesystem::path directory = archive_path(ledger, m);
        const std::string base = "archive/" + hex(m) + "/";
        auto lock = ledger::DirectoryLock::acquire(directory, 60'000);
        if (!lock) {
            return std::unexpected(lock_failure(lock.error()).error());
        }
        for (const std::string_view name : {state_file, token_file, ca_file, kept_file}) {
            if (auto s = add(directory / name, base + std::string(name)); !s) {
                return std::unexpected(s.error());
            }
        }
        std::vector<std::string> bundles;
        std::error_code ec;
        for (const auto& e :
             std::filesystem::directory_iterator(directory / published_folder, ec)) {
            const std::string relative =
                base + std::string(published_folder) + "/" + e.path().filename().string();
            if (archive_backup_path_allowed(relative)) {
                bundles.push_back(relative);
            }
        }
        std::ranges::sort(bundles);
        for (const std::string& relative : bundles) {
            // One too large for a backup's item is fetched again from the
            // member, if it can be.
            if (std::filesystem::file_size(ledger / relative, ec) > most_backed_up_bundle) {
                continue;
            }
            if (auto s = add(ledger / relative, relative); !s) {
                return std::unexpected(s.error());
            }
        }
        std::string whole;
        if (!std::filesystem::exists(directory / "statements", ec)) {
            // Restored and not opened since: its copy as it came.
            auto joined = joined_backup(directory);
            if (!joined) {
                continue;
            }
            whole = std::move(*joined);
        }
        if (whole.empty()) {
            auto fs = ledger::PosixFileSystem::open_directory(directory);
            if (!fs) {
                return std::unexpected(fs.error());
            }
            auto replica = ledger::Ledger::open(*fs, clock, provider);
            if (!replica) {
                return std::unexpected(replica.error());
            }
            std::ostringstream stream(std::ios::binary);
            if (auto written = ledger::write_backup(*replica, provider, {}, clock.now(), stream);
                !written) {
                return std::unexpected(written.error());
            }
            whole = std::move(stream).str();
        }
        for (std::size_t at = 0, n = 0; at < whole.size(); at += backup_piece, ++n) {
            const std::size_t length = std::min(backup_piece, whole.size() - at);
            out.emplace_back(base + std::string(backup_file) + std::to_string(n),
                             Bytes(whole.begin() + static_cast<std::ptrdiff_t>(at),
                                   whole.begin() + static_cast<std::ptrdiff_t>(at + length)));
        }
    }
    return out;
}

// ---- the service -------------------------------------------------------------------

struct ArchiveService::Entry {
    std::unique_ptr<ArchivedLedger> archive;
    /// What was last said of it, so that only changes are told.
    std::string said;
};

ArchiveService::ArchiveService(std::filesystem::path ledger, const crypto::Provider& provider,
                               std::function<void(const std::string&)> say)
    : ledger_(std::move(ledger)), provider_(provider), say_(std::move(say)) {
    rescan();
}

ArchiveService::~ArchiveService() {
    stopping_ = true;
}

std::shared_ptr<ArchiveService::Entry> ArchiveService::find(const protocol::Id& member) const {
    const std::lock_guard lock(mutex_);
    const auto it = entries_.find(protocol::key_of(member));
    return it == entries_.end() ? nullptr : it->second;
}

void ArchiveService::rescan() {
    const auto members = archived_ledgers(ledger_);
    std::set<protocol::IdKey> present;
    for (const protocol::Id& m : members) {
        present.insert(protocol::key_of(m));
        if (find(m)) {
            continue;
        }
        // Busy (another process adds or syncs it): the next time.
        auto opened = ArchivedLedger::open(ledger_, m, clock_, provider_, 200);
        if (!opened) {
            if (opened.error().code != Errc::rejected && say_) {
                say_(std::format("archive {}: cannot open it: {}", hex(m).substr(0, 16),
                                 opened.error().detail));
            }
            continue;
        }
        auto entry = std::make_shared<Entry>();
        entry->archive = std::move(*opened);
        const std::lock_guard lock(mutex_);
        entries_[protocol::key_of(m)] = std::move(entry);
    }
    const std::lock_guard lock(mutex_);
    std::erase_if(entries_, [&](const auto& item) { return !present.contains(item.first); });
}

std::optional<http::Response> ArchiveService::handle(const http::Request& r) const {
    const std::string_view path = r.path;
    if (!path.starts_with("/a/")) {
        return std::nullopt;
    }
    http::Response out = [&]() -> http::Response {
        if (r.method != "GET") {
            auto response = error_response(405, "unsupported", "method not allowed");
            response.headers.emplace_back("Allow", "GET");
            return response;
        }
        const std::size_t slash = path.find('/', 3);
        const auto member = id_of(
            path.substr(3, slash == std::string_view::npos ? std::string_view::npos : slash - 3));
        if (!member) {
            return error_response(404, "not_found", "no ledger is archived at that address");
        }
        const auto entry = find(*member);
        if (!entry) {
            return error_response(404, "not_found", "that ledger is not archived here");
        }
        if (slash == std::string_view::npos) {
            return error_response(404, "not_found", "no such route");
        }
        return entry->archive->answer(r, path.substr(slash));
    }();
    out.headers.emplace_back("Access-Control-Allow-Origin", "*");
    out.headers.emplace_back("Cache-Control", "no-store");
    out.principal = "public";
    return out;
}

void ArchiveService::status(json& status) const {
    if (auto archives = archives_status(ledger_, clock_.now())) {
        status["archives"] = std::move(*archives);
    }
}

void ArchiveService::run(const std::stop_token& stop) {
    const std::stop_callback on_stop(stop, [this] { stopping_ = true; });
    std::mutex mutex;
    std::condition_variable_any wake;
    std::string config_said;
    while (!stop.stop_requested()) {
        rescan();
        auto config = load_archive_config(ledger_);
        const std::string config_problem =
            config ? std::string() : std::string(config.error().detail);
        if (config_problem != config_said && say_ && !config_problem.empty()) {
            say_("archives: " + config_problem);
        }
        config_said = config_problem;
        std::vector<std::shared_ptr<Entry>> entries;
        {
            const std::lock_guard lock(mutex_);
            for (const auto& [key, entry] : entries_) {
                entries.push_back(entry);
            }
        }
        for (const auto& entry : entries) {
            if (stop.stop_requested()) {
                break;
            }
            ArchivedLedger& archive = *entry->archive;
            const std::string name = hex(archive.id()).substr(0, 16);
            if (auto picked = archive.refresh(); !picked && say_) {
                say_(std::format("archive {}: re-reading it: {}", name, picked.error().detail));
                continue;
            }
            auto state = load_archive_state(archive.directory());
            if (!state || !config) {
                continue;
            }
            const protocol::Timestamp now = clock_.now();
            if (now >= next_sync(*state, *config)) {
                const auto synced = archive.sync(&stopping_, 1000);
                std::string said;
                if (!synced) {
                    said = std::format("syncing: {}", synced.error().detail);
                } else if (!synced->synced) {
                    said = synced->code == Errc::unavailable
                               ? std::format("its server cannot be reached; served as last "
                                             "synced ({})",
                                             synced->error)
                               : std::format("the sync failed: {}", synced->error);
                }
                if (said != entry->said && say_ && !stop.stop_requested()) {
                    say_(std::format("archive {}: {}", name,
                                     said.empty() ? std::string("synced") : said));
                }
                entry->said = said;
                if (synced && synced->synced && say_ &&
                    synced->replica.entries + synced->published.kept > 0) {
                    say_(std::format("archive {}: synced {} entries, {} published records kept",
                                     name, synced->replica.entries, synced->published.kept));
                }
                state = load_archive_state(archive.directory());
                if (!state) {
                    continue;
                }
            }
            if ((config->witnesses.empty() && config->authorities.empty()) ||
                clock_.now() < next_attestation(*state, *config) || state->size == 0) {
                continue;
            }
            const auto attested = archive.attest(*config, false, &stopping_, 1000);
            if (!say_ || stop.stop_requested()) {
                continue;
            }
            if (!attested) {
                say_(std::format("archive {}: re-attesting: {}", name, attested.error().detail));
                continue;
            }
            if (!attested->due) {
                continue;
            }
            for (const AttesterOutcome& o : attested->outcomes) {
                if (o.already) {
                    continue;
                }
                const std::string who =
                    std::format("{} {}", o.kind, o.name.empty() ? o.url : o.name);
                say_(o.attested ? std::format("archive {}: {} attested the checkpoint at size {}",
                                              name, who, *o.attested)
                                : std::format("archive {}: {}: {}", name, who, o.problem));
            }
        }
        std::unique_lock lock(mutex);
        wake.wait_for(lock, stop, std::chrono::seconds(2), [] { return false; });
    }
}

} // namespace kanhe::node
