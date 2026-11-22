// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// Archives (spec section 16, "Archives"). A server keeps other ledgers, its
// members' typically, so that their published records and renewals are
// still answered once their own servers are gone (archive ...); a ledger
// lists the archives that keep it, which links to its published records then
// name as fallbacks (trust archive ...).

#include <algorithm>
#include <cctype>
#include <charconv>
#include <filesystem>
#include <format>
#include <optional>
#include <print>
#include <string>
#include <string_view>
#include <vector>

#include <kanhe/client/public_witnesses.hpp>
#include <kanhe/core/protocol/log.hpp>
#include <kanhe/ledger/environment.hpp>
#include <kanhe/node/archive.hpp>
#include <kanhe/node/client.hpp>
#include <kanhe/node/long_term.hpp>
#include <kanhe/node/trust.hpp>

#include "commands.hpp"
#include "output.hpp"
#include "records.hpp"
#include "serve.hpp"

namespace kanhe::cli {

namespace {

/// The server's own ledger directory, beside which its archives are kept.
std::filesystem::path archive_ledger(const Args& args) {
    const std::filesystem::path dir = args.ledger();
    require_ledger_directory(dir);
    return dir;
}

/// "90", "90s", "15m", "12h", or "365d".
std::chrono::seconds parse_duration(std::string_view text, std::string_view what) {
    std::uint64_t unit = 1;
    if (!text.empty()) {
        switch (text.back()) {
        case 's':
            text.remove_suffix(1);
            break;
        case 'm':
            unit = 60;
            text.remove_suffix(1);
            break;
        case 'h':
            unit = 3600;
            text.remove_suffix(1);
            break;
        case 'd':
            unit = 86'400;
            text.remove_suffix(1);
            break;
        default:
            break;
        }
    }
    std::uint64_t value = 0;
    const auto [end, ec] = std::from_chars(text.data(), text.data() + text.size(), value);
    if (text.empty() || ec != std::errc{} || end != text.data() + text.size() ||
        value > 3650ULL * 86'400 / unit) {
        throw UsageError{std::format("{} is a duration: N seconds, or Ns, Nm, Nh, Nd", what)};
    }
    return std::chrono::seconds(value * unit);
}

/// "1 h", "365 d", "90 s": a duration in words.
std::string duration_text(std::chrono::seconds d) {
    const auto s = static_cast<std::uint64_t>(d.count());
    if (s % 86'400 == 0) {
        return std::format("{} d", s / 86'400);
    }
    if (s % 3600 == 0) {
        return std::format("{} h", s / 3600);
    }
    if (s % 60 == 0) {
        return std::format("{} min", s / 60);
    }
    return std::format("{} s", s);
}

protocol::Id full_ledger_id(const std::string& text) {
    const auto bytes = from_hex(text);
    const auto id =
        bytes ? protocol::to_id(*bytes) : Result<protocol::Id>(std::unexpected(bytes.error()));
    if (!id || text.size() != 64) {
        throw UsageError{"a ledger id is its full 64 hex digits"};
    }
    return *id;
}

/// An archived ledger named by its id or a unique prefix of it.
protocol::Id archived_named(const std::filesystem::path& dir, std::string text) {
    std::ranges::transform(text, text.begin(),
                           [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    std::vector<protocol::Id> found;
    for (const protocol::Id& id : node::archived_ledgers(dir)) {
        if (hex_id(id).starts_with(text)) {
            found.push_back(id);
        }
    }
    if (text.empty() || found.empty()) {
        throw CommandError{"no ledger " + text + " is archived here (kanhe archive list)"};
    }
    if (found.size() > 1) {
        throw UsageError{"more than one archived ledger starts with " + text +
                         ": give more digits"};
    }
    return found.front();
}

Json time_or_null(const std::optional<protocol::Timestamp>& t) {
    return t ? Json(format_time(*t)) : Json(nullptr);
}

Json witness_json(const node::ArchiveWitness& w) {
    return {{"url", w.url},
            {"name", w.name},
            {"algorithm", crypto::name(w.key.algorithm)},
            {"post_quantum", node::post_quantum_algorithm(w.key.algorithm)},
            {"key", witness_key_hex(w.key)}};
}

Json config_json(const node::ArchiveConfig& c) {
    Json witnesses = Json::array();
    for (const auto& w : c.witnesses) {
        witnesses.push_back(witness_json(w));
    }
    return {{"witnesses", witnesses},
            {"authorities", c.authorities},
            {"sync_interval", c.sync_interval.count()},
            {"attest_interval", c.attest_interval.count()}};
}

node::ArchiveConfig load_config(const std::filesystem::path& dir) {
    return unwrap(node::load_archive_config(dir), "reading the archives' config");
}

node::ArchiveState load_state(const std::filesystem::path& dir, const protocol::Id& id) {
    return unwrap(node::load_archive_state(node::archive_path(dir, id)),
                  "reading the archive of " + short_id(id));
}

/// One archived ledger, as list and show give it.
Json archive_json(const std::filesystem::path& dir, const protocol::Id& id,
                  const node::ArchiveConfig& config) {
    const node::ArchiveState s = load_state(dir, id);
    const auto kept = node::load_kept(node::archive_path(dir, id));
    const bool attesters = !config.witnesses.empty() || !config.authorities.empty();
    return {{"ledger_id", id_json(id)},
            {"organization", s.organization},
            {"source", s.source},
            {"address", "/a/" + hex_id(id)},
            {"size", s.size},
            {"checkpoint_time", time_or_null(s.checkpoint_time)},
            {"created", format_time(s.created)},
            {"last_sync", time_or_null(s.last_sync)},
            {"last_error", s.last_error.empty() ? Json(nullptr) : Json(s.last_error)},
            {"unreachable_since", time_or_null(s.unreachable_since)},
            {"published", kept ? kept->size() : std::size_t{0}},
            {"attested_at", time_or_null(s.attested_at)},
            {"last_attest", time_or_null(s.last_attest)},
            {"next_attestation",
             attesters ? Json(format_time(node::next_attestation(s, config))) : Json(nullptr)},
            {"next_sync", format_time(node::next_sync(s, config))},
            {"attest_problems", s.attest_problems},
            {"published_problems", s.published_problems}};
}

Json sync_report_json(const protocol::Id& id, const node::ArchiveSyncReport& r) {
    Json out{{"ledger_id", id_json(id)}, {"synced", r.synced}};
    if (!r.synced) {
        out["error"] = std::string(r.error);
        out["unreachable"] = r.code == Errc::unavailable;
        out["verified"] = r.code != Errc::verification_failed;
        return out;
    }
    out["entries"] = r.replica.entries;
    out["checkpoints"] = r.replica.checkpoints;
    out["cosignatures"] = r.replica.cosignatures;
    out["timestamps"] = r.replica.timestamps;
    out["network_cosignatures"] = r.replica.network_cosignatures;
    out["size"] = r.replica.size;
    out["published"] = {{"listed", r.published.listed},       {"listing", r.published.listing},
                        {"fetched", r.published.fetched},     {"kept", r.published.kept},
                        {"unchanged", r.published.unchanged}, {"removed", r.published.removed},
                        {"problems", r.published.problems}};
    return out;
}

void print_sync(const protocol::Id& id, const node::ArchiveSyncReport& r) {
    if (!r.synced) {
        std::println("{}: {}{}", short_id(id),
                     r.code == Errc::unavailable           ? "its server cannot be reached: "
                     : r.code == Errc::verification_failed ? "NOT VERIFIED: "
                                                           : "",
                     r.error);
        return;
    }
    std::println("{}: synced {} entries, {} checkpoints, {} cosignatures, {} tokens; size {}; "
                 "published records: {} listed, {} kept anew, {} unchanged, {} taken down",
                 short_id(id), r.replica.entries, r.replica.checkpoints, r.replica.cosignatures,
                 r.replica.timestamps, r.replica.size, r.published.listing, r.published.kept,
                 r.published.unchanged, r.published.removed);
    for (const std::string& p : r.published.problems) {
        std::println("  {}", p);
    }
}

} // namespace

// ---------------------------------------------------------------------------
// The archive's operator
// ---------------------------------------------------------------------------

int cmd_archive_config(const Args& args) {
    const std::filesystem::path dir = archive_ledger(args);
    node::ArchiveConfig config = load_config(dir);
    bool changed = false;
    if (args.has("witness") && args.has("no-witnesses")) {
        throw UsageError{"--witness and --no-witnesses exclude each other"};
    }
    if (args.has("tsa") && args.has("no-tsa")) {
        throw UsageError{"--tsa and --no-tsa exclude each other"};
    }
    if (args.has("witness") || args.has("no-witnesses")) {
        config.witnesses.clear();
        for (const std::string& url : args.all("witness")) {
            if (!url.starts_with("https://") && !url.starts_with("http://")) {
                throw UsageError{"a witness is its server's URL: https://HOST[:PORT]"};
            }
            // Its key as it says it now: its cosignatures are checked with it.
            const client::WitnessInfo info = client::fetch_witness_info(url);
            config.witnesses.push_back({url, info.name, info.key});
        }
        changed = true;
    }
    if (args.has("tsa") || args.has("no-tsa")) {
        config.authorities = args.all("tsa");
        changed = true;
    }
    if (const auto every = args.get("sync-interval")) {
        config.sync_interval = parse_duration(*every, "--sync-interval");
        changed = true;
    }
    if (const auto every = args.get("attest-interval")) {
        config.attest_interval = parse_duration(*every, "--attest-interval");
        changed = true;
    }
    if (changed) {
        unwrap(node::save_archive_config(dir, config), "saving the archives' config");
    }
    const bool classical =
        !config.witnesses.empty() &&
        std::ranges::none_of(config.witnesses, [](const node::ArchiveWitness& w) {
            return node::post_quantum_algorithm(w.key.algorithm);
        });
    if (args.json()) {
        Json out = config_json(config);
        out["changed"] = changed;
        out["classical_witnesses_only"] = classical;
        print_json(out);
        return exit_ok;
    }
    std::println("{}the archives here:", changed ? "saved; " : "");
    if (config.witnesses.empty()) {
        std::println("  witnesses:          none");
    }
    for (const auto& w : config.witnesses) {
        std::println("  witness:            {} ({}, {})", w.url,
                     w.name.empty() ? std::string("unnamed") : w.name,
                     crypto::name(w.key.algorithm));
    }
    if (config.authorities.empty()) {
        std::println("  authorities:        none");
    }
    for (const auto& a : config.authorities) {
        std::println("  authority:          {}", a);
    }
    std::println("  sync interval:      {}", duration_text(config.sync_interval));
    std::println("  attestation every:  {}", duration_text(config.attest_interval));
    if (classical) {
        std::println("warning: every witness here has a classical key; add one whose key is "
                     "ML-DSA, so that re-attestations outlast the classical algorithms");
    }
    return exit_ok;
}

int cmd_archive_add(const Args& args) {
    const std::filesystem::path dir = archive_ledger(args);
    const protocol::Id member = full_ledger_id(args.positional().front());
    {
        // Only the id: the session is closed before anything is fetched.
        Session session(dir);
        if (session.state().ledger_id() == member) {
            throw UsageError{"a ledger is no archive of its own: name another ledger"};
        }
    }
    const std::string url = args.need("source");
    if (!node::Url::parse(url)) {
        throw UsageError{"--source is the member's server: http(s)://HOST[:PORT]"};
    }
    node::ArchiveSource source;
    source.url = url;
    const Bytes token = read_file(args.need("token-file"));
    source.token.assign(token.begin(), token.end());
    while (!source.token.empty() && (source.token.back() == '\n' || source.token.back() == '\r' ||
                                     source.token.back() == ' ')) {
        source.token.pop_back();
    }
    if (source.token.empty()) {
        throw UsageError{"--token-file holds no token"};
    }
    if (const auto ca = args.get("ca-file")) {
        source.ca_pem = read_file(*ca);
    }
    ledger::SystemClock clock;
    auto created = node::ArchivedLedger::create(dir, member, source, clock, shared_provider());
    if (!created) {
        const Error& e = created.error();
        if (args.json()) {
            print_json({{"archived", false},
                        {"error", std::string(e.detail)},
                        {"verified", e.code != Errc::verification_failed}});
        } else {
            std::println(stderr, "error: archiving ledger {} from {}: {}{} ({})", short_id(member),
                         url, e.code == Errc::verification_failed ? "NOT VERIFIED: " : "", e.detail,
                         to_string(e.code));
        }
        return e.code == Errc::verification_failed ? exit_not_verified : exit_failure;
    }
    const node::ArchiveSyncReport& report = created->second;
    const node::ArchiveConfig config = load_config(dir);
    if (args.json()) {
        Json out = archive_json(dir, member, config);
        out["archived"] = true;
        out["sync"] = sync_report_json(member, report);
        print_json(out);
        return exit_ok;
    }
    const node::ArchiveState s = load_state(dir, member);
    std::println("archived ledger {} ({}) from {}: size {}, {} published records kept",
                 hex_id(member), s.organization, s.source, s.size, report.published.kept);
    for (const std::string& p : report.published.problems) {
        std::println("  {}", p);
    }
    std::println("served at /a/{} by kanhe serve; synced every {}", hex_id(member),
                 duration_text(config.sync_interval));
    return exit_ok;
}

int cmd_archive_list(const Args& args) {
    const std::filesystem::path dir = archive_ledger(args);
    const node::ArchiveConfig config = load_config(dir);
    const auto ids = node::archived_ledgers(dir);
    if (args.json()) {
        Json out = Json::array();
        for (const protocol::Id& id : ids) {
            out.push_back(archive_json(dir, id, config));
        }
        print_json(out);
        return exit_ok;
    }
    if (ids.empty()) {
        std::println("no ledger is archived here (kanhe archive add LEDGER_ID --source URL "
                     "--token-file FILE)");
    }
    for (const protocol::Id& id : ids) {
        const Json a = archive_json(dir, id, config);
        std::println("{}  {:<24} size {:<8} synced {}{}  {} published", short_id(id),
                     a["organization"].get<std::string>(), a["size"].get<std::uint64_t>(),
                     a["last_sync"].is_null() ? std::string("never")
                                              : a["last_sync"].get<std::string>(),
                     a["unreachable_since"].is_null()
                         ? std::string()
                         : " (unreachable since " + a["unreachable_since"].get<std::string>() + ")",
                     a["published"].get<std::size_t>());
    }
    return exit_ok;
}

int cmd_archive_show(const Args& args) {
    const std::filesystem::path dir = archive_ledger(args);
    const protocol::Id id = archived_named(dir, args.positional().front());
    const node::ArchiveConfig config = load_config(dir);
    Json a = archive_json(dir, id, config);
    const auto kept = unwrap(node::load_kept(node::archive_path(dir, id)), "reading kept.json");
    Json bundles = Json::array();
    for (const node::KeptBundle& k : kept) {
        bundles.push_back({{"token", k.token},
                           {"record", id_json(k.record)},
                           {"size", k.size},
                           {"checkpoint_time", format_time(k.time)},
                           {"address", "/a/" + hex_id(id) + "/c/" + k.token}});
    }
    a["bundles"] = bundles;
    if (args.json()) {
        print_json(a);
        return exit_ok;
    }
    std::println("ledger:            {}", hex_id(id));
    std::println("organization:      {}", a["organization"].get<std::string>());
    std::println("source:            {}", a["source"].get<std::string>());
    std::println("served at:         /a/{}", hex_id(id));
    std::println("size:              {} (checkpoint of {})", a["size"].get<std::uint64_t>(),
                 a["checkpoint_time"].is_null() ? std::string("-")
                                                : a["checkpoint_time"].get<std::string>());
    std::println("last sync:         {}", a["last_sync"].is_null()
                                              ? std::string("never")
                                              : a["last_sync"].get<std::string>());
    if (!a["last_error"].is_null()) {
        std::println("last error:        {}", a["last_error"].get<std::string>());
    }
    if (!a["unreachable_since"].is_null()) {
        std::println("unreachable since: {}", a["unreachable_since"].get<std::string>());
    }
    std::println("attested:          {}", a["attested_at"].is_null()
                                              ? std::string("never")
                                              : a["attested_at"].get<std::string>());
    if (!a["next_attestation"].is_null()) {
        std::println("next attestation:  {}", a["next_attestation"].get<std::string>());
    }
    for (const Json& p : a["attest_problems"]) {
        std::println("  {}", p.get<std::string>());
    }
    std::println("published records: {}", kept.size());
    for (const node::KeptBundle& k : kept) {
        std::println("  {}  {}  size {}  {}", k.token, short_id(k.record), k.size,
                     format_time(k.time));
    }
    for (const Json& p : a["published_problems"]) {
        std::println("  {}", p.get<std::string>());
    }
    return exit_ok;
}

int cmd_archive_sync(const Args& args) {
    const std::filesystem::path dir = archive_ledger(args);
    std::vector<protocol::Id> ids;
    if (args.positional().empty()) {
        ids = node::archived_ledgers(dir);
    } else {
        ids.push_back(archived_named(dir, args.positional().front()));
    }
    if (ids.empty()) {
        throw CommandError{"no ledger is archived here (kanhe archive add)"};
    }
    ledger::SystemClock clock;
    Json out = Json::array();
    int code = exit_ok;
    for (const protocol::Id& id : ids) {
        auto archive = unwrap(node::ArchivedLedger::open(dir, id, clock, shared_provider()),
                              "opening the archive of " + short_id(id));
        const auto report = unwrap(archive->sync(), "syncing the archive of " + short_id(id));
        if (!report.synced) {
            code = std::max(code, report.code == Errc::verification_failed ? exit_not_verified
                                                                           : exit_failure);
        }
        if (args.json()) {
            out.push_back(sync_report_json(id, report));
        } else {
            print_sync(id, report);
        }
    }
    if (args.json()) {
        print_json(out);
    }
    return code;
}

int cmd_archive_attest(const Args& args) {
    const std::filesystem::path dir = archive_ledger(args);
    const node::ArchiveConfig config = load_config(dir);
    if (config.witnesses.empty() && config.authorities.empty()) {
        throw CommandError{"no witness or time-stamp authority to attest with: kanhe archive "
                           "config --witness URL --tsa URL"};
    }
    std::vector<protocol::Id> ids;
    if (args.positional().empty()) {
        ids = node::archived_ledgers(dir);
    } else {
        ids.push_back(archived_named(dir, args.positional().front()));
    }
    if (ids.empty()) {
        throw CommandError{"no ledger is archived here (kanhe archive add)"};
    }
    ledger::SystemClock clock;
    Json out = Json::array();
    int code = exit_ok;
    for (const protocol::Id& id : ids) {
        auto archive = unwrap(node::ArchivedLedger::open(dir, id, clock, shared_provider()),
                              "opening the archive of " + short_id(id));
        const auto report = unwrap(archive->attest(config, args.has("force")),
                                   "re-attesting the archive of " + short_id(id));
        const bool any = std::ranges::any_of(report.outcomes, [](const node::AttesterOutcome& o) {
            return o.attested.has_value() || o.already;
        });
        if (report.due && !any) {
            code = exit_failure;
        }
        if (args.json()) {
            Json outcomes = Json::array();
            for (const node::AttesterOutcome& o : report.outcomes) {
                outcomes.push_back(
                    {{"kind", o.kind},
                     {"name", o.name},
                     {"url", o.url},
                     {"attested", o.attested ? Json(*o.attested) : Json(nullptr)},
                     {"registered", o.registered},
                     {"already", o.already},
                     {"problem", o.problem.empty() ? Json(nullptr) : Json(o.problem)}});
            }
            out.push_back({{"ledger_id", id_json(id)},
                           {"due", report.due},
                           {"size", report.size},
                           {"attested_at", time_or_null(report.attested_at)},
                           {"next_attestation", time_or_null(report.next)},
                           {"outcomes", outcomes}});
            continue;
        }
        if (!report.due) {
            std::println("{}: attested {}; the next round is due {} (--force asks now)",
                         short_id(id),
                         report.attested_at ? format_time(*report.attested_at) : "never",
                         report.next ? format_time(*report.next) : "-");
            continue;
        }
        std::println("{}: the checkpoint at size {}:", short_id(id), report.size);
        for (const node::AttesterOutcome& o : report.outcomes) {
            const std::string who = o.kind + " " + (o.name.empty() ? o.url : o.name);
            if (o.attested) {
                std::println("  {} attested it{}", who,
                             o.registered ? " (the ledger is registered with it now)" : "");
            } else if (o.already) {
                std::println("  {} has cosigned it already", who);
            } else {
                std::println("  {}: {}", who, o.problem);
            }
        }
    }
    if (args.json()) {
        print_json(out);
    }
    return code;
}

int cmd_archive_remove(const Args& args) {
    const std::filesystem::path dir = archive_ledger(args);
    const protocol::Id id = archived_named(dir, args.positional().front());
    if (!args.has("yes")) {
        throw UsageError{"removing the archive of " + hex_id(id) +
                         " deletes this server's copy of that ledger and the bundles kept for it; "
                         "its links' fallbacks here stop answering: pass --yes"};
    }
    unwrap(node::remove_archive(dir, id), "removing the archive");
    if (args.json()) {
        print_json({{"removed", id_json(id)}});
    } else {
        std::println("removed the archive of ledger {}", hex_id(id));
    }
    return exit_ok;
}

// ---------------------------------------------------------------------------
// The member: the archives that keep this ledger
// ---------------------------------------------------------------------------

namespace {

/// The archives are listed beside the ledger: in client mode, the server's.
std::filesystem::path own_ledger(const Session& session) {
    if (!session.server_url().empty()) {
        throw UsageError{"the archives are listed beside the ledger: run this where the ledger "
                         "is"};
    }
    return session.directory();
}

/// An archive's latest checkpoint of this ledger: the size, the time, and
/// whether this ledger made it; or why not.
struct ArchiveCheck {
    std::optional<protocol::SignedCheckpoint> checkpoint;
    bool ours = false;
    std::string problem;
};

ArchiveCheck check_archive(Session& session, const std::string& url,
                           const std::optional<std::string>& ca_file) {
    ArchiveCheck out;
    const node::Client archive = client::client_for(url, std::nullopt, ca_file);
    const auto answer = archive.request("GET", "/v1/checkpoint");
    if (!answer) {
        out.problem = std::format("cannot reach it: {}", answer.error().detail);
        return out;
    }
    if (answer->status == 404) {
        out.problem = "it does not keep this ledger (yet): its operator runs kanhe archive add " +
                      hex_id(session.state().ledger_id());
        return out;
    }
    if (answer->status != 200) {
        out.problem = std::format("it answered status {}: {}", answer->status,
                                  node::error_message_of(answer->body).value_or("no checkpoint"));
        return out;
    }
    auto checkpoint = protocol::parse_checkpoint(answer->body);
    if (!checkpoint || checkpoint->checkpoint.ledger_id != session.state().ledger_id()) {
        out.problem = "it answers a checkpoint of another ledger";
        return out;
    }
    // One this ledger made and keeps, byte for byte.
    const auto mine = session.ledger().checkpoints_of_size(checkpoint->checkpoint.tree_size);
    out.ours = mine && std::ranges::any_of(*mine, [&](const protocol::SignedCheckpoint& c) {
                   return c.encoded == checkpoint->encoded;
               });
    if (!out.ours) {
        out.problem = "it answers a checkpoint this ledger never made";
    }
    out.checkpoint = std::move(*checkpoint);
    return out;
}

std::string without_slash(std::string url) {
    while (url.ends_with('/')) {
        url.pop_back();
    }
    return url;
}

} // namespace

int cmd_trust_archive_add(const Args& args) {
    Session session(args);
    const auto dir = own_ledger(session);
    const protocol::Id own = session.state().ledger_id();
    const std::string url = without_slash(args.positional().front());
    if (!node::valid_archive_link(url, own)) {
        throw UsageError{"an archive's address for this ledger is https://HOST/a/" + hex_id(own) +
                         " (no query or fragment)"};
    }
    auto archives = unwrap(node::load_archive_links(dir), "reading the archives");
    if (std::ranges::any_of(archives, [&](const node::ArchiveLink& a) { return a.url == url; })) {
        throw CommandError{"that archive is listed already"};
    }
    if (archives.size() >= node::max_archive_links) {
        throw CommandError{"a ledger lists at most 4 archives: remove one first"};
    }
    const ArchiveCheck check = check_archive(session, url, args.get("ca-file"));
    if (!check.ours) {
        throw CommandError{"not added: " + check.problem};
    }
    const protocol::Timestamp now = ledger::SystemClock().now();
    archives.push_back({url, now});
    unwrap(node::save_archive_links(dir, own, archives), "saving the archives");
    const protocol::Checkpoint& c = check.checkpoint->checkpoint;
    if (args.json()) {
        print_json({{"url", url},
                    {"added", format_time(now)},
                    {"size", c.tree_size},
                    {"checkpoint_time", format_time(c.timestamp)}});
    } else {
        std::println("added archive {}: it keeps this ledger up to size {} ({}); links to "
                     "published records now name it as a fallback",
                     url, c.tree_size, format_time(c.timestamp));
    }
    return exit_ok;
}

int cmd_trust_archive_list(const Args& args) {
    Session session(args);
    const auto dir = own_ledger(session);
    const auto archives = unwrap(node::load_archive_links(dir), "reading the archives");
    if (args.json()) {
        Json out = Json::array();
        for (const node::ArchiveLink& a : archives) {
            out.push_back({{"url", a.url}, {"added", format_time(a.added)}});
        }
        print_json(out);
        return exit_ok;
    }
    if (archives.empty()) {
        std::println("no archive keeps this ledger (kanhe trust archive add URL)");
    }
    for (const node::ArchiveLink& a : archives) {
        std::println("{}  added {}", a.url, format_time(a.added));
    }
    return exit_ok;
}

int cmd_trust_archive_remove(const Args& args) {
    Session session(args);
    const auto dir = own_ledger(session);
    auto archives = unwrap(node::load_archive_links(dir), "reading the archives");
    const std::string url = without_slash(args.positional().front());
    if (std::erase_if(archives, [&](const node::ArchiveLink& a) { return a.url == url; }) == 0) {
        throw CommandError{"no archive " + url + " is listed (kanhe trust archive list)"};
    }
    unwrap(node::save_archive_links(dir, session.state().ledger_id(), archives),
           "saving the archives");
    if (args.json()) {
        print_json({{"removed", url}});
    } else {
        std::println("removed archive {}: links no longer name it", url);
    }
    return exit_ok;
}

int cmd_trust_archive_check(const Args& args) {
    Session session(args);
    const auto dir = own_ledger(session);
    const auto archives = unwrap(node::load_archive_links(dir), "reading the archives");
    if (archives.empty()) {
        throw CommandError{"no archive keeps this ledger (kanhe trust archive add URL)"};
    }
    const auto latest = session.ledger().latest_checkpoint();
    const std::uint64_t own_size = latest ? latest->checkpoint.tree_size : 0;
    const protocol::Timestamp own_time = latest ? latest->checkpoint.timestamp : 0;
    Json out = Json::array();
    bool all = true;
    for (const node::ArchiveLink& a : archives) {
        const ArchiveCheck check = check_archive(session, a.url, args.get("ca-file"));
        all = all && check.ours;
        if (args.json()) {
            Json item{{"url", a.url}, {"ok", check.ours}};
            if (check.checkpoint) {
                const protocol::Checkpoint& c = check.checkpoint->checkpoint;
                item["size"] = c.tree_size;
                item["checkpoint_time"] = format_time(c.timestamp);
                item["behind_entries"] = own_size > c.tree_size ? own_size - c.tree_size : 0;
                item["behind_seconds"] =
                    own_time > c.timestamp ? (own_time - c.timestamp) / 1000 : 0;
            }
            item["problem"] = check.problem.empty() ? Json(nullptr) : Json(check.problem);
            out.push_back(item);
            continue;
        }
        if (!check.checkpoint) {
            std::println("{}: {}", a.url, check.problem);
            continue;
        }
        const protocol::Checkpoint& c = check.checkpoint->checkpoint;
        std::println("{}: size {} of {} ({}){}", a.url, c.tree_size, own_size,
                     format_time(c.timestamp), check.ours ? std::string() : ": " + check.problem);
    }
    if (args.json()) {
        print_json(out);
    }
    return all ? exit_ok : exit_failure;
}

} // namespace kanhe::cli
