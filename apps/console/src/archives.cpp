// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// The archives that keep this ledger (spec section 16, "Archives"): trust
// nodes that keep a read-only copy of it and the evidence of its published
// records, and answer them once this ledger's own server cannot. The list
// is the ledger's trust/archives.json (node/trust.hpp), the same that
// `kanhe trust archive` changes; certificates' links name each archive
// after the ledger's own address, so a certificate printed after an archive
// was added still verifies if this ledger's server closes. An archive is
// added only once it answers a checkpoint this ledger made.

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <future>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

#include <nlohmann/json.hpp>

#include <kanhe/console/certificates.hpp>
#include <kanhe/console/console.hpp>
#include <kanhe/core/bytes.hpp>
#include <kanhe/core/protocol/log.hpp>
#include <kanhe/ledger/storage.hpp>
#include <kanhe/node/client.hpp>
#include <kanhe/node/trust.hpp>

#include "responses.hpp"

namespace kanhe::console {

namespace {

/// How long an archive has to answer.
constexpr auto archive_patience = std::chrono::seconds(10);
/// A checkpoint is a few kilobytes at most (an ML-DSA signature included).
constexpr std::size_t max_checkpoint_answer = 64 * 1024;

/// What an archive answered at its /v1/checkpoint: the bytes, or why none
/// came.
struct Fetched {
    std::optional<Bytes> body;
    std::string problem;
};

Fetched fetch_checkpoint(const std::string& url) {
    const auto base = node::Url::parse(url);
    if (!base) {
        return {std::nullopt, std::string(base.error().detail)};
    }
    node::ClientOptions options;
    options.timeout = archive_patience;
    options.max_body = max_checkpoint_answer;
    const node::Client client(*base, options);
    auto answer = client.request("GET", "/v1/checkpoint");
    if (!answer) {
        return {std::nullopt, std::string(answer.error().detail)};
    }
    if (answer->status != 200) {
        return {std::nullopt, node::error_message_of(answer->body)
                                  .value_or("status " + std::to_string(answer->status))};
    }
    return {std::move(answer->body), {}};
}

/// What an archive's answer is to this ledger: its checkpoint, if this
/// ledger made it (one it keeps, byte for byte: an archive copies them and
/// cannot make any), else why not, as a code and in words (and, when it did
/// not answer, what went wrong).
struct Checked {
    std::optional<protocol::Checkpoint> checkpoint;
    std::string code;
    std::string message;
    std::string detail;
};

Checked check_answer(const ledger::Ledger& served, const Fetched& fetched) {
    if (!fetched.body) {
        return {std::nullopt, "unreachable", "the archive did not answer: " + fetched.problem,
                fetched.problem};
    }
    const auto parsed = protocol::parse_checkpoint(*fetched.body);
    if (!parsed) {
        return {std::nullopt, "not_checkpoint", "the archive's answer is not a checkpoint", {}};
    }
    if (parsed->checkpoint.ledger_id != served.id()) {
        return {std::nullopt, "other_ledger", "the archive keeps another ledger", {}};
    }
    const auto same = served.checkpoints_of_size(parsed->checkpoint.tree_size);
    if (!same || std::ranges::none_of(*same, [&](const protocol::SignedCheckpoint& c) {
            return std::ranges::equal(c.encoded, *fetched.body);
        })) {
        return {std::nullopt,
                "not_ours",
                "the archive answered a checkpoint that this ledger never made",
                {}};
    }
    return {parsed->checkpoint, {}, {}, {}};
}

/// Why the list cannot be read, in words.
std::string list_problem(const Error& e) {
    return e.code == Errc::malformed
               ? "the ledger's list of archives (trust/archives.json) is damaged"
               : "the ledger's list of archives (trust/archives.json) cannot be read";
}

/// The address an owner typed, as an archive's address for `ledger`: without
/// a trailing slash, and the archive's server alone (https://HOST) completed
/// with /a/LEDGER.
std::string archive_address(std::string url, const protocol::Id& ledger) {
    while (url.ends_with('/')) {
        url.pop_back();
    }
    const std::size_t scheme = url.find("://");
    if (scheme != std::string::npos && url.find('/', scheme + 3) == std::string::npos) {
        url += "/a/" + to_hex(ledger.bytes());
    }
    return url;
}

} // namespace

std::vector<std::string> Console::archive_links_of(std::string_view token) const {
    const auto archives = node::load_archive_links(services_.directory.parent_path());
    return archives ? node::archive_fallbacks(*archives, token) : std::vector<std::string>{};
}

bool Console::archive_links_fit(const protocol::Id& ledger,
                                const std::vector<node::ArchiveLink>& archives) const {
    // The longest link a certificate of this console's gets: a token is 22
    // characters, and the page's language at most 7.
    const std::string token(22, 'A');
    const auto fallbacks = node::archive_fallbacks(archives, token);
    const std::string link = verifier_link(certificate_verifier, ledger, ledger,
                                           api_url() + "/c/" + token, "zh-Hant", fallbacks);
    std::size_t named = 0;
    for (std::size_t at = link.find("&a="); at != std::string::npos;
         at = link.find("&a=", at + 1)) {
        ++named;
    }
    return named == fallbacks.size();
}

http::Response Console::archives_route(const http::Request& request) const {
    auto who = authenticate(request);
    if (auto* refused = std::get_if<http::Response>(&who)) {
        return std::move(*refused);
    }
    const Signed& signer = std::get<Signed>(who);
    if (signer.role != Role::owner && signer.role != Role::admin) {
        return error(403, "forbidden", "only an owner or an admin sees and changes the archives");
    }
    const ledger::Ledger* served = ledger();
    if (served == nullptr) {
        return error(503, "unavailable", "the console has no ledger yet");
    }
    const std::filesystem::path dir = services_.directory.parent_path();
    const protocol::Id ledger_id = served->id();
    if (request.method == "GET") {
        const auto archives = node::load_archive_links(dir);
        nlohmann::json out{{"archives", nlohmann::json::array()},
                           {"ledger", to_hex(ledger_id.bytes())},
                           {"max", node::max_archive_links},
                           {"problem", nullptr},
                           {"may_change", true}};
        if (!archives) {
            out["problem"] = list_problem(archives.error());
            return json(200, out);
        }
        // Asked at once, each within its own time; checked here, one by one.
        std::vector<std::future<Fetched>> asked;
        for (const node::ArchiveLink& a : *archives) {
            asked.push_back(std::async(std::launch::async, fetch_checkpoint, a.url));
        }
        for (std::size_t i = 0; i < archives->size(); ++i) {
            const node::ArchiveLink& a = (*archives)[i];
            const Checked checked = check_answer(*served, asked[i].get());
            out["archives"].push_back(
                {{"url", a.url},
                 {"added", a.added},
                 {"size", checked.checkpoint ? nlohmann::json(checked.checkpoint->tree_size)
                                             : nlohmann::json()},
                 {"time", checked.checkpoint ? nlohmann::json(checked.checkpoint->timestamp)
                                             : nlohmann::json()},
                 {"problem",
                  checked.code.empty() ? nlohmann::json() : nlohmann::json(checked.code)},
                 {"message",
                  checked.message.empty() ? nlohmann::json() : nlohmann::json(checked.message)},
                 {"detail",
                  checked.detail.empty() ? nlohmann::json() : nlohmann::json(checked.detail)}});
        }
        return json(200, out);
    }
    if (request.method != "POST") {
        http::Response refused = error(405, "unsupported", "method not allowed");
        refused.headers.emplace_back("Allow", "GET, POST");
        return refused;
    }
    if (services_.keys == nullptr || !services_.keys->unlocked()) {
        return error(423, "locked", "the console is locked: unlock it first");
    }
    const auto body =
        nlohmann::json::parse(request.body.begin(), request.body.end(), nullptr, false);
    if (!body.is_object() || (!body.contains("url") && !body.contains("remove")) ||
        !body.value(body.contains("url") ? "url" : "remove", nlohmann::json()).is_string()) {
        return error(400, "invalid_argument", "give an archive's address as url, or as remove");
    }
    // The list is read and written under the console's lock: two changes at
    // once never lose one.
    const auto change = [&](auto&& f) -> http::Response {
        const auto lock = ledger::DirectoryLock::acquire(services_.directory, 2000);
        if (!lock) {
            return error(503, "unavailable", "the archives are being changed; try again");
        }
        auto archives = node::load_archive_links(dir);
        if (!archives) {
            return error(500, "internal", list_problem(archives.error()));
        }
        return f(*archives);
    };
    if (body.contains("remove")) {
        const std::string url = body["remove"].get<std::string>();
        return change([&](std::vector<node::ArchiveLink>& archives) {
            if (std::erase_if(archives, [&](const node::ArchiveLink& a) { return a.url == url; }) ==
                0) {
                return error(404, "not_found", "this ledger lists no archive at that address");
            }
            if (!node::save_archive_links(dir, ledger_id, archives)) {
                return error(500, "internal", "the list of archives could not be written");
            }
            log_activity(signer.user, "archives.remove", {{"url", url}});
            return json(200, {{"removed", url}});
        });
    }
    const std::string url = archive_address(body["url"].get<std::string>(), ledger_id);
    if (!node::valid_archive_link(url, ledger_id)) {
        return error(400, "not_address",
                     "an archive's address for this ledger is http(s)://HOST/a/" +
                         to_hex(ledger_id.bytes()) + ", with no query or fragment");
    }
    // What it would be, checked before the archive is asked and again after.
    const auto refused =
        [&](const std::vector<node::ArchiveLink>& archives) -> std::optional<http::Response> {
        if (std::ranges::contains(archives, url, &node::ArchiveLink::url)) {
            return error(409, "listed", "this ledger lists that archive already");
        }
        if (archives.size() >= node::max_archive_links) {
            return error(409, "full", "a ledger lists at most 4 archives");
        }
        std::vector<node::ArchiveLink> with = archives;
        with.push_back({url, 0});
        if (!archive_links_fit(ledger_id, with)) {
            return error(409, "too_long",
                         "with that address, a certificate's link would be too long for its QR "
                         "code to stay readable: use an archive with a shorter address");
        }
        return std::nullopt;
    };
    {
        const auto archives = node::load_archive_links(dir);
        if (!archives) {
            return error(500, "internal", list_problem(archives.error()));
        }
        if (auto r = refused(*archives)) {
            return std::move(*r);
        }
    }
    const Checked checked = check_answer(*served, fetch_checkpoint(url));
    if (!checked.checkpoint) {
        return json(
            checked.code == "unreachable" ? 502 : 422,
            {{"error",
              {{"code", checked.code}, {"message", checked.message}, {"detail", checked.detail}}}});
    }
    return change([&](std::vector<node::ArchiveLink>& archives) {
        if (auto r = refused(archives)) {
            return std::move(*r);
        }
        archives.push_back({url, services_.clock->now()});
        if (!node::save_archive_links(dir, ledger_id, archives)) {
            return error(500, "internal", "the list of archives could not be written");
        }
        log_activity(signer.user, "archives.add", {{"url", url}});
        return json(200, {{"added", url},
                          {"size", checked.checkpoint->tree_size},
                          {"time", checked.checkpoint->timestamp}});
    });
}

} // namespace kanhe::console
