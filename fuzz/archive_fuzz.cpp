// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// What an archive reads: a member's list of its published records (GET
// /v1/published, from the member's server), and the archive's own files
// (each archived ledger's archive.json and kept.json, the archives' config),
// and the paths a backup may restore beside them. Whatever arrives, the
// readers must not crash, and what they accept stays within its bounds.

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <set>
#include <string>
#include <string_view>

#include <kanhe/node/archive.hpp>
#include <kanhe/node/published.hpp>

namespace node = kanhe::node;

namespace {

void require(bool condition) {
    if (!condition) {
        std::abort();
    }
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    const kanhe::ByteView input{data, size};
    if (const auto list = node::parse_published_list(input)) {
        require(list->size() <= node::max_archived_published);
        std::set<std::string> tokens;
        for (const node::PublishedListing& l : *list) {
            require(node::valid_published_token(l.token));
            require(tokens.insert(l.token).second);
        }
    }
    if (const auto state = node::parse_archive_state(input)) {
        require(state->own.size() <= node::max_own_attestations);
        require(state->attest_problems.size() <= 64);
        require(state->published_problems.size() <= 64);
    }
    if (const auto config = node::parse_archive_config(input)) {
        require(config->witnesses.size() <= node::max_archive_attesters);
        require(config->authorities.size() <= node::max_archive_attesters);
        require(config->sync_interval >= node::min_sync_interval &&
                config->sync_interval <= node::max_sync_interval);
        require(config->attest_interval >= node::min_attest_interval &&
                config->attest_interval <= node::max_attest_interval);
    }
    if (const auto kept = node::parse_kept(input)) {
        require(kept->size() <= node::max_archived_published);
        for (const node::KeptBundle& k : *kept) {
            require(node::valid_published_token(k.token));
        }
    }
    const std::string_view path(reinterpret_cast<const char*>(data), size);
    if (node::archive_backup_path_allowed(path)) {
        // Nothing that climbs out of the archive's folder.
        require(path.starts_with("archive/") && path.find("..") == std::string_view::npos &&
                path.find('\0') == std::string_view::npos);
    }
    return 0;
}
