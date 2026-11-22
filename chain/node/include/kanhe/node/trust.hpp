// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <cstdint>
#include <filesystem>
#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <kanhe/core/bytes.hpp>
#include <kanhe/core/crypto.hpp>
#include <kanhe/core/error.hpp>
#include <kanhe/core/protocol/common.hpp>
#include <kanhe/core/protocol/evidence.hpp>
#include <kanhe/core/protocol/id_map.hpp>
#include <kanhe/ledger/ledger.hpp>
#include <kanhe/node/client.hpp>

/// Trust nodes (spec v0.16, section 16), on both sides.
///
/// A trust node serves `GET /m/LEDGER`: the evidence of its newest
/// membership naming that ledger. A member lists the trust nodes it belongs
/// to, fetches its proof from each, and adds the proofs it keeps to the
/// evidence it serves and exports (bundle key 9):
///
///   <ledger>/trust/nodes.json            the trust nodes this ledger belongs to
///   <ledger>/trust/proofs/<ledger>.cbor  the proof last fetched from each
namespace kanhe::node {

/// A trust node this ledger belongs to: a local name for it, its ledger, and
/// where its server is.
struct TrustNodeEntry {
    std::string name;
    protocol::Id ledger_id;
    std::string url;
    protocol::Timestamp added = 0;

    friend bool operator==(const TrustNodeEntry&, const TrustNodeEntry&) = default;
};

/// None if the file does not exist.
[[nodiscard]] Result<std::vector<TrustNodeEntry>>
load_trust_nodes(const std::filesystem::path& ledger_directory);
/// At most 16 (a bundle carries at most 16 proofs), names and ledgers each
/// unique.
[[nodiscard]] Status save_trust_nodes(const std::filesystem::path& ledger_directory,
                                      const std::vector<TrustNodeEntry>& nodes);

[[nodiscard]] std::filesystem::path
membership_proof_path(const std::filesystem::path& ledger_directory, const protocol::Id& node);

/// A proof as a member takes it from `node`: a complete bundle of that
/// ledger about a membership that names `member`, with the report.
[[nodiscard]] Result<protocol::EvidenceReport>
check_membership_proof(const crypto::Provider& provider, ByteView proof, const protocol::Id& node,
                       const protocol::Id& member);

/// The proofs kept for the trust nodes listed, in the list's order, each
/// checked as `member`'s evidence will check it (a node without one, or
/// with one that does not check, is left out: it would fail every bundle).
[[nodiscard]] std::vector<Bytes>
kept_membership_proofs(const crypto::Provider& provider,
                       const std::filesystem::path& ledger_directory, const protocol::Id& member);

/// Fetches this ledger's (`member`'s) proof from `node`'s server
/// (`GET /m/MEMBER`), checks it, and keeps it in place of the one before,
/// unless it is older than that one (Errc::verification_failed: the node or
/// a cache in between went back). Errc::not_found if the trust node names
/// this ledger in no membership.
[[nodiscard]] Result<protocol::EvidenceReport>
fetch_membership_proof(const crypto::Provider& provider,
                       const std::filesystem::path& ledger_directory, const TrustNodeEntry& node,
                       const protocol::Id& member, const ClientOptions& client = {});

/// Adds the kept proofs to `bundle`, evidence of a record of this ledger's
/// (`member`) whose type is `record_type` (empty for an instance), unless it
/// is a membership: a proof carries none.
void add_membership_proofs(const crypto::Provider& provider,
                           const std::filesystem::path& ledger_directory,
                           const protocol::Id& member, std::string_view record_type,
                           protocol::EvidenceBundle& bundle);

/// The archives that keep this ledger (spec section 16, "Archives"): each
/// an archive's address for it, `https://HOST/a/LEDGER` (no trailing slash),
/// where it answers this ledger's published records (`/c/TOKEN`) and
/// renewals once this ledger's own server cannot. Links to published records
/// name them as fallbacks, so a printed certificate outlives its issuer.
///
///   <ledger>/trust/archives.json   {"version": 1, "archives": [{"url", "added"}]}
struct ArchiveLink {
    std::string url;
    protocol::Timestamp added = 0;
    friend bool operator==(const ArchiveLink&, const ArchiveLink&) = default;
};

/// At most this many archives a ledger lists, and a link names.
inline constexpr std::size_t max_archive_links = 4;

/// Whether `url` is an archive's address for `ledger`: http or https, no
/// query or fragment, ending in /a/ and the ledger id in 64 lower-case hex
/// digits.
[[nodiscard]] bool valid_archive_link(std::string_view url, const protocol::Id& ledger);
/// None if the file does not exist; Errc::malformed if it is damaged.
[[nodiscard]] Result<std::vector<ArchiveLink>>
load_archive_links(const std::filesystem::path& ledger_directory);
/// At most 4, each valid for `ledger` and listed once.
[[nodiscard]] Status save_archive_links(const std::filesystem::path& ledger_directory,
                                        const protocol::Id& ledger,
                                        const std::vector<ArchiveLink>& archives);
/// The fallback addresses of the record published under `token`, one per
/// archive in the list's order: URL/c/TOKEN. A verifier's link carries each
/// as `&a=` (percent-encoded) after its `&b=`.
[[nodiscard]] std::vector<std::string> archive_fallbacks(const std::vector<ArchiveLink>& archives,
                                                         std::string_view token);

/// Which ledger each membership on a trust node's ledger names, read from
/// its registration once (a membership's metadata never changes).
class MembershipIndex {
public:
    /// The membership registered last that names `member`, if any. The
    /// state's records are looked through only when it changed since.
    [[nodiscard]] std::optional<protocol::Id> newest(const crypto::Provider& provider,
                                                     const ledger::Ledger& ledger,
                                                     const protocol::Id& member);

private:
    std::mutex mutex_;
    /// The state's statement count when its records were last looked
    /// through.
    std::uint64_t scanned_ = 0;
    /// Membership record -> (its registration's log index, its member, if
    /// its metadata reads as a membership).
    std::map<protocol::IdKey, std::pair<std::uint64_t, std::optional<protocol::Id>>> known_;
};

} // namespace kanhe::node
