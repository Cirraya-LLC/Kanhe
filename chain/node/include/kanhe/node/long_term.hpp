// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <cstdint>
#include <map>
#include <mutex>
#include <optional>
#include <string>

#include <nlohmann/json.hpp>

#include <kanhe/core/bytes.hpp>
#include <kanhe/core/crypto.hpp>
#include <kanhe/core/protocol/common.hpp>
#include <kanhe/ledger/ledger.hpp>

/// A ledger's long-term status (spec v0.21, section 11.1; informative):
/// whether its keys and the attestations it keeps would carry its evidence
/// past the classical algorithms, and what its operator should do about it,
/// in plain words. `kanhe status`, GET /v1/status, and the console show it.
///
/// As JSON:
///   {"post_quantum": the root key and the log key in effect are ML-DSA,
///    "root_key": {"algorithm", "post_quantum"}, "log_key": {...},
///    "genesis_post_quantum": the genesis named ML-DSA root and log keys,
///    "keys_post_quantum": every root and log key the ledger ever had is
///        ML-DSA: its own checkpoints are post-quantum attestations,
///    "last_post_quantum_cosignature": null, or the newest cosignature kept by
///        a witness whose key is ML-DSA: {"witness" (its kid, hex),
///        "algorithm", "tree_size", "checkpoint_time", "time" (its own,
///        when dated; else null)},
///    "certificates_expiring": each time-stamp authority whose newest token's
///        signing certificate expires within 90 days, or has: {"authority",
///        "not_after", "days_left"},
///    "advice": [what to do, each a sentence]}
/// Times are ISO 8601 UTC with milliseconds.
namespace kanhe::node {

/// Post-quantum, as section 11.1 means it: ML-DSA.
[[nodiscard]] bool post_quantum_algorithm(crypto::SigAlg alg) noexcept;

/// How long before a time-stamp authority's certificate expires the status
/// warns of it.
inline constexpr protocol::Timestamp certificate_warning = 90ULL * 86'400'000ULL;

/// What the status needs of the cosignatures and tokens a ledger keeps, read
/// once each: a server keeps one and asks it on every GET /v1/status. Safe to
/// call from several threads.
class LongTermWatch {
public:
    /// The status at `now` (milliseconds), after reading whatever the ledger
    /// stored since the last call.
    [[nodiscard]] nlohmann::json status(const ledger::Ledger& ledger, protocol::Timestamp now);

private:
    struct Cosignature {
        std::string witness;
        crypto::SigAlg algorithm = crypto::SigAlg::ml_dsa_65;
        std::uint64_t tree_size = 0;
        protocol::Timestamp checkpoint_time = 0;
        std::optional<std::uint64_t> time;
    };
    struct Authority {
        std::string name;
        protocol::Timestamp token_time = 0;
        std::optional<protocol::Timestamp> not_after;
    };

    void read_new(const ledger::Ledger& ledger);

    std::mutex mutex_;
    std::uint64_t cosignatures_read_ = 0;
    std::uint64_t timestamps_read_ = 0;
    std::optional<Cosignature> last_;
    /// By the SHA-256 of the authority's key, in hex.
    std::map<std::string, Authority> authorities_;
};

/// The status at `now`, read afresh.
[[nodiscard]] nlohmann::json long_term_json(const ledger::Ledger& ledger, protocol::Timestamp now);

/// The signing certificate's notAfter (milliseconds since the epoch) of an
/// RFC 3161 time-stamp token, if it carries one that parses.
[[nodiscard]] std::optional<protocol::Timestamp> timestamp_certificate_expiry(ByteView token);

} // namespace kanhe::node
