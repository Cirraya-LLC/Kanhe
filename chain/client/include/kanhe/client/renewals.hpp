// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <cstdint>
#include <optional>
#include <string>

#include <kanhe/core/bytes.hpp>
#include <kanhe/core/error.hpp>
#include <kanhe/core/protocol/evidence.hpp>

/// Renewals (spec v0.21, section 11.1): newer attestations of a ledger's
/// tree, which whoever holds a bundle adds to it, from the ledger's server
/// (GET /v1/renewal, section 16), an archive that serves the same route, or
/// the ledger's own directory (ledger::Ledger::renewal). They hold nothing
/// private. The command line (evidence renew) and the console share these.
namespace kanhe::client {

/// The size a renewal of `bundle` starts from: its last renewal's
/// checkpoint's, or else its own checkpoint's.
[[nodiscard]] std::uint64_t renewal_start(const protocol::EvidenceBundle& bundle);

/// GET URL/v1/renewal?from=FROM[&size=SIZE], with no token, trusting the CA
/// certificates in `ca_file` if given: the renewal, decoded and not yet
/// checked against any bundle. Throws ActionError with the server's message
/// (404 when it keeps no checkpoint of that size, or none attested).
[[nodiscard]] protocol::Renewal fetch_renewal(const std::string& url, std::uint64_t from,
                                              std::optional<std::uint64_t> size,
                                              const std::optional<std::string>& ca_file);

/// A bundle with a renewal appended, and the whole verified.
struct Renewed {
    /// The renewed bundle, encoded.
    Bytes bundle;
    /// The renewal appended, as appended.
    protocol::Renewal added;
    /// The size it renews from.
    std::uint64_t from = 0;
    /// The renewed bundle verified with the options given, or why not.
    Result<protocol::EvidenceReport> report = fail(Errc::unavailable, "not verified");
};

/// Appends `renewal` to the bundle `encoded`: when it repeats the bundle's
/// last checkpoint (the same bytes), without the attestations the bundle
/// holds already. Then verifies the whole bundle with `options`. Throws
/// ActionError if `encoded` is not a bundle, if the renewal adds nothing (it
/// repeats the last checkpoint with no attestation the bundle lacks), or if
/// the bundle holds 64 renewals already.
[[nodiscard]] Renewed renew_bundle(ByteView encoded, protocol::Renewal renewal,
                                   const protocol::VerifyOptions& options);

} // namespace kanhe::client
