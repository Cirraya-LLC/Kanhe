// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <filesystem>
#include <utility>
#include <vector>

#include <kanhe/core/bytes.hpp>
#include <kanhe/core/crypto.hpp>
#include <kanhe/core/error.hpp>
#include <kanhe/core/protocol/common.hpp>
#include <kanhe/core/protocol/evidence.hpp>
#include <kanhe/core/protocol/statement.hpp>

/// Source proofs (spec v0.18, section 11, step 10), kept beside the ledger.
///
/// A record names the records it was made from; for a source on another
/// ledger, the evidence of that source, as its ledger gave it, may be kept
/// here, and is added to the record's evidence wherever it is served or
/// exported (bundle key 10):
///
///   <ledger>/sources/<record>/<ledger>.<source>.cbor
///
/// One level only: a proof's own source proofs are dropped when it is kept.
namespace kanhe::node {

struct KeptSourceProof {
    protocol::Source source;
    Bytes proof;
};

[[nodiscard]] std::filesystem::path source_proof_path(const std::filesystem::path& ledger_directory,
                                                      const protocol::Id& record,
                                                      const protocol::Source& source);

/// A source proof as it is kept: the evidence of a source on another
/// ledger, without source proofs of its own; with its report.
struct CheckedSourceProof {
    protocol::Source source;
    Bytes proof;
    protocol::EvidenceReport report;
};

/// Checks `proof` as the proof of one of `sources` (a record's): a complete
/// bundle of a record that one of them names on another ledger than
/// `own_ledger` (a local source's statements go in the bundle itself).
/// The proof's own source proofs are dropped: one level per bundle.
[[nodiscard]] Result<CheckedSourceProof>
check_source_proof(const crypto::Provider& provider, ByteView proof,
                   const std::vector<protocol::Source>& sources, const protocol::Id& own_ledger);

/// Keeps a checked proof of `source`, a source of `record`, in place of the
/// one before.
[[nodiscard]] Status keep_source_proof(const std::filesystem::path& ledger_directory,
                                       const protocol::Id& record, const protocol::Source& source,
                                       ByteView proof);

/// Removes the kept proof of `source`; false if none was kept.
[[nodiscard]] bool remove_source_proof(const std::filesystem::path& ledger_directory,
                                       const protocol::Id& record, const protocol::Source& source);

/// The proofs kept for `record`, by file name (a file that does not read as
/// a bundle is left out).
[[nodiscard]] std::vector<KeptSourceProof>
kept_source_proofs(const std::filesystem::path& ledger_directory, const protocol::Id& record);

/// Adds the proofs kept for the bundle's record to it.
void add_source_proofs(const std::filesystem::path& ledger_directory,
                       protocol::EvidenceBundle& bundle);

} // namespace kanhe::node
