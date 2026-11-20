// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <kanhe/client/records.hpp>
#include <kanhe/core/bytes.hpp>
#include <kanhe/core/cbor.hpp>
#include <kanhe/core/error.hpp>
#include <kanhe/core/protocol/evidence.hpp>
#include <kanhe/core/protocol/ranges.hpp>

/// Range proofs (spec v0.22, sections 6 and 11.3) as an issuer and a holder
/// make them: provable values marked when a record is issued, their openings
/// kept in the vault and handed out as range openings files, and proofs added
/// to a record's evidence from an opening, with bounds as people write them.
/// The command line (record issue --provable, record openings, evidence
/// prove) and the MCP server share these.
namespace kanhe::client {

/// An encoding as the command line writes it: `number` (scale 0),
/// `number:SCALE` (0 to 18), `money:CCY:SCALE` (an ISO 4217 code of three
/// upper-case letters, 0 to 4), or `date`. Throws UsageError for anything
/// else.
[[nodiscard]] protocol::ProvableEncoding parse_provable_encoding(std::string_view text);
/// An encoding written back in that form.
[[nodiscard]] std::string provable_encoding_text(const protocol::ProvableEncoding& encoding);
/// Throws UsageError unless `encoding`'s parameters are in range.
void check_provable_encoding(const protocol::ProvableEncoding& encoding);
/// NAME:ENCODING, as record issue --provable takes it (the name is what
/// comes before the first colon). Throws UsageError.
[[nodiscard]] std::pair<std::string, protocol::ProvableEncoding>
parse_provable(std::string_view text);

/// A field's value, as its issuer holds it, read as the integer x of
/// `encoding` (spec section 6), with exact arithmetic:
///   - number: an integer or a decimal, commas allowed ("1,234.5"), with at
///     most `scale` digits after the point; x is it times 10^scale;
///   - money: "HKD 30,000.00", or a bare amount taken in the encoding's
///     currency, with at most `scale` decimals; x is the amount in units of
///     10^-scale;
///   - date: YYYY-MM-DD, from 0001-01-01 to 9999-12-31; x is its number of
///     days from 1970-01-01 (1969-12-31 is -1).
/// x must lie within -2^63 to 2^63 - 1. Throws UsageError saying why it
/// cannot be read.
[[nodiscard]] std::int64_t provable_value_x(const protocol::ProvableEncoding& encoding,
                                            std::string_view value);

/// A bound as people write it, in the claim value form the spec gives for
/// `encoding` (section 11.3): a number as an integer (18) or a decimal text
/// ("18.5"), digits beyond the scale dropped if they are zeros; money as
/// [amount, currency, scale] in the encoding's currency and scale, from
/// "HKD 30,000.00" or a bare amount; a date as its text. Throws UsageError
/// for a bound of another form or currency, with more decimals than the
/// scale, or out of range.
[[nodiscard]] cbor::Value range_bound_value(const protocol::ProvableEncoding& encoding,
                                            std::string_view text);

/// A statement to prove, as people give it: the provable value's name, and
/// a least value, a greatest, or both, written as range_bound_value takes
/// them; and a relying party's challenge, if it gave one (1 to 64 bytes).
struct RangeRequest {
    std::string field;
    std::optional<std::string> at_least;
    std::optional<std::string> at_most;
    std::optional<Bytes> context;
};

/// The proof `request` asks for, without its proof bytes: its bounds in the
/// claim forms of `provable`'s encoding, checked as a verifier checks them
/// (range_public_values). Throws UsageError for a request without bounds, a
/// bound that is not of the encoding, a low above the high, or a context of
/// another size.
[[nodiscard]] protocol::RangeProof range_statement(const protocol::ProvableValue& provable,
                                                   const RangeRequest& request);

/// The record an evidence bundle is about, as the bundle shows it verified.
struct ProvableRecord {
    protocol::Id ledger;
    protocol::Id record;
    /// Its registration's provable values (key 8), in their order.
    std::vector<protocol::ProvableValue> provable;
};

/// The ledger, the record, and its provable values, from the bundle
/// `encoded` verified with `options`, its range proofs left out (a proof
/// about to be replaced or removed does not count): or why it does not
/// verify. Throws ActionError if it is not an evidence bundle.
[[nodiscard]] Result<ProvableRecord> provable_record(ByteView encoded,
                                                     const protocol::VerifyOptions& options);

/// `record`'s provable value `field`; throws UsageError naming the record's
/// provable values if it has no such one.
[[nodiscard]] const protocol::ProvableValue& provable_value(const ProvableRecord& record,
                                                            std::string_view field);

/// Whether this build makes and checks proofs of system 1 (Longfellow ZK;
/// KANHE_RANGE_PROOFS).
[[nodiscard]] bool range_proofs_built() noexcept;
/// System 1's verifier, for protocol::VerifyOptions::range_verifier: empty
/// in a build without range proofs, whose verifications then report proofs
/// as not checked.
[[nodiscard]] protocol::RangeVerifier range_verifier();

/// A bundle with a range proof added, and the whole verified.
struct Proved {
    /// The new bundle, encoded.
    Bytes bundle;
    /// The proof added, as added.
    protocol::RangeProof proof;
    /// Whether it replaced a proof of the same field.
    bool replaced = false;
    /// The new bundle verified with the options given and system 1's
    /// verifier, or why not.
    Result<protocol::EvidenceReport> report = fail(Errc::unavailable, "not verified");
};

/// Proves `statement` (from range_statement) about `record`, the record of
/// the bundle `encoded`, from `opening`, with fresh randomness; adds the
/// proof to the bundle (key 12) in place of one of the same field, or after
/// the others; and verifies the whole with `options` and range_verifier().
/// Throws UsageError if the field is not provable; ActionError if this build
/// has no range proofs, if the opening is not of that field or does not
/// match its commitment in the registration, if the value lies outside the
/// bounds (no proof can be made), or if the bundle carries 16 proofs of other
/// fields already.
[[nodiscard]] Proved add_range_proof(ByteView encoded, const ProvableRecord& record,
                                     protocol::RangeProof statement,
                                     const protocol::RangeOpening& opening,
                                     protocol::VerifyOptions options);

/// A bundle with range proofs removed, and the whole verified.
struct Unproved {
    Bytes bundle;
    /// The proofs removed, in the bundle's order.
    std::vector<protocol::RangeProof> removed;
    Result<protocol::EvidenceReport> report = fail(Errc::unavailable, "not verified");
};

/// The bundle `encoded` without its range proofs of `fields`, verified with
/// `options` and range_verifier(). Throws ActionError if it is not a bundle
/// or carries no proof of one of the fields, and UsageError if a field is
/// named twice.
[[nodiscard]] Unproved remove_range_proofs(ByteView encoded, std::span<const std::string> fields,
                                           protocol::VerifyOptions options);

/// The range openings of `record` that its vault holds, each checked against
/// its commitment in the registration `body`: all of them, or those of
/// `fields` (each named once). Throws UsageError for a field that is not
/// provable or named twice, and ActionError if the vault holds no opening of
/// one, or one that does not match.
[[nodiscard]] protocol::RangeOpenings
vault_openings(const crypto::Provider& provider, const protocol::Id& ledger,
               const protocol::Id& record, const protocol::RecordRegisterBody& body,
               const Vault& vault, std::span<const std::string> fields);

/// The opening of `field` in `openings`, a range openings file's: checked
/// to be of `record`'s ledger and record. Throws ActionError otherwise, or
/// if it holds no opening of the field.
[[nodiscard]] protocol::RangeOpening opening_of(const protocol::RangeOpenings& openings,
                                                const ProvableRecord& record,
                                                std::string_view field);

} // namespace kanhe::client
