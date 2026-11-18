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

#include <kanhe/core/bytes.hpp>
#include <kanhe/core/crypto.hpp>
#include <kanhe/core/error.hpp>
#include <kanhe/core/protocol/approvals.hpp>
#include <kanhe/core/protocol/record.hpp>
#include <kanhe/core/protocol/statement.hpp>

/// Approval files (spec v0.20, section 5.1; `approval-file` in the CDDL): a
/// statement carried between approvers who share no server, with the
/// approvals gathered so far, the rest of its submission, and, for a
/// registration, the fields its field root commits to, shown to approvers:
///
///   {1: 1, 2: signed statement, 3: ledger hash (COSE id), ? 4: [1*32 approval],
///    ? 5: bstr .cbor submission-parts, ? 6: [+ record-field], ? 7: note}
///
/// Reading one checks its shape, never the ledger's rules: tools check the
/// statement and each approval against the ledger itself before relying on
/// them.
namespace kanhe::protocol {

/// An approval file is at most this large; its note at most this long.
inline constexpr std::size_t max_approval_file = std::size_t{16} << 20;
inline constexpr std::size_t max_approval_note = 1000;
inline constexpr std::string_view approval_file_extension = ".kanheapproval";

/// The parts of a submission besides its statement and approvals
/// (`submission-parts`): what is kept with the statement when it is
/// registered.
struct SubmissionParts {
    /// Key 2: a record's sealed private data, its vault file.
    std::optional<Bytes> vault;
    /// Key 3: a contract call's consent bundles, one per consent it cites, in
    /// its order. Never with key 2 or 4.
    std::vector<Bytes> consents;
    /// Key 4: a record's attached files, sealed, as [index, sealed file],
    /// indexes strictly ascending. Only with key 2.
    std::vector<std::pair<std::uint64_t, Bytes>> files;

    [[nodiscard]] bool empty() const noexcept {
        return !vault && consents.empty() && files.empty();
    }

    friend bool operator==(const SubmissionParts&, const SubmissionParts&) = default;
};

/// A submission's parts as `submission-parts` encodes them, at least one key,
/// and back.
[[nodiscard]] Result<Bytes> encode_submission_parts(const SubmissionParts& parts);
[[nodiscard]] Result<SubmissionParts> decode_submission_parts(ByteView encoded);

/// Whether `statement` takes these parts: sealed private data (and files for
/// its attachments) for a record's registration; one consent bundle per
/// consent a contract call cites. Their contents are the server's to check.
[[nodiscard]] Status check_submission_parts(const Statement& statement,
                                            const SubmissionParts& parts);

/// Whether `fields` are every field of the registration `statement`, in the
/// order of their leaves, giving its field root and field count.
[[nodiscard]] Status check_shown_fields(const crypto::Provider& provider, crypto::HashAlg hash,
                                        const Statement& statement,
                                        std::span<const RecordField> fields);

struct ApprovalFile {
    /// The signed statement, parsed under the file's ledger hash: its id is
    /// computed from the bytes, never taken from the file.
    SignedStatement statement;
    /// The approvals gathered so far, each for this statement and its
    /// ledger, no approver twice. Written ascending by approver.
    std::vector<SignedApproval> approvals;
    /// The rest of its submission, if any.
    std::optional<SubmissionParts> parts;
    /// A registration's fields, shown to approvers (in clear); empty: none.
    std::vector<RecordField> fields;
    /// A note for people, 1 to 1,000 bytes.
    std::optional<std::string> note;
};

/// Writes an approval file, refusing what a reader would refuse.
[[nodiscard]] Result<Bytes> encode_approval_file(const ApprovalFile& file);

/// Reads an approval file: at most 16 MiB, format version 1, no other key; a
/// statement that parses under the hash it names and is not a genesis; each
/// approval parsed, for that statement and its ledger, no approver twice;
/// fields only for a registration, and giving its field root and count;
/// submission parts the statement takes.
[[nodiscard]] Result<ApprovalFile> decode_approval_file(const crypto::Provider& provider,
                                                        ByteView encoded);

/// Adds an approval to a file, replacing one by the same approver. Refuses
/// one for another statement or ledger, and a 33rd.
[[nodiscard]] Status add_approval(ApprovalFile& file, SignedApproval approval);

} // namespace kanhe::protocol
