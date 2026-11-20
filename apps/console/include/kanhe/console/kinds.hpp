// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <cstdint>
#include <filesystem>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

#include <nlohmann/json.hpp>

#include <kanhe/core/crypto.hpp>
#include <kanhe/core/protocol/ranges.hpp>
#include <kanhe/core/protocol/record.hpp>
#include <kanhe/ledger/environment.hpp>

/// Document kinds: the console's templates for registering records. A kind
/// names a record type and the fields and files its records carry, so the
/// console can show a form; it is the console's own (kinds.json in its
/// folder), never part of the protocol: a record of the type registered any
/// other way is the same record. Private fields are committed by salted hash
/// (record fields, disclosed one by one); public ones go into the record's
/// metadata, which anyone reading the ledger sees.
///
///   {"sheet": 1, "kind": "document", "type": "example.org.photo/1",
///    "name": "Photo", "description": "...",
///    "fields": [{"name": "place", "label": "Place", "type": "text",
///                "private": true, "required": true},
///               {"name": "taken", "type": "date", "provable": "date"}, ...],
///    "files": "optional" | "required" | "none", "keep_files": true,
///    "printed": ["place", ...], "answers": ["taken", ...]}
///
/// A private number or date may be "provable" (spec v0.22): its records then
/// commit to its value apart too, so that whoever holds its opening can later
/// prove that it lies within bounds without showing it. The encoding is
/// written as the command line writes it: "date" for a date; for a number,
/// "number" (whole), "number:SCALE" (SCALE decimal places, 0 to 18), or
/// "money:CCY:SCALE" for an amount in a currency (an ISO 4217 code, 0 to 4
/// decimal places).
namespace kanhe::console {

enum class FieldType : std::uint8_t { text, number, date, yes_no };

[[nodiscard]] std::string_view name_of(FieldType type) noexcept;

struct KindField {
    /// The record field's name, as the ledger commits to it.
    std::string name;
    /// What the form shows (the name if empty).
    std::string label;
    FieldType type = FieldType::text;
    bool is_private = true;
    bool required = false;
    /// How its value is read when it is provable; none if it is not.
    std::optional<protocol::ProvableEncoding> provable = {};
};

enum class KindFiles : std::uint8_t { none, optional, required };

struct Kind {
    std::string type;
    std::string name;
    std::string description;
    std::vector<KindField> fields;
    KindFiles files = KindFiles::optional;
    /// Keep the files with the record, sealed (else they stay with the
    /// person, committed by hash only).
    bool keep_files = true;
    /// The fields a certificate of this kind shows on paper, in order
    /// (certificates.hpp): whoever scans its QR code sees these, and only
    /// these. None for a kind that is no certificate.
    std::vector<std::string> printed;
    /// The fields whose conditions the console's machine may answer by
    /// itself when a party asks (spec v0.15), once an owner lets it: an
    /// answer only when the condition holds, signed by the machine. None:
    /// people answer every question.
    std::vector<std::string> answers;
};

/// Reads a kind sheet; throws std::invalid_argument saying what is wrong.
[[nodiscard]] Kind parse_kind(const nlohmann::json& sheet);
[[nodiscard]] nlohmann::json kind_json(const Kind& kind);

/// Checks a value typed for `field`: its form for its type (a number, a
/// date as YYYY-MM-DD, yes or no; text up to 4096 bytes). The reason it is
/// not one, if it is not.
[[nodiscard]] std::optional<std::string> check_value(const KindField& field,
                                                     std::string_view value);

/// The provable values of a record of `kind` (spec v0.22): each field the
/// kind marks provable that `fields` (the record's private fields, values as
/// text) gives, its value read as its encoding's integer and committed with
/// a fresh salt of its own; and their openings, for the vault. Both names
/// ascending, as key 8 and the vault keep them; none if the kind marks none.
struct ProvableDraft {
    std::vector<protocol::ProvableValue> values;
    std::vector<protocol::RangeOpening> openings;
};
/// The draft, or why a value cannot be read in its field's encoding.
[[nodiscard]] std::variant<ProvableDraft, std::string>
provable_draft(const Kind& kind, std::span<const protocol::RecordField> fields,
               const crypto::Provider& provider, ledger::Entropy& entropy);

/// A registration's provable values as the page reads them, in key 8's
/// order: each {field, encoding: {type, scale, currency}}, the encoding as a
/// verification report gives it (scale null for a date, currency null but
/// for money).
[[nodiscard]] nlohmann::json provable_view(std::span<const protocol::ProvableValue> values);

/// The console's kinds (none if never written). Throws std::runtime_error
/// if the file is damaged.
[[nodiscard]] std::vector<Kind> load_kinds(const std::filesystem::path& directory);
/// Replaces them atomically.
void save_kinds(const std::filesystem::path& directory, const std::vector<Kind>& kinds);

} // namespace kanhe::console
