// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <format>
#include <limits>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <kanhe/client/errors.hpp>
#include <kanhe/client/ranges.hpp>
#include <kanhe/client/support.hpp>
#include <kanhe/ledger/verify.hpp>

#if defined(KANHE_HAVE_RANGE_PROOFS)
#include <kanhe/crypto/longfellow.hpp>
#endif

namespace kanhe::client {

namespace {

using V = cbor::Value;
using Type = protocol::ProvableEncoding::Type;

/// The longest decimal text a bound may be (spec section 6, claim-number).
constexpr std::size_t max_decimal_text = 40;

std::string_view trimmed(std::string_view text) {
    while (!text.empty() && text.front() == ' ') {
        text.remove_prefix(1);
    }
    while (!text.empty() && text.back() == ' ') {
        text.remove_suffix(1);
    }
    return text;
}

bool all_digits(std::string_view s) {
    return !s.empty() && std::ranges::all_of(s, [](char c) { return c >= '0' && c <= '9'; });
}

bool upper_letters(std::string_view s) {
    return std::ranges::all_of(s, [](char c) { return c >= 'A' && c <= 'Z'; });
}

/// A decimal, -?[0-9]+(\.[0-9]+)?, read apart.
struct Decimal {
    bool negative = false;
    std::string whole;
    std::string fraction;
};

/// `text` without its commas ("1,234.5"), read as a decimal; nothing if it
/// is not one.
std::optional<Decimal> decimal_of(std::string_view text) {
    std::string s;
    for (const char c : trimmed(text)) {
        if (c != ',') {
            s.push_back(c);
        }
    }
    Decimal d;
    std::string_view rest = s;
    if (rest.starts_with('-')) {
        d.negative = true;
        rest.remove_prefix(1);
    }
    const std::size_t dot = rest.find('.');
    d.whole = std::string(rest.substr(0, dot));
    if (dot != std::string_view::npos) {
        d.fraction = std::string(rest.substr(dot + 1));
    }
    if (!all_digits(d.whole) || (dot != std::string_view::npos && !all_digits(d.fraction))) {
        return std::nullopt;
    }
    return d;
}

/// The decimal times 10^scale, if it fits in 64 signed bits; its fraction
/// has at most `scale` digits.
std::optional<std::int64_t> scaled(const Decimal& d, std::size_t scale) {
    std::string digits = d.whole + d.fraction;
    digits.append(scale - d.fraction.size(), '0');
    constexpr std::uint64_t two_63 = std::uint64_t{1} << 63;
    const std::uint64_t limit = d.negative ? two_63 : two_63 - 1;
    std::uint64_t magnitude = 0;
    for (const char c : digits) {
        const auto digit = static_cast<std::uint64_t>(c - '0');
        if (magnitude > (limit - digit) / 10) {
            return std::nullopt;
        }
        magnitude = magnitude * 10 + digit;
    }
    if (!d.negative) {
        return static_cast<std::int64_t>(magnitude);
    }
    if (magnitude == two_63) {
        return std::numeric_limits<std::int64_t>::min();
    }
    return -static_cast<std::int64_t>(magnitude);
}

/// Days from 1970-01-01 to a date of the proleptic Gregorian calendar
/// (Hinnant's days-from-civil algorithm, on integers).
std::int64_t days_from_civil(std::int64_t year, std::int64_t month, std::int64_t day) {
    year -= month <= 2 ? 1 : 0;
    const std::int64_t era = (year >= 0 ? year : year - 399) / 400;
    const std::int64_t year_of_era = year - era * 400;
    const std::int64_t shifted_month = month > 2 ? month - 3 : month + 9;
    const std::int64_t day_of_year = (153 * shifted_month + 2) / 5 + day - 1;
    const std::int64_t day_of_era =
        year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    return era * 146'097 + day_of_era - 719'468;
}

/// A date YYYY-MM-DD from 0001-01-01 to 9999-12-31, as its x: its days from
/// 1970-01-01. Nothing if it is not one.
std::optional<std::int64_t> date_x(std::string_view s) {
    if (s.size() != 10 || s[4] != '-' || s[7] != '-' || !all_digits(s.substr(0, 4)) ||
        !all_digits(s.substr(5, 2)) || !all_digits(s.substr(8, 2))) {
        return std::nullopt;
    }
    const auto number = [](std::string_view part) {
        std::int64_t n = 0;
        for (const char c : part) {
            n = n * 10 + (c - '0');
        }
        return n;
    };
    const std::int64_t year = number(s.substr(0, 4));
    const std::int64_t month = number(s.substr(5, 2));
    const std::int64_t day = number(s.substr(8, 2));
    if (year < 1 || month < 1 || month > 12 || day < 1) {
        return std::nullopt;
    }
    constexpr std::array<std::int64_t, 12> days_in{31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
    const bool leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
    const std::int64_t most =
        month == 2 && leap ? 29 : days_in[static_cast<std::size_t>(month - 1)];
    if (day > most) {
        return std::nullopt;
    }
    return days_from_civil(year, month, day);
}

/// "HKD 30,000.00" apart: its currency and its amount; a bare amount has no
/// currency.
std::pair<std::string, std::string_view> money_parts(std::string_view text) {
    const std::string_view t = trimmed(text);
    if (t.size() >= 5 && t[3] == ' ' && upper_letters(t.substr(0, 3))) {
        return {std::string(t.substr(0, 3)), trimmed(t.substr(4))};
    }
    return {std::string(), t};
}

std::string quoted(std::string_view text) {
    return "'" + std::string(trimmed(text)) + "'";
}

std::string decimals(std::size_t scale) {
    return std::format("{} decimal{}", scale, scale == 1 ? "" : "s");
}

/// The amount of `text` in `encoding`'s currency (a number's is all of it).
std::string_view amount_of(const protocol::ProvableEncoding& encoding, std::string_view text) {
    if (encoding.type != Type::money) {
        return text;
    }
    const auto [currency, amount] = money_parts(text);
    if (!currency.empty() && currency != encoding.currency) {
        throw UsageError{quoted(text) + " is in " + currency + ", not " + encoding.currency};
    }
    return amount;
}

std::string what_of(const protocol::ProvableEncoding& encoding) {
    return encoding.type == Type::money ? "an amount of money (" + encoding.currency + " 30,000.00)"
                                        : "a number";
}

std::string out_of_range(std::string_view text, std::size_t scale) {
    return quoted(text) + std::format(" is out of range: at scale {}, the value times 10^{} must "
                                      "lie within -2^63 and 2^63 - 1",
                                      scale, scale);
}

const char* const date_form = "a date (YYYY-MM-DD, from 0001-01-01 to 9999-12-31)";

std::string names_of(const std::vector<protocol::ProvableValue>& provable) {
    std::string out;
    for (const protocol::ProvableValue& p : provable) {
        out += (out.empty() ? "" : ", ") + p.name;
    }
    return out;
}

} // namespace

void check_provable_encoding(const protocol::ProvableEncoding& encoding) {
    switch (encoding.type) {
    case Type::number:
        if (encoding.scale > protocol::max_number_scale || !encoding.currency.empty()) {
            throw UsageError{"a number's scale is 0 to 18, and it has no currency"};
        }
        return;
    case Type::money:
        if (encoding.scale > protocol::max_money_scale || encoding.currency.size() != 3 ||
            !upper_letters(encoding.currency)) {
            throw UsageError{"money has a currency of three upper-case letters (ISO 4217, such as "
                             "HKD) and a scale of 0 to 4"};
        }
        return;
    case Type::date:
        if (encoding.scale != 0 || !encoding.currency.empty()) {
            throw UsageError{"a date has neither a scale nor a currency"};
        }
        return;
    }
    throw UsageError{"an encoding is a number, money, or a date"};
}

protocol::ProvableEncoding parse_provable_encoding(std::string_view text) {
    const std::string forms =
        "an encoding is number, number:SCALE (0 to 18), money:CCY:SCALE (such as money:HKD:2), "
        "or date: " +
        std::string(text);
    std::vector<std::string_view> parts;
    for (std::size_t start = 0;;) {
        const std::size_t colon = text.find(':', start);
        parts.push_back(
            text.substr(start, colon == std::string_view::npos ? colon : colon - start));
        if (colon == std::string_view::npos) {
            break;
        }
        start = colon + 1;
    }
    const auto scale_of = [&](std::string_view s, unsigned most) {
        if (!all_digits(s) || s.size() > 2) {
            throw UsageError{forms};
        }
        unsigned n = 0;
        for (const char c : s) {
            n = n * 10 + static_cast<unsigned>(c - '0');
        }
        if (n > most) {
            throw UsageError{std::format("a scale is 0 to {} here: {}", most, text)};
        }
        return static_cast<std::uint8_t>(n);
    };
    protocol::ProvableEncoding encoding;
    if (parts[0] == "number" && parts.size() <= 2) {
        encoding.type = Type::number;
        encoding.scale = parts.size() == 2 ? scale_of(parts[1], 18) : std::uint8_t{0};
    } else if (parts[0] == "money" && parts.size() == 3) {
        encoding.type = Type::money;
        encoding.currency = std::string(parts[1]);
        encoding.scale = scale_of(parts[2], 4);
    } else if (parts[0] == "date" && parts.size() == 1) {
        encoding.type = Type::date;
    } else {
        throw UsageError{forms};
    }
    check_provable_encoding(encoding);
    return encoding;
}

std::string provable_encoding_text(const protocol::ProvableEncoding& encoding) {
    switch (encoding.type) {
    case Type::number:
        return encoding.scale == 0 ? std::string("number")
                                   : std::format("number:{}", unsigned{encoding.scale});
    case Type::money:
        return std::format("money:{}:{}", encoding.currency, unsigned{encoding.scale});
    case Type::date:
        return "date";
    }
    return "unknown";
}

std::pair<std::string, protocol::ProvableEncoding> parse_provable(std::string_view text) {
    const std::size_t colon = text.find(':');
    if (colon == std::string_view::npos || colon == 0) {
        throw UsageError{"a provable value is NAME:ENCODING, such as birth_date:date or "
                         "monthly_salary:money:HKD:2: " +
                         std::string(text)};
    }
    return {std::string(text.substr(0, colon)), parse_provable_encoding(text.substr(colon + 1))};
}

std::int64_t provable_value_x(const protocol::ProvableEncoding& encoding, std::string_view value) {
    check_provable_encoding(encoding);
    if (encoding.type == Type::date) {
        if (const auto x = date_x(trimmed(value))) {
            return *x;
        }
        throw UsageError{quoted(value) + " is not " + date_form};
    }
    const auto d = decimal_of(amount_of(encoding, value));
    if (!d) {
        throw UsageError{quoted(value) + " is not " + what_of(encoding)};
    }
    const auto scale = static_cast<std::size_t>(encoding.scale);
    if (d->fraction.size() > scale) {
        throw UsageError{quoted(value) + " has more than " + decimals(scale) +
                         ", the scale it is read at"};
    }
    if (const auto x = scaled(*d, scale)) {
        return *x;
    }
    throw UsageError{out_of_range(value, scale)};
}

cbor::Value range_bound_value(const protocol::ProvableEncoding& encoding, std::string_view text) {
    check_provable_encoding(encoding);
    if (trimmed(text).empty()) {
        throw UsageError{"a bound is empty"};
    }
    if (encoding.type == Type::date) {
        if (!date_x(trimmed(text))) {
            throw UsageError{quoted(text) + " is not " + date_form};
        }
        return V::text(std::string(trimmed(text)));
    }
    auto d = decimal_of(amount_of(encoding, text));
    if (!d) {
        throw UsageError{quoted(text) + " is not " + what_of(encoding)};
    }
    // Digits beyond the scale are taken if they are zeros: 18.50 is 18.5.
    const auto scale = static_cast<std::size_t>(encoding.scale);
    while (d->fraction.size() > scale && d->fraction.back() == '0') {
        d->fraction.pop_back();
    }
    if (d->fraction.size() > scale) {
        throw UsageError{quoted(text) + " has more than " + decimals(scale) +
                         ", the scale the value is read at"};
    }
    const auto x = scaled(*d, scale);
    if (!x) {
        throw UsageError{out_of_range(text, scale)};
    }
    if (encoding.type == Type::money) {
        return V::array(
            {V::integer(*x), V::text(encoding.currency), V::unsigned_integer(encoding.scale)});
    }
    // A number as a claim writes it: an integer, or a decimal text.
    if (d->fraction.empty()) {
        return V::integer(*scaled(*d, 0));
    }
    d->whole.erase(0, std::min(d->whole.find_first_not_of('0'), d->whole.size() - 1));
    std::string written = (d->negative ? "-" : "") + d->whole + "." + d->fraction;
    if (written.size() > max_decimal_text) {
        throw UsageError{quoted(text) + " is longer than a bound may be written (40 characters)"};
    }
    return V::text(std::move(written));
}

protocol::RangeProof range_statement(const protocol::ProvableValue& provable,
                                     const RangeRequest& request) {
    if (!request.at_least && !request.at_most) {
        throw UsageError{"a statement to prove has a least value, a greatest, or both"};
    }
    protocol::RangeProof proof;
    proof.field = provable.name;
    if (request.at_least) {
        proof.low = range_bound_value(provable.encoding, *request.at_least);
    }
    if (request.at_most) {
        proof.high = range_bound_value(provable.encoding, *request.at_most);
    }
    if (request.context) {
        if (request.context->empty() || request.context->size() > protocol::max_range_context) {
            throw UsageError{"a context is a relying party's challenge of 1 to 64 bytes"};
        }
        proof.context = *request.context;
    }
    proof.system = protocol::range_system_longfellow;
    // As a verifier reads them: in range, and the low no greater than the
    // high.
    const auto values = protocol::range_public_values(provable.encoding, proof);
    if (!values) {
        throw UsageError{"those bounds are refused: " + std::string(values.error().detail)};
    }
    if (values->first > values->second) {
        throw UsageError{"the least value given is above the greatest"};
    }
    return proof;
}

Result<ProvableRecord> provable_record(ByteView encoded, const protocol::VerifyOptions& options) {
    auto bundle = unwrap(protocol::decode_bundle(encoded), "reading the evidence bundle");
    bundle.range_proofs.clear();
    const Bytes without = unwrap(protocol::encode_bundle(bundle), "encoding the evidence bundle");
    protocol::VerifyOptions plain = options;
    plain.range_verifier = {};
    plain.range_context.reset();
    auto report = ledger::verify_bundle(shared_provider(), without, plain, on_all_cores());
    if (!report) {
        return std::unexpected(report.error());
    }
    return ProvableRecord{report->ledger_id, report->record, std::move(report->provable)};
}

const protocol::ProvableValue& provable_value(const ProvableRecord& record,
                                              std::string_view field) {
    const auto found = std::ranges::find(record.provable, field, &protocol::ProvableValue::name);
    if (found != record.provable.end()) {
        return *found;
    }
    if (record.provable.empty()) {
        throw UsageError{"record " + short_id(record.record) +
                         " has no provable values: its issuer marked none"};
    }
    throw UsageError{std::string(field) + " is not a provable value of record " +
                     short_id(record.record) + " (it has: " + names_of(record.provable) + ")"};
}

bool range_proofs_built() noexcept {
#if defined(KANHE_HAVE_RANGE_PROOFS)
    return true;
#else
    return false;
#endif
}

protocol::RangeVerifier range_verifier() {
#if defined(KANHE_HAVE_RANGE_PROOFS)
    return [](ByteView commitment, std::uint64_t low, std::uint64_t high, ByteView transcript,
              ByteView proof) -> Status {
        return crypto::longfellow::verify_range(commitment, low, high, transcript, proof);
    };
#else
    return {};
#endif
}

Proved add_range_proof(ByteView encoded, const ProvableRecord& record,
                       protocol::RangeProof statement, const protocol::RangeOpening& opening,
                       protocol::VerifyOptions options) {
    const protocol::ProvableValue& provable = provable_value(record, statement.field);
    if (!range_proofs_built()) {
        throw ActionError{"this program was built without range proofs (KANHE_RANGE_PROOFS): it "
                          "cannot make them"};
    }
    auto bundle = unwrap(protocol::decode_bundle(encoded), "reading the evidence bundle");
    const auto same =
        std::ranges::find(bundle.range_proofs, statement.field, &protocol::RangeProof::field);
    if (same == bundle.range_proofs.end() &&
        bundle.range_proofs.size() >= protocol::max_range_proofs) {
        throw ActionError{"the bundle carries 16 range proofs, as many as a bundle holds: remove "
                          "one first"};
    }
    // The opening must be the one the registration committed to: a proof
    // made from another would not verify.
    if (opening.name != provable.name) {
        throw ActionError{"that opening is of " + opening.name + ", not " + provable.name};
    }
    const Bytes commitment =
        unwrap(protocol::range_commitment(shared_provider(), opening.salt, opening.x),
               "computing the commitment of " + provable.name);
    if (commitment != provable.commitment) {
        throw ActionError{"the opening of " + provable.name +
                          " does not match its commitment in the record's registration: it is "
                          "not this record's value"};
    }
    const auto values = protocol::range_public_values(provable.encoding, statement);
    if (!values) {
        throw UsageError{"those bounds are refused: " + std::string(values.error().detail)};
    }
    const auto [low, high] = *values;
    const std::uint64_t v = protocol::range_v(opening.x);
    if (v < low || v > high) {
        throw ActionError{"no proof can be made that " +
                          protocol::range_words(provable.encoding, statement) +
                          ": the value lies outside those bounds"};
    }
    const Bytes transcript = protocol::range_transcript(
        record.ledger, record.record, statement.field, commitment, low, high,
        statement.context ? ByteView(*statement.context) : ByteView());
#if defined(KANHE_HAVE_RANGE_PROOFS)
    // Fresh randomness from OpenSSL's generator, for every proof: what keeps
    // it zero-knowledge.
    statement.proof =
        unwrap(crypto::longfellow::prove_range(opening.salt, v, low, high, transcript),
               "proving " + statement.field);
#endif
    statement.system = protocol::range_system_longfellow;

    Proved out;
    if (same != bundle.range_proofs.end()) {
        *same = statement;
        out.replaced = true;
    } else {
        bundle.range_proofs.push_back(statement);
    }
    out.proof = std::move(statement);
    out.bundle = unwrap(protocol::encode_bundle(bundle), "encoding the evidence bundle");
    // The whole bundle, as any verifier will check it.
    options.range_verifier = range_verifier();
    out.report = ledger::verify_bundle(shared_provider(), out.bundle, options, on_all_cores());
    return out;
}

Unproved remove_range_proofs(ByteView encoded, std::span<const std::string> fields,
                             protocol::VerifyOptions options) {
    auto bundle = unwrap(protocol::decode_bundle(encoded), "reading the evidence bundle");
    for (std::size_t i = 0; i < fields.size(); ++i) {
        if (std::ranges::contains(fields.first(i), fields[i])) {
            throw UsageError{fields[i] + " is named twice"};
        }
        if (!std::ranges::contains(bundle.range_proofs, fields[i], &protocol::RangeProof::field)) {
            throw ActionError{"the bundle carries no range proof of " + fields[i]};
        }
    }
    Unproved out;
    const auto named = [&](const protocol::RangeProof& p) {
        return std::ranges::contains(fields, p.field);
    };
    for (const protocol::RangeProof& p : bundle.range_proofs) {
        if (named(p)) {
            out.removed.push_back(p);
        }
    }
    std::erase_if(bundle.range_proofs, named);
    out.bundle = unwrap(protocol::encode_bundle(bundle), "encoding the evidence bundle");
    options.range_verifier = range_verifier();
    out.report = ledger::verify_bundle(shared_provider(), out.bundle, options, on_all_cores());
    return out;
}

protocol::RangeOpenings vault_openings(const crypto::Provider& provider, const protocol::Id& ledger,
                                       const protocol::Id& record,
                                       const protocol::RecordRegisterBody& body, const Vault& vault,
                                       std::span<const std::string> fields) {
    if (body.provable.empty()) {
        throw ActionError{"record " + short_id(record) + " has no provable values"};
    }
    for (std::size_t i = 0; i < fields.size(); ++i) {
        if (std::ranges::contains(fields.first(i), fields[i])) {
            throw UsageError{fields[i] + " is named twice"};
        }
        if (!std::ranges::contains(body.provable, fields[i], &protocol::ProvableValue::name)) {
            throw UsageError{fields[i] + " is not a provable value of record " + short_id(record) +
                             " (it has: " + names_of(body.provable) + ")"};
        }
    }
    protocol::RangeOpenings out{ledger, record, {}};
    // In key 8's order, which is the file's: names ascending.
    for (const protocol::ProvableValue& p : body.provable) {
        if (!fields.empty() && !std::ranges::contains(fields, p.name)) {
            continue;
        }
        const auto found = std::ranges::find(vault.openings, p.name, &protocol::RangeOpening::name);
        if (found == vault.openings.end()) {
            throw ActionError{"the vault holds no opening of " + p.name + " for record " +
                              short_id(record) + " (it was issued by a program that keeps none)"};
        }
        const Bytes commitment = unwrap(protocol::range_commitment(provider, found->salt, found->x),
                                        "computing the commitment of " + p.name);
        if (commitment != p.commitment) {
            throw ActionError{"the vault's opening of " + p.name + " for record " +
                              short_id(record) +
                              " does not match its commitment on the ledger; it may have been "
                              "altered"};
        }
        out.openings.push_back(*found);
    }
    return out;
}

protocol::RangeOpening opening_of(const protocol::RangeOpenings& openings,
                                  const ProvableRecord& record, std::string_view field) {
    if (openings.ledger != record.ledger || openings.record != record.record) {
        throw ActionError{"the openings are of record " + short_id(openings.record) +
                          " on ledger " + short_id(openings.ledger) +
                          ", not of the evidence's record " + short_id(record.record) +
                          " on ledger " + short_id(record.ledger)};
    }
    const auto found = std::ranges::find(openings.openings, field, &protocol::RangeOpening::name);
    if (found == openings.openings.end()) {
        std::string names;
        for (const protocol::RangeOpening& o : openings.openings) {
            names += (names.empty() ? "" : ", ") + o.name;
        }
        throw ActionError{"the openings hold none of " + std::string(field) +
                          " (they hold: " + names + ")"};
    }
    return *found;
}

} // namespace kanhe::client
