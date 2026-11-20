// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include <algorithm>
#include <array>
#include <limits>
#include <string>
#include <utility>
#include <vector>

#include <kanhe/core/protocol/claims.hpp>
#include <kanhe/core/protocol/ranges.hpp>

#include "reader.hpp"

namespace kanhe::protocol {

namespace {

using detail::entry;
using detail::MapReader;

constexpr std::uint64_t int64_max =
    static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max());
constexpr std::uint64_t int64_min_magnitude = int64_max + 1; // 2^63
constexpr std::size_t max_decimal_text = 40;

bool valid_name(std::string_view name) {
    return !name.empty() && name.size() <= max_provable_name;
}

bool valid_currency(std::string_view currency) {
    return currency.size() == 3 &&
           std::ranges::all_of(currency, [](char c) { return c >= 'A' && c <= 'Z'; });
}

bool digit(char c) {
    return c >= '0' && c <= '9';
}

/// Strictly ascending by their UTF-8 bytes (std::string compares as unsigned
/// char).
template <class T>
bool names_ascending(std::span<const T> items) {
    for (std::size_t i = 1; i < items.size(); ++i) {
        if (!(items[i - 1].name < items[i].name)) {
            return false;
        }
    }
    return true;
}

Status check_encoding(const ProvableEncoding& e) {
    switch (e.type) {
    case ProvableEncoding::Type::number:
        if (e.scale > max_number_scale || !e.currency.empty()) {
            return fail(Errc::malformed,
                        "a provable number's encoding is [\"number\", scale of 0 to 18]");
        }
        return {};
    case ProvableEncoding::Type::money:
        if (e.scale > max_money_scale || !valid_currency(e.currency)) {
            return fail(Errc::malformed, "a provable amount's encoding is [\"money\", currency of "
                                         "three upper-case letters, scale of 0 to 4]");
        }
        return {};
    case ProvableEncoding::Type::date:
        if (e.scale != 0 || !e.currency.empty()) {
            return fail(Errc::malformed, "a provable date's encoding is [\"date\"]");
        }
        return {};
    }
    return fail(Errc::malformed, "a provable value's encoding is not number, money, or date");
}

/// A signed integer from its sign and magnitude, if it is an int64.
Result<std::int64_t> signed_x(bool negative, std::uint64_t magnitude) {
    if (!negative) {
        if (magnitude > int64_max) {
            return fail(Errc::malformed,
                        "a bound is out of range: its integer is not within -2^63 to 2^63 - 1");
        }
        return static_cast<std::int64_t>(magnitude);
    }
    if (magnitude > int64_min_magnitude) {
        return fail(Errc::malformed,
                    "a bound is out of range: its integer is not within -2^63 to 2^63 - 1");
    }
    if (magnitude == int64_min_magnitude) {
        return std::numeric_limits<std::int64_t>::min();
    }
    return -static_cast<std::int64_t>(magnitude);
}

/// A CBOR integer's sign and magnitude; nullopt for anything else, and for
/// -2^64, whose magnitude does not fit (out of range all the same).
struct Signed {
    bool negative = false;
    std::uint64_t magnitude = 0;
    bool overflow = false;
};
std::optional<Signed> integer_of(const cbor::Value& v) {
    if (const auto u = v.as_uint64()) {
        return Signed{false, *u, false};
    }
    if (const auto n = v.as_negative()) {
        // -1 - n, whose magnitude is n + 1.
        if (n->n == std::numeric_limits<std::uint64_t>::max()) {
            return Signed{true, 0, true};
        }
        return Signed{true, n->n + 1, false};
    }
    return std::nullopt;
}

/// `value` times 10^scale, unless it overflows 64 bits.
bool scale_up(std::uint64_t& value, unsigned scale) {
    for (unsigned i = 0; i < scale; ++i) {
        if (value > std::numeric_limits<std::uint64_t>::max() / 10) {
            return false;
        }
        value *= 10;
    }
    return true;
}

Result<std::int64_t> number_x(unsigned scale, const cbor::Value& bound) {
    if (const auto integer = integer_of(bound)) {
        std::uint64_t magnitude = integer->magnitude;
        if (integer->overflow || !scale_up(magnitude, scale)) {
            return fail(Errc::malformed,
                        "a bound is out of range: its integer is not within -2^63 to 2^63 - 1");
        }
        return signed_x(integer->negative, magnitude);
    }
    // -?[0-9]+(\.[0-9]+)?, at most 40 characters.
    const std::string* text = bound.as_text();
    auto not_a_number = [] {
        return fail(Errc::malformed, "a bound is not a number (an integer, or a decimal text of at "
                                     "most 40 characters)");
    };
    if (text == nullptr || text->size() > max_decimal_text) {
        return not_a_number();
    }
    std::string_view s = *text;
    const bool negative = s.starts_with('-');
    if (negative) {
        s.remove_prefix(1);
    }
    const std::size_t dot = s.find('.');
    const std::string_view whole = s.substr(0, dot);
    const std::string_view fraction =
        dot == std::string_view::npos ? std::string_view() : s.substr(dot + 1);
    if (whole.empty() || !std::ranges::all_of(whole, digit) ||
        (dot != std::string_view::npos &&
         (fraction.empty() || !std::ranges::all_of(fraction, digit)))) {
        return not_a_number();
    }
    if (fraction.size() > scale) {
        return fail(Errc::malformed,
                    "a bound has more digits after the point than its provable value's scale");
    }
    // The digits, the fraction's padded to `scale`: x's magnitude.
    std::uint64_t magnitude = 0;
    bool overflow = false;
    auto take = [&](char c) {
        const auto d = static_cast<std::uint64_t>(c - '0');
        if (magnitude > (std::numeric_limits<std::uint64_t>::max() - d) / 10) {
            overflow = true;
            return;
        }
        magnitude = magnitude * 10 + d;
    };
    for (const char c : whole) {
        take(c);
    }
    for (const char c : fraction) {
        take(c);
    }
    if (overflow || !scale_up(magnitude, scale - static_cast<unsigned>(fraction.size()))) {
        return fail(Errc::malformed,
                    "a bound is out of range: its integer is not within -2^63 to 2^63 - 1");
    }
    return signed_x(negative && magnitude != 0, magnitude);
}

Result<std::int64_t> money_x(const ProvableEncoding& e, const cbor::Value& bound) {
    const cbor::Array* parts = bound.as_array();
    const std::optional<Signed> amount =
        parts != nullptr && parts->size() == 3 ? integer_of((*parts)[0]) : std::nullopt;
    const std::string* currency = amount ? (*parts)[1].as_text() : nullptr;
    const auto scale = currency != nullptr ? (*parts)[2].as_uint64() : std::nullopt;
    if (!scale || !valid_currency(*currency) || *scale > max_money_scale) {
        return fail(Errc::malformed, "a bound is not money ([amount, currency, scale])");
    }
    if (*currency != e.currency) {
        return fail(Errc::malformed, "a bound is in another currency than its provable value's");
    }
    if (*scale != e.scale) {
        return fail(Errc::malformed, "a bound has another scale than its provable value's");
    }
    if (amount->overflow) {
        return fail(Errc::malformed,
                    "a bound is out of range: its integer is not within -2^63 to 2^63 - 1");
    }
    return signed_x(amount->negative, amount->magnitude);
}

int days_in_month(int year, int month) {
    if (month == 2) {
        return year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) ? 29 : 28;
    }
    return month == 4 || month == 6 || month == 9 || month == 11 ? 30 : 31;
}

/// Days from 1970-01-01 in the proleptic Gregorian calendar (H. Hinnant's
/// days_from_civil).
std::int64_t days_from_civil(std::int64_t y, unsigned m, unsigned d) {
    y -= m <= 2 ? 1 : 0;
    const std::int64_t era = (y >= 0 ? y : y - 399) / 400;
    const auto yoe = static_cast<std::uint64_t>(y - era * 400);
    const std::uint64_t doy = (153 * (m > 2 ? m - 3 : m + 9) + 2) / 5 + d - 1;
    const std::uint64_t doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146'097 + static_cast<std::int64_t>(doe) - 719'468;
}

Result<std::int64_t> date_x(const cbor::Value& bound) {
    // [0-9]{4}-[0-9]{2}-[0-9]{2}
    const std::string* text = bound.as_text();
    if (text == nullptr || text->size() != 10 || (*text)[4] != '-' || (*text)[7] != '-') {
        return fail(Errc::malformed, "a bound is not a date (YYYY-MM-DD)");
    }
    auto number = [&](std::size_t at, std::size_t n) -> std::optional<int> {
        int out = 0;
        for (std::size_t i = at; i < at + n; ++i) {
            if (!digit((*text)[i])) {
                return std::nullopt;
            }
            out = out * 10 + ((*text)[i] - '0');
        }
        return out;
    };
    const auto year = number(0, 4);
    const auto month = number(5, 2);
    const auto day = number(8, 2);
    if (!year || !month || !day) {
        return fail(Errc::malformed, "a bound is not a date (YYYY-MM-DD)");
    }
    if (*month < 1 || *month > 12 || *day < 1 || *day > days_in_month(*year, *month)) {
        return fail(Errc::malformed, "a bound is not a valid date");
    }
    if (*year < 1) {
        return fail(Errc::malformed, "a bound is before 0001-01-01");
    }
    return days_from_civil(*year, static_cast<unsigned>(*month), static_cast<unsigned>(*day));
}

void append_bytes(Bytes& out, ByteView bytes) {
    cbor::append_head(out, cbor::Major::bytes, bytes.size());
    out.insert(out.end(), bytes.begin(), bytes.end());
}

void append_text(Bytes& out, std::string_view text) {
    cbor::append_head(out, cbor::Major::text, text.size());
    out.insert(out.end(), text.begin(), text.end());
}

} // namespace

std::string_view name(ProvableEncoding::Type type) noexcept {
    switch (type) {
    case ProvableEncoding::Type::number:
        return "number";
    case ProvableEncoding::Type::money:
        return "money";
    case ProvableEncoding::Type::date:
        return "date";
    }
    return "unknown";
}

// ---------------------------------------------------------------------------
// Provable values (key 8)
// ---------------------------------------------------------------------------

Result<cbor::Value> provable_encoding_value(const ProvableEncoding& encoding) {
    KANHE_CHECK(check_encoding(encoding));
    cbor::Array parts{cbor::Value::text(std::string(name(encoding.type)))};
    if (encoding.type == ProvableEncoding::Type::money) {
        parts.push_back(cbor::Value::text(encoding.currency));
    }
    if (encoding.type != ProvableEncoding::Type::date) {
        parts.push_back(cbor::Value::unsigned_integer(encoding.scale));
    }
    return cbor::Value::array(std::move(parts));
}

Result<ProvableEncoding> provable_encoding_from(const cbor::Value& value) {
    const cbor::Array* parts = value.as_array();
    const std::string* kind = parts != nullptr && !parts->empty() ? (*parts)[0].as_text() : nullptr;
    if (kind == nullptr) {
        return fail(Errc::malformed, "a provable value's encoding is not [type, ...]");
    }
    ProvableEncoding e;
    if (*kind == "number") {
        const auto scale = parts->size() == 2 ? (*parts)[1].as_uint64() : std::nullopt;
        if (!scale || *scale > max_number_scale) {
            return fail(Errc::malformed,
                        "a provable number's encoding is not [\"number\", scale of 0 to 18]");
        }
        e.type = ProvableEncoding::Type::number;
        e.scale = static_cast<std::uint8_t>(*scale);
        return e;
    }
    if (*kind == "money") {
        const std::string* currency = parts->size() == 3 ? (*parts)[1].as_text() : nullptr;
        const auto scale = currency != nullptr ? (*parts)[2].as_uint64() : std::nullopt;
        if (!scale || !valid_currency(*currency) || *scale > max_money_scale) {
            return fail(Errc::malformed, "a provable amount's encoding is not [\"money\", currency "
                                         "of three upper-case letters, scale of 0 to 4]");
        }
        e.type = ProvableEncoding::Type::money;
        e.currency = *currency;
        e.scale = static_cast<std::uint8_t>(*scale);
        return e;
    }
    if (*kind == "date") {
        if (parts->size() != 1) {
            return fail(Errc::malformed, "a provable date's encoding is not [\"date\"]");
        }
        e.type = ProvableEncoding::Type::date;
        return e;
    }
    return fail(Errc::malformed, "a provable value's encoding is not number, money, or date");
}

Status check_provable(std::span<const ProvableValue> values, std::uint64_t field_count) {
    if (values.empty()) {
        return fail(Errc::non_canonical, "an empty list of provable values must be omitted");
    }
    if (values.size() > max_provable_values) {
        return fail(Errc::limit_exceeded, "a registration has at most 64 provable values");
    }
    if (values.size() > field_count) {
        return fail(Errc::malformed, "a registration has more provable values than fields");
    }
    for (const ProvableValue& v : values) {
        if (!valid_name(v.name)) {
            return fail(Errc::malformed, "a provable value's name is 1 to 64 bytes of text");
        }
        if (v.commitment.size() != range_commitment_size) {
            return fail(Errc::malformed, "a provable value's commitment is 32 bytes");
        }
        KANHE_CHECK(check_encoding(v.encoding));
    }
    if (!names_ascending(values)) {
        return fail(Errc::malformed,
                    "a registration's provable values are strictly ascending by name");
    }
    return {};
}

Result<cbor::Value> provable_list_value(std::span<const ProvableValue> values,
                                        std::uint64_t field_count) {
    KANHE_CHECK(check_provable(values, field_count));
    cbor::Array items;
    for (const ProvableValue& v : values) {
        KANHE_TRY(cbor::Value encoding, provable_encoding_value(v.encoding));
        items.push_back(cbor::Value::array(
            {cbor::Value::text(v.name), std::move(encoding), cbor::Value::bytes(v.commitment)}));
    }
    return cbor::Value::array(std::move(items));
}

Result<std::vector<ProvableValue>> provable_list_from(const cbor::Value& value,
                                                      std::uint64_t field_count) {
    KANHE_TRY(const cbor::Array* items, detail::as_array(value));
    // The limits before anything is kept.
    if (items->empty()) {
        return fail(Errc::non_canonical, "an empty list of provable values must be omitted");
    }
    if (items->size() > max_provable_values) {
        return fail(Errc::limit_exceeded, "a registration has at most 64 provable values");
    }
    if (items->size() > field_count) {
        return fail(Errc::malformed, "a registration has more provable values than fields");
    }
    std::vector<ProvableValue> out;
    out.reserve(items->size());
    for (const cbor::Value& item : *items) {
        const cbor::Array* parts = item.as_array();
        if (parts == nullptr || parts->size() != 3) {
            return fail(Errc::malformed, "a provable value is [name, encoding, commitment]");
        }
        ProvableValue v;
        KANHE_TRY(v.name, detail::as_text((*parts)[0]));
        KANHE_TRY(v.encoding, provable_encoding_from((*parts)[1]));
        KANHE_TRY(v.commitment, detail::as_bytes_value((*parts)[2]));
        out.push_back(std::move(v));
    }
    KANHE_CHECK(check_provable(out, field_count));
    return out;
}

// ---------------------------------------------------------------------------
// Range proofs (bundle key 12)
// ---------------------------------------------------------------------------

Status check_range_proof(const RangeProof& p) {
    if (!valid_name(p.field)) {
        return fail(Errc::malformed, "a range proof's field is 1 to 64 bytes of text");
    }
    if (!p.low && !p.high) {
        return fail(Errc::malformed, "a range proof has a low (key 2), a high (key 3), or both");
    }
    if ((p.low && p.low->is_null()) || (p.high && p.high->is_null())) {
        return fail(Errc::malformed, "a range proof's bound is never null");
    }
    if (p.proof.empty() || p.proof.size() > max_range_proof_size) {
        return fail(Errc::malformed, "a range proof's proof is 1 to 262,144 bytes");
    }
    if (p.context && (p.context->empty() || p.context->size() > max_range_context)) {
        return fail(Errc::malformed, "a range proof's context is 1 to 64 bytes");
    }
    return {};
}

Result<cbor::Value> range_proof_value(const RangeProof& p) {
    KANHE_CHECK(check_range_proof(p));
    cbor::Map map{entry(1, cbor::Value::text(p.field))};
    if (p.low) {
        map.push_back(entry(2, *p.low));
    }
    if (p.high) {
        map.push_back(entry(3, *p.high));
    }
    map.push_back(entry(4, cbor::Value::unsigned_integer(p.system)));
    map.push_back(entry(5, cbor::Value::bytes(p.proof)));
    if (p.context) {
        map.push_back(entry(6, cbor::Value::bytes(*p.context)));
    }
    return cbor::Value::map(std::move(map));
}

Result<RangeProof> range_proof_from(const cbor::Value& value) {
    KANHE_TRY(MapReader reader, MapReader::open(value));
    RangeProof p;
    KANHE_TRY(p.field, reader.need_text(1));
    if (const cbor::Value* low = reader.get(2)) {
        p.low = *low;
    }
    if (const cbor::Value* high = reader.get(3)) {
        p.high = *high;
    }
    KANHE_TRY(p.system, reader.need_uint(4));
    KANHE_TRY(p.proof, reader.need_bytes(5));
    KANHE_TRY(p.context, reader.opt_bytes(6));
    KANHE_CHECK(reader.finish());
    KANHE_CHECK(check_range_proof(p));
    return p;
}

// ---------------------------------------------------------------------------
// Range openings files
// ---------------------------------------------------------------------------

namespace {

Status check_openings(const RangeOpenings& file) {
    if (file.openings.empty() || file.openings.size() > max_provable_values) {
        return fail(Errc::malformed, "a range openings file holds 1 to 64 openings");
    }
    for (const RangeOpening& o : file.openings) {
        if (!valid_name(o.name) || o.salt.size() != range_salt_size) {
            return fail(Errc::malformed,
                        "a range opening is [name of 1 to 64 bytes, 32-byte salt, x]");
        }
    }
    if (!names_ascending(std::span(file.openings))) {
        return fail(Errc::malformed, "a range openings file's names are strictly ascending");
    }
    return {};
}

} // namespace

Result<Bytes> encode_range_openings(const RangeOpenings& file) {
    KANHE_CHECK(check_openings(file));
    cbor::Array openings;
    for (const RangeOpening& o : file.openings) {
        openings.push_back(cbor::Value::array(
            {cbor::Value::text(o.name), cbor::Value::bytes(o.salt), cbor::Value::integer(o.x)}));
    }
    KANHE_TRY(Bytes out,
              cbor::encode(cbor::Value::map({entry(1, cbor::Value::bytes(file.ledger.bytes())),
                                             entry(2, cbor::Value::bytes(file.record.bytes())),
                                             entry(3, cbor::Value::array(std::move(openings)))})));
    if (out.size() > max_range_openings_file) {
        return fail(Errc::limit_exceeded, "a range openings file is at most 65,536 bytes");
    }
    return out;
}

Result<RangeOpenings> decode_range_openings(ByteView encoded) {
    if (encoded.size() > max_range_openings_file) {
        return fail(Errc::limit_exceeded, "a range openings file is at most 65,536 bytes");
    }
    KANHE_TRY(cbor::Value value, cbor::decode(encoded));
    KANHE_TRY(MapReader reader, MapReader::open(value));
    RangeOpenings file;
    KANHE_TRY(file.ledger, reader.need_id(1));
    KANHE_TRY(file.record, reader.need_id(2));
    KANHE_TRY(const cbor::Value* list, reader.need(3));
    KANHE_TRY(const cbor::Array* items, detail::as_array(*list));
    if (items->empty() || items->size() > max_provable_values) {
        return fail(Errc::malformed, "a range openings file holds 1 to 64 openings");
    }
    for (const cbor::Value& item : *items) {
        const cbor::Array* parts = item.as_array();
        const auto x =
            parts != nullptr && parts->size() == 3 ? (*parts)[2].as_int64() : std::nullopt;
        if (!x) {
            return fail(Errc::malformed, "a range opening is [name, 32-byte salt, x within -2^63 "
                                         "to 2^63 - 1]");
        }
        RangeOpening o;
        KANHE_TRY(o.name, detail::as_text((*parts)[0]));
        KANHE_TRY(o.salt, detail::as_bytes_value((*parts)[1]));
        o.x = *x;
        file.openings.push_back(std::move(o));
    }
    KANHE_CHECK(reader.finish());
    KANHE_CHECK(check_openings(file));
    return file;
}

// ---------------------------------------------------------------------------
// Values, bounds, the commitment, the transcript, and the words
// ---------------------------------------------------------------------------

Result<std::int64_t> range_bound_x(const ProvableEncoding& encoding, const cbor::Value& bound) {
    switch (encoding.type) {
    case ProvableEncoding::Type::number:
        return number_x(encoding.scale, bound);
    case ProvableEncoding::Type::money:
        return money_x(encoding, bound);
    case ProvableEncoding::Type::date:
        return date_x(bound);
    }
    return fail(Errc::malformed, "a provable value's encoding is not number, money, or date");
}

Result<std::pair<std::uint64_t, std::uint64_t>>
range_public_values(const ProvableEncoding& encoding, const RangeProof& proof) {
    if (!proof.low && !proof.high) {
        return fail(Errc::malformed, "a range proof has a low (key 2), a high (key 3), or both");
    }
    std::pair<std::uint64_t, std::uint64_t> out{0, std::numeric_limits<std::uint64_t>::max()};
    std::optional<std::int64_t> low;
    if (proof.low) {
        KANHE_TRY(low, range_bound_x(encoding, *proof.low));
        out.first = range_v(*low);
    }
    if (proof.high) {
        KANHE_TRY(const std::int64_t high, range_bound_x(encoding, *proof.high));
        if (low && *low > high) {
            return fail(Errc::malformed, "a range proof's low is above its high");
        }
        out.second = range_v(high);
    }
    return out;
}

Result<Bytes> range_commitment(const crypto::Provider& provider, ByteView salt, std::int64_t x) {
    if (salt.size() != range_salt_size) {
        return fail(Errc::invalid_argument, "a provable value's salt is 32 bytes");
    }
    const std::uint64_t v = range_v(x);
    std::array<std::uint8_t, 8> be{};
    for (std::size_t i = 0; i < be.size(); ++i) {
        be[i] = static_cast<std::uint8_t>(v >> (56 - 8 * i));
    }
    KANHE_TRY(crypto::Digest c, provider.digest(crypto::HashAlg::sha256,
                                                {as_bytes(range_commitment_domain), salt, be}));
    const ByteView bytes = c.bytes();
    return Bytes(bytes.begin(), bytes.end());
}

Bytes range_transcript(const Id& ledger, const Id& record, std::string_view field,
                       ByteView commitment, std::uint64_t lo, std::uint64_t hi, ByteView context) {
    // ["kanhe.range/1", ledger, record, field, C, lo', hi', context]
    Bytes out;
    cbor::append_head(out, cbor::Major::array, 8);
    append_text(out, range_transcript_label);
    append_bytes(out, ledger.bytes());
    append_bytes(out, record.bytes());
    append_text(out, field);
    append_bytes(out, commitment);
    cbor::append_head(out, cbor::Major::unsigned_integer, lo);
    cbor::append_head(out, cbor::Major::unsigned_integer, hi);
    append_bytes(out, context);
    return out;
}

std::string range_words(const ProvableEncoding& encoding, const RangeProof& proof) {
    const bool written = (proof.low || proof.high) &&
                         (!proof.low || range_bound_x(encoding, *proof.low)) &&
                         (!proof.high || range_bound_x(encoding, *proof.high));
    if (written) {
        // In a claim's words (section 11): a term "at least", "at most", or
        // "between".
        ClaimTerm term{proof.field, "", std::string(name(encoding.type)), cbor::Value()};
        if (proof.low && proof.high) {
            term.op = "between";
            term.value = cbor::Value::array({*proof.low, *proof.high});
        } else if (proof.low) {
            term.op = ">=";
            term.value = *proof.low;
        } else {
            term.op = "<=";
            term.value = *proof.high;
        }
        return condition_text(std::vector<ClaimTerm>{std::move(term)});
    }
    // Bounds the encoding does not read, as they are.
    if (proof.low && proof.high) {
        return proof.field + " is between " + cbor::diagnostic(*proof.low) + " and " +
               cbor::diagnostic(*proof.high);
    }
    if (proof.low) {
        return proof.field + " is at least " + cbor::diagnostic(*proof.low);
    }
    if (proof.high) {
        return proof.field + " is at most " + cbor::diagnostic(*proof.high);
    }
    return proof.field;
}

} // namespace kanhe::protocol
