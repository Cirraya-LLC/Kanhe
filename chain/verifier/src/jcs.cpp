// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include <algorithm>
#include <array>
#include <charconv>
#include <cstdint>
#include <iterator>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <kanhe/verifier/jcs.hpp>

namespace kanhe::verifier {

namespace {

/// Whether `cp` is a noncharacter (Unicode, section 23.7): U+FDD0 to U+FDEF,
/// and the last two code points of every plane.
constexpr bool noncharacter(std::uint32_t cp) noexcept {
    return (cp >= 0xFDD0 && cp <= 0xFDEF) || (cp & 0xFFFEU) == 0xFFFEU;
}

/// The UTF-16 code units of UTF-8 text; nullopt if it is not UTF-8. Sets
/// `*nonchar`, if given, when the text holds a noncharacter.
std::optional<std::u16string> utf16(std::string_view text, bool* nonchar = nullptr) {
    std::u16string out;
    std::size_t i = 0;
    while (i < text.size()) {
        const auto b0 = static_cast<std::uint8_t>(text[i]);
        std::uint32_t cp = 0;
        std::size_t n = 0;
        if (b0 < 0x80) {
            cp = b0;
            n = 1;
        } else if (b0 >= 0xC2 && b0 <= 0xDF) {
            cp = b0 & 0x1FU;
            n = 2;
        } else if (b0 >= 0xE0 && b0 <= 0xEF) {
            cp = b0 & 0x0FU;
            n = 3;
        } else if (b0 >= 0xF0 && b0 <= 0xF4) {
            cp = b0 & 0x07U;
            n = 4;
        } else {
            return std::nullopt;
        }
        if (i + n > text.size()) {
            return std::nullopt;
        }
        for (std::size_t k = 1; k < n; ++k) {
            const auto b = static_cast<std::uint8_t>(text[i + k]);
            if ((b & 0xC0U) != 0x80U) {
                return std::nullopt;
            }
            cp = (cp << 6) | (b & 0x3FU);
        }
        // Overlong forms, surrogates, and code points past U+10FFFF.
        if ((n == 3 && cp < 0x800) || (n == 4 && (cp < 0x10000 || cp > 0x10FFFF)) ||
            (cp >= 0xD800 && cp <= 0xDFFF)) {
            return std::nullopt;
        }
        if (nonchar != nullptr && noncharacter(cp)) {
            *nonchar = true;
        }
        if (cp >= 0x10000) {
            cp -= 0x10000;
            out.push_back(static_cast<char16_t>(0xD800 + (cp >> 10)));
            out.push_back(static_cast<char16_t>(0xDC00 + (cp & 0x3FFU)));
        } else {
            out.push_back(static_cast<char16_t>(cp));
        }
        i += n;
    }
    return out;
}

/// Whether `text`, a string's or (if `name`) a member name's, is UTF-8 that
/// I-JSON allows: no noncharacter.
Status i_json_text(std::string_view text, bool name) {
    bool nonchar = false;
    if (!utf16(text, &nonchar)) {
        return fail(Errc::malformed,
                    name ? "a JSON member name that is not UTF-8" : "JSON text that is not UTF-8");
    }
    if (nonchar) {
        return fail(Errc::malformed,
                    name ? "a JSON member name with a noncharacter, which I-JSON excludes"
                         : "JSON text with a noncharacter, which I-JSON excludes");
    }
    return {};
}

Status write_string(std::string& out, std::string_view text) {
    if (auto s = i_json_text(text, false); !s) {
        return s;
    }
    static constexpr std::string_view hex = "0123456789abcdef";
    out.push_back('"');
    for (const char c : text) {
        const auto u = static_cast<unsigned char>(c);
        switch (c) {
        case '"':
            out += "\\\"";
            break;
        case '\\':
            out += "\\\\";
            break;
        case '\b':
            out += "\\b";
            break;
        case '\f':
            out += "\\f";
            break;
        case '\n':
            out += "\\n";
            break;
        case '\r':
            out += "\\r";
            break;
        case '\t':
            out += "\\t";
            break;
        default:
            if (u < 0x20) {
                out += "\\u00";
                out.push_back(hex[u >> 4]);
                out.push_back(hex[u & 0xFU]);
            } else {
                out.push_back(c);
            }
        }
    }
    out.push_back('"');
    return {};
}

Status write(std::string& out, const Json& value, int depth) {
    if (depth > max_json_depth) {
        return fail(Errc::limit_exceeded, "JSON nested too deeply");
    }
    switch (value.type()) {
    case Json::value_t::null:
        out += "null";
        return {};
    case Json::value_t::boolean:
        out += value.get<bool>() ? "true" : "false";
        return {};
    case Json::value_t::number_integer:
    case Json::value_t::number_unsigned: {
        std::int64_t n = 0;
        if (value.is_number_unsigned()) {
            const auto u = value.get<std::uint64_t>();
            if (u > static_cast<std::uint64_t>(max_json_integer)) {
                return fail(Errc::unsupported, "a JSON integer past 2^53 - 1");
            }
            n = static_cast<std::int64_t>(u);
        } else {
            n = value.get<std::int64_t>();
        }
        if (n > max_json_integer || n < -max_json_integer) {
            return fail(Errc::unsupported, "a JSON integer past 2^53 - 1");
        }
        std::array<char, 24> buffer{};
        const auto [end, ec] = std::to_chars(buffer.data(), buffer.data() + buffer.size(), n);
        out.append(buffer.data(), end);
        return {};
    }
    case Json::value_t::number_float:
        return fail(Errc::unsupported, "a JSON number that is not an integer");
    case Json::value_t::string:
        return write_string(out, value.get_ref<const std::string&>());
    case Json::value_t::array: {
        out.push_back('[');
        bool first = true;
        for (const Json& item : value) {
            if (!first) {
                out.push_back(',');
            }
            first = false;
            if (auto s = write(out, item, depth + 1); !s) {
                return s;
            }
        }
        out.push_back(']');
        return {};
    }
    case Json::value_t::object: {
        // The members, sorted once with their values beside them: looking
        // each name up again would read every name before it (an
        // ordered_json object is a list), n^2 for n members.
        using Member = Json::object_t::value_type;
        std::vector<std::pair<std::u16string, const Member*>> members;
        members.reserve(value.size());
        for (const Member& member : value.get_ref<const Json::object_t&>()) {
            if (auto s = i_json_text(member.first, true); !s) {
                return s;
            }
            members.emplace_back(*utf16(member.first), &member);
        }
        std::ranges::sort(members, {}, &std::pair<std::u16string, const Member*>::first);
        out.push_back('{');
        bool first = true;
        for (const auto& [units, member] : members) {
            (void)units;
            if (!first) {
                out.push_back(',');
            }
            first = false;
            if (auto s = write_string(out, member->first); !s) {
                return s;
            }
            out.push_back(':');
            if (auto s = write(out, member->second, depth + 1); !s) {
                return s;
            }
        }
        out.push_back('}');
        return {};
    }
    default:
        return fail(Errc::unsupported, "a JSON value of another kind");
    }
}

/// What parse_i_json looks for as the text is read (nlohmann's SAX
/// interface), keeping only the names of each object open: a name given
/// twice, a noncharacter, a value nested more than max_json_depth deep. It
/// builds no value, so it neither copies nor recurses.
struct Checks {
    bool repeated = false;
    bool nonchar = false;
    bool too_deep = false;
    std::size_t open = 0;                     // containers open: the depth of the next value
    std::vector<std::set<std::string>> names; // of each object open

    bool value() {
        too_deep = too_deep || open > static_cast<std::size_t>(max_json_depth);
        return true;
    }
    bool text(const std::string& got) {
        static_cast<void>(utf16(got, &nonchar));
        return true;
    }
    bool null() { return value(); }
    bool boolean(bool) { return value(); }
    bool number_integer(Json::number_integer_t) { return value(); }
    bool number_unsigned(Json::number_unsigned_t) { return value(); }
    bool number_float(Json::number_float_t, const Json::string_t&) { return value(); }
    bool string(Json::string_t& got) { return value() && text(got); }
    bool binary(Json::binary_t&) { return value(); }
    bool start_object(std::size_t) {
        value();
        ++open;
        names.emplace_back();
        return true;
    }
    bool key(Json::string_t& got) {
        repeated = repeated || !names.back().insert(got).second;
        return text(got);
    }
    bool end_object() {
        --open;
        names.pop_back();
        return true;
    }
    bool start_array(std::size_t) {
        value();
        ++open;
        return true;
    }
    bool end_array() {
        --open;
        return true;
    }
    bool parse_error(std::size_t, const std::string&, const nlohmann::detail::exception&) {
        return false;
    }
};

/// Builds the value parse_i_json returns, once Checks has passed it (no
/// name twice, nothing nested past max_json_depth): what nlohmann's own
/// builder makes, members in the order written, in time linear in the text.
/// Its builder adds a member to an ordered_json object by first reading
/// every name before it (the object is a list), n^2 for n members; here an
/// object's members are kept as they come and made into the object, as
/// they are, when it closes.
struct Builder {
    struct Open {
        bool object = false;
        Json array;
        std::vector<std::pair<std::string, Json>> members;
        std::string key;
    };
    std::vector<Open> open; // the containers open, innermost last
    Json root;

    bool put(Json got) {
        if (open.empty()) {
            root = std::move(got);
        } else if (Open& top = open.back(); top.object) {
            top.members.emplace_back(std::move(top.key), std::move(got));
        } else {
            top.array.get_ref<Json::array_t&>().push_back(std::move(got));
        }
        return true;
    }
    bool null() { return put(Json(nullptr)); }
    bool boolean(bool got) { return put(Json(got)); }
    bool number_integer(Json::number_integer_t got) { return put(Json(got)); }
    bool number_unsigned(Json::number_unsigned_t got) { return put(Json(got)); }
    bool number_float(Json::number_float_t got, const Json::string_t&) { return put(Json(got)); }
    bool string(Json::string_t& got) { return put(Json(got)); }
    bool binary(Json::binary_t& got) { return put(Json(got)); }
    bool start_object(std::size_t) {
        open.emplace_back().object = true;
        return true;
    }
    bool key(Json::string_t& got) {
        open.back().key = got;
        return true;
    }
    bool end_object() {
        auto members = std::move(open.back().members);
        open.pop_back();
        Json object = Json::object();
        object.get_ref<Json::object_t&>() = Json::object_t(std::make_move_iterator(members.begin()),
                                                           std::make_move_iterator(members.end()));
        return put(std::move(object));
    }
    bool start_array(std::size_t) {
        open.emplace_back().array = Json::array();
        return true;
    }
    bool end_array() {
        Json array = std::move(open.back().array);
        open.pop_back();
        return put(std::move(array));
    }
    bool parse_error(std::size_t, const std::string&, const nlohmann::detail::exception&) {
        return false;
    }
};

} // namespace

Result<std::string> jcs(const Json& value) {
    std::string out;
    if (auto s = write(out, value, 0); !s) {
        return std::unexpected(s.error());
    }
    return out;
}

Result<Json> parse_i_json(std::string_view text) {
    if (text.starts_with("\xEF\xBB\xBF")) {
        return fail(Errc::malformed, "JSON text that begins with a byte order mark");
    }
    // JSON has no NUL outside a string (and none unescaped in one), but the
    // parser takes one for the end of its input.
    if (text.find('\0') != std::string_view::npos) {
        return fail(Errc::malformed, "not JSON");
    }
    // First a pass that builds nothing, so that nothing copies or recurses
    // however deep the text nests (the parser's callbacks copy each object
    // into its parent, recursively): it sees a repeated name (the parser
    // keeps the last value), a noncharacter (the parser passes them), and
    // the nesting. (The parser refuses the rest: text that is not UTF-8, a
    // surrogate's escape alone, a number that overflows a double.)
    Checks checks;
    if (!Json::sax_parse(text, &checks)) {
        return fail(Errc::malformed, "not JSON");
    }
    if (checks.repeated) {
        return fail(Errc::malformed, "a JSON object names a member twice");
    }
    if (checks.too_deep) {
        return fail(Errc::limit_exceeded, "JSON nested too deeply");
    }
    if (checks.nonchar) {
        return fail(Errc::malformed, "JSON text with a noncharacter, which I-JSON excludes");
    }
    // Then the value itself, nested at most 64 deep.
    Builder builder;
    if (!Json::sax_parse(text, &builder)) {
        return fail(Errc::malformed, "not JSON");
    }
    return std::move(builder.root);
}

Result<Json> parse_jcs(std::string_view text) {
    auto parsed = parse_i_json(text);
    if (!parsed) {
        return parsed;
    }
    Json value = std::move(*parsed);
    const auto again = jcs(value);
    if (!again) {
        return std::unexpected(again.error());
    }
    if (*again != text) {
        return fail(Errc::non_canonical, "JSON that is not in its canonical form (RFC 8785)");
    }
    return value;
}

} // namespace kanhe::verifier
