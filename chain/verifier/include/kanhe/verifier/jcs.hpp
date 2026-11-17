// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <cstdint>
#include <string>
#include <string_view>

#include <kanhe/core/error.hpp>
#include <kanhe/verifier/report.hpp>

/// JSON Canonicalization (RFC 8785, JCS) for the JSON credentials are made of
/// (credentials.hpp), and the strict I-JSON (RFC 7493) every JSON text a
/// verifier is given must be. Portable C++23, like core.
namespace kanhe::verifier {

/// The largest integer JCS writes exactly (2^53 - 1).
inline constexpr std::int64_t max_json_integer = 9'007'199'254'740'991;
/// How deep the JSON a verifier reads may nest: the value at the top is at
/// depth 0, its members' and items' values at 1, and so on. Nothing this
/// profile makes comes near it; it bounds the work hostile JSON costs.
inline constexpr int max_json_depth = 64;

/// The JCS serialization of `value`: members sorted by their names' UTF-16
/// code units, no whitespace, the shortest string escapes. Fails on a
/// number that is not an integer of at most 2^53 - 1 in magnitude (credentials
/// carry no others), on text that is not UTF-8 or holds a noncharacter (which
/// I-JSON excludes), and on a value nested more than `max_json_depth` deep.
[[nodiscard]] Result<std::string> jcs(const Json& value);

/// Parses `text` as strict I-JSON (RFC 7493): JSON (RFC 8259) in UTF-8 with
/// no byte order mark; no surrogate code point (an escaped half of a pair
/// alone) or noncharacter in any string or member name; no number an IEEE
/// 754 double cannot hold; no member name twice in one object. And nested at
/// most `max_json_depth` deep. Refused, in this order of precedence: a byte
/// order mark, "not JSON" (surrogates and numbers included), a name given
/// twice, nesting, a noncharacter.
[[nodiscard]] Result<Json> parse_i_json(std::string_view text);

/// Parses `text` as strict I-JSON and requires it to be the JCS
/// serialization of what it parses to: so no whitespace, and nothing written
/// two ways.
[[nodiscard]] Result<Json> parse_jcs(std::string_view text);

} // namespace kanhe::verifier
