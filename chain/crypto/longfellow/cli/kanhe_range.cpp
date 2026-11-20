// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// kanhe-range: the range proofs of <kanhe/crypto/longfellow.hpp> over JSON on
// standard input and output, for programs that do not link the C++ library
// (an independent verifier, a generator of test vectors). Every number is an
// unsigned 64-bit integer written as a decimal string, every byte string
// lowercase hex.

#include <algorithm>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <exception>
#include <fstream>
#include <initializer_list>
#include <iostream>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#include <nlohmann/json.hpp>

#include <kanhe/core/bytes.hpp>
#include <kanhe/core/error.hpp>
#include <kanhe/crypto/longfellow.hpp>

#if defined(KANHE_HAVE_ZSTD)
#include <zstd.h>
#endif

namespace {

namespace range = kanhe::crypto::longfellow;
using kanhe::Bytes;
using kanhe::ByteView;
using nlohmann::json;

constexpr int exit_ok = 0;
constexpr int exit_refused = 1;
constexpr int exit_usage = 2;
constexpr std::size_t max_input_size = 8 * 1024 * 1024;

constexpr std::string_view overview_help = R"(Usage: kanhe-range COMMAND [--help]

Zero-knowledge range proofs over a salted SHA-256 commitment (Longfellow ZK):

    C = SHA-256("Kanhe range v1" || salt || BE64(value))  and  low <= value <= high

C, low, and high are public; the 32-byte salt and the value stay private.
prove and verify read one JSON object on standard input and write one on
standard output. Numbers are unsigned 64-bit integers written as decimal
strings; bytes are lowercase hex.

Commands:
  prove     Prove that a committed value lies in a range
  verify    Verify a range proof
  circuit   Write the circuit, serialized, to a file

Run `kanhe-range COMMAND --help` for a command's input and output.
)";

constexpr std::string_view prove_help = R"(Usage: kanhe-range prove < INPUT

Proves that the value committed to with the salt lies in [low, high]. The
transcript (the proof's Fiat-Shamir transcript's initial bytes) binds the proof
to its context; the verifier supplies the same bytes.

Input:  {"salt": HEX (32 bytes), "value": N, "low": N, "high": N,
         "transcript": HEX, "seed": HEX (32 bytes, optional)}
Output: {"commitment": HEX (32 bytes), "proof": HEX}

Without "seed", the proof's randomness is fresh. A seed makes the proof
reproducible, for test vectors only: whoever knows the seed can recover the
salt and the value from the proof.

Exit status: 0 proved; 1 the value is outside the range, with
{"error": MESSAGE}; 2 a usage or input error, or no proof made, with
{"error": MESSAGE}.
)";

constexpr std::string_view verify_help = R"(Usage: kanhe-range verify < INPUT

Verifies a proof that the value committed to in C lies in [low, high], for the
transcript the proof was made with.

Input:  {"commitment": HEX (32 bytes), "low": N, "high": N,
         "transcript": HEX, "proof": HEX}
Output: {"valid": true}, or {"valid": false} with the reason on standard error

Exit status: 0 valid; 1 not valid; 2 a usage or input error, or no verdict,
with {"error": MESSAGE}.
)";

constexpr std::string_view circuit_help = R"(Usage: kanhe-range circuit --out FILE [--zstd]

Writes the circuit in Longfellow's serialized form (about 2 MB) to FILE, for
verifiers that load the circuit instead of building it. It is read back, and
its id computed again, before it is written.

Options:
  --out FILE   The file to write
  --zstd       Compress it with zstd (to about 23 KB), where built with zstd

Output: {"id": HEX, "size": N}: the circuit's pinned id, and the file's size
in bytes (a number).

Exit status: 0 written; 1 not written, with {"error": MESSAGE}; 2 a usage
error.
)";

/// A usage or input error, reported as {"error": ...} with exit status 2.
struct InputError {
    std::string message;
};

[[noreturn]] void refuse(std::string message) {
    throw InputError{std::move(message)};
}

std::string in_quotes(std::string_view key) {
    return "\"" + std::string(key) + "\"";
}

void print(const json& value) {
    std::cout << value.dump() << '\n';
}

int error(int code, std::string_view message) {
    print(json{{"error", message}});
    return code;
}

std::string read_input() {
    std::string text;
    std::vector<char> buffer(64 * 1024);
    std::size_t n = 0;
    while ((n = std::fread(buffer.data(), 1, buffer.size(), stdin)) > 0) {
        text.append(buffer.data(), n);
        if (text.size() > max_input_size) {
            refuse("the input is longer than 8 MiB");
        }
    }
    if (std::ferror(stdin) != 0) {
        refuse("cannot read standard input");
    }
    return text;
}

/// The input's JSON object, with no fields but `keys`.
json parse_object(const std::string& text, std::initializer_list<std::string_view> keys) {
    json doc = json::parse(text, nullptr, /*allow_exceptions=*/false);
    if (doc.is_discarded()) {
        refuse("the input is not JSON");
    }
    if (!doc.is_object()) {
        refuse("the input must be a JSON object");
    }
    for (const auto& item : doc.items()) {
        if (std::find(keys.begin(), keys.end(), item.key()) == keys.end()) {
            refuse("unknown field " + in_quotes(item.key()));
        }
    }
    return doc;
}

const json& field(const json& doc, std::string_view key) {
    const auto it = doc.find(key);
    if (it == doc.end()) {
        refuse("missing field " + in_quotes(key));
    }
    return *it;
}

/// A decimal string, canonical: digits only, no leading zero, at most 2^64 - 1.
std::uint64_t number(const json& doc, std::string_view key) {
    const json& value = field(doc, key);
    if (!value.is_string()) {
        refuse(in_quotes(key) + " must be a decimal string");
    }
    const auto& text = value.get_ref<const std::string&>();
    const bool digits = !text.empty() && std::all_of(text.begin(), text.end(),
                                                     [](char c) { return c >= '0' && c <= '9'; });
    std::uint64_t out = 0;
    const auto* end = text.data() + text.size();
    const auto [ptr, ec] = std::from_chars(text.data(), end, out);
    if (!digits || (text.size() > 1 && text.front() == '0') || ec != std::errc{} || ptr != end) {
        refuse(in_quotes(key) + " must be a decimal string of an unsigned 64-bit integer");
    }
    return out;
}

/// Hexadecimal bytes, of `size` bytes if given.
Bytes bytes(const json& doc, std::string_view key, std::optional<std::size_t> size) {
    const json& value = field(doc, key);
    if (!value.is_string()) {
        refuse(in_quotes(key) + " must be a hex string");
    }
    auto decoded = kanhe::from_hex(value.get_ref<const std::string&>());
    if (!decoded) {
        refuse(in_quotes(key) + " must be a hex string");
    }
    if (size && decoded->size() != *size) {
        refuse(in_quotes(key) + " must be " + std::to_string(*size) + " bytes");
    }
    return std::move(*decoded);
}

Bytes transcript(const json& doc) {
    Bytes out = bytes(doc, "transcript", std::nullopt);
    if (out.size() > range::max_range_transcript_size) {
        refuse("\"transcript\" is at most 1 MiB");
    }
    return out;
}

int prove(const std::string& text) {
    const json doc = parse_object(text, {"salt", "value", "low", "high", "transcript", "seed"});
    const Bytes salt = bytes(doc, "salt", range::range_salt_size);
    const std::uint64_t value = number(doc, "value");
    const std::uint64_t low = number(doc, "low");
    const std::uint64_t high = number(doc, "high");
    const Bytes context = transcript(doc);
    std::optional<Bytes> seed;
    if (const auto it = doc.find("seed"); it != doc.end() && !it->is_null()) {
        seed = bytes(doc, "seed", range::range_seed_size);
    }
    if (value < low || value > high) {
        return error(exit_refused, "the value is outside the range");
    }
    const auto commitment = range::range_commitment(salt, value);
    if (!commitment) {
        return error(exit_usage, commitment.error().detail);
    }
    const auto proof =
        range::prove_range(salt, value, low, high, context,
                           seed ? std::optional<ByteView>(*seed) : std::optional<ByteView>());
    if (!proof) {
        return error(exit_usage, proof.error().detail);
    }
    print(json{{"commitment", kanhe::to_hex(*commitment)}, {"proof", kanhe::to_hex(*proof)}});
    return exit_ok;
}

int verify(const std::string& text) {
    const json doc = parse_object(text, {"commitment", "low", "high", "transcript", "proof"});
    const Bytes commitment = bytes(doc, "commitment", range::range_commitment_size);
    const std::uint64_t low = number(doc, "low");
    const std::uint64_t high = number(doc, "high");
    const Bytes context = transcript(doc);
    const Bytes proof = bytes(doc, "proof", std::nullopt);
    const auto result = range::verify_range(commitment, low, high, context, proof);
    if (result) {
        print(json{{"valid", true}});
        return exit_ok;
    }
    // No verdict: the circuit could not be built as pinned.
    if (result.error().code == kanhe::Errc::crypto_failure) {
        return error(exit_usage, result.error().detail);
    }
    std::cerr << "kanhe-range: " << result.error().detail << '\n';
    print(json{{"valid", false}});
    return exit_refused;
}

#if defined(KANHE_HAVE_ZSTD)
std::optional<Bytes> compress(ByteView data) {
    Bytes out(ZSTD_compressBound(data.size()));
    const std::size_t size = ZSTD_compress(out.data(), out.size(), data.data(), data.size(), 19);
    if (ZSTD_isError(size) != 0) {
        return std::nullopt;
    }
    out.resize(size);
    return out;
}
#endif

int circuit(const std::vector<std::string_view>& args) {
    std::optional<std::string> path;
    bool zstd = false;
    for (std::size_t i = 0; i < args.size(); ++i) {
        if (args[i] == "--out" && i + 1 < args.size()) {
            path = std::string(args[++i]);
        } else if (args[i] == "--zstd") {
            zstd = true;
        } else {
            std::cerr << "kanhe-range circuit: unexpected argument " << in_quotes(args[i]) << "\n\n"
                      << circuit_help;
            return exit_usage;
        }
    }
    if (!path) {
        std::cerr << "kanhe-range circuit: --out FILE is required\n\n" << circuit_help;
        return exit_usage;
    }
#if !defined(KANHE_HAVE_ZSTD)
    if (zstd) {
        std::cerr << "kanhe-range circuit: this build has no zstd\n";
        return exit_usage;
    }
#endif
    auto serialized = range::range_circuit_bytes();
    if (!serialized) {
        return error(exit_refused, serialized.error().detail);
    }
    Bytes contents = std::move(*serialized);
#if defined(KANHE_HAVE_ZSTD)
    if (zstd) {
        auto compressed = compress(contents);
        if (!compressed) {
            return error(exit_refused, "zstd failed");
        }
        contents = std::move(*compressed);
    }
#endif
    std::ofstream out(*path, std::ios::binary | std::ios::trunc);
    out.write(reinterpret_cast<const char*>(contents.data()),
              static_cast<std::streamsize>(contents.size()));
    out.close();
    if (!out) {
        return error(exit_refused, "cannot write " + *path);
    }
    print(json{{"id", kanhe::to_hex(range::range_circuit_id())}, {"size", contents.size()}});
    return exit_ok;
}

bool asks_for_help(const std::vector<std::string_view>& args) {
    return std::any_of(args.begin(), args.end(),
                       [](std::string_view a) { return a == "--help" || a == "-h"; });
}

std::optional<std::string_view> help_of(std::string_view command) {
    if (command == "prove") {
        return prove_help;
    }
    if (command == "verify") {
        return verify_help;
    }
    if (command == "circuit") {
        return circuit_help;
    }
    return std::nullopt;
}

int run(const std::vector<std::string_view>& args) {
    if (args.empty()) {
        std::cerr << overview_help;
        return exit_usage;
    }
    const std::string_view command = args.front();
    const std::vector<std::string_view> rest(args.begin() + 1, args.end());
    if (command == "--help" || command == "-h" || command == "help") {
        if (rest.empty()) {
            std::cout << overview_help;
            return exit_ok;
        }
        if (const auto help = help_of(rest.front()); help && rest.size() == 1) {
            std::cout << *help;
            return exit_ok;
        }
        std::cerr << "kanhe-range: no such command " << in_quotes(rest.front()) << "\n\n"
                  << overview_help;
        return exit_usage;
    }
    const auto help = help_of(command);
    if (!help) {
        std::cerr << "kanhe-range: no such command " << in_quotes(command) << "\n\n"
                  << overview_help;
        return exit_usage;
    }
    if (asks_for_help(rest)) {
        std::cout << *help;
        return exit_ok;
    }
    if (command == "circuit") {
        return circuit(rest);
    }
    if (!rest.empty()) {
        std::cerr << "kanhe-range " << command << ": unexpected argument "
                  << in_quotes(rest.front()) << " (the input is read from standard input)\n\n"
                  << *help;
        return exit_usage;
    }
    const std::string input = read_input();
    return command == "prove" ? prove(input) : verify(input);
}

} // namespace

int main(int argc, char** argv) {
    try {
        return run(std::vector<std::string_view>(argv + 1, argv + argc));
    } catch (const InputError& e) {
        return error(exit_usage, e.message);
    } catch (const std::exception& e) {
        return error(exit_usage, e.what());
    }
}
