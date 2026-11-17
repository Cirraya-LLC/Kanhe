// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include <algorithm>
#include <array>
#include <cstdint>
#include <format>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

#include <nlohmann/json.hpp>

#include <kanhe/client/errors.hpp>
#include <kanhe/client/public_witness.hpp>
#include <kanhe/client/support.hpp>
#include <kanhe/client/witness.hpp>
#include <kanhe/core/cbor.hpp>
#include <kanhe/core/protocol/keys.hpp>
#include <kanhe/core/protocol/witness.hpp>

namespace kanhe::client {

namespace {

using node::http::Response;

Response json_answer(int status, const nlohmann::json& body) {
    Response r;
    r.status = status;
    r.principal = "witness";
    const std::string text = body.dump() + "\n";
    r.body.assign(text.begin(), text.end());
    return r;
}

Response refusal(int status, std::string_view code, std::string_view message) {
    return json_answer(status, {{"error", {{"code", code}, {"message", message}}}});
}

Response too_many(std::string_view message, protocol::Timestamp retry_ms) {
    auto r = refusal(429, "limit_exceeded", message);
    r.headers.emplace_back(
        "Retry-After", std::to_string(std::max<protocol::Timestamp>(1, (retry_ms + 999) / 1000)));
    return r;
}

Response refusal(const Error& error) {
    switch (error.code) {
    case Errc::not_found:
        return refusal(404, "not_found", error.detail);
    case Errc::rejected:
        return refusal(409, "rejected", error.detail);
    case Errc::verification_failed:
        return refusal(422, "verification_failed", error.detail);
    case Errc::unavailable:
        return refusal(503, "unavailable", error.detail);
    default:
        return refusal(400, "malformed", error.detail);
    }
}

/// The ledger a cosign request is for, from its checkpoint.
Result<protocol::Id> ledger_of(ByteView request) {
    auto decoded = protocol::decode_cosign_request(request);
    if (!decoded) {
        return std::unexpected(decoded.error());
    }
    auto checkpoint = protocol::parse_checkpoint(decoded->checkpoint);
    if (!checkpoint) {
        return std::unexpected(checkpoint.error());
    }
    return checkpoint->checkpoint.ledger_id;
}

constexpr protocol::Timestamp day_ms = 24 * 60 * 60'000;

using Ipv4 = std::array<std::uint8_t, 4>;
using Ipv6 = std::array<std::uint8_t, 16>;

/// A dotted IPv4 address as servers and proxies write one: four decimal
/// numbers up to 255, with no leading zeros.
std::optional<Ipv4> parse_ipv4(std::string_view text) {
    Ipv4 out{};
    for (std::size_t part = 0; part < out.size(); ++part) {
        if (part > 0) {
            if (!text.starts_with('.')) {
                return std::nullopt;
            }
            text.remove_prefix(1);
        }
        std::size_t digits = 0;
        unsigned value = 0;
        while (digits < text.size() && digits < 4 && text[digits] >= '0' && text[digits] <= '9') {
            value = value * 10 + static_cast<unsigned>(text[digits] - '0');
            ++digits;
        }
        if (digits == 0 || digits > 3 || value > 255 || (digits > 1 && text.front() == '0')) {
            return std::nullopt;
        }
        out[part] = static_cast<std::uint8_t>(value);
        text.remove_prefix(digits);
    }
    if (!text.empty()) {
        return std::nullopt;
    }
    return out;
}

/// Groups of one to four hex digits separated by ':', appended to `out`
/// (eight at most); an empty text has none.
bool hex_groups(std::string_view text, std::vector<std::uint16_t>& out) {
    if (text.empty()) {
        return true;
    }
    while (true) {
        const std::size_t colon = text.find(':');
        const std::string_view group = text.substr(0, colon);
        if (group.empty() || group.size() > 4 || out.size() == 8) {
            return false;
        }
        unsigned value = 0;
        for (const char c : group) {
            const int digit = c >= '0' && c <= '9'   ? c - '0'
                              : c >= 'a' && c <= 'f' ? c - 'a' + 10
                              : c >= 'A' && c <= 'F' ? c - 'A' + 10
                                                     : -1;
            if (digit < 0) {
                return false;
            }
            value = value * 16 + static_cast<unsigned>(digit);
        }
        out.push_back(static_cast<std::uint16_t>(value));
        if (colon == std::string_view::npos) {
            return true;
        }
        text.remove_prefix(colon + 1);
    }
}

/// An IPv6 address in text (RFC 4291 section 2.2: "::" once at most, and a
/// dotted IPv4 address as the last 32 bits), without its zone ("%eth0").
std::optional<Ipv6> parse_ipv6(std::string_view text) {
    text = text.substr(0, text.find('%'));
    std::optional<Ipv4> ipv4;
    if (const std::size_t dot = text.find('.'); dot != std::string_view::npos) {
        const std::size_t colon = text.rfind(':');
        if (colon == std::string_view::npos || colon > dot) {
            return std::nullopt;
        }
        ipv4 = parse_ipv4(text.substr(colon + 1));
        if (!ipv4) {
            return std::nullopt;
        }
        // What comes before it, less the colon that separates them (unless
        // that colon is half of a "::").
        text = text.substr(0, colon + 1);
        if (!text.ends_with("::")) {
            text.remove_suffix(1);
        }
    }
    const std::size_t gap = text.find("::");
    std::vector<std::uint16_t> head;
    std::vector<std::uint16_t> tail;
    if (gap == std::string_view::npos) {
        if (!hex_groups(text, head)) {
            return std::nullopt;
        }
    } else if (text.find("::", gap + 1) != std::string_view::npos ||
               !hex_groups(text.substr(0, gap), head) || !hex_groups(text.substr(gap + 2), tail)) {
        return std::nullopt;
    }
    std::vector<std::uint16_t>& last = gap == std::string_view::npos ? head : tail;
    if (ipv4) {
        const Ipv4& b = *ipv4;
        last.push_back(static_cast<std::uint16_t>((static_cast<unsigned>(b[0]) << 8U) |
                                                  static_cast<unsigned>(b[1])));
        last.push_back(static_cast<std::uint16_t>((static_cast<unsigned>(b[2]) << 8U) |
                                                  static_cast<unsigned>(b[3])));
    }
    const std::size_t groups = head.size() + tail.size();
    if (gap == std::string_view::npos ? groups != 8 : groups > 7) {
        return std::nullopt;
    }
    Ipv6 out{};
    auto put = [&out](std::size_t at, std::uint16_t group) {
        out[2 * at] = static_cast<std::uint8_t>(static_cast<unsigned>(group) >> 8U);
        out[2 * at + 1] = static_cast<std::uint8_t>(static_cast<unsigned>(group) & 0xffU);
    };
    for (std::size_t i = 0; i < head.size(); ++i) {
        put(i, head[i]);
    }
    for (std::size_t i = 0; i < tail.size(); ++i) {
        put(8 - tail.size() + i, tail[i]);
    }
    return out;
}

/// Whether the first `count` bytes are zero.
bool zeros(const Ipv6& address, std::size_t count) {
    for (std::size_t i = 0; i < count; ++i) {
        if (address[i] != 0) {
            return false;
        }
    }
    return true;
}

/// ::ffff:a.b.c.d: an IPv4 caller on an IPv6 socket.
bool mapped_ipv4(const Ipv6& address) {
    return zeros(address, 10) && address[10] == 0xff && address[11] == 0xff;
}

std::string ipv4_text(std::uint8_t a, std::uint8_t b, std::uint8_t c, std::uint8_t d) {
    return std::format("{}.{}.{}.{}", static_cast<unsigned>(a), static_cast<unsigned>(b),
                       static_cast<unsigned>(c), static_cast<unsigned>(d));
}

bool loopback(std::string_view address) {
    if (const auto ipv4 = parse_ipv4(address)) {
        return (*ipv4)[0] == 127;
    }
    if (const auto ipv6 = parse_ipv6(address)) {
        if (mapped_ipv4(*ipv6)) {
            return (*ipv6)[12] == 127;
        }
        return zeros(*ipv6, 15) && (*ipv6)[15] == 1;
    }
    return false;
}

} // namespace

std::string quota_address(std::string_view address) {
    if (const auto ipv4 = parse_ipv4(address)) {
        const Ipv4& b = *ipv4;
        return ipv4_text(b[0], b[1], b[2], b[3]);
    }
    if (const auto ipv6 = parse_ipv6(address)) {
        const Ipv6& b = *ipv6;
        if (mapped_ipv4(b)) {
            return ipv4_text(b[12], b[13], b[14], b[15]);
        }
        auto group = [&b](std::size_t i) {
            return (static_cast<unsigned>(b[2 * i]) << 8U) | static_cast<unsigned>(b[2 * i + 1]);
        };
        return std::format("{:x}:{:x}:{:x}:{:x}::/64", group(0), group(1), group(2), group(3));
    }
    return std::string(address);
}

std::string forwarded_address(const node::http::Request& request, std::string_view peer) {
    if (!loopback(peer)) {
        return std::string(peer);
    }
    // Each proxy appends the address it was called from: the last is the
    // one this host's proxy saw; those before it, anyone may have written.
    std::optional<std::string_view> forwarded;
    for (const auto& [field, value] : request.headers) {
        if (field == "x-forwarded-for") {
            forwarded = value;
        }
    }
    if (!forwarded) {
        return std::string(peer);
    }
    std::string_view last = *forwarded;
    if (const std::size_t comma = last.rfind(','); comma != std::string_view::npos) {
        last.remove_prefix(comma + 1);
    }
    while (!last.empty() && (last.front() == ' ' || last.front() == '\t')) {
        last.remove_prefix(1);
    }
    while (!last.empty() && (last.back() == ' ' || last.back() == '\t')) {
        last.remove_suffix(1);
    }
    if (parse_ipv4(last) || parse_ipv6(last)) {
        return std::string(last);
    }
    return std::string(peer);
}

Result<Bytes> encode_witness_registration(const WitnessRegistration& registration) {
    return cbor::encode(cbor::Value::map(
        {{cbor::Value::integer(1), cbor::Value::bytes(registration.genesis)},
         {cbor::Value::integer(2), cbor::Value::bytes(registration.cosign_request)}}));
}

Result<WitnessRegistration> decode_witness_registration(ByteView encoded) {
    if (encoded.size() > max_witness_registration) {
        return fail(Errc::limit_exceeded, "a registration is at most 4 MiB");
    }
    auto value = cbor::decode(encoded);
    if (!value) {
        return std::unexpected(value.error());
    }
    const cbor::Map* map = value->as_map();
    const cbor::Value* genesis = value->find(1);
    const cbor::Value* request = value->find(2);
    if (map == nullptr || map->size() != 2 || genesis == nullptr ||
        genesis->as_bytes() == nullptr || request == nullptr || request->as_bytes() == nullptr) {
        return fail(Errc::malformed, "a registration is {1: genesis entry, 2: cosign request}");
    }
    return WitnessRegistration{Bytes(genesis->as_bytes()->begin(), genesis->as_bytes()->end()),
                               Bytes(request->as_bytes()->begin(), request->as_bytes()->end())};
}

PublicWitness::PublicWitness(std::filesystem::path dir, std::shared_ptr<const crypto::Signer> key,
                             std::string name, PublicWitnessLimits limits)
    : dir_(std::move(dir)), key_(std::move(key)), name_(std::move(name)), limits_(limits) {
    std::filesystem::create_directories(dir_);
    std::error_code ec;
    for (const auto& entry : std::filesystem::directory_iterator(dir_, ec)) {
        if (entry.path().extension() == ".cbor") {
            ++ledgers_;
        }
    }
}

std::size_t PublicWitness::ledgers() const {
    const std::lock_guard lock(mutex_);
    return ledgers_;
}

std::optional<Response> PublicWitness::handle(const node::http::Request& request,
                                              std::string_view address, protocol::Timestamp now) {
    const bool get = request.method == "GET";
    const bool post = request.method == "POST";
    auto only = [](std::string_view method) {
        auto r = refusal(405, "unsupported", "method not allowed");
        r.headers.emplace_back("Allow", std::string(method));
        return r;
    };
    if (request.path == "/v1/witness") {
        return get ? info() : only("GET");
    }
    if (request.path != "/v1/witness/register" && request.path != "/v1/witness/cosign") {
        return std::nullopt;
    }
    if (!post) {
        return only("POST");
    }
    const bool registering = request.path == "/v1/witness/register";
    // No I/O thread waits for another caller.
    const std::unique_lock lock(mutex_, std::try_to_lock);
    if (!lock) {
        auto busy = refusal(503, "unavailable", "the witness is busy; retry");
        busy.headers.emplace_back("Retry-After", "1");
        return busy;
    }
    return registering ? register_ledger(request.body, address, now) : cosign(request.body, now);
}

Response PublicWitness::info() const {
    const std::lock_guard lock(mutex_);
    const auto key = cbor::encode(protocol::encode_public_key(key_->public_key()));
    return json_answer(200, {{"witness", true},
                             {"name", name_},
                             {"key", key ? to_hex(*key) : std::string()},
                             {"algorithm", crypto::name(key_->public_key().algorithm)},
                             {"ledgers", ledgers_},
                             {"limits",
                              {{"max_ledgers", limits_.max_ledgers},
                               {"registrations_per_day", limits_.registrations_per_day},
                               {"cosign_interval_ms", limits_.cosign_interval}}}});
}

Response PublicWitness::register_ledger(ByteView body, std::string_view address,
                                        protocol::Timestamp now) {
    auto registration = decode_witness_registration(body);
    if (!registration) {
        return refusal(registration.error());
    }
    auto ledger = ledger_of(registration->cosign_request);
    if (!ledger) {
        return refusal(ledger.error());
    }
    const std::filesystem::path path = witness_state_path(dir_, *ledger);
    if (std::filesystem::exists(path)) {
        // Registered before: a cosign request like any other.
        return cosign_followed(*ledger, registration->cosign_request, now);
    }
    if (ledgers_ >= limits_.max_ledgers) {
        return refusal(503, "unavailable", "this witness follows as many ledgers as it takes");
    }
    const std::uint64_t today = now / day_ms;
    for (auto it = registrations_.begin(); it != registrations_.end();) {
        it = it->second.first == today ? std::next(it) : registrations_.erase(it);
    }
    auto& [day, count] = registrations_[quota_address(address)];
    day = today;
    if (count >= limits_.registrations_per_day) {
        return too_many("too many registrations from this address today",
                        (today + 1) * day_ms - now);
    }
    // Every attempt counts, before its checks: they are the work the quota
    // bounds (reading the genesis entry, writing its state, checking the
    // log key's signature), and a caller cannot spend another's quota, only
    // that of the address it calls from (an IPv6 address's /64).
    ++count;
    WitnessState state;
    try {
        state = state_from_genesis(registration->genesis, "", *ledger);
        add_witnessed(dir_, state);
    } catch (const ActionError& e) {
        return refusal(400, "malformed", e.message);
    }
    auto cosigned = witness_cosign(dir_, *key_, registration->cosign_request, now);
    if (!cosigned) {
        // Followed only once it has proved its log key.
        std::error_code ec;
        std::filesystem::remove(path, ec);
        return refusal(cosigned.error());
    }
    ++ledgers_;
    cosigned_[protocol::key_of(*ledger)] = now;
    Response r;
    r.principal = "witness";
    r.status = 201;
    r.content_type = "application/cose";
    r.body = std::move(*cosigned);
    return r;
}

Response PublicWitness::cosign(ByteView body, protocol::Timestamp now) {
    auto ledger = ledger_of(body);
    if (!ledger) {
        return refusal(ledger.error());
    }
    if (!std::filesystem::exists(witness_state_path(dir_, *ledger))) {
        return refusal(404, "not_found",
                       "this witness does not follow the ledger: register it first "
                       "(POST /v1/witness/register)");
    }
    return cosign_followed(*ledger, body, now);
}

Response PublicWitness::cosign_followed(const protocol::Id& ledger, ByteView request,
                                        protocol::Timestamp now) {
    const auto key = protocol::key_of(ledger);
    if (const auto it = cosigned_.find(key);
        it != cosigned_.end() && now < it->second + limits_.cosign_interval) {
        return too_many("this ledger was cosigned a moment ago",
                        it->second + limits_.cosign_interval - now);
    }
    auto cosigned = witness_cosign(dir_, *key_, request, now);
    if (!cosigned) {
        return refusal(cosigned.error());
    }
    cosigned_[key] = now;
    Response r;
    r.principal = "witness";
    r.content_type = "application/cose";
    r.body = std::move(*cosigned);
    return r;
}

} // namespace kanhe::client
