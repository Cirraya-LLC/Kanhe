// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// Statements held for approval (spec v0.20): hold requests come from
// whoever has a submit token (POST /v1/approvals), held files from disk,
// from Raft entries, and from snapshots. Decoding must never crash, and
// whatever decodes must encode back to the same bytes.

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdlib>

#include <kanhe/core/cbor.hpp>
#include <kanhe/node/approvals.hpp>

namespace node = kanhe::node;
namespace cbor = kanhe::cbor;

namespace {

void require(bool condition) {
    if (!condition) {
        std::abort();
    }
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    const kanhe::ByteView input(data, size);
    if (const auto request = node::decode_hold_request(input)) {
        const auto again = node::encode_hold_request(*request);
        require(again && std::ranges::equal(*again, input));
        require(request->approvals.empty() && request->preparer.empty());
    }
    if (const auto held = node::decode_held_statement(input)) {
        const auto again = node::encode_held_statement(*held);
        require(again && std::ranges::equal(*again, input));
        require(held->approvals.size() <= kanhe::protocol::max_approvals);
        require(held->state != node::HeldState::open || held->ended_at == 0);
    }
    if (const auto value = cbor::decode(input)) {
        if (const auto changes = node::decode_held_changes(*value)) {
            const auto again = cbor::encode(node::held_changes_value(*changes));
            require(again && std::ranges::equal(*again, input));
        }
    }
    return 0;
}
