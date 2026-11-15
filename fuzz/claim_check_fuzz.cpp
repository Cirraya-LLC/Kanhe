// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// A condition checked against a record's private data: the condition comes
// from a peer's access request (spec v0.15), which the ledger has read and
// taken, and the data may hold any value. Checking must never crash.
// Input: a CBOR array [condition, {field name: value}].

#include <cstddef>
#include <cstdint>
#include <vector>

#include <kanhe/client/claims.hpp>
#include <kanhe/core/cbor.hpp>
#include <kanhe/core/protocol/claims.hpp>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    namespace protocol = kanhe::protocol;
    const auto value = kanhe::cbor::decode({data, size});
    if (!value) {
        return 0;
    }
    const kanhe::cbor::Array* parts = value->as_array();
    if (parts == nullptr || parts->size() != 2 || (*parts)[1].as_map() == nullptr) {
        return 0;
    }
    auto condition = protocol::decode_claim_condition((*parts)[0]);
    if (!condition) {
        return 0;
    }
    std::vector<protocol::RecordField> fields;
    for (const kanhe::cbor::MapEntry& entry : *(*parts)[1].as_map()) {
        if (const std::string* name = entry.key.as_text()) {
            fields.push_back({*name, {}, entry.value});
        }
    }
    protocol::Claim claim;
    claim.condition = std::move(*condition);
    static_cast<void>(kanhe::client::check_claim(claim, fields));
    return 0;
}
