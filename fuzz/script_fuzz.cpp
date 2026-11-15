// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// A script's metadata (spec v0.18) comes from whoever approves a script, and
// reaches every verifier inside the evidence of the records it made: reading
// it must refuse what is not one, never crash, and what it accepts must
// encode back to metadata that reads the same, with safe paths in order.

#include <cstddef>
#include <cstdint>

#include <kanhe/core/cbor.hpp>
#include <kanhe/core/protocol/scripts.hpp>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    const auto value = kanhe::cbor::decode({data, size});
    if (!value) {
        return 0;
    }
    const auto script = kanhe::protocol::decode_script(*value);
    if (!script) {
        return 0;
    }
    const auto again = kanhe::protocol::encode_script(*script);
    if (!again || kanhe::protocol::decode_script(*again) != script) {
        __builtin_trap();
    }
    for (std::size_t i = 0; i < script->files.size(); ++i) {
        if (!kanhe::protocol::valid_script_path(script->files[i].path) ||
            (i > 0 && !(script->files[i - 1].path < script->files[i].path))) {
            __builtin_trap();
        }
    }
    return 0;
}
