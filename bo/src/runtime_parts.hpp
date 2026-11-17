// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// The runtime's routines, one function each that writes its body
// (runtime_cbor.cpp, runtime_math.cpp), and what they share.

#pragma once

#include <cstdint>

#include <kanhe/bo/runtime.hpp>
#include <kanhe/bo/wasm.hpp>

namespace kanhe::bo::runtime::detail {

using wasm::FunctionBuilder;

/// Writes a routine's body; `rt` gives the routines it calls.
using Define = void (*)(Runtime& rt, FunctionBuilder& b);

/// Returns from the function being written, with zeros for its results.
inline void return_zeros(Runtime& rt, FunctionBuilder& b) {
    for (const wasm::ValType type : rt.module().type_of(b.self()).results) {
        if (type == wasm::ValType::i64) {
            b.i64(0);
        } else {
            b.i32(0);
        }
    }
    b.return_();
}

/// After a call that may fail: in a module that records failures
/// (Runtime::record_failures), the call returns from a failure while
/// recording is on, and so does the function being written, with zeros.
/// Elsewhere such a call never returns, and nothing is written.
inline void after_failure(Runtime& rt, FunctionBuilder& b) {
    if (rt.recording()) {
        return_zeros(rt, b);
    }
}

/// [] -> [i32]: 1 if recording is on and a failure is recorded. Only in a
/// module that records failures.
inline void push_failed(Runtime& rt, FunctionBuilder& b) {
    const Runtime::Recording& r = *rt.recording();
    b.global_get(r.on).global_get(r.length);
    b.op(wasm::Op::i32_eqz).op(wasm::Op::i32_eqz).op(wasm::Op::i32_and);
}

/// In a module that records failures: while recording is on, keeps the
/// reason `reason` pushes (its address and length) unless one is kept
/// already, and returns zeros. Writes nothing in other modules, where the
/// abort that follows is the only way out.
template <typename Push>
void record_failure(Runtime& rt, FunctionBuilder& b, const Push& reason) {
    if (!rt.recording()) {
        return;
    }
    const Runtime::Recording& r = *rt.recording();
    b.global_get(r.on);
    const wasm::Label on = b.if_();
    b.global_get(r.length).op(wasm::Op::i32_eqz);
    const wasm::Label first = b.if_();
    reason();
    b.global_set(r.length).global_set(r.at);
    b.end(first);
    return_zeros(rt, b);
    b.end(on);
}

/// Aborts with the reason if the i32 on the stack is not zero (or, while a
/// module records failures, keeps it and returns zeros).
inline void fail_if(Runtime& rt, FunctionBuilder& b, const Reason reason) {
    const wasm::Label then = b.if_();
    b.call(rt.fail(reason));
    after_failure(rt, b);
    b.end(then);
}

void define_read_input(Runtime& rt, FunctionBuilder& b);
void define_read_item(Runtime& rt, FunctionBuilder& b);
void define_item_end(Runtime& rt, FunctionBuilder& b);
void define_head_arg(Runtime& rt, FunctionBuilder& b);
void define_content(Runtime& rt, FunctionBuilder& b);
void define_map_get(Runtime& rt, FunctionBuilder& b);
void define_array_get(Runtime& rt, FunctionBuilder& b);
void define_out_reserve(Runtime& rt, FunctionBuilder& b);
void define_out_head_size(Runtime& rt, FunctionBuilder& b);
void define_out_head(Runtime& rt, FunctionBuilder& b);
void define_out_int(Runtime& rt, FunctionBuilder& b);
void define_out_bool(Runtime& rt, FunctionBuilder& b);
void define_out_null(Runtime& rt, FunctionBuilder& b);
void define_out_bytes(Runtime& rt, FunctionBuilder& b);
void define_out_text(Runtime& rt, FunctionBuilder& b);
void define_out_raw(Runtime& rt, FunctionBuilder& b);
void define_out_close(Runtime& rt, FunctionBuilder& b);
void define_out_finish(Runtime& rt, FunctionBuilder& b);
void define_add(Runtime& rt, FunctionBuilder& b);
void define_sub(Runtime& rt, FunctionBuilder& b);
void define_mul(Runtime& rt, FunctionBuilder& b);
void define_neg(Runtime& rt, FunctionBuilder& b);
void define_muldiv(Runtime& rt, FunctionBuilder& b);
void define_udiv128(Runtime& rt, FunctionBuilder& b);
void define_days_from_civil(Runtime& rt, FunctionBuilder& b);
void define_civil_from_days(Runtime& rt, FunctionBuilder& b);
void define_days_in_month(Runtime& rt, FunctionBuilder& b);
void define_local_days(Runtime& rt, FunctionBuilder& b);
void define_add_months(Runtime& rt, FunctionBuilder& b);
void define_date_parts(Runtime& rt, FunctionBuilder& b);
void define_check_date(Runtime& rt, FunctionBuilder& b);
void define_date_from_parts(Runtime& rt, FunctionBuilder& b);
void define_bytes_cmp(Runtime& rt, FunctionBuilder& b);
void define_bytes_eq(Runtime& rt, FunctionBuilder& b);
void define_read_call(Runtime& rt, FunctionBuilder& b);
void define_consent(Runtime& rt, FunctionBuilder& b);
void define_in_person(Runtime& rt, FunctionBuilder& b);
void define_out_needs(Runtime& rt, FunctionBuilder& b);
void define_expect_int(Runtime& rt, FunctionBuilder& b);
void define_expect_text(Runtime& rt, FunctionBuilder& b);
void define_expect_ledger(Runtime& rt, FunctionBuilder& b);
void define_expect_bool(Runtime& rt, FunctionBuilder& b);
void define_fail_numbered(Runtime& rt, FunctionBuilder& b);
void define_out_finish_at(Runtime& rt, FunctionBuilder& b);
void define_fail_with(Runtime& rt, FunctionBuilder& b);

} // namespace kanhe::bo::runtime::detail
