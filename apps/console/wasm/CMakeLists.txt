# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya

# The web console's checks in the browser (decoding a payload, computing its
# presence challenge; a statement's id and an approval's challenge;
# verifying a proof file): an ES module and a separate .wasm file, which a native
# build embeds in the console when KANHE_CONSOLE_WASM_DIR names them.
add_executable(kanhe_console_wasm console_wasm.cpp)
set_target_properties(kanhe_console_wasm PROPERTIES OUTPUT_NAME kanhe-console SUFFIX ".mjs")
target_link_libraries(kanhe_console_wasm PRIVATE kanhe::verifier kanhe::crypto_openssl)
target_compile_features(kanhe_console_wasm PRIVATE cxx_std_23)
target_link_options(kanhe_console_wasm PRIVATE
    -sMODULARIZE=1
    -sEXPORT_ES6=1
    -sEXPORT_NAME=KanheConsole
    -sENVIRONMENT=web
    -sALLOW_MEMORY_GROWTH=1
    -sDYNAMIC_EXECUTION=0
    -sFILESYSTEM=0
    "-sEXPORTED_FUNCTIONS=_malloc,_free,_kanhe_describe_payload,_kanhe_presence_challenge,_kanhe_statement_id,_kanhe_approval_challenge,_kanhe_field_root,_kanhe_attachment_commitment,_kanhe_digest,_kanhe_proof_reset,_kanhe_proof_attachment,_kanhe_proof_range_context,_kanhe_proof_verify,_kanhe_free"
    "-sEXPORTED_RUNTIME_METHODS=HEAPU8,UTF8ToString")

# Range proofs (spec v0.22, section 11.3), checked as the browser verifier
# checks them: with the Longfellow layer, on the published circuit, embedded
# compressed by the verifier's own script and loaded on the first proof.
# Without them, the Verify screen reports proofs as not checked.
if(TARGET kanhe::crypto_longfellow)
    if(CMAKE_CROSSCOMPILING_EMULATOR)
        list(GET CMAKE_CROSSCOMPILING_EMULATOR 0 embed_node)
    else()
        find_program(embed_node NAMES node nodejs REQUIRED)
    endif()
    set(circuit_source "${CMAKE_CURRENT_BINARY_DIR}/range_circuit.cpp")
    set(embed_script "${PROJECT_SOURCE_DIR}/chain/verifier/wasm/embed-circuit.js")
    add_custom_command(
        OUTPUT "${circuit_source}"
        COMMAND "${embed_node}" "${embed_script}"
            "${PROJECT_SOURCE_DIR}/testvectors/range-circuit-1.bin.zst" "${circuit_source}"
        DEPENDS "${embed_script}" "${PROJECT_SOURCE_DIR}/testvectors/range-circuit-1.bin.zst"
        COMMENT "Embedding the range proofs' circuit in the console's checks")
    target_sources(kanhe_console_wasm PRIVATE "${circuit_source}")
    target_link_libraries(kanhe_console_wasm PRIVATE kanhe::crypto_longfellow)
    target_compile_definitions(kanhe_console_wasm PRIVATE KANHE_RANGE_PROOFS=1)
endif()
