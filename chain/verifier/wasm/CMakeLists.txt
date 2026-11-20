# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya

# The browser verifier: core, the OpenSSL provider, and report rendering
# compiled to WebAssembly, then packaged into one self-contained HTML page
# (kanhe-verify.html) that works offline, even when opened from disk.
add_executable(kanhe_verifier_wasm verifier_wasm.cpp)
set_target_properties(kanhe_verifier_wasm PROPERTIES OUTPUT_NAME kanhe-verifier SUFFIX ".js")
target_link_libraries(kanhe_verifier_wasm PRIVATE kanhe::verifier kanhe::crypto_openssl)
target_compile_definitions(kanhe_verifier_wasm PRIVATE KANHE_VERSION="${PROJECT_VERSION}")
target_compile_features(kanhe_verifier_wasm PRIVATE cxx_std_23)
target_link_options(kanhe_verifier_wasm PRIVATE
    -sMODULARIZE=1
    -sEXPORT_NAME=KanheVerifier
    -sSINGLE_FILE=1
    # Base64, not the default binary-in-UTF-8 string: the page must stay pure
    # ASCII to survive being emailed, re-encoded, or served without a charset.
    -sSINGLE_FILE_BINARY_ENCODE=0
    -sENVIRONMENT=web,node
    -sALLOW_MEMORY_GROWTH=1
    -sDYNAMIC_EXECUTION=0
    -sFILESYSTEM=0
    "-sEXPORTED_FUNCTIONS=_malloc,_free,_kanhe_version,_kanhe_reset,_kanhe_set_expected_ledger,_kanhe_add_witness,_kanhe_add_network_witness,_kanhe_add_timestamp_root,_kanhe_add_trust_node,_kanhe_add_distrust,_kanhe_set_range_context,_kanhe_add_attachment,_kanhe_verify,_kanhe_credential_addresses,_kanhe_verify_credential,_kanhe_free"
    "-sEXPORTED_RUNTIME_METHODS=HEAPU8,UTF8ToString,stringToUTF8,lengthBytesUTF8")

# Range proofs (spec v0.22, section 11.3), checked with the Longfellow layer
# on the published circuit, embedded compressed and loaded on the first proof
# (a quarter of the time building it takes, and half the memory). Without
# them, proofs are reported as not checked.
if(TARGET kanhe::crypto_longfellow)
    # Emscripten's own Node.js, which its toolchain names as the emulator.
    if(CMAKE_CROSSCOMPILING_EMULATOR)
        list(GET CMAKE_CROSSCOMPILING_EMULATOR 0 embed_node)
    else()
        find_program(embed_node NAMES node nodejs REQUIRED)
    endif()
    set(circuit_source "${CMAKE_CURRENT_BINARY_DIR}/range_circuit.cpp")
    add_custom_command(
        OUTPUT "${circuit_source}"
        COMMAND "${embed_node}" "${CMAKE_CURRENT_SOURCE_DIR}/embed-circuit.js"
            "${PROJECT_SOURCE_DIR}/testvectors/range-circuit-1.bin.zst" "${circuit_source}"
        DEPENDS embed-circuit.js "${PROJECT_SOURCE_DIR}/testvectors/range-circuit-1.bin.zst"
        COMMENT "Embedding the range proofs' circuit")
    target_sources(kanhe_verifier_wasm PRIVATE "${circuit_source}")
    target_link_libraries(kanhe_verifier_wasm PRIVATE kanhe::crypto_longfellow)
    target_compile_definitions(kanhe_verifier_wasm PRIVATE KANHE_RANGE_PROOFS=1)
endif()

set(page "${CMAKE_CURRENT_BINARY_DIR}/kanhe-verify.html")
add_custom_command(
    OUTPUT "${page}"
    COMMAND "${CMAKE_COMMAND}"
        "-DMODULE=$<TARGET_FILE:kanhe_verifier_wasm>"
        "-DAPI=${CMAKE_CURRENT_SOURCE_DIR}/verifier-api.js"
        "-DTEMPLATE=${CMAKE_CURRENT_SOURCE_DIR}/page.html"
        "-DOUT=${page}"
        -P "${CMAKE_CURRENT_SOURCE_DIR}/assemble.cmake"
    DEPENDS kanhe_verifier_wasm verifier-api.js page.html assemble.cmake
    COMMENT "Assembling kanhe-verify.html")
add_custom_target(kanhe_verify_page ALL DEPENDS "${page}")
