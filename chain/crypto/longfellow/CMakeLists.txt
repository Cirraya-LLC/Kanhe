# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya

# Zero-knowledge range proofs on Google's Longfellow ZK, whose compiled sources
# cmake/KanheDependencies.cmake builds as kanhe_longfellow (the rest of the
# library is header templates). Only src/engine.cpp includes its headers.
add_library(kanhe_crypto_longfellow
    src/engine.cpp
    src/range.cpp)
add_library(kanhe::crypto_longfellow ALIAS kanhe_crypto_longfellow)

target_include_directories(kanhe_crypto_longfellow PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>)
target_link_libraries(kanhe_crypto_longfellow
    PUBLIC kanhe::core
    PRIVATE kanhe_longfellow OpenSSL::Crypto)
target_compile_features(kanhe_crypto_longfellow PUBLIC cxx_std_23)
kanhe_target_defaults(kanhe_crypto_longfellow)
# The library's templates are instantiated in engine.cpp, where proofs are
# made and checked: it is optimized in every build, debug builds included, or
# their tests would take minutes (-O3 proves about 12% and verifies about 18%
# faster than -O2).
set_source_files_properties(src/engine.cpp PROPERTIES COMPILE_OPTIONS -O3)

# kanhe-range: proofs and checks as JSON on standard input and output, for
# programs that do not link this library.
add_executable(kanhe-range cli/kanhe_range.cpp)
set_target_properties(kanhe-range PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
target_link_libraries(kanhe-range PRIVATE kanhe::crypto_longfellow nlohmann_json::nlohmann_json)
target_compile_features(kanhe-range PRIVATE cxx_std_23)
kanhe_target_defaults(kanhe-range)
# zstd, if the system has it, compresses the circuit file (`circuit --zstd`).
find_path(KANHE_ZSTD_INCLUDE_DIR zstd.h)
find_library(KANHE_ZSTD_LIBRARY zstd)
if(KANHE_ZSTD_INCLUDE_DIR AND KANHE_ZSTD_LIBRARY)
    target_include_directories(kanhe-range SYSTEM PRIVATE ${KANHE_ZSTD_INCLUDE_DIR})
    target_link_libraries(kanhe-range PRIVATE ${KANHE_ZSTD_LIBRARY})
    target_compile_definitions(kanhe-range PRIVATE KANHE_HAVE_ZSTD=1)
else()
    message(STATUS "zstd not found: kanhe-range writes the circuit uncompressed only")
endif()
