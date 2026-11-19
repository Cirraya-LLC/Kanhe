// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// The browser verifier's interface to JavaScript. Options are set one call at
// a time (so attachment contents need no encoding), then kanhe_verify runs
// the same verification as `kanhe verify` (or, for a contract instance's
// evidence, `kanhe contract verify`) and returns the report as JSON, with
// "kind" set to "record" or "contract".
// Strings returned to JavaScript are allocated with malloc; release them with
// kanhe_free.

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <emscripten/emscripten.h>
#include <exception>
#include <optional>
#include <string>
#include <vector>

#include <kanhe/core/cbor.hpp>
#include <kanhe/core/protocol/common.hpp>
#include <kanhe/core/protocol/contract_evidence.hpp>
#include <kanhe/core/protocol/evidence.hpp>
#include <kanhe/crypto/openssl.hpp>
#include <kanhe/verifier/credentials.hpp>
#include <kanhe/verifier/report.hpp>

namespace {

using namespace kanhe;
using verifier::Json;

protocol::VerifyOptions options;
/// The distrust entries since the last reset (spec v0.21), read again as
/// one list each time one is added: an algorithm is distrusted once.
std::vector<std::string> distrust_entries;

const crypto::openssl::Provider& provider() {
    static const crypto::openssl::Provider instance;
    return instance;
}

char* to_c_string(const Json& value) {
    const std::string text = value.dump(-1, ' ', false, Json::error_handler_t::replace);
    char* out = static_cast<char*>(std::malloc(text.size() + 1));
    if (out != nullptr) {
        std::memcpy(out, text.c_str(), text.size() + 1);
    }
    return out;
}

Json failure(std::string_view message) {
    return {{"verified", false}, {"error", message}};
}

/// Input as given, byte for byte, as `kanhe credential verify` reads a file:
/// not UTF-8 checked or replaced here, and not cut at a NUL.
std::string text_of(const std::uint8_t* bytes, std::size_t size) {
    return size == 0 ? std::string() : std::string(reinterpret_cast<const char*>(bytes), size);
}

char* verify_contract(ByteView input) {
    const auto report = protocol::verify_contract_evidence(provider(), input, options);
    if (!report) {
        Json out = failure(report.error().detail);
        out["kind"] = "contract";
        return to_c_string(out);
    }
    const bool checked = options.expected_ledger.has_value();
    Json out = verifier::contract_report_json(*report, checked);
    out["kind"] = "contract";
    out["text"] = verifier::contract_report_text(*report, checked);
    return to_c_string(out);
}

} // namespace

extern "C" {

EMSCRIPTEN_KEEPALIVE const char* kanhe_version() {
    return KANHE_VERSION;
}

EMSCRIPTEN_KEEPALIVE void kanhe_reset() {
    options = {};
    distrust_entries.clear();
}

/// Distrusts an algorithm from a date (spec v0.21, section 11.1), given as
/// `ALG@YYYY-MM-DD`, as `kanhe verify --distrust` takes it. Returns 0, or -1
/// if the entry is malformed or names an algorithm distrusted since the
/// last reset (directly or through `classical`).
EMSCRIPTEN_KEEPALIVE int kanhe_add_distrust(const char* entry) {
    distrust_entries.emplace_back(entry);
    auto parsed = protocol::parse_distrust(distrust_entries);
    if (!parsed) {
        distrust_entries.pop_back();
        return -1;
    }
    options.distrust = std::move(*parsed);
    return 0;
}

/// Returns 0, or -1 if `hex` is not a ledger id.
EMSCRIPTEN_KEEPALIVE int kanhe_set_expected_ledger(const char* hex) {
    const auto bytes = from_hex(hex);
    if (!bytes) {
        return -1;
    }
    const auto id = protocol::to_id(*bytes);
    if (!id) {
        return -1;
    }
    options.expected_ledger = *id;
    return 0;
}

/// Trusts a witness, given its public key file. Returns 0, or -1 if the file
/// is not a Kanhe public key.
EMSCRIPTEN_KEEPALIVE int kanhe_add_witness(const std::uint8_t* data, std::size_t size) {
    const auto value = cbor::decode(ByteView(data, size));
    if (!value) {
        return -1;
    }
    const auto key = protocol::decode_public_key(*value);
    if (!key) {
        return -1;
    }
    options.trusted_witnesses.push_back(*key);
    return 0;
}

/// Trusts an open network's witness, given its verifier key (spec v0.13):
/// a cosigner's, type 0x04 or 0x06. Returns 0, or -1 if it is not one.
EMSCRIPTEN_KEEPALIVE int kanhe_add_network_witness(const char* vkey) {
    auto key = protocol::network::parse_verifier_key(provider(), vkey);
    if (!key || (key->type != protocol::network::cosigner_ed25519 &&
                 key->type != protocol::network::cosigner_ml_dsa_44)) {
        return -1;
    }
    options.trusted_network_witnesses.push_back(std::move(*key));
    return 0;
}

/// Trusts the time-stamp authorities under these root certificates (a PEM
/// file of one or more, or one DER certificate; spec v0.11). Returns 0, or -1
/// if there is none or one does not parse.
EMSCRIPTEN_KEEPALIVE int kanhe_add_timestamp_root(const std::uint8_t* data, std::size_t size) {
    auto roots = crypto::openssl::read_certificates(ByteView(data, size));
    if (!roots) {
        return -1;
    }
    options.trusted_timestamp_roots.insert(options.trusted_timestamp_roots.end(), roots->begin(),
                                           roots->end());
    return 0;
}

/// Believes a trust node's memberships (spec v0.16), naming it `name` (the
/// page's list gives it, never the evidence). Returns 0, or -1 if `hex` is
/// not a ledger id or the name is empty.
EMSCRIPTEN_KEEPALIVE int kanhe_add_trust_node(const char* hex, const char* name) {
    const auto bytes = from_hex(hex);
    const auto id =
        bytes ? protocol::to_id(*bytes) : Result<protocol::Id>(std::unexpected(bytes.error()));
    if (!id || *name == '\0') {
        return -1;
    }
    options.trust_nodes.push_back({*id, name});
    return 0;
}

EMSCRIPTEN_KEEPALIVE void kanhe_add_attachment(const char* name, const std::uint8_t* data,
                                               std::size_t size) {
    options.attachment_contents[name] = Bytes(data, data + size);
}

/// Verifies an evidence bundle or a contract instance's evidence, with the
/// options set since the last reset.
EMSCRIPTEN_KEEPALIVE char* kanhe_verify(const std::uint8_t* bundle, std::size_t size) {
    try {
        const ByteView input(bundle, size);
        const bool checked = options.expected_ledger.has_value();
        // A record's evidence bundle never decodes as an instance's evidence.
        if (protocol::decode_contract_evidence(input)) {
            return verify_contract(input);
        }
        const auto report = protocol::verify_bundle(provider(), input, options);
        if (!report) {
            return to_c_string(failure(report.error().detail));
        }
        Json out = verifier::report_json(*report, checked);
        out["kind"] = "record";
        out["text"] = verifier::report_text(*report, checked);
        return to_c_string(out);
    } catch (const std::exception& e) {
        return to_c_string(failure(std::string("internal error: ") + e.what()));
    }
}

/// The addresses a credential (a compact JWS, `size` bytes) names: its
/// record's evidence, the issuer's DID document, and its status list, and the
/// ledger: JSON {evidence, did_document, status_list, ledger}, or {error}.
EMSCRIPTEN_KEEPALIVE char* kanhe_credential_addresses(const std::uint8_t* credential,
                                                      std::size_t size) {
    const auto addresses = verifier::credential_addresses(text_of(credential, size));
    if (!addresses) {
        return to_c_string(failure(addresses.error().detail));
    }
    return to_c_string(Json{{"evidence", addresses->evidence},
                            {"did_document", addresses->did_document},
                            {"status_list", addresses->status_list},
                            {"ledger", to_hex(addresses->ledger.bytes())}});
}

/// Verifies a credential against its record's evidence (spec/credentials.md,
/// section 7), with the issuer's DID document and status list if given
/// (null for none), and the options set since the last reset. Each is bytes
/// and their count, read as the command line reads its files.
EMSCRIPTEN_KEEPALIVE char*
kanhe_verify_credential(const std::uint8_t* credential, std::size_t credential_size,
                        const std::uint8_t* bundle, std::size_t size,
                        const std::uint8_t* did_document, std::size_t did_size,
                        const std::uint8_t* status_list, std::size_t list_size) {
    try {
        verifier::CredentialOptions credential_options;
        credential_options.verify = options;
        if (did_document != nullptr) {
            credential_options.did_document = text_of(did_document, did_size);
        }
        if (status_list != nullptr) {
            credential_options.status_list = text_of(status_list, list_size);
        }
        const auto report =
            verifier::verify_credential(provider(), text_of(credential, credential_size),
                                        ByteView(bundle, size), credential_options);
        if (!report) {
            Json out = failure(report.error().detail);
            out["kind"] = "credential";
            return to_c_string(out);
        }
        const bool checked = options.expected_ledger.has_value();
        Json out = verifier::credential_report_json(*report, checked);
        out["text"] = verifier::credential_report_text(*report, checked);
        return to_c_string(out);
    } catch (const std::exception& e) {
        return to_c_string(failure(std::string("internal error: ") + e.what()));
    }
}

EMSCRIPTEN_KEEPALIVE void kanhe_free(char* text) {
    std::free(text);
}

} // extern "C"
