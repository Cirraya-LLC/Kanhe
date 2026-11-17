// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// A credential checked against its record's evidence, as `kanhe credential
// verify` and the browser verifier check one (spec/credentials.md, section
// 7): the credential, the evidence, the issuer's DID document and status list
// all come from the issuer's web server, or from whoever hands them over.
// Input: three lines and the rest, "CREDENTIAL\nDID DOCUMENT\nSTATUS
// LIST\nEVIDENCE", where an empty line gives no DID document or no status
// list; the evidence, binary, comes last. Properties: checking never crashes;
// a report is of the ledger and addresses the credential names; it checks
// only what it was given; a credential without problems names the device
// key that signed it; a status list that verified says what the ledger says;
// and the report prints, as the command line prints it.

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <optional>
#include <string>
#include <string_view>

#include <kanhe/core/bytes.hpp>
#include <kanhe/crypto/openssl.hpp>
#include <kanhe/verifier/credentials.hpp>

namespace verifier = kanhe::verifier;

namespace {

void require(bool condition) {
    if (!condition) {
        std::abort();
    }
}

/// The next line of `rest`, taken off it; nullopt if no line ends.
std::optional<std::string_view> next_line(std::string_view& rest) {
    const std::size_t end = rest.find('\n');
    if (end == std::string_view::npos) {
        return std::nullopt;
    }
    const std::string_view line = rest.substr(0, end);
    rest.remove_prefix(end + 1);
    return line;
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    static const kanhe::crypto::openssl::Provider provider;
    std::string_view rest(reinterpret_cast<const char*>(data), size);
    const auto credential = next_line(rest);
    const auto did_document = next_line(rest);
    const auto status_list = next_line(rest);
    if (!credential || !did_document || !status_list) {
        return 0;
    }
    const kanhe::ByteView evidence(data + (size - rest.size()), rest.size());
    verifier::CredentialOptions options;
    if (!did_document->empty()) {
        options.did_document = std::string(*did_document);
    }
    if (!status_list->empty()) {
        options.status_list = std::string(*status_list);
    }

    const auto report = verifier::verify_credential(provider, *credential, evidence, options);
    if (!report) {
        return 0;
    }
    // Of the ledger the credential names (the evidence must be that
    // ledger's), and the addresses it gives for fetching.
    const auto addresses = verifier::credential_addresses(*credential);
    require(addresses.has_value());
    require(addresses->ledger == report->evidence.ledger_id);
    require(addresses->evidence == report->evidence_url);
    require(addresses->status_list == report->status_list_url);
    require(report->record_status == "live" || report->record_status == "revoked" ||
            report->record_status == "replaced");
    // Only what was given is checked.
    require(!report->did_document_checked || options.did_document.has_value());
    require(!report->status_list_checked || options.status_list.has_value());
    require(!report->status_list_bit || report->status_list_checked);
    if (report->problems.empty()) {
        // Nothing wrong with the credential itself: every check given ran,
        // and the signature is by a device that endorsed the record as this
        // credential.
        require(report->did_document_checked == options.did_document.has_value());
        require(report->status_list_checked == options.status_list.has_value());
        require(report->key_actor.has_value());
    }
    if (report->verified() && report->status_list_bit) {
        require(*report->status_list_bit == (report->record_status != "live"));
    }

    // The report prints: its JSON as `--json` writes it (strict UTF-8), and
    // its text.
    const auto json = verifier::credential_report_json(*report, false);
    require(json.at("verified").get<bool>() == report->verified());
    static_cast<void>(json.dump(2));
    const std::string text = verifier::credential_report_text(*report, false);
    require(text.starts_with("VERIFIED") == report->verified());
    return 0;
}
