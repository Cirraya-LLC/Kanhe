// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include <algorithm>
#include <string>
#include <system_error>
#include <utility>

#include <kanhe/core/bytes.hpp>
#include <kanhe/node/sources.hpp>

#include "files.hpp"

namespace kanhe::node {

namespace {

std::filesystem::path record_directory(const std::filesystem::path& ledger_directory,
                                       const protocol::Id& record) {
    return ledger_directory / "sources" / to_hex(record.bytes());
}

std::string file_name(const protocol::Source& source) {
    return to_hex(source.ledger.bytes()) + "." + to_hex(source.record.bytes()) + ".cbor";
}

/// The source a kept file's name says it is of.
std::optional<protocol::Source> source_of_name(const std::string& name) {
    constexpr std::size_t hex_size = 2 * protocol::id_size;
    if (name.size() != 2 * hex_size + 6 || name[hex_size] != '.' || !name.ends_with(".cbor")) {
        return std::nullopt;
    }
    const auto ledger = from_hex(name.substr(0, hex_size));
    const auto record = from_hex(name.substr(hex_size + 1, hex_size));
    if (!ledger || !record) {
        return std::nullopt;
    }
    const auto l = protocol::to_id(*ledger);
    const auto r = protocol::to_id(*record);
    if (!l || !r) {
        return std::nullopt;
    }
    return protocol::Source{*l, *r};
}

} // namespace

std::filesystem::path source_proof_path(const std::filesystem::path& ledger_directory,
                                        const protocol::Id& record,
                                        const protocol::Source& source) {
    return record_directory(ledger_directory, record) / file_name(source);
}

Result<CheckedSourceProof> check_source_proof(const crypto::Provider& provider, ByteView proof,
                                              const std::vector<protocol::Source>& sources,
                                              const protocol::Id& own_ledger) {
    auto decoded = protocol::decode_bundle(proof);
    if (!decoded) {
        return std::unexpected(decoded.error());
    }
    // One level per bundle: the source's own sources stay ids.
    decoded->source_proofs.clear();
    auto kept = protocol::encode_bundle(*decoded);
    if (!kept) {
        return std::unexpected(kept.error());
    }
    auto report = protocol::verify_bundle(provider, *kept, protocol::VerifyOptions{});
    if (!report) {
        return std::unexpected(report.error());
    }
    if (!report->complete) {
        return fail(Errc::verification_failed, "the source's evidence is not complete");
    }
    if (report->instance || report->events.empty()) {
        return fail(Errc::verification_failed, "the evidence is not a record's");
    }
    if (report->ledger_id == own_ledger) {
        return fail(Errc::invalid_argument,
                    "the evidence is of this ledger: a local source needs no proof");
    }
    const auto found = std::ranges::find_if(sources, [&](const protocol::Source& s) {
        return s.ledger == report->ledger_id && s.record == report->record;
    });
    if (found == sources.end()) {
        return fail(Errc::not_found,
                    "the evidence is not of a source the record names on another ledger");
    }
    return CheckedSourceProof{*found, std::move(*kept), std::move(*report)};
}

Status keep_source_proof(const std::filesystem::path& ledger_directory, const protocol::Id& record,
                         const protocol::Source& source, ByteView proof) {
    const auto path = source_proof_path(ledger_directory, record, source);
    std::error_code ec;
    std::filesystem::create_directories(path.parent_path(), ec);
    return detail::write_file(path, proof, false);
}

bool remove_source_proof(const std::filesystem::path& ledger_directory, const protocol::Id& record,
                         const protocol::Source& source) {
    std::error_code ec;
    return std::filesystem::remove(source_proof_path(ledger_directory, record, source), ec);
}

std::vector<KeptSourceProof> kept_source_proofs(const std::filesystem::path& ledger_directory,
                                                const protocol::Id& record) {
    std::vector<KeptSourceProof> out;
    const auto directory = record_directory(ledger_directory, record);
    std::error_code ec;
    std::vector<std::filesystem::path> files;
    for (const auto& entry : std::filesystem::directory_iterator(directory, ec)) {
        if (entry.is_regular_file(ec)) {
            files.push_back(entry.path());
        }
    }
    std::ranges::sort(files);
    for (const auto& path : files) {
        const auto source = source_of_name(path.filename().string());
        auto bytes = detail::read_file(path);
        if (!source || !bytes) {
            continue;
        }
        const auto decoded = protocol::decode_bundle(*bytes);
        if (!decoded || decoded->record != source->record) {
            continue;
        }
        out.push_back({*source, std::move(*bytes)});
        if (out.size() == protocol::max_source_proofs) {
            break;
        }
    }
    return out;
}

void add_source_proofs(const std::filesystem::path& ledger_directory,
                       protocol::EvidenceBundle& bundle) {
    for (KeptSourceProof& kept : kept_source_proofs(ledger_directory, bundle.record)) {
        bundle.source_proofs.push_back(std::move(kept.proof));
    }
}

} // namespace kanhe::node
