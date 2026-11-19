// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// Renewing evidence (spec v0.21, section 11.1): a newer attestation of the
// ledger's tree appended to a bundle, from the ledger's server, an archive
// that serves the same route, or the ledger's own directory.

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <format>
#include <optional>
#include <print>
#include <string>
#include <string_view>
#include <utility>

#include <kanhe/client/renewals.hpp>
#include <kanhe/core/protocol/evidence.hpp>
#include <kanhe/core/protocol/log.hpp>

#include "commands.hpp"
#include "output.hpp"
#include "records.hpp"

namespace kanhe::cli {

namespace {

/// FILE's name with "-renewed" before its extension, beside it.
std::filesystem::path renewed_name(const std::filesystem::path& file) {
    return file.parent_path() / (file.stem().string() + "-renewed" + file.extension().string());
}

/// What a renewal adds, as JSON.
Json added_json(const protocol::Renewal& renewal) {
    const auto checkpoint =
        unwrap(protocol::parse_checkpoint(renewal.checkpoint), "reading the renewal's checkpoint");
    return {{"tree_size", checkpoint.checkpoint.tree_size},
            {"root", to_hex(checkpoint.checkpoint.root.bytes())},
            {"timestamp", iso_time(checkpoint.checkpoint.timestamp)},
            {"consistency_proof", renewal.consistency.size()},
            {"key_rotations", renewal.rotations.size()},
            {"cosignatures", renewal.cosignatures.size()},
            {"timestamps", renewal.timestamps.size()},
            {"network_cosignatures", renewal.network_cosignatures.size()}};
}

/// "1 witness cosignature" / "2 witness cosignatures".
std::string count(std::size_t n, std::string_view one, std::string_view many) {
    return std::format("{} {}", n, n == 1 ? one : many);
}

/// The long-term status of a report (spec section 11.1), in words.
std::string long_term_words(const Json& long_term) {
    if (!long_term.is_object()) {
        return "not reported";
    }
    const auto pq = long_term.find("post_quantum");
    if (pq == long_term.end() || !pq->is_boolean() || !pq->get<bool>()) {
        const auto before = long_term.find("renew_before");
        const std::string date = before != long_term.end() && before->is_string()
                                     ? before->get<std::string>().substr(0, 10)
                                     : std::string("2030-01-01");
        return "no post-quantum attestation this verifier relies on yet (trust the witnesses "
               "with --witness, or renew with an ML-DSA witness's cosignature): renew before " +
               date;
    }
    std::string out = "post-quantum";
    if (const auto it = long_term.find("checkpoint"); it != long_term.end() && it->is_object()) {
        out += std::format(", by the checkpoint of size {}", it->value("tree_size", 0ULL));
        if (const auto renewal = it->find("renewal");
            renewal != it->end() && renewal->is_number_integer()) {
            out += std::format(" (renewal {})", renewal->get<std::uint64_t>());
        } else {
            out += " (the bundle's own)";
        }
    }
    if (const auto it = long_term.find("attested_by"); it != long_term.end() && it->is_array()) {
        std::string by;
        for (const Json& a : *it) {
            const std::string who = a.value("by", std::string());
            by += std::format(
                "{}{} {} ({})", by.empty() ? "" : ", ", a.value("kind", std::string()),
                who.size() > 16 ? who.substr(0, 16) : who, a.value("algorithm", std::string()));
        }
        if (!by.empty()) {
            out += ": " + by;
        }
    }
    return out;
}

} // namespace

int cmd_evidence_renew(const Args& args) {
    const std::filesystem::path file = args.positional().front();
    const bool in_place = args.has("in-place");
    if (in_place && args.has("out")) {
        throw UsageError{"--out and --in-place exclude each other"};
    }
    const std::filesystem::path out = in_place          ? file
                                      : args.has("out") ? std::filesystem::path(args.need("out"))
                                                        : renewed_name(file);
    if (!in_place && !args.has("out") && std::filesystem::exists(out)) {
        throw CommandError{out.string() +
                           " exists already: name the renewed bundle with --out, or replace " +
                           file.string() + " with --in-place"};
    }
    const Bytes encoded = read_file(file);
    const auto bundle = unwrap(protocol::decode_bundle(encoded), "reading " + file.string());
    const protocol::Id ledger_id =
        unwrap(protocol::bundle_ledger_id(encoded), "reading " + file.string());
    const std::uint64_t from = client::renewal_start(bundle);
    std::optional<std::uint64_t> size;
    if (const auto text = args.get("size")) {
        size = parse_number(*text, "--size");
        if (*size < from) {
            throw UsageError{std::format(
                "--size {} is below the size the bundle renews from ({}): a renewal never goes "
                "back",
                *size, from)};
        }
    }

    // Where the renewal comes from: a server (or an archive), or the
    // ledger's own directory.
    protocol::Renewal renewal;
    std::string source;
    if (const auto url = server_option(args)) {
        renewal = client::fetch_renewal(*url, from, size, args.get("ca-file"));
        source = *url;
    } else {
        const char* env = std::getenv("KANHE_LEDGER");
        if (!args.has("ledger") && (env == nullptr || *env == '\0')) {
            throw UsageError{"say where the renewal comes from: --server URL (the ledger's server, "
                             "or an archive's), or --ledger DIR (the ledger's directory)"};
        }
        const std::filesystem::path directory = args.ledger();
        Session session(directory);
        if (session.state().ledger_id() != ledger_id) {
            throw CommandError{"the ledger at " + directory.string() + " is " +
                               hex_id(session.state().ledger_id()) + ", not the bundle's (" +
                               hex_id(ledger_id) + "): give the bundle's ledger, or --server"};
        }
        auto made = session.ledger().renewal(from, size);
        if (!made) {
            throw CommandError{
                std::format("no renewal from size {}: {}{}", from, made.error().detail,
                            made.error().code == Errc::not_found
                                ? " (ask a witness or a time-stamp authority to attest the latest "
                                  "checkpoint, or renew to an attested one with --size)"
                                : "")};
        }
        renewal = std::move(*made);
        source = directory.string();
    }

    const protocol::VerifyOptions options = verify_options(args);
    client::Renewed renewed = client::renew_bundle(encoded, std::move(renewal), options);
    if (!renewed.report) {
        if (args.json()) {
            print_json({{"renewed", false},
                        {"error", renewed.report.error().detail},
                        {"from_size", from},
                        {"source", source}});
        } else {
            std::println("RENEWAL REFUSED: the renewed bundle does not verify: {}",
                         renewed.report.error().detail);
            std::println("nothing was written");
        }
        return exit_not_verified;
    }
    write_file(out, renewed.bundle, false);

    const Json report = verifier::report_json(*renewed.report, options.expected_ledger.has_value());
    const Json long_term = report.contains("long_term") ? report["long_term"] : Json(nullptr);
    const std::size_t renewals = bundle.renewals.size() + 1;
    if (args.json()) {
        Json result{{"renewed", true},
                    {"file", out.string()},
                    {"from_size", from},
                    {"source", source},
                    {"added", added_json(renewed.added)},
                    {"renewals", renewals}};
        // The renewal as the report describes it (its log key, rotations,
        // witnesses, and tokens).
        if (const auto it = report.find("renewals");
            it != report.end() && it->is_array() && !it->empty()) {
            result["renewal"] = it->back();
        }
        result["long_term"] = long_term;
        print_json(result);
        return exit_ok;
    }
    const auto checkpoint =
        unwrap(protocol::parse_checkpoint(renewed.added.checkpoint), "reading the checkpoint");
    std::println("renewed from size {} to a checkpoint of size {} ({}), from {}", from,
                 checkpoint.checkpoint.tree_size, format_time(checkpoint.checkpoint.timestamp),
                 source);
    std::println(
        "  {}, {}, {}, {}", count(renewed.added.rotations.size(), "key rotation", "key rotations"),
        count(renewed.added.cosignatures.size(), "witness cosignature", "witness cosignatures"),
        count(renewed.added.timestamps.size(), "time-stamp token", "time-stamp tokens"),
        count(renewed.added.network_cosignatures.size(), "network cosignature",
              "network cosignatures"));
    std::println("wrote {} ({}, verified)", out.string(), count(renewals, "renewal", "renewals"));
    std::println("long-term status: {}", long_term_words(long_term));
    return exit_ok;
}

} // namespace kanhe::cli
