// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// Range proofs (spec v0.22): the openings an issuer hands a holder (record
// openings), and proofs added to a record's evidence that one of its values
// lies within bounds, without disclosing it (evidence prove, evidence proof).

#include <cstdlib>
#include <filesystem>
#include <format>
#include <optional>
#include <print>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <kanhe/client/ranges.hpp>
#include <kanhe/core/protocol/evidence.hpp>
#include <kanhe/core/protocol/ranges.hpp>

#include "commands.hpp"
#include "output.hpp"
#include "records.hpp"

namespace kanhe::cli {

namespace {

/// Where a command that changes a bundle writes it: --out FILE, --in-place
/// (FILE itself), or else FILE's name with `suffix` before its extension,
/// beside it, which is never written over.
std::filesystem::path output_of(const Args& args, const std::filesystem::path& file,
                                std::string_view suffix) {
    if (args.has("in-place") && args.has("out")) {
        throw UsageError{"--out and --in-place exclude each other"};
    }
    if (args.has("in-place")) {
        return file;
    }
    if (args.has("out")) {
        return std::filesystem::path(args.need("out"));
    }
    const std::filesystem::path out =
        file.parent_path() /
        (file.stem().string() + std::string(suffix) + file.extension().string());
    if (std::filesystem::exists(out)) {
        throw CommandError{out.string() + " exists already: name the new bundle with --out, or " +
                           "replace " + file.string() + " with --in-place"};
    }
    return out;
}

/// A range openings file, read and checked against the CDDL.
protocol::RangeOpenings read_openings(const std::filesystem::path& path) {
    const Bytes content = read_file(path);
    if (content.size() > protocol::max_range_openings_file) {
        throw CommandError{path.string() +
                           " is larger than a range openings file may be (65,536 bytes)"};
    }
    auto openings = protocol::decode_range_openings(content);
    if (!openings) {
        throw CommandError{path.string() + " is not a range openings file: " +
                           std::string(openings.error().detail)};
    }
    return std::move(*openings);
}

/// What to prove, from --field, --at-least, --at-most, --between, and
/// --context.
RangeRequest request_of(const Args& args) {
    RangeRequest request;
    request.field = args.need("field");
    request.at_least = args.get("at-least");
    request.at_most = args.get("at-most");
    if (const auto between = args.get("between")) {
        if (request.at_least || request.at_most) {
            throw UsageError{"--between gives both bounds: it excludes --at-least and --at-most"};
        }
        const std::size_t separator = between->find(" and ");
        if (separator == std::string::npos) {
            throw UsageError{"--between is LOW and HIGH, such as --between \"18 and 65\": " +
                             *between};
        }
        request.at_least = between->substr(0, separator);
        request.at_most = between->substr(separator + 5);
    }
    if (!request.at_least && !request.at_most) {
        throw UsageError{"say what to prove: --at-least VALUE, --at-most VALUE, or --between "
                         "\"LOW and HIGH\""};
    }
    if (const auto context = args.get("context")) {
        auto bytes = from_hex(*context);
        if (!bytes || bytes->empty() || bytes->size() > protocol::max_range_context) {
            throw UsageError{"--context is a relying party's challenge: 1 to 64 bytes, in hex"};
        }
        request.context = std::move(*bytes);
    }
    return request;
}

/// Adds the report's provable values and range proofs to `out`, as kanhe
/// verify --json gives them.
void add_proofs(Json& out, const protocol::EvidenceReport& report, bool ledger_checked) {
    const Json full = report_json(report, ledger_checked);
    for (const char* key : {"provable", "range_proofs"}) {
        out[key] = full.contains(key) ? full[key] : Json::array();
    }
}

/// One range proof of a report, as the text lists print it.
template <class ProofReport>
std::string proof_line(const ProofReport& p) {
    return p.text + (p.context ? " (context " + to_hex(*p.context) + ")" : std::string()) +
           (p.verified ? ", verified" : ", not checked (this build has no range proofs)");
}

/// The record's provable values, as the text lists print them.
std::string provable_line(const std::vector<protocol::ProvableValue>& provable) {
    std::string out;
    for (const protocol::ProvableValue& p : provable) {
        out += (out.empty() ? "" : ", ") + p.name + " (" + provable_encoding_text(p.encoding) + ")";
    }
    return out.empty() ? std::string("none") : out;
}

/// A bundle that does not verify, before or after the change: nothing is
/// written.
int refused(const Args& args, std::string_view key, const std::string& error) {
    if (args.json()) {
        print_json({{std::string(key), false}, {"error", error}});
    } else {
        std::println("REFUSED: {}", error);
        std::println("nothing was written");
    }
    return exit_not_verified;
}

std::string count(std::size_t n, std::string_view one, std::string_view many) {
    return std::format("{} {}", n, n == 1 ? one : many);
}

} // namespace

int cmd_record_openings_export(const Args& args) {
    Session session(args);
    const protocol::Id record = session.record_id(args.positional().front());
    const protocol::RecordRegisterBody body = registration_of(session, record);
    if (body.provable.empty()) {
        throw CommandError{"record " + short_id(record) +
                           " has no provable values (record issue --provable marks them)"};
    }
    const std::vector<std::string> fields = args.all("field");
    for (const std::string& field : fields) {
        if (!std::ranges::contains(body.provable, field, &protocol::ProvableValue::name)) {
            throw UsageError{field + " is not a provable value of record " + short_id(record) +
                             " (it has: " + provable_line(body.provable) + ")"};
        }
    }
    const Vault vault = read_vault(session, record, args);
    const protocol::RangeOpenings openings = vault_openings(
        session.provider(), session.state().ledger_id(), record, body, vault, fields);
    const std::filesystem::path out(args.need("out"));
    write_file(out, unwrap(protocol::encode_range_openings(openings), "encoding the openings"),
               true);
    Json names = Json::array();
    std::string list;
    for (const protocol::RangeOpening& o : openings.openings) {
        names.push_back(o.name);
        list += (list.empty() ? "" : ", ") + o.name;
    }
    if (args.json()) {
        print_json({{"file", out.string()},
                    {"ledger", id_json(openings.ledger)},
                    {"record", id_json(openings.record)},
                    {"fields", std::move(names)}});
        return exit_ok;
    }
    std::println("wrote {}: the openings of {} of record {} ({})", out.string(),
                 count(openings.openings.size(), "provable value", "provable values"),
                 short_id(record), list);
    std::println("It holds the values in clear: give it only to whom they belong, privately. "
                 "With the record's\nevidence, they prove bounds without disclosing the values: "
                 "kanhe evidence prove EVIDENCE --openings {}",
                 out.filename().string());
    return exit_ok;
}

int cmd_record_openings_show(const Args& args) {
    const std::filesystem::path file = args.positional().front();
    const protocol::RangeOpenings openings = read_openings(file);
    const bool values = args.has("values");
    if (args.json()) {
        Json list = Json::array();
        for (const protocol::RangeOpening& o : openings.openings) {
            Json j{{"field", o.name}};
            if (values) {
                j["x"] = o.x;
                j["salt"] = to_hex(o.salt);
            }
            list.push_back(std::move(j));
        }
        print_json({{"file", file.string()},
                    {"ledger", id_json(openings.ledger)},
                    {"record", id_json(openings.record)},
                    {"openings", std::move(list)}});
        return exit_ok;
    }
    std::println("range openings of record {}", hex_id(openings.record));
    std::println("on ledger {}", hex_id(openings.ledger));
    for (const protocol::RangeOpening& o : openings.openings) {
        if (values) {
            std::println("  {}  x = {}  salt = {}", o.name, o.x, to_hex(o.salt));
        } else {
            std::println("  {}", o.name);
        }
    }
    if (!values) {
        std::println("(values hidden; --values shows them: whoever holds this file learns them)");
    }
    return exit_ok;
}

int cmd_evidence_prove(const Args& args) {
    if (!range_proofs_built()) {
        throw CommandError{"this kanhe was built without range proofs (KANHE_RANGE_PROOFS): it "
                           "cannot make them"};
    }
    const std::filesystem::path file = args.positional().front();
    const RangeRequest request = request_of(args);
    const bool from_file = args.has("openings");
    if (from_file && (args.has("ledger") || args.has("server") || args.has("vault-key"))) {
        throw UsageError{"--openings excludes --ledger, --server, and --vault-key: the opening "
                         "comes from the file, or from the record's ledger"};
    }
    if (!from_file) {
        const char* env = std::getenv("KANHE_LEDGER");
        if (!args.has("ledger") && (env == nullptr || *env == '\0') && !server_option(args)) {
            throw UsageError{"say where the value's opening comes from: --openings FILE (the "
                             "range openings file its issuer gave you), or the record's ledger "
                             "(--ledger DIR, with its vault key)"};
        }
    }
    const std::filesystem::path out = output_of(args, file, "-proved");
    const Bytes encoded = read_file(file);
    const protocol::VerifyOptions options = verify_options(args);
    const auto record = provable_record(encoded, options);
    if (!record) {
        return refused(args, "proved",
                       "the evidence does not verify: " + std::string(record.error().detail));
    }
    const protocol::ProvableValue& provable = provable_value(*record, request.field);
    protocol::RangeProof statement = range_statement(provable, request);

    // The opening: the holder's file, or the issuer's vault.
    protocol::RangeOpening opening;
    std::string source;
    if (from_file) {
        const std::filesystem::path path(*args.get("openings"));
        opening = opening_of(read_openings(path), *record, request.field);
        source = path.string();
    } else {
        Session session(args);
        if (session.state().ledger_id() != record->ledger) {
            throw CommandError{"this ledger is " + hex_id(session.state().ledger_id()) +
                               ", not the evidence's (" + hex_id(record->ledger) +
                               "): give the record's ledger, or --openings FILE"};
        }
        const auto body = registration_of(session, record->record);
        const Vault vault = read_vault(session, record->record, args);
        const std::vector<std::string> one{request.field};
        opening =
            vault_openings(session.provider(), record->ledger, record->record, body, vault, one)
                .openings.front();
        source = "the vault";
    }

    Proved proved = add_range_proof(encoded, *record, std::move(statement), opening, options);
    if (!proved.report) {
        return refused(args, "proved",
                       "the new bundle does not verify: " +
                           std::string(proved.report.error().detail));
    }
    write_file(out, proved.bundle, false);
    const std::string words = protocol::range_words(provable.encoding, proved.proof);
    const std::size_t proofs = proved.report->range_proofs.size();
    if (args.json()) {
        Json result{
            {"proved", true},
            {"file", out.string()},
            {"field", proved.proof.field},
            {"text", words},
            {"low", proved.proof.low ? cbor_json(*proved.proof.low) : Json(nullptr)},
            {"high", proved.proof.high ? cbor_json(*proved.proof.high) : Json(nullptr)},
            {"context", proved.proof.context ? Json(to_hex(*proved.proof.context)) : Json(nullptr)},
            {"system", proved.proof.system},
            {"proof_size", proved.proof.proof.size()},
            {"replaced", proved.replaced},
            {"opening", from_file ? "file" : "vault"}};
        add_proofs(result, *proved.report, options.expected_ledger.has_value());
        print_json(result);
        return exit_ok;
    }
    std::println("proved: {}{}", words,
                 proved.proof.context ? " (context " + to_hex(*proved.proof.context) + ")"
                                      : std::string());
    std::println("  from the opening in {}, {} bytes{}", source, proved.proof.proof.size(),
                 proved.replaced ? "; it replaces the proof of " + proved.proof.field + " before"
                                 : std::string());
    std::println("wrote {} ({}, verified)", out.string(),
                 count(proofs, "range proof", "range proofs"));
    return exit_ok;
}

int cmd_evidence_proof_list(const Args& args) {
    const std::filesystem::path file = args.positional().front();
    const protocol::VerifyOptions options = verify_options(args);
    const auto report =
        ledger::verify_bundle(shared_provider(), read_file(file), options, on_all_cores());
    if (!report) {
        if (args.json()) {
            print_json({{"verified", false}, {"error", report.error().detail}});
        } else {
            std::println("VERIFICATION FAILED: {}", report.error().detail);
        }
        return exit_not_verified;
    }
    if (args.json()) {
        Json out{{"verified", true}, {"record", id_json(report->record)}};
        add_proofs(out, *report, options.expected_ledger.has_value());
        print_json(out);
        return exit_ok;
    }
    std::println("record:    {} ({})", hex_id(report->record), report->record_type);
    std::println("provable:  {}", provable_line(report->provable));
    if (report->range_proofs.empty()) {
        std::println("proofs:    none (kanhe evidence prove adds one)");
    }
    for (const auto& p : report->range_proofs) {
        std::println("proof:     {}", proof_line(p));
    }
    return exit_ok;
}

int cmd_evidence_proof_remove(const Args& args) {
    const std::filesystem::path file = args.positional().front();
    if (!args.has("out") && !args.has("in-place")) {
        throw UsageError{"say where the bundle goes: --out FILE, or --in-place to replace " +
                         file.string()};
    }
    const std::filesystem::path out = output_of(args, file, "");
    const std::vector<std::string> fields(args.positional().begin() + 1, args.positional().end());
    const protocol::VerifyOptions options = verify_options(args);
    Unproved unproved = remove_range_proofs(read_file(file), fields, options);
    if (!unproved.report) {
        return refused(args, "removed",
                       "the bundle does not verify: " +
                           std::string(unproved.report.error().detail));
    }
    write_file(out, unproved.bundle, false);
    // The words of what was removed, in the encodings of the record's own
    // provable values.
    std::vector<std::string> words;
    for (const protocol::RangeProof& p : unproved.removed) {
        const auto provable =
            std::ranges::find(unproved.report->provable, p.field, &protocol::ProvableValue::name);
        words.push_back(provable == unproved.report->provable.end()
                            ? p.field
                            : protocol::range_words(provable->encoding, p));
    }
    if (args.json()) {
        Json removed = Json::array();
        for (std::size_t i = 0; i < unproved.removed.size(); ++i) {
            removed.push_back({{"field", unproved.removed[i].field}, {"text", words[i]}});
        }
        Json result{{"removed", std::move(removed)}, {"file", out.string()}};
        add_proofs(result, *unproved.report, options.expected_ledger.has_value());
        print_json(result);
        return exit_ok;
    }
    for (const std::string& w : words) {
        std::println("removed the proof that {}", w);
    }
    std::println("wrote {} ({} left, verified)", out.string(),
                 count(unproved.report->range_proofs.size(), "range proof", "range proofs"));
    return exit_ok;
}

} // namespace kanhe::cli
