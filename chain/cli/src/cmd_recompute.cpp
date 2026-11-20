// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// Recomputation (spec v0.18, informative): a record made by a script its
// organization states deterministic can be made again. Whoever holds the
// record's evidence with the fields to compare disclosed, its sources'
// evidence with the fields the script reads, and the script's files runs the
// script on those fields and compares what it prints with what the record
// holds, each value proven against the record's commitment. Nothing is
// recorded anywhere.

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <format>
#include <map>
#include <optional>
#include <print>
#include <set>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#include <nlohmann/json.hpp>

#include <kanhe/core/cbor.hpp>
#include <kanhe/core/protocol/evidence.hpp>
#include <kanhe/core/protocol/scripts.hpp>
#include <kanhe/crypto/openssl.hpp>
#include <kanhe/node/process.hpp>

#include "commands.hpp"
#include "output.hpp"
#include "records.hpp"

namespace kanhe::cli {

namespace {

/// JSON compared whatever the order of its objects' keys.
using Plain = nlohmann::json;

constexpr std::uint64_t default_timeout = 60;
constexpr std::uint64_t max_timeout = 3600;
/// The most the script may print.
constexpr std::size_t max_output = std::size_t{16} << 20;

/// --run's command line in words, split as a shell splits them (blanks
/// between words; '...' as it is; "..." with \" and \\ for a quote and a
/// backslash; a backslash keeping the next character as it is), but run
/// without one: nothing is expanded, and the characters a shell would act
/// on are refused unquoted, so that none is passed on by mistake.
std::vector<std::string> split_command(std::string_view text) {
    constexpr std::string_view shell_characters = "|&;<>()$`";
    std::vector<std::string> words;
    std::string word;
    bool in_word = false;
    for (std::size_t i = 0; i < text.size(); ++i) {
        const char c = text[i];
        if (c == ' ' || c == '\t' || c == '\n') {
            if (in_word) {
                words.push_back(std::move(word));
                word.clear();
                in_word = false;
            }
            continue;
        }
        in_word = true;
        if (c == '\'') {
            const std::size_t end = text.find('\'', i + 1);
            if (end == std::string_view::npos) {
                throw UsageError{"--run: a quote (') is not closed"};
            }
            word.append(text.substr(i + 1, end - i - 1));
            i = end;
        } else if (c == '"') {
            std::size_t j = i + 1;
            for (; j < text.size() && text[j] != '"'; ++j) {
                if (text[j] == '\\' && j + 1 < text.size() &&
                    (text[j + 1] == '"' || text[j + 1] == '\\')) {
                    ++j;
                }
                word.push_back(text[j]);
            }
            if (j >= text.size()) {
                throw UsageError{"--run: a quote (\") is not closed"};
            }
            i = j;
        } else if (c == '\\') {
            if (i + 1 >= text.size()) {
                throw UsageError{"--run ends with a backslash"};
            }
            word.push_back(text[++i]);
        } else if (shell_characters.find(c) != std::string_view::npos) {
            throw UsageError{std::format("--run runs the program without a shell: quote {} to pass "
                                         "it to the program as it is",
                                         c)};
        } else {
            word.push_back(c);
        }
    }
    if (in_word) {
        words.push_back(std::move(word));
    }
    if (words.empty() || words.front().empty()) {
        throw UsageError{"--run names the program to run, and its arguments"};
    }
    return words;
}

/// The program's environment: PATH, HOME, and TMPDIR as this process has
/// them, a fixed locale and time zone, and nothing else (no KANHE_*
/// variable: passphrases, tokens, PINs).
std::vector<std::string> minimal_environment() {
    std::vector<std::string> out;
    for (const char* name : {"PATH", "HOME", "TMPDIR"}) {
        if (const char* value = std::getenv(name); value != nullptr) {
            out.push_back(std::string(name) + "=" + value);
        }
    }
    if (std::getenv("PATH") == nullptr) {
        out.emplace_back("PATH=/usr/bin:/bin");
    }
    out.emplace_back("LC_ALL=C");
    out.emplace_back("TZ=UTC");
    return out;
}

Plain plain(const Json& value) {
    return Plain::parse(value.dump(-1, ' ', false, Json::error_handler_t::replace));
}

Json ordered(const Plain& value) {
    return Json::parse(value.dump(-1, ' ', false, Plain::error_handler_t::replace));
}

/// How many arrays and objects a value nests (0 for a scalar), and whether
/// it holds a number with a fraction or an exponent, which no field's value
/// does (values are CBOR, without floating point). Without recursion: the
/// script's output may nest deeply.
struct Shape {
    std::size_t depth = 0;
    bool fraction = false;
};

Shape shape_of(const Plain& value) {
    Shape out;
    std::vector<std::pair<const Plain*, std::size_t>> stack{{&value, std::size_t{0}}};
    while (!stack.empty()) {
        const auto [v, enclosing] = stack.back();
        stack.pop_back();
        out.fraction = out.fraction || v->is_number_float();
        if (v->is_structured()) {
            out.depth = std::max(out.depth, enclosing + 1);
            for (const Plain& item : *v) {
                stack.emplace_back(&item, enclosing + 1);
            }
        }
    }
    return out;
}

/// A value as the report shows it: its JSON, cut short after 200 bytes.
std::string shown(const Plain& value) {
    std::string text = value.dump(-1, ' ', false, Plain::error_handler_t::replace);
    if (text.size() > 200) {
        std::size_t end = 197;
        while (end > 0 && (static_cast<unsigned char>(text[end]) & 0xC0U) == 0x80U) {
            --end;
        }
        text.resize(end);
        text += "...";
    }
    return text;
}

/// Disclosed fields by name (bytewise order), each value as verify --json
/// shows it: what the script reads.
Json fields_json(const std::vector<protocol::RecordField>& fields) {
    std::map<std::string, const cbor::Value*> by_name;
    for (const protocol::RecordField& f : fields) {
        by_name.emplace(f.name, &f.value);
    }
    Json out = Json::object();
    for (const auto& entry : by_name) {
        out[entry.first] = cbor_json(*entry.second);
    }
    return out;
}

Json field_names(const std::vector<protocol::RecordField>& fields) {
    std::set<std::string> names;
    for (const protocol::RecordField& f : fields) {
        names.insert(f.name);
    }
    Json out = Json::array();
    for (const std::string& name : names) {
        out.push_back(name);
    }
    return out;
}

int not_verified(const Args& args, const std::string& why) {
    if (args.json()) {
        print_json({{"recomputed", false}, {"verified", false}, {"error", why}});
    } else {
        std::println("VERIFICATION FAILED: {}", why);
    }
    return exit_not_verified;
}

/// A source's evidence as --source gives it, verified.
struct GivenSource {
    std::string file;
    protocol::EvidenceReport report;
};

} // namespace

int cmd_record_recompute(const Args& args) {
    // What to run, and where, before anything is read.
    const std::vector<std::string> command = split_command(args.need("run"));
    const std::uint64_t timeout =
        args.has("timeout") ? parse_number(*args.get("timeout"), "--timeout") : default_timeout;
    if (timeout == 0 || timeout > max_timeout) {
        throw UsageError{std::format("--timeout is 1 to {} seconds", max_timeout)};
    }
    const std::filesystem::path given_directory = args.need("script-dir");
    std::error_code ec;
    if (!std::filesystem::is_directory(given_directory, ec)) {
        throw UsageError{"--script-dir: no such directory: " + given_directory.string()};
    }
    const std::filesystem::path directory = std::filesystem::absolute(given_directory);
    const std::uint64_t min_witnesses =
        args.has("min-witnesses") ? parse_number(*args.get("min-witnesses"), "--min-witnesses") : 0;
    const std::uint64_t min_timestamps =
        args.has("min-timestamps") ? parse_number(*args.get("min-timestamps"), "--min-timestamps")
                                   : 0;

    // The record's evidence, verified as verify verifies it.
    const crypto::openssl::Provider provider;
    const protocol::VerifyOptions options = verify_options(args);
    const std::string evidence = args.positional().front();
    const auto report =
        ledger::verify_bundle(provider, read_file(evidence), options, on_all_cores());
    if (!report) {
        return not_verified(args, evidence + ": " + std::string(report.error().detail));
    }
    if (report->trusted_cosignatures < min_witnesses) {
        return not_verified(args,
                            std::format("{}: {} trusted witness cosignatures, {} required",
                                        evidence, report->trusted_cosignatures, min_witnesses));
    }
    if (report->trusted_timestamp_authorities < min_timestamps) {
        return not_verified(args, std::format("{}: {} trusted time-stamp authorities, {} required",
                                              evidence, report->trusted_timestamp_authorities,
                                              min_timestamps));
    }
    if (report->instance || report->events.empty()) {
        throw UsageError{evidence + " is a contract instance's evidence: recompute takes a "
                                    "record's"};
    }

    // The script its registration names: approved still, and deterministic.
    const protocol::RecordEvent& registration = report->events.front();
    if (!registration.provenance || !registration.provenance->script) {
        throw CommandError{"nothing to recompute: the record's registration names no script"};
    }
    const auto found = std::ranges::find(report->scripts, *registration.provenance->script,
                                         &protocol::ScriptReport::id);
    if (found == report->scripts.end()) {
        throw CommandError{"the record's script is not in its evidence"};
    }
    const protocol::ScriptReport& script = *found;
    const std::string script_name = script.script.name + " " + script.script.version;
    if (script.withdrawn_at) {
        throw CommandError{std::format("the script {} was withdrawn on {}: there is no approval "
                                       "to recompute against",
                                       script_name, format_time(*script.withdrawn_at))};
    }
    if (!script.script.deterministic) {
        throw CommandError{"nothing to recompute: the script " + script_name +
                           " is not stated deterministic"};
    }
    if (report->disclosed_fields.empty()) {
        throw CommandError{"nothing to compare: " + evidence +
                           " discloses none of the record's fields (kanhe export --disclose)"};
    }

    // Its files in the directory, each as approved.
    Json files = Json::array();
    std::string differ;
    for (const protocol::ScriptFile& f : script.script.files) {
        const std::string status = script_file_status(provider, report->hash, directory, f);
        files.push_back({{"path", f.path}, {"status", status}});
        if (status != "same") {
            differ += (differ.empty() ? "" : ", ") + f.path + " " + status;
        }
    }
    if (!differ.empty()) {
        throw CommandError{"--script-dir does not hold the script " + script_name +
                           " as approved: " + differ};
    }

    // The sources' evidence, each verified against its own ledger: one for
    // each source the record names.
    protocol::VerifyOptions source_options = options;
    source_options.expected_ledger.reset();
    source_options.attachment_contents.clear();
    source_options.range_context.reset();
    std::vector<std::optional<GivenSource>> sources(report->sources.size());
    for (const std::string& file : args.all("source")) {
        auto verified =
            ledger::verify_bundle(provider, read_file(file), source_options, on_all_cores());
        if (!verified) {
            return not_verified(args, file + ": " + std::string(verified.error().detail));
        }
        if (verified->instance) {
            throw UsageError{file + " is a contract instance's evidence, not a source's"};
        }
        const auto named =
            std::ranges::find_if(report->sources, [&](const protocol::SourceReport& s) {
                return s.source.ledger == verified->ledger_id &&
                       s.source.record == verified->record;
            });
        if (named == report->sources.end()) {
            throw UsageError{std::format("{} is the evidence of record {} of ledger {}, not of a "
                                         "source the record names",
                                         file, short_id(verified->record),
                                         short_id(verified->ledger_id))};
        }
        std::optional<GivenSource>& slot =
            sources[static_cast<std::size_t>(named - report->sources.begin())];
        if (slot) {
            throw UsageError{file + " and " + slot->file + " are the evidence of one source"};
        }
        slot = GivenSource{file, std::move(*verified)};
    }
    for (std::size_t i = 0; i < sources.size(); ++i) {
        if (!sources[i]) {
            const protocol::SourceReport& s = report->sources[i];
            throw UsageError{std::format(
                "no --source for the source {}{}: give its evidence, exported with the fields the "
                "script reads disclosed",
                short_id(s.source.record),
                s.local ? std::string(" (on this ledger)")
                        : " of ledger " + short_id(s.source.ledger))};
        }
    }

    // The script's input: the sources in the record's order, with their
    // disclosed fields.
    Json input_sources = Json::array();
    for (const std::optional<GivenSource>& s : sources) {
        const protocol::EvidenceReport& r = s->report;
        input_sources.push_back({{"ledger", hex_id(r.ledger_id)},
                                 {"record", hex_id(r.record)},
                                 {"type", r.record_type},
                                 {"fields", fields_json(r.disclosed_fields)}});
    }
    Json input = Json::object();
    input["sources"] = std::move(input_sources);
    const std::string input_text =
        input.dump(-1, ' ', false, Json::error_handler_t::replace) + "\n";

    // Run it in the directory, without a shell, with a minimal environment.
    std::string executable = command.front();
    if (executable.find('/') != std::string::npos &&
        !std::filesystem::path(executable).is_absolute()) {
        executable = (directory / executable).lexically_normal().string();
    }
    node::ChildOptions child_options;
    child_options.directory = directory;
    child_options.environment = minimal_environment();
    auto child = node::ChildProcess::start(
        executable, std::vector<std::string>(command.begin() + 1, command.end()), child_options);
    if (!child) {
        throw CommandError{"cannot run " + command.front() + ": " +
                           std::string(child.error().detail)};
    }
    const node::ChildProcess::Run ran =
        child->communicate(as_bytes(std::string_view(input_text)),
                           std::chrono::seconds(static_cast<std::int64_t>(timeout)), max_output);
    if (!ran.exit) {
        throw CommandError{std::format(
            "the script did not finish within {} s, and was stopped (--timeout)", timeout)};
    }
    if (ran.exit->signal != 0) {
        throw CommandError{std::format("the script was ended by signal {}", ran.exit->signal)};
    }
    if (ran.exit->code != 0) {
        throw CommandError{
            std::format("the script exited with status {}: nothing to compare", ran.exit->code)};
    }
    if (ran.truncated) {
        throw CommandError{"the script printed more than 16 MiB"};
    }
    const Plain output = Plain::parse(ran.output.begin(), ran.output.end(), nullptr, false);
    if (output.is_discarded() || !output.is_object()) {
        throw CommandError{"the script's output is not one JSON object of fields and values"};
    }
    if (shape_of(output).depth > cbor::max_nesting_depth + 1) {
        throw CommandError{std::format("the script's output nests deeper than {} levels",
                                       cbor::max_nesting_depth)};
    }

    // Each field, compared: disclosed and printed, disclosed only, printed
    // only.
    std::map<std::string, const cbor::Value*> recorded;
    for (const protocol::RecordField& f : report->disclosed_fields) {
        recorded.emplace(f.name, &f.value);
    }
    std::set<std::string> names;
    for (const auto& entry : recorded) {
        names.insert(entry.first);
    }
    for (auto it = output.begin(); it != output.end(); ++it) {
        names.insert(it.key());
    }
    Json fields = Json::array();
    std::size_t matched = 0;
    std::size_t differs = 0;
    std::size_t not_recomputed = 0;
    std::size_t not_disclosed = 0;
    std::string field_lines;
    for (const std::string& name : names) {
        const auto held = recorded.find(name);
        const auto printed = output.find(name);
        const bool disclosed = held != recorded.end();
        const bool recomputed = printed != output.end();
        Json item{{"name", name},
                  {"status", nullptr},
                  {"recorded", disclosed ? cbor_json(*held->second) : Json(nullptr)},
                  {"recomputed", recomputed ? ordered(*printed) : Json(nullptr)}};
        std::string words;
        if (disclosed && recomputed) {
            const Plain want = plain(cbor_json(*held->second));
            if (!shape_of(*printed).fraction && *printed == want) {
                ++matched;
                item["status"] = "match";
                words = "match";
            } else {
                ++differs;
                item["status"] = "differs";
                words = std::format("differs (recorded {}, recomputed {})", shown(want),
                                    shown(*printed));
            }
        } else if (disclosed) {
            ++not_recomputed;
            item["status"] = "not_recomputed";
            words = "not recomputed";
        } else {
            ++not_disclosed;
            item["status"] = "not_disclosed";
            words = "cannot be checked (not disclosed)";
        }
        field_lines += std::format("    {}: {}\n", name, words);
        fields.push_back(std::move(item));
    }
    const bool same = differs == 0 && matched > 0;
    const std::string verdict =
        differs > 0 ? std::format("{} field{} differ{} from what the record holds", differs,
                                  differs == 1 ? "" : "s", differs == 1 ? "s" : "")
                    : "the script's output recomputes none of the record's disclosed fields";

    if (args.json()) {
        Json listed = Json::array();
        for (const std::optional<GivenSource>& s : sources) {
            const protocol::EvidenceReport& r = s->report;
            listed.push_back({{"ledger", hex_id(r.ledger_id)},
                              {"record", hex_id(r.record)},
                              {"type", r.record_type},
                              {"organization", r.organization},
                              {"file", s->file},
                              {"fields", field_names(r.disclosed_fields)}});
        }
        print_json(
            {{"recomputed", same},
             {"verified", true},
             {"ledger",
              {{"id", hex_id(report->ledger_id)},
               {"organization", report->organization},
               {"id_checked", options.expected_ledger.has_value()}}},
             {"record", {{"id", hex_id(report->record)}, {"type", report->record_type}}},
             {"script",
              {{"id", hex_id(script.id)},
               {"name", script.script.name},
               {"version", script.script.version},
               {"deterministic", script.script.deterministic},
               {"runtime", script.script.runtime ? Json(*script.script.runtime) : Json(nullptr)},
               {"approved_by", script.approved_by.name},
               {"approved_at", iso_time(script.approved_at)},
               {"files", std::move(files)}}},
             {"directory", given_directory.string()},
             {"command", command},
             {"sources", std::move(listed)},
             {"fields", std::move(fields)},
             {"matched", matched},
             {"differ", differs},
             {"not_recomputed", not_recomputed},
             {"not_disclosed", not_disclosed},
             {"error", same ? Json(nullptr) : Json(verdict)}});
        return same ? exit_ok : exit_not_verified;
    }

    std::string run_line;
    for (const std::string& word : command) {
        run_line += (run_line.empty() ? "" : " ") + word;
    }
    std::println("Kanhe recomputation\n");
    std::println("  Ledger       {} (id {})", report->organization, short_id(report->ledger_id));
    if (!options.expected_ledger) {
        std::println("               ! not compared with an expected ledger id");
    }
    std::println("  Record       {} (id {})", report->record_type, short_id(report->record));
    const protocol::Script& s = script.script;
    std::println("  Script       {} ({} file{}, deterministic{}), approved {}by {} on {}; still "
                 "approved",
                 script_name, s.files.size(), s.files.size() == 1 ? "" : "s",
                 s.runtime ? ", " + *s.runtime : std::string(), script.presence ? "in person " : "",
                 script.approved_by.name, format_time(script.approved_at));
    std::println("  Files        {} in {}, each as approved", s.files.size(),
                 given_directory.string());
    for (const std::optional<GivenSource>& g : sources) {
        const protocol::EvidenceReport& r = g->report;
        const std::size_t n = r.disclosed_fields.size();
        std::println("  Source       {} (id {}) on {}, from {}: {} field{} disclosed",
                     r.record_type, short_id(r.record),
                     r.ledger_id == report->ledger_id ? std::string("this ledger")
                                                      : r.organization + "'s ledger",
                     g->file, n, n == 1 ? "" : "s");
    }
    std::println("  Ran          {}, in {}: exit status 0", run_line, given_directory.string());
    std::println("\n  Fields (each recorded value proven against the record's commitment)");
    std::print("{}", field_lines);
    if (same) {
        std::println("\n  Recomputed: every field compared matches ({} of {} disclosed).", matched,
                     recorded.size());
    } else if (differs > 0) {
        std::println("\nRECOMPUTATION DIFFERS: {}", verdict);
    } else {
        std::println("\nNOTHING COMPARED: {}", verdict);
    }
    return same ? exit_ok : exit_not_verified;
}

} // namespace kanhe::cli
