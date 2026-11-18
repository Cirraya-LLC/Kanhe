// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// What a contract's calls take, and their arguments built from a form's
// values: the creation's fields and roles, an action's inputs and the role
// it binds, time rules; values written in each official language's forms,
// read by the declared type; and every problem by its code.

#include <algorithm>
#include <cstddef>
#include <filesystem>
#include <fstream>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

#include <catch2/catch_test_macros.hpp>

#include <kanhe/bo/calls.hpp>
#include <kanhe/bo/checker.hpp>
#include <kanhe/bo/lexer.hpp>
#include <kanhe/bo/pack.hpp>
#include <kanhe/bo/parser.hpp>
#include <kanhe/core/bytes.hpp>
#include <kanhe/core/cbor.hpp>

using namespace kanhe;
using namespace kanhe::bo;

namespace {

const std::filesystem::path golden_dir = KANHE_BO_GOLDEN_DIR;

const PackSet& official_set() {
    static const PackSet set = *make_pack_set({}).set;
    return set;
}

const Lexicon& official() {
    static const Lexicon lexicon(official_set());
    return lexicon;
}

std::string read_text(const std::filesystem::path& path) {
    std::ifstream in(path, std::ios::binary);
    std::stringstream out;
    out << in.rdbuf();
    return out.str();
}

model::Model model_of(std::string_view source) {
    const Lexed lexed = lex(source, official());
    const Parsed parsed = parse(source, lexed);
    REQUIRE_FALSE(has_errors(lexed.diagnostics));
    REQUIRE_FALSE(has_errors(parsed.diagnostics));
    Checked checked = check(source, parsed.file);
    REQUIRE_FALSE(has_errors(checked.diagnostics));
    return std::move(checked.model);
}

const std::string order = "contract Order\nparties we, buyer, carrier\n\nthing Deal\n"
                          "  cost HKD\n  fee HKD = HKD 10\n  starts date\n  weight kg\n"
                          "  urgent yes or no\n  tags list text at most 2\n  note text\n\n"
                          "can ship by we to carrier with lead day\n  requires lead > 0\n"
                          "  open -> shipped\n";

const std::string we(64, '1');
const std::string buyer(64, '2');

calls::Values creation_values(std::string cost = "HKD 1_250.50",
                              std::string starts = "2027-01-06") {
    return {{"cost", {std::move(cost)}},
            {"starts", {std::move(starts)}},
            {"weight", {std::string("3 kg")}},
            {"urgent", {false}},
            {"tags", {std::vector<calls::Value>{{std::string("fragile")}}}},
            {"note", {std::string("by hand")}},
            {"we", {we}},
            {"buyer", {buyer}}};
}

/// A value of the creation's "fields", in diagnostic notation.
std::string field(const calls::Arguments& built, std::string_view name) {
    REQUIRE(built.value.has_value());
    const cbor::Value* fields = built.value->find("fields");
    REQUIRE(fields != nullptr);
    const cbor::Value* value = fields->find(name);
    REQUIRE(value != nullptr);
    return cbor::diagnostic(*value);
}

std::string codes(const calls::Arguments& built) {
    std::string out;
    for (const calls::Problem& p : built.problems) {
        out += p.name + ":" + std::string(p.code) + " ";
    }
    return out;
}

} // namespace

TEST_CASE("bo calls: what lending's calls take", "[bo][calls]") {
    const std::string source = read_text(golden_dir / "form" / "lending" / "source.bo");
    const model::Model model = model_of(source);
    const calls::Description d = calls::describe(model, source, nullptr);
    CHECK(d.contract == "Lending");
    REQUIRE(d.calls.size() == 3);
    CHECK(d.calls[0].kind == calls::Kind::create);
    // The holder starts with the owner (R2): only the name is given, and
    // the owner's ledger.
    REQUIRE(d.calls[0].inputs.size() == 2);
    CHECK(d.calls[0].inputs[0].name == "name");
    CHECK(d.calls[0].inputs[0].place == calls::Place::field);
    CHECK(d.calls[0].inputs[1].name == "owner");
    CHECK(d.calls[0].inputs[1].place == calls::Place::role);
    CHECK(d.calls[1].function == "lend");
    // R21: a counterparty each call names.
    REQUIRE(d.calls[1].inputs.size() == 1);
    CHECK(d.calls[1].inputs[0].name == "counterparty");
    CHECK(d.calls[1].inputs[0].type == "party");
    CHECK_FALSE(d.calls[1].clauses.empty());
    CHECK(d.calls[2].function == "bring_back");
    CHECK(d.calls[2].inputs.empty());
    // In Chinese: the same calls, labelled and typed in its words.
    const calls::Description zh = calls::describe(model, source, official_pack("zh-Hant-HK"));
    REQUIRE(zh.calls.size() == 3);
    CHECK(zh.calls[1].inputs[0].label != d.calls[1].inputs[0].label);
    CHECK(zh.calls[1].clauses != d.calls[1].clauses);
}

TEST_CASE("bo calls: roles an action binds, defaults, time rules", "[bo][calls]") {
    const model::Model model = model_of(order);
    const calls::Description d = calls::describe(model, order, nullptr);
    REQUIRE(d.calls.size() == 2);
    const auto& create = d.calls[0].inputs;
    REQUIRE(create.size() == 9);
    CHECK(create[1].name == "fee");
    CHECK(create[1].optional);
    CHECK(create[1].initial == "HKD 10");
    CHECK(create[0].type == "money cur.HKD");
    CHECK(create[0].type_text == "money in HKD");
    const auto& ship = d.calls[1].inputs;
    REQUIRE(ship.size() == 2);
    CHECK(ship[1].name == "carrier");
    CHECK(ship[1].place == calls::Place::role);
    CHECK(ship[1].optional);

    const std::string source = read_text(golden_dir / "form" / "time" / "source.bo");
    const model::Model hosting = model_of(source);
    const calls::Description rules = calls::describe(hosting, source, nullptr);
    std::vector<std::string> functions;
    for (const calls::Call& c : rules.calls) {
        if (c.kind == calls::Kind::rule) {
            functions.push_back(c.function);
        }
    }
    CHECK(functions == std::vector<std::string>{"when.suspend", "when.terminate"});
    // A time rule takes no values.
    CHECK(calls::arguments(hosting, official(), "when.suspend", {}).value == cbor::Value::null());
    CHECK(codes(calls::arguments(hosting, official(), "when.suspend",
                                 {{"x", {std::string("1")}}})) == ":unknown ");
}

TEST_CASE("bo args: values typed by the contract, in any language's forms", "[bo][calls]") {
    const model::Model model = model_of(order);
    const calls::Arguments built = calls::arguments(model, official(), "create", creation_values());
    INFO(codes(built));
    REQUIRE(built.value.has_value());
    CHECK(field(built, "cost") == "125050");
    CHECK(field(built, "starts") == "1799164800000");
    CHECK(field(built, "weight") == "3000");
    CHECK(field(built, "urgent") == "false");
    CHECK(field(built, "tags") == "[\"fragile\"]");
    CHECK(field(built, "note") == "\"by hand\"");
    // The fee keeps its default: left out.
    CHECK(built.value->find("fields")->find("fee") == nullptr);
    const cbor::Value* parties = built.value->find("parties");
    REQUIRE(parties != nullptr);
    CHECK(cbor::diagnostic(*parties->find("we")) == "h'" + we + "'");
    // Canonical: the same values in another order give the same bytes.
    calls::Values reversed = creation_values();
    std::ranges::reverse(reversed);
    CHECK(calls::arguments(model, official(), "create", reversed).value == built.value);

    // Money in each language's forms, and a plain number in its currency.
    for (const char* cost : {"HKD 1_250.50", "1250.50 HKD", "1_250.50", "1250.5港元"}) {
        INFO(cost);
        CHECK(field(calls::arguments(model, official(), "create", creation_values(cost)), "cost") ==
              "125050");
    }
    CHECK(field(calls::arguments(model, official(), "create", creation_values("500萬港元")),
                "cost") == "500000000");
    for (const char* day : {"2027-01-06", "2027年1月6日"}) {
        INFO(day);
        CHECK(field(calls::arguments(model, official(), "create", creation_values("HKD 1", day)),
                    "starts") == "1799164800000");
    }
    // An action: its input, and the role it binds when given.
    for (const char* days : {"3 days", "3日", "3 天"}) {
        INFO(days);
        const calls::Arguments ship =
            calls::arguments(model, official(), "ship", {{"lead", {std::string(days)}}});
        INFO(codes(ship));
        REQUIRE(ship.value.has_value());
        CHECK(cbor::diagnostic(*ship.value) == "{\"lead\": 259200000}");
    }
    const calls::Arguments bound =
        calls::arguments(model, official(), "ship",
                         {{"lead", {std::string("1 day")}}, {"carrier", {std::string(64, 'a')}}});
    REQUIRE(bound.value.has_value());
    CHECK(bound.value->find("carrier") != nullptr);
}

TEST_CASE("bo args: a role each call names is required, as bo calls says", "[bo][calls]") {
    // The pool allocates an address to a customer each call names (R23):
    // the contract's code refuses a call without the customer's ledger, so
    // the arguments refuse it first, as the form shows it.
    const std::string source = read_text(golden_dir / "form" / "ip-pool" / "source.bo");
    const model::Model model = model_of(source);
    const calls::Description d = calls::describe(model, source, nullptr);
    const calls::Call* allocate = nullptr;
    for (const calls::Call& c : d.calls) {
        if (c.function == "allocate") {
            allocate = &c;
        }
    }
    REQUIRE(allocate != nullptr);
    REQUIRE(allocate->inputs.size() == 1);
    const calls::Input& customer = allocate->inputs[0];
    CHECK(customer.place == calls::Place::role);
    CHECK(customer.each_call);
    CHECK_FALSE(customer.optional);
    const calls::Arguments left_out = calls::arguments(model, official(), "allocate", {});
    CHECK_FALSE(left_out.value.has_value());
    CHECK(codes(left_out) == customer.name + ":missing ");
    const calls::Arguments given =
        calls::arguments(model, official(), "allocate", {{customer.name, {std::string(64, 'c')}}});
    INFO(codes(given));
    REQUIRE(given.value.has_value());
    CHECK(given.value->find(customer.name) != nullptr);
    // A role an action binds once stays optional: the order's carrier.
    const model::Model deal = model_of(order);
    CHECK(calls::arguments(deal, official(), "ship", {{"lead", {std::string("1 day")}}})
              .value.has_value());
}

TEST_CASE("bo args: every problem by its code", "[bo][calls]") {
    const model::Model model = model_of(order);
    const auto problem = [&](calls::Values values, std::string_view function = "create") {
        const calls::Arguments built = calls::arguments(model, official(), function, values);
        CHECK_FALSE(built.value.has_value());
        return codes(built);
    };
    CHECK(problem(creation_values("USD 5")) == "cost:type ");
    CHECK(problem(creation_values("HKD 0.001")) == "cost:exact ");
    CHECK(problem(creation_values("HKD 1 HKD 2")) == "cost:literal ");
    CHECK(problem(creation_values("HKD 1", "tomorrow")) == "starts:literal ");
    CHECK(problem(creation_values("HKD 1", "5")) == "starts:type ");
    // The lexer knows the calendar.
    CHECK(problem(creation_values("HKD 1", "2027-02-30")) == "starts:literal ");
    CHECK(problem(creation_values("HKD 100_000_000_000_000_000")) == "cost:exact ");
    calls::Values values = creation_values();
    values[2].second = {std::string("3 GB")};
    CHECK(problem(values) == "weight:type ");
    values = creation_values();
    values[3].second = {std::string("no")};
    CHECK(problem(values) == "urgent:type ");
    values = creation_values();
    values[4].second = {
        std::vector<calls::Value>{{std::string("a")}, {std::string("b")}, {std::string("c")}}};
    CHECK(problem(values) == "tags:bound ");
    values = creation_values();
    values[5].second = {std::string(1001, 'x')};
    CHECK(problem(values) == "note:size ");
    values = creation_values();
    values[5].second = {std::string("\x8b\xe6\x9c\x88")};
    CHECK(problem(values) == "note:literal ");
    values = creation_values();
    values[7].second = {std::string("not a ledger")};
    CHECK(problem(values) == "buyer:ledger ");
    values = creation_values();
    values.erase(values.begin() + 5);
    CHECK(problem(values) == "note:missing ");
    values = creation_values();
    values.push_back({"colour", {std::string("red")}});
    CHECK(problem(values) == "colour:unknown ");
    values = creation_values();
    values.push_back({"note", {std::string("again")}});
    CHECK(problem(values) == "note:twice ");
    CHECK(problem({{"lead", {std::string("1 month")}}}, "ship") == "lead:type ");
    CHECK(problem({}, "ship") == "lead:missing ");
    CHECK(problem({}, "nothing") == ":function ");
}

TEST_CASE("bo args: people, as actor ids", "[bo][calls]") {
    // R36: a person is an actor id, 64 hexadecimal digits; a list of
    // people, a list of them.
    const model::Model model =
        model_of("contract Payments\nparties we\n\nthing Payment\n  amount HKD\n"
                 "  directors list person at most 3\n\ncan disburse by we with deputy person\n"
                 "  over 1_000 requires 1 approval by directors in person within 7 days\n"
                 "  active -> disbursed\n");
    const std::string alice(64, 'a');
    const std::string bob(64, 'b');
    const calls::Values values{{"amount", {std::string("HKD 2_000")}},
                               {"directors", {std::vector<calls::Value>{{alice}, {bob}}}},
                               {"we", {we}}};
    const calls::Arguments built = calls::arguments(model, official(), "create", values);
    INFO(codes(built));
    REQUIRE(built.value.has_value());
    CHECK(field(built, "directors") == "[h'" + alice + "', h'" + bob + "']");
    const calls::Arguments deputy =
        calls::arguments(model, official(), "disburse", {{"deputy", {bob}}});
    INFO(codes(deputy));
    REQUIRE(deputy.value.has_value());
    CHECK(cbor::diagnostic(*deputy.value) == "{\"deputy\": h'" + bob + "'}");
    const calls::Arguments wrong =
        calls::arguments(model, official(), "disburse", {{"deputy", {std::string("alice")}}});
    CHECK_FALSE(wrong.value.has_value());
    CHECK(codes(wrong) == "deputy:actor ");
    const calls::Arguments short_id =
        calls::arguments(model, official(), "disburse", {{"deputy", {std::string(62, 'a')}}});
    CHECK(codes(short_id) == "deputy:actor ");
}

TEST_CASE("bo args: values from JSON", "[bo][calls]") {
    const auto read = calls::parse_values(R"({"a": "x", "b": true, "c": ["y", "z"]})");
    REQUIRE(std::holds_alternative<calls::Values>(read));
    CHECK(std::get<calls::Values>(read).size() == 3);
    CHECK(std::holds_alternative<std::string>(calls::parse_values("[1]")));
    CHECK(std::holds_alternative<std::string>(calls::parse_values(R"({"a": 1})")));
    CHECK(std::holds_alternative<std::string>(calls::parse_values(R"({"a": [["x"]]})")) == false);
    CHECK(std::holds_alternative<std::string>(calls::parse_values(R"({"a": [[["x"]]]})")));
    CHECK(std::holds_alternative<std::string>(calls::parse_values("not json")));
    CHECK(std::holds_alternative<std::string>(
        calls::parse_values(std::string(calls::max_values_json + 1, ' '))));
    // Nested as deep as 64 KiB allows: the JSON reader keeps its nesting on
    // the heap, and a value is read two lists deep at most.
    const std::size_t deep = (calls::max_values_json - 16) / 2;
    const std::string nested = std::string(deep, '[') + std::string(deep, ']');
    CHECK(std::holds_alternative<std::string>(calls::parse_values(R"({"a": )" + nested + "}")));
    CHECK(std::holds_alternative<std::string>(calls::parse_values(nested)));
    CHECK(std::holds_alternative<std::string>(calls::parse_values(std::string(2 * deep, '['))));
}
