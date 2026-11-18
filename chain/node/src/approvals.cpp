// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include <algorithm>
#include <limits>
#include <string>
#include <system_error>
#include <type_traits>
#include <utility>
#include <variant>

#include <kanhe/core/bytes.hpp>
#include <kanhe/core/cbor.hpp>
#include <kanhe/core/protocol/presence.hpp>
#include <kanhe/node/approvals.hpp>
#include <kanhe/verifier/report.hpp>

#include "files.hpp"

namespace kanhe::node {

namespace {

using json = nlohmann::json;

std::string hex(const protocol::Id& id) {
    return to_hex(id.bytes());
}

std::string short_hex(const protocol::Id& id) {
    return hex(id).substr(0, 12);
}

cbor::Value key(std::uint64_t k) {
    return cbor::Value::unsigned_integer(k);
}

bool before(const protocol::Id& a, const protocol::Id& b) {
    return std::ranges::lexicographical_compare(a.bytes(), b.bytes());
}

constexpr std::unexpected<Error> malformed(std::string_view detail) {
    return fail(Errc::malformed, detail);
}

/// "held/<id>.cbor" or "done/<id>.cbor", and back.
std::string held_name(const protocol::Id& id, bool done) {
    return std::string(done ? "done/" : "held/") + hex(id) + ".cbor";
}

std::optional<protocol::Id> id_of_file(std::string_view file) {
    if (file.size() != 64 + 5 || !file.ends_with(".cbor")) {
        return std::nullopt;
    }
    const std::string_view digits = file.substr(0, 64);
    if (!std::ranges::all_of(
            digits, [](char c) { return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'); })) {
        return std::nullopt;
    }
    const auto bytes = from_hex(digits);
    if (!bytes) {
        return std::nullopt;
    }
    auto id = protocol::to_id(*bytes);
    return id ? std::optional<protocol::Id>(*id) : std::nullopt;
}

std::optional<std::pair<bool, protocol::Id>> parse_held_name(std::string_view name) {
    bool done = false;
    if (name.starts_with("held/")) {
        done = false;
    } else if (name.starts_with("done/")) {
        done = true;
    } else {
        return std::nullopt;
    }
    const auto id = id_of_file(name.substr(5));
    if (!id) {
        return std::nullopt;
    }
    return std::pair{done, *id};
}

Result<cbor::Value> field_value(const protocol::RecordField& field) {
    auto leaf = protocol::encode_field(field);
    if (!leaf) {
        return std::unexpected(leaf.error());
    }
    return cbor::decode(*leaf);
}

Result<protocol::RecordField> field_from(const cbor::Value& value) {
    auto leaf = cbor::encode(value);
    if (!leaf) {
        return std::unexpected(leaf.error());
    }
    return protocol::decode_field(*leaf);
}

Result<cbor::Value> fields_value(std::span<const protocol::RecordField> fields) {
    cbor::Array list;
    for (const protocol::RecordField& f : fields) {
        auto value = field_value(f);
        if (!value) {
            return std::unexpected(value.error());
        }
        list.push_back(std::move(*value));
    }
    return cbor::Value::array(std::move(list));
}

Result<std::vector<protocol::RecordField>> fields_from(const cbor::Value& value) {
    const cbor::Array* list = value.as_array();
    if (list == nullptr || list->empty()) {
        return malformed("the fields shown are a list of fields");
    }
    std::vector<protocol::RecordField> out;
    for (const cbor::Value& item : *list) {
        auto field = field_from(item);
        if (!field) {
            return std::unexpected(field.error());
        }
        out.push_back(std::move(*field));
    }
    return out;
}

Result<std::string> note_from(const cbor::Value& value) {
    const std::string* note = value.as_text();
    if (note == nullptr || note->empty() || note->size() > protocol::max_approval_note) {
        return malformed("a note is 1 to 1,000 bytes of text");
    }
    return *note;
}

Result<protocol::Id> id_value(const cbor::Value& value) {
    const Bytes* bytes = value.as_bytes();
    if (bytes == nullptr) {
        return malformed("an id is a byte string");
    }
    return protocol::to_id(*bytes);
}

/// The approver an approval names, if it parses.
std::optional<protocol::Id> approver_of(const Bytes& approval) {
    auto parsed = protocol::parse_approval(approval);
    return parsed ? std::optional<protocol::Id>(parsed->approval.approver) : std::nullopt;
}

KeptApproval kept_of(const Bytes& encoded, const protocol::ApprovalCheck& check) {
    KeptApproval kept;
    kept.encoded = encoded;
    if (check.presence) {
        kept.presence = check.presence->method;
        kept.user_verified = check.presence->user_verified;
    }
    return kept;
}

/// The earliest end of the rules' windows (0 if none applies).
protocol::Timestamp earliest_lapse(const protocol::ApprovalTally& tally) {
    protocol::Timestamp out = 0;
    for (const protocol::RuleTally& r : tally.rules) {
        out = out == 0 ? r.lapses_at : std::min(out, r.lapses_at);
    }
    return out;
}

/// The signer proved presence, user-verified.
bool signer_verified(const crypto::Provider& provider, const protocol::LedgerState& state,
                     const protocol::SignedStatement& signed_statement) {
    const protocol::Statement& s = signed_statement.statement;
    const protocol::ActorState* signer = s.actor_id ? state.actor(*s.actor_id) : nullptr;
    if (!s.presence || signer == nullptr || signer->kind != protocol::ActorKind::person) {
        return false;
    }
    auto check = protocol::verify_presence(provider, state.hash(), s, signed_statement.kid,
                                           signer->presence);
    return check && check->user_verified;
}

/// The changes that end a held statement: what became of it kept in done/,
/// without its fields or the rest of its submission, and its held file
/// removed.
std::vector<HeldChange> finish(const protocol::Id& id, HeldStatement held, HeldState state,
                               protocol::Timestamp now, std::optional<std::uint64_t> index,
                               std::optional<std::string> reason) {
    held.parts.reset();
    held.fields.clear();
    held.state = state;
    held.ended_at = now;
    held.index = index;
    held.reason = std::move(reason);
    std::vector<HeldChange> changes;
    if (auto encoded = encode_held_statement(held)) {
        changes.push_back({held_name(id, true), std::move(*encoded)});
    }
    changes.push_back({held_name(id, false), std::nullopt});
    return changes;
}

/// The kept approvals parsed, in their order; those that do not parse are
/// left out.
std::vector<protocol::SignedApproval> parse_kept(const HeldStatement& held) {
    std::vector<protocol::SignedApproval> out;
    for (const KeptApproval& k : held.approvals) {
        if (auto parsed = protocol::parse_approval(k.encoded)) {
            out.push_back(std::move(*parsed));
        }
    }
    return out;
}

/// Checks each kept approval alone, as the ledger would at `now`: those that
/// verify stay (with how they proved presence), the others are dropped and
/// listed. True if anything changed.
bool recheck_kept(const crypto::Provider& provider, const protocol::LedgerState& state,
                  const protocol::SignedStatement& signed_statement, HeldStatement& held,
                  protocol::Timestamp now) {
    bool changed = false;
    std::vector<KeptApproval> still;
    for (KeptApproval& k : held.approvals) {
        auto parsed = protocol::parse_approval(k.encoded);
        if (!parsed) {
            changed = true;
            continue;
        }
        auto alone = state.check_approvals(provider, signed_statement, std::span(&*parsed, 1), now);
        if (!alone || alone->approvals.empty()) {
            held.dropped.push_back(
                {parsed->approval.approver, now,
                 alone ? std::string("it counts for no rule") : std::string(alone.error().detail)});
            changed = true;
            continue;
        }
        KeptApproval updated = kept_of(k.encoded, alone->approvals.front());
        changed = changed || !(updated == k);
        still.push_back(std::move(updated));
    }
    held.approvals = std::move(still);
    return changed;
}

json actor_ref(const protocol::LedgerState& state, const protocol::Id& id) {
    const protocol::ActorState* a = state.actor(id);
    return {{"id", hex(id)},
            {"name", a != nullptr ? json(a->display_name) : json("unknown")},
            {"kind", a != nullptr ? json(verifier::kind_text(a->kind)) : json(nullptr)}};
}

std::string actor_name(const protocol::LedgerState& state, const protocol::Id& id) {
    const protocol::ActorState* a = state.actor(id);
    return a != nullptr ? a->display_name : short_hex(id);
}

Status write_into(const std::filesystem::path& path, const Bytes& bytes) {
    std::error_code ec;
    std::filesystem::create_directories(path.parent_path(), ec);
    if (ec) {
        return fail(Errc::unavailable, "cannot create the held statements' directory");
    }
    return detail::write_file(path, bytes, true, false);
}

} // namespace

std::filesystem::path approvals_directory(const std::filesystem::path& ledger_directory) {
    return ledger_directory / "approvals";
}

std::string_view name(HeldState state) noexcept {
    switch (state) {
    case HeldState::open:
        return "open";
    case HeldState::registered:
        return "registered";
    case HeldState::lapsed:
        return "lapsed";
    case HeldState::withdrawn:
        return "withdrawn";
    case HeldState::dropped:
        return "dropped";
    }
    return "unknown";
}

Result<Bytes> encode_held_statement(const HeldStatement& held) {
    cbor::Map map{{key(1), cbor::Value::bytes(held.statement)}};
    if (held.parts) {
        map.push_back({key(2), cbor::Value::bytes(*held.parts)});
    }
    if (!held.fields.empty()) {
        auto fields = fields_value(held.fields);
        if (!fields) {
            return std::unexpected(fields.error());
        }
        map.push_back({key(3), std::move(*fields)});
    }
    if (held.note) {
        map.push_back({key(4), cbor::Value::text(*held.note)});
    }
    if (!held.approvals.empty()) {
        cbor::Array list;
        for (const KeptApproval& k : held.approvals) {
            list.push_back(
                cbor::Value::array({cbor::Value::bytes(k.encoded),
                                    key(k.presence ? static_cast<std::uint64_t>(*k.presence) : 0),
                                    cbor::Value::boolean(k.user_verified)}));
        }
        map.push_back({key(5), cbor::Value::array(std::move(list))});
    }
    map.push_back({key(6), cbor::Value::text(held.preparer)});
    map.push_back({key(7), key(held.held_at)});
    map.push_back({key(8), key(held.lapses_at)});
    map.push_back({key(9), cbor::Value::boolean(held.signer_verified)});
    if (!held.declines.empty()) {
        cbor::Array list;
        for (const HeldDecline& d : held.declines) {
            list.push_back(cbor::Value::array({cbor::Value::bytes(d.approver.bytes()), key(d.at)}));
        }
        map.push_back({key(10), cbor::Value::array(std::move(list))});
    }
    if (!held.dropped.empty()) {
        cbor::Array list;
        for (const DroppedApproval& d : held.dropped) {
            list.push_back(cbor::Value::array(
                {cbor::Value::bytes(d.approver.bytes()), key(d.at), cbor::Value::text(d.reason)}));
        }
        map.push_back({key(11), cbor::Value::array(std::move(list))});
    }
    if (held.state != HeldState::open) {
        map.push_back({key(12), key(static_cast<std::uint64_t>(held.state))});
        map.push_back({key(13), key(held.ended_at)});
    }
    if (held.index) {
        map.push_back({key(14), key(*held.index)});
    }
    if (held.reason) {
        map.push_back({key(15), cbor::Value::text(*held.reason)});
    }
    return cbor::encode(cbor::Value::map(std::move(map)));
}

Result<HeldStatement> decode_held_statement(ByteView encoded) {
    auto value = cbor::decode(encoded);
    if (!value) {
        return std::unexpected(value.error());
    }
    const cbor::Map* map = value->as_map();
    if (map == nullptr || !std::ranges::all_of(*map, [](const cbor::MapEntry& e) {
            const auto k = e.key.as_uint64();
            return k && *k >= 1 && *k <= 15;
        })) {
        return malformed("a held statement is a map of keys 1 to 15");
    }
    HeldStatement held;
    const cbor::Value* statement = value->find(1);
    if (statement == nullptr || statement->as_bytes() == nullptr) {
        return malformed("a held statement holds its signed statement");
    }
    held.statement = *statement->as_bytes();
    if (const cbor::Value* parts = value->find(2)) {
        if (parts->as_bytes() == nullptr) {
            return malformed("a held statement's parts are a byte string");
        }
        held.parts = *parts->as_bytes();
    }
    if (const cbor::Value* fields = value->find(3)) {
        auto decoded = fields_from(*fields);
        if (!decoded) {
            return std::unexpected(decoded.error());
        }
        held.fields = std::move(*decoded);
    }
    if (const cbor::Value* note = value->find(4)) {
        auto decoded = note_from(*note);
        if (!decoded) {
            return std::unexpected(decoded.error());
        }
        held.note = std::move(*decoded);
    }
    if (const cbor::Value* approvals = value->find(5)) {
        const cbor::Array* list = approvals->as_array();
        if (list == nullptr || list->empty() || list->size() > protocol::max_approvals) {
            return malformed("a held statement keeps 1 to 32 approvals");
        }
        for (const cbor::Value& item : *list) {
            const cbor::Array* parts = item.as_array();
            if (parts == nullptr || parts->size() != 3 || (*parts)[0].as_bytes() == nullptr ||
                !(*parts)[1].as_uint64() || *(*parts)[1].as_uint64() > 2 ||
                !(*parts)[2].as_bool()) {
                return malformed("a kept approval is [approval, presence, user verified]");
            }
            KeptApproval kept{*(*parts)[0].as_bytes(), std::nullopt, *(*parts)[2].as_bool()};
            if (const std::uint64_t method = *(*parts)[1].as_uint64(); method != 0) {
                kept.presence = static_cast<protocol::PresenceMethod>(method);
            }
            held.approvals.push_back(std::move(kept));
        }
    }
    const cbor::Value* preparer = value->find(6);
    const cbor::Value* held_at = value->find(7);
    const cbor::Value* lapses_at = value->find(8);
    const cbor::Value* verified = value->find(9);
    if (preparer == nullptr || preparer->as_text() == nullptr || held_at == nullptr ||
        !held_at->as_uint64() || lapses_at == nullptr || !lapses_at->as_uint64() ||
        verified == nullptr || !verified->as_bool()) {
        return malformed("a held statement names its preparer, when it was held and lapses, and "
                         "whether its signer was verified");
    }
    held.preparer = *preparer->as_text();
    held.held_at = *held_at->as_uint64();
    held.lapses_at = *lapses_at->as_uint64();
    held.signer_verified = *verified->as_bool();
    if (const cbor::Value* declines = value->find(10)) {
        const cbor::Array* list = declines->as_array();
        if (list == nullptr || list->empty()) {
            return malformed("declines are a list of one or more");
        }
        for (const cbor::Value& item : *list) {
            const cbor::Array* parts = item.as_array();
            if (parts == nullptr || parts->size() != 2 || !(*parts)[1].as_uint64()) {
                return malformed("a decline is [approver, at]");
            }
            auto approver = id_value((*parts)[0]);
            if (!approver) {
                return std::unexpected(approver.error());
            }
            held.declines.push_back({*approver, *(*parts)[1].as_uint64()});
        }
    }
    if (const cbor::Value* dropped = value->find(11)) {
        const cbor::Array* list = dropped->as_array();
        if (list == nullptr || list->empty()) {
            return malformed("dropped approvals are a list of one or more");
        }
        for (const cbor::Value& item : *list) {
            const cbor::Array* parts = item.as_array();
            if (parts == nullptr || parts->size() != 3 || !(*parts)[1].as_uint64() ||
                (*parts)[2].as_text() == nullptr) {
                return malformed("a dropped approval is [approver, at, reason]");
            }
            auto approver = id_value((*parts)[0]);
            if (!approver) {
                return std::unexpected(approver.error());
            }
            held.dropped.push_back({*approver, *(*parts)[1].as_uint64(), *(*parts)[2].as_text()});
        }
    }
    if (const cbor::Value* state = value->find(12)) {
        const auto code = state->as_uint64();
        const cbor::Value* ended = value->find(13);
        if (!code || *code < 1 || *code > 4 || ended == nullptr || !ended->as_uint64()) {
            return malformed("what became of a held statement is 1 to 4, with when");
        }
        held.state = static_cast<HeldState>(*code);
        held.ended_at = *ended->as_uint64();
    } else if (value->find(13) != nullptr) {
        return malformed("an open held statement has not ended");
    }
    if (const cbor::Value* index = value->find(14)) {
        if (!index->as_uint64()) {
            return malformed("a log index is a number");
        }
        held.index = *index->as_uint64();
    }
    if (const cbor::Value* reason = value->find(15)) {
        if (reason->as_text() == nullptr) {
            return malformed("a reason is text");
        }
        held.reason = *reason->as_text();
    }
    return held;
}

Result<Bytes> encode_hold_request(const HeldStatement& held) {
    cbor::Map map{{key(1), cbor::Value::bytes(held.statement)}};
    if (held.parts) {
        map.push_back({key(2), cbor::Value::bytes(*held.parts)});
    }
    if (!held.fields.empty()) {
        auto fields = fields_value(held.fields);
        if (!fields) {
            return std::unexpected(fields.error());
        }
        map.push_back({key(3), std::move(*fields)});
    }
    if (held.note) {
        map.push_back({key(4), cbor::Value::text(*held.note)});
    }
    return cbor::encode(cbor::Value::map(std::move(map)));
}

Result<HeldStatement> decode_hold_request(ByteView encoded) {
    auto value = cbor::decode(encoded);
    if (!value) {
        return std::unexpected(value.error());
    }
    const cbor::Map* map = value->as_map();
    if (map == nullptr || !std::ranges::all_of(*map, [](const cbor::MapEntry& e) {
            const auto k = e.key.as_uint64();
            return k && *k >= 1 && *k <= 4;
        })) {
        return malformed("send {1: signed statement, ? 2: submission parts, ? 3: fields, ? 4: "
                         "note}");
    }
    HeldStatement held;
    const cbor::Value* statement = value->find(1);
    if (statement == nullptr || statement->as_bytes() == nullptr) {
        return malformed("send the signed statement in key 1");
    }
    held.statement = *statement->as_bytes();
    if (const cbor::Value* parts = value->find(2)) {
        if (parts->as_bytes() == nullptr) {
            return malformed("the submission's parts (key 2) are a byte string");
        }
        held.parts = *parts->as_bytes();
    }
    if (const cbor::Value* fields = value->find(3)) {
        auto decoded = fields_from(*fields);
        if (!decoded) {
            return std::unexpected(decoded.error());
        }
        held.fields = std::move(*decoded);
    }
    if (const cbor::Value* note = value->find(4)) {
        auto decoded = note_from(*note);
        if (!decoded) {
            return std::unexpected(decoded.error());
        }
        held.note = std::move(*decoded);
    }
    return held;
}

cbor::Value held_changes_value(std::span<const HeldChange> changes) {
    return pending_changes_value(changes);
}

Result<std::vector<HeldChange>> decode_held_changes(const cbor::Value& value) {
    const cbor::Array* list = value.as_array();
    if (list == nullptr || list->size() > 8 * max_held_statements) {
        return malformed("changes to held statements are a list");
    }
    std::vector<HeldChange> out;
    for (const cbor::Value& item : *list) {
        const cbor::Array* parts = item.as_array();
        if (parts == nullptr || parts->size() != 2 || (*parts)[0].as_text() == nullptr ||
            ((*parts)[1].as_bytes() == nullptr && !(*parts)[1].is_null())) {
            return malformed("a change to a held statement is [name, file or null]");
        }
        HeldChange change{*(*parts)[0].as_text(), std::nullopt};
        if (const Bytes* file = (*parts)[1].as_bytes()) {
            change.file = *file;
        }
        out.push_back(std::move(change));
    }
    return out;
}

Status apply_held_changes(const std::filesystem::path& ledger_directory,
                          std::span<const HeldChange> changes) {
    for (const HeldChange& c : changes) {
        const auto parsed = parse_held_name(c.name);
        if (!parsed) {
            return malformed("not a held statement's name");
        }
        if (c.file) {
            auto held = decode_held_statement(*c.file);
            if (!held || (held->state != HeldState::open) != parsed->first) {
                return malformed("a held statement's file does not match its name");
            }
        }
    }
    const std::filesystem::path root = approvals_directory(ledger_directory);
    bool wrote_held = false;
    bool wrote_done = false;
    for (const HeldChange& c : changes) {
        const std::filesystem::path path = root / c.name;
        if (c.file) {
            if (auto s = write_into(path, *c.file); !s) {
                return s;
            }
            (parse_held_name(c.name)->first ? wrote_done : wrote_held) = true;
        } else {
            std::error_code ec;
            std::filesystem::remove(path, ec);
        }
    }
    if (wrote_held) {
        detail::sync_directory(root / "held");
    }
    if (wrote_done) {
        detail::sync_directory(root / "done");
    }
    return {};
}

std::vector<std::string> held_file_names(const std::filesystem::path& ledger_directory) {
    std::vector<std::string> out;
    for (const bool done : {false, true}) {
        const std::filesystem::path dir =
            approvals_directory(ledger_directory) / (done ? "done" : "held");
        std::error_code ec;
        for (auto it = std::filesystem::directory_iterator(dir, ec);
             !ec && it != std::filesystem::directory_iterator(); it.increment(ec)) {
            if (const auto id = id_of_file(it->path().filename().string())) {
                out.push_back(held_name(*id, done));
            }
        }
    }
    std::ranges::sort(out);
    return out;
}

std::vector<std::pair<protocol::Id, HeldStatement>>
held_statements(const std::filesystem::path& ledger_directory, bool done) {
    std::vector<std::pair<protocol::Id, HeldStatement>> out;
    const std::filesystem::path dir =
        approvals_directory(ledger_directory) / (done ? "done" : "held");
    std::vector<protocol::Id> ids;
    std::error_code ec;
    for (auto it = std::filesystem::directory_iterator(dir, ec);
         !ec && it != std::filesystem::directory_iterator(); it.increment(ec)) {
        if (const auto id = id_of_file(it->path().filename().string())) {
            ids.push_back(*id);
        }
    }
    std::ranges::sort(ids, before);
    for (const protocol::Id& id : ids) {
        auto file = detail::read_file(dir / (hex(id) + ".cbor"));
        auto held = file ? decode_held_statement(*file)
                         : Result<HeldStatement>(std::unexpected(file.error()));
        if (held && (held->state != HeldState::open) == done) {
            out.emplace_back(id, std::move(*held));
        }
    }
    return out;
}

std::optional<HeldStatement> held_statement(const std::filesystem::path& ledger_directory,
                                            const protocol::Id& id, bool done) {
    auto file = detail::read_file(approvals_directory(ledger_directory) / held_name(id, done));
    if (!file) {
        return std::nullopt;
    }
    auto held = decode_held_statement(*file);
    if (!held || (held->state != HeldState::open) != done) {
        return std::nullopt;
    }
    return std::move(*held);
}

std::size_t held_count(const std::filesystem::path& ledger_directory) {
    std::size_t n = 0;
    std::error_code ec;
    for (auto it = std::filesystem::directory_iterator(
             approvals_directory(ledger_directory) / "held", ec);
         !ec && it != std::filesystem::directory_iterator(); it.increment(ec)) {
        n += id_of_file(it->path().filename().string()) ? 1U : 0U;
    }
    return n;
}

Result<Bytes> held_approval_file(const crypto::Provider& provider, crypto::HashAlg hash,
                                 const HeldStatement& held) {
    protocol::ApprovalFile file;
    auto parsed = protocol::parse_statement(provider, held.statement, hash);
    if (!parsed) {
        return std::unexpected(parsed.error());
    }
    file.statement = std::move(*parsed);
    file.approvals = parse_kept(held);
    if (held.parts) {
        auto parts = protocol::decode_submission_parts(*held.parts);
        if (!parts) {
            return std::unexpected(parts.error());
        }
        file.parts = std::move(*parts);
    }
    file.fields = held.fields;
    file.note = held.note;
    return protocol::encode_approval_file(file);
}

// ---------------------------------------------------------------------------
// The desk
// ---------------------------------------------------------------------------

ApprovalDesk::ApprovalDesk(std::filesystem::path ledger_directory)
    : directory_(std::move(ledger_directory)) {}

Result<HeldProgress> ApprovalDesk::hold(const crypto::Provider& provider,
                                        const protocol::LedgerState& state, HeldStatement candidate,
                                        protocol::Timestamp now) const {
    auto parsed = protocol::parse_statement(provider, candidate.statement, state.hash());
    if (!parsed) {
        return std::unexpected(parsed.error());
    }
    const protocol::SignedStatement& signed_statement = *parsed;
    const protocol::Statement& statement = signed_statement.statement;
    if (statement.type() == protocol::StatementType::genesis) {
        return fail(Errc::rejected, "a genesis is never held for approval");
    }
    HeldProgress out;
    out.id = signed_statement.id;
    if (state.statement_index(out.id)) {
        // Registered already: answered as a registration is.
        out.verdict = HeldProgress::Verdict::ready;
        out.held = std::move(candidate);
        return out;
    }
    if (auto s = state.validate_held(provider, signed_statement, now); !s) {
        return std::unexpected(s.error());
    }
    if (candidate.parts) {
        auto parts = protocol::decode_submission_parts(*candidate.parts);
        if (!parts) {
            return std::unexpected(parts.error());
        }
        if (auto s = protocol::check_submission_parts(statement, *parts); !s) {
            return std::unexpected(s.error());
        }
    }
    if (!candidate.fields.empty()) {
        if (auto s =
                protocol::check_shown_fields(provider, state.hash(), statement, candidate.fields);
            !s) {
            return std::unexpected(s.error());
        }
    }
    if (candidate.note &&
        (candidate.note->empty() || candidate.note->size() > protocol::max_approval_note)) {
        return fail(Errc::invalid_argument, "a note is 1 to 1,000 bytes");
    }
    auto tally = state.check_approvals(provider, signed_statement, {}, now);
    if (!tally) {
        return std::unexpected(tally.error());
    }
    out.tally = std::move(*tally);
    if (out.tally.none() || out.tally.met(now)) {
        out.verdict = HeldProgress::Verdict::ready;
        out.held = std::move(candidate);
        return out;
    }
    if (auto existing = held_statement(directory_, out.id)) {
        // The same statement again: as it stands.
        const std::vector<protocol::SignedApproval> kept = parse_kept(*existing);
        if (auto counted = state.check_approvals(provider, signed_statement, kept, now)) {
            out.tally = std::move(*counted);
        }
        out.verdict =
            out.tally.met(now) ? HeldProgress::Verdict::ready : HeldProgress::Verdict::waiting;
        for (const KeptApproval& k : existing->approvals) {
            out.approvals.push_back(k.encoded);
        }
        out.held = std::move(*existing);
        return out;
    }
    if (held_count(directory_) >= max_held_statements) {
        return fail(Errc::limit_exceeded,
                    "1,000 statements are held for approval here already: withdraw one first");
    }
    candidate.approvals.clear();
    candidate.declines.clear();
    candidate.dropped.clear();
    candidate.state = HeldState::open;
    candidate.ended_at = 0;
    candidate.index.reset();
    candidate.reason.reset();
    candidate.held_at = now;
    candidate.lapses_at = earliest_lapse(out.tally);
    candidate.signer_verified = signer_verified(provider, state, signed_statement);
    auto file = encode_held_statement(candidate);
    if (!file) {
        return std::unexpected(file.error());
    }
    if (file->size() > max_held_statement) {
        return fail(Errc::limit_exceeded, "a statement held for approval is at most 1 MiB, with "
                                          "what comes with it");
    }
    out.changes.push_back({held_name(out.id, false), std::move(*file)});
    out.held = std::move(candidate);
    out.verdict = HeldProgress::Verdict::waiting;
    return out;
}

Result<HeldProgress> ApprovalDesk::approve(const crypto::Provider& provider,
                                           const protocol::LedgerState& state,
                                           const protocol::Id& id, ByteView approval_bytes,
                                           protocol::Timestamp now) const {
    auto found = held_statement(directory_, id);
    if (!found) {
        return fail(Errc::not_found, "no statement is held for approval with this id");
    }
    HeldStatement held = std::move(*found);
    auto parsed = protocol::parse_statement(provider, held.statement, state.hash());
    if (!parsed) {
        return std::unexpected(parsed.error());
    }
    const protocol::SignedStatement& signed_statement = *parsed;
    // 3.1 and 3.2: an approval, of this statement on this ledger.
    auto approval = protocol::parse_approval(approval_bytes);
    if (!approval) {
        return std::unexpected(approval.error());
    }
    if (approval->approval.ledger != state.ledger_id()) {
        return fail(Errc::rejected, "the approval is for another ledger");
    }
    if (approval->approval.statement != id) {
        return fail(Errc::rejected, "the approval is for another statement");
    }
    HeldProgress out;
    out.id = id;
    if (const auto index = state.statement_index(id)) {
        out.verdict = HeldProgress::Verdict::ready;
        out.changes = finish(id, held, HeldState::registered, now, *index, std::nullopt);
        out.held = std::move(held);
        return out;
    }
    if (now > held.lapses_at) {
        return fail(Errc::rejected, "the statement lapsed: its window has ended");
    }
    if (auto s = state.validate_held(provider, signed_statement, now); !s) {
        return std::unexpected(s.error());
    }
    bool retry = false;
    for (const KeptApproval& k : held.approvals) {
        if (approver_of(k.encoded) == std::optional<protocol::Id>(approval->approval.approver)) {
            if (!std::ranges::equal(k.encoded, approval_bytes)) {
                return fail(Errc::rejected,
                            "an approval by this approver is kept already: it approves once");
            }
            retry = true;
        }
    }
    // 3.3 to 3.7, for this one alone, as the ledger will check it.
    auto alone = state.check_approvals(provider, signed_statement, std::span(&*approval, 1), now);
    if (!alone) {
        return std::unexpected(alone.error());
    }
    if (alone->approvals.empty()) {
        return fail(Errc::rejected, "the approval counts for no rule of the statement");
    }
    // Kept approvals that stopped verifying are dropped, so that their
    // approvers may approve again.
    bool changed = recheck_kept(provider, state, signed_statement, held, now);
    if (!retry) {
        held.approvals.push_back(kept_of(approval->encoded, alone->approvals.front()));
        changed = true;
    }
    std::ranges::sort(held.approvals, [](const KeptApproval& a, const KeptApproval& b) {
        const auto x = approver_of(a.encoded);
        const auto y = approver_of(b.encoded);
        return x && y && before(*x, *y);
    });
    if (held.approvals.size() > protocol::max_approvals) {
        return fail(Errc::limit_exceeded, "a statement travels with at most 32 approvals");
    }
    // A decline the approver left is superseded by its approval.
    std::erase_if(held.declines,
                  [&](const HeldDecline& d) { return d.approver == approval->approval.approver; });
    const std::vector<protocol::SignedApproval> kept = parse_kept(held);
    auto tally = state.check_approvals(provider, signed_statement, kept, now);
    if (!tally) {
        return std::unexpected(tally.error());
    }
    out.tally = std::move(*tally);
    if (changed) {
        auto file = encode_held_statement(held);
        if (!file) {
            return std::unexpected(file.error());
        }
        if (file->size() > max_held_statement) {
            return fail(Errc::limit_exceeded, "a statement held for approval is at most 1 MiB, "
                                              "with what comes with it");
        }
        out.changes.push_back({held_name(id, false), std::move(*file)});
    }
    out.verdict =
        out.tally.met(now) ? HeldProgress::Verdict::ready : HeldProgress::Verdict::waiting;
    for (const KeptApproval& k : held.approvals) {
        out.approvals.push_back(k.encoded);
    }
    out.held = std::move(held);
    return out;
}

Result<std::vector<HeldChange>> ApprovalDesk::withdraw(const protocol::Id& id,
                                                       protocol::Timestamp now) const {
    auto found = held_statement(directory_, id);
    if (!found) {
        return fail(Errc::not_found, "no statement is held for approval with this id");
    }
    return finish(id, std::move(*found), HeldState::withdrawn, now, std::nullopt, std::nullopt);
}

Result<std::vector<HeldChange>> ApprovalDesk::decline(const crypto::Provider& provider,
                                                      const protocol::LedgerState& state,
                                                      const protocol::Id& id,
                                                      const protocol::Id& approver,
                                                      protocol::Timestamp now) const {
    auto found = held_statement(directory_, id);
    if (!found) {
        return fail(Errc::not_found, "no statement is held for approval with this id");
    }
    HeldStatement held = std::move(*found);
    auto statement = protocol::parse_statement(provider, held.statement, state.hash());
    if (!statement) {
        return std::unexpected(statement.error());
    }
    const auto rules = state.approval_rules(statement->statement);
    if (std::ranges::none_of(rules, [&](const protocol::AppliedRule& r) {
            return std::ranges::contains(r.rule.approvers, approver);
        })) {
        return fail(Errc::rejected, "no approval rule of the statement names this approver");
    }
    std::erase_if(held.declines, [&](const HeldDecline& d) { return d.approver == approver; });
    held.declines.push_back({approver, now});
    auto file = encode_held_statement(held);
    if (!file) {
        return std::unexpected(file.error());
    }
    return std::vector<HeldChange>{{held_name(id, false), std::move(*file)}};
}

std::vector<HeldChange> ApprovalDesk::registered(const protocol::Id& id, std::uint64_t index,
                                                 protocol::Timestamp now) const {
    auto found = held_statement(directory_, id);
    if (!found) {
        return {};
    }
    return finish(id, std::move(*found), HeldState::registered, now, index, std::nullopt);
}

std::vector<HeldChange> ApprovalDesk::sweep(const crypto::Provider& provider,
                                            const protocol::LedgerState& state,
                                            protocol::Timestamp now, bool recheck) const {
    std::vector<HeldChange> changes;
    auto add = [&](std::vector<HeldChange> more) {
        changes.insert(changes.end(), std::make_move_iterator(more.begin()),
                       std::make_move_iterator(more.end()));
    };
    for (auto& [id, held] : held_statements(directory_)) {
        if (const auto index = state.statement_index(id)) {
            add(finish(id, std::move(held), HeldState::registered, now, *index, std::nullopt));
            continue;
        }
        if (now > held.lapses_at) {
            add(finish(id, std::move(held), HeldState::lapsed, now, std::nullopt, std::nullopt));
            continue;
        }
        if (!recheck) {
            continue;
        }
        auto parsed = protocol::parse_statement(provider, held.statement, state.hash());
        if (!parsed) {
            add(finish(id, std::move(held), HeldState::dropped, now, std::nullopt,
                       std::string("the statement does not parse")));
            continue;
        }
        if (auto s = state.validate_held(provider, *parsed, now); !s) {
            add(finish(id, std::move(held), HeldState::dropped, now, std::nullopt,
                       std::string(s.error().detail)));
            continue;
        }
        if (recheck_kept(provider, state, *parsed, held, now)) {
            if (auto file = encode_held_statement(held)) {
                changes.push_back({held_name(id, false), std::move(*file)});
            }
        }
    }
    for (const auto& [id, done] : held_statements(directory_, true)) {
        if (done.ended_at < now && now - done.ended_at > held_history) {
            changes.push_back({held_name(id, true), std::nullopt});
        }
    }
    return changes;
}

// ---------------------------------------------------------------------------
// Views
// ---------------------------------------------------------------------------

bool may_approve(const crypto::Provider& provider, const protocol::LedgerState& state,
                 const HeldStatement& held, const protocol::Id& approver) {
    auto parsed = protocol::parse_statement(provider, held.statement, state.hash());
    if (!parsed || parsed->statement.actor_id == std::optional<protocol::Id>(approver)) {
        return false;
    }
    for (const KeptApproval& k : held.approvals) {
        if (approver_of(k.encoded) == std::optional<protocol::Id>(approver)) {
            return false;
        }
    }
    const auto rules = state.approval_rules(parsed->statement);
    return std::ranges::any_of(rules, [&](const protocol::AppliedRule& r) {
        return std::ranges::contains(r.rule.approvers, approver);
    });
}

std::string held_summary(const protocol::LedgerState& state, const protocol::Statement& statement) {
    const auto quoted = [&](const protocol::Id& id) {
        return "\"" + actor_name(state, id) + "\"";
    };
    return std::visit(
        [&](const auto& b) -> std::string {
            using T = std::decay_t<decltype(b)>;
            if constexpr (std::is_same_v<T, protocol::ActorRegisterBody>) {
                return "register " + verifier::kind_label(b.kind) + " \"" + b.display_name + "\"";
            } else if constexpr (std::is_same_v<T, protocol::ActorRotateKeyBody>) {
                return b.actor == state.ledger_id() ? std::string("rotate the organization's "
                                                                  "root key")
                                                    : "rotate the key of " + quoted(b.actor);
            } else if constexpr (std::is_same_v<T, protocol::ActorRevokeBody>) {
                return "revoke " + quoted(b.actor);
            } else if constexpr (std::is_same_v<T, protocol::DelegationGrantBody>) {
                return "grant a delegation to " + quoted(b.grantee);
            } else if constexpr (std::is_same_v<T, protocol::DelegationRevokeBody>) {
                return "revoke the delegation " + short_hex(b.delegation);
            } else if constexpr (std::is_same_v<T, protocol::ActorSetPresenceBody>) {
                return "set the presence credentials of " + quoted(b.actor);
            } else if constexpr (std::is_same_v<T, protocol::LedgerRotateLogKeyBody>) {
                return "rotate the log key";
            } else if constexpr (std::is_same_v<T, protocol::LedgerSetGuardiansBody>) {
                return b.guardians
                           ? "set guardians: " + std::to_string(b.guardians->needed) + " of " +
                                 std::to_string(b.guardians->approvers.size()) + " must approve"
                           : std::string("remove the guardians");
            } else if constexpr (std::is_same_v<T, protocol::RecordRegisterBody>) {
                return "register a " + b.record_type + " record";
            } else if constexpr (std::is_same_v<T, protocol::RecordEndorseBody>) {
                return "endorse " + short_hex(b.record) + " as " + b.role;
            } else if constexpr (std::is_same_v<T, protocol::RecordTransitionBody>) {
                return "move " + short_hex(b.record) + " from " + b.from_state + " to " +
                       b.to_state;
            } else if constexpr (std::is_same_v<T, protocol::RecordRevokeBody>) {
                return "revoke the record " + short_hex(b.record);
            } else if constexpr (std::is_same_v<T, protocol::ContractDeployBody>) {
                return "deploy the contract " + b.name.value_or(std::string("(unnamed)"));
            } else if constexpr (std::is_same_v<T, protocol::ContractCallBody>) {
                return b.instance ? "call " + b.function + " on " + short_hex(*b.instance)
                                  : "create an instance with " + b.function;
            } else if constexpr (std::is_same_v<T, protocol::ContractRetireBody>) {
                return "retire the contract " + short_hex(b.contract);
            } else {
                return std::string(protocol::name(statement.type()));
            }
        },
        statement.body);
}

json held_list_json(const crypto::Provider& provider, const protocol::LedgerState& state,
                    const std::filesystem::path& ledger_directory,
                    const std::optional<protocol::Id>& approver, bool all,
                    protocol::Timestamp now) {
    json list = json::array();
    for (const auto& [id, held] : held_statements(ledger_directory)) {
        if (!approver || may_approve(provider, state, held, *approver)) {
            list.push_back(held_json(provider, state, id, held));
        }
    }
    if (all) {
        for (const auto& [id, held] : held_statements(ledger_directory, true)) {
            if (held.ended_at < now && now - held.ended_at > held_history) {
                continue;
            }
            json item = held_json(provider, state, id, held);
            bool concerns = !approver;
            for (const json& rule : item["rules"]) {
                for (const json& a : rule["approvers"]) {
                    concerns = concerns || a.value("id", std::string()) == hex(*approver);
                }
            }
            if (concerns) {
                list.push_back(std::move(item));
            }
        }
    }
    return {{"approvals", std::move(list)}, {"time", now}};
}

json held_json(const crypto::Provider& provider, const protocol::LedgerState& state,
               const protocol::Id& id, const HeldStatement& held) {
    json out = {{"id", hex(id)}, {"state", name(held.state)}};
    auto parsed = protocol::parse_statement(provider, held.statement, state.hash());
    if (!parsed) {
        out["error"] = "the statement does not parse";
        return out;
    }
    const protocol::Statement& st = parsed->statement;
    out["type"] = protocol::name(st.type());
    out["summary"] = held_summary(state, st);
    out["signer"] = st.actor_id ? actor_ref(state, *st.actor_id) : json(nullptr);
    out["delegation"] = st.delegation_id ? json(hex(*st.delegation_id)) : json(nullptr);
    out["issued_at"] = st.issued_at;
    out["held_at"] = held.held_at;
    out["preparer"] = held.preparer;
    out["lapses_at"] = held.lapses_at;
    out["note"] = held.note ? json(*held.note) : json(nullptr);
    out["fields_shown"] = !held.fields.empty();
    out["signer_verified"] = held.signer_verified;

    const std::vector<protocol::SignedApproval> kept = parse_kept(held);
    const auto rules = state.approval_rules(st);
    // Whether each kept approval counts for each rule, as it was checked.
    auto counts = [&](std::size_t approval, const protocol::ApprovalRule& rule) {
        const protocol::Id& approver = kept[approval].approval.approver;
        const auto k = std::ranges::find_if(held.approvals, [&](const KeptApproval& a) {
            return approver_of(a.encoded) == std::optional<protocol::Id>(approver);
        });
        return std::ranges::contains(rule.approvers, approver) &&
               (rule.without_presence || (k != held.approvals.end() && k->user_verified));
    };
    json rule_list = json::array();
    json missing = json::array();
    for (const protocol::AppliedRule& applied : rules) {
        const protocol::ApprovalRule& rule = applied.rule;
        json approvers = json::array();
        for (const protocol::Id& a : rule.approvers) {
            approvers.push_back(actor_ref(state, a));
        }
        json counted = json::array();
        std::uint64_t count = 0;
        for (std::size_t i = 0; i < kept.size(); ++i) {
            if (counts(i, rule)) {
                counted.push_back(hex(kept[i].approval.approver));
                ++count;
            }
        }
        const bool signer_counts = st.actor_id &&
                                   std::ranges::contains(rule.approvers, *st.actor_id) &&
                                   (held.signer_verified || rule.without_presence);
        if (signer_counts) {
            counted.push_back(hex(*st.actor_id));
            ++count;
        }
        const std::uint64_t short_by = count >= rule.needed ? 0 : rule.needed - count;
        const protocol::Timestamp lapses =
            st.issued_at > std::numeric_limits<protocol::Timestamp>::max() - rule.within
                ? std::numeric_limits<protocol::Timestamp>::max()
                : st.issued_at + rule.within;
        rule_list.push_back(
            {{"source", protocol::name(applied.source)},
             {"delegation", applied.delegation ? json(hex(*applied.delegation)) : json(nullptr)},
             {"k", rule.needed},
             {"approvers", std::move(approvers)},
             {"within_ms", rule.within},
             {"without_presence", rule.without_presence},
             {"counted", std::move(counted)},
             {"signer_counts", signer_counts},
             {"missing", short_by},
             {"lapses_at", lapses}});
        missing.push_back(short_by);
    }
    out["rules"] = std::move(rule_list);
    out["missing"] = std::move(missing);
    json approvals = json::array();
    for (std::size_t i = 0; i < kept.size(); ++i) {
        const auto k = std::ranges::find_if(held.approvals, [&](const KeptApproval& a) {
            return approver_of(a.encoded) == std::optional<protocol::Id>(kept[i].approval.approver);
        });
        json counts_for = json::array();
        for (std::size_t r = 0; r < rules.size(); ++r) {
            if (counts(i, rules[r].rule)) {
                counts_for.push_back(r);
            }
        }
        std::optional<protocol::PresenceMethod> method;
        if (k != held.approvals.end()) {
            method = k->presence;
        }
        approvals.push_back(
            {{"approver", actor_ref(state, kept[i].approval.approver)},
             {"approved_at", kept[i].approval.approved_at},
             {"presence", !method                                             ? json(nullptr)
                          : *method == protocol::PresenceMethod::hardware_key ? json("hardware-key")
                                                                              : json("passkey")},
             {"user_verified", k != held.approvals.end() && k->user_verified},
             {"counts_for", std::move(counts_for)}});
    }
    out["approvals"] = std::move(approvals);
    json declines = json::array();
    for (const HeldDecline& d : held.declines) {
        declines.push_back({{"approver", actor_ref(state, d.approver)}, {"at", d.at}});
    }
    out["declines"] = std::move(declines);
    json dropped = json::array();
    for (const DroppedApproval& d : held.dropped) {
        dropped.push_back(
            {{"approver", actor_ref(state, d.approver)}, {"at", d.at}, {"reason", d.reason}});
    }
    out["dropped"] = std::move(dropped);
    if (held.state != HeldState::open) {
        out["ended_at"] = held.ended_at;
        out["index"] = held.index ? json(*held.index) : json(nullptr);
        out["reason"] = held.reason ? json(*held.reason) : json(nullptr);
    }
    return out;
}

} // namespace kanhe::node
