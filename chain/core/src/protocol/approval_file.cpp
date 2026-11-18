// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include <algorithm>
#include <utility>
#include <variant>

#include <kanhe/core/cbor.hpp>
#include <kanhe/core/protocol/approval_file.hpp>

namespace kanhe::protocol {

namespace {

constexpr std::unexpected<Error> malformed(std::string_view detail) {
    return fail(Errc::malformed, detail);
}

/// At most this many attached files travel in a submission.
constexpr std::size_t max_submission_files = 256;

bool before(const Id& a, const Id& b) {
    return std::ranges::lexicographical_compare(a.bytes(), b.bytes());
}

cbor::Value key(std::uint64_t k) {
    return cbor::Value::unsigned_integer(k);
}

/// Every key of `map` is a whole number from `first` to `last`.
bool keys_within(const cbor::Map& map, std::uint64_t first, std::uint64_t last) {
    return std::ranges::all_of(map, [&](const cbor::MapEntry& e) {
        const auto k = e.key.as_uint64();
        return k && *k >= first && *k <= last;
    });
}

Status check_approvals_for(const SignedStatement& statement,
                           std::span<const SignedApproval> approvals) {
    if (approvals.size() > max_approvals) {
        return fail(Errc::limit_exceeded, "an approval file carries at most 32 approvals");
    }
    for (std::size_t i = 0; i < approvals.size(); ++i) {
        const Approval& a = approvals[i].approval;
        if (!statement.statement.ledger_id || a.ledger != *statement.statement.ledger_id) {
            return fail(Errc::rejected, "an approval in the file is for another ledger");
        }
        if (a.statement != statement.id) {
            return fail(Errc::rejected, "an approval in the file is for another statement");
        }
        for (std::size_t j = 0; j < i; ++j) {
            if (approvals[j].approval.approver == a.approver) {
                return fail(Errc::rejected, "an approval file repeats an approver");
            }
        }
    }
    return {};
}

} // namespace

Result<Bytes> encode_submission_parts(const SubmissionParts& parts) {
    if (parts.empty()) {
        return fail(Errc::invalid_argument, "submission parts hold at least one part");
    }
    cbor::Map map;
    if (parts.vault) {
        map.push_back({key(2), cbor::Value::bytes(*parts.vault)});
    }
    if (!parts.consents.empty()) {
        cbor::Array list;
        for (const Bytes& bundle : parts.consents) {
            list.push_back(cbor::Value::bytes(bundle));
        }
        map.push_back({key(3), cbor::Value::array(std::move(list))});
    }
    if (!parts.files.empty()) {
        cbor::Array list;
        for (const auto& [index, sealed] : parts.files) {
            list.push_back(cbor::Value::array({key(index), cbor::Value::bytes(sealed)}));
        }
        map.push_back({key(4), cbor::Value::array(std::move(list))});
    }
    auto encoded = cbor::encode(cbor::Value::map(std::move(map)));
    if (!encoded) {
        return std::unexpected(encoded.error());
    }
    if (auto again = decode_submission_parts(*encoded); !again) {
        return std::unexpected(Error{Errc::invalid_argument, again.error().detail});
    }
    return encoded;
}

Result<SubmissionParts> decode_submission_parts(ByteView encoded) {
    auto value = cbor::decode(encoded);
    if (!value) {
        return std::unexpected(value.error());
    }
    const cbor::Map* map = value->as_map();
    if (map == nullptr || map->empty() || !keys_within(*map, 2, 4)) {
        return malformed("submission parts are a map of keys 2 to 4, at least one");
    }
    SubmissionParts parts;
    if (const cbor::Value* vault = value->find(2)) {
        if (vault->as_bytes() == nullptr || vault->as_bytes()->empty()) {
            return malformed("a submission's sealed private data (key 2) is a byte string");
        }
        parts.vault = *vault->as_bytes();
    }
    if (const cbor::Value* consents = value->find(3)) {
        const cbor::Array* list = consents->as_array();
        if (list == nullptr || list->empty() || list->size() > max_contract_consents) {
            return malformed("a submission's consent bundles (key 3) are 1 to 16 byte strings");
        }
        for (const cbor::Value& bundle : *list) {
            if (bundle.as_bytes() == nullptr || bundle.as_bytes()->empty()) {
                return malformed("a consent bundle is a byte string");
            }
            parts.consents.push_back(*bundle.as_bytes());
        }
        if (parts.vault) {
            return malformed("consent bundles (key 3) never travel with private data (key 2)");
        }
    }
    if (const cbor::Value* files = value->find(4)) {
        const cbor::Array* list = files->as_array();
        if (list == nullptr || list->empty() || list->size() > max_submission_files) {
            return malformed("a submission's files (key 4) are 1 to 256 [index, sealed file]");
        }
        for (const cbor::Value& item : *list) {
            const cbor::Array* pair = item.as_array();
            const auto index =
                pair != nullptr && pair->size() == 2 ? (*pair)[0].as_uint64() : std::nullopt;
            if (!index || (*pair)[1].as_bytes() == nullptr || (*pair)[1].as_bytes()->empty()) {
                return malformed("a submission's file is [index, sealed file]");
            }
            if (!parts.files.empty() && *index <= parts.files.back().first) {
                return fail(Errc::non_canonical, "a submission's files' indexes ascend and differ");
            }
            parts.files.emplace_back(*index, *(*pair)[1].as_bytes());
        }
        if (!parts.vault) {
            return malformed("a submission's files (key 4) travel with its private data (key 2)");
        }
    }
    return parts;
}

Status check_submission_parts(const Statement& statement, const SubmissionParts& parts) {
    if (parts.vault || !parts.files.empty()) {
        const auto* registration = std::get_if<RecordRegisterBody>(&statement.body);
        if (registration == nullptr) {
            return fail(Errc::rejected, "only a record's registration carries private data and "
                                        "files");
        }
        for (const auto& [index, sealed] : parts.files) {
            if (index >= registration->attachments.size()) {
                return fail(Errc::rejected, "a file is for an attachment the registration does "
                                            "not have");
            }
        }
    }
    if (!parts.consents.empty()) {
        const auto* call = std::get_if<ContractCallBody>(&statement.body);
        if (call == nullptr || call->consents.size() != parts.consents.size()) {
            return fail(Errc::rejected, "consent bundles go with a contract call that cites as "
                                        "many consents");
        }
    }
    return {};
}

Status check_shown_fields(const crypto::Provider& provider, crypto::HashAlg hash,
                          const Statement& statement, std::span<const RecordField> fields) {
    const auto* registration = std::get_if<RecordRegisterBody>(&statement.body);
    if (registration == nullptr) {
        return fail(Errc::rejected, "only a record's registration has fields to show");
    }
    if (fields.size() != registration->field_count) {
        return fail(Errc::rejected, "the fields shown are not every field of the record");
    }
    auto commitment =
        commit_fields(provider, hash, std::vector<RecordField>(fields.begin(), fields.end()));
    if (!commitment) {
        return std::unexpected(commitment.error());
    }
    if (!std::ranges::equal(commitment->fields, fields)) {
        return fail(Errc::rejected, "the fields shown are not in the order of their leaves");
    }
    if (!std::ranges::equal(commitment->root.bytes(), registration->field_root)) {
        return fail(Errc::verification_failed,
                    "the fields shown do not give the record's field root");
    }
    return {};
}

Result<Bytes> encode_approval_file(const ApprovalFile& file) {
    const SignedStatement& s = file.statement;
    cbor::Map map{{key(1), cbor::Value::unsigned_integer(1)},
                  {key(2), cbor::Value::bytes(s.encoded)},
                  {key(3), cbor::Value::integer(crypto::cose_id(s.hash_alg))}};
    if (!file.approvals.empty()) {
        std::vector<const SignedApproval*> sorted;
        for (const SignedApproval& a : file.approvals) {
            sorted.push_back(&a);
        }
        std::ranges::sort(sorted, [](const SignedApproval* a, const SignedApproval* b) {
            return before(a->approval.approver, b->approval.approver);
        });
        cbor::Array list;
        for (const SignedApproval* a : sorted) {
            list.push_back(cbor::Value::bytes(a->encoded));
        }
        map.push_back({key(4), cbor::Value::array(std::move(list))});
    }
    if (file.parts && !file.parts->empty()) {
        auto parts = encode_submission_parts(*file.parts);
        if (!parts) {
            return std::unexpected(parts.error());
        }
        map.push_back({key(5), cbor::Value::bytes(std::move(*parts))});
    }
    if (!file.fields.empty()) {
        cbor::Array list;
        for (const RecordField& f : file.fields) {
            auto leaf = encode_field(f);
            if (!leaf) {
                return std::unexpected(leaf.error());
            }
            auto value = cbor::decode(*leaf);
            if (!value) {
                return std::unexpected(value.error());
            }
            list.push_back(std::move(*value));
        }
        map.push_back({key(6), cbor::Value::array(std::move(list))});
    }
    if (file.note) {
        map.push_back({key(7), cbor::Value::text(*file.note)});
    }
    auto encoded = cbor::encode(cbor::Value::map(std::move(map)));
    if (!encoded) {
        return std::unexpected(encoded.error());
    }
    // What a reader would refuse is not written.
    if (encoded->size() > max_approval_file) {
        return fail(Errc::limit_exceeded, "an approval file is at most 16 MiB");
    }
    if (file.note && (file.note->empty() || file.note->size() > max_approval_note)) {
        return fail(Errc::invalid_argument, "an approval file's note is 1 to 1,000 bytes");
    }
    if (s.statement.type() == StatementType::genesis) {
        return fail(Errc::invalid_argument, "a genesis takes no approvals");
    }
    if (auto checked = check_approvals_for(s, file.approvals); !checked) {
        return std::unexpected(checked.error());
    }
    if (file.parts) {
        if (auto checked = check_submission_parts(s.statement, *file.parts); !checked) {
            return std::unexpected(checked.error());
        }
    }
    if (!file.fields.empty() && !std::holds_alternative<RecordRegisterBody>(s.statement.body)) {
        return fail(Errc::invalid_argument, "only a record's registration has fields to show");
    }
    return encoded;
}

Result<ApprovalFile> decode_approval_file(const crypto::Provider& provider, ByteView encoded) {
    if (encoded.size() > max_approval_file) {
        return fail(Errc::limit_exceeded, "an approval file is at most 16 MiB");
    }
    auto value = cbor::decode(encoded);
    if (!value) {
        return std::unexpected(value.error());
    }
    const cbor::Map* map = value->as_map();
    if (map == nullptr) {
        return malformed("an approval file is a map");
    }
    if (!keys_within(*map, 1, 7)) {
        return malformed("an approval file's keys are 1 to 7");
    }
    const cbor::Value* version = value->find(1);
    if (version == nullptr || version->as_uint64() != std::optional<std::uint64_t>(1)) {
        return fail(Errc::unsupported, "an approval file of another format version");
    }
    const cbor::Value* statement = value->find(2);
    const cbor::Value* hash = value->find(3);
    if (statement == nullptr || statement->as_bytes() == nullptr) {
        return malformed("an approval file holds its signed statement (key 2)");
    }
    const auto alg = hash != nullptr && hash->as_int64()
                         ? crypto::hash_alg_from_cose(*hash->as_int64())
                         : std::optional<crypto::HashAlg>();
    if (!alg || (*alg != crypto::HashAlg::sha256 && *alg != crypto::HashAlg::sm3)) {
        return malformed("an approval file names its ledger's hash (key 3): SHA-256 or SM3");
    }
    ApprovalFile file;
    auto parsed = parse_statement(provider, *statement->as_bytes(), *alg);
    if (!parsed) {
        return std::unexpected(parsed.error());
    }
    file.statement = std::move(*parsed);
    if (file.statement.statement.type() == StatementType::genesis ||
        !file.statement.statement.ledger_id) {
        return fail(Errc::rejected, "an approval file never holds a genesis");
    }
    if (const cbor::Value* approvals = value->find(4)) {
        const cbor::Array* list = approvals->as_array();
        if (list == nullptr || list->empty() || list->size() > max_approvals) {
            return malformed("an approval file's approvals (key 4) are 1 to 32 byte strings");
        }
        for (const cbor::Value& item : *list) {
            if (item.as_bytes() == nullptr) {
                return malformed("an approval is a byte string");
            }
            auto approval = parse_approval(*item.as_bytes());
            if (!approval) {
                return std::unexpected(approval.error());
            }
            file.approvals.push_back(std::move(*approval));
        }
        if (auto checked = check_approvals_for(file.statement, file.approvals); !checked) {
            return std::unexpected(checked.error());
        }
    }
    if (const cbor::Value* parts = value->find(5)) {
        if (parts->as_bytes() == nullptr) {
            return malformed("an approval file's submission parts (key 5) are a byte string");
        }
        auto decoded = decode_submission_parts(*parts->as_bytes());
        if (!decoded) {
            return std::unexpected(decoded.error());
        }
        if (auto checked = check_submission_parts(file.statement.statement, *decoded); !checked) {
            return std::unexpected(checked.error());
        }
        file.parts = std::move(*decoded);
    }
    if (const cbor::Value* fields = value->find(6)) {
        const cbor::Array* list = fields->as_array();
        if (list == nullptr || list->empty()) {
            return malformed("an approval file's fields (key 6) are a list of fields");
        }
        for (const cbor::Value& item : *list) {
            auto leaf = cbor::encode(item);
            if (!leaf) {
                return std::unexpected(leaf.error());
            }
            auto field = decode_field(*leaf);
            if (!field) {
                return std::unexpected(field.error());
            }
            file.fields.push_back(std::move(*field));
        }
        if (auto checked =
                check_shown_fields(provider, *alg, file.statement.statement, file.fields);
            !checked) {
            return std::unexpected(checked.error());
        }
    }
    if (const cbor::Value* note = value->find(7)) {
        if (note->as_text() == nullptr || note->as_text()->empty() ||
            note->as_text()->size() > max_approval_note) {
            return malformed("an approval file's note (key 7) is 1 to 1,000 bytes of text");
        }
        file.note = *note->as_text();
    }
    return file;
}

Status add_approval(ApprovalFile& file, SignedApproval approval) {
    const SignedApproval* single = &approval;
    if (auto checked = check_approvals_for(file.statement, std::span(single, 1)); !checked) {
        return checked;
    }
    const auto same = std::ranges::find_if(file.approvals, [&](const SignedApproval& a) {
        return a.approval.approver == approval.approval.approver;
    });
    if (same != file.approvals.end()) {
        *same = std::move(approval);
        return {};
    }
    if (file.approvals.size() >= max_approvals) {
        return fail(Errc::limit_exceeded, "an approval file carries at most 32 approvals");
    }
    file.approvals.push_back(std::move(approval));
    return {};
}

} // namespace kanhe::protocol
