// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// Long-term evidence (spec v0.21, section 11.1): renewals, the long-term
// status, and distrusted algorithms. Every attestation a bundle holds (its
// own cosignatures, its anchors' tokens and network cosignatures, its
// renewals' three kinds) is kept in one list, in the order it was checked,
// so that the long-term status and the coverage of signatures by a
// distrusted algorithm are read from it.

#include "longterm.hpp"

#include <algorithm>
#include <array>
#include <initializer_list>
#include <limits>
#include <optional>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>

#include <kanhe/core/merkle.hpp>
#include <kanhe/core/protocol/keys.hpp>
#include <kanhe/core/protocol/network.hpp>

#include "reader.hpp"

namespace kanhe::protocol {

namespace {

std::unexpected<Error> verification_failure(std::string_view detail) {
    return fail(Errc::verification_failed, detail);
}

using Family = crypto::SignatureFamily;

/// The names `--distrust` takes, each for itself; `classical` stands for the
/// classical ones, `other` among them.
constexpr std::array<std::pair<std::string_view, Family>, 7> distrust_names{{
    {"ed25519", Family::ed25519},
    {"ecdsa", Family::ecdsa},
    {"sm2", Family::sm2},
    {"rsa", Family::rsa},
    {"ml-dsa-44", Family::ml_dsa_44},
    {"ml-dsa-65", Family::ml_dsa_65},
    {"ml-dsa-87", Family::ml_dsa_87},
}};
constexpr std::array classical_families{Family::ed25519, Family::ecdsa, Family::sm2, Family::rsa,
                                        Family::other};

/// Four or two decimal digits.
std::optional<std::uint64_t> digits(std::string_view text) {
    std::uint64_t out = 0;
    for (const char c : text) {
        if (c < '0' || c > '9') {
            return std::nullopt;
        }
        out = out * 10 + static_cast<std::uint64_t>(c - '0');
    }
    return out;
}

/// Days from 1970-01-01 to a date from 1970 on (H. Hinnant's
/// days-from-civil algorithm, on unsigned integers).
std::uint64_t days_from_civil(std::uint64_t year, std::uint64_t month, std::uint64_t day) {
    if (month <= 2) {
        --year;
    }
    const std::uint64_t era = year / 400;
    const std::uint64_t yoe = year - era * 400;
    const std::uint64_t doy = (153 * (month > 2 ? month - 3 : month + 9) + 2) / 5 + day - 1;
    const std::uint64_t doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146'097 + doe - 719'468;
}

std::uint64_t days_in_month(std::uint64_t year, std::uint64_t month) {
    constexpr std::array<std::uint64_t, 12> days{31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
    const bool leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
    return month == 2 && leap ? 29 : days[static_cast<std::size_t>(month - 1)];
}

} // namespace

Result<std::vector<Distrust>> parse_distrust(std::span<const std::string> options) {
    std::array<std::optional<Timestamp>, crypto::all_signature_families.size()> dates{};
    for (const std::string& text : options) {
        // ALG@YYYY-MM-DD, ALG lower-case letters, digits, and hyphens.
        const std::size_t at = text.find('@');
        const std::string_view name = std::string_view(text).substr(0, at);
        const std::string_view date =
            at == std::string::npos ? std::string_view() : std::string_view(text).substr(at + 1);
        const bool name_shaped = !name.empty() && std::ranges::all_of(name, [](char c) {
            return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-';
        });
        const bool date_shaped = date.size() == 10 && date[4] == '-' && date[7] == '-' &&
                                 digits(date.substr(0, 4)) && digits(date.substr(5, 2)) &&
                                 digits(date.substr(8, 2));
        std::vector<Family> families;
        if (name == "classical") {
            families.assign(classical_families.begin(), classical_families.end());
        } else if (const auto it = std::ranges::find(distrust_names, name,
                                                     &std::pair<std::string_view, Family>::first);
                   it != distrust_names.end()) {
            families.push_back(it->second);
        }
        if (!name_shaped || !date_shaped || families.empty()) {
            return fail(Errc::invalid_argument,
                        "--distrust takes ALG@YYYY-MM-DD, ALG one of ed25519, ecdsa, sm2, rsa, "
                        "ml-dsa-44, ml-dsa-65, ml-dsa-87, or classical");
        }
        const std::uint64_t year = *digits(date.substr(0, 4));
        const std::uint64_t month = *digits(date.substr(5, 2));
        const std::uint64_t day = *digits(date.substr(8, 2));
        if (month < 1 || month > 12 || day < 1 || day > days_in_month(year, month)) {
            return fail(Errc::invalid_argument, "--distrust names a date that is none");
        }
        if (year < 1970) {
            return fail(Errc::invalid_argument, "--distrust names a date before 1970");
        }
        const Timestamp after = days_from_civil(year, month, day) * 86'400'000;
        for (const Family family : families) {
            auto& slot = dates[static_cast<std::size_t>(family)];
            if (slot) {
                return fail(Errc::invalid_argument, "--distrust names an algorithm twice");
            }
            slot = after;
        }
    }
    std::vector<Distrust> out;
    for (const Family family : crypto::all_signature_families) {
        if (const auto& after = dates[static_cast<std::size_t>(family)]) {
            out.push_back({family, *after});
        }
    }
    return out;
}

std::string_view attestation_kind_name(AttestationKind kind) noexcept {
    switch (kind) {
    case AttestationKind::witness:
        return "witness";
    case AttestationKind::timestamp:
        return "timestamp";
    case AttestationKind::network_witness:
        return "network-witness";
    case AttestationKind::log_key:
        return "log-key";
    }
    return "unknown";
}

std::string_view signed_object_name(SignedObject signed_object) noexcept {
    switch (signed_object) {
    case SignedObject::statement:
        return "statement";
    case SignedObject::presence:
        return "presence";
    case SignedObject::approval:
        return "approval";
    case SignedObject::approval_presence:
        return "approval-presence";
    case SignedObject::state_commitment:
        return "state-commitment";
    case SignedObject::receipt:
        return "receipt";
    case SignedObject::checkpoint:
        return "checkpoint";
    case SignedObject::anchor:
        return "anchor";
    case SignedObject::renewal:
        return "renewal";
    case SignedObject::rotation:
        return "rotation";
    }
    return "unknown";
}

namespace detail {

namespace {

/// The date from which the verifier distrusts `family`, if it does.
std::optional<Timestamp> distrusted_from(std::span<const Distrust> distrust, Family family) {
    const auto it = std::ranges::find(distrust, family, &Distrust::algorithm);
    return it == distrust.end() ? std::nullopt : std::optional(it->after);
}

/// A network cosignature's algorithm is its type's (section 11.1).
Family network_family(std::uint8_t type) {
    switch (type) {
    case network::cosigner_ed25519:
        return Family::ed25519;
    case network::cosigner_ml_dsa_44:
        return Family::ml_dsa_44;
    default:
        return Family::other;
    }
}

/// An attester's identity: a tag for its kind, then what tells it apart.
/// Names hold no control characters, so a NUL ends one.
Bytes identity_of(char tag, std::string_view name, std::initializer_list<ByteView> parts) {
    Bytes out{static_cast<std::uint8_t>(tag)};
    const ByteView name_bytes = kanhe::as_bytes(name);
    out.insert(out.end(), name_bytes.begin(), name_bytes.end());
    out.push_back(0);
    for (const ByteView part : parts) {
        out.insert(out.end(), part.begin(), part.end());
    }
    return out;
}

void merge_into(Witnessed& into, const Witnessed& from) {
    into.trusted.insert(from.trusted.begin(), from.trusted.end());
    into.untrusted.insert(from.untrusted.begin(), from.untrusted.end());
}

/// Its signature, and a token's signing certificate's too, are post-quantum.
bool post_quantum(const Attestation& a) {
    return crypto::is_post_quantum(a.report.algorithm) &&
           (!a.report.certificate_algorithm ||
            crypto::is_post_quantum(*a.report.certificate_algorithm));
}

/// The attestations `keep` keeps, in the bundle's order (section 11.1): its
/// own cosignatures; each anchor's tokens, then its network cosignatures;
/// each renewal's cosignatures, tokens, then network cosignatures; in the
/// order checked within each.
template <class Keep>
std::vector<const Attestation*> in_bundle_order(std::span<const Attestation> attestations,
                                                Keep keep) {
    std::vector<const Attestation*> out;
    for (const Attestation& a : attestations) {
        if (keep(a)) {
            out.push_back(&a);
        }
    }
    auto order = [](const Attestation* a) {
        const AttestationReport& r = a->report;
        const std::size_t group = r.anchor    ? std::size_t{1}
                                  : r.renewal ? std::size_t{2}
                                              : std::size_t{0};
        const std::size_t number = r.anchor ? *r.anchor : r.renewal.value_or(0);
        return std::tuple(group, number, static_cast<std::size_t>(r.kind));
    };
    std::ranges::stable_sort(out, {}, order);
    return out;
}

} // namespace

Tally::Tally(const crypto::Provider& provider, const LedgerState& state,
             const VerifyOptions& options)
    : provider_(provider), state_(state), options_(options) {
    for (const crypto::PublicKey& witness : options.trusted_witnesses) {
        if (auto kid = key_id(provider, state.hash(), witness)) {
            witnesses_.emplace_back(*kid, &witness);
        }
    }
}

Result<Witnessed> Tally::cosignatures(const SignedCheckpoint& head, std::span<const Bytes> list,
                                      std::optional<std::size_t> anchor,
                                      std::optional<std::size_t> renewal) {
    Witnessed out;
    for (const Bytes& encoded : list) {
        // A dated cosignature's CWT claims are exactly {6: iat} (v0.21),
        // whoever its witness is: parsing refuses anything else.
        auto cosignature = parse_cosignature(encoded);
        if (!cosignature || cosignature->checkpoint != head.checkpoint) {
            return verification_failure(
                "a cosignature is malformed or does not cover the checkpoint it is given with");
        }
        const auto witness = std::ranges::find(witnesses_, cosignature->kid,
                                               &std::pair<Id, const crypto::PublicKey*>::first);
        const crypto::PublicKey* key = witness == witnesses_.end() ? nullptr : witness->second;
        const Family family =
            crypto::family_of(key != nullptr ? key->algorithm : cosignature->envelope.algorithm);
        const bool set_aside =
            key != nullptr && distrusted_from(options_.distrust, family).has_value();
        Bytes identity = identity_of('c', {}, {cosignature->kid.bytes()});
        // Each one by a trusted witness verifies, a repeated one too (step
        // 6); only the counting is by witness.
        if (key != nullptr && !set_aside) {
            if (!verify_cosignature(provider_, *cosignature, *key)) {
                return verification_failure("a trusted witness's cosignature does not verify");
            }
            out.trusted.insert(identity);
        } else {
            out.untrusted.insert(identity);
        }
        Attestation a;
        a.report.kind = AttestationKind::witness;
        a.report.by = to_hex(cosignature->kid.bytes());
        a.report.algorithm = family;
        // Dated by its iat, the witness's word (v0.21); undated otherwise.
        if (cosignature->witness_time) {
            a.report.time = AttestedTime{*cosignature->witness_time, 0};
            a.report.dated_by = a.report.time;
        }
        a.report.checkpoint_size = head.checkpoint.tree_size;
        a.report.anchor = anchor;
        a.report.renewal = renewal;
        a.relied_on = key != nullptr && !set_aside;
        a.set_aside = set_aside;
        a.distrusted = family;
        a.identity = std::move(identity);
        items_.push_back(std::move(a));
    }
    merge_into(witnessed_, out);
    return out;
}

Result<Witnessed> Tally::note_cosignatures(const SignedCheckpoint& head,
                                           std::span<const network::NoteSignature> list,
                                           std::optional<std::size_t> anchor,
                                           std::optional<std::size_t> renewal,
                                           std::vector<NetworkCosignatureCheck>& checks) {
    Witnessed out;
    // Open networks witness SHA-256 trees only (section 10.2).
    if (!list.empty() && state_.hash() != crypto::HashAlg::sha256) {
        return verification_failure(
            "an SM3 ledger's anchor or renewal carries network cosignatures");
    }
    const Checkpoint& at = head.checkpoint;
    const std::string origin = network::origin(state_.ledger_id());
    for (const network::NoteSignature& cosignature : list) {
        auto time = network::cosignature_time(cosignature.bytes);
        if (!time) {
            return verification_failure("a network cosignature is malformed");
        }
        const ByteView id(cosignature.bytes.data(), 4);
        auto named = [&](const network::VerifierKey& k) {
            return k.name == cosignature.name && std::ranges::equal(k.id, id);
        };
        const auto first = std::ranges::find_if(options_.trusted_network_witnesses, named);
        const bool known = first != options_.trusted_network_witnesses.end();
        const Family family = known ? network_family(first->type) : Family::other;
        const bool set_aside = known && distrusted_from(options_.distrust, family).has_value();
        const bool trusted = known && !set_aside;
        Bytes identity = identity_of('u', cosignature.name, {id});
        if (trusted) {
            // Two trusted keys could share a name and a 4-byte key ID: the
            // cosignature is that of the first one it verifies with, and a
            // trusted witness is told apart by its whole verifier key.
            const network::VerifierKey* verified = nullptr;
            for (const network::VerifierKey& k : options_.trusted_network_witnesses) {
                if (named(k) && network::verify_cosignature(provider_, k, origin, at.tree_size,
                                                            at.root, cosignature)) {
                    verified = &k;
                    break;
                }
            }
            if (verified == nullptr) {
                return verification_failure(
                    "a trusted network witness's cosignature does not verify");
            }
            const std::array<std::uint8_t, 1> type{verified->type};
            identity = identity_of('t', verified->name, {verified->id, type, verified->key.bytes});
            out.trusted.insert(identity);
        } else {
            out.untrusted.insert(identity);
        }
        checks.push_back(NetworkCosignatureCheck{
            .witness = cosignature.name,
            .size = at.tree_size,
            .time = *time,
            .trusted = trusted,
        });
        Attestation a;
        a.report.kind = AttestationKind::network_witness;
        a.report.by = cosignature.name;
        a.report.algorithm = family;
        a.report.time = AttestedTime{*time, 0};
        a.report.dated_by = a.report.time;
        a.report.checkpoint_size = at.tree_size;
        a.report.anchor = anchor;
        a.report.renewal = renewal;
        a.relied_on = trusted;
        a.set_aside = set_aside;
        a.distrusted = family;
        a.identity = std::move(identity);
        items_.push_back(std::move(a));
    }
    merge_into(witnessed_, out);
    return out;
}

Status Tally::tokens(const SignedCheckpoint& head, std::span<const Bytes> list,
                     const std::map<std::uint64_t, Timestamp>& held,
                     std::optional<std::size_t> anchor, std::optional<std::size_t> renewal,
                     std::vector<TimestampCheck>& checks, std::span<RecordEvent> events) {
    if (list.empty()) {
        return {};
    }
    const Checkpoint& at = head.checkpoint;
    KANHE_TRY(crypto::Digest stamped, provider_.digest(state_.hash(), *head.envelope.payload));
    for (const Bytes& encoded : list) {
        auto token = provider_.read_timestamp(encoded, options_.trusted_timestamp_roots);
        if (!token) {
            if (token.error().code == Errc::unsupported) {
                return std::unexpected(token.error());
            }
            return verification_failure("a time-stamp token does not verify");
        }
        if (token->imprint_alg != state_.hash() ||
            !std::ranges::equal(token->imprint, stamped.bytes())) {
            return verification_failure(
                "a time-stamp token stamps something other than the checkpoint it is given with");
        }
        // Set aside if either of its algorithms is distrusted (v0.21).
        const bool signature_distrusted =
            distrusted_from(options_.distrust, token->signature_family).has_value();
        const bool set_aside =
            token->trusted &&
            (signature_distrusted ||
             distrusted_from(options_.distrust, token->certificate_family).has_value());
        const bool trusted = token->trusted && !set_aside;
        // A token's time and accuracy fit (the token's reading refuses more).
        const Timestamp seen = token->time + token->accuracy;
        Attestation a;
        a.report.kind = AttestationKind::timestamp;
        a.report.by = token->authority;
        a.report.algorithm = token->signature_family;
        a.report.certificate_algorithm = token->certificate_family;
        a.report.time = AttestedTime::from_millis(token->time);
        a.report.dated_by = AttestedTime::from_millis(seen);
        a.report.checkpoint_size = at.tree_size;
        a.report.anchor = anchor;
        a.report.renewal = renewal;
        a.relied_on = trusted;
        a.set_aside = set_aside;
        a.distrusted = signature_distrusted ? token->signature_family : token->certificate_family;
        a.identity = identity_of('a', {}, {token->authority_key});
        items_.push_back(std::move(a));
        checks.push_back(TimestampCheck{
            .size = at.tree_size,
            .time = token->time,
            .accuracy = token->accuracy,
            .authority = token->authority,
            .trusted = trusted,
        });
        if (!trusted) {
            continue;
        }
        // The clock rule (section 10.1): the ledger dated nothing it had by
        // then later than the authority's time allows. Saturating: the
        // slack on top of a time that fits may not.
        constexpr Timestamp latest_time = std::numeric_limits<Timestamp>::max();
        const Timestamp bound =
            seen > latest_time - timestamp_clock_slack ? latest_time : seen + timestamp_clock_slack;
        if (at.timestamp > bound) {
            return verification_failure("the ledger's clock contradicts a time-stamp authority: "
                                        "it dates a checkpoint after the authority saw it");
        }
        for (const auto& [index, registered_at] : held) {
            if (index >= at.tree_size) {
                break;
            }
            if (registered_at > bound) {
                return verification_failure("the ledger's clock contradicts a time-stamp "
                                            "authority: it dates an entry after the authority "
                                            "saw it");
            }
        }
        authorities_.insert(token->authority_key);
        for (RecordEvent& event : events) {
            if (event.index < at.tree_size) {
                event.existed_by = event.existed_by ? std::min(*event.existed_by, seen) : seen;
            }
        }
    }
    return {};
}

Result<std::vector<CheckedRenewal>>
check_renewals(const crypto::Provider& provider, const LedgerState& state,
               const SignedCheckpoint& checkpoint, std::span<const Renewal> renewals, Tally& tally,
               std::map<std::uint64_t, Timestamp> held, std::span<RecordEvent> events) {
    std::vector<CheckedRenewal> out;
    if (renewals.empty()) {
        return out;
    }
    // The keys as the replay left them at the bundle's checkpoint, followed
    // from there as a witness follows them.
    LedgerKeys keys = state.keys();
    std::vector<crypto::SigAlg> key_algorithms;
    for (const KeyEpoch& e : state.root_keys()) {
        key_algorithms.push_back(e.key.algorithm);
    }
    for (const KeyEpoch& e : state.log_keys()) {
        key_algorithms.push_back(e.key.algorithm);
    }
    const crypto::HashAlg hash = state.hash();
    Checkpoint previous = checkpoint.checkpoint;
    for (std::size_t n = 1; n <= renewals.size(); ++n) {
        const Renewal& r = renewals[n - 1];
        // Check 1: a checkpoint of this ledger, extending the previous one.
        auto head = parse_checkpoint(r.checkpoint);
        if (!head) {
            return verification_failure("a renewal's checkpoint is malformed");
        }
        const Checkpoint c = head->checkpoint;
        if (c.ledger_id != state.ledger_id() || c.tree_hash != hash) {
            return verification_failure("a renewal's checkpoint belongs to a different ledger");
        }
        if (c.tree_size < previous.tree_size) {
            return verification_failure("a renewal's checkpoint is smaller than the one before it");
        }
        if (c.tree_size == previous.tree_size) {
            if (!r.consistency.empty() || !r.rotations.empty()) {
                return verification_failure("a renewal repeats the size before it, and carries a "
                                            "consistency proof or key rotations");
            }
            if (c.root != previous.root) {
                return verification_failure(
                    "a renewal repeats the size before it with another root");
            }
        } else if (r.consistency.empty() ||
                   !merkle::verify_consistency(provider, hash, previous.tree_size, c.tree_size,
                                               previous.root, c.root, r.consistency)) {
            return verification_failure(
                "a renewal's checkpoint is not proven consistent with the one before it");
        }
        // Check 2: the rotations in between, in its tree, followed as a
        // witness follows them (approvals on them ignored).
        CheckedRenewal checked{};
        std::optional<std::uint64_t> last;
        for (const KeyRotationProof& rotation : r.rotations) {
            if (rotation.index < previous.tree_size || rotation.index >= c.tree_size ||
                (last && rotation.index <= *last)) {
                return verification_failure("a renewal's key rotations do not ascend from the "
                                            "previous size to below its own");
            }
            last = rotation.index;
            KANHE_TRY(crypto::Digest leaf, merkle::leaf_hash(provider, hash, rotation.entry));
            if (!merkle::verify_inclusion(provider, hash, leaf, rotation.index, c.tree_size,
                                          rotation.path, c.root)) {
                return verification_failure(
                    "a renewal's key rotation is not in its checkpoint's tree");
            }
            if (!is_key_rotation(provider, keys, rotation.entry)) {
                return verification_failure("an entry a renewal gives as a key rotation rotates "
                                            "neither the root key nor the log key");
            }
            const std::size_t log_keys_before = keys.log_keys.size();
            if (!follow_key_rotation(provider, keys, rotation.index, rotation.entry)) {
                return verification_failure(
                    "a renewal's key rotation is not signed by the root key in effect, or names "
                    "a weak key or one that was a log key");
            }
            const bool of_log_key = keys.log_keys.size() > log_keys_before;
            ++(of_log_key ? checked.report.log_key_rotations : checked.report.root_key_rotations);
            key_algorithms.push_back(
                (of_log_key ? keys.log_keys.back().key : keys.root_key).algorithm);
            // Its signature's algorithm (step 12), and its time, for the
            // clock rule of this renewal's tokens and the later ones'.
            KANHE_TRY(LogEntry entry, decode_log_entry(rotation.entry));
            KANHE_TRY(SignedStatement statement, parse_statement(provider, entry.statement, hash));
            checked.rotations.emplace_back(rotation.index, statement.envelope.algorithm);
            held[rotation.index] = entry.registered_at;
        }
        // Check 3: signed by the log key in effect at its size.
        const crypto::PublicKey log_key = key_in_effect(keys.log_keys, c.tree_size);
        if (!verify_checkpoint(provider, *head, log_key)) {
            return verification_failure(
                "a renewal's checkpoint is not signed by the log key in effect at its size");
        }
        // Check 4: its attestations, checked and counted as the bundle's own.
        KANHE_TRY(Witnessed cosigned, tally.cosignatures(*head, r.cosignatures, std::nullopt, n));
        KANHE_CHECK(tally.tokens(*head, r.timestamps, held, std::nullopt, n,
                                 checked.report.timestamps, events));
        KANHE_TRY(Witnessed networked,
                  tally.note_cosignatures(*head, r.network_cosignatures, std::nullopt, n,
                                          checked.report.network_cosignatures));
        merge_into(cosigned, networked);
        checked.report.checkpoint = c;
        checked.report.log_key = log_key;
        checked.report.trusted_cosignatures = cosigned.trusted.size();
        checked.report.untrusted_cosignatures = cosigned.untrusted.size();
        checked.key_algorithms = key_algorithms;
        checked.head = std::move(*head);
        out.push_back(std::move(checked));
        previous = c;
    }
    return out;
}

Result<std::vector<DistrustedSignature>> cover(std::span<const ReliedSignature> signatures,
                                               std::span<const Attestation> attestations,
                                               std::span<const Distrust> distrust) {
    std::vector<DistrustedSignature> out;
    if (distrust.empty()) {
        return out;
    }
    // The dated attestations relied on: tokens, network cosignatures, and
    // dated witness cosignatures (an undated one carries no time).
    const std::vector<const Attestation*> dated = in_bundle_order(
        attestations, [](const Attestation& a) { return a.relied_on && a.report.dated_by; });
    for (const ReliedSignature& s : signatures) {
        const Family family = crypto::family_of(s.algorithm);
        const std::optional<Timestamp> after = distrusted_from(distrust, family);
        if (!after) {
            continue;
        }
        // Dated before the date: as exact numbers, seconds and milliseconds.
        const AttestedTime cutoff = AttestedTime::from_millis(*after);
        const Attestation* best = nullptr;
        for (const Attestation* a : dated) {
            // A tree that holds what was signed: a tree head a log key
            // signed (a receipt's among them) is in a tree of at least its
            // size; any other signature, in a tree above its entry's index.
            const bool inside = s.tree_size ? a->report.checkpoint_size >= *s.tree_size
                                            : a->report.checkpoint_size > s.index.value_or(0);
            if (inside && *a->report.dated_by < cutoff &&
                (best == nullptr || *a->report.dated_by < *best->report.dated_by)) {
                best = a;
            }
        }
        if (best == nullptr) {
            return verification_failure(
                "a signature by a distrusted algorithm is covered by no trusted dated attestation "
                "(a time-stamp token, a network cosignature, or a dated witness cosignature) "
                "before its date");
        }
        out.push_back(DistrustedSignature{
            .signed_object = s.signed_object,
            .index = s.index,
            .tree_size = s.tree_size,
            .approver = s.approver,
            .anchor = s.anchor,
            .renewal = s.renewal,
            .algorithm = family,
            .covered_by = best->report,
        });
    }
    return out;
}

std::vector<SetAsideAttestation> set_aside_attestations(std::span<const Attestation> attestations) {
    std::vector<SetAsideAttestation> out;
    for (const Attestation* a :
         in_bundle_order(attestations, [](const Attestation& x) { return x.set_aside; })) {
        out.push_back({a->report, a->distrusted});
    }
    return out;
}

Result<LongTermStatus> long_term_status(const crypto::Provider& provider, const LedgerState& state,
                                        const SignedCheckpoint& checkpoint,
                                        const crypto::PublicKey& log_key,
                                        std::span<const CheckedRenewal> renewals,
                                        std::span<const Attestation> attestations,
                                        std::span<const Distrust> distrust) {
    auto usable = [&](crypto::SigAlg alg) {
        const Family family = crypto::family_of(alg);
        return crypto::is_post_quantum(family) && !distrusted_from(distrust, family);
    };
    // The covering checkpoints: the bundle's own, then each renewal's. Its
    // log key's signature counts if every root and log key up to it, the
    // genesis keys first, is ML-DSA (and not distrusted).
    struct Covering {
        std::optional<std::size_t> renewal;
        const Checkpoint* checkpoint = nullptr;
        const crypto::PublicKey* log_key = nullptr;
        bool keys_post_quantum = false;
    };
    std::vector<Covering> covering;
    const bool bundle_keys =
        std::ranges::all_of(state.root_keys(),
                            [&](const KeyEpoch& e) { return usable(e.key.algorithm); }) &&
        std::ranges::all_of(state.log_keys(),
                            [&](const KeyEpoch& e) { return usable(e.key.algorithm); });
    covering.push_back({std::nullopt, &checkpoint.checkpoint, &log_key, bundle_keys});
    for (std::size_t n = 0; n < renewals.size(); ++n) {
        covering.push_back({n + 1, &renewals[n].report.checkpoint, &renewals[n].report.log_key,
                            std::ranges::all_of(renewals[n].key_algorithms, usable)});
    }
    for (auto c = covering.rbegin(); c != covering.rend(); ++c) {
        auto mine = [&](const Attestation& a) {
            return c->renewal
                       ? a.report.renewal == c->renewal
                       : !a.report.renewal && a.report.checkpoint_size == c->checkpoint->tree_size;
        };
        LongTermStatus status;
        std::set<std::pair<AttestationKind, Bytes>> seen;
        for (const AttestationKind kind : {AttestationKind::witness, AttestationKind::timestamp,
                                           AttestationKind::network_witness}) {
            for (const Attestation& a : attestations) {
                if (a.report.kind == kind && mine(a) && a.relied_on && post_quantum(a) &&
                    seen.emplace(kind, a.identity).second) {
                    status.attested_by.push_back(a.report);
                }
            }
        }
        if (c->keys_post_quantum && usable(c->log_key->algorithm)) {
            KANHE_TRY(Id kid, key_id(provider, state.hash(), *c->log_key));
            AttestationReport r;
            r.kind = AttestationKind::log_key;
            r.by = to_hex(kid.bytes());
            r.algorithm = crypto::family_of(c->log_key->algorithm);
            r.checkpoint_size = c->checkpoint->tree_size;
            r.renewal = c->renewal;
            status.attested_by.push_back(std::move(r));
        }
        if (!status.attested_by.empty()) {
            status.checkpoint = *c->checkpoint;
            status.renewal = c->renewal;
            return status;
        }
    }
    return LongTermStatus{};
}

} // namespace detail

} // namespace kanhe::protocol
