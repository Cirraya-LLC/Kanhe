// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include <algorithm>
#include <format>
#include <memory>
#include <span>
#include <utility>
#include <vector>

#include <openssl/asn1.h>
#include <openssl/err.h>
#include <openssl/pkcs7.h>
#include <openssl/x509.h>

#include <kanhe/core/protocol/keys.hpp>
#include <kanhe/core/protocol/log.hpp>
#include <kanhe/core/protocol/state.hpp>
#include <kanhe/node/long_term.hpp>
#include <kanhe/verifier/report.hpp>

namespace kanhe::node {

namespace {

using json = nlohmann::json;

constexpr protocol::Timestamp day_ms = 86'400'000;

template <auto Free>
struct Deleter {
    template <class T>
    void operator()(T* p) const noexcept {
        Free(p);
    }
};
using Pkcs7Ptr = std::unique_ptr<PKCS7, Deleter<&PKCS7_free>>;
using Asn1TimePtr = std::unique_ptr<ASN1_TIME, Deleter<&ASN1_TIME_free>>;

json key_json(crypto::SigAlg alg) {
    return {{"algorithm", crypto::name(alg)}, {"post_quantum", node::post_quantum_algorithm(alg)}};
}

/// "2027-01-05" of a time in milliseconds.
std::string date_of(protocol::Timestamp ms) {
    return verifier::iso_time(ms).substr(0, 10);
}

} // namespace

bool post_quantum_algorithm(crypto::SigAlg alg) noexcept {
    return alg == crypto::SigAlg::ml_dsa_44 || alg == crypto::SigAlg::ml_dsa_65 ||
           alg == crypto::SigAlg::ml_dsa_87;
}

std::optional<protocol::Timestamp> timestamp_certificate_expiry(ByteView token) {
    const unsigned char* p = token.data();
    const Pkcs7Ptr pkcs7(d2i_PKCS7(nullptr, &p, static_cast<long>(token.size())));
    if (!pkcs7 || p != token.data() + token.size()) {
        ERR_clear_error();
        return std::nullopt;
    }
    // The signing certificate, which the token carries (ledgers keep only
    // tokens that do): the stack is the caller's, its certificates the token's.
    STACK_OF(X509)* signers = PKCS7_get0_signers(pkcs7.get(), nullptr, 0);
    if (signers == nullptr || sk_X509_num(signers) != 1) {
        sk_X509_free(signers);
        ERR_clear_error();
        return std::nullopt;
    }
    const X509* signer = sk_X509_value(signers, 0);
    sk_X509_free(signers);
    const Asn1TimePtr epoch(ASN1_TIME_set(nullptr, 0));
    int days = 0;
    int seconds = 0;
    if (!epoch || ASN1_TIME_diff(&days, &seconds, epoch.get(), X509_get0_notAfter(signer)) != 1 ||
        days < 0 || seconds < 0) {
        ERR_clear_error();
        return std::nullopt;
    }
    return (static_cast<protocol::Timestamp>(days) * 86'400 +
            static_cast<protocol::Timestamp>(seconds)) *
           1000;
}

void LongTermWatch::read_new(const ledger::Ledger& ledger) {
    const crypto::HashAlg hash = ledger.hash();
    const std::uint64_t cosignatures = ledger.cosignature_count();
    while (cosignatures_read_ < cosignatures) {
        auto page = ledger.cosignatures(cosignatures_read_, cosignatures - cosignatures_read_);
        if (!page || page->empty()) {
            break;
        }
        cosignatures_read_ += page->size();
        for (const ledger::StoredCosignature& s : *page) {
            if (!node::post_quantum_algorithm(s.witness.algorithm)) {
                continue;
            }
            const protocol::Checkpoint& c = s.cosignature.checkpoint;
            if (last_ &&
                (c.tree_size < last_->tree_size ||
                 (c.tree_size == last_->tree_size && c.timestamp < last_->checkpoint_time))) {
                continue;
            }
            const auto kid = protocol::key_id(ledger.provider(), hash, s.witness);
            last_ = Cosignature{kid ? to_hex(kid->bytes()) : std::string(), s.witness.algorithm,
                                c.tree_size, c.timestamp, s.cosignature.witness_time};
        }
    }
    const std::uint64_t timestamps = ledger.timestamp_count();
    while (timestamps_read_ < timestamps) {
        auto page = ledger.timestamps(timestamps_read_, timestamps - timestamps_read_);
        if (!page || page->empty()) {
            break;
        }
        timestamps_read_ += page->size();
        for (const ledger::StoredTimestamp& t : *page) {
            const auto token = ledger.provider().read_timestamp(t.token, {});
            if (!token) {
                continue;
            }
            Authority& authority = authorities_[to_hex(token->authority_key)];
            if (!authority.name.empty() && token->time < authority.token_time) {
                continue;
            }
            authority.name = token->authority;
            authority.token_time = token->time;
            authority.not_after = timestamp_certificate_expiry(t.token);
        }
    }
}

json LongTermWatch::status(const ledger::Ledger& ledger, protocol::Timestamp now) {
    std::vector<crypto::SigAlg> root_keys;
    std::vector<crypto::SigAlg> log_keys;
    ledger.read_state([&](const protocol::LedgerState& s) {
        for (const protocol::KeyEpoch& e : s.root_keys()) {
            root_keys.push_back(e.key.algorithm);
        }
        for (const protocol::KeyEpoch& e : s.log_keys()) {
            log_keys.push_back(e.key.algorithm);
        }
    });
    const std::lock_guard lock(mutex_);
    read_new(ledger);

    const crypto::SigAlg root = root_keys.back();
    const crypto::SigAlg log_key = log_keys.back();
    const bool genesis = node::post_quantum_algorithm(root_keys.front()) &&
                         node::post_quantum_algorithm(log_keys.front());
    const bool every_key = std::ranges::all_of(root_keys, node::post_quantum_algorithm) &&
                           std::ranges::all_of(log_keys, node::post_quantum_algorithm);
    json out{{"post_quantum",
              node::post_quantum_algorithm(root) && node::post_quantum_algorithm(log_key)},
             {"root_key", key_json(root)},
             {"log_key", key_json(log_key)},
             {"genesis_post_quantum", genesis},
             {"keys_post_quantum", every_key}};
    if (last_) {
        out["last_post_quantum_cosignature"] = {
            {"witness", last_->witness},
            {"algorithm", crypto::name(last_->algorithm)},
            {"tree_size", last_->tree_size},
            {"checkpoint_time", verifier::iso_time(last_->checkpoint_time)},
            {"time", last_->time ? json(verifier::iso_time_seconds(*last_->time)) : json(nullptr)}};
    } else {
        out["last_post_quantum_cosignature"] = nullptr;
    }
    json expiring = json::array();
    std::vector<std::string> certificate_advice;
    for (const auto& [key, authority] : authorities_) {
        if (!authority.not_after || *authority.not_after > now + certificate_warning) {
            continue;
        }
        const protocol::Timestamp not_after = *authority.not_after;
        const std::int64_t days_left =
            not_after >= now ? static_cast<std::int64_t>((not_after - now) / day_ms)
                             : -static_cast<std::int64_t>((now - not_after + day_ms - 1) / day_ms);
        expiring.push_back({{"authority", authority.name},
                            {"not_after", verifier::iso_time(not_after)},
                            {"days_left", days_left}});
        certificate_advice.push_back(
            not_after >= now
                ? std::format("The time-stamp authority {}'s certificate expires on {} (in {} "
                              "days): its later tokens need its next certificate. Check that "
                              "it has one, or stamp with another authority (serve --tsa).",
                              authority.name, date_of(not_after), days_left)
                : std::format("The time-stamp authority {}'s certificate expired on {}: its "
                              "tokens since need another certificate. Stamp with an authority "
                              "whose certificate is current (serve --tsa).",
                              authority.name, date_of(not_after)));
    }
    out["certificates_expiring"] = std::move(expiring);

    json advice = json::array();
    const auto alg = [](crypto::SigAlg a) {
        return std::string(crypto::name(a));
    };
    if (!node::post_quantum_algorithm(root) && !node::post_quantum_algorithm(log_key)) {
        advice.push_back(std::format("The root key and the log key are classical ({}, {}): run "
                                     "kanhe ledger long-term to rotate both to ML-DSA-65.",
                                     alg(root), alg(log_key)));
    } else if (!node::post_quantum_algorithm(log_key)) {
        advice.push_back(std::format("The log key is classical ({}): run kanhe ledger long-term "
                                     "to rotate it to ML-DSA-65.",
                                     alg(log_key)));
    } else if (!node::post_quantum_algorithm(root)) {
        advice.push_back(std::format("The root key is classical ({}): run kanhe ledger long-term "
                                     "to rotate it to ML-DSA-65.",
                                     alg(root)));
    }
    if (!genesis) {
        advice.push_back("The genesis named classical keys, which no rotation undoes: this "
                         "ledger's evidence rests on attestations made before a quantum computer "
                         "breaks them. Have a witness whose key is ML-DSA cosign its "
                         "checkpoints, and renew evidence meant to last (kanhe evidence renew) "
                         "before 2030.");
    } else if (!every_key) {
        advice.push_back("A rotation set a classical key after the genesis: the checkpoints "
                         "signed since are no post-quantum attestation by themselves. Have a "
                         "witness whose key is ML-DSA cosign them.");
    }
    if (!last_) {
        advice.push_back("No witness whose key is ML-DSA has cosigned this ledger yet: ask one "
                         "(kanhe checkpoint cosign-request, or kanhe witness register), so that "
                         "a post-quantum attestation covers its checkpoints.");
    }
    for (std::string& line : certificate_advice) {
        advice.push_back(std::move(line));
    }
    out["advice"] = std::move(advice);
    return out;
}

json long_term_json(const ledger::Ledger& ledger, protocol::Timestamp now) {
    LongTermWatch watch;
    return watch.status(ledger, now);
}

} // namespace kanhe::node
