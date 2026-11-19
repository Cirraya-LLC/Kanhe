// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <set>
#include <span>
#include <utility>
#include <vector>

#include <kanhe/core/bytes.hpp>
#include <kanhe/core/crypto.hpp>
#include <kanhe/core/error.hpp>
#include <kanhe/core/protocol/evidence.hpp>
#include <kanhe/core/protocol/log.hpp>
#include <kanhe/core/protocol/state.hpp>

// Internal: long-term evidence (spec v0.21, section 11.1), the steps of a
// bundle's verification that read every attestation it holds. Not part of
// the public API.
namespace kanhe::protocol::detail {

/// One attestation of a checkpoint, as the verification keeps it: its own
/// cosignatures, its anchors' tokens and network cosignatures, and its
/// renewals' three kinds, in the order they were checked.
struct Attestation {
    AttestationReport report;
    /// Trusted by the verifier, and not set aside: relied on.
    bool relied_on = false;
    /// Trusted, but by an algorithm the verifier distrusts, and then that
    /// algorithm (a token's signature's first).
    bool set_aside = false;
    crypto::SignatureFamily distrusted = crypto::SignatureFamily::other;
    /// The attester, counted once: a witness by its kid, an authority by
    /// its key, a network witness by its name and key ID (and its whole
    /// verifier key, once a cosignature verified with it).
    Bytes identity;
};

/// The attesters of one checkpoint, each once: trusted, and the others.
struct Witnessed {
    std::set<Bytes> trusted;
    std::set<Bytes> untrusted;
};

/// Every attestation of a bundle, its anchors, and its renewals, checked as
/// steps 6 and 8 check them, and counted once per witness and per authority
/// across all of them. One the verifier would trust, by an algorithm it
/// distrusts, is set aside: treated as one it does not trust.
class Tally {
public:
    Tally(const crypto::Provider& provider, const LedgerState& state, const VerifyOptions& options);

    /// Step 6, for the witnesses' COSE cosignatures `list` of `head`, carried
    /// by the bundle (no anchor and no renewal) or by its renewal `renewal`: one
    /// over another checkpoint, a malformed one (its CWT claims among
    /// them), and a trusted witness's that does not verify fail.
    [[nodiscard]] Result<Witnessed> cosignatures(const SignedCheckpoint& head,
                                                 std::span<const Bytes> list,
                                                 std::optional<std::size_t> anchor,
                                                 std::optional<std::size_t> renewal);
    /// Step 8, for open-network witnesses' cosignatures `list` of `head`'s note
    /// (section 10.2): none for an SM3 ledger; a trusted one must verify.
    /// Each is reported in `checks`.
    [[nodiscard]] Result<Witnessed> note_cosignatures(const SignedCheckpoint& head,
                                                      std::span<const network::NoteSignature> list,
                                                      std::optional<std::size_t> anchor,
                                                      std::optional<std::size_t> renewal,
                                                      std::vector<NetworkCosignatureCheck>& checks);
    /// Step 8, for time-stamp tokens `list` over `head`'s payload: each verifies
    /// with its signing certificate and stamps it. For those relied on, the
    /// clock rule (section 10.1) on `head` and on every entry `held` holds
    /// below its size (by index, their registration times), and each of
    /// `events` below its size existed by the token's time plus accuracy.
    /// Each is reported in `checks`.
    [[nodiscard]] Status tokens(const SignedCheckpoint& head, std::span<const Bytes> list,
                                const std::map<std::uint64_t, Timestamp>& held,
                                std::optional<std::size_t> anchor,
                                std::optional<std::size_t> renewal,
                                std::vector<TimestampCheck>& checks, std::span<RecordEvent> events);

    [[nodiscard]] std::size_t trusted_witnesses() const noexcept {
        return witnessed_.trusted.size();
    }
    [[nodiscard]] std::size_t untrusted_witnesses() const noexcept {
        return witnessed_.untrusted.size();
    }
    [[nodiscard]] std::size_t trusted_authorities() const noexcept { return authorities_.size(); }
    [[nodiscard]] std::span<const Attestation> items() const noexcept { return items_; }

private:
    const crypto::Provider& provider_;
    const LedgerState& state_;
    const VerifyOptions& options_;
    /// The trusted witnesses' keys, by their kids under the ledger's hash.
    std::vector<std::pair<Id, const crypto::PublicKey*>> witnesses_;
    Witnessed witnessed_;
    std::set<Bytes> authorities_;
    std::vector<Attestation> items_;
};

/// A renewal as checked (step 11), with what step 12 and the long-term
/// status need of it.
struct CheckedRenewal {
    SignedCheckpoint head;
    RenewalReport report;
    /// Its rotations: each one's log index and its signature's algorithm.
    std::vector<std::pair<std::uint64_t, crypto::SigAlg>> rotations;
    /// The algorithms of every root key and log key the ledger had up to its
    /// checkpoint, the genesis keys among them.
    std::vector<crypto::SigAlg> key_algorithms;
};

/// Step 11: each renewal, in order, from the root key and log keys the
/// replay reached at `checkpoint` (section 11.1, checks 1 to 4). `held` is
/// every entry the bundle holds, by index, with its registration time, for
/// the clock rule; the renewals' rotations join it.
[[nodiscard]] Result<std::vector<CheckedRenewal>>
check_renewals(const crypto::Provider& provider, const LedgerState& state,
               const SignedCheckpoint& checkpoint, std::span<const Renewal> renewals, Tally& tally,
               std::map<std::uint64_t, Timestamp> held, std::span<RecordEvent> events);

/// A signature the steps before step 12 relied on (section 11.1), with the
/// algorithm of its key.
struct ReliedSignature {
    SignedObject signed_object = SignedObject::statement;
    std::optional<std::uint64_t> index;
    std::optional<std::uint64_t> tree_size;
    std::optional<Id> approver;
    std::optional<std::size_t> anchor;
    std::optional<std::size_t> renewal;
    crypto::SigAlg algorithm = crypto::SigAlg::ed25519;
};

/// Step 12: each of `signatures` by an algorithm in `distrust`, with the
/// dated attestation that covers it: relied on, dated before the
/// algorithm's date, over a checkpoint that holds what was signed; the
/// earliest, the first in the bundle's order among equal times. One that
/// none covers fails the evidence.
[[nodiscard]] Result<std::vector<DistrustedSignature>>
cover(std::span<const ReliedSignature> signatures, std::span<const Attestation> attestations,
      std::span<const Distrust> distrust);

/// The attestations set aside, in the bundle's order.
[[nodiscard]] std::vector<SetAsideAttestation>
set_aside_attestations(std::span<const Attestation> attestations);

/// The long-term status: the last covering checkpoint (the bundle's, signed
/// with `log_key`, or a renewal's) with a post-quantum attestation the
/// verifier relies on.
[[nodiscard]] Result<LongTermStatus>
long_term_status(const crypto::Provider& provider, const LedgerState& state,
                 const SignedCheckpoint& checkpoint, const crypto::PublicKey& log_key,
                 std::span<const CheckedRenewal> renewals,
                 std::span<const Attestation> attestations, std::span<const Distrust> distrust);

} // namespace kanhe::protocol::detail
