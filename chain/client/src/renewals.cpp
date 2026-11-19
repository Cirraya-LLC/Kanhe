// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include <algorithm>
#include <set>
#include <utility>
#include <vector>

#include <kanhe/client/errors.hpp>
#include <kanhe/client/renewals.hpp>
#include <kanhe/client/support.hpp>
#include <kanhe/core/protocol/log.hpp>
#include <kanhe/ledger/verify.hpp>
#include <kanhe/node/client.hpp>

namespace kanhe::client {

namespace {

/// A bundle carries at most this many renewals (spec section 11).
constexpr std::size_t most_renewals = 64;

} // namespace

std::uint64_t renewal_start(const protocol::EvidenceBundle& bundle) {
    const Bytes& last =
        bundle.renewals.empty() ? bundle.checkpoint : bundle.renewals.back().checkpoint;
    return unwrap(protocol::parse_checkpoint(last), "reading the bundle's checkpoint")
        .checkpoint.tree_size;
}

protocol::Renewal fetch_renewal(const std::string& url, std::uint64_t from,
                                std::optional<std::uint64_t> size,
                                const std::optional<std::string>& ca_file) {
    // Open to anyone: no token goes with it.
    const node::Client client = client_for(url, std::nullopt, ca_file);
    std::string path = "/v1/renewal?from=" + std::to_string(from);
    if (size) {
        path += "&size=" + std::to_string(*size);
    }
    const auto response = unwrap(client.request("GET", path), "reaching " + url);
    if (response.status != 200) {
        const auto message = node::error_message_of(response.body);
        throw ActionError{url + " gives no renewal from size " + std::to_string(from) + ": " +
                          message.value_or("status " + std::to_string(response.status))};
    }
    return unwrap(protocol::decode_renewal(response.body), "reading the renewal " + url + " gave");
}

Renewed renew_bundle(ByteView encoded, protocol::Renewal renewal,
                     const protocol::VerifyOptions& options) {
    auto bundle = unwrap(protocol::decode_bundle(encoded), "reading the evidence bundle");
    if (bundle.renewals.size() >= most_renewals) {
        throw ActionError{"the bundle carries 64 renewals already, as many as a bundle holds"};
    }
    Renewed out;
    out.from = renewal_start(bundle);
    // What the bundle holds already attests nothing anew: left out, so a
    // renewal that repeats the last checkpoint carries only what is new.
    std::set<Bytes> held(bundle.cosignatures.begin(), bundle.cosignatures.end());
    std::vector<protocol::network::NoteSignature> notes;
    for (const protocol::Anchor& a : bundle.anchors) {
        held.insert(a.timestamps.begin(), a.timestamps.end());
        notes.insert(notes.end(), a.network_cosignatures.begin(), a.network_cosignatures.end());
    }
    for (const protocol::Renewal& r : bundle.renewals) {
        held.insert(r.cosignatures.begin(), r.cosignatures.end());
        held.insert(r.timestamps.begin(), r.timestamps.end());
        notes.insert(notes.end(), r.network_cosignatures.begin(), r.network_cosignatures.end());
    }
    std::erase_if(renewal.cosignatures, [&](const Bytes& b) { return held.contains(b); });
    std::erase_if(renewal.timestamps, [&](const Bytes& b) { return held.contains(b); });
    std::erase_if(renewal.network_cosignatures, [&](const protocol::network::NoteSignature& n) {
        return std::ranges::contains(notes, n);
    });
    if (renewal.cosignatures.empty() && renewal.timestamps.empty() &&
        renewal.network_cosignatures.empty()) {
        throw ActionError{"the renewal adds nothing: the ledger's checkpoint is the bundle's "
                          "last, with no attestation the bundle lacks (ask a witness or a "
                          "time-stamp authority to attest a newer checkpoint)"};
    }
    out.added = renewal;
    bundle.renewals.push_back(std::move(renewal));
    out.bundle = unwrap(protocol::encode_bundle(bundle), "encoding the renewed bundle");
    // The whole bundle, as any verifier will check it.
    out.report = ledger::verify_bundle(shared_provider(), out.bundle, options, on_all_cores());
    return out;
}

} // namespace kanhe::client
