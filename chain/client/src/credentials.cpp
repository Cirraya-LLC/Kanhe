// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#include <algorithm>

#include <kanhe/client/credentials.hpp>
#include <kanhe/client/errors.hpp>
#include <kanhe/client/support.hpp>
#include <kanhe/core/protocol/evidence.hpp>
#include <kanhe/ledger/environment.hpp>
#include <kanhe/node/credentials.hpp>
#include <kanhe/node/published.hpp>

namespace kanhe::client {

IssuedCredential issue_credential(Session& session, const crypto::Signer& key,
                                  const CredentialRequest& request, const LogKey& log_key) {
    if (!node::valid_published_token(request.token)) {
        throw UsageError{"a published record's token is 22 characters (record published)"};
    }
    const protocol::ActorState& actor = session.actor_for(key);
    if (!node::is_credential_key(session.state(), actor)) {
        throw ActionError{"\"" + actor.display_name +
                          "\" is not a credential key: a device with an esp256 key whose "
                          "delegations allow endorsements only (credential key add)"};
    }
    const protocol::Id actor_id = actor.id.id();

    // The record's evidence as its address gives it, verified here.
    const Bytes bundle = session.published_evidence(log_key, request.token);
    protocol::VerifyOptions verify;
    verify.expected_ledger = session.state().ledger_id();
    const auto report = unwrap(protocol::verify_bundle(session.provider(), bundle, verify),
                               "the published record's evidence");

    const auto entries = node::credential_entries(session.state());
    const auto existing = node::credential_entry_of(entries, report.record, actor_id);
    verifier::StatusEntry entry;
    if (existing) {
        entry = existing->entry;
    } else {
        ledger::SystemEntropy entropy;
        entry = node::choose_status_entry(entries, entropy);
    }
    auto content = verifier::credential_content(report, request.base, request.token, entry,
                                                request.metadata, request.name);
    if (!content) {
        throw ActionError{content.error()};
    }
    IssuedCredential out;
    out.record = report.record;
    out.entry = entry;
    out.claims = content->subject.size();
    if (!existing) {
        out.endorsement = session.submit(
            key, protocol::RecordEndorseBody{report.record, verifier::credential_role(entry)},
            request.delegation);
    }
    out.credential = unwrap(verifier::sign_credential(key, session.provider(), request.base.did,
                                                      verifier::credential_json(*content)),
                            "signing the credential");
    return out;
}

} // namespace kanhe::client
