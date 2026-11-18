// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

#pragma once

#include <cstdint>
#include <filesystem>
#include <functional>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

#include <nlohmann/json.hpp>

#include <kanhe/client/support.hpp>
#include <kanhe/core/bytes.hpp>
#include <kanhe/core/protocol/approvals.hpp>
#include <kanhe/core/protocol/log.hpp>
#include <kanhe/core/protocol/record.hpp>
#include <kanhe/core/protocol/state.hpp>
#include <kanhe/core/protocol/statement.hpp>
#include <kanhe/crypto/openssl.hpp>
#include <kanhe/ledger/environment.hpp>
#include <kanhe/ledger/ledger.hpp>
#include <kanhe/ledger/storage.hpp>
#include <kanhe/node/client.hpp>
#include <kanhe/node/published.hpp>
#include <kanhe/node/record_files.hpp>

namespace kanhe::client {

/// What a person's authenticator is asked to sign: a passkey assertion over
/// the statement's presence challenge.
struct PasskeyRequest {
    std::string rp_id;
    Bytes challenge;
    /// The person's passkeys for `rp_id`, by credential id.
    std::vector<Bytes> allow;
    /// "Confirm as NAME", and what is being signed, for the person.
    std::string title;
    std::string summary;
};

/// The authenticator's answer.
struct PasskeyAssertion {
    Bytes credential_id;
    Bytes authenticator_data;
    Bytes client_data_json;
    Bytes signature;
};

/// Runs a passkey ceremony: the command line's one-time local page, or the
/// console's approval. Throws if the person cancels.
using PasskeyCeremony = std::function<PasskeyAssertion(const PasskeyRequest&)>;

/// How the signer (a person) proves presence before signing.
struct PresenceRequest {
    /// A hardware key (an opened token key) that signs the challenge;
    /// otherwise a passkey, through `passkey`.
    std::shared_ptr<crypto::Signer> hardware_key = nullptr;
    PasskeyCeremony passkey = {};
};

/// The log key, for what is signed with it on a ledger directory:
/// checkpoints, evidence, and receipts. In client mode the server signs, and
/// a log key given is refused.
struct LogKey {
    bool given = false;
    /// Loads it (on a ledger directory only, when it is needed).
    std::function<std::unique_ptr<crypto::Signer>()> load;
};

/// A server whose ledger a session mirrors (client mode).
struct ServerLocation {
    std::string url;
    std::optional<std::string> ca_file;
    std::optional<std::string> token;
    /// The ledger id expected, in hex: required on first use of an http://
    /// URL, which then pins the ledger it serves.
    std::optional<std::string> ledger_id;
    /// Where mirrors live: default $XDG_CACHE_HOME/kanhe or
    /// ~/.cache/kanhe.
    std::optional<std::filesystem::path> cache;
};

/// A ledger directory, or a server.
using Location = std::variant<std::filesystem::path, ServerLocation>;

/// What was sent for approval instead of registered (spec v0.20).
struct SentForApproval {
    protocol::Id statement;
    /// The approval file written; none if it is held (at the server, or in
    /// the ledger directory's held statements).
    std::optional<std::filesystem::path> file;
    /// A registration's fields went with it, in clear.
    bool fields_shown = false;
    /// The rules that apply, counted at this machine's clock: the signer, if
    /// it counts, and no approval yet.
    protocol::ApprovalTally tally;
    /// Where it is held: the held statement as listed (GET /v1/approvals);
    /// null for a file.
    nlohmann::json held;
};

/// How a session treats a statement whose approval rules (spec v0.20) need
/// more than its signer: refused, with the rules in words (before a
/// passkey is asked, when one is), unless `send`; then sent for approval
/// instead of registered: an approval file written to `file` (a directory:
/// a file named after the statement in it), or else the statement held at
/// the server in client mode, or in the ledger directory's held statements.
/// A statement that needs no approvals is registered as usual.
struct ApprovalMode {
    bool send = false;
    std::optional<std::filesystem::path> file;
    /// A registration's fields go with it, for approvers to see (in clear).
    bool show_fields = false;
    std::optional<std::string> note;
    /// Who prepared it, for a statement held in the ledger directory.
    std::string preparer = "cli";
    /// Added to a refusal, after a colon ("add --for-approval").
    std::string hint;
    /// Told what was sent. What follows a registration cannot follow, so the
    /// action stops after it: by its throwing, or else the session throws an
    /// ActionError.
    std::function<void(const SentForApproval&)> sent;
};

/// Makes the sealed private data of the record `id` names (for record
/// registrations, which keep it in the vault).
using SealVault = std::function<Bytes(const protocol::Id& record)>;
/// Makes the sealed files of the record `id` names, to keep with it.
using SealFiles = std::function<std::vector<node::SealedFile>(const protocol::Id& record)>;

/// An open ledger with the environment needed to act on it: a ledger
/// directory, or, in client mode, a verified mirror of the ledger a
/// server serves.
///
/// Client mode, at a ServerLocation: the mirror lives in the cache, one
/// directory per ledger id. Each session first syncs it with the replica
/// code, so every entry and checkpoint it shows was re-validated here, and a
/// server that rewrites or rolls back what this client saw is refused. The
/// ledger a URL serves is pinned on first use. Statements are signed here
/// and sent to the server; keys never leave this machine.
class Session {
public:
    explicit Session(const Location& location);

    [[nodiscard]] ledger::Ledger& ledger() { return *ledger_; }
    [[nodiscard]] const protocol::LedgerState& state() const { return ledger_->state(); }
    [[nodiscard]] const crypto::Provider& provider() const { return provider_; }
    [[nodiscard]] const std::filesystem::path& directory() const { return directory_; }

    /// Resolves a full or abbreviated (8+ hex digits) identifier among actors,
    /// delegations, or records.
    [[nodiscard]] protocol::Id actor_id(std::string_view text) const;
    [[nodiscard]] protocol::Id record_id(std::string_view text) const;
    [[nodiscard]] protocol::Id delegation_id(std::string_view text) const;
    [[nodiscard]] protocol::Id contract_id(std::string_view text) const;
    [[nodiscard]] protocol::Id instance_id(std::string_view text) const;
    /// A request (v0.8), by its id or a unique prefix.
    [[nodiscard]] protocol::Id request_id(std::string_view text) const;

    /// The actor holding `key`.
    [[nodiscard]] const protocol::ActorState& actor_for(const crypto::Signer& key) const;

    /// Builds, signs, and submits a statement by the holder of `signer`,
    /// choosing a delegation that covers it unless `delegation` is given, and
    /// filling in provenance for agents. Returns the statement's id.
    /// With `presence` set, the signer (a person) first proves presence, with
    /// a passkey in the browser or with a hardware key.
    /// With `seal_vault`, the record's sealed private data is kept with it:
    /// written to the vault here, or sent with the statement in client mode.
    /// With `consents` (a contract call's, in the order it cites them), the
    /// consents' evidence is kept with it the same way.
    /// With `fields` (a registration's, in the order of its leaves), they
    /// go to its approvers if the approval mode shows them.
    protocol::Id submit(const crypto::Signer& signer, protocol::Body body,
                        const std::optional<std::string>& delegation,
                        std::optional<protocol::Provenance> provenance = std::nullopt,
                        const std::optional<PresenceRequest>& presence = std::nullopt,
                        const SealVault& seal_vault = {}, std::span<const Bytes> consents = {},
                        const SealFiles& seal_files = {},
                        std::span<const protocol::RecordField> fields = {});

    /// Builds and signs a statement as `submit` does, without registering
    /// it: to run a contract call first, or for a dry run.
    [[nodiscard]] protocol::SignedStatement
    sign(const crypto::Signer& signer, protocol::Body body,
         const std::optional<std::string>& delegation,
         std::optional<protocol::Provenance> provenance = std::nullopt,
         const std::optional<PresenceRequest>& presence = std::nullopt);
    /// Registers a statement from `sign`, with its sealed private data or
    /// its consents' evidence, as `submit` does. One whose approval rules
    /// need approvals is refused or sent for approval (see ApprovalMode).
    protocol::Id submit_signed(const protocol::SignedStatement& statement,
                               const std::optional<Bytes>& sealed = std::nullopt,
                               std::span<const Bytes> consents = {},
                               std::span<const node::SealedFile> files = {},
                               std::span<const protocol::RecordField> fields = {});
    /// Registers a signed statement with the approvals it travels with
    /// (spec v0.20), in any order, and the rest of its submission: here, or
    /// through the server. The ledger checks them.
    protocol::Id register_signed(const protocol::SignedStatement& statement,
                                 const std::optional<Bytes>& sealed,
                                 std::span<const Bytes> consents,
                                 std::span<const node::SealedFile> files,
                                 std::span<const Bytes> approvals);

    /// Approvals (spec v0.20): how statements that need them are treated.
    void set_approval_mode(ApprovalMode mode) { approval_mode_ = std::move(mode); }
    [[nodiscard]] const ApprovalMode& approval_mode() const noexcept { return approval_mode_; }
    /// The approval rules of `statement`, and their count with its signer
    /// alone, at this machine's clock; and a refusal in words for one they
    /// leave unmet ("needs 2 of ... within 7 days").
    [[nodiscard]] std::string needs_text(std::span<const protocol::AppliedRule> rules) const;

    /// This machine's clock (with any offset applied).
    [[nodiscard]] protocol::Timestamp now() const { return ledger::SystemClock{}.now(); }
    /// True once the ledger shows the statement `id` registered: in client
    /// mode, after syncing the mirror for up to ten seconds (a cluster's
    /// follower may apply it a moment later).
    bool await_statement(const protocol::Id& id);

    /// Proves presence for `actor` (a person) over `challenge`: with the
    /// hardware key `request` names (one of the person's credentials, not
    /// `signing_key`), or with a passkey, through `request.passkey`, which
    /// shows `title` and `summary`. Checked against the credentials.
    [[nodiscard]] protocol::PresenceProof prove(const protocol::ActorState& actor,
                                                const crypto::PublicKey& signing_key,
                                                ByteView challenge, const PresenceRequest& request,
                                                std::string title, std::string summary) const;

    /// Resolves an index or (abbreviated) statement id to a log index.
    [[nodiscard]] std::uint64_t entry_index(std::string_view text) const;

    /// The log entry at `index` and its statement, parsed.
    [[nodiscard]] protocol::LogEntry log_entry(std::uint64_t index) const;
    [[nodiscard]] protocol::SignedStatement statement(std::uint64_t index) const;
    /// The state commitment at `index` (which must be one).
    [[nodiscard]] protocol::SignedStateCommitment state_commitment(std::uint64_t index) const;

    /// The actor's display name, or "unknown" for an unknown id.
    [[nodiscard]] std::string actor_name(const protocol::Id& id) const;

    [[nodiscard]] std::filesystem::path vault_path(const protocol::Id& record) const;

    /// Throws unless this ledger is a primary: a replica only copies its
    /// primary, and writing to it would fork the ledger. (In client mode
    /// writes go to the server.)
    void require_primary() const;

    /// True in client mode.
    [[nodiscard]] bool remote() const noexcept { return remote_.has_value(); }

    // What the log key signs: here with `log_key`; in client mode by the
    // server, and checked against the mirror before it is used.
    [[nodiscard]] protocol::SignedCheckpoint checkpoint(const LogKey& log_key);
    [[nodiscard]] protocol::EvidenceBundle evidence(const LogKey& log_key,
                                                    const protocol::Id& record);
    /// A published record's evidence as its address gives it, its fields
    /// disclosed: built here (after a checkpoint, if the latest does not
    /// cover the record as it is now), or the server's `/c/TOKEN`, verified
    /// against the mirror and refused if it leaves out anything the mirror
    /// holds about the record.
    [[nodiscard]] Bytes published_evidence(const LogKey& log_key, std::string_view token);
    /// An instance's contract evidence with the consents its calls cite,
    /// without private data: built here with the log key (after a
    /// checkpoint, if the latest does not cover the instance's last call), or
    /// the server's, verified against the mirror.
    [[nodiscard]] Bytes contract_evidence(const LogKey& log_key, const protocol::Id& instance);
    [[nodiscard]] Bytes receipt(const LogKey& log_key, std::uint64_t index);
    void add_cosignature(ByteView cosignature, const crypto::PublicKey& witness);
    /// Keeps a time-stamp token over a checkpoint of `size` (spec v0.11), on
    /// the ledger or through its server (an admin token).
    void add_timestamp(ByteView token, std::uint64_t size);
    /// Keeps an open-network witness's cosignature of the note of a
    /// checkpoint of `size` (spec v0.13), on the ledger or its server.
    void add_network_cosignature(const protocol::network::VerifierKey& witness,
                                 const protocol::network::NoteSignature& cosignature,
                                 std::uint64_t size);

    /// A record published at a private address (node/published.hpp): its
    /// token, and the fields it discloses, by name and value as shown.
    struct PublishedRecord {
        std::string token;
        protocol::Id record;
        std::vector<std::pair<std::string, std::string>> fields;
        protocol::Timestamp published_at = 0;
    };
    /// Publishes `record` with `disclosures` (each opening one of its fields),
    /// on the ledger or through its server (an admin token).
    PublishedRecord publish(const protocol::Id& record,
                            std::vector<protocol::FieldDisclosure> disclosures);
    /// The records published, oldest first.
    [[nodiscard]] std::vector<PublishedRecord> published() const;
    /// Takes a published record's address down (the record stays).
    void unpublish(std::string_view token);
    /// The server's address in client mode (empty on a ledger directory).
    [[nodiscard]] std::string server_url() const { return remote_ ? remote_->url : std::string(); }

    /// Client mode: fetches a record's sealed private data into the mirror,
    /// unless it is there. False if the server holds none.
    bool fetch_vault(const protocol::Id& record) const;
    /// Client mode: fetches the server's vault public key into the mirror
    /// (once per session).
    void fetch_vault_public_key() const;

    /// Client mode: sends a request to the server, and fails unless it
    /// succeeded (with the server's message). Returns the answer's body.
    Bytes request(std::string_view method, std::string_view path, ByteView body = {},
                  std::string_view content_type = {}) const;

private:
    void prove_presence(const protocol::ActorState& actor, protocol::Statement& statement,
                        const crypto::PublicKey& signing_key, const PresenceRequest& request) const;
    /// Sends for approval what `submit_signed` would register (see
    /// ApprovalMode), and stops the action; a statement the server or the
    /// directory registers at once (its signer met its rules after all) is
    /// returned as registered.
    protocol::Id send_for_approval(const protocol::SignedStatement& statement,
                                   const std::optional<Bytes>& sealed,
                                   std::span<const Bytes> consents,
                                   std::span<const node::SealedFile> files,
                                   std::span<const protocol::RecordField> fields,
                                   const protocol::ApprovalTally& tally);

    [[nodiscard]] std::optional<protocol::Id> choose_delegation(const protocol::ActorState& actor,
                                                                const protocol::Body& body) const;

    void open(const std::filesystem::path& directory);
    void open_remote(const ServerLocation& server);
    /// Client mode: brings the mirror up to the server, tail included.
    void sync();
    /// Client mode: syncs until `done`, for up to ten seconds: a cluster's
    /// follower may apply what its leader did a moment later.
    bool sync_until(const std::function<bool()>& done);
    /// True if the mirror holds this signed checkpoint.
    [[nodiscard]] bool has_checkpoint(ByteView encoded) const;
    /// Client mode: sends a request, and fails unless it succeeded.
    Bytes call(std::string_view method, std::string_view path, ByteView body = {},
               std::string_view content_type = {}) const;

    struct Remote {
        node::Client client;
        std::string url;
        mutable bool vault_key_fetched = false;
    };

    std::filesystem::path directory_;
    std::optional<Remote> remote_;
    std::optional<ledger::DirectoryLock> lock_;
    crypto::openssl::Provider provider_;
    ledger::SystemClock clock_;
    ledger::SystemEntropy entropy_;
    std::optional<ledger::PosixFileSystem> fs_;
    std::optional<ledger::Ledger> ledger_;
    ApprovalMode approval_mode_;
};

} // namespace kanhe::client
