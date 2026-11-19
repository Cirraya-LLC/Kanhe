// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// A ledger's keys moved to post-quantum signatures in one step (spec v0.21,
// section 11.1): the log key rotated, then the root key, each signed by the
// root key in effect, then a checkpoint with the new log key. Run again
// with the same keys, it goes on from where it stopped: after a rotation
// the guardians had to approve, or a checkpoint the server could not sign.

#include <algorithm>
#include <filesystem>
#include <format>
#include <memory>
#include <optional>
#include <print>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

#include <kanhe/client/approvals.hpp>
#include <kanhe/core/protocol/keys.hpp>
#include <kanhe/core/protocol/log.hpp>
#include <kanhe/core/protocol/statement.hpp>
#include <kanhe/node/long_term.hpp>

#include "commands.hpp"
#include "output.hpp"

namespace kanhe::cli {

namespace {

bool ml_dsa_key(const crypto::PublicKey& key) {
    return node::post_quantum_algorithm(key.algorithm);
}

protocol::Id kid_of(const Session& session, const crypto::PublicKey& key) {
    return unwrap(protocol::key_id(session.provider(), session.state().hash(), key), "key id");
}

/// "Ed25519 3fa2c19be0d1"
std::string key_words(const Session& session, const crypto::PublicKey& key) {
    return std::format("{} {}", crypto::name(key.algorithm), short_id(kid_of(session, key)));
}

Json key_entry(const Session& session, const crypto::PublicKey& key) {
    Json out = public_key_json(key);
    out["kid"] = id_json(kid_of(session, key));
    return out;
}

/// One step of the conversion.
struct Step {
    std::string name;
    /// "planned", "rotated" or "made" (by this run), "done" (before it),
    /// "kept" (post-quantum already), "sent-for-approval", or "failed".
    std::string status = "planned";
    std::optional<crypto::PublicKey> from;
    std::optional<crypto::PublicKey> to;
    /// A key to be generated (--generate), not made yet: where it goes.
    std::optional<std::string> to_file;
    std::optional<protocol::Id> statement;
    std::optional<std::uint64_t> index;
    std::optional<std::uint64_t> tree_size;
    std::optional<std::string> error;
};

Json step_json(const Session& session, const Step& s) {
    Json out{{"step", s.name}, {"status", s.status}};
    if (s.name != "checkpoint") {
        out["from"] = s.from ? key_entry(session, *s.from) : Json(nullptr);
        if (s.to) {
            out["to"] = key_entry(session, *s.to);
        } else if (s.to_file) {
            out["to"] = {{"file", *s.to_file}};
        } else {
            out["to"] = nullptr;
        }
        out["statement_id"] = s.statement ? id_json(*s.statement) : Json(nullptr);
        out["index"] = s.index ? Json(*s.index) : Json(nullptr);
    } else {
        out["tree_size"] = s.tree_size ? Json(*s.tree_size) : Json(nullptr);
    }
    if (s.error) {
        out["error"] = *s.error;
    }
    return out;
}

/// What a run still leaves to do.
Json remaining_json(const std::vector<Step>& steps) {
    Json out = Json::array();
    for (const Step& s : steps) {
        if (s.status == "planned" || s.status == "sent-for-approval" || s.status == "failed") {
            out.push_back(s.name);
        }
    }
    return out;
}

/// The same in words: "the root key's rotation, the checkpoint".
std::string remaining_words(const std::vector<Step>& steps) {
    std::string out;
    for (const Step& s : steps) {
        if (s.status == "planned" || s.status == "sent-for-approval" || s.status == "failed") {
            const std::string_view words = s.name == "rotate-log-key"    ? "the log key's rotation"
                                           : s.name == "rotate-root-key" ? "the root key's rotation"
                                                                         : "the checkpoint";
            out += (out.empty() ? "" : ", ") + std::string(words);
        }
    }
    return out;
}

std::string step_title(const Step& s) {
    return s.name == "rotate-log-key"    ? "log key:   "
           : s.name == "rotate-root-key" ? "root key:  "
                                         : "checkpoint:";
}

void print_step(const Session& session, const Step& s) {
    const std::string title = step_title(s);
    if (s.name == "checkpoint") {
        if (s.status == "made" || s.status == "done") {
            std::println("  {} size {}, signed with the log key in effect{}", title,
                         s.tree_size.value_or(0), s.status == "done" ? " (made before)" : "");
        } else if (s.status == "failed") {
            std::println("  {} not made: {}", title, s.error.value_or(""));
        } else {
            std::println("  {} one with the new log key", title);
        }
        return;
    }
    const std::string from = s.from ? key_words(session, *s.from) : std::string("?");
    const std::string to = s.to        ? key_words(session, *s.to)
                           : s.to_file ? "a new key, written to " + *s.to_file
                                       : std::string("?");
    if (s.status == "kept") {
        std::println("  {} {} is post-quantum already: kept", title, from);
    } else if (s.status == "done") {
        std::println("  {} {} (rotated before)", title, to);
    } else if (s.status == "rotated") {
        std::println("  {} rotated at index {}: {} -> {}", title, s.index.value_or(0), from, to);
    } else if (s.status == "sent-for-approval") {
        std::println("  {} {} -> {}: sent for approval", title, from, to);
    } else {
        std::println("  {} {} -> {}", title, from, to);
    }
}

/// The rotations of the organization's keys held for approval now (at the
/// server, or in the ledger directory): what to approve or withdraw first.
std::vector<std::pair<std::string, protocol::Id>> held_rotations(Session& session) {
    std::vector<std::pair<std::string, protocol::Id>> out;
    const auto listed = client::list_held(session, std::nullopt, false, 0);
    const protocol::Id& ledger_id = session.state().ledger_id();
    for (const auto& item : listed["approvals"]) {
        if (!item.is_object() || item.value("state", std::string()) != "open") {
            continue;
        }
        const std::string type = item.value("type", std::string());
        if (type != "ledger-rotate-log-key" && type != "actor-rotate-key") {
            continue;
        }
        // The statement itself, as held: signed by the organization, and for
        // an actor-rotate-key, of its own root key (not a person's key).
        const protocol::Id id = client::held_id(session, item.value("id", std::string()));
        const auto file = client::fetch_held(session, id);
        const protocol::Statement& statement = file.statement.statement;
        if (statement.actor_id && *statement.actor_id != ledger_id) {
            continue;
        }
        if (std::holds_alternative<protocol::LedgerRotateLogKeyBody>(statement.body)) {
            out.emplace_back("the log key's rotation", id);
        } else if (const auto* body = std::get_if<protocol::ActorRotateKeyBody>(&statement.body);
                   body != nullptr && body->actor == ledger_id) {
            out.emplace_back("the root key's rotation", id);
        }
    }
    return out;
}

} // namespace

int cmd_ledger_long_term(const Args& args) {
    Session session(args);
    const bool dry_run = args.has("dry-run");
    const bool generate = args.has("generate");
    if (args.has("alg") && !generate) {
        throw UsageError{"--alg goes with --generate (given keys have their own algorithm)"};
    }
    const crypto::SigAlg alg = parse_algorithm(args.get("alg").value_or("ml-dsa-65"));
    if (!node::post_quantum_algorithm(alg)) {
        throw UsageError{"--alg is a post-quantum algorithm: ml-dsa-44, ml-dsa-65 (the default), "
                         "or ml-dsa-87"};
    }
    const std::string root_file = args.need("new-root-key");
    const std::string log_file = args.need("new-log-key");
    if (std::filesystem::path(root_file) == std::filesystem::path(log_file)) {
        throw UsageError{"the new root key and the new log key must differ"};
    }
    if (session.remote() && args.has("log-key")) {
        throw UsageError{"with --server the server holds the log key: drop --log-key, and give "
                         "the server the new one too (serve --log-key OLD --log-key NEW)"};
    }
    const protocol::LedgerState& state = session.state();
    const protocol::Id ledger_id = state.ledger_id();

    // The new keys, unless --generate makes them below.
    std::optional<crypto::PublicKey> new_root;
    std::optional<crypto::PublicKey> new_log;
    if (generate) {
        for (const std::string& file : {root_file, log_file}) {
            if (std::filesystem::exists(file)) {
                throw CommandError{file + " exists already: keys are never overwritten (to go on "
                                          "with keys made before, drop --generate)"};
            }
        }
    } else {
        new_root = public_key_of(root_file, args);
        new_log = public_key_of(log_file, args);
        for (const auto& [key, option] :
             {std::pair{*new_root, "--new-root-key"}, std::pair{*new_log, "--new-log-key"}}) {
            if (!ml_dsa_key(key)) {
                throw UsageError{std::format(
                    "{} is {}, not post-quantum: make an ML-DSA key (kanhe key generate --alg "
                    "ml-dsa-65), or pass --generate",
                    option, crypto::name(key.algorithm))};
            }
        }
        if (*new_root == *new_log) {
            throw UsageError{"the new root key and the new log key must differ"};
        }
    }

    // What each key needs: rotated, done already (a run before rotated it to
    // the key given), or kept (post-quantum already, another key).
    const crypto::PublicKey current_root = state.root_key();
    const crypto::PublicKey current_log = state.log_key();
    auto plan = [&](std::string name, const crypto::PublicKey& current,
                    const std::optional<crypto::PublicKey>& wanted, const std::string& file) {
        Step s;
        s.name = std::move(name);
        s.from = current;
        if (wanted && current == *wanted) {
            s.status = "done";
            s.to = current;
        } else if (ml_dsa_key(current)) {
            s.status = "kept";
            s.to = current;
        } else if (wanted) {
            s.to = wanted;
        } else {
            s.to_file = file;
        }
        return s;
    };
    std::vector<Step> steps;
    steps.push_back(plan("rotate-log-key", current_log, new_log, log_file));
    steps.push_back(plan("rotate-root-key", current_root, new_root, root_file));
    Step checkpoint_step;
    checkpoint_step.name = "checkpoint";
    steps.push_back(std::move(checkpoint_step));
    Step& log_step = steps[0];
    Step& root_step = steps[1];
    Step& made = steps[2];
    if (log_step.status == "kept" && root_step.status == "kept") {
        throw CommandError{std::format("the root key and the log key are post-quantum already "
                                       "({}, {}): nothing to convert (kanhe status says what "
                                       "else the ledger's evidence needs)",
                                       key_words(session, current_root),
                                       key_words(session, current_log))};
    }
    // A log key rotated before (a resumed run) replaced the one before it.
    if (log_step.status == "done") {
        log_step.from = state.log_keys().size() >= 2
                            ? std::optional(state.log_keys()[state.log_keys().size() - 2].key)
                            : std::nullopt;
    }
    if (root_step.status == "done") {
        root_step.from = state.root_keys().size() >= 2
                             ? std::optional(state.root_keys()[state.root_keys().size() - 2].key)
                             : std::nullopt;
    }
    const bool rotates = log_step.status == "planned" || root_step.status == "planned";

    // The key files given must be the keys in effect.
    if (!session.remote()) {
        if (!args.has("log-key")) {
            throw UsageError{"missing required option --log-key: the ledger's current log key "
                             "(file or pkcs11: URI), checked against the one in effect"};
        }
        const crypto::PublicKey given = public_key_of(args.need("log-key"), args);
        const bool replaced = log_step.status == "done" && log_step.from && given == *log_step.from;
        if (given != current_log && !replaced) {
            throw UsageError{"--log-key is not the ledger's log key in effect (" +
                             key_words(session, current_log) + ")"};
        }
    }
    std::unique_ptr<crypto::Signer> root_signer;
    if (rotates) {
        std::optional<crypto::PublicKey> as;
        if (dry_run) {
            as = public_key_of(args.need("as"), args);
        } else {
            root_signer = load_signer(args.need("as"), args);
            as = root_signer->public_key();
        }
        if (*as != current_root) {
            throw UsageError{"--as is not the organization's root key in effect (" +
                             key_words(session, current_root) + ")"};
        }
    }

    // Rotations that wait for approval come first, and the guardians guard
    // every rotation of the root and log keys (spec section 5.2).
    if (rotates) {
        const auto held = held_rotations(session);
        if (!held.empty()) {
            throw CommandError{std::format(
                "{} ({}) waits for the guardians' approvals: approve it (kanhe approval give "
                "{}), or withdraw it (kanhe approval withdraw {}), then run this again",
                held.front().first, hex_id(held.front().second), short_id(held.front().second),
                short_id(held.front().second))};
        }
    }
    const protocol::GuardianSetting* guardians = state.guardians();
    const bool guarded = guardians != nullptr && guardians->guardians.has_value();
    if (rotates && guarded && !dry_run && !session.approval_mode().send) {
        throw UsageError{"guardians guard the rotations of the root and log keys (" +
                         client::rule_text(session, *guardians->guardians) +
                         "): add --for-approval, and run this again once each rotation is "
                         "registered"};
    }

    auto result_json = [&] {
        Json out{{"ledger_id", id_json(ledger_id)},
                 {"dry_run", dry_run},
                 {"algorithm", generate ? Json(crypto::name(alg)) : Json(nullptr)}};
        Json list = Json::array();
        for (const Step& s : steps) {
            list.push_back(step_json(session, s));
        }
        out["steps"] = std::move(list);
        out["guardians"] =
            guarded ? Json{{"k", guardians->guardians->needed},
                           {"of", guardians->guardians->approvers.size()},
                           {"summary", client::rule_text(session, *guardians->guardians)}}
                    : Json(nullptr);
        out["remaining"] = remaining_json(steps);
        return out;
    };

    if (dry_run) {
        if (args.json()) {
            Json out = result_json();
            out["long_term"] =
                Json::parse(node::long_term_json(session.ledger(), session.now()).dump());
            print_json(out);
            return exit_ok;
        }
        std::println("the plan for ledger {} ({}):", short_id(ledger_id), state.organization());
        for (const Step& s : steps) {
            print_step(session, s);
        }
        if (guarded && rotates) {
            std::println("guardians guard both rotations ({}): each goes for approval "
                         "(--for-approval), and this runs again once each is registered",
                         client::rule_text(session, *guardians->guardians));
        }
        std::println("nothing was changed (--dry-run)");
        return exit_ok;
    }

    // The keys --generate makes, only those to be rotated to.
    std::vector<std::string> written;
    std::unique_ptr<crypto::Signer> new_log_signer;
    for (Step* s : {&log_step, &root_step}) {
        if (s->status != "planned" || !s->to_file) {
            continue;
        }
        const std::optional<std::string> secret = passphrase(args, *s->to_file, true);
        auto generated = unwrap(crypto::openssl::KeyPair::generate(alg), "generating the key");
        save_key(*s->to_file, generated, secret);
        written.push_back(*s->to_file);
        s->to = generated.public_key();
        s->to_file.reset();
        if (s == &log_step) {
            new_log_signer = std::make_unique<crypto::openssl::KeyPair>(std::move(generated));
        }
    }
    // The key that signs the checkpoint, here: the new log key, or the
    // current one if it is post-quantum already. (Through a server, the
    // server signs.)
    std::unique_ptr<crypto::Signer> checkpoint_signer;
    if (!session.remote()) {
        if (log_step.status == "kept") {
            checkpoint_signer = load_signer(args.need("log-key"), args);
        } else if (new_log_signer) {
            checkpoint_signer = std::move(new_log_signer);
        } else {
            try {
                checkpoint_signer = load_signer(log_file, args);
            } catch (const CommandError& e) {
                throw CommandError{"the new log key signs the checkpoint here, so --new-log-key is "
                                   "its private key file or a pkcs11: URI: " +
                                   e.message};
            }
            if (log_step.to && checkpoint_signer->public_key() != *log_step.to) {
                throw CommandError{"--new-log-key " + log_file + " is not the key rotated to"};
            }
        }
    }

    // A statement sent for approval ends the run: what follows needs it
    // registered.
    client::ApprovalMode mode = session.approval_mode();
    Step* sending = nullptr;
    mode.sent = [&](const client::SentForApproval& sent) {
        sending->status = "sent-for-approval";
        sending->statement = sent.statement;
        if (args.json()) {
            protocol::Timestamp lapses = 0;
            for (const protocol::RuleTally& r : sent.tally.rules) {
                lapses = lapses == 0 ? r.lapses_at : std::min(lapses, r.lapses_at);
            }
            Json out = result_json();
            out["sent_for_approval"] = {
                {"step", sending->name},
                {"statement_id", id_json(sent.statement)},
                {"where", sent.file          ? "file"
                          : session.remote() ? "server"
                                             : "ledger directory"},
                {"file", sent.file ? Json(sent.file->string()) : Json(nullptr)},
                {"rules", tally_json(session, sent.tally)},
                {"lapses_at", iso_time(lapses)}};
            out["keys_written"] = written;
            print_json(out);
        } else {
            for (const std::string& file : written) {
                std::println("wrote the new key {} (encrypted)", file);
            }
            print_sent_for_approval(args, session, sent);
            std::println("Once it is registered, run kanhe ledger long-term again with the same "
                         "keys{}: it goes on with what remains ({}).",
                         generate ? " (without --generate)" : "", remaining_words(steps));
        }
        throw CommandFinished{0};
    };
    session.set_approval_mode(std::move(mode));

    // Each rotation signed by the root key in effect: the log key's first,
    // then the root key's.
    for (Step* s : {&log_step, &root_step}) {
        if (s->status != "planned") {
            continue;
        }
        sending = s;
        protocol::Body body = s == &log_step
                                  ? protocol::Body{protocol::LedgerRotateLogKeyBody{*s->to}}
                                  : protocol::Body{protocol::ActorRotateKeyBody{ledger_id, *s->to}};
        const protocol::Id id =
            session.submit(*root_signer, std::move(body), std::nullopt, std::nullopt, std::nullopt);
        s->status = "rotated";
        s->statement = id;
        s->index = session.state().statement_index(id);
    }

    // Then a checkpoint with the log key in effect, unless the latest
    // already covers the whole log and is signed by it.
    const auto& latest = session.ledger().latest_checkpoint();
    if (latest && latest->checkpoint.tree_size == session.ledger().size() &&
        latest->kid == kid_of(session, session.state().log_key())) {
        made.status = "done";
        made.tree_size = latest->checkpoint.tree_size;
    } else if (session.remote()) {
        try {
            made.tree_size = session.checkpoint(LogKey{}).checkpoint.tree_size;
            made.status = "made";
        } catch (const CommandError& e) {
            made.status = "failed";
            made.error = e.message + " (give the server the new log key: serve --log-key OLD "
                                     "--log-key NEW; then run this again, or kanhe checkpoint "
                                     "create)";
        }
    } else {
        session.require_primary();
        made.tree_size = unwrap(session.ledger().checkpoint(*checkpoint_signer),
                                "checkpointing with the new log key")
                             .checkpoint.tree_size;
        made.status = "made";
    }

    const Json long_term =
        Json::parse(node::long_term_json(session.ledger(), session.now()).dump());
    if (args.json()) {
        Json out = result_json();
        out["keys_written"] = written;
        out["long_term"] = long_term;
        print_json(out);
        return made.status == "failed" ? exit_failure : exit_ok;
    }
    for (const std::string& file : written) {
        std::println("wrote the new key {} (encrypted; back it up)", file);
    }
    std::println("ledger {} ({}):", short_id(ledger_id), state.organization());
    for (const Step& s : steps) {
        print_step(session, s);
    }
    if (made.status == "failed") {
        return exit_failure;
    }
    std::println("Its root and log keys are post-quantum now.");
    if (!long_term.value("genesis_post_quantum", false)) {
        std::println("Its genesis named classical keys, which no rotation undoes: have a witness "
                     "whose key is ML-DSA cosign this checkpoint (kanhe checkpoint "
                     "cosign-request), and renew the evidence exported before (kanhe evidence "
                     "renew).");
    }
    if (!session.remote() && log_step.status == "rotated") {
        std::println("A server on this ledger signs with the new log key once it holds it: "
                     "kanhe serve --log-key OLD --log-key NEW.");
    }
    return exit_ok;
}

} // namespace kanhe::cli
