// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya
//
// The WebAssembly verifier must reach exactly the conclusions of the native
// one. Usage: node verifier_node.js MODULE_JS API_JS EVIDENCE_DIR
"use strict";
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const [moduleJs, apiJs, dir] = process.argv.slice(2);
const factory = require(path.resolve(moduleJs));
const { createKanheVerifier } = require(path.resolve(apiJs));
const read = (name) => new Uint8Array(fs.readFileSync(path.join(dir, name)));
const text = (name) => fs.readFileSync(path.join(dir, name), "utf8").trim();

(async () => {
  const verifier = await createKanheVerifier(factory);
  const bundle = read("bundle.cbor");
  const ledgerId = text("ledger-id");

  // Same report as `kanhe verify --json`, field for field.
  const report = verifier.verify(bundle, { ledgerId, attachments: { "report.pdf": read("report.pdf") } });
  assert.equal(report.verified, true, report.error);
  assert.equal(typeof report.text, "string");
  assert.match(report.text, /AI agent: claude-opus-5-5; responsible: Alice Inspector/);
  delete report.text;
  assert.equal(report.kind, "record");
  delete report.kind;
  assert.deepEqual(report, JSON.parse(text("native-report.json")));
  assert.equal(report.record.id, text("record-id"));
  assert.equal(report.disclosed_fields.result, "pass");
  assert.equal(report.disclosed_fields.note, "中文 ✓ <script>alert(1)</script>");
  assert.equal(report.attachments[0].status, "verified");
  assert.equal(report.events[0].actor.kind, "agent");
  assert.equal(report.events[0].actor.responsible, "Alice Inspector");

  // Without an expected ledger id the report says it was not checked.
  const unchecked = verifier.verify(bundle);
  assert.equal(unchecked.verified, true);
  assert.equal(unchecked.ledger.id_checked, false);
  assert.equal(unchecked.attachments[0].status, "not-provided");

  // A forged attachment, another ledger, a bad id, and damaged bytes all fail.
  const forged = verifier.verify(bundle, { attachments: { "report.pdf": new TextEncoder().encode("forged") } });
  assert.equal(forged.verified, false);
  assert.equal(forged.attachments[0].status, "mismatch");
  const otherLedger = verifier.verify(bundle, { ledgerId: "00".repeat(32) });
  assert.equal(otherLedger.verified, false);
  assert.match(otherLedger.error, /ledger/);
  assert.equal(verifier.verify(bundle, { ledgerId: "xyz" }).verified, false);
  // Every byte matters. (The bundle ends with the attachment's salt, which can
  // only be checked against the attachment's content, so supply it.)
  const attachments = { "report.pdf": read("report.pdf") };
  for (let offset = 0; offset < bundle.length; offset += 7) {
    const damaged = bundle.slice();
    damaged[offset] ^= 1;
    assert.equal(verifier.verify(damaged, { ledgerId, attachments }).verified, false, "flipped byte at " + offset);
  }
  const lastByte = bundle.slice();
  lastByte[lastByte.length - 1] ^= 1;
  assert.equal(verifier.verify(lastByte, { ledgerId, attachments }).verified, false);
  assert.equal(verifier.verify(new Uint8Array(0)).verified, false);

  // A time-stamp authority's token (v0.11): the same report as `kanhe
  // verify --tsa-root`, and without the root, nothing relied on.
  const stamped = read("stamped.cbor");
  const stampedReport = verifier.verify(stamped, {
    ledgerId, attachments: { "report.pdf": read("report.pdf") }, timestampRoots: [read("tsa-root.pem")] });
  assert.equal(stampedReport.verified, true, stampedReport.error);
  assert.match(stampedReport.text, /Time-stamps  1 trusted authority/);
  delete stampedReport.text;
  delete stampedReport.kind;
  assert.deepEqual(stampedReport, JSON.parse(text("native-stamped-report.json")));
  assert.equal(stampedReport.timestamps.trusted_authorities, 1);
  assert.match(stampedReport.timestamps.existed_by, /^20\d\d-/);
  const unrooted = verifier.verify(stamped, { ledgerId });
  assert.equal(unrooted.verified, true);
  assert.equal(unrooted.timestamps.trusted_authorities, 0);
  assert.equal(unrooted.timestamps.existed_by, null);
  assert.equal(verifier.verify(stamped, { timestampRoots: [read("witness.pub")] }).verified, false);

  // Witness keys: a public key file is accepted, anything else refused.
  assert.equal(verifier.verify(bundle, { witnesses: [read("witness.pub")] }).verified, true);
  assert.equal(verifier.verify(bundle, { witnesses: [read("witness.key")] }).verified, false);

  // Options do not leak from one call into the next.
  assert.equal(verifier.verify(bundle).attachments[0].status, "not-provided");

  // A contract instance's evidence: the contract is run again on every call,
  // here by the interpreter compiled to WebAssembly, and the report is the
  // same as `kanhe contract verify`, in JSON and in text.
  const contract = read("contract.cbor");
  const contractLedger = text("contract-ledger-id");
  const contractReport = verifier.verify(contract, { ledgerId: contractLedger });
  assert.equal(contractReport.kind, "contract");
  assert.equal(contractReport.verified, true, contractReport.error);
  assert.equal(contractReport.text, fs.readFileSync(path.join(dir, "native-contract-report.txt"), "utf8"));
  delete contractReport.text;
  delete contractReport.kind;
  assert.deepEqual(contractReport, JSON.parse(text("native-contract-report.json")));
  assert.equal(contractReport.instance.id, text("instance-id"));
  assert.equal(contractReport.instance.status, "effective");
  assert.equal(contractReport.instance.contract.name, "Supply agreement");
  assert.equal(contractReport.complete, true);
  assert.deepEqual(contractReport.calls.map((c) => c.function), ["propose", "sign"]);
  const signed = contractReport.calls[1];
  assert.equal(signed.called_by.name, "Procurement Manager");
  assert.equal(signed.outcome.status, "effective");
  assert.deepEqual(signed.outcome.events.map((e) => e.name), ["signed"]);
  assert.deepEqual(signed.consents.map((c) => c.organization).sort(), ["Cirraya Bank", "Cirraya Supplier"]);
  const bankConsent = signed.consents.find((c) => c.organization === "Cirraya Bank");
  assert.equal(bankConsent.signer.kind, "agent");
  assert.equal(bankConsent.provenance.model, "credit-model-7");
  assert.equal(bankConsent.signer.responsible, "Credit Officer");
  assert.equal(bankConsent.reference, "Credit approval CA-9");
  // Unpinned, it verifies but says the home was not compared; pinned to
  // another ledger it fails; and so does any damage.
  const contractUnchecked = verifier.verify(contract);
  assert.equal(contractUnchecked.verified, true, contractUnchecked.error);
  assert.equal(contractUnchecked.home.id_checked, false);
  assert.equal(verifier.verify(contract, { ledgerId }).verified, false);
  for (let offset = 0; offset < contract.length; offset += 97) {
    const damaged = contract.slice();
    damaged[offset] ^= 1;
    assert.equal(verifier.verify(damaged, { ledgerId: contractLedger }).verified, false,
                 "contract: flipped byte at " + offset);
  }

  // A tier-3 part of a receivable (v0.7): its subject is no statement id but
  // derived from the call that created it, and its ancestors' calls are run
  // again too. The same report as `kanhe contract verify`.
  const part = read("part.cbor");
  const partReport = verifier.verify(part, { ledgerId: contractLedger });
  assert.equal(partReport.kind, "contract");
  assert.equal(partReport.verified, true, partReport.error);
  assert.equal(partReport.text, fs.readFileSync(path.join(dir, "native-part-report.txt"), "utf8"));
  assert.match(partReport.text, /Ancestors {4}oldest first/);
  delete partReport.text;
  delete partReport.kind;
  assert.deepEqual(partReport, JSON.parse(text("native-part-report.json")));
  assert.equal(partReport.instance.id, text("part-id"));
  assert.equal(partReport.instance.parent, text("part-parent-id"));
  assert.equal(partReport.instance.depth, 2);
  assert.deepEqual(partReport.instance.ancestors.map((a) => a.id), [text("part-root-id"), text("part-parent-id")]);
  assert.deepEqual(partReport.calls.map((c) => c.function), ["issue", "split", "split", "transfer"]);
  assert.equal(partReport.calls[1].outcome.children.length, 2);
  assert.deepEqual(partReport.calls.map((c) => c.consents.map((k) => k.organization)),
                   [[], ["Cirraya Supplier"], ["Cirraya Supplier"], ["Cirraya Bank"]]);
  assert.equal(verifier.verify(part, { ledgerId }).verified, false);
  for (let offset = 0; offset < part.length; offset += 97) {
    const damaged = part.slice();
    damaged[offset] ^= 1;
    assert.equal(verifier.verify(damaged, { ledgerId: contractLedger }).verified, false,
                 "part: flipped byte at " + offset);
  }

  // Requests and answers (v0.8): every request the calls made, each answer
  // with its status and lateness, and the open ones, one overdue at the
  // checkpoint. The same report as `kanhe contract verify`.
  const asking = read("requests.cbor");
  const askingLedger = text("requests-ledger-id");
  const askingReport = verifier.verify(asking, { ledgerId: askingLedger });
  assert.equal(askingReport.verified, true, askingReport.error);
  assert.equal(askingReport.text, fs.readFileSync(path.join(dir, "native-requests-report.txt"), "utf8"));
  assert.match(askingReport.text, /OVERDUE/);
  delete askingReport.text;
  delete askingReport.kind;
  assert.deepEqual(askingReport, JSON.parse(text("native-requests-report.json")));
  const asked = askingReport.instance;
  assert.equal(asked.id, text("requests-id"));
  assert.deepEqual(asked.requests.map((r) => r.kind), ["notify", "http.post", "notify", "notify"]);
  assert.deepEqual(asked.requests.map((r) => r.status), ["done", "done", "open", "open"]);
  assert.equal(asked.open_requests.length, 2);
  assert.deepEqual(asked.overdue_requests, [asked.requests[2].id]);
  const answers = askingReport.calls.filter((c) => c.answer);
  assert.deepEqual(answers.map((c) => [c.answer.kind, c.answer.status, c.answer.late, c.called_by.kind]),
                   [["notify", "done", false, "device"], ["http.post", "done", true, "person"]]);
  assert.equal(answers[1].outcome.requests.length, 1);
  assert.equal(askingReport.calls[0].outcome.requests.length, 3);
  for (let offset = 0; offset < asking.length; offset += 97) {
    const damaged = asking.slice();
    damaged[offset] ^= 1;
    assert.equal(verifier.verify(damaged, { ledgerId: askingLedger }).verified, false,
                 "requests: flipped byte at " + offset);
  }

  // Trust nodes (spec v0.16): the independent vectors' members' evidence,
  // with the trust nodes the page is told to believe, and without.
  const v16 = JSON.parse(fs.readFileSync(path.join(__dirname, "../../testvectors/protocol-v0.16.json"), "utf8"));
  const hexBytes = (h) => new Uint8Array(Buffer.from(h, "hex"));
  for (const c of v16.bundles.valid) {
    const got = verifier.verify(hexBytes(c.bundle), { ledgerId: c.ledger, trustNodes: c.trust_nodes });
    assert.equal(got.verified, true, c.name + ": " + got.error);
    assert.equal(got.memberships.length, c.memberships.length, c.name);
    got.memberships.forEach((m, i) => {
      const want = c.memberships[i];
      for (const key of ["trust_node", "trusted", "trust_node_name", "membership", "kind", "name", "verified", "at_record", "at_checkpoint"]) {
        assert.equal(m[key], want[key], c.name + ": " + key);
      }
    });
  }
  for (const c of v16.bundles.refused) {
    assert.equal(verifier.verify(hexBytes(c.bundle), { ledgerId: c.ledger }).verified, false, c.name);
  }
  assert.equal(verifier.verify(new Uint8Array(1), { trustNodes: [{ ledger: "xyz", name: "A" }] }).verified, false);

  // Long-term evidence (spec v0.21): every bundle of the independent vectors,
  // with its options (the witnesses, network witnesses, and time-stamp
  // authorities trusted, and the algorithms distrusted), reaches their verdict
  // and, when verified, their facts: the renewals, the long-term status, and
  // what covers each signature by a distrusted algorithm.
  const v21 = JSON.parse(fs.readFileSync(path.join(__dirname, "../../testvectors/protocol-v0.21.json"), "utf8"));
  const mismatches = (fact, value, where = "") => {
    if (fact !== null && typeof fact === "object" && !Array.isArray(fact)) {
      if (value === null || typeof value !== "object" || Array.isArray(value)) return [where + ": not an object"];
      return Object.entries(fact).flatMap(([key, sub]) =>
        key in value ? mismatches(sub, value[key], where + "." + key) : [where + "." + key + ": not in the report"]);
    }
    if (Array.isArray(fact)) {
      if (!Array.isArray(value) || value.length !== fact.length) return [where + ": " + fact.length + " items expected"];
      return fact.flatMap((sub, i) => mismatches(sub, value[i], where + "[" + i + "]"));
    }
    return fact === value ? [] : [where + ": " + JSON.stringify(fact) + " expected, " + JSON.stringify(value) + " reported"];
  };
  const optionsOf = (o) => ({
    ledgerId: o.ledger_id, witnesses: (o.witnesses || []).map(hexBytes),
    timestampRoots: (o.tsa_roots || []).map((pem) => new TextEncoder().encode(pem)),
    networkWitnesses: o.witness_vkeys || [], distrust: o.distrust || [],
    attachments: Object.fromEntries(Object.entries(o.attachments || {}).map(([name, hex]) => [name, hexBytes(hex)])),
  });
  const USAGE = /^the distrust option /;
  for (const c of v21.bundles) {
    const got = verifier.verify(hexBytes(c.evidence), optionsOf(c.options));
    assert.equal(got.verified, c.verified, c.name + ": " + (got.error || "verified"));
    if (c.verified) assert.deepEqual(mismatches(c.facts, got), [], c.name);
    else assert.doesNotMatch(String(got.error), USAGE, c.name);
  }
  // The option as the specification reads it: refused before anything is
  // checked, or read into the algorithms and dates the report gives. An
  // ML-DSA-65 authority's token covers every signature of this bundle.
  const stampedPq = v21.bundles.find((c) => c.name === "renewal-post-quantum-timestamp");
  const withDistrust = (distrust) =>
    verifier.verify(hexBytes(stampedPq.evidence), Object.assign(optionsOf(stampedPq.options), { distrust }));
  for (const c of v21.distrust_options.refused) {
    const got = withDistrust(c.options);
    assert.equal(got.verified, false, c.name);
    assert.match(got.error, USAGE, c.name);
  }
  v21.distrust_options.valid.forEach((c, i) => {
    const got = withDistrust(c.options);
    assert.doesNotMatch(String(got.error), USAGE, c.options.join(" "));
    if (i < 3) assert.equal(got.verified, true, c.options.join(" ") + ": " + got.error);
    if (got.verified) assert.deepEqual(got.distrust.algorithms, c.algorithms);
  });
  assert.equal(withDistrust([]).distrust, null);

  // Long-term evidence made by the command line (v0.21): a classical
  // ledger's certificate, then the same renewed after the ledger moved to
  // ML-DSA-65 keys, cosigned by an Ed25519 and an ML-DSA-65 witness, each
  // cosignature dated. The same reports as `kanhe verify --json`.
  const ltOptions = (distrust) => ({ ledgerId: text("longterm-ledger-id"),
    witnesses: [read("lt-classical.pub"), read("lt-quantum.pub")], distrust });
  const asNative = (report, file) => {
    delete report.text;
    delete report.kind;
    assert.deepEqual(report, JSON.parse(text(file)), file);
  };
  const classical = verifier.verify(read("longterm.cbor"), ltOptions());
  assert.equal(classical.verified, true, classical.error);
  assert.deepEqual(classical.renewals, []);
  assert.deepEqual(classical.long_term,
                   { post_quantum: false, checkpoint: null, attested_by: [], renew_before: "2030-01-01T00:00:00.000Z" });
  assert.equal(classical.distrust, null);
  asNative(classical, "native-longterm-report.json");
  const renewed = verifier.verify(read("renewed.cbor"), ltOptions());
  assert.equal(renewed.verified, true, renewed.error);
  assert.equal(renewed.renewals.length, 1);
  const [renewal] = renewed.renewals;
  assert.ok(renewal.tree_size > renewed.checkpoint.tree_size);
  assert.deepEqual([renewal.log_key.algorithm, renewal.log_key_rotations, renewal.root_key_rotations],
                   ["ML-DSA-65", 1, 1]);
  assert.deepEqual(renewal.witnesses, { trusted: 2, untrusted: 0, network: [] });
  assert.deepEqual(renewal.timestamps, []);
  assert.equal(renewed.witnesses.trusted, 2);
  assert.equal(renewed.complete, true);
  const lt = renewed.long_term;
  assert.deepEqual([lt.post_quantum, lt.checkpoint.tree_size, lt.checkpoint.renewal, lt.renew_before],
                   [true, renewal.tree_size, 1, null]);
  assert.deepEqual(lt.attested_by.map((a) => [a.kind, a.algorithm]), [["witness", "ml-dsa-65"]]);
  assert.match(lt.attested_by[0].time, /^20\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.000Z$/, "a dated cosignature");
  const quantumWitness = lt.attested_by[0].by;
  asNative(renewed, "native-renewed-report.json");
  // Ed25519 distrusted: the Ed25519 witness's cosignatures are set aside,
  // and the ML-DSA-65 witness's dated cosignature of the renewal covers every
  // Ed25519 signature: the entries', the receipts, the checkpoint, and the
  // rotations, which the old root key signed. The renewal's checkpoint is
  // ML-DSA-65's, and needs no cover.
  const distrusted = verifier.verify(read("renewed.cbor"), ltOptions(["ed25519@2099-01-01"]));
  assert.equal(distrusted.verified, true, distrusted.error);
  const d = distrusted.distrust;
  assert.deepEqual(d.algorithms, [{ algorithm: "ed25519", after: "2099-01-01T00:00:00.000Z" }]);
  assert.deepEqual(d.set_aside.map((a) => [a.kind, a.algorithm, a.anchor, a.renewal, a.checkpoint_size]),
                   [["witness", "ed25519", null, null, distrusted.checkpoint.tree_size],
                    ["witness", "ed25519", null, 1, renewal.tree_size]]);
  assert.ok(d.set_aside.every((a) => a.by !== quantumWitness));
  assert.ok(d.signatures.length > 0);
  for (const s of d.signatures) {
    assert.equal(s.algorithm, "ed25519");
    assert.deepEqual([s.covered_by.kind, s.covered_by.by, s.covered_by.renewal, s.covered_by.checkpoint_size],
                     ["witness", quantumWitness, 1, renewal.tree_size], JSON.stringify(s));
  }
  const signedKinds = new Set(d.signatures.map((s) => s.signed));
  for (const kind of ["statement", "receipt", "state-commitment", "checkpoint", "rotation"]) assert.ok(signedKinds.has(kind), kind);
  assert.ok(!signedKinds.has("renewal"));
  assert.equal(distrusted.long_term.post_quantum, true);
  asNative(distrusted, "native-distrusted-report.json");
  // ML-DSA-65 distrusted: its witness is set aside, so no post-quantum
  // attestation is left, and the Ed25519 witness's dated cosignature covers
  // the renewal's checkpoint.
  const noQuantum = verifier.verify(read("renewed.cbor"), ltOptions(["ml-dsa-65@2099-01-01"]));
  assert.equal(noQuantum.verified, true, noQuantum.error);
  assert.equal(noQuantum.long_term.post_quantum, false);
  assert.deepEqual(noQuantum.distrust.set_aside.map((a) => [a.by, a.renewal]), [[quantumWitness, 1]]);
  const covered = noQuantum.distrust.signatures.find((s) => s.signed === "renewal");
  assert.deepEqual([covered.renewal, covered.tree_size, covered.covered_by.kind, covered.covered_by.renewal],
                   [1, renewal.tree_size, "witness", 1]);
  // Distrusted from before the witnesses dated their cosignatures, Ed25519
  // signatures are covered by nothing: the evidence fails (and the page
  // checks it again without the option, to say so). Without the renewal,
  // nothing covers them either: the bundle's own cosignature is undated.
  const tooEarly = verifier.verify(read("renewed.cbor"), ltOptions(["ed25519@2020-01-01"]));
  assert.equal(tooEarly.verified, false);
  assert.doesNotMatch(tooEarly.error, USAGE);
  assert.equal(verifier.verify(read("longterm.cbor"), ltOptions(["ed25519@2099-01-01"])).verified, false);
  // Ed25519 named twice, through classical: refused before anything is checked.
  assert.match(verifier.verify(read("renewed.cbor"), ltOptions(["ed25519@2099-01-01", "classical@2099-01-01"])).error,
               USAGE);
  // Options do not leak: the next check distrusts nothing.
  assert.equal(verifier.verify(read("renewed.cbor"), ltOptions()).distrust, null);

  // A W3C credential (spec/credentials.md): the same report as `kanhe
  // credential verify --offline`, and a changed claim fails.
  const credential = text("credential.jwt");
  const where = verifier.credentialAddresses(credential);
  assert.equal(where.evidence, "https://college.example/c/" + text("credential-token"));
  assert.equal(where.did_document, "https://college.example/.well-known/did.json");
  assert.equal(where.status_list, "https://college.example/status/1");
  assert.equal(where.ledger, ledgerId);
  const credentialOptions = { didDocument: text("credential-did.json"), statusList: text("credential-list.jwt") };
  const checked = verifier.verifyCredential(credential, read("credential-evidence.cbor"), credentialOptions);
  assert.equal(checked.verified, true, JSON.stringify(checked.problems || checked.error));
  assert.equal(typeof checked.text, "string");
  delete checked.text;
  assert.deepEqual(checked, JSON.parse(text("native-credential-report.json")));
  assert.equal(checked.credential.subject.note, "中文 ✓ <script>alert(1)</script>");
  const [h, p, sig] = credential.split(".");
  const payload = JSON.parse(Buffer.from(p, "base64url").toString("utf8"));
  payload.credentialSubject.result = "fail";
  const canonical = (v) => Array.isArray(v) ? "[" + v.map(canonical).join(",") + "]"
    : v && typeof v === "object" ? "{" + Object.keys(v).sort().map((k) => JSON.stringify(k) + ":" + canonical(v[k])).join(",") + "}"
    : JSON.stringify(v);
  const forgedCredential = [h, Buffer.from(canonical(payload)).toString("base64url"), sig].join(".");
  const lie = verifier.verifyCredential(forgedCredential, read("credential-evidence.cbor"), credentialOptions);
  assert.equal(lie.verified, false);
  assert.ok(lie.problems.some((x) => /result = fail/.test(x)), JSON.stringify(lie.problems));
  assert.match(verifier.credentialAddresses("not a credential").error, /JWS/);
  // Bytes, read as `kanhe credential verify` reads its files (spec/credentials.md,
  // section 7): the line ends after a credential are not part of it; nothing else is
  // taken off, nothing replaced, nothing cut at a NUL.
  const evidence = read("credential-evidence.cbor");
  const asRead = verifier.verifyCredential(read("credential.jwt"), evidence,
    { didDocument: read("credential-did.json"), statusList: read("credential-list.jwt") });
  delete asRead.text;
  assert.deepEqual(asRead, JSON.parse(text("native-credential-report.json")));
  assert.equal(verifier.credentialAddresses(credential + "\r\n\n").evidence, where.evidence);
  for (const around of [" " + credential, "\n" + credential, credential + " ", credential + "\t", "\ufeff" + credential]) {
    assert.ok(verifier.credentialAddresses(around).error, JSON.stringify(around.slice(0, 3)));
    assert.ok(verifier.credentialAddresses(new TextEncoder().encode(around)).error);
  }
  const did = read("credential-did.json");
  const withNul = new Uint8Array([...did, 0, 0x78]); // a NUL, then more
  const afterNul = verifier.verifyCredential(credential, evidence, { didDocument: withNul });
  assert.deepEqual(afterNul.did_document.problems, ["the DID document cannot be read (not JSON)"]);
  const notUtf8 = new TextEncoder().encode(text("credential-did.json").slice(0, -1) + ',"x":"?"}');
  notUtf8[notUtf8.length - 3] = 0xff; // the ? becomes a byte no UTF-8 text holds
  const badBytes = verifier.verifyCredential(credential, evidence, { didDocument: notUtf8 });
  assert.deepEqual(badBytes.did_document.problems, ["the DID document cannot be read (not JSON)"]);
  const bom = new Uint8Array([0xef, 0xbb, 0xbf, ...did]);
  assert.deepEqual(verifier.verifyCredential(credential, evidence, { didDocument: bom }).did_document.problems,
    ["the DID document cannot be read (JSON text that begins with a byte order mark)"]);

  // Approvals and guardians (v0.20), when SoftHSM stood in for the approvers'
  // hardware keys: the same report as `kanhe verify --json`, naming who
  // approved each event and how, the guardians in effect, and every setting.
  if (fs.existsSync(path.join(dir, "approvals.cbor"))) {
    const officeLedger = text("office-ledger-id");
    const approved = verifier.verify(read("approvals.cbor"), { ledgerId: officeLedger });
    assert.equal(approved.verified, true, approved.error);
    assert.match(approved.text, /needs 2 of 3 named, within 7 days by the delegation /);
    assert.match(approved.text, /approved by "Lee Ka Yan" \[[^\]]*in person: hardware key\]/);
    assert.match(approved.text, /approved by "Review Agent" \[AI agent; not in person\]/);
    assert.match(approved.text, /the signer among them/);
    assert.match(approved.text, /Guardians {4}2 of 3 must approve/);
    delete approved.text;
    delete approved.kind;
    assert.deepEqual(approved, JSON.parse(text("native-approvals-report.json")));
    const [form, endorsed] = approved.events;
    assert.deepEqual(form.rules.map((r) => [r.source, r.k, r.approvers.length, r.within_ms, r.without_presence, r.signer_counted, r.count]),
                     [["delegation", 2, 3, 604800000, false, false, 2]]);
    assert.deepEqual(form.approvals.map((a) => [a.approver.name, a.presence.method, a.counted_for]).sort(),
                     [["Chan Tai Man", "hardware-key", [0]], ["Lee Ka Yan", "hardware-key", [0]]]);
    assert.deepEqual(endorsed.rules.map((r) => [r.within_ms, r.without_presence, r.signer_counted, r.count]),
                     [[86400000, true, true, 2]]);
    assert.deepEqual(endorsed.approvals.map((a) => [a.approver.name, a.approver.kind, a.presence, a.counted_for]),
                     [["Review Agent", "agent", null, [0]]]);
    const inEffect = approved.guardians.in_effect;
    assert.deepEqual([inEffect.k, inEffect.within_ms, inEffect.guards], [2, 604800000, null]);
    assert.deepEqual(inEffect.guardians.map((a) => a.name).sort(), ["Chan Tai Man", "Ho Wing", "Lee Ka Yan"]);
    assert.deepEqual(approved.guardians.settings.map((s) => s.rules.map((r) => r.source)), [["new_guardians"]]);
    const after = verifier.verify(read("guardians.cbor"), { ledgerId: officeLedger });
    assert.equal(after.verified, true, after.error);
    assert.match(after.text, /Guardians {4}none in effect/);
    assert.match(after.text, /removed them/);
    delete after.text;
    delete after.kind;
    assert.deepEqual(after, JSON.parse(text("native-guardians-report.json")));
    assert.equal(after.guardians.in_effect, null);
    assert.deepEqual(after.guardians.settings.map((s) => [s.removed, s.guards, s.rules.map((r) => r.source)]),
                     [[false, null, ["new_guardians"]], [false, ["record-revoke"], ["guardians", "new_guardians"]],
                      [true, null, ["guardians"]]]);
  }
  console.log("wasm verifier (node): ok, version " + verifier.version);
})().catch((e) => {
  console.error(e);
  process.exit(1);
});
