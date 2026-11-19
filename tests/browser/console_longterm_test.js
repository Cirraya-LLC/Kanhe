// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya
//
// Evidence for decades (spec v0.21) in the console, in real browsers. Alice
// sets up a console and answers yes to its one question (records that must
// verify in 20 years or more): her ledger begins with post-quantum keys, and
// Settings say so. Bob answers no: his ledger begins with today's keys, Home
// reminds him, and he gives out a document's proof file. In Settings he
// prepares for the long term (two passkey taps, then the console's
// checkpoint), and Home reminds him no more. A public witness whose key is
// ML-DSA-65 cosigns his ledger; the proof file he gave out before is renewed
// on the Things screen, and covered by that witness's long-term signature,
// as kanhe verify agrees. Alice's console refuses Bob's proof file: another
// ledger's.
// Usage: node console_longterm_test.js KANHE
"use strict";
const assert = require("node:assert/strict");
const { spawn, execFileSync } = require("node:child_process");
const fs = require("node:fs");
const net = require("node:net");
const os = require("node:os");
const path = require("node:path");
const { chromium } = require("playwright");

const kanhe = path.resolve(process.argv[2]);
// The programs beside kanhe: a command line's first word may name one.
const programOf = (args) =>
  ["bo", "kanhe-console", "kanhe-index"].includes(args[0])
    ? [path.join(path.dirname(kanhe), args[0]), args.slice(1)]
    : [kanhe, args];
const work = fs.mkdtempSync(path.join(os.tmpdir(), "kanhe-longterm-"));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function freePort() {
  return new Promise((resolve) => {
    const server = net.createServer();
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address();
      server.close(() => resolve(port));
    });
  });
}

const people = [];
let current;

/// One person's console, set up in their browser: `longTerm` answers the
/// first run's question (yes is chosen already).
async function person(browser, name, longTerm) {
  const ledger = path.join(work, name.toLowerCase(), "ledger");
  fs.mkdirSync(path.dirname(ledger), { recursive: true });
  const env = { ...process.env, KANHE_LEDGER: ledger, KANHE_NO_BROWSER: "1",
                HOME: path.dirname(ledger) };
  const run = (...args) => execFileSync(...programOf(args), { cwd: work, env, encoding: "utf8" });
  const port = await freePort();
  const process_ = spawn(...programOf(["kanhe-console", "run", "--port", String(port), "--quiet"]),
                         { cwd: work, env });
  for (let i = 0; i < 300 && !fs.existsSync(path.join(ledger, "console", "setup-link")); i++) {
    await sleep(100);
  }
  const context = await browser.newContext({ locale: "en-GB", acceptDownloads: true });
  const page = await context.newPage();
  const violations = [];
  page.on("console", (m) => {
    if (/Content Security Policy|Refused to/.test(m.text())) violations.push(m.text());
  });
  page.on("pageerror", (e) => violations.push(String(e)));
  const cdp = await context.newCDPSession(page);
  await cdp.send("WebAuthn.enable");
  await cdp.send("WebAuthn.addVirtualAuthenticator", { options: {
    protocol: "ctap2", transport: "internal", hasResidentKey: true, hasUserVerification: true,
    isUserVerified: true, automaticPresenceSimulation: true, hasPrf: true } });
  const p = { name, page, run, process: process_, violations, ledger };
  people.push(p);
  current = p;
  await page.goto(fs.readFileSync(path.join(ledger, "console", "setup-link"), "utf8").trim());
  await page.getByRole("heading", { name: "Set up your console" }).waitFor();
  await page.getByText("Will these records need to verify in 20 years or more? " +
                       "(certificates, diplomas, deeds, contracts)").waitFor();
  assert.equal(await page.getByLabel(/^\s*Yes \(recommended\)/).isChecked(), true,
               "yes is the recommended answer, chosen already");
  if (!longTerm) {
    await page.getByLabel(/^\s*No: today's keys/).check();
  }
  await page.getByLabel("Your name").fill(name);
  await page.getByRole("button", { name: "Create my passkey" }).click();
  await page.getByRole("heading", { name: "Your recovery code" }).waitFor();
  await page.getByLabel("I have printed or saved my recovery code").check();
  await page.getByRole("button", { name: "Continue" }).click();
  await page.getByRole("button", { name: "Not now" }).click();
  await page.getByRole("heading", { name: "Home" }).waitFor();
  p.id = JSON.parse(run("status", "--json")).ledger_id;
  return p;
}

/// A public witness's server, its key ML-DSA-65, on its own ledger.
async function startWitness() {
  const witnessDir = path.join(work, "witness");
  fs.mkdirSync(witnessDir, { recursive: true });
  const witnessEnv = { ...process.env, KANHE_PASSPHRASE: "witness test" };
  const w = (...args) => execFileSync(...programOf(args), { cwd: witnessDir, env: witnessEnv,
                                                        encoding: "utf8" });
  for (const k of ["root", "log"]) w("key", "generate", "--out", `${k}.key`);
  w("key", "generate", "--alg", "ml-dsa-65", "--out", "witness.key");
  w("key", "public", "witness.key", "--out", "witness.pub");
  w("init", "--ledger", "ledger", "--org", "Witness", "--root-key", "root.key",
    "--log-key", "log.key");
  const port = await freePort();
  const process_ = spawn(...programOf(["serve", "--ledger", "ledger", "--listen", `127.0.0.1:${port}`,
                                    "--witness-dir", "state", "--witness-key", "witness.key",
                                    "--witness-public", "--witness-name", "archive-witness",
                                    "--quiet"]),
                         { cwd: witnessDir, env: witnessEnv });
  const url = `http://127.0.0.1:${port}`;
  let info;
  for (let i = 0; i < 300 && !info; i++) {
    info = await fetch(`${url}/v1/witness`).then((r) => r.json()).catch(() => null);
    if (!info) await sleep(100);
  }
  return { process: process_, url, key: info.key, pub: path.join(witnessDir, "witness.pub") };
}

/// Confirms what the page shows, checked in the browser, with the passkey.
async function confirm(page, what) {
  await page.getByRole("heading", { name: "Confirm with your passkey" }).waitFor();
  await page.getByText("Checked in this browser").waitFor();
  if (what) await page.getByText(what, { exact: true }).first().waitFor();
  await page.getByRole("button", { name: "Confirm with your passkey" }).click();
}

/// Settings, at the long-term section.
async function settings(page) {
  await page.getByRole("link", { name: "Settings" }).click();
  await page.getByRole("heading", { name: "Keep records verifiable for decades" }).waitFor();
}

const statusLine = async (page) => (await page.locator("#long-term-status").textContent()).trim();
const reminder = "These records rely on signatures a future quantum computer could forge: " +
                 "prepare for the long term before 2030.";

(async () => {
  const browser = await chromium.launch();
  let witness;
  try {
    // Alice: yes, the recommended answer. Her ledger's own keys are
    // post-quantum from its genesis, and nothing reminds her.
    const alice = await person(browser, "Alice", true);
    const a = alice.page;
    const aliceStatus = JSON.parse(alice.run("status", "--json")).long_term;
    assert.equal(aliceStatus.root_key.algorithm, "ML-DSA-65");
    assert.equal(aliceStatus.log_key.algorithm, "ML-DSA-65");
    assert.equal(aliceStatus.genesis_post_quantum, true);
    assert.equal(await a.getByRole("link", { name: reminder }).count(), 0);
    await settings(a);
    assert.equal(await statusLine(a),
                 "This ledger began with long-term keys: its records stay verifiable for decades.");
    assert.equal(await a.getByRole("button", { name: "Prepare for the long term" }).count(), 0);

    // Bob: no. Today's keys, and Home reminds him.
    const bob = await person(browser, "Bob", false);
    const b = bob.page;
    let bobStatus = JSON.parse(bob.run("status", "--json")).long_term;
    assert.equal(bobStatus.root_key.algorithm, "Ed25519");
    assert.equal(bobStatus.post_quantum, false);
    await b.getByRole("link", { name: reminder }).waitFor();

    // He registers a diploma and gives out its proof file.
    const sheet = path.join(work, "diploma.json");
    fs.writeFileSync(sheet, JSON.stringify({
      sheet: 1, kind: "document", type: "example.org.diploma/1", name: "Diploma", files: "none",
      fields: [{ name: "holder", label: "Holder", required: true }] }));
    bob.run("kanhe-console", "kind", "add", sheet);
    await b.evaluate(() => { location.hash = "#/new"; });
    await b.getByLabel("Holder (required)").fill("Chan Tai Man");
    await b.getByRole("button", { name: "Prepare" }).click();
    await confirm(b, "Chan Tai Man");
    await b.getByRole("heading", { name: "Done" }).waitFor();
    await b.getByRole("link", { name: "Open it" }).click();
    await b.getByRole("heading", { name: "Diploma", level: 1 }).waitFor();
    await b.getByRole("button", { name: "Share proof" }).click();
    await b.getByRole("heading", { name: "Share proof" }).waitFor();
    const proving = b.waitForEvent("download");
    await b.getByRole("button", { name: "Make the proof" }).click();
    const download = await proving;
    const oldProof = path.join(work, download.suggestedFilename());
    await download.saveAs(oldProof);
    assert.match(path.basename(oldProof), /^proof-[0-9a-f]{12}\.cbor$/);

    // Settings: today's keys, and what it takes. Two taps, then the
    // console's checkpoint with the new log key.
    await settings(b);
    assert.equal(await statusLine(b),
                 "This ledger signs with today's keys (top key Ed25519, log key Ed25519), which a " +
                 "quantum computer could forge. Prepare for the long term before 2030.");
    await b.getByText(/^Give the ledger a long-term log key \(now Ed25519\): to do$/).waitFor();
    await b.getByRole("button", { name: "Prepare for the long term" }).click();
    await b.getByText("Step 1 of 2").waitFor();
    await b.getByText(/^ML-DSA-65 \(long-term\) [0-9a-f]{16}\.\.\.$/).waitFor();
    await confirm(b, "Give the ledger a long-term log key");
    await b.getByText("Step 2 of 2").waitFor();
    await confirm(b, "Give the organization a long-term top key");
    await b.getByRole("heading", { name: "Done" }).waitFor();
    await b.getByText("Done: the ledger's keys are long-term keys, and a checkpoint is signed with " +
                      "the new log key.").waitFor();
    bobStatus = JSON.parse(bob.run("status", "--json")).long_term;
    assert.equal(bobStatus.post_quantum, true);
    assert.equal(bobStatus.root_key.algorithm, "ML-DSA-65");
    assert.equal(bobStatus.log_key.algorithm, "ML-DSA-65");
    assert.equal(bobStatus.genesis_post_quantum, false);
    const keys = JSON.parse(bob.run("kanhe-console", "key", "list", "--json")).keys.map((k) => k.name).sort();
    assert.deepEqual(keys, ["log", "log-retired", "machine", "owner", "root", "root-retired", "witness"]);
    // The Done screen's own button draws Settings again (the address has
    // not changed).
    await b.getByRole("button", { name: "Settings" }).click();
    await b.getByRole("heading", { name: "Keep records verifiable for decades" }).waitFor();
    assert.match(await statusLine(b), /^This ledger's keys are long-term keys now\./);
    assert.equal(await b.getByRole("button", { name: "Prepare for the long term" }).count(), 0);
    await b.getByRole("link", { name: "Home" }).click();
    await b.getByRole("heading", { name: "Home" }).waitFor();
    assert.equal(await b.getByRole("link", { name: reminder }).count(), 0, "Home reminds no more");

    // A witness whose key is ML-DSA-65 cosigns his ledger.
    witness = await startWitness();
    await b.getByRole("link", { name: "Parties" }).click();
    await b.getByRole("heading", { name: "Public witnesses" }).waitFor();
    await b.getByLabel("Its address").fill(witness.url);
    await b.getByLabel("Its key").fill(witness.key);
    await b.getByRole("button", { name: "Ask it to witness this ledger" }).click();
    await b.getByText(/^archive-witness cosigned this ledger at \d+ entries/).waitFor();

    // The proof file given out before, renewed on the Things screen.
    await b.getByRole("link", { name: "Things" }).click();
    await b.getByRole("link", { name: "Renew a proof file" }).click();
    await b.getByRole("heading", { name: "Renew a proof file" }).waitFor();
    await b.locator("#renew-file").setInputFiles(oldProof);
    const renewing = b.waitForEvent("download");
    await b.getByRole("button", { name: "Renew it" }).click();
    const renewedDownload = await renewing;
    const renewed = path.join(work, renewedDownload.suggestedFilename());
    await renewedDownload.saveAs(renewed);
    assert.match(path.basename(renewed), /^proof-[0-9a-f]{12}-renewed\.cbor$/);
    await b.getByText(/^Renewed: saved proof-[0-9a-f]{12}-renewed\.cbor, now up to the checkpoint of \d+ entries/)
      .waitFor();
    await b.getByText(/^Stays verifiable for decades: a long-term signature covers it \(a witness, at \d+ entries\)\.$/)
      .waitFor();
    const report = JSON.parse(bob.run("verify", renewed, "--ledger-id", bob.id, "--witness", witness.pub,
                                      "--json"));
    assert.equal(report.verified, true);
    assert.equal(report.long_term.post_quantum, true);
    assert.equal(report.renewals.length, 1);
    assert.ok(report.long_term.attested_by.some((x) => x.kind === "witness" && x.algorithm === "ml-dsa-65"));
    // The Verify screen says the same of the renewed file.
    await b.getByRole("link", { name: "Verify" }).click();
    await b.getByRole("heading", { name: "Verify a proof" }).waitFor();
    await b.locator("#verify-proof").setInputFiles(renewed);
    await b.getByText(/^Verified, but whose ledger\?$/).waitFor();
    await b.getByRole("definition").filter({ hasText: /^(Stays verifiable for decades|No long-term signature covers it yet)/ })
      .waitFor();

    // Alice's console refuses Bob's proof file: another ledger's.
    current = alice;
    await a.evaluate(() => { location.hash = "#/renew"; });
    await a.getByRole("heading", { name: "Renew a proof file" }).waitFor();
    await a.locator("#renew-file").setInputFiles(oldProof);
    await a.getByRole("button", { name: "Renew it" }).click();
    await a.getByText("This proof file comes from another ledger: only that ledger can renew it.")
        .waitFor();

    // In the reader's language.
    current = bob;
    await settings(b);
    // Settings has a second language list (for new browsers): the page's
    // own is #language.
    await b.locator("#language").selectOption("zh-Hant-HK");
    await b.getByRole("heading", { name: "讓記錄在數十年後仍可核實" }).waitFor();
    await b.locator("#language").selectOption("zh-Hans-CN");
    await b.getByRole("heading", { name: "让记录几十年后仍能核验" }).waitFor();
    await b.locator("#language").selectOption("en");

    for (const p of people) {
      assert.deepEqual(p.violations, [], `${p.name}: no CSP violation or script error`);
    }
    console.log("console long-term browser test: passed");
  } catch (error) {
    if (current) {
      console.error(`${current.name}'s page ${current.page.url()}:\n` +
                    `${await current.page.locator("main").innerText().catch(() => "")}`);
    }
    for (const p of people) {
      if (p.violations.length) console.error(`${p.name}: ${p.violations.join("\n")}`);
    }
    throw error;
  } finally {
    await browser.close();
    for (const p of people) {
      try {
        p.run("kanhe-console", "stop");
      } catch {
        // Not running: nothing to stop.
      }
      p.process.kill();
    }
    if (witness) witness.process.kill();
    fs.rmSync(work, { recursive: true, force: true });
  }
})().catch((e) => {
  console.error(e);
  process.exit(1);
});
