// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya
//
// Scripts and sources in the console, in a real browser. Alice sets up a
// console and approves a script of two files with one tap: this browser
// computes their digests and sends only those. She checks files against the
// approval (the same, then one changed), registers a document, then a second
// made from it and from another ledger's record (its proof chosen here,
// checked and kept by the console), made by the script; the second's page
// shows where it came from, and after the first is revoked, warns. Its proof
// says the same on the Verify screen; withdrawing the script shows on its
// page. The command line agrees at each step.
// Usage: node console_scripts_test.js KANHE
"use strict";
const assert = require("node:assert/strict");
const { spawn, execFileSync } = require("node:child_process");
const crypto = require("node:crypto");
const fs = require("node:fs");
const net = require("node:net");
const os = require("node:os");
const path = require("node:path");
const { chromium } = require("playwright");

const kanhe = path.resolve(process.argv[2]);
const programOf = (args) =>
  ["bo", "kanhe-console", "kanhe-index"].includes(args[0])
    ? [path.join(path.dirname(kanhe), args[0]), args.slice(1)]
    : [kanhe, args];
const work = fs.mkdtempSync(path.join(os.tmpdir(), "kanhe-scripts-"));
const idFrom = (text) => text.match(/[0-9a-f]{64}/)[0];
const sha256 = (file) => crypto.createHash("sha256").update(fs.readFileSync(file)).digest("hex");

function freePort() {
  return new Promise((resolve) => {
    const server = net.createServer();
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address();
      server.close(() => resolve(port));
    });
  });
}

async function tap(page, what) {
  await page.getByRole("heading", { name: "Confirm with your passkey" }).waitFor();
  await page.getByText("Checked in this browser").waitFor();
  if (what) await page.getByText(what, { exact: true }).first().waitFor();
  await page.getByRole("button", { name: "Confirm with your passkey" }).click();
  await page.getByRole("heading", { name: "Done" }).waitFor();
}

(async () => {
  const port = await freePort();
  const ledger = path.join(work, "ledger");
  const env = { ...process.env, KANHE_LEDGER: ledger, KANHE_NO_BROWSER: "1", HOME: work,
                KANHE_PASSPHRASE: "scripts test" };
  const run = (...args) => execFileSync(...programOf(args), { cwd: work, env, encoding: "utf8" });

  // Another organization's ledger, with a record and its evidence.
  for (const k of ["other-root", "other-log"]) run("key", "generate", "--out", `${k}.key`);
  const other = path.join(work, "other");
  const otherLedger = idFrom(run("init", "--org", "Other Org", "--root-key", "other-root.key",
                                 "--log-key", "other-log.key", "--ledger", other));
  const otherRecord = idFrom(run("record", "issue", "--ledger", other, "--as", "other-root.key",
                                 "--type", "example.other/1", "--field", "result=pass"));
  run("checkpoint", "create", "--ledger", other, "--log-key", "other-log.key");
  const otherProof = path.join(work, "other.cbor");
  run("export", otherRecord, "--ledger", other, "--log-key", "other-log.key", "--out", otherProof);

  // The script's files, and one changed since.
  fs.mkdirSync(path.join(work, "script"));
  fs.mkdirSync(path.join(work, "changed"));
  const main = path.join(work, "script", "main.py");
  const total = path.join(work, "script", "total.py");
  fs.writeFileSync(main, "import total\nprint(total.of([1, 2, 3]))\n");
  fs.writeFileSync(total, "def of(rows):\n    return sum(rows)\n");
  const changed = path.join(work, "changed", "main.py");
  fs.writeFileSync(changed, "import total\nprint(total.of([1, 2, 4]))\n");

  const console_ = spawn(...programOf(["kanhe-console", "run", "--port", String(port), "--quiet"]),
                         { cwd: work, env });
  for (let i = 0; i < 300 && !fs.existsSync(path.join(ledger, "console", "setup-link")); i++) {
    await new Promise((r) => setTimeout(r, 100));
  }
  const browser = await chromium.launch();
  const context = await browser.newContext({ locale: "en-GB", acceptDownloads: true });
  const a = await context.newPage();
  const violations = [];
  a.on("console", (m) => {
    if (/Content Security Policy|Refused to/.test(m.text())) violations.push(m.text());
  });
  a.on("pageerror", (e) => violations.push(String(e)));
  const cdp = await context.newCDPSession(a);
  await cdp.send("WebAuthn.enable");
  await cdp.send("WebAuthn.addVirtualAuthenticator", { options: {
    protocol: "ctap2", transport: "internal", hasResidentKey: true, hasUserVerification: true,
    isUserVerified: true, automaticPresenceSimulation: true, hasPrf: true } });
  const go = (hash) => a.evaluate((h) => { location.hash = h; }, hash);
  try {
    await a.goto(fs.readFileSync(path.join(ledger, "console", "setup-link"), "utf8").trim());
    await a.getByLabel("Your name").fill("Alice");
    await a.getByRole("button", { name: "Create my passkey" }).click();
    await a.getByRole("heading", { name: "Your recovery code" }).waitFor();
    await a.getByLabel("I have printed or saved my recovery code").check();
    await a.getByRole("button", { name: "Continue" }).click();
    await a.getByRole("button", { name: "Not now" }).click();
    await a.getByRole("heading", { name: "Home" }).waitFor();
    const sheet = path.join(work, "report.json");
    fs.writeFileSync(sheet, JSON.stringify({
      sheet: 1, kind: "document", type: "example.org.report/1", name: "Report", files: "none",
      fields: [{ name: "title", label: "Title", required: true }] }));
    run("kanhe-console", "kind", "add", sheet);

    // A script, approved with one tap: its files fingerprinted here.
    await a.getByRole("link", { name: "Scripts", exact: true }).click();
    await a.getByRole("heading", { name: "Scripts", level: 1 }).waitFor();
    await a.getByLabel("Name", { exact: true }).fill("monthly-report");
    await a.getByLabel("Version", { exact: true }).fill("1.0");
    await a.locator("#script-files").setInputFiles([main, total]);
    await a.getByRole("cell", { name: sha256(main) }).waitFor();
    await a.getByRole("cell", { name: "total.py", exact: true }).waitFor();
    await a.getByRole("checkbox", { name: /Deterministic/ }).check();
    await a.getByLabel("What runs it (optional)").fill("python 3.12");
    await a.getByRole("button", { name: "Prepare" }).click();
    await tap(a, "Approve a script");
    const script = (await a.locator("main p.id").textContent()).trim();
    assert.match(script, /^[0-9a-f]{64}$/);
    const listed = JSON.parse(run("script", "list", "--json"));
    assert.equal(listed.length, 1);
    assert.equal(listed[0].name, "monthly-report");
    assert.equal(listed[0].deterministic, true);
    assert.equal(listed[0].runtime, "python 3.12");
    assert.equal(listed[0].presence, "webauthn");
    assert.deepEqual(listed[0].files.map((f) => [f.path, f.size, f.digest]),
                     [["main.py", fs.statSync(main).size, sha256(main)],
                      ["total.py", fs.statSync(total).size, sha256(total)]]);

    // Its page; files checked against it here: the same, then one changed.
    await a.getByRole("link", { name: "Open the script" }).click();
    await a.getByRole("heading", { name: "monthly-report 1.0", level: 1 }).waitFor();
    await a.getByText("by Alice, in person with a passkey").waitFor();
    await a.locator("#check-files").setInputFiles([main, total]);
    await a.getByText("These files are the script as approved.").waitFor();
    await a.locator("#check-files").setInputFiles([changed, total]);
    await a.getByText("1 of 2 files differ from the approval.").waitFor();
    await a.getByText("main.py: CHANGED").waitFor();
    await a.getByText("total.py: the same").waitFor();

    // A document, then another made from it and from the other ledger's
    // record, by the script.
    await go("#/new");
    await a.getByLabel("Title (required)").fill("October figures");
    await a.getByRole("button", { name: "Prepare" }).click();
    await tap(a);
    const first = (await a.locator("main p.id").textContent()).trim();
    await a.getByRole("link", { name: "Things" }).click();
    await a.getByRole("link", { name: "Register a document" }).click();
    await a.getByRole("heading", { name: "Register a document" }).waitFor();
    await a.getByLabel("Title (required)").fill("Monthly report");
    await a.locator("#register-source").selectOption(first);
    await a.getByRole("button", { name: "Add it" }).click();
    await a.getByText(`Report (${first.slice(0, 12)}...), on this ledger`).waitFor();
    await a.getByText("A record of another ledger").click();
    await a.locator("#register-source-proof").setInputFiles(otherProof);
    await a.getByRole("button", { name: "Add this record" }).click();
    await a.getByText(`example.other/1 (${otherRecord.slice(0, 12)}...) on Other Org's ledger, with its proof`)
      .waitFor();
    await a.locator("#register-script").selectOption({ label: "monthly-report 1.0" });
    await a.getByRole("button", { name: "Prepare" }).click();
    await a.getByRole("heading", { name: "Confirm with your passkey" }).waitFor();
    await a.getByText("Made by the script").waitFor();
    await a.getByText("monthly-report 1.0", { exact: true }).waitFor();
    await a.getByText(`record ${otherRecord.slice(0, 12)}... on the ledger ${otherLedger.slice(0, 12)}`).waitFor();
    await tap(a);
    const derived = (await a.locator("main p.id").textContent()).trim();
    const sources = JSON.parse(run("record", "source", "list", derived, "--json")).sources;
    assert.deepEqual(sources.map((s) => [s.record, s.local]), [[first, true], [otherRecord, false]]);
    assert.equal(sources[0].status, "live");
    assert.equal(sources[1].proof_kept, true, "the other ledger's proof is kept with the record");
    assert.equal(JSON.parse(run("record", "show", derived, "--json")).script.name, "monthly-report");

    // Its page: where it came from.
    await a.getByRole("link", { name: "Open it" }).click();
    await a.getByRole("heading", { name: "Where it came from" }).waitFor();
    await a.getByRole("link", { name: "monthly-report 1.0" }).waitFor();
    await a.getByText(/approved in person by Alice, .*; still approved/).waitFor();
    await a.getByText("on this ledger: live when this record was made; now live").waitFor();
    await a.getByText(/example\.other\/1 on Other Org's ledger: live when this record was made; live as of/).waitFor();

    // The first revoked: the second warns, and stays as it is.
    await go(`#/thing/${first}`);
    await a.getByRole("button", { name: "Act on this example.org.report/1 record" }).click();
    await a.getByLabel("Revoke it").check();
    await a.getByLabel("Reason").fill("figures restated");
    await a.getByRole("button", { name: "Prepare" }).click();
    await tap(a);
    await go(`#/thing/${derived}`);
    await a.getByText("A source was revoked or replaced since this record was made.", { exact: false }).waitFor();
    await a.getByText(/on this ledger: live when this record was made; now revoked on/).waitFor();
    assert.equal(JSON.parse(run("record", "source", "list", derived, "--json")).sources[0].status, "revoked");

    // Its proof, checked on the Verify screen, says where it came from.
    await a.getByRole("button", { name: "Share proof" }).click();
    const proving = a.waitForEvent("download");
    await a.getByRole("button", { name: "Make the proof" }).click();
    const proof = path.join(work, "derived.cbor");
    await (await proving).saveAs(proof);
    await a.getByRole("link", { name: "Verify" }).click();
    await a.locator("#verify-proof").setInputFiles(proof);
    await a.getByRole("heading", { name: "Where it came from" }).waitFor();
    await a.getByText(/the script monthly-report 1\.0 \(2 files\), approved in person by Alice/).waitFor();
    await a.getByText(/example\.other\/1 on Other Org's ledger: live when this record was made/).waitFor();
    const ledgerId = JSON.parse(run("status", "--json")).ledger_id;
    const report = JSON.parse(run("verify", proof, "--ledger-id", ledgerId, "--json"));
    assert.equal(report.scripts[0].name, "monthly-report");
    assert.equal(report.sources.find((s) => !s.local).provided, true);

    // Withdrawn with a tap: records can no longer name it.
    await go(`#/script/${script}`);
    await a.getByRole("heading", { name: "monthly-report 1.0", level: 1 }).waitFor();
    await a.getByLabel("Reason").fill("replaced by 1.1");
    await a.getByRole("button", { name: "Withdraw the script" }).click();
    await tap(a, "Withdraw a script");
    await a.getByText("monthly-report 1.0 is withdrawn.").waitFor();
    assert.equal(JSON.parse(run("script", "list", "--json")).length, 0);
    assert.equal(JSON.parse(run("script", "list", "--all", "--json"))[0].status, "withdrawn");
    await go(`#/thing/${derived}`);
    await a.getByText(/WITHDRAWN on/).waitFor();
    await go("#/scripts");
    await a.getByRole("cell", { name: /^withdrawn on/ }).waitFor();

    // In the reader's language.
    await a.getByLabel("Language").selectOption("zh-Hant-HK");
    await a.getByRole("heading", { name: "腳本", level: 1 }).waitFor();
    await a.getByLabel("語言").selectOption("zh-Hans-CN");
    await a.getByRole("heading", { name: "脚本", level: 1 }).waitFor();
    await a.getByLabel("语言").selectOption("en");

    assert.deepEqual(violations, [], "no CSP violation or script error");
    console.log("console scripts browser test: passed");
  } catch (error) {
    console.error(`the page ${a.url()}:\n${await a.locator("main").innerText().catch(() => "")}`);
    console.error(violations.join("\n"));
    throw error;
  } finally {
    await browser.close();
    try {
      run("kanhe-console", "stop");
    } catch {
      // Not running: nothing to stop.
    }
    console_.kill();
    fs.rmSync(work, { recursive: true, force: true });
  }
})().catch((e) => {
  console.error(e);
  process.exit(1);
});
