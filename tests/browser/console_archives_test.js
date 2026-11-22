// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya
//
// The archives that keep a ledger, on the console, in a real browser. Alice
// sets up a console, registers a certificate in person (published at once),
// and adds in Settings an archive that keeps her ledger: a small server
// here, answering the archive's address for it with the ledger's own latest
// checkpoint, as an archive that copied it would. The console checks the
// answer before it lists the archive; an address that is not one for this
// ledger is refused. The certificate's link then names the archive after its
// own address. Settings reads in Traditional and Simplified Chinese; the
// archive is removed again.
// Usage: node console_archives_test.js KANHE
"use strict";
const assert = require("node:assert/strict");
const { spawn, execFileSync } = require("node:child_process");
const fs = require("node:fs");
const http = require("node:http");
const net = require("node:net");
const os = require("node:os");
const path = require("node:path");
const { chromium } = require("playwright");

const kanhe = path.resolve(process.argv[2]);
const programOf = (args) =>
  ["bo", "kanhe-console", "kanhe-index"].includes(args[0])
    ? [path.join(path.dirname(kanhe), args[0]), args.slice(1)]
    : [kanhe, args];
const work = fs.mkdtempSync(path.join(os.tmpdir(), "kanhe-archives-"));

function freePort() {
  return new Promise((resolve) => {
    const server = net.createServer();
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address();
      server.close(() => resolve(port));
    });
  });
}

async function tap(page) {
  await page.getByRole("heading", { name: "Confirm with your passkey" }).waitFor();
  await page.getByText("Checked in this browser").waitFor();
  await page.getByRole("button", { name: "Confirm with your passkey" }).click();
}

(async () => {
  const port = await freePort();
  const ledger = path.join(work, "ledger");
  const env = { ...process.env, KANHE_LEDGER: ledger, KANHE_NO_BROWSER: "1", HOME: work };
  const run = (...args) => execFileSync(...programOf(args), { cwd: work, env, encoding: "utf8" });
  const console_ = spawn(...programOf(["kanhe-console", "run", "--port", String(port), "--quiet"]),
                         { cwd: work, env });
  for (let i = 0; i < 300 && !fs.existsSync(path.join(ledger, "console", "setup-link")); i++) {
    await new Promise((r) => setTimeout(r, 100));
  }
  // The archive: its address for a ledger answers that ledger's latest
  // checkpoint, which it takes from the ledger's own server here.
  const asked = [];
  const archive = http.createServer(async (req, res) => {
    asked.push(req.url);
    const found = /^\/a\/([0-9a-f]{64})\/v1\/checkpoint$/.exec(req.url);
    if (!found) {
      res.writeHead(404).end();
      return;
    }
    const own = await fetch(`http://127.0.0.1:${port}/v1/checkpoint`);
    res.writeHead(own.status, { "Content-Type": "application/cose" });
    res.end(Buffer.from(await own.arrayBuffer()));
  });
  await new Promise((resolve) => archive.listen(0, "127.0.0.1", resolve));
  const archiveServer = `http://127.0.0.1:${archive.address().port}`;

  const browser = await chromium.launch();
  const context = await browser.newContext({ locale: "en-GB" });
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
  try {
    await a.goto(fs.readFileSync(path.join(ledger, "console", "setup-link"), "utf8").trim());
    await a.getByLabel("Your name").fill("Alice");
    await a.getByRole("button", { name: "Create my passkey" }).click();
    await a.getByRole("heading", { name: "Your recovery code" }).waitFor();
    await a.getByLabel("I have printed or saved my recovery code").check();
    await a.getByRole("button", { name: "Continue" }).click();
    await a.getByRole("button", { name: "Not now" }).click();
    await a.getByRole("heading", { name: "Home" }).waitFor();

    // A certificate, registered in person: published at once.
    const sheet = path.join(work, "award.json");
    fs.writeFileSync(sheet, JSON.stringify({
      sheet: 1, kind: "document", type: "example.org.award/1", name: "Award", files: "none",
      fields: [{ name: "name", label: "Name", required: true }], printed: ["name"] }));
    run("kanhe-console", "kind", "add", sheet);
    await a.evaluate(() => { location.hash = "#/new"; });
    await a.getByLabel("Name (required)").fill("Ho Ka Ming");
    await a.getByRole("button", { name: "Prepare" }).click();
    await tap(a);
    await a.getByRole("heading", { name: "Done" }).waitFor();
    const linkOf = async () => {
      await a.getByRole("link", { name: "Certificates" }).click();
      await a.getByRole("heading", { name: "Certificates", level: 1 }).waitFor();
      await a.getByRole("button", { name: "QR code of Ho Ka Ming" }).click();
      await a.getByRole("img", { name: "QR code that opens the certificate of Ho Ka Ming" }).waitFor();
      return a.getByLabel("The link the QR code of Ho Ka Ming holds").inputValue();
    };
    const before = await linkOf();
    const plain = before.match(/^https:\/\/kanhe\.cirraya\.com\/verify\/#l=([0-9a-f]{64})&r=([0-9a-f]{64})&b=([^&]+)$/);
    assert.ok(plain, before);
    const ledgerId = plain[1];
    const token = decodeURIComponent(plain[3]).split("/c/")[1];
    // Its evidence, fetched once, so that the ledger has a checkpoint.
    assert.equal((await fetch(decodeURIComponent(plain[3]).replace("localhost", "127.0.0.1"))).status, 200);

    // Settings: no archive yet, and what adding one does to links.
    await a.getByRole("link", { name: "Settings" }).click();
    await a.getByRole("heading", { name: "Archives that keep this ledger" }).waitFor();
    await a.getByText("No archive keeps this ledger yet.").waitFor();
    await a.getByText("Links printed after you add an archive name it, so those certificates still " +
                      "verify if this ledger's server closes. Links printed before do not.").waitFor();
    // An address that is not this ledger's is refused, and nothing is asked.
    await a.locator("#archive-url").fill(`${archiveServer}/a/${"0".repeat(64)}`);
    await a.getByRole("button", { name: "Add the archive" }).click();
    await a.getByText(/That is not an archive's address for this ledger/).waitFor();
    assert.deepEqual(asked, []);
    // The archive's server: completed with /a/LEDGER, asked, and its answer
    // is this ledger's checkpoint.
    await a.locator("#archive-url").fill(archiveServer);
    await a.getByRole("button", { name: "Add the archive" }).click();
    const kept = `${archiveServer}/a/${ledgerId}`;
    await a.getByText(new RegExp(`The archive at ${kept.replace(/[.]/g, "\\.")} keeps this ledger: its latest copy has \\d+ entries`)).waitFor();
    // (Asked when added, and again as Settings lists it.)
    assert.ok(asked.length >= 1 && asked.every((p) => p === `/a/${ledgerId}/v1/checkpoint`), asked.join(", "));
    await a.getByRole("cell", { name: kept, exact: true }).waitFor();
    await a.getByRole("cell", { name: /^\d+ entries, as of / }).waitFor();
    const listed = JSON.parse(fs.readFileSync(path.join(ledger, "trust", "archives.json"), "utf8"));
    assert.deepEqual(listed.archives.map((x) => x.url), [kept]);
    assert.match(JSON.parse(run("kanhe-console", "settings", "show", "--json")).archives[0].url, new RegExp(`/a/${ledgerId}$`));

    // The certificate's link now names the archive, after its own address.
    const after = await linkOf();
    assert.ok(after.startsWith(before + "&a="), after);
    const named = [...after.slice(before.length).matchAll(/&a=([^&]+)/g)].map((m) => decodeURIComponent(m[1]));
    assert.deepEqual(named, [`${kept}/c/${token}`]);

    // In Traditional and Simplified Chinese.
    await a.getByRole("link", { name: "Settings" }).click();
    await a.getByRole("cell", { name: kept, exact: true }).waitFor();
    await a.locator("#language").selectOption("zh-Hant-HK");
    await a.getByRole("heading", { name: "保存這個賬本的存檔" }).waitFor();
    await a.getByText("新增存檔後列印的連結會列明它", { exact: false }).waitFor();
    await a.getByRole("button", { name: "新增存檔" }).waitFor();
    await a.getByRole("cell", { name: /^\d+ 個項目，截至 / }).waitFor();
    await a.locator("#language").selectOption("zh-Hans-CN");
    await a.getByRole("heading", { name: "保存这个账本的存档" }).waitFor();
    await a.getByText("添加存档后打印的链接会写明它", { exact: false }).waitFor();
    await a.getByRole("button", { name: "移除存档 " + kept }).waitFor();
    await a.locator("#language").selectOption("en");
    await a.getByRole("heading", { name: "Archives that keep this ledger" }).waitFor();

    // Removed: new links no longer name it.
    await a.getByRole("button", { name: "Remove the archive " + kept }).click();
    await a.getByText(`New links no longer name the archive ${kept}. Links printed before still do.`).waitFor();
    await a.getByText("No archive keeps this ledger yet.").waitFor();
    assert.equal(await linkOf(), before);

    assert.deepEqual(violations, [], "no CSP violation or script error");
    console.log("console archives browser test: passed");
  } catch (error) {
    console.error(`the page ${a.url()}:\n${await a.locator("main").innerText().catch(() => "")}`);
    console.error(violations.join("\n"));
    throw error;
  } finally {
    await browser.close();
    archive.close();
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
