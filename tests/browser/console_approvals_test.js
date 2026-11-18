// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya
//
// Approvals and guardians in the console, in real browsers, one for each
// person. Alice sets up a console and approves Chan, Lee, and Wong as
// people; what Wong signs needs 2 of Chan and Lee, within 7 days. Wong
// registers a purchase order: the page says before his tap who must
// approve it, and it is sent for approval instead of registered. Chan sees
// it waiting on Home, checks it in his browser (its id recomputed from its
// bytes, its fields against what it commits to), and approves it with his
// passkey; Lee approves it too, and it is registered with both approvals.
// Then Alice sets 2 of Alice, Chan, and Lee as the organization's
// guardians: the new guardians approve, and the setting takes effect. The
// command line agrees at each step.
// Usage: node console_approvals_test.js KANHE
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
const work = fs.mkdtempSync(path.join(os.tmpdir(), "kanhe-approvals-"));

function freePort() {
  return new Promise((resolve) => {
    const server = net.createServer();
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address();
      server.close(() => resolve(port));
    });
  });
}

/// A browser context with a passkey of its own, and what goes wrong in it.
async function personIn(browser, name) {
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
  return { name, page, violations };
}

/// Confirms what the page shows, checked in the browser, with the passkey.
async function confirm(page, what, button = "Confirm with your passkey") {
  await page.getByRole("heading", { name: "Confirm with your passkey" }).waitFor();
  await page.getByText("Checked in this browser").waitFor();
  if (what) await page.getByText(what, { exact: true }).first().waitFor();
  await page.getByRole("button", { name: button }).click();
}

/// Approves the first statement waiting for this person's approval, from
/// Home: checked in the browser, then the passkey's tap.
async function approveWaiting(page, what) {
  await page.getByRole("link", { name: "Home" }).click();
  await page.getByRole("link", { name: "1 waiting for your approval" }).click();
  await page.getByRole("heading", { name: "Approvals", level: 1 }).waitFor();
  await page.getByRole("link", { name: what }).first().click();
  await page.getByRole("heading", { name: "Approve someone else's statement" }).waitFor();
  await page.getByText("Checked in this browser: these are the statement's own bytes").waitFor();
  await page.getByRole("button", { name: "Approve with your passkey" }).click();
  await page.getByRole("heading", { name: "Approved" }).waitFor();
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
  const browser = await chromium.launch();
  const people = [];
  let current;
  try {
    const alice = await personIn(browser, "Alice");
    people.push(alice);
    current = alice;
    const a = alice.page;
    await a.goto(fs.readFileSync(path.join(ledger, "console", "setup-link"), "utf8").trim());
    await a.getByLabel("Your name").fill("Alice");
    await a.getByRole("button", { name: "Create my passkey" }).click();
    await a.getByRole("heading", { name: "Your recovery code" }).waitFor();
    await a.getByLabel("I have printed or saved my recovery code").check();
    await a.getByRole("button", { name: "Continue" }).click();
    await a.getByRole("button", { name: "Not now" }).click();
    await a.getByRole("heading", { name: "Home" }).waitFor();
    const sheet = path.join(work, "po.json");
    fs.writeFileSync(sheet, JSON.stringify({
      sheet: 1, kind: "document", type: "example.org.po/1", name: "Purchase order", files: "none",
      fields: [{ name: "item", label: "Item", required: true }] }));
    run("kanhe-console", "kind", "add", sheet);

    // Chan, Lee, and Wong register passkeys in their own browsers; Alice
    // approves each. What Wong signs needs 2 of Chan and Lee.
    const others = {};
    await a.getByRole("link", { name: "People" }).click();
    await a.getByRole("heading", { name: "People", level: 1 }).waitFor();
    for (const name of ["Chan Tai Man", "Lee Ka Yan", "Wong Siu Ming"]) {
      current = alice;
      await a.getByLabel("Name", { exact: true }).fill(name);
      await a.getByRole("button", { name: "Make an invitation link" }).click();
      const link = await a.getByLabel(`The invitation for ${name}:`).inputValue();
      const person = await personIn(browser, name);
      people.push(person);
      others[name] = person.page;
      current = person;
      await person.page.goto(link);
      await person.page.getByLabel("Your name").fill(name);
      await person.page.getByRole("button", { name: "Register a passkey" }).click();
      await person.page.getByRole("heading", { name: "Home" }).waitFor();
      current = alice;
      await a.reload();
      await a.getByRole("button", { name: `Approve ${name}` }).click();
      await a.getByRole("heading", { name: `Approve ${name}` }).waitFor();
      if (name === "Wong Siu Ming") {
        await a.getByLabel("Others must approve what they sign").check();
        await a.getByLabel("How many must approve").fill("2");
        await a.getByLabel("Chan Tai Man", { exact: true }).check();
        await a.getByLabel("Lee Ka Yan", { exact: true }).check();
      }
      await a.getByRole("button", { name: "Approve (3 taps)" }).click();
      for (const [i, what] of [[1, "Register a person"], [2, "Register their passkeys"],
                               [3, "Grant what they may do"]]) {
        await a.getByText(`Step ${i} of 3`).waitFor();
        await confirm(a, what);
      }
      await a.getByRole("heading", { name: "Done" }).waitFor();
      // The address is still #/people: the link would not draw the screen
      // again, the button does.
      await a.getByRole("button", { name: "People" }).click();
      await a.getByRole("heading", { name: "People", level: 1 }).waitFor();
    }
    // The People screen says who approves for whom.
    // Approvers are listed as the rule keeps them, by their ids.
    const both = "(Chan Tai Man, Lee Ka Yan|Lee Ka Yan, Chan Tai Man)";
    await a.getByRole("cell", { name: new RegExp(`needs approval: 2 of ${both}, within 7 days`) }).waitFor();
    await a.getByRole("cell", { name: "Wong Siu Ming (2 of 2)" }).first().waitFor();

    // Wong registers a purchase order: before the tap, the page says who
    // must approve it; it is sent for approval, not registered.
    const w = others["Wong Siu Ming"];
    current = people.find((p) => p.page === w);
    await w.evaluate(() => { location.hash = "#/new"; });
    await w.getByLabel("Item (required)").fill("Ten chairs");
    await w.getByRole("button", { name: "Prepare" }).click();
    await w.getByText(new RegExp(`^Others must approve this before it is registered: 2 of ${both}, within 7 days\\.$`))
      .waitFor();
    await w.getByLabel("A note for them (optional)").fill("For the new meeting room");
    await confirm(w, "Register a document", "Confirm and send for approval");
    await w.getByRole("heading", { name: "Sent for approval" }).waitFor();
    const records = () => {
      const listed = JSON.parse(run("record", "list", "--json"));
      return (Array.isArray(listed) ? listed : listed.records)
        .filter((r) => (r.record_type ?? r.type) === "example.org.po/1");
    };
    assert.equal(records().length, 0, "held, not registered");
    await w.getByRole("button", { name: "Approvals" }).click();
    await w.getByRole("heading", { name: "Sent for approval", level: 2 }).waitFor();
    await w.getByText("2 more").first().waitFor();

    // Chan approves it, checked in his browser: its fields came with it.
    const c = others["Chan Tai Man"];
    current = people.find((p) => p.page === c);
    await c.reload();
    await approveWaiting(c, "Register a document");
    await c.getByText("Your approval is kept. It needs more before it is registered.").waitFor();
    assert.equal(records().length, 0, "one approval of two");

    // Lee looks first: the item as Wong typed it, and Wong's note.
    const l = others["Lee Ka Yan"];
    current = people.find((p) => p.page === l);
    await l.reload();
    await l.getByRole("link", { name: "1 waiting for your approval" }).click();
    await l.getByRole("link", { name: "Register a document" }).first().click();
    await l.getByText("Ten chairs", { exact: true }).waitFor();
    await l.getByText("For the new meeting room").first().waitFor();
    await l.getByText(/Chan Tai Man, in person with a passkey/).first().waitFor();
    await l.getByRole("button", { name: "Approve with your passkey" }).click();
    await l.getByRole("heading", { name: "Approved" }).waitFor();
    await l.getByText(/Your approval completed it: registered on the ledger as entry \d+\./).waitFor();
    assert.equal(records().length, 1, "registered with both approvals");

    // Wong sees what became of it.
    current = people.find((p) => p.page === w);
    await w.evaluate(() => { location.hash = "#/approvals"; });
    await w.reload();
    await w.getByText(/approved and registered on the ledger as entry \d+/).first().waitFor();

    // Alice sets guardians: 2 of Alice, Chan, and Lee, guarding everything
    // the organization signs. The warnings come first.
    current = alice;
    await a.getByRole("link", { name: "Settings" }).click();
    await a.getByRole("heading", { name: "Guardians of the top key" }).waitFor();
    await a.getByText("No guardians: the top key signs alone.").waitFor();
    await a.getByText(/If fewer of them than must approve can ever approve again/).waitFor();
    for (const name of ["Alice", "Chan Tai Man", "Lee Ka Yan"]) {
      await a.getByLabel(new RegExp(`^\\s*${name} \\(`)).check();
    }
    await a.getByRole("button", { name: "Prepare" }).click();
    await confirm(a, "Set the organization's guardians", "Confirm and send for approval");
    await a.getByRole("heading", { name: "Sent for approval" }).waitFor();
    for (const page of [c, l]) {
      current = people.find((p) => p.page === page);
      await page.reload();
      await approveWaiting(page, "Set the organization's guardians");
    }
    current = alice;
    await a.getByRole("link", { name: "Settings" }).click();
    await a.reload();
    await a.getByText(/^The top key is guarded by 2 of 3 guardians: /).waitFor();
    const shown = JSON.parse(run("ledger", "guardians", "show", "--json"));
    assert.equal(shown.in_effect.k, 2);
    assert.equal(shown.in_effect.of, 3);

    // In the reader's language.
    current = alice;
    await a.evaluate(() => { location.hash = "#/approvals"; });
    await a.getByRole("heading", { name: "Approvals", level: 1 }).waitFor();
    await a.getByLabel("Language").selectOption("zh-Hant-HK");
    await a.getByRole("heading", { name: "批核", level: 1 }).waitFor();
    await a.getByLabel("語言").selectOption("zh-Hans-CN");
    await a.getByRole("heading", { name: "审批", level: 1 }).waitFor();
    await a.getByLabel("语言").selectOption("en");

    for (const p of people) {
      assert.deepEqual(p.violations, [], `${p.name}: no CSP violation or script error`);
    }
    console.log("console approvals browser test: passed");
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
