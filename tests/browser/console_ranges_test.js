// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya
//
// Values proven without showing them (spec v0.22) in the console, in a real
// browser. Alice sets up a console and defines a kind of staff record whose
// birth date and monthly salary (an amount in HKD with 2 decimal places) can
// be proven later. She registers one, checked in this browser before the tap,
// commitments included. From its page she gives the holder a values file,
// after the warning, which kanhe evidence prove uses with the record's proof
// file. A relying party's Verify screen makes a challenge code; Alice proves
// that the person was born on or before 2008-11-21 and earns at least
// HKD 30,000.00, with that code, and the console offers the proof file
// verified. The Verify screen checks it in this browser with the code, and
// refuses another code; kanhe verify agrees. A value outside the bounds is
// refused. The report reads in Chinese too.
// Usage: node console_ranges_test.js KANHE
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
const work = fs.mkdtempSync(path.join(os.tmpdir(), "kanhe-ranges-"));
const ledger = path.join(work, "ledger");
const env = { ...process.env, KANHE_LEDGER: ledger, KANHE_NO_BROWSER: "1", HOME: work };
const run = (...args) => execFileSync(...programOf(args), { cwd: work, env, encoding: "utf8" });

function freePort() {
  return new Promise((resolve) => {
    const server = net.createServer();
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address();
      server.close(() => resolve(port));
    });
  });
}

async function waitRunning() {
  for (let i = 0; i < 300; i++) {
    if (JSON.parse(run("kanhe-console", "status", "--json")).running) return;
    await new Promise((r) => setTimeout(r, 100));
  }
  throw new Error("the console did not start");
}

(async () => {
  const port = await freePort();
  const consoleProcess = spawn(...programOf(["kanhe-console", "run", "--port", String(port), "--quiet"]),
                               { cwd: work, env });
  let browser;
  const violations = [];
  let page;
  try {
    await waitRunning();
    const setup = fs.readFileSync(path.join(ledger, "console", "setup-link"), "utf8").trim();
    browser = await chromium.launch();
    const context = await browser.newContext({ locale: "en-GB", acceptDownloads: true });
    page = await context.newPage();
    page.setDefaultTimeout(60000);
    page.on("console", (m) => {
      if (/Content Security Policy|Refused to/.test(m.text())) violations.push(m.text());
    });
    page.on("pageerror", (e) => violations.push(String(e)));
    const cdp = await context.newCDPSession(page);
    await cdp.send("WebAuthn.enable");
    await cdp.send("WebAuthn.addVirtualAuthenticator", { options: {
      protocol: "ctap2", transport: "internal", hasResidentKey: true, hasUserVerification: true,
      isUserVerified: true, automaticPresenceSimulation: true, hasPrf: true } });

    await page.goto(setup);
    await page.getByLabel("Your name").fill("Alice");
    await page.getByRole("button", { name: "Create my passkey" }).click();
    await page.getByRole("heading", { name: "Your recovery code" }).waitFor();
    await page.getByLabel("I have printed or saved my recovery code").check();
    await page.getByRole("button", { name: "Continue" }).click();
    await page.getByRole("button", { name: "Not now" }).click();
    await page.getByRole("heading", { name: "Home" }).waitFor();
    const ledgerId = JSON.parse(run("status", "--json")).ledger_id;

    // A kind: Staff, with a name, a birth date and a monthly salary that can
    // be proven later without being shown (off by default).
    await page.getByRole("link", { name: "Kinds" }).click();
    await page.getByRole("heading", { name: "Kinds", level: 1 }).waitFor();
    await page.getByLabel("Name", { exact: true }).first().fill("Staff");
    await page.getByLabel("Record type").fill("example.org.staff/1");
    const provable = (n) => page.locator("fieldset.kind-field").nth(n - 1)
      .getByRole("checkbox", { name: "Can be proven later without showing the value", includeHidden: true });
    await page.getByLabel("Name of field 1").fill("name");
    assert.equal(await provable(1).isVisible(), false, "a text is never provable");
    await page.getByRole("button", { name: "Add a field" }).click();
    await page.getByLabel("Name of field 2").fill("born");
    await page.getByLabel("Type of field 2").selectOption("date");
    assert.equal(await provable(2).isChecked(), false, "off by default");
    await provable(2).check();
    await page.getByRole("button", { name: "Add a field" }).click();
    await page.getByLabel("Name of field 3").fill("salary");
    await page.getByLabel("Type of field 3").selectOption("number");
    await provable(3).check();
    await page.getByLabel("Decimal places of field 3").fill("2");
    await page.getByLabel("Currency of field 3").fill("HKD");
    await page.getByLabel("Files", { exact: true }).selectOption("none");
    await page.getByRole("button", { name: "Save the kind" }).click();
    await page.getByRole("heading", { name: "Staff", level: 2 }).waitFor();
    await page.getByText("salary: number, private, can be proven later without showing it " +
                         "(an amount in HKD with 2 decimal places)").waitFor();
    const kinds = JSON.parse(run("kanhe-console", "kind", "list", "--json"));
    assert.deepEqual(kinds[0].fields.map((f) => [f.name, f.provable ?? null]),
                     [["name", null], ["born", "date"], ["salary", "money:HKD:2"]]);

    // A staff record: the page checks the commitments of the values it can
    // prove, computed here from the values typed, before the tap.
    await page.getByRole("link", { name: "Things" }).click();
    await page.getByRole("link", { name: "Register a document" }).click();
    await page.getByRole("heading", { name: "Register a document" }).waitFor();
    await page.getByLabel("name", { exact: true }).fill("Chan Tai Man");
    await page.getByLabel("born", { exact: true }).fill("2001-04-02");
    await page.getByLabel("salary", { exact: true }).fill("32000.50");
    await page.getByText(/Can be proven later without showing it \(an amount in HKD with 2 decimal places\)/).waitFor();
    await page.getByRole("button", { name: "Prepare" }).click();
    await page.getByRole("heading", { name: "Confirm with your passkey" }).waitFor();
    await page.getByText("Checked in this browser").waitFor();
    await page.getByText("born (a date), salary (an amount in HKD with 2 decimal places)").waitFor();
    await page.getByRole("button", { name: "Confirm with your passkey" }).click();
    await page.getByRole("heading", { name: "Done" }).waitFor();
    const record = (await page.locator("main p.id").textContent()).trim();
    assert.match(record, /^[0-9a-f]{64}$/);

    // Its page: the values it can prove, and what may be done with them.
    await page.getByRole("link", { name: "Open it" }).click();
    await page.getByRole("heading", { name: "Values that can be proven without showing them" }).waitFor();
    await page.getByText("Can be proven without showing the value: born (a date), " +
                         "salary (an amount in HKD with 2 decimal places).").waitFor();

    // Its proof file, as the holder keeps it.
    await page.getByRole("button", { name: "Share proof" }).click();
    const sharing = page.waitForEvent("download");
    await page.getByRole("button", { name: "Make the proof" }).click();
    const proof = path.join(work, "proof.cbor");
    await (await sharing).saveAs(proof);

    // Let the holder prove: a values file, only after the warning.
    await page.getByRole("button", { name: "Cancel" }).click();
    await page.getByRole("heading", { name: "Values that can be proven without showing them" }).waitFor();
    await page.getByRole("button", { name: "Let the holder prove..." }).click();
    await page.getByRole("heading", { name: "Let the holder prove" }).waitFor();
    await page.getByText("This file holds the values themselves").waitFor();
    await page.getByRole("button", { name: "Save the values file" }).click();
    await page.getByText("Confirm first that you will give it only to the person these values belong to.").waitFor();
    await page.getByLabel("I will give it only to the person these values belong to").check();
    const handing = page.waitForEvent("download");
    await page.getByRole("button", { name: "Save the values file" }).click();
    const values = path.join(work, "values.kanheopenings");
    await (await handing).saveAs(values);
    await page.getByText(/^Saved openings-[0-9a-f]{12}\.kanheopenings, checked against the document\.$/).waitFor();
    const shown = JSON.parse(run("record", "openings", "show", values, "--values", "--json"));
    assert.equal(shown.record, record);
    assert.deepEqual(shown.openings.map((o) => [o.field, o.x]), [["born", 11414], ["salary", 3200050]]);
    // The holder proves by itself, from the file and the proof file.
    const holder = JSON.parse(run("evidence", "prove", proof, "--field", "born", "--at-most", "2008-11-21",
                                  "--openings", values, "--out", path.join(work, "holder.cbor"), "--json"));
    assert.equal(holder.proved, true);
    assert.equal(holder.text, "born is at most 2008-11-21");

    // A relying party's challenge code, made on its Verify screen.
    await page.getByRole("link", { name: "Verify" }).click();
    await page.getByRole("heading", { name: "Verify a proof" }).waitFor();
    await page.getByRole("button", { name: "Make a new code" }).click();
    const code = await page.getByLabel("Challenge code for range proofs (optional)").inputValue();
    assert.match(code, /^[0-9a-f]{32}$/);

    // Prove a range from the console: at most and at least, with the code.
    await page.evaluate((id) => { location.hash = `#/thing/${id}`; }, record);
    await page.getByRole("button", { name: "Prove a range" }).click();
    await page.getByRole("heading", { name: "Prove a range" }).waitFor();
    await page.getByLabel("What to prove of born").selectOption("at_most");
    await page.getByLabel("Greatest value of born").fill("2008-11-21");
    await page.getByLabel("What to prove of salary").selectOption("at_least");
    await page.getByLabel("Least value of salary").fill("30000");
    await page.getByLabel("Challenge code from whoever asked (optional)").fill(code);
    const proving = page.waitForEvent("download");
    await page.getByRole("button", { name: "Make the proof file" }).click();
    const proved = path.join(work, "proved.cbor");
    await (await proving).saveAs(proved);
    await page.locator("#prove-done").waitFor();
    await page.getByText("born is at most 2008-11-21").waitFor();
    await page.getByText("salary is at least HKD 30,000.00").waitFor();
    assert.equal(await page.getByText(`carries your challenge code ${code}`).count(), 2);
    const report = JSON.parse(run("verify", proved, "--ledger-id", ledgerId, "--range-context", code, "--json"));
    assert.equal(report.verified, true);
    assert.deepEqual(report.range_proofs.map((p) => [p.text, p.status, p.context]),
                     [["born is at most 2008-11-21", "verified", code],
                      ["salary is at least HKD 30,000.00", "verified", code]]);
    assert.deepEqual(Object.keys(report.disclosed_fields ?? {}), [], "nothing disclosed");
    assert.ok(!fs.readFileSync(proved).includes(Buffer.from("2001-04-02")), "the date stays sealed");

    // Outside the bounds, no proof can be made.
    await page.getByLabel("What to prove of born").selectOption("none");
    await page.getByLabel("Least value of salary").fill("40000");
    await page.getByRole("button", { name: "Make the proof file" }).click();
    await page.getByText("The value is not within those bounds, so no proof of it can be made.").waitFor();

    // The relying party's Verify screen checks the proof in this browser,
    // with its code; another code is refused.
    await page.getByRole("link", { name: "Verify" }).click();
    await page.getByRole("heading", { name: "Verify a proof" }).waitFor();
    await page.getByLabel("Expected ledger id (optional)").fill(ledgerId);
    await page.getByLabel("Challenge code for range proofs (optional)").fill(code);
    await page.locator("#verify-proof").setInputFiles(proved);
    await page.getByText("Verified", { exact: true }).waitFor();
    const ranges = page.locator("ul.ranges");
    await ranges.getByText("born is at most 2008-11-21").waitFor();
    await ranges.getByText("salary is at least HKD 30,000.00").waitFor();
    assert.equal(await ranges.locator("li").count(), 2);
    assert.equal(await ranges.locator("li.bad").count(), 0, "both verified, none merely not checked");
    assert.equal(await ranges.getByText(`carries your challenge code ${code}`).count(), 2);
    await page.getByText("That each of these is the document's own value is the issuer's word, " +
                         "signed when it was registered.").waitFor();
    await page.getByLabel("Challenge code for range proofs (optional)").fill("ab".repeat(16));
    await page.getByLabel("Challenge code for range proofs (optional)").dispatchEvent("change");
    await page.getByText("Not verified with your challenge code").waitFor();
    // A proof file with no range proof, checked with a code, proves none.
    await page.locator("#verify-proof").setInputFiles(proof);
    await page.getByText("This file carries no range proof, so it proves no range, and your " +
                         "challenge code was not used.").first().waitFor();

    // In Chinese: the statements in the reader's words.
    await page.getByLabel("Language").selectOption("zh-Hant-HK");
    await page.getByRole("heading", { name: "核實證明" }).waitFor();
    await page.getByLabel("預期的賬本識別碼（可選）").fill(ledgerId);
    await page.getByLabel("範圍證明的挑戰值（可選）").fill(code);
    await page.locator("#verify-proof").setInputFiles(proved);
    await page.getByText("已核實", { exact: true }).first().waitFor();
    await page.locator("ul.ranges").getByText("born 不高於 2008-11-21").waitFor();
    await page.locator("ul.ranges").getByText("salary 不低於 HKD 30,000.00").waitFor();
    await page.getByRole("heading", { name: "無須顯示數值即可證明的值" }).waitFor();
    await page.evaluate((id) => { location.hash = `#/thing/${id}`; }, record);
    await page.getByRole("button", { name: "證明範圍" }).waitFor();
    await page.getByRole("button", { name: "讓持有人自行證明……" }).waitFor();
    await page.getByLabel("語言").selectOption("zh-Hans-CN");
    await page.getByRole("button", { name: "证明范围" }).waitFor();
    await page.getByLabel("语言").selectOption("en");

    assert.deepEqual(violations, [], "no CSP violation or script error");
    console.log("console ranges browser test: passed");
  } catch (error) {
    if (page) console.error(`page ${page.url()}:\n${await page.locator("main").innerText().catch(() => "")}`);
    throw error;
  } finally {
    if (browser) await browser.close();
    try {
      run("kanhe-console", "stop");
    } catch {
      // Not running: nothing to stop.
    }
    consoleProcess.kill();
    fs.rmSync(work, { recursive: true, force: true });
  }
})().catch((e) => {
  console.error(e);
  process.exit(1);
});
