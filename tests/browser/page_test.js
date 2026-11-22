// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya
//
// Drives kanhe-verify.html in a real browser, as a verifier would use it:
// opened from a QR link that names the ledger, the record, and the bundle's
// URL; opened from disk with files chosen by hand; fed a forged attachment;
// and given a contract instance's evidence, a part's, and one whose calls
// made requests and answered them; and in Chinese, as a certificate's QR code
// opens it; and, with SoftHSM, a record approved by several people under an
// organization's guardians, in the three languages; and long-term evidence,
// renewed after its ledger moved to post-quantum keys, with algorithms
// distrusted, in the three languages; and range proofs from the
// specification's test vectors, with a challenge required, in the three
// languages; and from an archive when the issuer's server is gone, which the
// link names after the bundle's own address.
// Usage: node page_test.js PAGE EVIDENCE_DIR KANHE
"use strict";
const assert = require("node:assert/strict");
const fs = require("node:fs");
const http = require("node:http");
const path = require("node:path");
const { execFileSync } = require("node:child_process");
const { chromium } = require("playwright");

const [pagePath, dir, kanhe] = process.argv.slice(2).map((p) => path.resolve(p));
const text = (name) => fs.readFileSync(path.join(dir, name), "utf8").trim();
const ledgerId = text("ledger-id");
const recordId = text("record-id");

function serve() {
  fs.writeFileSync(path.join(dir, "garbage.cbor"), "not evidence at all");
  const files = { "/kanhe-verify.html": pagePath, "/bundle.cbor": path.join(dir, "bundle.cbor"),
                  "/garbage.cbor": path.join(dir, "garbage.cbor"),
                  "/contract.cbor": path.join(dir, "contract.cbor"), "/part.cbor": path.join(dir, "part.cbor"),
                  "/claim.cbor": path.join(dir, "claim.cbor"), "/sourced.cbor": path.join(dir, "sourced.cbor"),
                  "/approvals.cbor": path.join(dir, "approvals.cbor"), "/guardians.cbor": path.join(dir, "guardians.cbor") };
  const server = http.createServer((req, res) => {
    const file = files[req.url];
    if (!file) { res.writeHead(404).end(); return; }
    res.writeHead(200, { "Content-Type": file.endsWith(".html") ? "text/html" : "application/cbor" });
    fs.createReadStream(file).pipe(res);
  });
  return new Promise((resolve) => server.listen(0, "127.0.0.1", () => resolve(server)));
}

const escapeRegExp = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
const permutations = (items) => items.length <= 1 ? [items]
  : items.flatMap((x, i) => permutations(items.filter((_, j) => j !== i)).map((rest) => [x, ...rest]));
// Names joined by `sep`, in any order: a report lists approvers by their ids.
const anyOrder = (items, sep) => "(?:" + permutations(items).map((p) => p.map(escapeRegExp).join(escapeRegExp(sep))).join("|") + ")";
const TIME = "\\d{4}-\\d\\d-\\d\\d \\d\\d:\\d\\d:\\d\\d UTC";

async function verdict(page) {
  await page.waitForFunction(() => !document.getElementById("result").hidden);
  return {
    kind: (await page.getAttribute("#verdict", "class")).replace("verdict ", ""),
    title: await page.textContent("#verdict-title"),
    detail: await page.textContent("#verdict-detail"),
  };
}

(async () => {
  // Pure ASCII, so the page survives email, re-encoding, and servers that
  // send no charset.
  assert.ok(/^[\x00-\x7f]*$/.test(fs.readFileSync(pagePath, "latin1")), "the page must be pure ASCII");
  // Its policy: no <base> to send links elsewhere, no form to post anywhere.
  assert.match(fs.readFileSync(pagePath, "utf8"),
               /<meta http-equiv="Content-Security-Policy" content="[^"]*; base-uri 'none'; form-action 'none'">/);
  const server = await serve();
  const base = "http://127.0.0.1:" + server.address().port;
  const browser = await chromium.launch();
  const problems = [];
  const open = async (url) => {
    const page = await browser.newPage();
    page.on("dialog", (d) => { problems.push("a dialog opened: " + d.message()); d.dismiss(); });
    page.on("console", (m) => { if (m.type() === "error") problems.push("console error: " + m.text()); });
    page.on("pageerror", (e) => problems.push("page error: " + e.message));
    await page.goto(url);
    try {
      await page.waitForFunction(() => window.verifierReady === true);
    } catch (e) {
      const verdict = await page.evaluate(() => document.getElementById("verdict-title").textContent + ": " +
                                                document.getElementById("verdict-detail").textContent);
      throw new Error(`the page did not get ready (${verdict}); problems: ${problems.join(" | ")}`);
    }
    return page;
  };
  try {
    // 1. The link in a QR code from `kanhe qr`: everything is checked, and
    // the result is green.
    const qr = JSON.parse(execFileSync(kanhe, [
      "qr", recordId, "--ledger", path.join(dir, "ledger"), "--json",
      "--bundle-url", base + "/bundle.cbor", "--verifier-url", base + "/kanhe-verify.html"]));
    const link = qr.url;
    let page = await open(link);
    let v = await verdict(page);
    assert.equal(v.kind, "ok", v.title + ": " + v.detail);
    assert.equal(v.title, "Verified");
    const body = await page.textContent("#result");
    assert.match(body, /Cirraya Test Factory/);
    assert.match(body, /AI agent/);
    assert.match(body, /model claude-opus-5-5 2026-09/);
    assert.match(body, /accountable person: Alice Inspector/);
    assert.match(body, /authorized by Alice Inspector ← Cirraya Test Factory/);
    assert.match(body, /Endorsed as inspector/);
    // Untrusted text is shown as text, never run.
    assert.match(body, /中文 ✓ <script>alert\(1\)<\/script>/);
    assert.equal(await page.locator("#fields script").count(), 0);
    assert.equal(await page.locator("#events .approvals").count(), 0);
    assert.doesNotMatch(await page.textContent("#facts"), /Guardian/);
    await page.close();

    // 2. A link naming another record is refused.
    page = await open(link.replace(`r=${recordId}`, "r=" + "ab".repeat(32)));
    v = await verdict(page);
    assert.equal(v.kind, "bad");
    assert.match(v.detail, /different record/);
    await page.close();

    // 3. Opened from disk; files chosen by hand.
    page = await open("file://" + pagePath);
    await page.setInputFiles("#bundle-file", path.join(dir, "bundle.cbor"));
    v = await verdict(page);
    assert.equal(v.kind, "warn", "without a ledger id the issuer is unconfirmed");
    await page.fill("#ledger", ledgerId);
    await page.dispatchEvent("#ledger", "change");
    await page.waitForFunction(() => document.getElementById("verdict-title").textContent === "Verified");
    // The trusted network witnesses count as soon as they change: a key that
    // is not one is refused, and taking it out checks the evidence again.
    await page.fill("#network-witnesses", "not a verifier key");
    await page.dispatchEvent("#network-witnesses", "change");
    await page.waitForFunction(() => /network witness/.test(document.getElementById("verdict-detail").textContent));
    assert.equal((await verdict(page)).kind, "bad");
    await page.fill("#network-witnesses", "");
    await page.dispatchEvent("#network-witnesses", "change");
    await page.waitForFunction(() => document.getElementById("verdict-title").textContent === "Verified");
    await page.setInputFiles("#attachment-files", path.join(dir, "report.pdf"));
    await page.waitForFunction(() => /matches/.test(document.getElementById("attachments").textContent));
    assert.equal((await verdict(page)).kind, "ok");

    // 4. A forged attachment turns the result red.
    const forged = path.join(dir, "forged", "report.pdf");
    fs.mkdirSync(path.dirname(forged), { recursive: true });
    fs.writeFileSync(forged, "forged");
    await page.setInputFiles("#attachment-files", forged);
    await page.waitForFunction(() => /DOES NOT MATCH/.test(document.getElementById("attachments").textContent));
    v = await verdict(page);
    assert.equal(v.kind, "bad");
    assert.match(v.detail, /attachment/);

    // 5. Damaged evidence is refused outright.
    const damaged = fs.readFileSync(path.join(dir, "bundle.cbor"));
    damaged[200] ^= 1;
    await page.setInputFiles("#bundle-file", { name: "damaged.cbor", mimeType: "application/cbor", buffer: damaged });
    await page.waitForFunction(() => document.getElementById("verdict-title").textContent === "Not verified");
    await page.close();

    // 6. A contract instance's evidence: every call, what the contract made
    // of it, and each consent with who gave it. The page's report is the one
    // `kanhe contract verify --json` gives for the same evidence.
    const contractLedger = text("contract-ledger-id");
    const instanceId = text("instance-id");
    page = await open("file://" + pagePath);
    await page.setInputFiles("#bundle-file", path.join(dir, "contract.cbor"));
    v = await verdict(page);
    assert.equal(v.kind, "warn", "without a ledger id the home is unconfirmed: " + v.detail);
    await page.fill("#ledger", contractLedger);
    await page.dispatchEvent("#ledger", "change");
    await page.waitForFunction(() => document.getElementById("verdict-title").textContent === "Verified");
    v = await verdict(page);
    assert.equal(v.kind, "ok", v.title + ": " + v.detail);
    assert.match(v.detail, /Supply agreement.* at "Cirraya Core Enterprise": status effective after 2 calls/);
    const shown = await page.evaluate(() => window.lastReport);
    assert.equal(shown.kind, "contract");
    delete shown.kind;
    delete shown.text;
    assert.deepEqual(shown, JSON.parse(text("native-contract-report.json")));
    const calls = await page.textContent("#result");
    assert.match(calls, /Instance ID/);
    assert.match(calls, new RegExp(instanceId));
    assert.match(calls, /bank: Cirraya Bank \(ledger [0-9a-f]{12}/);
    assert.match(calls, /Created with propose/);
    assert.match(calls, /reference: PO-2026-1012/);
    assert.match(calls, /Called sign/);
    assert.match(calls, /Procurement Manager/);
    assert.match(calls, /signed with their key; presence not proven/);
    assert.match(calls, /authorized by Cirraya Core Enterprise/);
    assert.match(calls, /outcome: status effective; event signed \{"amount": 125000\}/);
    assert.match(calls, /consent of Cirraya Bank \(SHA-256\): given by "Credit Agent" \(a machine: AI agent\), ref\. Credit approval CA-9/);
    assert.match(calls, /model credit-model-7 \u00b7 accountable person: Credit Officer/);
    assert.match(calls, /consent of Cirraya Supplier \(SHA-256\): given by "Cirraya Supplier" \(the organization's own key\)/);
    assert.match(calls, /complete \(proven against the state commitment\)/);
    assert.match(calls, /contract was run again on every call/);
    await page.close();

    // 7. A link to a contract instance's evidence, naming the home and the
    // instance, is green; one naming another instance is refused.
    const contractLink = base + "/kanhe-verify.html#l=" + contractLedger + "&r=" + instanceId +
      "&b=" + encodeURIComponent(base + "/contract.cbor");
    page = await open(contractLink);
    v = await verdict(page);
    assert.equal(v.kind, "ok", v.title + ": " + v.detail);
    await page.close();
    page = await open(contractLink.replace("r=" + instanceId, "r=" + "ab".repeat(32)));
    v = await verdict(page);
    assert.equal(v.kind, "bad");
    assert.match(v.detail, /different instance/);
    await page.close();

    // 8. A tier-3 part's evidence (v0.7): the chain of its ancestors, each
    // with its calls and consents, then its own; the report is the one
    // `kanhe contract verify --json` gives. A link naming the part is green.
    const partId = text("part-id");
    page = await open("file://" + pagePath);
    await page.fill("#ledger", contractLedger);
    await page.dispatchEvent("#ledger", "change");
    await page.setInputFiles("#bundle-file", path.join(dir, "part.cbor"));
    await page.waitForFunction(() => document.getElementById("verdict-title").textContent === "Verified");
    v = await verdict(page);
    assert.equal(v.kind, "ok", v.title + ": " + v.detail);
    assert.match(v.detail, /Receivable.* at "Cirraya Core Enterprise": a part at depth 2, status active after 4 calls \(its ancestors' included\)/);
    const shownPart = await page.evaluate(() => window.lastReport);
    delete shownPart.kind;
    delete shownPart.text;
    assert.deepEqual(shownPart, JSON.parse(text("native-part-report.json")));
    const partText = await page.textContent("#result");
    assert.match(partText, new RegExp("Part ofpart 0 of call #\\d+ on " + text("part-parent-id")));
    assert.match(partText, /Depth2 \(2 ancestors: /);
    assert.match(partText, new RegExp("Ancestor " + text("part-root-id") + ", depth 0"));
    assert.match(partText, new RegExp("Ancestor " + text("part-parent-id") + ", depth 1, part 0 of #\\d+ \\(above\\)"));
    assert.match(partText, /This instance's own calls, after the call that created it/);
    assert.match(partText, new RegExp("part 0 " + partId.slice(0, 12) + ": active \\(holder: Cirraya Bank"));
    assert.match(partText, /consent of Cirraya Bank \(SHA-256\)/);
    assert.match(partText, /run again too, consents and all/);
    // The ancestors' creating calls are shown once: four calls, four items.
    assert.equal(await page.locator("#events li:not(.group):not(.meta)").count(), 4);
    await page.close();
    page = await open(base + "/kanhe-verify.html#l=" + contractLedger + "&r=" + partId + "&b=" +
      encodeURIComponent(base + "/part.cbor"));
    v = await verdict(page);
    assert.equal(v.kind, "ok", v.title + ": " + v.detail);
    await page.close();

    // 9. Requests and answers (v0.8): per call, the requests it made and the
    // answer it gives, with its status and lateness; the open requests, one
    // overdue at the checkpoint. The report is `kanhe contract verify --json`'s.
    page = await open("file://" + pagePath);
    await page.fill("#ledger", text("requests-ledger-id"));
    await page.dispatchEvent("#ledger", "change");
    await page.setInputFiles("#bundle-file", path.join(dir, "requests.cbor"));
    await page.waitForFunction(() => document.getElementById("verdict-title").textContent === "Verified");
    v = await verdict(page);
    assert.equal(v.kind, "ok", v.title + ": " + v.detail);
    assert.match(v.detail, /4 requests made by its calls: 2 answered, 2 open \(1 OVERDUE at the checkpoint\)/);
    const shownRequests = await page.evaluate(() => window.lastReport);
    delete shownRequests.kind;
    delete shownRequests.text;
    assert.deepEqual(shownRequests, JSON.parse(text("native-requests-report.json")));
    const requestsText = await page.textContent("#result");
    assert.match(requestsText, /Requests4 requests made by its calls/);
    assert.match(requestsText, /Open requests/);
    assert.match(requestsText, /asks: notify \(request [0-9a-f]{12}\u2026\), due .* answered by calling result done/);
    assert.match(requestsText, /asks: http\.post .*done/);
    assert.match(requestsText, /asks: notify .*overdue/);
    assert.match(requestsText, /doneanswers request [0-9a-f]{12}\u2026 \(notify, asked by entry #\d+\), on time/);
    assert.match(requestsText, /doneanswers request [0-9a-f]{12}\u2026 \(http\.post, asked by entry #\d+\), LATE by \d+ s after its deadline/);
    assert.match(requestsText, /Desk Clerk/);
    assert.match(requestsText, /Notifier/);
    assert.match(requestsText, /requests and answers are derived from those calls/);
    assert.equal(await page.locator("#facts .chip.overdue").count(), 1);
    await page.close();

    // 10. A certificate's QR code, in Chinese: the outcome first and large,
    // who issued it and when, the rest folded; the language can be changed.
    page = await open(link + "&lang=zh-Hant");
    v = await verdict(page);
    assert.equal(v.kind, "ok", v.title + ": " + v.detail);
    assert.equal(v.title, "\u5df2\u9a57\u8b49");
    assert.match(v.detail, /\u300cCirraya Test Factory\u300d/);
    assert.equal(await page.getAttribute("html", "lang"), "zh-Hant");
    assert.match(await page.textContent("#summary"), /Cirraya Test Factory/);
    assert.match(await page.textContent("#summary"), /\u6709\u6548/);
    assert.equal(await page.getAttribute("#technical", "open"), null, "the details are folded");
    assert.equal(await page.isVisible("#input"), false);
    assert.ok(await page.evaluate(() => document.getElementById("result").compareDocumentPosition(
      document.getElementById("input")) & Node.DOCUMENT_POSITION_FOLLOWING), "the outcome comes first");
    await page.selectOption("#language", "en");
    await page.waitForFunction(() => document.getElementById("verdict-title").textContent === "Verified");
    assert.match(await page.textContent("#events"), /Endorsed as inspector/);
    await page.click("#another");
    assert.equal(await page.isVisible("#drop"), true);
    await page.close();
    // The browser's own language when the link names none.
    page = await browser.newPage({ locale: "zh-CN" });
    await page.goto(link);
    await page.waitForFunction(() => window.verifierReady === true);
    assert.equal((await verdict(page)).title, "\u5df2\u9a8c\u8bc1");
    await page.close();

    // 11. A claim (v0.14): the condition confirmed, in words, outcome first,
    // and none of the payslip's fields.
    const claimLink = base + "/kanhe-verify.html#l=" + ledgerId + "&r=" + text("claim-id") + "&b=" +
      encodeURIComponent(base + "/claim.cbor");
    page = await open(claimLink + "&lang=zh-Hans");
    v = await verdict(page);
    assert.equal(v.kind, "ok", v.title + ": " + v.detail);
    assert.equal(v.title, "\u5df2\u786e\u8ba4");
    assert.match(v.detail, /monthly_salary \u9ad8\u4e8e HKD 30,000\.00\uff0c\u4e14 status \u5c5e\u4e8e "staff"\u3001"contractor" \u5176\u4e2d\u4e4b\u4e00/);
    const claimSummary = await page.textContent("#summary");
    assert.match(claimSummary, /Chan Tai Man/);
    assert.doesNotMatch(await page.textContent("#result"), /32,000\.50/);
    await page.selectOption("#language", "en");
    await page.waitForFunction(() => document.getElementById("verdict-title").textContent === "Confirmed");
    assert.match((await verdict(page)).detail, /confirms: monthly_salary is above HKD 30,000\.00 and status is one of "staff", "contractor"/);
    await page.close();

    // 11b. Sources (v0.18): what the record was made from, where each stood
    // then and now, and the warning for the one revoked since.
    page = await open(base + "/kanhe-verify.html#l=" + ledgerId + "&r=" + text("sourced-id") + "&b=" +
      encodeURIComponent(base + "/sourced.cbor"));
    v = await verdict(page);
    assert.equal(v.kind, "ok", v.title + ": " + v.detail);
    let sourced = await page.textContent("#result");
    assert.match(sourced, /example\.org\.loan-book\/1 on this ledger: live when this record was made; revoked as of/);
    assert.match(sourced, /example\.org\.land-title\/1 on Cirraya Land Registry's ledger: live when this record was made; live as of/);
    assert.match(sourced, /A source was revoked or replaced since this record was made/);
    await page.selectOption("#language", "zh-Hant");
    await page.waitForFunction(() => document.getElementById("verdict-title").textContent !== "Verified");
    sourced = await page.textContent("#result");
    assert.match(sourced, /\u300cCirraya Land Registry\u300d\u5e33\u672c\u4e0a\u985e\u578b\u70ba example\.org\.land-title\/1 \u7684\u8a18\u9304/);
    assert.match(sourced, /\u5176\u5f8c\u6709\u4f9d\u64da\u7684\u8a18\u9304\u88ab\u64a4\u92b7\u6216\u53d6\u4ee3/);
    await page.close();

    // 11c. Approvals and guardians (v0.20), when SoftHSM stood in for the
    // approvers' hardware keys: under each event, who approved it, how, and
    // within what window, the signer among them when it counted; the
    // guardians in effect, what they guard, and the setting with who approved
    // it; in the three languages. After a change and a removal: every
    // setting, each with its approvals, and none in effect.
    if (fs.existsSync(path.join(dir, "approvals.cbor"))) {
      const officeLink = (bundle) => base + "/kanhe-verify.html#l=" + text("office-ledger-id") + "&r=" +
        text("approvals-record-id") + "&b=" + encodeURIComponent(base + "/" + bundle);
      const guardians = ["Chan Tai Man", "Lee Ka Yan", "Ho Wing"];
      const shown = (page) => page.evaluate(() => ({
        events: [...document.querySelectorAll("#events .approvals")].map((n) => n.textContent),
        facts: [...document.querySelectorAll("#facts dd")].map((n) => n.textContent),
        labels: [...document.querySelectorAll("#facts dt")].map((n) => n.textContent) }));
      const has = (lines, pattern) => assert.ok(lines.some((l) => pattern.test(l)), pattern + " in " + JSON.stringify(lines));
      const exactly = (s) => new RegExp("^" + escapeRegExp(s) + "$");
      page = await open(officeLink("approvals.cbor"));
      v = await verdict(page);
      assert.equal(v.kind, "ok", v.title + ": " + v.detail);
      let lines = await shown(page);
      assert.equal(lines.events.length, 2, JSON.stringify(lines.events));
      has(lines.events, new RegExp("^Approved by 2 of 3 within 7 days: " +
        anyOrder(["Chan Tai Man (in person, hardware key)", "Lee Ka Yan (in person, hardware key)"], ", ") + "$"));
      has(lines.events, exactly("Approved by 2 of 3 within 1 day (approvals without presence count): " +
        "Chan Tai Man (the signer, in person, hardware key), Review Agent (AI agent, not in person)"));
      has(lines.facts, new RegExp("^The top key is guarded by 2 of 3 guardians: " + anyOrder(guardians, ", ") +
        ", since " + TIME + "$"));
      has(lines.facts, exactly("Every statement the organization signs needs 2 of them, within 7 days of its issue."));
      has(lines.facts, new RegExp("^" + TIME + " \\(entry #\\d+\\): the organization set 2 of 3 guardians \\(" +
        anyOrder(guardians, ", ") + "\\), within 7 days, for every statement it signs$"));
      has(lines.facts, new RegExp("^Approved by 2 of 3 new guardians within 7 days: " +
        anyOrder(["Chan Tai Man (in person, hardware key)", "Lee Ka Yan (in person, hardware key)"], ", ") + "$"));
      await page.selectOption("#language", "zh-Hant");
      await page.waitForFunction(() => document.getElementById("verdict-title").textContent === "\u5df2\u9a57\u8b49");
      lines = await shown(page);
      has(lines.events, new RegExp("^\u65bc 7 \u65e5\u5167\u7d93 3 \u4eba\u4e2d 2 \u4eba\u6279\u6838\uff1a" +
        anyOrder(["Chan Tai Man\uff08\u89aa\u8eab\uff0c\u786c\u4ef6\u5bc6\u9470\uff09", "Lee Ka Yan\uff08\u89aa\u8eab\uff0c\u786c\u4ef6\u5bc6\u9470\uff09"], "\u3001") + "$"));
      has(lines.events, exactly("\u65bc 1 \u65e5\u5167\u7d93 3 \u4eba\u4e2d 2 \u4eba\u6279\u6838\uff08\u975e\u89aa\u8eab\u7684\u6279\u6838\u4ea6\u8a08\u7b97\u5728\u5167\uff09\uff1a" +
        "Chan Tai Man\uff08\u7c3d\u7f72\u4eba\uff0c\u89aa\u8eab\uff0c\u786c\u4ef6\u5bc6\u9470\uff09\u3001Review Agent\uff08AI \u4ee3\u7406\uff0c\u975e\u89aa\u8eab\uff09"));
      has(lines.facts, new RegExp("^\u6700\u9ad8\u5bc6\u9470\u7531 3 \u4f4d\u5b88\u8b77\u4eba\u4e2d\u4efb 2 \u4f4d\u5171\u540c\u628a\u95dc\uff1a" + anyOrder(guardians, "\u3001") +
        "\uff0c\u81ea " + TIME + " \u8d77$"));
      has(lines.facts, exactly("\u6a5f\u69cb\u7c3d\u7f72\u7684\u6bcf\u9805\u9673\u8ff0\uff0c\u5747\u9808\u65bc\u7c3d\u767c\u5f8c 7 \u65e5\u5167\u7d93\u5176\u4e2d 2 \u4f4d\u6279\u6838\u3002"));
      await page.selectOption("#language", "zh-Hans");
      await page.waitForFunction(() => document.getElementById("verdict-title").textContent === "\u5df2\u9a8c\u8bc1");
      lines = await shown(page);
      has(lines.events, new RegExp("^\u5728 7 \u5929\u5185\u7ecf 3 \u4eba\u4e2d 2 \u4eba\u5ba1\u6279\uff1a" +
        anyOrder(["Chan Tai Man\uff08\u672c\u4eba\uff0c\u786c\u4ef6\u5bc6\u94a5\uff09", "Lee Ka Yan\uff08\u672c\u4eba\uff0c\u786c\u4ef6\u5bc6\u94a5\uff09"], "\u3001") + "$"));
      has(lines.events, exactly("\u5728 1 \u5929\u5185\u7ecf 3 \u4eba\u4e2d 2 \u4eba\u5ba1\u6279\uff08\u975e\u672c\u4eba\u7684\u5ba1\u6279\u4e5f\u8ba1\u7b97\u5728\u5185\uff09\uff1a" +
        "Chan Tai Man\uff08\u7b7e\u7f72\u4eba\uff0c\u672c\u4eba\uff0c\u786c\u4ef6\u5bc6\u94a5\uff09\u3001Review Agent\uff08AI \u4ee3\u7406\uff0c\u975e\u672c\u4eba\uff09"));
      has(lines.facts, new RegExp("^\u6700\u9ad8\u5bc6\u94a5\u7531 3 \u4f4d\u5b88\u62a4\u4eba\u4e2d\u4efb 2 \u4f4d\u5171\u540c\u628a\u5173\uff1a" + anyOrder(guardians, "\u3001") +
        "\uff0c\u81ea " + TIME + " \u8d77$"));
      await page.close();

      page = await open(officeLink("guardians.cbor"));
      v = await verdict(page);
      assert.equal(v.kind, "ok", v.title + ": " + v.detail);
      lines = await shown(page);
      has(lines.facts, exactly("none in effect at the checkpoint"));
      assert.equal(lines.labels.filter((l) => l === "Guardian settings").length, 1);
      const setting = (what) => new RegExp("^" + TIME + " \\(entry #\\d+\\): the organization set 2 of 3 guardians \\(" +
        anyOrder(guardians, ", ") + "\\), within 7 days, for " + escapeRegExp(what) + "$");
      has(lines.facts, setting("every statement it signs"));
      has(lines.facts, setting("its record-revoke statements and those always guarded"));
      has(lines.facts, new RegExp("^" + TIME + " \\(entry #\\d+\\): the organization removed its guardians$"));
      // The change approved by both sets, each approval counting in both;
      // the removal by the guardians in effect.
      const approvedBy = (who, pair) => new RegExp("^Approved by 2 of 3 " + who + " within 7 days: " +
        anyOrder(pair.map((name) => name + " (in person, hardware key)"), ", ") + "$");
      const count = (pattern) => lines.facts.filter((l) => pattern.test(l)).length;
      assert.equal(count(approvedBy("new guardians", ["Chan Tai Man", "Lee Ka Yan"])), 2, JSON.stringify(lines.facts));
      assert.equal(count(approvedBy("guardians", ["Chan Tai Man", "Lee Ka Yan"])), 1, JSON.stringify(lines.facts));
      assert.equal(count(approvedBy("guardians", ["Chan Tai Man", "Ho Wing"])), 1, JSON.stringify(lines.facts));
      await page.selectOption("#language", "zh-Hant");
      await page.waitForFunction(() => document.getElementById("verdict-title").textContent === "\u5df2\u9a57\u8b49");
      lines = await shown(page);
      has(lines.facts, exactly("\u622a\u81f3\u6aa2\u67e5\u9ede\uff0c\u6c92\u6709\u5b88\u8b77\u4eba"));
      has(lines.facts, new RegExp("^" + TIME + "\uff08\u7b2c \\d+ \u9805\uff09\uff1a\u6a5f\u69cb\u64a4\u9664\u5176\u5b88\u8b77\u4eba$"));
      has(lines.facts, /\u9069\u7528\u65bc\u5176 record-revoke \u9673\u8ff0\u53ca\u4e00\u5f8b\u9808\u628a\u95dc\u7684\u9673\u8ff0$/);
      await page.selectOption("#language", "zh-Hans");
      await page.waitForFunction(() => document.getElementById("verdict-title").textContent === "\u5df2\u9a8c\u8bc1");
      lines = await shown(page);
      has(lines.facts, exactly("\u622a\u81f3\u68c0\u67e5\u70b9\uff0c\u6ca1\u6709\u5b88\u62a4\u4eba"));
      has(lines.facts, new RegExp("^" + TIME + "\uff08\u7b2c \\d+ \u9879\uff09\uff1a\u673a\u6784\u79fb\u9664\u5176\u5b88\u62a4\u4eba$"));
      has(lines.facts, /\u9002\u7528\u4e8e\u5176 record-revoke \u9648\u8ff0\u53ca\u4e00\u5f8b\u987b\u628a\u5173\u7684\u9648\u8ff0$/);
      await page.close();
    }

    // 11d. Long-term evidence (v0.21), with both witnesses' keys chosen: a
    // classical ledger's certificate, outcome first with the advice to renew
    // it; the same renewed after the ledger moved to post-quantum keys, and
    // the renewal; with Ed25519 distrusted, every signature by it covered,
    // what was set aside, and what covers what; the short form, a mistake in
    // the option, and a date that nothing covers; in the three languages. The
    // page's reports are `kanhe verify --json`'s.
    {
      const lines = (page) => page.evaluate(() => ({
        summary: [...document.querySelectorAll("#summary dd")].map((n) => n.textContent),
        summaryLabels: [...document.querySelectorAll("#summary dt")].map((n) => n.textContent),
        facts: [...document.querySelectorAll("#facts dd")].map((n) => n.textContent),
        labels: [...document.querySelectorAll("#facts dt")].map((n) => n.textContent),
        limits: document.getElementById("limits").textContent }));
      const holds = (list, pattern) => assert.ok(list.some((l) => pattern.test(l)), pattern + " in " + JSON.stringify(list));
      const exact = (s) => new RegExp("^" + escapeRegExp(s) + "$");
      const asNative = async (page, file) => {
        const shown = await page.evaluate(() => window.lastReport);
        delete shown.kind;
        delete shown.text;
        assert.deepEqual(shown, JSON.parse(text(file)), file);
      };
      const showing = (page, id, pattern) => page.waitForFunction(([id, source]) =>
        new RegExp(source).test(document.getElementById(id).textContent), [id, pattern.source]);
      const distrust = async (page, value) => {
        await page.fill("#distrust", value);
        await page.dispatchEvent("#distrust", "change");
      };
      const DAY = "\\d{1,2} (?:January|February|March|April|May|June|July|August|September|October|November|December) \\d{4}";
      const ZH_DAY = "\\d{4}\u5e74\\d{1,2}\u6708\\d{1,2}\u65e5";
      const ID = "[0-9a-f]{12}\u2026";
      page = await open("file://" + pagePath);
      await page.fill("#ledger", text("longterm-ledger-id"));
      await page.dispatchEvent("#ledger", "change");
      await page.setInputFiles("#witness-files", [path.join(dir, "lt-classical.pub"), path.join(dir, "lt-quantum.pub")]);
      await page.setInputFiles("#bundle-file", path.join(dir, "longterm.cbor"));
      v = await verdict(page);
      assert.equal(v.kind, "ok", v.title + ": " + v.detail);
      let l = await lines(page);
      assert.ok(l.summaryLabels.includes("Long-term proof"), JSON.stringify(l.summaryLabels));
      holds(l.summary, exact("no post-quantum attestation: renew this proof file before 1 January 2030. " +
        "A future quantum computer could forge the signatures it rests on today."));
      holds(l.facts, exact("no post-quantum attestation covers this evidence; renew it before 1 January 2030 " +
        "(NIST IR 8547 deprecates classical signatures after 2030)"));
      assert.ok(!l.labels.includes("Renewals") && !l.labels.includes("Algorithms you distrust"), JSON.stringify(l.labels));
      assert.doesNotMatch(l.limits, /renewals/);
      await asNative(page, "native-longterm-report.json");

      await page.setInputFiles("#bundle-file", path.join(dir, "renewed.cbor"));
      await showing(page, "summary", /post-quantum checkpoint/);
      assert.equal((await verdict(page)).kind, "ok");
      l = await lines(page);
      holds(l.summary, new RegExp("^covered since " + DAY + " by a post-quantum checkpoint, attested by a witness you trust$"));
      assert.equal(l.labels.filter((x) => x === "Renewals").length, 1);
      holds(l.facts, new RegExp("^Renewal 1: log size \\d+, signed " + TIME + " by its ML-DSA-65 log key; " +
        "key changes: 1 of the log key, 1 of the top key$"));
      holds(l.facts, exact("witnesses: 2 trusted, 0 other"));
      holds(l.facts, new RegExp("^post-quantum: the checkpoint of renewal 1 \\(log size \\d+, signed " + TIME +
        "\\), attested by witness " + ID + " \\(ML-DSA-65, dated " + TIME + "\\)$"));
      assert.match(l.limits, /Its renewals show that later checkpoints of the same ledger still hold this history/);
      await asNative(page, "native-renewed-report.json");

      // Distrusted, in the advanced options.
      await page.click("#advanced > summary");
      await distrust(page, "ed25519@2099-01-01");
      await showing(page, "summary", /Algorithms you distrust/);
      assert.equal((await verdict(page)).kind, "ok");
      assert.equal(await page.textContent("#distrust-names"), "Distrusted: Ed25519 from 1 January 2099");
      l = await lines(page);
      holds(l.summary, new RegExp("^Ed25519 from 1 January 2099: the \\d+ signature\\(s\\) by them that this evidence " +
        "relies on all existed before then, as dated attestations show$"));
      holds(l.summary, /^covered since .* attested by a witness you trust$/);
      holds(l.facts, exact("Ed25519 from 1 January 2099"));
      holds(l.facts, new RegExp("^Set aside: witness " + ID + " \\(log size \\d+, this proof file\\), signed with Ed25519: not relied on$"));
      holds(l.facts, new RegExp("^Set aside: witness " + ID + " \\(log size \\d+, renewal 1\\), signed with Ed25519: not relied on$"));
      holds(l.facts, new RegExp("^witness " + ID + " \\(log size \\d+, renewal 1\\), dated " + TIME + ", covers \\d+ Ed25519 " +
        "signature\\(s\\): statement #0, receipt #0, .*state commitment #\\d+, receipt #\\d+, the checkpoint \\(log size \\d+\\)" +
        "(?:, key change #\\d+ \\(renewal 1\\))+$"));
      await asNative(page, "native-distrusted-report.json");
      // The short form adds a line; Ed25519 twice is a mistake, shown before
      // anything is checked.
      await page.selectOption("#distrust-choice", "classical");
      await page.fill("#distrust-date", "2020-01-01");
      await page.click("#distrust-add");
      await showing(page, "verdict-title", /^Check the distrusted algorithms$/);
      assert.equal(await page.inputValue("#distrust"), "ed25519@2099-01-01\nclassical@2020-01-01");
      v = await verdict(page);
      assert.equal(v.kind, "warn");
      assert.equal(v.detail, "\"classical@2020-01-01\" names Ed25519 a second time");
      assert.equal(await page.textContent("#distrust-names"), v.detail);
      // Classical signatures distrusted from before the witnesses dated their
      // cosignatures: nothing covers them, so the evidence fails, though it
      // verifies without the option.
      await distrust(page, "");
      await page.click("#distrust-add");
      await showing(page, "verdict-title", /^Not verified with the algorithms you distrust$/);
      assert.equal(await page.inputValue("#distrust"), "classical@2020-01-01");
      assert.equal(await page.textContent("#distrust-names"),
                   "Distrusted: Ed25519, ECDSA, SM2, RSA, other algorithms from 1 January 2020");
      v = await verdict(page);
      assert.equal(v.kind, "bad");
      assert.match(v.detail, /^Without them this evidence verifies\. But it relies on a signature by an algorithm you distrust that no time-stamp, network witness, or dated witness signature from before your date covers, so it fails: ./);
      await distrust(page, "Ed25519@2035-01-01");
      await showing(page, "verdict-detail", /^"Ed25519@2035-01-01" is not ALG@YYYY-MM-DD/);
      assert.equal((await verdict(page)).detail, "\"Ed25519@2035-01-01\" is not ALG@YYYY-MM-DD with ALG one of ed25519, " +
        "ecdsa, sm2, rsa, ml-dsa-44, ml-dsa-65, ml-dsa-87, or classical (in lower case)");
      await distrust(page, "ed25519@2035-02-30");
      await showing(page, "verdict-detail", /^"ed25519@2035-02-30" names a date that does not exist$/);

      // In Traditional Chinese (Hong Kong).
      await distrust(page, "ed25519@2099-01-01");
      await page.selectOption("#language", "zh-Hant");
      await showing(page, "summary", /\u4f60\u4e0d\u4fe1\u4efb\u7684\u7b97\u6cd5/);
      assert.equal((await verdict(page)).title, "\u5df2\u9a57\u8b49");
      assert.equal(await page.textContent("#distrust-names"), "\u4e0d\u4fe1\u4efb\uff1aEd25519\uff08\u81ea2099\u5e741\u67081\u65e5\u8d77\uff09");
      l = await lines(page);
      holds(l.summary, new RegExp("^\u81ea" + ZH_DAY + "\u8d77\u5df2\u6709\u5f8c\u91cf\u5b50\u6aa2\u67e5\u9ede\u4fdd\u969c\uff0c\u7531\u4f60\u4fe1\u4efb\u7684\u898b\u8b49\u8005\u78ba\u8a8d$"));
      holds(l.summary, new RegExp("^Ed25519\uff08\u81ea2099\u5e741\u67081\u65e5\u8d77\uff09\uff1a\u9019\u4efd\u8b49\u660e\u6240\u4f9d\u8cf4\u3001\u4ee5\u5176\u4f5c\u51fa\u7684 \\d+ \u500b\u7c3d\u7f72\uff0c\u5747\u6709\u8a3b\u660e\u6642\u9593\u7684\u8b49\u660e\u986f\u793a\u5728\u8a72\u65e5\u671f\u524d\u5df2\u5b58\u5728$"));
      holds(l.facts, new RegExp("^\u7b2c 1 \u6b21\u66f4\u65b0\uff1a\u65e5\u8a8c\u5927\u5c0f \\d+\uff0c\u65bc " + TIME + " \u7531\u5176 ML-DSA-65 \u65e5\u8a8c\u5bc6\u9470\u7c3d\u7f72\uff1b\u5bc6\u9470\u8f2a\u63db\uff1a\u65e5\u8a8c\u5bc6\u9470 1 \u6b21\uff0c\u6700\u9ad8\u5bc6\u9470 1 \u6b21$"));
      holds(l.facts, new RegExp("^\u5f8c\u91cf\u5b50\uff1a\u7b2c 1 \u6b21\u66f4\u65b0\u7684\u6aa2\u67e5\u9ede\uff08\u65e5\u8a8c\u5927\u5c0f \\d+\uff0c\u7c3d\u7f72\u65bc " + TIME + "\uff09\uff0c\u7531\u898b\u8b49\u8005 " + ID +
        "\uff08ML-DSA-65\uff0c\u8a3b\u660e\u6642\u9593 " + TIME + "\uff09\u78ba\u8a8d$"));
      holds(l.facts, new RegExp("^\u4e0d\u4e88\u63a1\u4fe1\uff1a\u898b\u8b49\u8005 " + ID + "\uff08\u65e5\u8a8c\u5927\u5c0f \\d+\uff0c\u9019\u4efd\u8b49\u660e\u6a94\u6848\uff09\uff0c\u4ee5 Ed25519 \u7c3d\u7f72$"));
      holds(l.facts, new RegExp("^\u898b\u8b49\u8005 " + ID + "\uff08\u65e5\u8a8c\u5927\u5c0f \\d+\uff0c\u7b2c 1 \u6b21\u66f4\u65b0\uff09\uff08\u8a3b\u660e\u6642\u9593 " + TIME + "\uff09\u6db5\u84cb \\d+ \u500b Ed25519 \u7c3d\u7f72\uff1a" +
        "\u7b2c 0 \u9805\u7684\u9673\u8ff0\u3001\u7b2c 0 \u9805\u7684\u6536\u9304\u8b49\u660e\u3001"));
      await distrust(page, "classical@2020-01-01");
      await showing(page, "verdict-title", /^\u6309\u4f60\u4e0d\u4fe1\u4efb\u7684\u7b97\u6cd5\uff0c\u9a57\u8b49\u4e0d\u901a\u904e$/);
      assert.match((await verdict(page)).detail, /^\u4e0d\u8a08\u9019\u4e9b\u7b97\u6cd5\uff0c\u9019\u4efd\u8b49\u660e\u53ef\u901a\u904e\u9a57\u8b49\u3002/);
      await distrust(page, "Ed25519@2035-01-01");
      await showing(page, "verdict-title", /^\u8acb\u6aa2\u67e5\u4e0d\u4fe1\u4efb\u7684\u7b97\u6cd5$/);
      assert.match((await verdict(page)).detail, /^\u300cEd25519@2035-01-01\u300d\u4e0d\u7b26\u5408 ALG@YYYY-MM-DD \u7684\u683c\u5f0f/);
      await distrust(page, "");
      await page.setInputFiles("#bundle-file", path.join(dir, "longterm.cbor"));
      await showing(page, "summary", /\u5c1a\u672a\u6709\u5f8c\u91cf\u5b50\u4fdd\u969c/);
      holds((await lines(page)).summary,
            exact("\u5c1a\u672a\u6709\u5f8c\u91cf\u5b50\u4fdd\u969c\uff1a\u8acb\u65bc2030\u5e741\u67081\u65e5\u524d\u66f4\u65b0\u9019\u4efd\u8b49\u660e\u6a94\u6848\u3002\u65e5\u5f8c\u7684\u91cf\u5b50\u96fb\u8166\u6216\u53ef\u507d\u9020\u5b83\u73fe\u6642\u6240\u4f9d\u8cf4\u7684\u7c3d\u7f72\u3002"));

      // In Simplified Chinese.
      await page.selectOption("#language", "zh-Hans");
      await showing(page, "summary", /\u5c1a\u672a\u6709\u540e\u91cf\u5b50\u4fdd\u969c/);
      holds((await lines(page)).summary,
            exact("\u5c1a\u672a\u6709\u540e\u91cf\u5b50\u4fdd\u969c\uff1a\u8bf7\u57282030\u5e741\u67081\u65e5\u524d\u66f4\u65b0\u8fd9\u4efd\u8bc1\u660e\u6587\u4ef6\u3002\u65e5\u540e\u7684\u91cf\u5b50\u8ba1\u7b97\u673a\u6216\u53ef\u4f2a\u9020\u5b83\u73b0\u5728\u6240\u4f9d\u8d56\u7684\u7b7e\u540d\u3002"));
      await distrust(page, "ed25519@2099-01-01");
      await page.setInputFiles("#bundle-file", path.join(dir, "renewed.cbor"));
      await showing(page, "summary", /\u4f60\u4e0d\u4fe1\u4efb\u7684\u7b97\u6cd5/);
      assert.equal((await verdict(page)).title, "\u5df2\u9a8c\u8bc1");
      l = await lines(page);
      holds(l.summary, new RegExp("^\u81ea" + ZH_DAY + "\u8d77\u5df2\u6709\u540e\u91cf\u5b50\u68c0\u67e5\u70b9\u4fdd\u969c\uff0c\u7531\u4f60\u4fe1\u4efb\u7684\u89c1\u8bc1\u8005\u786e\u8ba4$"));
      holds(l.summary, new RegExp("^Ed25519\uff08\u81ea2099\u5e741\u67081\u65e5\u8d77\uff09\uff1a\u8fd9\u4efd\u8bc1\u660e\u6240\u4f9d\u8d56\u3001\u4ee5\u5176\u4f5c\u51fa\u7684 \\d+ \u4e2a\u7b7e\u540d\uff0c\u5747\u6709\u6ce8\u660e\u65f6\u95f4\u7684\u8bc1\u660e\u663e\u793a\u5728\u8be5\u65e5\u671f\u524d\u5df2\u5b58\u5728$"));
      holds(l.facts, new RegExp("^\u7b2c 1 \u6b21\u66f4\u65b0\uff1a\u65e5\u5fd7\u5927\u5c0f \\d+\uff0c\u4e8e " + TIME + " \u7531\u5176 ML-DSA-65 \u65e5\u5fd7\u5bc6\u94a5\u7b7e\u540d\uff1b\u5bc6\u94a5\u8f6e\u6362\uff1a\u65e5\u5fd7\u5bc6\u94a5 1 \u6b21\uff0c\u6700\u9ad8\u5bc6\u94a5 1 \u6b21$"));
      holds(l.facts, new RegExp("^\u4e0d\u4e88\u91c7\u4fe1\uff1a\u89c1\u8bc1\u8005 " + ID + "\uff08\u65e5\u5fd7\u5927\u5c0f \\d+\uff0c\u7b2c 1 \u6b21\u66f4\u65b0\uff09\uff0c\u4ee5 Ed25519 \u7b7e\u540d$"));
      await distrust(page, "classical@2020-01-01");
      await showing(page, "verdict-title", /^\u6309\u4f60\u4e0d\u4fe1\u4efb\u7684\u7b97\u6cd5\uff0c\u9a8c\u8bc1\u672a\u901a\u8fc7$/);
      await distrust(page, "ed25519@2035-02-30");
      await showing(page, "verdict-detail", /^\u201ced25519@2035-02-30\u201d\u7684\u65e5\u671f\u5e76\u4e0d\u5b58\u5728$/);
      await page.close();
    }

    // 11e. Range proofs (v0.22), from the specification's test vectors: three
    // proofs of one record, each statement in words with the challenge it
    // carries and verified, and the record's provable values, in the three
    // languages; negative values; a challenge required and met, missed, of
    // another, and mistyped; required of evidence that carries no proof; and
    // a tampered proof.
    {
      const vectors = JSON.parse(fs.readFileSync(path.join(__dirname, "..", "..", "testvectors", "protocol-v0.22.json"), "utf8"));
      const vector = (name) => vectors.bundles.find((b) => b.name === name);
      let loads = 0;
      const choose = async (page, name) => {
        const file = name + "-" + ++loads + ".cbor";
        await page.setInputFiles("#bundle-file", { name: file, mimeType: "application/cbor",
                                                   buffer: Buffer.from(vector(name).evidence, "hex") });
        await page.waitForFunction((f) => document.getElementById("bundle-name").textContent.startsWith(f + " "), file);
      };
      const pin = async (page, name) => {
        await page.fill("#ledger", vector(name).options.ledger_id);
        await page.dispatchEvent("#ledger", "change");
      };
      const challenge = async (page, hex) => {
        await page.fill("#range-context", hex);
        await page.dispatchEvent("#range-context", "change");
      };
      // Each row: the statement, the challenge line or null, and the status.
      const rows = (page) => page.evaluate(() => [...document.querySelectorAll("#ranges tr")].map((tr) => {
        const [statement, status] = tr.children;
        const context = statement.querySelector(".range-context");
        return [statement.firstChild.textContent, context ? context.textContent : null, status.textContent];
      }));
      // The technical lines from the one labelled `label`, `n` of them, then
      // the labels of all but the first (empty, as a list's go).
      const factsFrom = (page, label, n) => page.evaluate(([label, n]) => {
        const dt = [...document.querySelectorAll("#facts dt")];
        const dd = [...document.querySelectorAll("#facts dd")];
        const at = dt.findIndex((x) => x.textContent === label);
        return at < 0 ? null : dd.slice(at, at + n).map((x) => x.textContent).concat(dt.slice(at + 1, at + n).map((x) => x.textContent));
      }, [label, n]);
      const CHALLENGE = "acebe9f17b00eadb695631b515db1e07";
      page = await open("file://" + pagePath);
      await pin(page, "range-proofs-three");
      await choose(page, "range-proofs-three");
      v = await verdict(page);
      assert.equal(v.kind, "ok", v.title + ": " + v.detail);
      assert.equal(await page.isHidden("#ranges-section"), false);
      assert.deepEqual(await rows(page), [
        ["birth_date is at most 2008-11-20", null, "verified"],
        ["monthly_salary is at least HKD 30,000.00", "challenge " + CHALLENGE, "verified"],
        ["score is between 60 and 99.5", null, "verified"]]);
      assert.deepEqual(await factsFrom(page, "Provable values", 3),
        ["birth_date: a date", "monthly_salary: an amount in HKD with 2 decimal places",
         "score: a number with 1 decimal place", "", ""]);
      assert.deepEqual(await factsFrom(page, "Provable values", 4).then((l) => l[3]),
                       "(the issuer's word that each commitment is its field's value)");
      assert.deepEqual(await factsFrom(page, "Proof system", 1),
        ["Longfellow ZK (system 1): zero-knowledge and hash-based, with no trusted setup"]);

      // In Traditional Chinese, as the specification's table words them.
      await page.selectOption("#language", "zh-Hant");
      await page.waitForFunction(() => document.getElementById("verdict-title").textContent === "\u5df2\u9a57\u8b49");
      assert.deepEqual(await rows(page), [
        ["birth_date \u4e0d\u9ad8\u65bc 2008-11-20", null, "\u5df2\u9a57\u8b49"],
        ["monthly_salary \u4e0d\u4f4e\u65bc HKD 30,000.00", "\u6311\u6230\u503c " + CHALLENGE, "\u5df2\u9a57\u8b49"],
        ["score \u4ecb\u4e4e 60 \u81f3 99.5", null, "\u5df2\u9a57\u8b49"]]);
      assert.deepEqual(await factsFrom(page, "\u53ef\u8b49\u660e\u7684\u503c", 3),
        ["birth_date\uff1a\u65e5\u671f", "monthly_salary\uff1aHKD \u91d1\u984d\uff0c2 \u4f4d\u5c0f\u6578", "score\uff1a\u6578\u5b57\uff0c1 \u4f4d\u5c0f\u6578", "", ""]);
      assert.equal(await page.textContent("#ranges-section h3 span"), "\u7bc4\u570d\u8b49\u660e");

      // In Simplified Chinese; then negative values and a date before 1970.
      await page.selectOption("#language", "zh-Hans");
      await page.waitForFunction(() => document.getElementById("verdict-title").textContent === "\u5df2\u9a8c\u8bc1");
      assert.deepEqual(await rows(page), [
        ["birth_date \u4e0d\u9ad8\u4e8e 2008-11-20", null, "\u5df2\u9a8c\u8bc1"],
        ["monthly_salary \u4e0d\u4f4e\u4e8e HKD 30,000.00", "\u6311\u6218\u503c " + CHALLENGE, "\u5df2\u9a8c\u8bc1"],
        ["score \u4ecb\u4e8e 60 \u81f3 99.5", null, "\u5df2\u9a8c\u8bc1"]]);
      assert.deepEqual(await factsFrom(page, "\u53ef\u8bc1\u660e\u7684\u503c", 3),
        ["birth_date\uff1a\u65e5\u671f", "monthly_salary\uff1aHKD \u91d1\u989d\uff0c2 \u4f4d\u5c0f\u6570", "score\uff1a\u6570\u5b57\uff0c1 \u4f4d\u5c0f\u6570", "", ""]);
      await pin(page, "range-proof-negative-values");
      await choose(page, "range-proof-negative-values");
      assert.equal((await verdict(page)).kind, "ok");
      assert.deepEqual(await rows(page), [
        ["founded \u4e0d\u9ad8\u4e8e 1950-01-01", null, "\u5df2\u9a8c\u8bc1"],
        ["temperature \u4ecb\u4e8e -20 \u81f3 -10.0", null, "\u5df2\u9a8c\u8bc1"]]);
      await page.selectOption("#language", "en");
      await page.waitForFunction(() => document.getElementById("verdict-title").textContent === "Verified");
      assert.deepEqual((await rows(page)).map((r) => r[0]),
                       ["founded is at most 1950-01-01", "temperature is between -20 and -10.0"]);
      assert.deepEqual(await factsFrom(page, "Provable values", 2),
                       ["founded: a date", "temperature: a number with 1 decimal place", ""]);

      // A challenge required, in the advanced options: met, then missed by a
      // proof without one, and by a proof with another; both verify without
      // it, so the page says that the challenge alone failed them.
      await page.click("#advanced > summary");
      await pin(page, "range-proof-context-required");
      await challenge(page, CHALLENGE.toUpperCase());
      await choose(page, "range-proof-context-required");
      v = await verdict(page);
      assert.equal(v.kind, "ok", v.title + ": " + v.detail);
      assert.deepEqual(await rows(page),
        [["monthly_salary is at least HKD 30,000.00", "challenge " + CHALLENGE + ": the one you gave", "verified"]]);
      await choose(page, "range-context-missing");
      v = await verdict(page);
      assert.deepEqual([v.kind, v.title], ["bad", "Not verified with your challenge"]);
      assert.match(v.detail, /^Without the challenge this evidence verifies\. But a range proof in it does not carry your challenge, so it may have been made before you asked, or for someone else: ./);
      await page.selectOption("#language", "zh-Hant");
      await page.waitForFunction(() => document.getElementById("verdict-title").textContent === "\u6309\u4f60\u7684\u6311\u6230\u503c\uff0c\u9a57\u8b49\u4e0d\u901a\u904e");
      await page.selectOption("#language", "zh-Hans");
      await page.waitForFunction(() => document.getElementById("verdict-title").textContent === "\u6309\u4f60\u7684\u6311\u6218\u503c\uff0c\u9a8c\u8bc1\u672a\u901a\u8fc7");
      await page.selectOption("#language", "en");
      await challenge(page, "7305214e6e895121ec618e1378863595");
      await choose(page, "range-proof-context-required");
      assert.equal((await verdict(page)).title, "Not verified with your challenge");
      // Mistyped: shown before anything is checked.
      await challenge(page, "abc");
      v = await verdict(page);
      assert.deepEqual([v.kind, v.title, v.detail], ["warn", "Check the challenge",
        "The challenge must be 1 to 64 bytes in hex: an even number of hex digits, 2 to 128."]);
      await page.selectOption("#language", "zh-Hant");
      await page.waitForFunction(() => document.getElementById("verdict-title").textContent === "\u8acb\u6aa2\u67e5\u6311\u6230\u503c");
      await page.selectOption("#language", "en");
      // Required of evidence that carries no proof: it verifies, proves
      // nothing, and the outcome says so.
      await challenge(page, CHALLENGE);
      await choose(page, "range-provable-no-proofs");
      v = await verdict(page);
      assert.equal(v.kind, "ok", v.title + ": " + v.detail);
      assert.equal(await page.isHidden("#ranges-section"), true);
      assert.match(await page.textContent("#summary"),
                   /Range proofsnone: this file holds no range proof, so it proves no range, and your challenge was not used/);
      assert.equal((await factsFrom(page, "Provable values", 3)).length, 5);
      await challenge(page, "");
      await choose(page, "range-provable-no-proofs");
      assert.doesNotMatch(await page.textContent("#summary"), /Range proofs/);
      // One bit of a proof flipped.
      await choose(page, "range-proof-tampered");
      v = await verdict(page);
      assert.deepEqual([v.kind, v.title], ["bad", "Not verified"]);
      await page.close();
    }

    // 11f. Archives (spec section 16): after the bundle's address, a link
    // names the archives that keep the same record, each tried in turn only
    // when the addresses before it could not be fetched. Whichever answered,
    // the ledger and the record are checked as ever, and the page says that
    // an archive answered. The issuer's server here is a port nothing
    // listens on; the archive, another server, which answers one record.
    const archiveHits = [];
    const archive = http.createServer((req, res) => {
      archiveHits.push(req.url);
      const found = req.url === `/a/${ledgerId}/c/kept`;
      res.writeHead(found ? 200 : 404, { "Content-Type": "application/cbor", "Access-Control-Allow-Origin": "*" });
      if (found) fs.createReadStream(path.join(dir, "bundle.cbor")).pipe(res);
      else res.end();
    });
    await new Promise((resolve) => archive.listen(0, "127.0.0.1", resolve));
    const kept = `http://127.0.0.1:${archive.address().port}/a/${ledgerId}`;
    const gone = await new Promise((resolve) => {
      const probe = http.createServer().listen(0, "127.0.0.1", () => {
        const { port } = probe.address();
        probe.close(() => resolve(`http://127.0.0.1:${port}/c/gone`));
      });
    });
    const linked = (record, own, archives) => base + "/kanhe-verify.html#l=" + ledgerId + "&r=" + record + "&b=" +
      encodeURIComponent(own) + archives.map((a) => "&a=" + encodeURIComponent(a)).join("");
    // The issuer's server is gone, the first archive knows nothing of the
    // record (404), the second answers; what is not an http(s) URL is never
    // tried. In the three languages.
    const archived = linked(recordId, gone, ["javascript:alert(1)", kept + "/c/missing", "data:,x", kept + "/c/kept"]);
    try {
      page = await open(archived);
      v = await verdict(page);
      assert.equal(v.kind, "ok", v.title + ": " + v.detail);
      assert.equal(v.title, "Verified");
      assert.match(v.detail, /Cirraya Test Factory/);
      assert.deepEqual(archiveHits, [`/a/${ledgerId}/c/missing`, `/a/${ledgerId}/c/kept`]);
      assert.equal(await page.isVisible("#source"), true);
      assert.equal(await page.textContent("#source"),
                   "The issuer's server did not answer, so this evidence came from the archive at 127.0.0.1.");
      await page.selectOption("#language", "zh-Hant");
      await page.waitForFunction(() => document.getElementById("verdict-title").textContent === "\u5df2\u9a57\u8b49");
      assert.equal(await page.textContent("#source"),
                   "\u7c3d\u767c\u8005\u7684\u4f3a\u670d\u5668\u6c92\u6709\u56de\u61c9\uff0c\u6240\u4ee5\u9019\u4efd\u8b49\u660e\u53d6\u81ea 127.0.0.1 \u7684\u5b58\u6a94\u3002");
      await page.selectOption("#language", "zh-Hans");
      await page.waitForFunction(() => document.getElementById("verdict-title").textContent === "\u5df2\u9a8c\u8bc1");
      assert.equal(await page.textContent("#source"),
                   "\u7b7e\u53d1\u8005\u7684\u670d\u52a1\u5668\u6ca1\u6709\u54cd\u5e94\uff0c\u6240\u4ee5\u8fd9\u4efd\u8bc1\u660e\u53d6\u81ea 127.0.0.1 \u7684\u5b58\u6863\u3002");
      // Another file checked by hand is no archive's.
      await page.click("#another");
      await page.setInputFiles("#bundle-file", path.join(dir, "bundle.cbor"));
      await page.waitForFunction(() => document.getElementById("source").hidden);
      await page.close();

      // The archive's answer is checked as the issuer's would be: a link
      // naming another record refuses it.
      page = await open(linked("ab".repeat(32), gone, [kept + "/c/kept"]));
      v = await verdict(page);
      assert.equal(v.kind, "bad");
      assert.match(v.detail, /different record/);
      await page.close();

      // The issuer's server answered, with something that is not evidence:
      // that is the verdict, and no archive is asked.
      archiveHits.length = 0;
      page = await open(linked(recordId, base + "/garbage.cbor", [kept + "/c/kept"]));
      v = await verdict(page);
      assert.deepEqual([v.kind, v.title], ["bad", "Not verified"]);
      assert.equal(await page.isVisible("#source"), false);
      assert.deepEqual(archiveHits, []);
      await page.close();

      // Nothing answered: the error names each address tried, with what
      // went wrong.
      page = await open(linked(recordId, gone, [kept + "/c/missing"]));
      v = await verdict(page);
      assert.deepEqual([v.kind, v.title], ["warn", "Could not download the evidence"]);
      assert.ok(v.detail.startsWith("None of the link's addresses answered: " + gone + " ("), v.detail);
      assert.ok(v.detail.includes("; " + kept + "/c/missing (HTTP 404)."), v.detail);
      assert.equal(await page.isVisible("#drop"), true);
      await page.selectOption("#language", "zh-Hant");
      await page.waitForFunction(() => document.getElementById("verdict-title").textContent === "\u7121\u6cd5\u4e0b\u8f09\u8b49\u660e");
      assert.ok((await page.textContent("#verdict-detail")).includes("\uff1b" + kept + "/c/missing\uff08HTTP 404\uff09\u3002"));
      await page.close();
      // Only http and https: a bundle's address of another kind is not
      // fetched.
      page = await open(base + "/kanhe-verify.html#l=" + ledgerId + "&b=" + encodeURIComponent("data:,x"));
      v = await verdict(page);
      assert.equal(v.kind, "warn");
      assert.equal(v.detail, "The link points to data:,x (not an http or https address). Download that file yourself and drop it below.");
      await page.close();
    } finally {
      archive.close();
    }

    // 12. A W3C credential chosen as a file (spec/credentials.md): the page
    // fetches its record's evidence, the issuer's DID document, and its status
    // list from the addresses it names (answered here), and checks them all.
    const college = { ["/c/" + text("credential-token")]: ["credential-evidence.cbor", "application/cbor"],
                      "/.well-known/did.json": ["credential-did.json", "application/did+json"],
                      "/status/1": ["credential-list.jwt", "application/vc+jwt"] };
    const answerCollege = async (route) => {
      const found = college[new URL(route.request().url()).pathname];
      if (!found) return route.fulfill({ status: 404 });
      return route.fulfill({ status: 200, contentType: found[1], headers: { "Access-Control-Allow-Origin": "*" },
                             body: fs.readFileSync(path.join(dir, found[0])) });
    };
    page = await open("file://" + pagePath);
    await page.route("https://college.example/**", answerCollege);
    await page.setInputFiles("#bundle-file", path.join(dir, "credential.jwt"));
    v = await verdict(page);
    // Only the site's word for the ledger: amber, with the site, and the
    // ledger's own name for itself marked as not confirmed.
    assert.equal(v.kind, "warn", v.title + ": " + v.detail);
    assert.equal(v.title, "Valid, from college.example");
    assert.match(v.detail, /calls itself "Cirraya Test Factory"; that name is not confirmed/);
    const credentialSummary = await page.textContent("#summary");
    assert.match(credentialSummary, /Issuer's sitecollege\.example/);
    assert.match(credentialSummary, /Inspection certificate/);
    assert.match(credentialSummary, /Credentials, a device of the issuer's/);
    assert.match(credentialSummary, /not revoked, as the ledger says/);
    assert.match(credentialSummary, /names this key and this ledger/);
    assert.equal(await page.locator("#fields script").count(), 0);
    // With the ledger ID the issuer gave: valid, from the issuer by name.
    await page.fill("#ledger", ledgerId);
    await page.dispatchEvent("#ledger", "change");
    await page.waitForFunction(() => document.getElementById("verdict-title").textContent === "Valid credential");
    v = await verdict(page);
    assert.equal(v.kind, "ok", v.title + ": " + v.detail);
    assert.match(v.detail, /from "Cirraya Test Factory"/);
    await page.selectOption("#language", "zh-Hant");
    await page.waitForFunction(() => document.getElementById("verdict-title").textContent === "\u6191\u8b49\u6709\u6548");
    await page.close();
    // A link naming another record refuses the credential.
    page = await open("file://" + pagePath + "#r=" + "0".repeat(64));
    await page.route("https://college.example/**", answerCollege);
    await page.setInputFiles("#bundle-file", path.join(dir, "credential.jwt"));
    v = await verdict(page);
    assert.equal(v.kind, "bad", v.title + ": " + v.detail);
    assert.match(v.detail, /a different record/);
    await page.close();
    // A credential whose evidence cannot be fetched says so.
    page = await open("file://" + pagePath);
    await page.route("https://college.example/**", (route) => route.fulfill({ status: 404 }));
    await page.setInputFiles("#bundle-file", path.join(dir, "credential.jwt"));
    v = await verdict(page);
    assert.equal(v.kind, "warn");
    assert.match(v.detail, /college\.example\/c\//);
    await page.close();
    // (The browser logs the refused fetch; nothing else may be logged.)
    const fetched = problems.filter((p) => !/Failed to load resource/.test(p));
    problems.splice(0, problems.length, ...fetched);

    assert.deepEqual(problems, []);
    console.log("wasm verifier (browser): ok");
  } finally {
    await browser.close();
    server.close();
  }
})().catch((e) => {
  console.error(e);
  process.exit(1);
});
