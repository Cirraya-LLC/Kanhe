// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Cirraya

// The console's page. Everything the ledger or a person wrote is shown with
// textContent, never as markup. The session is a bearer token in
// sessionStorage (no cookies); the page talks only to its own console.

const LANGUAGES = ["en", "zh-Hant-HK", "zh-Hans-CN"];
const SESSION = "kanhe.session";
const LANGUAGE = "kanhe.language";

const state = { language: "en", text: {}, english: {}, who: null, firstRun: false,
                defaultLanguage: null, flash: null };

// --- Text ----------------------------------------------------------------

function t(key, values = {}) {
    const template = state.text[key] ?? state.english[key] ?? key;
    return template.replace(/\{(\w+)\}/g, (_, name) => String(values[name] ?? ""));
}

function stored(storage, key) {
    try {
        return storage.getItem(key);
    } catch {
        return null;
    }
}

function store(storage, key, value) {
    try {
        if (value === null) {
            storage.removeItem(key);
        } else {
            storage.setItem(key, value);
        }
    } catch {
        // Private browsing: the page still works, it only forgets.
    }
}

function preferredLanguage() {
    const saved = stored(localStorage, LANGUAGE);
    if (LANGUAGES.includes(saved)) {
        return saved;
    }
    // The console's own choice (Settings), then the browser's.
    if (LANGUAGES.includes(state.defaultLanguage)) {
        return state.defaultLanguage;
    }
    for (const tag of navigator.languages ?? []) {
        const lower = tag.toLowerCase();
        if (/^zh-(hant|hk|tw|mo)/.test(lower)) {
            return "zh-Hant-HK";
        }
        if (lower.startsWith("zh")) {
            return "zh-Hans-CN";
        }
        if (lower.startsWith("en")) {
            return "en";
        }
    }
    return "en";
}

async function catalog(language) {
    const response = await fetch(`i18n/${language}.json`, { credentials: "omit" });
    if (!response.ok) {
        throw new Error(`no catalog for ${language}`);
    }
    return response.json();
}

async function setLanguage(language, remember = true) {
    state.text = language === "en" ? state.english : await catalog(language);
    state.language = language;
    document.documentElement.lang = language;
    if (remember) {
        store(localStorage, LANGUAGE, language);
    }
    document.getElementById("language").value = language;
    for (const element of document.querySelectorAll("[data-text]")) {
        element.textContent = t(element.dataset.text);
    }
    for (const element of document.querySelectorAll("[data-label]")) {
        element.setAttribute("aria-label", t(element.dataset.label));
    }
    document.title = t("app.name");
}

// --- Elements --------------------------------------------------------------

/// An element with attributes and children (strings become text nodes).
function el(tag, attributes = {}, ...children) {
    const element = document.createElement(tag);
    for (const [name, value] of Object.entries(attributes)) {
        if (name === "text") {
            element.textContent = value;
        } else if (value !== undefined && value !== null && value !== false) {
            element.setAttribute(name, value === true ? "" : String(value));
        }
    }
    for (const child of children.flat()) {
        if (child !== null && child !== undefined) {
            element.append(typeof child === "string" ? document.createTextNode(child) : child);
        }
    }
    return element;
}

function show(...children) {
    const main = document.getElementById("main");
    main.replaceChildren(...children.filter((c) => c !== null));
    // A new screen starts at the top, the bar (a phone's menu button) in
    // view; the focus moves to it all the same, for screen readers.
    main.focus({ preventScroll: true });
    window.scrollTo(0, 0);
}

function status(text) {
    document.getElementById("status").textContent = text;
}

function problem(message) {
    return el("div", { class: "error", role: "alert" },
              el("strong", { text: t("error.title") }), el("p", { text: message }));
}

// --- The console's API ---------------------------------------------------------

class ApiError extends Error {
    /// `answer`: the console's whole answer (its problems, a dry run).
    constructor(status, message, answer = {}) {
        super(message);
        this.status = status;
        this.answer = answer;
    }
}

async function api(method, path, body) {
    const headers = {};
    const token = stored(sessionStorage, SESSION);
    if (token) {
        headers.Authorization = `Bearer ${token}`;
    }
    if (body !== undefined) {
        headers["Content-Type"] = "application/json";
    }
    const response = await fetch(`api/${path}`, {
        method,
        headers,
        body: body === undefined ? undefined : JSON.stringify(body),
        credentials: "omit",
        cache: "no-store",
    });
    const answer = await response.json().catch(() => ({}));
    if (!response.ok) {
        throw new ApiError(response.status, answer?.error?.message ?? String(response.status), answer);
    }
    return answer;
}

// --- Passkeys ------------------------------------------------------------------

function fromBase64url(text) {
    const base64 = text.replace(/-/g, "+").replace(/_/g, "/");
    const binary = atob(base64 + "=".repeat((4 - (base64.length % 4)) % 4));
    return Uint8Array.from(binary, (c) => c.charCodeAt(0)).buffer;
}

function toBase64url(buffer) {
    let binary = "";
    for (const byte of new Uint8Array(buffer)) {
        binary += String.fromCharCode(byte);
    }
    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function passkeysAvailable() {
    return typeof window.PublicKeyCredential === "function" && !!navigator.credentials;
}

/// What went wrong with a passkey, in the reader's words.
function passkeyProblem(error) {
    if (error instanceof ApiError) {
        return error.status === 400 && /address/.test(error.message)
            ? t("error.address")
            : t("error.server", { message: error.message });
    }
    if (error?.name === "NotAllowedError" || error?.name === "AbortError") {
        return t("error.cancelled");
    }
    return t("error.server", { message: String(error?.message ?? error) });
}

/// Makes a passkey with the console's registration options; what the
/// console needs back from it.
async function createPasskey(options, device) {
    // The PRF salt, where the console sends one, so that the new passkey
    // unlocks the console's keys from its first use.
    const extensions = { ...options.extensions };
    const salt = extensions.prf?.eval?.first;
    if (salt) {
        extensions.prf = { eval: { first: fromBase64url(salt) } };
    }
    const credential = await navigator.credentials.create({
        publicKey: {
            challenge: fromBase64url(options.challenge),
            rp: options.rp,
            user: {
                id: fromBase64url(options.user.id),
                name: options.user.name,
                displayName: options.user.displayName,
            },
            pubKeyCredParams: options.pubKeyCredParams,
            authenticatorSelection: options.authenticatorSelection,
            attestation: options.attestation,
            extensions,
            excludeCredentials: options.excludeCredentials.map((c) => ({
                type: c.type,
                id: fromBase64url(c.id),
            })),
            timeout: options.timeout,
        },
    });
    const prf = credential.getClientExtensionResults?.().prf?.results?.first;
    return {
        attestation_object: toBase64url(credential.response.attestationObject),
        client_data_json: toBase64url(credential.response.clientDataJSON),
        label: device,
        prf: prf ? toBase64url(prf) : undefined,
    };
}

/// `longTerm`, at the first run only: whether the ledger's records must
/// verify for decades (its keys then post-quantum).
async function register(code, name, device, longTerm) {
    const begun = await api("POST", "enroll/begin", { code, name });
    const made = await createPasskey(begun.public_key, device);
    return api("POST", "enroll/finish", { ceremony: begun.ceremony, ...made, long_term: longTerm });
}

/// A lost passkey: the recovery code opens the console, a new passkey is
/// made here, and the console makes it the owner's only one.
/// Who must approve a recovery while guardians guard it, in words.
const guardiansMust = (needs) => t("recover.guardians_must", {
    rules: (needs?.rules ?? []).filter((r) => r.missing > 0).map(ruleText).join(t("approvals.rule_separator")),
});

async function recover(code, name, device, notice) {
    const begun = await api("POST", "recover/begin", { recovery_code: code, name });
    // While guardians guard it, they must approve it: said before the new
    // passkey is made.
    if (begun.approvals?.needed && notice) {
        notice.replaceChildren(el("p", { class: "notice", role: "status", text: guardiansMust(begun.approvals) }));
    }
    const made = await createPasskey(begun.public_key, device);
    return api("POST", "recover/finish", { ceremony: begun.ceremony, ...made });
}

async function signIn() {
    const begun = await api("POST", "sign-in/begin", {});
    const options = begun.public_key;
    const publicKey = {
        challenge: fromBase64url(options.challenge),
        rpId: options.rpId,
        userVerification: options.userVerification,
        timeout: options.timeout,
    };
    // With sealed keys, the passkey's PRF output unlocks them (where the
    // passkey has one); the console sends the salt.
    const salt = options.extensions?.prf?.eval?.first;
    if (salt) {
        publicKey.extensions = { prf: { eval: { first: fromBase64url(salt) } } };
    }
    const credential = await navigator.credentials.get({ publicKey });
    const prf = credential.getClientExtensionResults?.().prf?.results?.first;
    return api("POST", "sign-in/finish", {
        ceremony: begun.ceremony,
        credential_id: toBase64url(credential.rawId),
        authenticator_data: toBase64url(credential.response.authenticatorData),
        client_data_json: toBase64url(credential.response.clientDataJSON),
        signature: toBase64url(credential.response.signature),
        prf: prf ? toBase64url(prf) : undefined,
    });
}

// --- Screens -------------------------------------------------------------------

function signedIn(answer, next = home) {
    store(sessionStorage, SESSION, answer.session);
    state.who = { user: answer.user, role: answer.role, keys: answer.keys ?? "none",
                  // A new passkey that could not unlock the console yet.
                  needsSlot: answer.key_slot === false && answer.keys === "unlocked" &&
                             (answer.role === "owner" || answer.role === "admin") };
    next();
}

/// A new passkey that gave no PRF output when it was made unlocks the
/// console only after one sign-in with it: offered on Home.
function slotNotice() {
    if (!state.who?.needsSlot || state.who.keys !== "unlocked") {
        return null;
    }
    const button = el("button", { type: "button", text: t("slot.button") });
    const answer = el("div");
    button.addEventListener("click", async () => {
        button.disabled = true;
        try {
            signedIn(await signIn(), route);
        } catch (error) {
            answer.replaceChildren(problem(passkeyProblem(error)));
            button.disabled = false;
        }
    });
    return el("section", { class: "notice" }, el("p", { text: t("slot.intro") }), answer, button);
}

/// While the console's keys are locked, it signs nothing: say so, and let
/// an owner or an admin unlock it with a passphrase or the recovery code.
function keysNotice() {
    if (state.who?.keys !== "locked") {
        return null;
    }
    const box = el("section", { class: "notice", "aria-labelledby": "keys-locked" },
                   el("p", { id: "keys-locked", text: t("keys.locked") }));
    if (state.who.role === "owner" || state.who.role === "admin") {
        const [secretField, secret] = field("unlock-secret", t("keys.secret"), t("keys.secret_hint"),
                                            { type: "password", autocomplete: "current-password" });
        const button = el("button", { type: "submit", text: t("keys.unlock") });
        const answer = el("div");
        const form = el("form", { novalidate: true }, secretField, answer, button);
        form.addEventListener("submit", async (event) => {
            event.preventDefault();
            button.disabled = true;
            try {
                const result = await api("POST", "unlock", { secret: secret.value });
                state.who.keys = result.keys;
                route();
            } catch (error) {
                answer.replaceChildren(problem(error.status === 403 ? t("keys.wrong")
                                                                    : passkeyProblem(error)));
            } finally {
                button.disabled = false;
            }
        });
        box.append(form);
    }
    return box;
}

/// To Home: through the hash when it changes, else at once.
function home() {
    if (location.hash !== "#/") {
        location.hash = "#/";
    } else {
        route();
    }
}

function signInScreen(message) {
    const button = el("button", { type: "button", class: "primary", text: t("sign_in.button") });
    const notice = el("div");
    if (message) {
        notice.append(problem(message));
    }
    button.addEventListener("click", async () => {
        if (!passkeysAvailable()) {
            notice.replaceChildren(problem(t("error.no_passkeys")));
            return;
        }
        button.disabled = true;
        status(t("status.working"));
        try {
            signedIn(await signIn());
        } catch (error) {
            notice.replaceChildren(problem(passkeyProblem(error)));
        } finally {
            button.disabled = false;
            status("");
        }
    });
    show(el("h1", { text: t("sign_in.title") }), el("p", { text: t("sign_in.intro") }), notice,
         button, el("p", {}, el("a", { href: "#/recover", text: t("recover.link") })),
         el("p", {}, el("a", { href: "#/verify", text: t("verify.link") })));
}

function field(id, label, hint, attributes = {}) {
    const input = el("input", { id, "aria-describedby": `${id}-hint`, ...attributes });
    return [el("div", { class: "field" }, el("label", { for: id, text: label }), input,
               el("span", { id: `${id}-hint`, class: "hint", text: hint })), input];
}

function enrollScreen(code) {
    const [nameField, name] = field("enroll-name", t("enroll.name"), t("enroll.name_hint"),
                                    { autocomplete: "name", maxlength: 64 });
    const [deviceField, device] = field("enroll-device", t("enroll.device"),
                                        t("enroll.device_hint"), { maxlength: 64 });
    const firstRun = state.firstRun;
    const button = el("button", { type: "submit", class: "primary",
                                  text: t(firstRun ? "setup.button" : "enroll.button") });
    const notice = el("div");
    // The first run's one question: records that must verify for decades
    // get post-quantum keys (recommended, so chosen already).
    const longYes = el("input", { type: "radio", name: "setup-long-term", id: "setup-long-term-yes",
                                  checked: true });
    const longNo = el("input", { type: "radio", name: "setup-long-term", id: "setup-long-term-no" });
    const question = firstRun
        ? el("fieldset", { "aria-describedby": "setup-long-term-hint" },
             el("legend", { text: t("setup.long_term") }),
             el("div", {}, el("label", { for: "setup-long-term-yes" }, longYes, " ", t("setup.long_term_yes"))),
             el("div", {}, el("label", { for: "setup-long-term-no" }, longNo, " ", t("setup.long_term_no"))),
             el("p", { id: "setup-long-term-hint", class: "hint", text: t("setup.long_term_hint") }))
        : null;
    const form = el("form", { novalidate: true }, nameField, deviceField, question, notice, button);
    form.addEventListener("submit", async (event) => {
        event.preventDefault();
        if (!passkeysAvailable()) {
            notice.replaceChildren(problem(t("error.no_passkeys")));
            return;
        }
        button.disabled = true;
        status(t("status.working"));
        try {
            const answer = await register(code, name.value.trim(), device.value.trim(),
                                          firstRun ? longYes.checked : undefined);
            state.pendingCode = null;
            if (answer.first_run) {
                // The ledger is made: the recovery sheet next, shown once.
                state.firstRun = false;
                signedIn(answer, () => sheetScreen(answer));
            } else {
                signedIn(answer);
            }
        } catch (error) {
            notice.replaceChildren(problem(passkeyProblem(error)));
        } finally {
            button.disabled = false;
            status("");
        }
    });
    if (firstRun) {
        show(el("p", { class: "step", text: t("setup.step", { step: 1 }) }),
             el("h1", { text: t("setup.title") }), el("p", { text: t("setup.intro") }), form);
    } else {
        show(el("h1", { text: t("enroll.title") }), el("p", { text: t("enroll.intro") }), form);
    }
}

/// The recovery sheet: the code, shown this once, to print or save before
/// going on.
function sheetScreen(answer) {
    const made = new Date().toISOString().slice(0, 10);
    const consoleAddress = `${location.origin}${location.pathname}`;
    const facts = el("dl", { class: "facts" },
                     el("dt", { text: t("sheet.organization") }), el("dd", { text: answer.user }),
                     el("dt", { text: t("sheet.ledger") }),
                     el("dd", { class: "id", text: answer.ledger }),
                     el("dt", { text: t("sheet.console") }), el("dd", { text: consoleAddress }),
                     el("dt", { text: t("sheet.date") }), el("dd", { text: made }));
    const code = el("p", { class: "code", id: "recovery-code", text: answer.recovery_code });
    const print = el("button", { type: "button", text: t("sheet.print") });
    print.addEventListener("click", () => window.print());
    const save = el("button", { type: "button", text: t("sheet.save") });
    save.addEventListener("click", () => {
        const lines = [t("sheet.title"), "", `${t("sheet.organization")}: ${answer.user}`,
                       `${t("sheet.ledger")}: ${answer.ledger}`,
                       `${t("sheet.console")}: ${consoleAddress}`, `${t("sheet.date")}: ${made}`,
                       "", `${t("sheet.code")}: ${answer.recovery_code}`, "", t("sheet.intro"), ""];
        const url = URL.createObjectURL(new Blob([lines.join("\n")],
                                                 { type: "text/plain;charset=utf-8" }));
        const link = el("a", { href: url, download: "kanhe-recovery-code.txt" });
        document.body.append(link);
        link.click();
        link.remove();
        setTimeout(() => URL.revokeObjectURL(url), 1000);
    });
    const kept = el("input", { type: "checkbox", id: "sheet-kept" });
    const notice = el("div");
    const next = el("button", { type: "submit", class: "primary", text: t("sheet.continue") });
    const form = el("form", { novalidate: true, class: "no-print" },
                    el("label", { class: "check" }, kept, " ", t("sheet.saved")), notice, next);
    // The code is never shown again: leaving the page asks first.
    const leaving = (event) => {
        event.preventDefault();
        event.returnValue = "";
    };
    window.addEventListener("beforeunload", leaving);
    form.addEventListener("submit", (event) => {
        event.preventDefault();
        if (!kept.checked) {
            notice.replaceChildren(problem(t("sheet.needed")));
            return;
        }
        window.removeEventListener("beforeunload", leaving);
        backupScreen();
    });
    show(el("p", { class: "step no-print", text: t("setup.step", { step: 2 }) }),
         el("section", { class: "sheet", "aria-labelledby": "sheet-title" },
            el("h1", { id: "sheet-title", text: t("sheet.title") }),
            el("p", { text: t("sheet.intro") }), facts,
            el("p", { class: "label", text: t("sheet.code") }), code,
            el("p", { class: "hint", text: t("sheet.once") })),
         el("p", { class: "no-print" }, print, " ", save), form);
}

/// Where backups go: a folder the person chooses, or later in Settings.
async function backupScreen() {
    const settings = await api("GET", "settings");
    const [folderField, folder] = field("backup-folder", t("backup.folder"),
                                        t("backup.folder_hint"),
                                        { value: settings.backup_folder ??
                                                 settings.suggested_backup_folder });
    const notice = el("div");
    const use = el("button", { type: "submit", class: "primary", text: t("backup.use") });
    const later = el("button", { type: "button", text: t("backup.later") });
    later.addEventListener("click", () => home());
    const form = el("form", { novalidate: true }, folderField, notice, use, " ", later);
    form.addEventListener("submit", async (event) => {
        event.preventDefault();
        use.disabled = true;
        try {
            await api("POST", "settings", { backup_folder: folder.value.trim() });
            home();
        } catch (error) {
            notice.replaceChildren(problem(t("error.server", { message: error.message })));
        } finally {
            use.disabled = false;
        }
    });
    show(el("p", { class: "step", text: t("setup.step", { step: 3 }) }),
         el("h1", { text: t("backup.title") }), el("p", { text: t("backup.intro") }), form);
}

/// The recovery code and a new passkey, for an owner who lost theirs.
function recoverScreen() {
    const [codeField, code] = field("recover-code", t("recover.code"), t("recover.code_hint"),
                                    { autocomplete: "off", spellcheck: "false",
                                      autocapitalize: "characters" });
    const [nameField, name] = field("recover-name", t("recover.name"), t("recover.name_hint"),
                                    { autocomplete: "name", maxlength: 64 });
    const [deviceField, device] = field("recover-device", t("enroll.device"),
                                        t("enroll.device_hint"), { maxlength: 64 });
    const button = el("button", { type: "submit", class: "primary", text: t("recover.button") });
    const notice = el("div");
    const form = el("form", { novalidate: true }, codeField, nameField, deviceField, notice,
                    button);
    form.addEventListener("submit", async (event) => {
        event.preventDefault();
        if (!passkeysAvailable()) {
            notice.replaceChildren(problem(t("error.no_passkeys")));
            return;
        }
        button.disabled = true;
        status(t("status.working"));
        try {
            const answer = await recover(code.value.trim(), name.value.trim(),
                                         device.value.trim(), notice);
            code.value = "";
            if (answer.held) {
                // Sent for the guardians' approval: the new passkey works
                // once they have approved it.
                show(el("h1", { text: t("recover.held_title") }),
                     el("p", { role: "status", text: guardiansMust(answer.approvals) }),
                     el("p", { text: t("recover.held_then", { time: timeText(answer.lapses_at) }) }),
                     el("p", { class: "id", text: answer.id }));
                return;
            }
            state.flash = t("recover.done");
            signedIn(answer);
        } catch (error) {
            notice.replaceChildren(problem(error instanceof ApiError && error.status === 403
                ? t("recover.wrong") : passkeyProblem(error)));
        } finally {
            button.disabled = false;
            status("");
        }
    });
    show(el("h1", { text: t("recover.title") }), el("p", { text: t("recover.intro") }), form);
}

/// A message for the next screen only.
function flash() {
    const message = state.flash;
    state.flash = null;
    return message ? el("p", { class: "notice", role: "status", text: message }) : null;
}

async function homeScreen() {
    let home;
    try {
        home = await api("GET", "home");
    } catch (error) {
        // Locked: Home waits for the unlock, and says how.
        if (error instanceof ApiError && error.status === 423) {
            state.who.keys = "locked";
            show(flash(), keysNotice(), el("h1", { text: t("home.title") }),
                 el("p", { class: "hint", text: t("home.locked") }));
            return;
        }
        throw error;
    }
    const counts = el("dl", { class: "facts" });
    const inbox = el("section", { "aria-live": "polite" });
    const documents = el("section", { "aria-live": "polite" });
    for (const key of ["actors", "records", "contracts", "instances", "open_requests"]) {
        counts.append(el("dt", { text: t(`count.${key}`) }),
                      el("dd", { text: String(home.counts[key]) }));
    }
    const backup = home.backup ?? {};
    // What waits for this person's approval, and what they sent (spec v0.20).
    const approvals = home.approvals ?? { waiting: 0, sent: 0 };
    const waitingPart = approvals.waiting || approvals.sent
        ? el("section", { class: approvals.waiting ? "notice" : null },
             el("h2", { text: t("approvals.waiting_title") }),
             el("p", {}, el("a", { href: "#/approvals", text: t("home.approvals_waiting", { n: approvals.waiting }) })),
             approvals.sent ? el("p", { class: "hint", text: t("home.approvals_sent", { n: approvals.sent }) }) : null)
        : null;
    // Reminders for the long term, for those who look after the console:
    // today's log key, and time-stamp certificates that expire soon.
    const looksAfter = state.who.role === "owner" || state.who.role === "admin";
    const longTerm = looksAfter ? home.long_term ?? null : null;
    const longTermParts = [];
    if (longTerm?.log_key_classical) {
        longTermParts.push(el("p", { class: "hint", id: "home-long-term" },
                              el("a", { href: "#/settings", text: t("home.long_term") })));
    }
    if (longTerm?.certificates_expiring?.length) {
        const c = longTerm.certificates_expiring[0];
        longTermParts.push(el("p", { class: "hint", id: "home-certificates" },
                              el("a", { href: "#/settings", text: t(c.days_left < 0 ? "home.certificate_expired"
                                                                                    : "home.certificate_expiring", {
                                  authority: c.authority, date: isoText(c.not_after), days: c.days_left }) })));
    }
    show(flash(), keysNotice(), slotNotice(), el("h1", { text: t("home.title") }),
         backup.overdue || backup.problem ? problem(t("home.backup_overdue", { problem: backup.problem ?? "" })) : null,
         waitingPart, ...longTermParts,
         el("dl", { class: "facts" },
            el("dt", { text: t("home.organization") }), el("dd", { text: home.ledger.organization }),
            el("dt", { text: t("home.ledger") }), el("dd", { class: "id", text: home.ledger.id })),
         el("h2", { text: t("home.counts") }), counts, backupStatus(backup),
         el("p", {}, el("a", { href: "#/exchange", text: t("exchange.link") })), inbox, documents);
    inboxInto(inbox);
    accessInto(documents);
}

/// The last backup, in a line.
function backupStatus(b) {
    if (!b.folder) {
        return el("p", { class: "hint", text: t("home.backup_no_folder") });
    }
    return el("p", { class: "hint", text: b.at ? t("home.backup_last", { time: timeText(b.at), file: b.file })
                                               : t("home.backup_none") });
}

/// The calls the parties hold for this ledger's consent, asked for when
/// Home opens (and every minute by the node).
async function inboxInto(area) {
    let listed;
    try {
        listed = await api("GET", "inbox?refresh=1");
    } catch {
        return;
    }
    const waiting = listed.inbox.filter((c) => c.asks_us);
    if (waiting.length === 0) {
        return;
    }
    area.replaceChildren(el("h2", { text: t("parties.inbox_title") }),
                         el("ul", {}, waiting.map((c) => {
                             const open = el("button", { type: "button", text: t("parties.open"),
                                                         "aria-label": t("parties.open_label", { function: c.function, peer: c.peer }) });
                             open.addEventListener("click", async () => {
                                 status(t("status.working"));
                                 try {
                                     const read = await api("POST", "inbox/open", {
                                         peer: c.peer, call: c.call, language: state.language,
                                     });
                                     show(el("h1", { text: t("exchange.title") }),
                                          el("section", {}, ...proposalView(read, read.upload)));
                                 } catch (error) {
                                     area.append(problem(t("error.server", { message: error.message })));
                                 } finally {
                                     status("");
                                 }
                             });
                             return el("li", {}, t("parties.waiting", {
                                 function: c.function, peer: c.peer, arguments: c.arguments,
                             }), " ", open);
                         })));
}

function table(caption, columns, rows) {
    if (rows.length === 0) {
        return [el("h2", { text: caption }), el("p", { text: t("things.none") })];
    }
    const head = el("tr", {}, columns.map(([key]) => el("th", { scope: "col", text: t(key) })));
    const body = rows.map((row) =>
        el("tr", {}, columns.map(([key, cell]) => {
            const value = cell(row);
            if (value instanceof Node) {
                return el("td", { "data-label": t(key) }, value);
            }
            return el("td", { "data-label": t(key), class: value.id ? "id" : null,
                              text: value.text ?? value });
        })));
    return [el("table", {}, el("caption", { text: caption }), el("thead", {}, head),
               el("tbody", {}, body))];
}

const short = (id) => ({ id: true, text: `${id.slice(0, 12)}...` });

/// A file's size in the reader's units.
function sizeText(bytes) {
    const format = (n, unit) => t(unit, { n: new Intl.NumberFormat(state.language,
                                                                     { maximumFractionDigits: 1 })
                                                 .format(n) });
    if (bytes < 1024) {
        return format(bytes, "size.bytes");
    }
    if (bytes < 1024 * 1024) {
        return format(bytes / 1024, "size.kib");
    }
    return format(bytes / (1024 * 1024), "size.mib");
}

/// Uploads a file for a registration; its upload id.
async function uploadFile(file) {
    const headers = { "Content-Type": "application/octet-stream" };
    const token = stored(sessionStorage, SESSION);
    if (token) {
        headers.Authorization = `Bearer ${token}`;
    }
    const response = await fetch(`api/uploads?name=${encodeURIComponent(file.name)}`, {
        method: "POST", headers, body: file, credentials: "omit", cache: "no-store",
    });
    const answer = await response.json().catch(() => ({}));
    if (!response.ok) {
        throw new ApiError(response.status, answer?.error?.message ?? String(response.status));
    }
    return answer.upload;
}
const yesNo = (value) => t(value ? "value.yes" : "value.no");

/// The query string of a search or report: only the values given.
function queryOf(values) {
    const query = new URLSearchParams();
    for (const [name, value] of Object.entries(values)) {
        if (value !== undefined && value !== null && value !== "") {
            query.set(name, value);
        }
    }
    const text = query.toString();
    return text ? `?${text}` : "";
}

/// The browser's offset from UTC, as reports take it (+08:00).
function utcOffset() {
    const minutes = -new Date().getTimezoneOffset();
    const abs = Math.abs(minutes);
    return `${minutes < 0 ? "-" : "+"}${String(Math.floor(abs / 60)).padStart(2, "0")}:${String(abs % 60).padStart(2, "0")}`;
}

const isoText = (iso) => (iso ? timeText(new Date(iso).getTime()) : "");

/// Things: records and things under rules, found through the node's search
/// index (by kind, state, text, and time, a page at a time), or the newest
/// of each where the node keeps no index.
async function thingsScreen() {
    const listed = await api("GET", "kinds").catch(() => ({ kinds: [] }));
    const rules = await api("GET", "rules").catch(() => ({ contracts: [] }));
    const recordsArea = el("div");
    const instancesArea = el("div");
    const kind = el("select", { id: "search-kind" }, el("option", { value: "", text: t("search.any_kind") }),
                    listed.kinds.map((k) => el("option", { value: k.type, text: k.name })));
    const text = el("input", { id: "search-text", type: "search", maxlength: 200 });
    const since = el("input", { id: "search-since", type: "date" });
    const until = el("input", { id: "search-until", type: "date" });
    const old = el("input", { id: "search-old", type: "checkbox" });
    const contract = el("select", { id: "search-rules" }, el("option", { value: "", text: t("search.any_rules") }),
                        rules.contracts.filter((c) => c.name)
                            .map((c) => el("option", { value: c.name, text: c.name })));
    const status = el("input", { id: "search-status", type: "text", maxlength: 200 });
    const nextDay = (date) => (date ? new Date(new Date(`${date}T00:00:00`).getTime() + 86400000).toISOString().slice(0, 10) : "");
    const dayStart = (date) => (date ? String(new Date(`${date}T00:00:00`).getTime()) : "");
    const recordQuery = () => ({
        type: kind.value, q: text.value.trim(), current: old.checked ? "" : "1",
        since: dayStart(since.value), until: until.value ? dayStart(nextDay(until.value)) : "",
    });
    const recordColumns = [
        ["column.type", (r) => el("a", { href: `#/thing/${r.id}`, text: r.type })],
        ["column.state", (r) => (r.revoked ? t("value.revoked")
                                 : r.superseded_by ? t("value.superseded") : r.state)],
        ["search.public", (r) => Object.entries(r.metadata).map(([k, v]) => `${k}: ${v}`).join(", ")],
        ["search.registered", (r) => isoText(r.registered_at)],
        ["column.id", (r) => short(r.id)],
        ...(state.who.role === "viewer" ? [] : [["column.actions", (r) => {
            const button = el("button", { type: "button", text: t("act.button"),
                                          "aria-label": t("act.label", { type: r.type }) });
            button.addEventListener("click", () => actScreen(r));
            return button;
        }]]),
    ];
    const instanceColumns = [
        ["column.contract", (i) => el("a", { href: `#/instance/${i.id}`,
                                             text: i.contract_name ?? short(i.contract).text })],
        ["column.status", (i) => i.status ?? t("value.none")],
        ["search.fields", (i) => Object.entries(i.fields).map(([k, v]) => `${k}: ${v}`).join(", ")],
        ["column.final", (i) => yesNo(i.final)],
        ["column.open_requests", (i) => String(i.open_requests)],
        ["column.id", (i) => short(i.id)],
    ];
    // A page, and "More" for the next; each search starts again.
    const paged = async (area, caption, path, query, columns, key) => {
        const rows = [];
        const more = async (cursor) => {
            const page = await api("GET", `${path}${queryOf({ ...query, limit: "50", cursor })}`);
            rows.push(...page[key]);
            const next = page.next
                ? el("button", { type: "button", text: t("search.more") }) : null;
            next?.addEventListener("click", () => more(page.next).catch(failed(area)));
            area.replaceChildren(...table(caption, columns, rows), next ?? "");
        };
        await more(undefined);
    };
    const failed = (area) => (error) => area.replaceChildren(problem(t("error.server", { message: error.message })));
    const searchRecords = () => paged(recordsArea, t("things.records"), "search/records", recordQuery(),
                                      recordColumns, "records");
    const searchInstances = () => paged(instancesArea, t("things.instances"), "search/instances",
                                        { contract_name: contract.value, status: status.value.trim() },
                                        instanceColumns, "instances");
    const recordForm = el("form", { class: "search", role: "search" },
        el("div", { class: "field" }, el("label", { for: "search-text", text: t("search.text") }), text),
        el("div", { class: "field" }, el("label", { for: "search-kind", text: t("register.kind") }), kind),
        el("div", { class: "field" }, el("label", { for: "search-since", text: t("search.since") }), since),
        el("div", { class: "field" }, el("label", { for: "search-until", text: t("search.until") }), until),
        el("label", { class: "check" }, old, " ", t("search.old_versions")),
        el("button", { type: "submit", class: "primary", text: t("search.button") }));
    recordForm.addEventListener("submit", (event) => {
        event.preventDefault();
        searchRecords().catch(failed(recordsArea));
    });
    const instanceForm = el("form", { class: "search", role: "search" },
        el("div", { class: "field" }, el("label", { for: "search-rules", text: t("search.rules") }), contract),
        el("div", { class: "field" }, el("label", { for: "search-status", text: t("column.status") }), status),
        el("button", { type: "submit", text: t("search.button") }));
    instanceForm.addEventListener("submit", (event) => {
        event.preventDefault();
        searchInstances().catch(failed(instancesArea));
    });
    const register = state.who.role === "viewer" ? null
        : el("p", {}, el("a", { href: "#/new", class: "button", text: t("register.button") }), " ",
             el("a", { href: "#/renew", text: t("renew.link") }));
    try {
        await searchRecords();
        await searchInstances();
        show(el("h1", { text: t("things.title") }), el("p", { class: "hint", text: t("things.hint") }),
             register, recordForm, recordsArea, instanceForm, instancesArea,
             el("p", { class: "hint", text: t("search.hint") }));
    } catch (error) {
        if (!(error instanceof ApiError) || error.status !== 503) {
            throw error;
        }
        // No index on this node: the newest of each, as before.
        const things = await api("GET", "things");
        show(el("h1", { text: t("things.title") }), el("p", { class: "hint", text: t("things.hint") }),
             register, ...table(t("things.records"), recordColumns.filter(([k]) => k !== "search.public" && k !== "search.registered"), things.records),
             ...table(t("things.instances"), instanceColumns.filter(([k]) => k !== "search.fields"), things.instances),
             things.more ? el("p", { class: "hint", text: t("things.more") }) : null);
    }
}

/// Reports: counts by kind and state, by day, and things by rules and
/// state with a number field's totals; each also as a CSV file.
async function reportsScreen() {
    const offset = utcOffset();
    const area = el("div");
    const rules = await api("GET", "rules").catch(() => ({ contracts: [] }));
    const names = new Map(rules.contracts.map((c) => [c.id, c.name ?? short(c.id).text]));
    const keyText = (b, value) => (b === "contract" ? names.get(value) ?? short(value).text : value);
    const group = (labels, path, query) => {
        const box = el("section");
        const load = async () => {
            const report = await api("GET", `${path}${queryOf({ ...query(), utc_offset: offset })}`);
            const summed = report.groups.some((g) => g.sum !== undefined);
            const columns = [
                ...report.by.map((b) => [`report.by.${b}`, (g) => keyText(b, g.key[b] ?? "")]),
                ["report.count", (g) => String(g.count)],
                ...(summed ? [["report.sum", (g) => String(g.sum ?? "")],
                              ["report.min", (g) => String(g.min ?? "")],
                              ["report.max", (g) => String(g.max ?? "")]] : []),
            ];
            const csv = el("button", { type: "button", text: t("report.csv") });
            csv.addEventListener("click", () =>
                saveDownload(`${path}${queryOf({ ...query(), utc_offset: offset, format: "csv" })}`, {},
                             "report.csv").catch((error) =>
                    box.append(problem(t("error.server", { message: error.message })))));
            box.replaceChildren(...table(labels, columns, report.groups), csv,
                                report.truncated ? el("p", { class: "hint", text: t("report.truncated") }) : "");
        };
        return { box, load };
    };
    const byKind = group(t("report.records_by_kind"), "reports/records", () => ({ by: "type,state" }));
    const byDay = group(t("report.records_by_day"), "reports/records", () => ({ by: "day" }));
    const sum = el("input", { id: "report-sum", type: "text", maxlength: 100 });
    const byRules = group(t("report.things_by_rules"), "reports/instances",
                          () => ({ by: "contract,state", sum: sum.value.trim() }));
    const sumForm = el("form", { class: "search" },
        el("div", { class: "field" }, el("label", { for: "report-sum", text: t("report.sum_field") }), sum,
           el("span", { class: "hint", text: t("report.sum_hint") })),
        el("button", { type: "submit", text: t("report.update") }));
    sumForm.addEventListener("submit", (event) => {
        event.preventDefault();
        byRules.load().catch((error) => byRules.box.replaceChildren(problem(t("error.server", { message: error.message }))));
    });
    try {
        await Promise.all([byKind.load(), byDay.load(), byRules.load()]);
    } catch (error) {
        if (error instanceof ApiError && error.status === 503) {
            show(el("h1", { text: t("report.title") }), el("p", { text: t("report.unavailable") }));
            return;
        }
        throw error;
    }
    area.replaceChildren(byKind.box, byDay.box, sumForm, byRules.box);
    show(el("h1", { text: t("report.title") }),
         el("p", { class: "hint", text: t("report.hint", { offset }) }), area);
}

// --- A thing's page, and its proof --------------------------------------------------

/// Fetches a file from the console and saves it (the session's token goes
/// in a header, so no plain link can fetch it).
async function saveDownload(path, options, fallback) {
    const headers = { ...(options.headers ?? {}) };
    const token = stored(sessionStorage, SESSION);
    if (token) {
        headers.Authorization = `Bearer ${token}`;
    }
    const response = await fetch(`api/${path}`, { ...options, headers, credentials: "omit",
                                                 cache: "no-store" });
    if (!response.ok) {
        const answer = await response.json().catch(() => ({}));
        throw new ApiError(response.status, answer?.error?.message ?? String(response.status));
    }
    const disposition = response.headers.get("Content-Disposition") ?? "";
    const named = disposition.match(/filename\*=UTF-8''(.+)$/);
    const name = named ? decodeURIComponent(named[1]) : fallback;
    const url = URL.createObjectURL(await response.blob());
    const link = el("a", { href: url, download: name });
    document.body.append(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    return name;
}

async function thingScreen(id) {
    const thing = await api("GET", `records/${id}`);
    const facts = el("dl", { class: "facts" });
    const fact = (key, value, attributes = {}) => {
        facts.append(el("dt", { text: t(key) }), el("dd", { text: String(value), ...attributes }));
    };
    fact("column.type", thing.type);
    fact("column.state", thing.revoked ? t("value.revoked") : thing.state);
    fact("column.registrant", thing.registrant.name ?? short(thing.registrant.id).text);
    fact("thing.entry", thing.index);
    fact("column.id", thing.id, { class: "id" });
    for (const [name, value] of Object.entries(thing.metadata)) {
        fact("thing.public", `${name}: ${value}`);
    }
    const parts = [keysNotice(), el("h1", { text: thing.kind ?? thing.type })];
    const latest = thing.versions[thing.versions.length - 1];
    if (thing.superseded_by) {
        parts.push(el("div", { class: "notice replaced", role: "status" },
                      el("p", { text: t("thing.superseded", { index: thing.superseded_index }) }),
                      el("p", {}, el("a", { href: `#/thing/${latest.id}`, text: t("thing.open_latest") }))));
    }
    if (thing.supersedes) {
        fact("register.replaces", thing.supersedes, { class: "id" });
    }
    parts.push(facts);
    if (thing.claim) {
        // A claim (v0.14): what it confirms, and whether it still stands.
        const c = thing.claim;
        const claim = el("dl", { class: "facts" });
        const line = (key, value) => claim.append(el("dt", { text: t(key) }), el("dd", {}, value));
        line("claim.confirms", c.text);
        line("claim.answer", t(c.holds ? "claim.holds" : "claim.does_not_hold"));
        if (c.subject) line("claim.subject", c.subject);
        line("claim.as_of", timeText(c.as_of));
        if (c.until) line("claim.until", timeText(c.until));
        line("claim.status", t(`claim.status.${c.status.replace(" ", "_")}`));
        line("claim.source", el("a", { href: `#/thing/${c.source}`, text: c.source_type ?? c.source }));
        parts.push(el("h2", { text: t("claim.title") }), claim);
    }
    parts.push(...madeFromView(thing));
    if (thing.versions.length > 1) {
        parts.push(el("h2", { text: t("thing.versions_title") }),
                   el("ol", { class: "versions" }, thing.versions.map((v, n) => {
                       const line = t("thing.version_line", { n: n + 1, type: v.type, index: v.index }) +
                           (v.revoked ? t("thing.version_revoked") : "");
                       return el("li", {}, v.current ? el("strong", { text: line + t("thing.version_this") })
                                                     : el("a", { href: `#/thing/${v.id}`, text: line }));
                   })));
    }
    parts.push(el("h2", { text: t("thing.private_title") }));
    if (!thing.private.allowed) {
        parts.push(el("p", { class: "hint", text: t("thing.private_hidden") }));
    } else if (thing.private.locked) {
        parts.push(el("p", { class: "hint", text: t("thing.private_locked") }));
    } else if (thing.private.fields === null) {
        parts.push(el("p", { class: "hint", text: t("thing.private_elsewhere") }));
    } else {
        const fields = el("dl", { class: "facts" });
        for (const f of thing.private.fields) {
            fields.append(el("dt", { text: f.name }), el("dd", { text: f.value }));
        }
        parts.push(fields);
    }
    // Values that can be proven without showing them (v0.22): proven from
    // here, or by the holder they belong to, given their openings.
    if ((thing.provable ?? []).length > 0) {
        const provable = el("p", { text: t("ranges.provable_line", { list: provableList(thing.provable) }) });
        const buttons = el("p", { class: "actions" });
        if (thing.may_prove && !thing.private.locked) {
            const prove = el("button", { type: "button", text: t("prove.button") });
            prove.addEventListener("click", () => proveScreen(thing));
            buttons.append(prove);
        }
        if (thing.may_hand_out && !thing.private.locked) {
            const hand = el("button", { type: "button", text: t("openings.button") });
            hand.addEventListener("click", () => openingsScreen(thing));
            buttons.append(buttons.children.length ? " " : "", hand);
        }
        parts.push(el("h2", { text: t("ranges.title") }), provable,
                   el("p", { class: "hint", text: t("ranges.thing_hint") }),
                   buttons.children.length ? buttons : null);
    }
    parts.push(el("h2", { text: t("thing.files_title") }));
    if (thing.files.length === 0) {
        parts.push(el("p", { text: t("thing.no_files") }));
    }
    const notice = el("div");
    for (const f of thing.files) {
        const line = el("p", { text: `${f.name}, ${sizeText(f.size)} ` });
        if (f.kept && thing.private.allowed && !thing.private.locked) {
            const save = el("button", { type: "button", text: t("thing.download"),
                                        "aria-label": t("thing.download_label", { name: f.name }) });
            save.addEventListener("click", async () => {
                try {
                    await saveDownload(`records/${thing.id}/files/${f.index}`, {}, f.name);
                } catch (error) {
                    notice.replaceChildren(problem(t("error.server", { message: error.message })));
                }
            });
            line.append(save);
        } else if (!f.kept) {
            line.append(t("thing.not_kept"));
        }
        parts.push(line);
    }
    parts.push(notice, el("h2", { text: t("thing.endorsements_title") }));
    if (thing.endorsements.length === 0) {
        parts.push(el("p", { text: t("things.none") }));
    } else {
        parts.push(el("ul", {}, thing.endorsements.map((e) => el("li", {
            text: t("thing.endorsed", { name: e.actor.name ?? short(e.actor.id).text, role: e.role }),
        }))));
    }
    const actions = el("p", { class: "actions" });
    const share = el("button", { type: "button", class: "primary", text: t("share.button") });
    share.addEventListener("click", () => shareScreen(thing));
    actions.append(share);
    const script = thing.type === SCRIPT_TYPE;
    if (script) {
        // A script's approval: its page shows its files, checks them, and
        // withdraws it.
        actions.append(" ", el("a", { href: `#/script/${thing.id}`, class: "button", text: t("scripts.open") }));
    }
    if (state.who.role !== "viewer" && !thing.revoked && !script) {
        const act = el("button", { type: "button", text: t("act.button"),
                                   "aria-label": t("act.label", { type: thing.type }) });
        act.addEventListener("click", () => actScreen({ id: thing.id, type: thing.type }));
        actions.append(" ", act);
    }
    if (state.who.role !== "viewer" && !thing.superseded_by && !thing.claim && !script) {
        actions.append(" ", el("a", { href: `#/new/${thing.id}`, class: "button",
                                      text: t("thing.new_version") }));
    }
    if (state.who.role !== "viewer" && thing.may_claim) {
        const confirm = el("button", { type: "button", text: t("claim.button") });
        confirm.addEventListener("click", () => claimScreen(thing));
        actions.append(" ", confirm);
    }
    parts.push(actions);
    show(...parts);
}

/// A script's approval on the ledger (v0.18).
const SCRIPT_TYPE = "kanhe.script/1";

/// A source as the approval names it, in a line.
function sourceText(s) {
    return s.local
        ? t("approve.source_local", { name: s.kind ?? s.type ?? s.record.slice(0, 12), id: s.record.slice(0, 12) })
        : t("approve.source_other", { id: s.record.slice(0, 12), ledger: s.party ?? s.ledger.slice(0, 12) });
}

/// A source's status, in the reader's words.
const sourceStatus = (key) => t(`made.status.${key ?? "unknown"}`);

/// Where a record came from (v0.18): the script that made it and the
/// records it was made from, each as it stood when this one was made and
/// as it stands now, with a warning when one was revoked or replaced since.
/// A source on another ledger shows what the proof kept here says of it.
function madeFromView(thing) {
    const made = thing.made_from;
    if (!made || (!made.script && made.sources.length === 0)) {
        return [];
    }
    const parts = [el("h2", { text: t("made.title") })];
    if (made.stale) {
        parts.push(el("div", { class: "notice replaced", role: "status" }, el("p", { text: t("made.stale") })));
    }
    const facts = el("dl", { class: "facts" });
    if (made.script) {
        const s = made.script;
        const dd = s.name
            ? el("dd", { class: s.status === "withdrawn" ? "bad" : null },
                 el("a", { href: `#/script/${s.id}`, text: `${s.name} ${s.version}` }), " ",
                 t("made.script_line", { person: s.approved_by.name ?? short(s.approved_by.id).text,
                                         time: timeText(s.approved_at) }),
                 s.status === "withdrawn"
                     ? t("made.script_withdrawn", { time: s.withdrawn_at ? timeText(s.withdrawn_at) : "" })
                     : t("made.script_still"))
            : el("dd", { class: "id", text: s.id });
        facts.append(el("dt", { text: t("made.by_script") }), dd);
    }
    for (const s of made.sources) {
        facts.append(el("dt", { text: t("made.source") }), sourceView(thing, s));
    }
    parts.push(facts);
    return parts;
}

function sourceView(thing, s) {
    const changed = s.now === "revoked" || s.now === "replaced";
    const now = sourceStatus(s.now) + (s.changed_at ? t("made.on", { time: timeText(s.changed_at) }) : "");
    const dd = el("dd", { class: changed ? "bad" : null });
    if (s.local) {
        dd.append(el("a", { href: `#/thing/${s.record}`, text: s.kind ?? s.type ?? short(s.record).text }), " ",
                  s.type === null ? t("made.local_unknown")
                                  : t("made.local_line", { then: sourceStatus(s.at_record), now }));
        if (s.replaced_by) {
            dd.append(" ", el("a", { href: `#/thing/${s.replaced_by}`, text: t("made.open_newer") }));
        }
        return dd;
    }
    const ledger = s.organization ?? s.party ?? short(s.ledger).text;
    dd.append(s.type !== null
        ? t("made.remote_line", { type: s.type, ledger, then: sourceStatus(s.at_record), now,
                                  time: timeText(s.as_of) })
        : t(s.proof_kept ? "made.remote_bad_proof" : "made.remote_no_proof",
            { ledger, problem: s.proof_problem ?? "" }),
              " ", el("span", { class: "id", text: `${s.record.slice(0, 12)}...` }));
    if (state.who.role !== "viewer" && thing.private.allowed) {
        dd.append(" ", keepProofInput(thing, s));
    }
    return dd;
}

/// Keeps the proof of a source on another ledger (its ledger's evidence of
/// it, as a file) with the record, in place of the one before: the
/// record's proof then carries it, and its page reads the source from it.
function keepProofInput(thing, s) {
    const label = t(s.proof_kept ? "made.replace_proof" : "made.keep_proof", { id: s.record.slice(0, 12) });
    const input = el("input", { type: "file", accept: ".cbor,application/cbor", "aria-label": label });
    const out = el("span", { role: "status" });
    input.addEventListener("change", async () => {
        const file = input.files[0];
        if (!file) {
            return;
        }
        try {
            const upload = await uploadFile(file);
            await api("POST", `records/${thing.id}/source-proofs`, { upload });
            await thingScreen(thing.id);
        } catch (error) {
            out.replaceChildren(problem(t("error.server", { message: error.message })));
        }
    });
    return el("span", {}, el("label", {}, label, " ", input), out);
}

/// Confirming a condition on a document's fields without them (a claim,
/// v0.14): the conditions, checked by the console against the private
/// data, then approved with a tap as any registration.
/// Conditions to confirm or to ask about, one row each: a field (chosen
/// from `names`, or typed when the fields are another party's), a
/// comparison, and a value. `read()` gives them as the console takes them.
function conditionRows(names) {
    const rows = el("div");
    let count = 0;
    const addRow = () => {
        count += 1;
        const n = count;
        const field = names
            ? el("select", { "aria-label": t("claim.field", { n }) },
                 names.map((name) => el("option", { value: name, text: name })))
            : el("input", { type: "text", "aria-label": t("claim.field", { n }), maxlength: 64,
                            spellcheck: "false" });
        const op = el("select", { "aria-label": t("claim.op", { n }) },
                      [">", ">=", "<", "<=", "=", "!=", "between", "in", "exists"].map((o) =>
                          el("option", { value: o, text: t(`claim.ops.${o}`) })));
        const value = el("input", { type: "text", "aria-label": t("claim.value", { n }), maxlength: 512 });
        op.addEventListener("change", () => { value.hidden = op.value === "exists"; });
        const row = el("fieldset", { class: "kind-field" },
                       el("legend", { text: t("claim.condition", { n }) }), field, op, value);
        row.read = () => ({ field: field.value.trim(), op: op.value, value: value.value.trim() });
        rows.append(row);
    };
    addRow();
    const more = el("button", { type: "button", text: t("claim.add") });
    more.addEventListener("click", addRow);
    return { rows, more, read: () => [...rows.children].map((r) => r.read()) };
}

function claimScreen(thing) {
    const { rows, more, read } = conditionRows((thing.private.fields ?? []).map((f) => f.name));
    const [subjectField, subject] = field("claim-subject", t("claim.subject"), t("claim.subject_hint"),
                                          { maxlength: 256 });
    const [untilField, until] = field("claim-until", t("claim.until"), t("claim.until_hint"), { type: "date" });
    const allowNo = el("input", { type: "checkbox", id: "claim-allow-no" });
    const notice = el("div", { role: "status" });
    const prepare = el("button", { type: "submit", class: "primary", text: t("act.prepare") });
    const form = el("form", { novalidate: true }, rows, more,
                    el("p", { class: "hint", text: t("claim.value_hint") }),
                    subjectField, untilField,
                    el("label", { class: "check" }, allowNo, " ", t("claim.allow_no")), notice, prepare);
    form.addEventListener("submit", async (event) => {
        event.preventDefault();
        try {
            const prepared = await api("POST", "prepare", {
                action: "claim.issue", record: thing.id, conditions: read(), subject: subject.value.trim(),
                until: until.value ? Date.parse(`${until.value}T23:59:59Z`) : null,
                allow_no: allowNo.checked,
            });
            await approveScreen(prepared);
        } catch (error) {
            notice.replaceChildren(problem(t("error.server", { message: error.message })));
        }
    });
    show(el("h1", { text: t("claim.title_new") }), el("p", { class: "hint", text: t("claim.intro") }),
         el("p", { class: "id", text: thing.id }), form, backButton(t("nav.things")));
}

/// Proving that values lie within bounds without showing them (v0.22),
/// from the console's vault: for each provable value, at least, at most,
/// or between bounds written as people write them; and the relying party's
/// challenge, if it gave one. The console makes the proof file, verifies it,
/// and offers it; the page shows what it proves.
function proveScreen(thing) {
    const rows = thing.provable.map((p, i) => {
        const id = `prove-${i}`;
        const how = el("select", { id: `${id}-how`, "aria-label": t("prove.how", { field: p.field }) },
                       ["none", "at_least", "at_most", "between"].map((v) =>
                           el("option", { value: v, text: t(`prove.how.${v}`) })));
        const type = p.encoding.type === "date" ? "date" : "text";
        const low = el("input", { id: `${id}-low`, type, maxlength: 64, inputmode: type === "text" ? "decimal" : null,
                                  "aria-label": t("prove.low", { field: p.field }) });
        const high = el("input", { id: `${id}-high`, type, maxlength: 64, inputmode: type === "text" ? "decimal" : null,
                                   "aria-label": t("prove.high", { field: p.field }) });
        const and = el("span", { text: t("prove.and") });
        const redraw = () => {
            low.hidden = !["at_least", "between"].includes(how.value);
            high.hidden = !["at_most", "between"].includes(how.value);
            and.hidden = how.value !== "between";
        };
        how.addEventListener("change", redraw);
        redraw();
        const row = el("fieldset", { class: "kind-field" },
                       el("legend", { text: t("ranges.provable_item", { field: p.field, encoding: encodingText(p.encoding) }) }),
                       how, " ", low, " ", and, " ", high,
                       p.encoding.type !== "date"
                           ? el("p", { class: "hint", text: t(p.encoding.type === "money" ? "prove.money_hint" : "prove.number_hint", {
                               currency: p.encoding.currency ?? "", scale: p.encoding.scale }) })
                           : null);
        row.read = () => (how.value === "none" ? null : {
            field: p.field,
            at_least: low.hidden ? null : low.value.trim(),
            at_most: high.hidden ? null : high.value.trim(),
        });
        return row;
    });
    const [challengeField, challenge] = field("prove-challenge", t("prove.challenge"), t("prove.challenge_hint"),
                                              { spellcheck: "false", maxlength: 128, autocomplete: "off" });
    const notice = el("div", { role: "status", "aria-live": "polite" });
    const make = el("button", { type: "submit", class: "primary", text: t("prove.make") });
    const form = el("form", { novalidate: true }, ...rows, challengeField, notice, make, " ",
                    (() => {
                        const back = el("button", { type: "button", text: t("approve.cancel") });
                        back.addEventListener("click", () => thingScreen(thing.id));
                        return back;
                    })());
    form.addEventListener("submit", async (event) => {
        event.preventDefault();
        const ranges = rows.map((r) => r.read()).filter((r) => r);
        if (ranges.length === 0) {
            notice.replaceChildren(problem(t("prove.nothing")));
            return;
        }
        const code = challenge.value.trim().toLowerCase();
        if (code && !/^([0-9a-f]{2}){1,64}$/.test(code)) {
            notice.replaceChildren(problem(t("verify.challenge_bad")));
            return;
        }
        make.disabled = true;
        status(t("prove.working"));
        notice.replaceChildren(el("p", { text: t("prove.working") }));
        try {
            const proved = await api("POST", "prove", { record: thing.id, ranges, context: code || null });
            saveBytes(fromBase64url(proved.file), proved.name);
            notice.replaceChildren(
                el("p", { class: "notice", id: "prove-done", text: t("prove.done", { name: proved.name }) }),
                el("ul", { class: "ranges" }, proved.range_proofs.map((p) => rangeLine(p, code))),
                el("p", { class: "hint", text: t(code ? "prove.send_challenge" : "prove.send") }));
        } catch (error) {
            const known = ["not_within", "bad_bounds", "bad_challenge", "no_provable", "unsupported"];
            const why = error.answer?.error?.code;
            notice.replaceChildren(problem(known.includes(why)
                ? t(`prove.${why}`, { message: error.message })
                : error.status === 423 ? t("keys.locked") : t("error.server", { message: error.message })));
        } finally {
            make.disabled = false;
            status("");
        }
    });
    show(el("h1", { text: t("prove.title") }), el("p", { class: "id", text: `${thing.kind ?? thing.type} ${thing.id}` }),
         el("p", { text: t("prove.intro") }), form);
}

/// Letting the holder prove (v0.22): the record's openings as a file, for
/// the person the values belong to, after a warning that it holds them.
function openingsScreen(thing) {
    const boxes = thing.provable.map((p) => el("input", { type: "checkbox", value: p.field, checked: true }));
    const values = el("fieldset", {}, el("legend", { text: t("openings.which") }),
                      ...thing.provable.map((p, i) => el("label", { class: "check" }, boxes[i], " ",
                          t("ranges.provable_item", { field: p.field, encoding: encodingText(p.encoding) }))));
    const understood = el("input", { type: "checkbox", id: "openings-understood" });
    const notice = el("div", { role: "status", "aria-live": "polite" });
    const save = el("button", { type: "submit", class: "primary", text: t("openings.save") });
    const form = el("form", { novalidate: true }, values,
                    el("div", { class: "error", role: "note" }, el("strong", { text: t("openings.warning_title") }),
                       el("p", { text: t("openings.warning") })),
                    el("label", { class: "check" }, understood, " ", t("openings.understood")),
                    notice, save, " ",
                    (() => {
                        const back = el("button", { type: "button", text: t("approve.cancel") });
                        back.addEventListener("click", () => thingScreen(thing.id));
                        return back;
                    })());
    form.addEventListener("submit", async (event) => {
        event.preventDefault();
        const fields = boxes.filter((b) => b.checked).map((b) => b.value);
        if (!understood.checked) {
            notice.replaceChildren(problem(t("openings.confirm_first")));
            return;
        }
        if (fields.length === 0) {
            notice.replaceChildren(problem(t("openings.none_chosen")));
            return;
        }
        save.disabled = true;
        try {
            const saved = await saveDownload(`records/${thing.id}/openings`, {
                method: "POST", headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ fields }),
            }, "openings.kanheopenings");
            notice.replaceChildren(el("p", { class: "notice", id: "openings-done", text: t("openings.done", { name: saved }) }),
                                   el("p", { class: "hint", text: t("openings.then") }));
        } catch (error) {
            notice.replaceChildren(problem(error.status === 423 ? t("keys.locked")
                                                                : t("error.server", { message: error.message })));
        } finally {
            save.disabled = false;
        }
    });
    show(el("h1", { text: t("openings.title") }), el("p", { class: "id", text: `${thing.kind ?? thing.type} ${thing.id}` }),
         el("p", { text: t("openings.intro") }), form);
}

/// Sharing proof: the fields to disclose and whether to open the files;
/// the proof as a file, and the files to send along.
function shareScreen(thing) {
    const boxes = [];
    const fields = el("fieldset", {}, el("legend", { text: t("share.disclose") }));
    const readable = thing.private.allowed && Array.isArray(thing.private.fields);
    if (readable) {
        for (const f of thing.private.fields) {
            const box = el("input", { type: "checkbox", value: f.name });
            boxes.push(box);
            fields.append(el("label", { class: "check" }, box, " ", f.name));
        }
    } else {
        fields.append(el("p", { class: "hint", text: t("share.nothing_private") }));
    }
    const filesBox = el("input", { type: "checkbox", checked: thing.files.length > 0 && readable });
    const files = thing.files.length > 0 && readable
        ? el("label", { class: "check" }, filesBox, " ", t("share.files")) : null;
    const notice = el("div");
    const after = el("div");
    const make = el("button", { type: "submit", class: "primary", text: t("share.make") });
    const form = el("form", { novalidate: true }, fields, files, notice, make, " ",
                    (() => {
                        const back = el("button", { type: "button", text: t("approve.cancel") });
                        back.addEventListener("click", () => thingScreen(thing.id));
                        return back;
                    })());
    form.addEventListener("submit", async (event) => {
        event.preventDefault();
        make.disabled = true;
        status(t("status.working"));
        try {
            const disclose = boxes.filter((b) => b.checked).map((b) => b.value);
            const withFiles = !!files && filesBox.checked;
            const saved = await saveDownload("proof", {
                method: "POST", headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ record: thing.id, disclose, files: withFiles }),
            }, "proof.cbor");
            const sendAlong = withFiles ? thing.files.filter((f) => f.kept).map((f) => {
                const save = el("button", { type: "button",
                                            text: t("thing.download_label", { name: f.name }) });
                save.addEventListener("click", () =>
                    saveDownload(`records/${thing.id}/files/${f.index}`, {}, f.name));
                return el("p", {}, save);
            }) : [];
            after.replaceChildren(el("p", { role: "status", text: t("share.made", { name: saved }) }),
                                  el("p", { text: t(withFiles ? "share.send_files" : "share.send") }),
                                  ...sendAlong);
        } catch (error) {
            notice.replaceChildren(problem(error.status === 423 ? t("keys.locked")
                                                                : t("error.server", { message: error.message })));
        } finally {
            make.disabled = false;
            status("");
        }
    });
    show(el("h1", { text: t("share.title") }), el("p", { class: "id", text: `${thing.type} ${thing.id}` }),
         el("p", { text: t("share.intro") }), form, after);
}

// --- Verify ----------------------------------------------------------------------------

// --- Values proven without showing them (v0.22) ----------------------------------------

/// How a provable value is read, in words: a date, a whole number, an
/// amount in HKD with 2 decimal places.
function encodingText(e) {
    const places = e.scale === 0 ? "_0" : e.scale === 1 ? "_1" : "";
    if (e.type === "date") {
        return t("ranges.enc_date");
    }
    return t(`ranges.enc_${e.type === "money" ? "money" : "number"}${places}`,
             { currency: e.currency ?? "", scale: e.scale ?? 0 });
}

/// An encoding as a kind sheet writes it ("money:HKD:2"), as a report gives
/// it: {type, scale, currency}.
function encodingOf(text) {
    const [type, a, b] = String(text ?? "").split(":");
    if (type === "date") {
        return { type, scale: null, currency: null };
    }
    if (type === "money") {
        return { type, scale: Number(b), currency: a };
    }
    return { type: "number", scale: Number(a ?? 0), currency: null };
}

/// Provable values in a line: "born (a date), salary (an amount in HKD
/// with 2 decimal places)".
const provableList = (list) => list.map((p) => t("ranges.provable_item", {
    field: p.field, encoding: encodingText(p.encoding) })).join(t("approvals.separator"));

/// A range proof's statement in the reader's language (spec v0.22, section
/// 11.3): its bounds taken from the report's English words, which write
/// them as a claim does, and exactly.
function rangeText(proof) {
    const words = proof.text.startsWith(`${proof.field} `) ? proof.text.slice(proof.field.length) : null;
    let m;
    if (words && proof.low !== null && proof.high !== null && (m = /^ is between (.+) and (.+)$/.exec(words))) {
        return t("ranges.between", { field: proof.field, low: m[1], high: m[2] });
    }
    if (words && proof.high === null && (m = /^ is at least (.+)$/.exec(words))) {
        return t("ranges.at_least", { field: proof.field, low: m[1] });
    }
    if (words && proof.low === null && (m = /^ is at most (.+)$/.exec(words))) {
        return t("ranges.at_most", { field: proof.field, high: m[1] });
    }
    return proof.text;
}

/// A range proof in a line: its statement, the challenge it carries, and
/// whether it was checked.
function rangeLine(proof, challenge = "") {
    const verified = proof.status === "verified";
    const carried = proof.context
        ? t(proof.context === challenge ? "ranges.challenge_yours" : "ranges.challenge", { code: proof.context })
        : t("ranges.no_challenge");
    return el("li", { class: verified ? null : "bad" }, el("strong", { text: rangeText(proof) }), " ",
              t(verified ? "ranges.verified" : "ranges.not_checked"), " ",
              el("span", { class: "hint", text: carried }));
}

/// What a verification report says of provable values and range proofs.
function rangesView(report, challenge = "") {
    const provable = report.provable ?? [];
    const proofs = report.range_proofs ?? [];
    if (provable.length === 0 && proofs.length === 0) {
        return challenge ? [el("p", { class: "notice", text: t("ranges.none_for_challenge") })] : [];
    }
    const parts = [el("h2", { text: t("ranges.title") })];
    if (provable.length > 0) {
        parts.push(el("p", { text: t("ranges.provable_line", { list: provableList(provable) }) }),
                   el("p", { class: "hint", text: t("ranges.issuers_word") }));
    }
    if (proofs.length > 0) {
        parts.push(el("ul", { class: "ranges" }, proofs.map((p) => rangeLine(p, challenge))));
    } else {
        parts.push(el("p", { text: t(challenge ? "ranges.none_for_challenge" : "ranges.none") }));
    }
    return parts;
}

/// A localized verification report, from the verifier's JSON; with the
/// challenge its range proofs were required to carry, if any.
function reportView(given, challenge = "") {
    const parts = [];
    if (given.error) {
        parts.push(el("div", { class: "error", role: "alert" },
                      el("strong", { text: t("verify.failed") }),
                      el("p", { text: t("verify.reason", { reason: given.error }) })));
        return parts;
    }
    // A thing with rules: its instance's evidence report, with the contract's
    // facts beside it.
    const contract = given.kind === "contract" ? given : null;
    const report = contract ? { ...contract.report, kind: "contract" } : given;
    const mismatch = (report.attachments ?? []).some((a) => a.status === "mismatch");
    const unconfirmed = !report.ledger.id_checked;
    parts.push(el("div", { class: mismatch ? "error" : "notice", role: "status" },
                  el("strong", { text: t(mismatch ? "verify.mismatch_title"
                                                  : unconfirmed ? "verify.unconfirmed_title"
                                                                : "verify.verified_title") }),
                  el("p", { text: t(mismatch ? "verify.mismatch"
                                             : unconfirmed ? "verify.unconfirmed" : "verify.verified") })));
    const facts = el("dl", { class: "facts" });
    const fact = (key, value, attributes = {}) => {
        facts.append(el("dt", { text: t(key) }), el("dd", { text: String(value), ...attributes }));
    };
    fact("verify.organization", report.ledger.organization);
    fact("home.ledger", report.ledger.id, { class: "id" });
    fact("verify.checkpoint", t("verify.checkpoint_value", { size: report.checkpoint.tree_size ??
                                                                    report.checkpoint.size,
                                                             time: report.checkpoint.timestamp ?? "" }));
    if (report.long_term) {
        fact("long_term.status", longTermWords(report.long_term));
    }
    if (contract) {
        const i = contract.instance;
        fact("column.contract", i.contract.name ?? i.contract.id);
        fact("column.state", i.status ?? t("value.none"));
        fact("column.final", yesNo(i.final));
        fact("column.id", i.id, { class: "id" });
    }
    if (report.kind === "record") {
        fact("column.type", report.record.type);
        fact("column.state", report.record.revoked ? t("value.revoked") : report.record.state);
        fact("column.id", report.record.id, { class: "id" });
        if (report.record.superseded_by) {
            fact("verify.superseded", t("verify.superseded_value", { id: report.record.superseded_by }));
        }
        if (report.record.supersedes) {
            fact("verify.replaces", report.record.supersedes, { class: "id" });
        }
    }
    parts.push(facts);
    if (report.events) {
        parts.push(el("h2", { text: t("verify.history") }));
        parts.push(el("ol", { class: "events" }, report.events.map((e) => {
            const who = e.actor.kind === "person"
                ? t(e.presence ? (e.presence.user_verified ? "verify.person_present"
                                                           : "verify.person_passkey")
                               : "verify.person_not_present", { name: e.actor.name })
                : t(`verify.actor.${e.actor.kind}`, { name: e.actor.name });
            const what = e.new_version ? t("verify.event.superseded", { detail: e.detail ?? "" })
                : t(`verify.event.${e.type}`, { detail: e.detail ?? "" });
            return el("li", {}, el("span", { class: "id", text: `#${e.index} ` }),
                      `${what} ${t("verify.by", { who })} `,
                      el("span", { class: "hint", text: e.registered_at }));
        })));
    }
    parts.push(...reportMadeFrom(report));
    parts.push(...rangesView(report, challenge));
    const disclosed = Object.entries(report.disclosed_fields ?? {});
    if (disclosed.length > 0) {
        parts.push(el("h2", { text: t("verify.disclosed") }));
        const fields = el("dl", { class: "facts" });
        for (const [name, value] of disclosed) {
            fields.append(el("dt", { text: name }),
                          el("dd", { text: typeof value === "string" ? value : JSON.stringify(value) }));
        }
        parts.push(fields);
    }
    if ((report.attachments ?? []).length > 0) {
        parts.push(el("h2", { text: t("verify.files") }));
        parts.push(el("ul", {}, report.attachments.map((a) => el("li", {
            class: a.status === "mismatch" ? "bad" : null,
            text: t(`verify.file.${a.status}`, { name: a.name, size: sizeText(a.size) }),
        }))));
    }
    parts.push(el("p", { class: "hint", text: t(report.complete ? "verify.complete"
                                                                : "verify.incomplete") }));
    return parts;
}

/// Where the proof's record came from, as the verifier reports it (v0.18):
/// the scripts its events name, with their approvals, and its sources, each
/// as it stood when the record was made and at the checkpoint.
function reportMadeFrom(report) {
    const scripts = report.scripts ?? [];
    const sources = report.sources ?? [];
    if (scripts.length === 0 && sources.length === 0) {
        return [];
    }
    const facts = el("dl", { class: "facts" });
    for (const s of scripts) {
        facts.append(el("dt", { text: t("made.by_script") }), el("dd", {
            class: s.withdrawn_at ? "bad" : null,
            text: t("verify.script_line", { name: s.name, version: s.version, files: s.files.length,
                                            person: s.approved_by.name, time: isoText(s.approved_at) }) +
                (s.deterministic ? t("verify.script_deterministic") : "") +
                (s.withdrawn_at ? t("made.script_withdrawn", { time: isoText(s.withdrawn_at) })
                                : t("made.script_still")),
        }));
    }
    let stale = false;
    for (const s of sources) {
        const changed = s.at_checkpoint === "revoked" || s.at_checkpoint === "replaced";
        stale = stale || changed;
        const now = sourceStatus(s.at_checkpoint) + (s.changed_at ? t("made.on", { time: isoText(s.changed_at) }) : "");
        const text = !s.provided
            ? t("verify.source_missing", { id: s.record.slice(0, 12), ledger: s.ledger.slice(0, 12) })
            : t(s.local ? "verify.source_local" : "verify.source_remote", {
                type: s.type, ledger: s.organization ?? s.ledger.slice(0, 12), then: sourceStatus(s.at_record),
                now, time: isoText(s.checkpoint_time) }) +
                (s.trust_node ? t("verify.source_trust_node", { name: s.trust_node }) : "");
        facts.append(el("dt", { text: t("made.source") }), el("dd", { class: changed ? "bad" : null, text }));
    }
    const parts = [el("h2", { text: t("made.title") })];
    if (stale) {
        parts.push(el("p", { class: "notice replaced", role: "status", text: t("made.stale") }));
    }
    parts.push(facts);
    return parts;
}

/// Checking a proof, in this browser: the proof file, the files it may
/// check, and the ledger it should come from.
function verifyScreen() {
    const proofInput = el("input", { id: "verify-proof", type: "file", accept: ".cbor,application/cbor" });
    const filesInput = el("input", { id: "verify-files", type: "file", multiple: true });
    const [ledgerField, ledgerInput] = field("verify-ledger", t("verify.ledger"), t("verify.ledger_hint"),
                                             { spellcheck: "false", maxlength: 64 });
    // A challenge for range proofs (v0.22): made here and given to whoever
    // proves, so that a proof carrying it was made after it was asked for.
    const [challengeField, challengeInput] = field("verify-challenge", t("verify.challenge"),
                                                   t("verify.challenge_hint"),
                                                   { spellcheck: "false", maxlength: 128, autocomplete: "off" });
    const fresh = el("button", { type: "button", text: t("verify.challenge_new") });
    challengeField.append(fresh);
    const result = el("section", { "aria-live": "polite", "aria-labelledby": "verify-result" });
    let proof = null;
    const files = new Map();
    const check = async () => {
        if (!proof) {
            return;
        }
        const checker = await loadChecker();
        if (!checker) {
            result.replaceChildren(problem(t("verify.unavailable")));
            return;
        }
        const ledger = ledgerInput.value.trim().toLowerCase();
        const challenge = challengeInput.value.trim().toLowerCase();
        if (challenge && !/^([0-9a-f]{2}){1,64}$/.test(challenge)) {
            result.replaceChildren(problem(t("verify.challenge_bad")));
            return;
        }
        const report = checker.verify(proof, files, ledger, challenge);
        // Not verified with the challenge, but verified without it: a range
        // proof was made before it was asked for, or for someone else.
        const without = !report.error || !challenge ? null : checker.verify(proof, files, ledger);
        result.replaceChildren(el("h2", { id: "verify-result", text: t("verify.result") }),
                               ...(without && !without.error
                                   ? [el("div", { class: "error", role: "alert" },
                                         el("strong", { text: t("verify.challenge_failed") }),
                                         el("p", { text: t("verify.challenge_failed_detail") }))]
                                   : reportView(report, challenge)));
    };
    fresh.addEventListener("click", async () => {
        const bytes = crypto.getRandomValues(new Uint8Array(16));
        challengeInput.value = [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
        await check();
    });
    const take = async (list) => {
        for (const file of list) {
            const bytes = new Uint8Array(await file.arrayBuffer());
            if (file.name.endsWith(".cbor") && !proof) {
                proof = bytes;
            } else {
                files.set(file.name, bytes);
            }
        }
        await check();
    };
    proofInput.addEventListener("change", async () => {
        proof = null;
        await take(proofInput.files);
    });
    filesInput.addEventListener("change", async () => {
        for (const file of filesInput.files) {
            files.set(file.name, new Uint8Array(await file.arrayBuffer()));
        }
        await check();
    });
    ledgerInput.addEventListener("change", check);
    challengeInput.addEventListener("change", check);
    const drop = el("section", { class: "drop", "aria-label": t("verify.drop") },
                    el("p", { text: t("verify.drop") }));
    drop.addEventListener("dragover", (event) => {
        event.preventDefault();
        drop.classList.add("over");
    });
    drop.addEventListener("dragleave", () => drop.classList.remove("over"));
    drop.addEventListener("drop", async (event) => {
        event.preventDefault();
        drop.classList.remove("over");
        await take(event.dataTransfer.files);
    });
    show(el("h1", { text: t("verify.title") }), el("p", { text: t("verify.intro") }), drop,
         el("div", { class: "field" }, el("label", { for: "verify-proof", text: t("verify.proof") }),
            proofInput),
         el("div", { class: "field" }, el("label", { for: "verify-files", text: t("verify.with_files") }),
            filesInput),
         ledgerField, challengeField, result);
}

// --- Kinds and new documents --------------------------------------------------------

/// A kind's record type, suggested from its name (the user may change it):
/// the name in lower case, spaces as dashes, version 1.
function kindType(name) {
    const slug = name.trim().toLowerCase().replace(/\s+/g, "-");
    return slug ? `${slug}/1` : "";
}

async function kindsScreen() {
    const listed = await api("GET", "kinds");
    const parts = [el("h1", { text: t("kinds.title") }), el("p", { class: "hint", text: t("kinds.hint") })];
    if (listed.kinds.length === 0) {
        parts.push(el("p", { text: t("kinds.none") }));
    }
    for (const kind of listed.kinds) {
        const fields = el("ul", {}, kind.fields.map((f) => el("li", {
            text: t(f.private ? "kinds.field_private" : "kinds.field_public",
                    { name: f.label || f.name, type: t(`field.${f.type}`) }) +
                  (f.required ? t("kinds.required") : "") +
                  (f.provable ? t("kinds.provable_mark", { encoding: encodingText(encodingOf(f.provable)) }) : ""),
        })));
        const section = el("section", { class: "kind", "aria-labelledby": `kind-${kind.type}` },
                           el("h2", { id: `kind-${kind.type}`, text: kind.name }),
                           el("p", { class: "id", text: kind.type }),
                           kind.description ? el("p", { text: kind.description }) : null,
                           fields, el("p", { text: t(`kinds.files.${kind.files}`) }),
                           kind.printed?.length
                               ? el("p", { text: t("kinds.printed_list", { fields: kind.printed.join(", ") }) })
                               : null,
                           kind.answers?.length
                               ? el("p", { text: t("kinds.answers_list", { fields: kind.answers.join(", ") }) })
                               : null);
        if (listed.may_change) {
            const remove = el("button", { type: "button", text: t("kinds.remove"),
                                          "aria-label": t("kinds.remove_label", { name: kind.name }) });
            remove.addEventListener("click", async () => {
                await api("POST", "kinds", { remove: kind.type });
                route();
            });
            section.append(remove);
        }
        parts.push(section);
    }
    if (listed.may_change) {
        parts.push(kindForm());
    }
    show(...parts);
}

/// The form that defines a kind: a name, its fields, and its files.
function kindForm() {
    const [nameField, name] = field("kind-name", t("kinds.name"), t("kinds.name_hint"),
                                    { maxlength: 64 });
    const [typeField, type] = field("kind-type", t("kinds.type"), t("kinds.type_hint"),
                                    { maxlength: 128, spellcheck: "false" });
    let typed = false;
    type.addEventListener("input", () => { typed = true; });
    name.addEventListener("input", () => {
        if (!typed) {
            type.value = kindType(name.value);
        }
    });
    const rows = el("div", { class: "kind-fields" });
    let count = 0;
    const addRow = () => {
        count += 1;
        const n = count;
        const label = el("input", { id: `kind-field-${n}`, maxlength: 64,
                                    "aria-label": t("kinds.field_name", { n }) });
        const kindOf = el("select", { "aria-label": t("kinds.field_type", { n }) },
                          ["text", "number", "date", "yes-no"].map((v) =>
                              el("option", { value: v, text: t(`field.${v}`) })));
        const secret = el("input", { type: "checkbox", checked: true });
        const required = el("input", { type: "checkbox" });
        const printed = el("input", { type: "checkbox" });
        const answers = el("input", { type: "checkbox" });
        // A private number or date may be provable later without being
        // shown (v0.22): off by default; a number's decimal places, and its
        // currency if it is an amount of money.
        const provable = el("input", { type: "checkbox" });
        const places = el("input", { type: "number", min: 0, max: 18, value: 0, inputmode: "numeric",
                                     "aria-label": t("kinds.provable_places", { n }) });
        const currency = el("input", { type: "text", maxlength: 3, size: 4, spellcheck: "false",
                                       autocapitalize: "characters", placeholder: "HKD",
                                       "aria-label": t("kinds.provable_currency", { n }) });
        const numberPart = el("span", { class: "provable-number" },
                              el("label", {}, t("kinds.provable_places_label"), " ", places), " ",
                              el("label", {}, t("kinds.provable_currency_label"), " ", currency));
        const provablePart = el("span", {},
                                el("label", { class: "check" }, provable, " ", t("kinds.provable")),
                                numberPart);
        const redraw = () => {
            const kind = kindOf.value;
            provablePart.hidden = kind !== "number" && kind !== "date";
            if (provablePart.hidden) {
                provable.checked = false;
            }
            numberPart.hidden = kind !== "number" || !provable.checked;
        };
        kindOf.addEventListener("change", redraw);
        provable.addEventListener("change", () => {
            // What is proven without being shown is never public.
            if (provable.checked) {
                secret.checked = true;
            }
            redraw();
        });
        secret.addEventListener("change", () => {
            if (!secret.checked) {
                provable.checked = false;
                redraw();
            }
        });
        redraw();
        const row = el("fieldset", { class: "kind-field" },
                       el("legend", { text: t("kinds.field", { n }) }),
                       el("label", { for: `kind-field-${n}`, text: t("kinds.field_label") }), label,
                       kindOf,
                       el("label", { class: "check" }, secret, " ", t("kinds.private")),
                       el("label", { class: "check" }, required, " ", t("kinds.required_box")),
                       el("label", { class: "check" }, printed, " ", t("kinds.printed")),
                       el("label", { class: "check" }, answers, " ", t("kinds.answers")),
                       provablePart);
        const encoding = () => {
            if (!provable.checked || provablePart.hidden) {
                return null;
            }
            if (kindOf.value === "date") {
                return "date";
            }
            const scale = Math.max(0, Math.trunc(Number(places.value) || 0));
            const code = currency.value.trim().toUpperCase();
            return code ? `money:${code}:${scale}` : scale ? `number:${scale}` : "number";
        };
        row.read = () => ({ name: label.value.trim(), type: kindOf.value, private: secret.checked,
                            required: required.checked, printed: printed.checked,
                            answers: answers.checked, provable: encoding() });
        rows.append(row);
        label.focus();
    };
    const more = el("button", { type: "button", text: t("kinds.add_field") });
    more.addEventListener("click", addRow);
    const files = el("select", { id: "kind-files" },
                     ["optional", "required", "none"].map((v) =>
                         el("option", { value: v, text: t(`kinds.files.${v}`) })));
    const keep = el("input", { type: "checkbox", id: "kind-keep", checked: true });
    const notice = el("div");
    const save = el("button", { type: "submit", class: "primary", text: t("kinds.save") });
    const form = el("form", { novalidate: true, "aria-labelledby": "kind-new" },
                    el("h2", { id: "kind-new", text: t("kinds.new") }), nameField, typeField, rows,
                    more,
                    el("div", { class: "field" }, el("label", { for: "kind-files", text: t("kinds.files_label") }), files),
                    el("label", { class: "check" }, keep, " ", t("kinds.keep")), notice, save);
    addRow();
    form.addEventListener("submit", async (event) => {
        event.preventDefault();
        const fields = [...rows.children].map((r) => r.read()).filter((f) => f.name);
        try {
            await api("POST", "kinds", {
                sheet: 1, kind: "document", type: type.value.trim(), name: name.value.trim(),
                fields: fields.map((f) => ({ name: f.name, label: f.name, type: f.type,
                                             private: f.private, required: f.required,
                                             ...(f.provable ? { provable: f.provable } : {}) })),
                files: files.value, keep_files: keep.checked,
                ...(fields.some((f) => f.printed)
                    ? { printed: fields.filter((f) => f.printed).map((f) => f.name) } : {}),
                ...(fields.some((f) => f.answers)
                    ? { answers: fields.filter((f) => f.answers).map((f) => f.name) } : {}),
            });
            route();
        } catch (error) {
            notice.replaceChildren(problem(t("error.server", { message: error.message })));
        }
    });
    return form;
}

/// Registering a document: a kind, its fields, its files, then the tap.
async function newDocumentScreen(supersedes = null) {
    const listed = await api("GET", "kinds");
    const old = supersedes ? await api("GET", `records/${supersedes}`) : null;
    if (listed.kinds.length === 0) {
        show(el("h1", { text: t("register.title") }), el("p", { text: t("register.no_kinds") }),
             el("p", {}, el("a", { href: "#/kinds", text: t("register.define") })));
        return;
    }
    const chooser = el("select", { id: "register-kind" },
                       listed.kinds.map((k) => el("option", { value: k.type, text: k.name })));
    if (old && listed.kinds.some((k) => k.type === old.type)) {
        chooser.value = old.type;
    }
    const area = el("div");
    const notice = el("div");
    const inputs = new Map();
    let fileInput;
    const render = () => {
        const kind = listed.kinds.find((k) => k.type === chooser.value);
        inputs.clear();
        const parts = kind.fields.map((f, i) => {
            const id = `register-field-${i}`;
            let input;
            if (f.type === "yes-no") {
                input = el("select", { id }, el("option", { value: "", text: "" }),
                           el("option", { value: "yes", text: t("value.yes") }),
                           el("option", { value: "no", text: t("value.no") }));
            } else {
                input = el("input", { id, type: f.type === "date" ? "date" : "text",
                                      inputmode: f.type === "number" ? "decimal" : null,
                                      required: f.required, maxlength: 4096 });
            }
            inputs.set(f.name, input);
            return el("div", { class: "field" },
                      el("label", { for: id, text: (f.label || f.name) +
                                                   (f.required ? t("register.required_mark") : "") }),
                      input,
                      el("span", { class: "hint", text: t(f.private ? "register.private_hint"
                                                                    : "register.public_hint") }),
                      // Provable later without being shown (v0.22).
                      f.provable ? el("span", { class: "hint", text: t("register.provable_hint", {
                          encoding: encodingText(encodingOf(f.provable)) }) }) : null);
        });
        if (kind.files !== "none") {
            fileInput = el("input", { id: "register-files", type: "file", multiple: true,
                                      required: kind.files === "required" });
            parts.push(el("div", { class: "field" },
                          el("label", { for: "register-files", text: t("register.files") }),
                          fileInput,
                          el("span", { class: "hint", text: t(kind.keep_files ? "register.files_kept"
                                                                              : "register.files_not_kept") })));
        } else {
            fileInput = null;
        }
        area.replaceChildren(...parts);
    };
    chooser.addEventListener("change", render);
    render();
    const madeFrom = await madeFromPart();
    const prepare = el("button", { type: "submit", class: "primary", text: t("act.prepare") });
    const form = el("form", { novalidate: true },
                    old ? el("p", { class: "notice", text: t("register.replaces_hint", {
                        name: old.kind ?? old.type, id: old.id }) }) : null,
                    el("div", { class: "field" },
                       el("label", { for: "register-kind", text: t("register.kind") }), chooser),
                    area, madeFrom.part, notice, prepare);
    form.addEventListener("submit", async (event) => {
        event.preventDefault();
        prepare.disabled = true;
        status(t("status.working"));
        try {
            const fields = {};
            for (const [name, input] of inputs) {
                if (input.value.trim()) {
                    fields[name] = input.value.trim();
                }
            }
            // Each file uploaded, and kept here too: the page checks its
            // commitment before the tap.
            const files = new Map();
            const uploads = [];
            for (const file of fileInput?.files ?? []) {
                if (file.size > 16 * 1024 * 1024) {
                    throw new ApiError(413, t("register.too_large", { name: file.name }));
                }
                const id = await uploadFile(file);
                uploads.push(id);
                files.set(id, new Uint8Array(await file.arrayBuffer()));
            }
            // Where it came from: the sources' proofs uploaded, checked and
            // kept by the console with the record.
            const { sources, proofs, script } = madeFrom.read();
            const sourceProofs = [];
            for (const proof of proofs) {
                sourceProofs.push(await uploadFile(proof));
            }
            const prepared = await api("POST", "prepare", {
                action: "record.register", kind: chooser.value, fields, files: uploads,
                supersedes: old ? old.id : null, sources, source_proofs: sourceProofs, script,
            });
            await approveScreen(prepared, files);
        } catch (error) {
            notice.replaceChildren(problem(error.status === 423 ? t("keys.locked")
                                                                : t("error.server", { message: error.message })));
        } finally {
            prepare.disabled = false;
            status("");
        }
    });
    show(el("h1", { text: t(old ? "register.new_version_title" : "register.title") }), form);
}

/// What a new document was made from (v0.18), all optional: records of
/// this ledger, chosen from its live ones; another ledger's, by its id and
/// the record's, with its proof (that ledger's evidence of it) if there is
/// one, which the console checks and keeps with the record; and the
/// approved script that made it.
async function madeFromPart() {
    const made = await api("GET", "sources").catch(() => ({ records: [], scripts: [] }));
    const chosen = [];
    const list = el("ul", { "aria-live": "polite" });
    const render = () => {
        list.replaceChildren(...chosen.map((c, i) => {
            const remove = el("button", { type: "button", text: t("register.source_remove"),
                                          "aria-label": t("register.source_remove_label", { name: c.label }) });
            remove.addEventListener("click", () => {
                chosen.splice(i, 1);
                render();
            });
            return el("li", {}, `${c.label} `, remove);
        }));
    };
    const sourceNotice = el("div", { role: "status" });
    const local = el("select", { id: "register-source" }, el("option", { value: "", text: "" }),
                     made.records.map((r) => el("option", {
                         value: r.id, text: t("register.source_option", {
                             name: r.kind ?? r.type, id: r.id.slice(0, 12), index: r.index }) })));
    const addLocal = el("button", { type: "button", text: t("register.source_add") });
    addLocal.addEventListener("click", () => {
        const r = made.records.find((x) => x.id === local.value);
        if (r && !chosen.some((c) => c.record === r.id)) {
            chosen.push({ ledger: null, record: r.id, proof: null,
                          label: t("approve.source_local", { name: r.kind ?? r.type, id: r.id.slice(0, 12) }) });
            render();
        }
    });
    const [ledgerField, ledgerInput] = field("register-source-ledger", t("register.source_ledger"),
                                             t("register.source_ids_hint"), { maxlength: 64, spellcheck: "false" });
    const [recordField, recordInput] = field("register-source-record", t("register.source_record"),
                                             t("register.source_ids_hint"), { maxlength: 64, spellcheck: "false" });
    const proofInput = el("input", { id: "register-source-proof", type: "file", accept: ".cbor,application/cbor" });
    const addOther = el("button", { type: "button", text: t("register.source_add_other") });
    addOther.addEventListener("click", async () => {
        sourceNotice.replaceChildren();
        let ledger = ledgerInput.value.trim().toLowerCase();
        let record = recordInput.value.trim().toLowerCase();
        const proof = proofInput.files[0] ?? null;
        let label = null;
        if (proof) {
            // What the proof is of, checked in this browser where it can be.
            const check = await loadChecker();
            const report = check ? check.verify(new Uint8Array(await proof.arrayBuffer()), new Map(), "") : null;
            if (report?.record?.id && report?.ledger?.id && !report.error) {
                ledger ||= report.ledger.id;
                record ||= report.record.id;
                label = t("register.source_other_named", { type: report.record.type,
                                                           ledger: report.ledger.organization,
                                                           id: report.record.id.slice(0, 12) });
            }
        }
        if (!/^[0-9a-f]{64}$/.test(ledger) || !/^[0-9a-f]{64}$/.test(record)) {
            sourceNotice.replaceChildren(problem(t("register.source_ids")));
            return;
        }
        if (chosen.some((c) => c.record === record && c.ledger === ledger)) {
            return;
        }
        chosen.push({ ledger, record, proof,
                      label: (label ?? t("approve.source_other", { id: record.slice(0, 12), ledger: ledger.slice(0, 12) })) +
                          (proof ? t("register.source_with_proof") : "") });
        ledgerInput.value = "";
        recordInput.value = "";
        proofInput.value = "";
        render();
    });
    const script = el("select", { id: "register-script" },
                      el("option", { value: "", text: t("register.script_none") }),
                      made.scripts.map((s) => el("option", { value: s.id, text: `${s.name} ${s.version}` })));
    const part = el("fieldset", {}, el("legend", { text: t("register.made_from") }),
                    el("p", { class: "hint", text: t("register.made_from_hint") }), list,
                    made.records.length
                        ? el("div", { class: "field" },
                             el("label", { for: "register-source", text: t("register.source_local") }),
                             local, " ", addLocal)
                        : null,
                    el("details", {}, el("summary", { text: t("register.source_other") }),
                       ledgerField, recordField,
                       el("div", { class: "field" },
                          el("label", { for: "register-source-proof", text: t("register.source_proof") }),
                          proofInput,
                          el("span", { class: "hint", text: t("register.source_proof_hint") })),
                       addOther),
                    sourceNotice,
                    el("div", { class: "field" },
                       el("label", { for: "register-script", text: t("register.script") }), script,
                       el("span", { class: "hint", text: t("register.script_hint") })));
    return {
        part,
        read: () => ({
            sources: chosen.map((c) => (c.ledger ? { ledger: c.ledger, record: c.record } : { record: c.record })),
            proofs: chosen.filter((c) => c.proof).map((c) => c.proof),
            script: script.value || null,
        }),
    };
}

// --- Settings ----------------------------------------------------------------------

async function settingsScreen() {
    const settings = await api("GET", "settings");
    const parts = [el("h1", { text: t("settings.title") })];
    const ledger = settings.ledger;
    parts.push(el("h2", { text: t("settings.ledger") }));
    if (ledger) {
        parts.push(el("dl", { class: "facts" },
                      el("dt", { text: t("home.organization") }),
                      el("dd", { text: ledger.organization }),
                      el("dt", { text: t("home.ledger") }), el("dd", { class: "id", text: ledger.id }),
                      el("dt", { text: t("settings.entries") }),
                      el("dd", { text: String(ledger.entries) }),
                      el("dt", { text: t("settings.hash") }), el("dd", { text: ledger.hash }),
                      el("dt", { text: t("settings.directory") }),
                      el("dd", { class: "id", text: settings.directory })));
    } else {
        parts.push(el("p", { class: "hint", text: t("home.locked") }));
    }

    parts.push(el("h2", { text: t("settings.language") }),
               el("p", { class: "hint", text: t("settings.language_here") }));
    const notice = el("div", { role: "status" });
    const changeable = settings.may_change;
    const language = el("select", { id: "default-language", disabled: !changeable },
                        el("option", { value: "", text: t("settings.browser_language") }),
                        settings.languages.map((l) => el("option", {
                            value: l, lang: l,
                            text: document.querySelector(`#language option[value="${l}"]`)
                                ?.textContent ?? l,
                        })));
    language.value = settings.language ?? "";
    parts.push(el("div", { class: "field" },
                  el("label", { for: "default-language", text: t("settings.default_language") }),
                  language));

    parts.push(el("h2", { text: t("settings.backups") }));
    const [folderField, folder] = field("settings-backup", t("backup.folder"),
                                        t("backup.folder_hint"),
                                        { value: settings.backup_folder ?? "",
                                          placeholder: settings.suggested_backup_folder,
                                          disabled: !changeable });
    parts.push(folderField, el("p", { class: "hint", text: t("settings.backup_note") }),
               backupStatus(settings.backup ?? {}));
    if (settings.may_change) {
        const now = el("button", { type: "button", text: t("settings.back_up_now") });
        const said = el("div", { role: "status" });
        now.addEventListener("click", async () => {
            now.disabled = true;
            status(t("status.working"));
            try {
                said.replaceChildren(backupStatus(await api("POST", "backup", {})));
            } catch (error) {
                said.replaceChildren(problem(t("settings.backup_problem", { problem: error.message })));
            } finally {
                now.disabled = false;
                status("");
            }
        });
        parts.push(now, said);
    }
    if (changeable) {
        const save = el("button", { type: "button", class: "primary", text: t("settings.save") });
        save.addEventListener("click", async () => {
            save.disabled = true;
            try {
                const typed = folder.value.trim();
                const saved = await api("POST", "settings", {
                    language: language.value === "" ? null : language.value,
                    backup_folder: typed === "" ? null : typed,
                });
                state.defaultLanguage = saved.language;
                notice.replaceChildren(el("p", { text: t("settings.saved") }));
            } catch (error) {
                notice.replaceChildren(problem(t("error.server", { message: error.message })));
            } finally {
                save.disabled = false;
            }
        });
        parts.push(notice, save);
    } else {
        parts.push(el("p", { class: "hint", text: t("settings.read_only") }));
    }

    parts.push(el("h2", { text: t("settings.keys") }),
               el("p", { id: "keys-state", text: t(`settings.keys_state.${settings.keys}`) }));
    if (changeable && settings.keys === "unlocked") {
        const lock = el("button", { type: "button", text: t("settings.lock") });
        lock.addEventListener("click", async () => {
            const result = await api("POST", "unlock", { lock: true });
            state.who.keys = result.keys;
            route();
        });
        parts.push(lock);
    }
    parts.push(...await longTermView());
    parts.push(...await guardiansView());
    if (changeable) {
        parts.push(archivesView(), ...await tokensView(), ...await activityView());
    }
    show(flash(), keysNotice(), ...parts);
}

// --- Archives that keep this ledger ------------------------------------------------

/// Why an archive is not added, or what is wrong with one listed: the
/// console's codes, each in the catalogs.
const ARCHIVE_PROBLEMS = ["not_address", "listed", "full", "too_long", "unreachable", "not_checkpoint",
                          "other_ledger", "not_ours"];

/// Settings, "Archives that keep this ledger": trust nodes that keep a copy
/// of it and its published records' evidence, and answer them once its own
/// server is gone; certificates' links printed after one is added name it.
/// Each listed with the latest copy it answers, which the console checks is
/// one this ledger made; added by its address, and removed. The archives are
/// asked as the screen opens, so the section fills in when they answer.
function archivesView() {
    const area = el("section", { id: "archives", "aria-labelledby": "archives-title", "aria-live": "polite" });
    const head = [el("h2", { id: "archives-title", text: t("archives.title") }),
                  el("p", { class: "hint", text: t("archives.intro") }),
                  el("p", { class: "hint", id: "archives-hint", text: t("archives.hint") })];
    area.replaceChildren(...head, el("p", { class: "hint", text: t("archives.checking") }));
    const said = el("div", { role: "status" });
    const refusal = (error, ledger) => {
        const code = error.answer?.error?.code;
        if (error.status === 423) {
            return t("keys.locked");
        }
        return ARCHIVE_PROBLEMS.includes(code)
            ? t(`archives.refused.${code}`, { ledger, message: error.answer.error.detail || error.message })
            : t("error.server", { message: error.message });
    };
    const fill = (listed) => {
        const parts = [...head];
        if (listed.problem) {
            parts.push(el("p", { class: "problem warning", text: t("archives.damaged", { message: listed.problem }) }));
        }
        if (listed.archives.length === 0) {
            parts.push(el("p", { id: "archives-none", text: t("archives.none") }));
        } else {
            parts.push(...table(t("archives.listed"), [
                ["archives.address", (a) => ({ id: true, text: a.url })],
                ["archives.latest", (a) => (a.size !== null && a.size !== undefined
                    ? t("archives.copy", { size: a.size, time: timeText(a.time) })
                    : t(`archives.problem.${ARCHIVE_PROBLEMS.includes(a.problem) ? a.problem : "unreachable"}`,
                        { message: a.detail ?? a.message ?? "" }))],
                ["archives.added_at", (a) => timeText(a.added)],
                ["archives.remove", (a) => {
                    const remove = el("button", { type: "button", text: t("archives.remove"),
                                                  "aria-label": t("archives.remove_label", { url: a.url }) });
                    remove.addEventListener("click", async () => {
                        remove.disabled = true;
                        status(t("status.working"));
                        try {
                            await api("POST", "archives", { remove: a.url });
                            state.flash = t("archives.removed", { url: a.url });
                            route();
                        } catch (error) {
                            said.replaceChildren(problem(refusal(error, listed.ledger)));
                            remove.disabled = false;
                        } finally {
                            status("");
                        }
                    });
                    return remove;
                }],
            ], listed.archives));
        }
        if (listed.archives.length >= listed.max) {
            parts.push(el("p", { class: "hint", text: t("archives.full", { max: listed.max }) }), said);
            area.replaceChildren(...parts);
            return;
        }
        const [urlField, url] = field("archive-url", t("archives.url"),
                                      t("archives.url_hint", { ledger: listed.ledger }),
                                      { type: "url", placeholder: "https://", spellcheck: "false" });
        const add = el("button", { type: "submit", text: t("archives.add") });
        const form = el("form", { novalidate: true }, urlField, add, said);
        form.addEventListener("submit", async (event) => {
            event.preventDefault();
            add.disabled = true;
            status(t("status.working"));
            try {
                const added = await api("POST", "archives", { url: url.value.trim() });
                state.flash = t("archives.added", { url: added.added, size: added.size });
                route();
            } catch (error) {
                said.replaceChildren(problem(refusal(error, listed.ledger)));
            } finally {
                add.disabled = false;
                status("");
            }
        });
        parts.push(form);
        area.replaceChildren(...parts);
    };
    api("GET", "archives").then(fill, (error) => {
        area.replaceChildren(...head, problem(t("error.server", { message: error.message })));
    });
    return area;
}

// --- Evidence for decades -----------------------------------------------------------

/// Whether an algorithm, as the console names it, is post-quantum (ML-DSA).
const postQuantum = (algorithm) => /^ML-DSA/i.test(algorithm ?? "");

/// A proof's long-term status (spec v0.21), as a verifier reports it, in
/// words.
function longTermWords(lt) {
    if (!lt) {
        return "";
    }
    if (!lt.post_quantum) {
        return t("long_term.proof_not_yet", { date: (lt.renew_before ?? "2030-01-01").slice(0, 10) });
    }
    const who = [...new Set((lt.attested_by ?? []).map((a) => t(`long_term.by.${a.kind}`)))]
        .join(t("approvals.separator"));
    return t("long_term.proof_safe", { who, size: lt.checkpoint?.tree_size ?? "" });
}

/// Settings, "Keep records verifiable for decades": the ledger's long-term
/// status in words and, while its keys are today's, preparing it for the
/// long term (two passkey taps, then a checkpoint the console makes).
async function longTermView() {
    const lt = await api("GET", "long-term").catch(() => null);
    if (!lt || !lt.status) {
        return [];
    }
    const s = lt.status;
    const parts = [el("h2", { id: "long-term-title", text: t("long_term.title") }),
                   el("p", { class: "hint", text: t("long_term.intro") })];
    const said = s.genesis_post_quantum ? t("long_term.born")
        : s.post_quantum ? t("long_term.converted")
        : t("long_term.classical", { root: s.root_key.algorithm, log: s.log_key.algorithm });
    parts.push(el("p", { id: "long-term-status", role: "status", text: said }));
    const facts = el("dl", { class: "facts" },
                     el("dt", { text: t("long_term.top_key") }),
                     el("dd", { text: t(s.root_key.post_quantum ? "long_term.key_long" : "long_term.key_today",
                                        { algorithm: s.root_key.algorithm }) }),
                     el("dt", { text: t("long_term.log_key") }),
                     el("dd", { text: t(s.log_key.post_quantum ? "long_term.key_long" : "long_term.key_today",
                                        { algorithm: s.log_key.algorithm }) }));
    const w = s.last_post_quantum_cosignature;
    if (w || !s.genesis_post_quantum) {
        facts.append(el("dt", { text: t("long_term.witness") }),
                     el("dd", { text: w ? t("long_term.witness_last", { size: w.tree_size,
                                                                        time: isoText(w.time ?? w.checkpoint_time) })
                                        : t("long_term.witness_none") }));
    }
    parts.push(facts);
    for (const c of s.certificates_expiring ?? []) {
        parts.push(el("p", { class: "notice", text: t(c.days_left < 0 ? "long_term.certificate_expired"
                                                                      : "long_term.certificate", {
            authority: c.authority, date: isoText(c.not_after), days: c.days_left }) }));
    }
    // The conversion's steps, for a ledger that began with today's keys.
    if (!s.genesis_post_quantum) {
        const held = new Map((lt.held ?? []).map((h) => [h.step, h.id]));
        parts.push(el("h3", { text: t("long_term.steps") }),
                   el("ol", { class: "steps" }, lt.steps.map((step) => {
                       const progress = held.has(step.step) ? "waiting"
                           : step.status === "planned" ? "planned" : "done";
                       const now = step.step !== "checkpoint" && progress !== "done" && step.from
                           ? t("long_term.now", { algorithm: step.from.algorithm }) : "";
                       return el("li", { "data-step": step.step }, `${t(`long_term.step.${step.step}`)}${now}`,
                                 t("long_term.step_separator"),
                                 el("span", { class: "hint", text: t(`long_term.state.${progress}`) }));
                   })));
    }
    const notice = el("div", { role: "status" });
    if (lt.next) {
        if (lt.may_convert) {
            const button = el("button", { type: "button", class: "primary", id: "long-term-prepare",
                                          text: t("long_term.prepare") });
            button.addEventListener("click", () => prepareLongTerm(lt, notice, button));
            parts.push(el("p", { class: "hint", text: t("long_term.prepare_hint") }),
                       lt.guardians ? el("p", { class: "hint", text: t("long_term.guardians_hint") }) : null,
                       notice, button);
        } else if (lt.why_not) {
            const held = lt.held?.[0];
            parts.push(el("p", { class: "notice" }, t(`long_term.why_not.${lt.why_not}`),
                          held ? " " : null,
                          held ? el("a", { href: `#/approval/${held.id}`, text: t("guardians.open_waiting") }) : null));
        }
    } else if (s.post_quantum && !s.genesis_post_quantum) {
        parts.push(el("p", { class: "hint" }, t("long_term.renew_old"), " ",
                      el("a", { href: "#/renew", text: t("renew.link") })));
    }
    return parts.filter((p) => p !== null);
}

/// Prepares the ledger for the long term: each new key confirmed with the
/// passkey (signed by the organization), then the checkpoint, which the
/// console makes. A new key that waits for the guardians is taken further
/// by the console itself once they have approved it.
async function prepareLongTerm(lt, notice, button) {
    const rotations = lt.remaining.filter((step) => step !== "checkpoint").length;
    const finish = async () => {
        const after = await api("POST", "long-term/checkpoint", {});
        return el("p", { class: "notice", id: "long-term-done",
                         text: t(after.status?.post_quantum ? "long_term.done" : "long_term.checkpoint_made") });
    };
    const step = async (index) => {
        const prepared = await api("POST", "prepare", { action: "long-term.convert" });
        if (rotations > 1) {
            prepared.progress = { index, of: rotations };
        }
        prepared.continues = "long_term.continues";
        await approveScreen(prepared, new Map(), async () => {
            const now = await api("GET", "long-term");
            if (now.next === "rotate-log-key" || now.next === "rotate-root-key") {
                await step(index + 1);
                return TAKEN;
            }
            // Both keys are long-term keys: the checkpoint with the new log
            // key (made unless the latest covers everything already).
            return finish();
        });
    };
    button.disabled = true;
    try {
        if (lt.next === "checkpoint") {
            notice.replaceChildren(await finish());
            return;
        }
        await step(1);
    } catch (error) {
        notice.replaceChildren(problem(error.status === 423 ? t("keys.locked")
                                                            : t("error.server", { message: error.message })));
    } finally {
        button.disabled = false;
    }
}

/// A proof file someone brings back, renewed with this ledger's newest
/// attested checkpoint (spec v0.21): nothing in it changes.
const RENEW_REFUSALS = ["other_ledger", "not_attested", "not_a_proof", "nothing_new"];

function renewScreen() {
    const input = el("input", { type: "file", id: "renew-file", accept: ".cbor,application/cbor" });
    const notice = el("div", { role: "status", "aria-live": "polite" });
    const button = el("button", { type: "submit", class: "primary", text: t("renew.button") });
    const form = el("form", { novalidate: true },
                    el("div", { class: "field" }, el("label", { for: "renew-file", text: t("renew.file") }), input),
                    notice, button, " ", backButton(t("nav.things")));
    form.addEventListener("submit", async (event) => {
        event.preventDefault();
        const file = input.files?.[0];
        if (!file) {
            notice.replaceChildren(problem(t("renew.no_file")));
            return;
        }
        button.disabled = true;
        status(t("status.working"));
        try {
            const upload = await uploadFile(file);
            const renewed = await api("POST", "long-term/renew", { upload });
            saveBytes(fromBase64url(renewed.file), renewed.name);
            notice.replaceChildren(
                el("p", { class: "notice", id: "renew-done", text: t("renew.done", {
                    name: renewed.name, size: renewed.tree_size, time: isoText(renewed.timestamp) }) }),
                el("p", { id: "renew-long-term", text: longTermWords(renewed.long_term) }),
                // Its range proofs (v0.22), kept by the renewal and checked.
                ...(renewed.range_proofs?.length
                    ? [el("p", { text: t("renew.range_proofs") }),
                       el("ul", { class: "ranges" }, renewed.range_proofs.map((p) => rangeLine(p)))]
                    : []),
                el("p", { class: "hint", text: t("renew.send") }));
        } catch (error) {
            const code = error.answer?.error?.code;
            notice.replaceChildren(problem(RENEW_REFUSALS.includes(code) ? t(`renew.${code}`)
                                                                         : t("error.server", { message: error.message })));
        } finally {
            button.disabled = false;
            status("");
        }
    });
    show(el("h1", { text: t("renew.title") }), el("p", { text: t("renew.intro") }), form);
}

/// The organization's guardians (spec v0.20): who must approve what the
/// organization signs with its top key, and, for an owner, setting them:
/// prepared here, confirmed by the owner, then approved by the new
/// guardians (and by the current ones, when changing them) before it takes
/// effect.
async function guardiansView() {
    const g = await api("GET", "guardians").catch(() => null);
    if (!g) {
        return [];
    }
    const parts = [el("h2", { text: t("guardians.title") }), el("p", { class: "hint", text: t("guardians.intro") })];
    const guardText = (guarded) => (guarded
        ? guarded.map((type) => t(`approve.type.${type}`)).join(t("approvals.separator"))
        : t("guardians.everything"));
    if (g.in_effect) {
        const e = g.in_effect;
        parts.push(el("p", { role: "status", text: t("guardians.in_effect", {
            k: e.k, n: e.guardians.length, names: e.guardians.map(nameOf).join(t("approvals.separator")),
            index: e.since }) }),
                   el("dl", { class: "facts" },
                      el("dt", { text: t("guardians.guard") }), el("dd", { text: guardText(e.guarded) }),
                      el("dt", { text: t("guardians.within") }), el("dd", { text: windowText(e.within) })));
        const few = e.guardians.filter((x) => x.passkeys < 2);
        if (few.length) {
            parts.push(el("p", { class: "notice", text: t("guardians.second_passkey", {
                names: few.map(nameOf).join(t("approvals.separator")) }) }));
        }
    } else {
        parts.push(el("p", { text: t("guardians.none") }));
    }
    for (const w of g.waiting) {
        parts.push(el("p", { class: "notice" }, t("guardians.waiting"), " ",
                      el("a", { href: `#/approval/${w.id}`, text: t("guardians.open_waiting") })));
    }
    if (!g.may_change) {
        return parts;
    }
    // Setting them: who, how many, within how long, what they guard.
    const notice = el("div", { role: "status" });
    const boxes = g.people.map((person) => {
        const box = el("input", { type: "checkbox", value: person.id,
                                  checked: Boolean(g.in_effect?.guardians.some((x) => x.id === person.id)) });
        return [box, el("div", {}, el("label", {}, box, " ", t(person.passkeys < 2 ? "guardians.person_one_passkey"
                                                                                  : "guardians.person", {
            name: person.name, n: person.passkeys })))];
    });
    const count = el("input", { type: "number", id: "guardians-k", min: 1, max: 16, inputmode: "numeric",
                                value: g.in_effect?.k ?? 2 });
    const days = el("input", { type: "number", id: "guardians-days", min: 1, max: 30, inputmode: "numeric",
                               value: g.in_effect ? Math.max(1, Math.round(g.in_effect.within / 86400000)) : 7 });
    const everything = el("input", { type: "radio", name: "guardians-guard", id: "guardians-everything",
                                     checked: !g.in_effect?.guarded });
    const some = el("input", { type: "radio", name: "guardians-guard", id: "guardians-some",
                               checked: Boolean(g.in_effect?.guarded) });
    const types = g.types.map((type) => {
        const box = el("input", { type: "checkbox", value: type,
                                  checked: Boolean(g.in_effect?.guarded?.includes(type)) });
        return [box, el("div", {}, el("label", {}, box, " ", t(`approve.type.${type}`)))];
    });
    const typesPart = el("div", { hidden: !some.checked }, types.map(([, v]) => v));
    for (const radio of [everything, some]) {
        radio.addEventListener("change", () => { typesPart.hidden = !some.checked; });
    }
    const spare = el("input", { type: "checkbox", id: "guardians-no-spare" });
    const prepare = el("button", { type: "submit", class: "primary", text: t("guardians.prepare") });
    const form = el("form", { novalidate: true },
        el("fieldset", {}, el("legend", { text: t("guardians.who") }), boxes.map(([, v]) => v)),
        el("div", { class: "field" }, el("label", { for: "guardians-k", text: t("guardians.k") }), count,
           el("span", { class: "hint", text: t("guardians.k_hint") })),
        el("div", { class: "field" }, el("label", { for: "guardians-days", text: t("guardians.within") }), days,
           el("span", { class: "hint", text: t("guardians.within_hint") })),
        el("fieldset", {}, el("legend", { text: t("guardians.guard") }),
           el("div", {}, el("label", { for: "guardians-everything" }, everything, " ", t("guardians.guard_everything"))),
           el("div", {}, el("label", { for: "guardians-some" }, some, " ", t("guardians.guard_some"))), typesPart),
        el("div", { class: "notice" },
           el("p", { text: t("guardians.warning_lockout") }),
           el("p", { text: t("guardians.warning_spare") }),
           el("p", { text: t("guardians.warning_passkeys") }),
           el("p", { text: t("guardians.warning_work", { work: g.organization_work.map((w) => t(`guardians.work.${w}`))
               .join(t("approvals.separator")) }) })),
        el("div", {}, el("label", { for: "guardians-no-spare" }, spare, " ", t("guardians.no_spare"))),
        notice, prepare);
    form.addEventListener("submit", async (event) => {
        event.preventDefault();
        const chosen = boxes.filter(([box]) => box.checked).map(([box]) => box.value);
        try {
            await approveScreen(await api("POST", "prepare", {
                action: "guardians.set", k: Number(count.value), guardians: chosen,
                within_days: Number(days.value), no_spare: spare.checked,
                guarded: some.checked ? types.filter(([box]) => box.checked).map(([box]) => box.value) : null,
            }));
        } catch (error) {
            notice.replaceChildren(problem(error.status === 423 ? t("keys.locked")
                                                                : t("error.server", { message: error.message })));
        }
    });
    parts.push(el("h3", { text: t(g.in_effect ? "guardians.change_title" : "guardians.set_title") }), form);
    if (g.in_effect) {
        const removed = el("div", { role: "status" });
        const remove = el("button", { type: "button", text: t("guardians.remove") });
        remove.addEventListener("click", async () => {
            try {
                await approveScreen(await api("POST", "prepare", { action: "guardians.remove" }));
            } catch (error) {
                removed.replaceChildren(problem(t("error.server", { message: error.message })));
            }
        });
        parts.push(el("p", { class: "hint", text: t("guardians.remove_hint") }), remove, removed);
    }
    return parts;
}

/// API tokens for programs (as `token create|list|revoke`).
async function tokensView() {
    const listed = await api("GET", "tokens");
    const shown = el("div", { role: "status" });
    const parts = [el("h2", { text: t("tokens.title") }), el("p", { class: "hint", text: t("tokens.intro") })];
    parts.push(...table(t("tokens.list"), [
        ["column.name", (k) => k.name],
        ["tokens.scopes", (k) => k.scopes.map((x) => t(`tokens.scope.${x}`)).join(", ")],
        ["tokens.created", (k) => timeText(k.created)],
        ["column.actions", (k) => {
            const revoke = el("button", { type: "button", text: t("tokens.revoke"),
                                          "aria-label": t("tokens.revoke_label", { name: k.name }) });
            revoke.addEventListener("click", async () => {
                try {
                    await api("POST", "tokens", { revoke: k.name });
                    route();
                } catch (error) {
                    shown.replaceChildren(problem(t("error.server", { message: error.message })));
                }
            });
            return revoke;
        }],
    ], listed.tokens));
    const [nameField, name] = field("token-name", t("column.name"), t("tokens.name_hint"), { maxlength: 64 });
    const boxes = ["read", "submit", "executor", "admin"].map((x) => {
        const box = el("input", { type: "checkbox", value: x, checked: x === "read" });
        return [box, el("label", {}, box, " ", t(`tokens.scope.${x}`))];
    });
    const create = el("button", { type: "submit", text: t("tokens.create") });
    const form = el("form", { novalidate: true }, nameField,
                    el("fieldset", {}, el("legend", { text: t("tokens.scopes") }),
                       boxes.map(([, label]) => el("div", {}, label))), create, shown);
    form.addEventListener("submit", async (event) => {
        event.preventDefault();
        try {
            const made = await api("POST", "tokens", {
                create: name.value.trim(),
                scopes: boxes.filter(([b]) => b.checked).map(([b]) => b.value),
            });
            const box = el("textarea", { readonly: true, rows: 2, class: "id",
                                         "aria-label": t("tokens.made", { name: made.name }) });
            box.value = made.token;
            shown.replaceChildren(el("p", { text: t("tokens.made", { name: made.name }) }), box,
                                  el("p", { class: "hint", text: t("tokens.once") }));
        } catch (error) {
            shown.replaceChildren(problem(t("error.server", { message: error.message })));
        }
    });
    parts.push(form);
    return parts;
}

/// What people changed in the console, newest first.
async function activityView() {
    const listed = await api("GET", "activity");
    const detail = (a) => Object.entries(a.detail ?? {})
        .filter(([k]) => k !== "statement")
        .map(([k, v]) => `${k}: ${Array.isArray(v) ? v.join(", ") : v ?? ""}`).join("; ");
    return table(t("activity.title"), [
        ["activity.at", (a) => timeText(a.at)],
        ["activity.who", (a) => a.user],
        ["activity.what", (a) => t(`activity.${a.action}`)],
        ["activity.detail", (a) => detail(a)],
    ], listed.activity.slice(0, 50));
}

// --- Automation ------------------------------------------------------------------------

/// A file to save, from bytes the page holds.
function saveBytes(bytes, name) {
    const url = URL.createObjectURL(new Blob([bytes]));
    const link = el("a", { href: url, download: name });
    document.body.append(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
}

/// What a machine's delegation lets it do, in plain words.
function machineWords(d, listed) {
    if (d.request_kinds) {
        const rules = (d.contracts ?? []).map((c) => c.name ?? `${c.id.slice(0, 12)}...`).join(", ");
        return t(d.revoked ? "automation.answers_withdrawn" : "automation.answers_under",
                 { kinds: d.request_kinds.join(", "), rules });
    }
    const words = mayWords({ ...d.may, in_person: false, revoked: d.revoked }, listed);
    return words;
}

/// Certificates: the kinds that print fields, the certificates published
/// (each with its QR code, its page to print, and Withdraw), and a table
/// issued by the console's machine once a passkey approves the batch.
async function certificatesScreen() {
    const listed = await api("GET", "certificates");
    const notice = el("div", { role: "status" });
    const parts = [flash(), el("h1", { text: t("certificates.title") }),
                   el("p", { class: "hint", text: t("certificates.intro") })];
    if (!listed.reachable) {
        parts.push(el("p", { class: "notice", text: t("certificates.unreachable", { address: listed.address || "-" }) }));
    }
    if (listed.kinds.length === 0) {
        parts.push(el("p", { text: t("certificates.no_kinds") }),
                   el("p", {}, el("a", { href: "#/kinds", text: t("certificates.to_kinds") })));
        show(...parts);
        return;
    }
    parts.push(...table(t("certificates.kinds"), [
        ["column.name", (k) => k.name],
        ["certificates.printed", (k) => k.printed.join(", ")],
        ["certificates.by_console", (k) => (k.granted ? t("certificates.allowed_yes")
            : listed.may_grant ? allowButton(k, notice) : t("certificates.allowed_not_yet"))],
    ], listed.kinds));
    parts.push(credentialsSection(listed, notice));
    parts.push(...table(t("certificates.list"), [
        ["certificates.printed", (c) => c.fields.map((f) => f.value).join(" · ")],
        ["certificates.kind", (c) => c.kind],
        ["certificates.issued", (c) => c.issued],
        ["certificates.status", (c) => t(`certificates.status.${c.status}`)],
        ["column.actions", (c) => certificateActions(c, listed, notice)],
    ], listed.certificates));
    parts.push(notice);
    if (listed.may_issue) {
        parts.push(issueForm(listed));
    }
    show(...parts);
}

/// Certificates as W3C credentials, for digital wallets: on once an owner
/// gives the console a credential key (two taps: the device, then what it
/// may do), each certificate then downloads as one.
function credentialsSection(listed, notice) {
    const c = listed.credentials || { state: "off" };
    const section = el("section", {}, el("h2", { text: t("credentials.title") }));
    if (c.state === "on") {
        section.append(el("p", { class: "hint", text: t("credentials.on_intro", { issuer: c.issuer ?? "-" }) }));
        if (c.problem) {
            section.append(el("p", { class: "notice", text: t("credentials.no_issuer", { problem: c.problem }) }));
        }
        return section;
    }
    section.append(el("p", { class: "hint", text: t("credentials.off_intro") }));
    if (!listed.may_grant) {
        section.append(el("p", { text: t("credentials.owner_turns_on") }));
        return section;
    }
    const button = el("button", { type: "button", text: t(c.state === "registered" ? "credentials.finish" : "credentials.turn_on") });
    button.addEventListener("click", () => turnCredentialsOn(notice));
    section.append(button);
    return section;
}

/// Each tap approves what is still missing, until the server says they are on.
async function turnCredentialsOn(notice) {
    let prepared;
    try {
        prepared = await api("POST", "prepare", { action: "machine.credentials" });
    } catch (error) {
        if (error.status === 409) {
            state.flash = t("credentials.turned_on");
            route();
            return;
        }
        notice.replaceChildren(problem(t("error.server", { message: error.message })));
        return;
    }
    await approveScreen(prepared, new Map(), async () => {
        await turnCredentialsOn(notice);
        return TAKEN;
    });
}

/// A certificate as a W3C credential (a compact JWS), saved as TOKEN.jwt.
async function downloadCredential(c, notice) {
    const headers = {};
    const token = stored(sessionStorage, SESSION);
    if (token) {
        headers.Authorization = `Bearer ${token}`;
    }
    try {
        const response = await fetch(`api/certificates/${c.token}/credential`,
                                     { method: "POST", headers, credentials: "omit", cache: "no-store" });
        if (!response.ok) {
            const answer = await response.json().catch(() => ({}));
            throw new ApiError(response.status, answer?.error?.message ?? String(response.status));
        }
        saveText(await response.text(), `${c.token}.jwt`, "application/vc+jwt");
    } catch (error) {
        notice.replaceChildren(problem(t("error.server", { message: error.message })));
    }
}

/// The organization lets the console's machine issue certificates of a
/// kind: one tap of an owner's passkey.
function allowButton(kind, notice) {
    const button = el("button", { type: "button", text: t("certificates.allow"),
                                  "aria-label": t("certificates.allow_label", { name: kind.name }) });
    button.addEventListener("click", async () => {
        try {
            const prepared = await api("POST", "prepare", { action: "machine.certify", type: kind.type });
            await approveScreen(prepared, new Map(), async () => {
                state.flash = t("certificates.allowed", { name: kind.name });
                // The approval was shown at this address: show the screen again.
                route();
                return TAKEN;
            });
        } catch (error) {
            notice.replaceChildren(problem(t("error.server", { message: error.message })));
        }
    });
    return button;
}

/// A certificate's QR code and link, its page to print, and Withdraw.
function certificateActions(c, listed, notice) {
    const what = c.fields.map((f) => f.value).join(" ") || c.kind;
    const area = el("div");
    const language = encodeURIComponent(state.language);
    const qr = el("button", { type: "button", text: t("certificates.qr"),
                              "aria-label": t("certificates.qr_label", { what }) });
    qr.addEventListener("click", async () => {
        const box = el("input", { type: "text", readonly: true, class: "id",
                                  "aria-label": t("certificates.link_label", { what }) });
        box.value = c.verify_url;
        const shown = [box];
        try {
            const blob = await fetchBlob(`certificates/${c.token}/qr?language=${language}`);
            shown.push(el("img", { class: "qr", src: URL.createObjectURL(blob), alt: t("certificates.qr_alt", { what }) }));
        } catch (error) {
            shown.push(problem(t("error.server", { message: error.message })));
        }
        area.replaceChildren(...shown);
    });
    const page = el("button", { type: "button", text: t("certificates.page"),
                                "aria-label": t("certificates.page_label", { what }) });
    page.addEventListener("click", async () => {
        try {
            const blob = await fetchBlob(`certificates/${c.token}/page?language=${language}`);
            saveText(await blob.text(), `${c.token}.html`, "text/html");
        } catch (error) {
            notice.replaceChildren(problem(t("error.server", { message: error.message })));
        }
    });
    const buttons = [qr, " ", c.status === "valid" ? page : null];
    if (listed.may_issue && listed.credentials?.state === "on" && c.status === "valid") {
        const credential = el("button", { type: "button", text: t("certificates.credential"),
                                          "aria-label": t("certificates.credential_label", { what }) });
        credential.addEventListener("click", () => downloadCredential(c, notice));
        buttons.push(" ", credential);
    }
    if (listed.may_issue) {
        const withdraw = el("button", { type: "button", text: t("certificates.withdraw"),
                                        "aria-label": t("certificates.withdraw_label", { what }) });
        withdraw.addEventListener("click", async () => {
            try {
                await api("DELETE", `certificates/${c.token}`);
                state.flash = t("certificates.withdrawn", { what });
                route();
            } catch (error) {
                notice.replaceChildren(problem(t("error.server", { message: error.message })));
            }
        });
        buttons.push(" ", withdraw);
    }
    return el("div", {}, el("div", {}, buttons), area);
}

/// A table (CSV) checked, then issued: the passkey approves the batch, the
/// console's machine signs each certificate, and the page follows it.
function issueForm(listed) {
    const allowed = listed.kinds.filter((k) => k.granted);
    const section = el("section", {}, el("h2", { text: t("certificates.issue_title") }),
                       el("p", { class: "hint", text: t("certificates.issue_intro") }));
    if (allowed.length === 0) {
        section.append(el("p", { text: t("certificates.none_allowed") }));
        return section;
    }
    const kind = el("select", { id: "certificate-kind" },
                    allowed.map((k) => el("option", { value: k.type, text: k.name })));
    const file = el("input", { type: "file", id: "certificate-table", accept: ".csv,text/csv" });
    const result = el("div", { role: "status" });
    const check = el("button", { type: "submit", text: t("certificates.check") });
    const form = el("form", { novalidate: true },
                    el("div", { class: "field" }, el("label", { for: "certificate-kind", text: t("certificates.kind") }), kind),
                    el("div", { class: "field" }, el("label", { for: "certificate-table", text: t("certificates.table") }), file),
                    check, result);
    form.addEventListener("submit", async (event) => {
        event.preventDefault();
        result.replaceChildren();
        if (!file.files.length) {
            result.append(problem(t("certificates.choose_table")));
            return;
        }
        const table = await file.files[0].text();
        try {
            const checked = await api("POST", "certificates/check", { type: kind.value, table });
            result.append(el("p", { text: t("certificates.checked", checked) }));
            if (checked.to_issue === 0) {
                return;
            }
            const go = el("button", { type: "button", class: "primary",
                                      text: t("certificates.issue", { count: checked.to_issue }) });
            go.addEventListener("click", () => issueBatch(kind.value, table, go, result));
            result.append(go);
        } catch (error) {
            result.append(problem(t("error.server", { message: error.message })));
        }
    });
    section.append(form);
    return section;
}

async function issueBatch(type, table, button, result) {
    button.disabled = true;
    try {
        const batch = await api("POST", "certificates/batch", { type, table });
        const options = batch.public_key;
        const credential = await navigator.credentials.get({
            publicKey: {
                challenge: fromBase64url(options.challenge),
                rpId: options.rpId,
                allowCredentials: options.allowCredentials.map((c) => ({ type: c.type, id: fromBase64url(c.id) })),
                userVerification: options.userVerification,
                timeout: options.timeout,
            },
        });
        await api("POST", "certificates/start", {
            batch: batch.batch,
            credential_id: toBase64url(credential.rawId),
            authenticator_data: toBase64url(credential.response.authenticatorData),
            client_data_json: toBase64url(credential.response.clientDataJSON),
            signature: toBase64url(credential.response.signature),
        });
        const progress = el("p", { role: "status" });
        result.replaceChildren(progress);
        for (;;) {
            const now = await api("GET", `certificates/batch/${batch.batch}`);
            progress.textContent = t("certificates.issuing", { issued: now.issued, total: now.total - now.already });
            if (now.state === "done") {
                state.flash = t("certificates.done", { issued: now.issued });
                route();
                return;
            }
            if (now.state === "failed") {
                result.replaceChildren(problem(t("certificates.failed", { problem: now.problem ?? "" })));
                return;
            }
            await new Promise((resolve) => setTimeout(resolve, 500));
        }
    } catch (error) {
        result.append(problem(passkeyProblem(error)));
        button.disabled = false;
    }
}

async function automationScreen() {
    const listed = await api("GET", "automation");
    const notice = el("div", { role: "status" });
    const parts = [flash(), el("h1", { text: t("automation.title") }),
                   el("p", { class: "hint", text: t("automation.intro") })];
    parts.push(...table(t("automation.requests"), [
        ["automation.kind", (r) => r.kind],
        ["automation.thing", (r) => el("a", { href: `#/instance/${r.instance}`, text: `${r.instance.slice(0, 12)}...` })],
        ["automation.deadline", (r) => timeText(r.deadline) + (r.overdue ? ` (${t("automation.overdue")})` : "")],
    ], listed.requests));
    parts.push(el("h2", { text: t("automation.keeper") }),
               el("p", { class: "hint", text: t(listed.locked ? "automation.keeper_locked" : "automation.keeper_runs") }),
               listed.due.length
                   ? el("ul", {}, listed.due.map((d) => el("li", {}, t(d.kind === "rule" ? "automation.due_rule" : "automation.due_expiry",
                                                                        { function: d.function ?? "", request: (d.request ?? "").slice(0, 12) }),
                                                               " ", el("a", { href: `#/instance/${d.instance}`, text: t("automation.open_thing") }))))
                   : el("p", { text: t("automation.nothing_due") }));
    if (!listed.may_change) {
        show(...parts);
        return;
    }
    parts.push(...table(t("automation.machines"), [
        ["column.name", (m) => m.name],
        ["automation.kind", (m) => t(m.kind === "agent" ? "automation.agent" : "automation.device")],
        ["automation.responsible", (m) => m.responsible ?? ""],
        ["people.may", (m) => (m.delegations.length ? m.delegations.map((d) => machineWords(d, listed)).join(" | ")
                                                    : t("value.none"))],
        ["column.actions", (m) => el("span", {}, m.delegations.filter((d) => !d.revoked).map((d) => {
            const withdraw = el("button", { type: "button", text: t("people.withdraw"),
                                            "aria-label": t("people.withdraw_label", { name: m.name }) });
            withdraw.addEventListener("click", async () => {
                try {
                    const prepared = await api("POST", "prepare", { action: "delegation.revoke", delegation: d.id,
                                                                     reason: t("people.withdraw_reason") });
                    await approveScreen(prepared, new Map(), async () => el("p", { class: "notice",
                        text: t("people.withdrawn", { name: m.name }) }));
                } catch (error) {
                    notice.replaceChildren(problem(t("error.server", { message: error.message })));
                }
            });
            return withdraw;
        }))],
    ], listed.machines));
    // Machines whose key waits here, their delegation now on the ledger
    // (after its approvals): their key, once.
    if (listed.set_up?.length) {
        parts.push(el("h2", { text: t("automation.set_up_title") }),
                   el("p", { class: "hint", text: t("automation.set_up_hint") }),
                   el("ul", {}, listed.set_up.map((m) => {
                       const go = el("button", { type: "button", class: "primary", text: t("automation.set_up"),
                                                 "aria-label": t("automation.set_up_label", { name: m.name }) });
                       go.addEventListener("click", () => machineSetupScreen(m.actor, m.delegation, m.name, m.agent));
                       return el("li", {}, `${m.name} `, go);
                   })));
    }
    parts.push(notice, executorForm(listed), agentForm(listed));
    show(...parts);
}

/// Adds a machine in two taps (its actor, then its delegation), then hands
/// out its key once.
async function addMachine(register, delegate, name, agent, notice) {
    try {
        // The second step goes with the first: if the registration has to
        // wait for approvals, the console takes it by itself once it is
        // registered, and the machine is set up from this screen then.
        const prepared = await api("POST", "prepare", { ...register, then: delegate });
        prepared.progress = { index: 1, of: 2 };
        await approveScreen(prepared, new Map(), async (done) => {
            const second = await api("POST", "prepare", { ...delegate, actor: done.statement_id, name });
            second.progress = { index: 2, of: 2 };
            await approveScreen(second, new Map(), async (granted) => {
                machineSetupScreen(done.statement_id, granted.statement_id, name, agent);
                return TAKEN;
            });
            return TAKEN;
        });
    } catch (error) {
        notice.replaceChildren(problem(t("error.server", { message: error.message })));
    }
}

function executorForm(listed) {
    const [nameField, name] = field("executor-name", t("column.name"), t("automation.name_hint"), { maxlength: 64 });
    const contract = el("select", { id: "executor-contract" },
                        listed.contracts.map((c) => el("option", { value: c.id, text: c.name ?? `${c.id.slice(0, 12)}...` })));
    const [kindsField, kinds] = field("executor-kinds", t("automation.answers"), t("automation.kinds_hint"));
    const [functionsField, functions] = field("executor-functions", t("automation.functions"), t("automation.functions_hint"));
    const notice = el("div", { role: "status" });
    const add = el("button", { type: "submit", class: "primary", text: t("automation.add_executor") });
    const form = el("form", { novalidate: true }, nameField,
                    el("div", { class: "field" }, el("label", { for: "executor-contract", text: t("column.contract") }), contract),
                    kindsField, functionsField, notice, add);
    form.addEventListener("submit", async (event) => {
        event.preventDefault();
        const list = (input) => input.value.split(",").map((x) => x.trim()).filter((x) => x);
        const chosen = listed.contracts.find((c) => c.id === contract.value);
        const fns = list(functions).length ? list(functions)
            : chosen?.functions.includes("result") ? ["result"] : [];
        await addMachine({ action: "machine.register", name: name.value.trim() },
                         { action: "machine.delegate", contract: contract.value, kinds: list(kinds), functions: fns },
                         name.value.trim(), false, notice);
    });
    return el("section", {}, el("h2", { text: t("automation.add_executor") }),
              el("p", { class: "hint", text: t("automation.executor_intro") }),
              listed.contracts.length ? form : el("p", { text: t("automation.no_rules") }));
}

function agentForm(listed) {
    const [nameField, name] = field("agent-name", t("column.name"), t("automation.name_hint"), { maxlength: 64 });
    const [modelField, model] = field("agent-model", t("automation.model"), t("automation.model_hint"), { maxlength: 128 });
    const [versionField, version] = field("agent-version", t("automation.model_version"), "", { maxlength: 128 });
    const responsible = el("select", { id: "agent-responsible" },
                           listed.people.map((p) => el("option", { value: p.name, text: p.name })));
    const box = (key) => {
        const input = el("input", { type: "checkbox", id: `agent-may-${key}`, checked: key === "register" || key === "act" });
        return [key, input, el("div", {}, el("label", { for: `agent-may-${key}` }, input, " ", t(`people.may.${key}`)))];
    };
    const words = ["register", "endorse", "revoke", "act"].map(box);
    const notice = el("div", { role: "status" });
    const add = el("button", { type: "submit", class: "primary", text: t("automation.add_agent") });
    const form = el("form", { novalidate: true }, nameField, modelField, versionField,
                    el("div", { class: "field" }, el("label", { for: "agent-responsible", text: t("automation.responsible") }), responsible),
                    el("fieldset", {}, el("legend", { text: t("people.what_they_may") }), words.map(([, , v]) => v)),
                    notice, add);
    form.addEventListener("submit", async (event) => {
        event.preventDefault();
        const may = Object.fromEntries(words.map(([k, input]) => [k, input.checked]));
        await addMachine({ action: "machine.register", name: name.value.trim(), agent: true, model: model.value.trim(),
                           model_version: version.value.trim(), responsible: responsible.value },
                         { action: "machine.delegate", may }, name.value.trim(), true, notice);
    });
    return el("section", {}, el("h2", { text: t("automation.add_agent") }),
              el("p", { class: "hint", text: t("automation.agent_intro") }),
              listed.people.length ? form : el("p", { text: t("automation.no_people") }));
}

/// The machine's key, once, encrypted with a passphrase typed here; its API
/// token; and how to run it.
function machineSetupScreen(actor, delegation, name, agent) {
    const [passField, pass] = field("machine-passphrase", t("automation.passphrase"), t("automation.passphrase_hint"),
                                    { type: "password", minlength: 8, autocomplete: "new-password" });
    const result = el("div", { role: "status" });
    const get = el("button", { type: "submit", class: "primary", text: t("automation.get_key") });
    const form = el("form", { novalidate: true }, passField, get);
    form.addEventListener("submit", async (event) => {
        event.preventDefault();
        try {
            const setup = await api("POST", "automation/setup", { actor, delegation, passphrase: pass.value });
            form.remove();
            const save = el("button", { type: "button", class: "primary", text: t("automation.save_key", { file: setup.key_file }) });
            save.addEventListener("click", () => saveBytes(new Uint8Array(fromBase64url(setup.key)), setup.key_file));
            const shown = (label, value, rows = 3) => {
                const area = el("textarea", { readonly: true, rows, class: "id", "aria-label": label });
                area.value = value;
                return [el("p", { text: label }), area];
            };
            const parts = [el("p", { class: "notice", text: t("automation.once") }), save,
                           ...shown(t("automation.token_for", { name: setup.token_name }), setup.token, 2)];
            if (setup.config) {
                const saveConfig = el("button", { type: "button", text: t("automation.save_config", { file: `${name}.json` }) });
                saveConfig.addEventListener("click", () => saveBytes(new TextEncoder().encode(setup.config), `${name}.json`));
                parts.push(...shown(t("automation.config"), setup.config, 6), saveConfig,
                           ...shown(t("automation.command"), setup.command, 3),
                           el("p", { class: "hint", text: t("automation.connectors_hint") }));
            } else {
                parts.push(...shown(t("automation.mcp"), JSON.stringify(setup.mcp, null, 2), 10),
                           el("p", { class: "hint", text: t("automation.mcp_hint") }));
            }
            result.replaceChildren(...parts, goButton(t("nav.automation"), "#/automation"));
        } catch (error) {
            result.replaceChildren(problem(t("error.server", { message: error.message })));
        }
    });
    show(el("h1", { text: t("automation.setup_title", { name }) }),
         el("p", { class: "hint", text: t(agent ? "automation.setup_agent" : "automation.setup_executor") }),
         form, result);
}

// --- Scripts --------------------------------------------------------------------------

/// A file's digest under the ledger's hash (its COSE id), as hex: with the
/// browser's own SHA-256, or the console's checks for another hash. The
/// file never leaves this browser.
async function fileDigest(bytes, hash) {
    if (hash === -16 && globalThis.crypto?.subtle) {
        const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
        return [...digest].map((b) => b.toString(16).padStart(2, "0")).join("");
    }
    const check = await loadChecker();
    const out = check ? check.digest(bytes, hash) : null;
    if (!out?.ok) {
        throw new Error(t("scripts.no_digest"));
    }
    return out.digest;
}

/// A script's file is named by its path in the script's folder: relative,
/// "/" between its parts, none empty, "." or "..".
const validScriptPath = (path) => path.length > 0 && new TextEncoder().encode(path).length <= 1024 &&
    path.split("/").every((part) => part !== "" && part !== "." && part !== "..");

/// The files chosen, each with its path, size, and digest: a folder's by
/// their paths below it, leaving out hidden ones (names starting with a
/// dot), as the command line does; files chosen one by one by their names.
async function scriptFiles(lists, hash) {
    const out = new Map();
    for (const list of lists) {
        for (const file of list) {
            const inFolder = Boolean(file.webkitRelativePath);
            const path = inFolder ? file.webkitRelativePath.split("/").slice(1).join("/") : file.name;
            if (inFolder && path.split("/").some((part) => part.startsWith("."))) {
                continue;
            }
            if (!validScriptPath(path)) {
                throw new Error(t("scripts.bad_path", { path }));
            }
            if (out.has(path)) {
                throw new Error(t("scripts.twice", { path }));
            }
            const bytes = new Uint8Array(await file.arrayBuffer());
            out.set(path, { path, size: file.size, digest: await fileDigest(bytes, hash) });
        }
    }
    return [...out.values()];
}

const byPath = (a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0);
const sameFiles = (a, b) => canonical([...(a ?? [])].sort(byPath)) === canonical([...b].sort(byPath));

function scriptFileTable(caption, files) {
    return table(caption, [
        ["scripts.path", (f) => f.path],
        ["scripts.size", (f) => sizeText(f.size)],
        ["scripts.digest", (f) => ({ id: true, text: f.digest })],
    ], files);
}

/// A file input and a folder input for a script's files: `changed` runs
/// when either changes.
function scriptInputs(prefix, changed) {
    const files = el("input", { type: "file", id: `${prefix}-files`, multiple: true });
    const folder = el("input", { type: "file", id: `${prefix}-folder`, multiple: true, webkitdirectory: true });
    files.addEventListener("change", changed);
    folder.addEventListener("change", changed);
    return {
        lists: () => [folder.files, files.files],
        parts: [el("div", { class: "field" }, el("label", { for: `${prefix}-files`, text: t("scripts.choose_files") }),
                   files),
                el("div", { class: "field" }, el("label", { for: `${prefix}-folder`, text: t("scripts.choose_folder") }),
                   folder, el("span", { class: "hint", text: t("scripts.folder_hint") }))],
    };
}

const whenText = (ms) => (ms ? timeText(ms) : "");

/// Scripts: what the ledger approved, in person, by its files' digests,
/// and what was withdrawn; owners and admins approve one here.
async function scriptsScreen() {
    const listed = await api("GET", "scripts");
    const parts = [flash(), keysNotice(), el("h1", { text: t("scripts.title") }),
                   el("p", { class: "hint", text: t("scripts.intro") })];
    parts.push(...table(t("scripts.list"), [
        ["column.name", (s) => el("a", { href: `#/script/${s.id}`, text: `${s.name} ${s.version}` })],
        ["scripts.files", (s) => String(s.files.length)],
        ["scripts.deterministic", (s) => yesNo(s.deterministic)],
        ["scripts.approved_by", (s) => t("scripts.approved_line", {
            name: s.approved_by.name ?? short(s.approved_by.id).text, time: whenText(s.approved_at) })],
        ["column.state", (s) => (s.status === "withdrawn"
            ? t("scripts.withdrawn_on", { time: whenText(s.withdrawn_at) }) : t("scripts.approved"))],
    ], listed.scripts));
    if (listed.may_approve) {
        parts.push(approveScriptForm(listed));
    }
    show(...parts);
}

/// Approving a script: its name, version, files (their digests computed
/// here; only paths, sizes, and digests are sent), whether deterministic,
/// what runs it, and a note; then one passkey tap.
function approveScriptForm(listed) {
    const [nameField, name] = field("script-name", t("scripts.name"), t("scripts.name_hint"),
                                    { maxlength: 128, spellcheck: "false" });
    const [versionField, version] = field("script-version", t("scripts.version"), t("scripts.version_hint"),
                                          { maxlength: 64, spellcheck: "false" });
    const [runtimeField, runtime] = field("script-runtime", t("scripts.runtime"), t("scripts.runtime_hint"),
                                          { maxlength: 128 });
    const [noteField, note] = field("script-note", t("scripts.note"), t("scripts.note_hint"), { maxlength: 1000 });
    const deterministic = el("input", { type: "checkbox", id: "script-deterministic" });
    const chosen = el("div", { "aria-live": "polite" });
    const notice = el("div", { role: "status" });
    let computed = [];
    let pending = Promise.resolve();
    const inputs = scriptInputs("script", () => {
        pending = (async () => {
            notice.replaceChildren();
            status(t("status.working"));
            try {
                computed = await scriptFiles(inputs.lists(), listed.hash.cose);
                chosen.replaceChildren(...(computed.length ? scriptFileTable(t("scripts.chosen"), computed) : []));
            } catch (error) {
                computed = [];
                chosen.replaceChildren();
                notice.replaceChildren(problem(error.message));
            } finally {
                status("");
            }
        })();
    });
    const prepare = el("button", { type: "submit", class: "primary", text: t("act.prepare") });
    const form = el("form", { novalidate: true }, nameField, versionField, ...inputs.parts,
                    el("p", { class: "hint", text: t("scripts.files_hint", { hash: listed.hash.name }) }),
                    chosen, el("label", { class: "check" }, deterministic, " ", t("scripts.deterministic_box")),
                    runtimeField, noteField, notice, prepare);
    form.addEventListener("submit", async (event) => {
        event.preventDefault();
        prepare.disabled = true;
        try {
            await pending;
            if (computed.length === 0) {
                notice.replaceChildren(problem(t("scripts.no_files")));
                return;
            }
            const prepared = await api("POST", "prepare", {
                action: "script.approve", name: name.value.trim(), version: version.value.trim(),
                runtime: runtime.value.trim(), deterministic: deterministic.checked, note: note.value.trim(),
                files: computed,
            });
            // The console's terms are the files this browser fingerprinted.
            if (!sameFiles(prepared.summary.script_approval?.files, computed)) {
                show(el("h1", { text: t("approve.title") }), problem(t("approve.mismatch")),
                     goButton(t("nav.scripts"), "#/scripts"));
                return;
            }
            await approveScreen(prepared);
        } catch (error) {
            notice.replaceChildren(problem(error.status === 423 ? t("keys.locked")
                                                                : t("error.server", { message: error.message })));
        } finally {
            prepare.disabled = false;
        }
    });
    return el("section", {}, el("h2", { text: t("scripts.approve_title") }),
              el("p", { class: "hint", text: t("scripts.approve_intro") }), form);
}

/// A script's page: its approval, its files, a check of files in this
/// browser against them, and its withdrawal.
async function scriptScreen(id) {
    const s = await api("GET", `scripts/${id}`);
    const facts = el("dl", { class: "facts" });
    const fact = (key, value, attributes = {}) => {
        facts.append(el("dt", { text: t(key) }), el("dd", { text: String(value), ...attributes }));
    };
    fact("scripts.version", s.version);
    fact("scripts.deterministic", yesNo(s.deterministic));
    fact("scripts.runtime", s.runtime ?? t("value.none"));
    fact("scripts.approved_by", t(s.in_person === "hardware-key" ? "scripts.in_person_key" : "scripts.in_person_passkey",
                                  { name: s.approved_by.name ?? short(s.approved_by.id).text, time: whenText(s.approved_at) }));
    fact("column.state", s.status === "withdrawn" ? t("scripts.withdrawn_on", { time: whenText(s.withdrawn_at) })
                                                  : t("scripts.approved"));
    if (s.withdraw_reason) {
        fact("act.reason", s.withdraw_reason);
    }
    fact("thing.entry", s.index);
    fact("column.id", s.id, { class: "id" });
    const parts = [flash(), keysNotice(), el("h1", { text: `${s.name} ${s.version}` })];
    if (s.status === "withdrawn") {
        parts.push(el("div", { class: "notice replaced", role: "status" },
                      el("p", { text: t("scripts.withdrawn_notice", { time: whenText(s.withdrawn_at) }) })));
    }
    parts.push(facts, ...scriptFileTable(t("scripts.files_title"), s.files), checkFilesPart(s));
    if (s.may_withdraw) {
        parts.push(withdrawScriptForm(s));
    }
    parts.push(el("p", { class: "actions" },
                  el("a", { href: `#/thing/${s.id}`, class: "button", text: t("scripts.open_record") }), " ",
                  goButton(t("nav.scripts"), "#/scripts")));
    show(...parts);
}

/// Files someone has, compared with the approval in this browser: the
/// same, changed, missing, or not in it. Nothing is sent.
function checkFilesPart(s) {
    const result = el("div", { "aria-live": "polite" });
    const inputs = scriptInputs("check", async () => {
        try {
            const chosen = await scriptFiles(inputs.lists(), s.hash.cose);
            const atPath = new Map(chosen.map((f) => [f.path, f]));
            // A file chosen on its own is found by its name too, if no other
            // has that name.
            const byName = new Map();
            for (const f of chosen) {
                const name = f.path.split("/").pop();
                byName.set(name, byName.has(name) ? null : f);
            }
            const used = new Set();
            const lines = s.files.map((f) => {
                let mine = atPath.get(f.path);
                if (!mine) {
                    const named = byName.get(f.path.split("/").pop());
                    mine = named && !used.has(named.path) && !s.files.some((g) => g.path === named.path)
                        ? named : undefined;
                }
                if (mine) {
                    used.add(mine.path);
                }
                const verdict = !mine ? "missing" : mine.size === f.size && mine.digest === f.digest ? "same" : "changed";
                return { path: f.path, verdict };
            });
            const extra = chosen.filter((f) => !used.has(f.path));
            const differ = lines.filter((l) => l.verdict !== "same").length;
            result.replaceChildren(
                el("p", { class: differ ? "notice replaced" : "notice", role: "status",
                          text: differ ? t("scripts.check_differ", { n: differ, of: s.files.length })
                                       : t(s.status === "withdrawn" ? "scripts.check_same_withdrawn"
                                                                    : "scripts.check_same") }),
                el("ul", {}, lines.map((l) => el("li", { class: l.verdict === "same" ? null : "bad",
                                                        text: t(`scripts.check.${l.verdict}`, { path: l.path }) })),
                   extra.map((f) => el("li", { text: t("scripts.check.extra", { path: f.path }) }))));
        } catch (error) {
            result.replaceChildren(problem(error.message));
        }
    });
    return el("section", {}, el("h2", { text: t("scripts.check_title") }),
              el("p", { class: "hint", text: t("scripts.check_intro") }), ...inputs.parts, result);
}

/// Withdrawing a script: its record revoked, with a reason, with a tap.
function withdrawScriptForm(s) {
    const [reasonField, reason] = field("script-reason", t("act.reason"), t("scripts.reason_hint"), { maxlength: 1000 });
    const notice = el("div", { role: "status" });
    const button = el("button", { type: "submit", text: t("scripts.withdraw") });
    const form = el("form", { novalidate: true }, reasonField, notice, button);
    form.addEventListener("submit", async (event) => {
        event.preventDefault();
        button.disabled = true;
        try {
            const prepared = await api("POST", "prepare", { action: "script.withdraw", script: s.id,
                                                             reason: reason.value.trim() });
            await approveScreen(prepared, new Map(), async () => el("p", { class: "notice",
                text: t("scripts.withdrawn_done", { name: `${s.name} ${s.version}` }) }));
        } catch (error) {
            notice.replaceChildren(problem(error.status === 423 ? t("keys.locked")
                                                                : t("error.server", { message: error.message })));
        } finally {
            button.disabled = false;
        }
    });
    return el("section", {}, el("h2", { text: t("scripts.withdraw_title") }),
              el("p", { class: "hint", text: t("scripts.withdraw_intro") }), form);
}

// --- People --------------------------------------------------------------------------

/// What someone may do on the ledger, in plain words.
function mayWords(d, listed) {
    const kindName = (type) => listed.kinds.find((k) => k.type === type)?.name ?? type;
    const ruleName = (id) => listed.contracts.find((c) => c.id === id)?.name ?? `${id.slice(0, 12)}...`;
    const parts = [];
    if (d.register) {
        parts.push(d.kinds ? t("people.may.register_kinds", { kinds: d.kinds.map(kindName).join(", ") })
                           : t("people.may.register"));
    }
    if (d.endorse) parts.push(t("people.may.endorse"));
    if (d.revoke) parts.push(t("people.may.revoke"));
    if (d.act) {
        parts.push(d.contracts ? t("people.may.act_rules", { rules: d.contracts.map(ruleName).join(", ") })
                               : t("people.may.act"));
    }
    if (d.rules) parts.push(t("people.may.rules"));
    if (d.people) parts.push(t("people.may.people"));
    parts.push(...(d.other ?? []));
    let text = parts.join("; ");
    if (d.in_person) text += `; ${t("people.may.in_person")}`;
    if (d.until) text += `; ${t("people.may.until", { time: timeText(d.until) })}`;
    if (d.approvals) {
        // Others approve what they sign under it (spec v0.20).
        const named = (id) => (listed.actors ?? []).find((a) => a.id === id) ?? { id };
        text += `; ${t("people.may.needs", { rule: ruleText({ ...d.approvals, approvers: d.approvals.approvers.map(named) }) })}`;
    }
    return d.revoked ? t("people.may.withdrawn", { what: text }) : text;
}

async function peopleScreen() {
    const listed = await api("GET", "people");
    const notice = el("div", { role: "status" });
    const parts = [flash(), el("h1", { text: t("people.title") }), el("p", { class: "hint", text: t("people.intro") })];
    const roles = ["owner", "admin", "member", "viewer"];
    parts.push(...table(t("people.users"), [
        ["column.name", (u) => u.name],
        ["people.role", (u) => t(`role.${u.role}`)],
        ["people.passkeys", (u) => String(u.passkeys.length)],
        ["column.state", (u) => t(`people.step.${u.step}`)],
        ["people.may", (u) => (u.delegations.length ? u.delegations.map((d) => mayWords(d, listed)).join(" | ")
                                                    : t("value.none"))],
        // Whose statements they approve: a delegation's, or the organization's
        // as a guardian.
        ["people.approves_for", (u) => {
            const lines = (u.approves_for ?? []).map((a) => t("people.approves_line", {
                name: a.grantee_name ?? short(a.grantee).text,
                rule: t("approvals.k_of_n", { k: a.rule.k, n: a.rule.approvers.length }),
            }));
            if (u.guardian) {
                lines.unshift(t("people.guardian"));
            }
            return lines.length ? lines.join("; ") : t("value.none");
        }],
        ["column.actions", (u) => {
            if (!listed.may_change) {
                return "";
            }
            const actions = el("span");
            if (u.step !== "active") {
                const approve = el("button", { type: "button", class: "primary", text: t("people.approve"),
                                               "aria-label": t("people.approve_label", { name: u.name }) });
                approve.addEventListener("click", () => approvePersonScreen(u, listed));
                actions.append(approve, " ");
            }
            const role = el("select", { "aria-label": t("people.role_of", { name: u.name }) },
                            roles.map((r) => el("option", { value: r, text: t(`role.${r}`) })));
            role.value = u.role;
            role.addEventListener("change", async () => {
                try {
                    await api("POST", "people", { role: u.name, to: role.value });
                    state.flash = t("people.role_changed", { name: u.name, role: t(`role.${role.value}`) });
                    route();
                } catch (error) {
                    role.value = u.role;
                    notice.replaceChildren(problem(t("error.server", { message: error.message })));
                }
            });
            actions.append(role);
            for (const d of u.delegations.filter((x) => !x.revoked)) {
                const withdraw = el("button", { type: "button", text: t("people.withdraw"),
                                                "aria-label": t("people.withdraw_label", { name: u.name }) });
                withdraw.addEventListener("click", async () => {
                    try {
                        const prepared = await api("POST", "prepare", { action: "delegation.revoke", delegation: d.id,
                                                                         reason: t("people.withdraw_reason") });
                        await approveScreen(prepared, new Map(), async () => el("p", { class: "notice",
                            text: t("people.withdrawn", { name: u.name }) }));
                    } catch (error) {
                        notice.replaceChildren(problem(t("error.server", { message: error.message })));
                    }
                });
                actions.append(" ", withdraw);
            }
            if (!u.me) {
                const remove = el("button", { type: "button", text: t("people.remove"),
                                              "aria-label": t("people.remove_label", { name: u.name }) });
                remove.addEventListener("click", async () => {
                    try {
                        await api("POST", "people", { remove: u.name });
                        state.flash = t("people.removed", { name: u.name });
                        route();
                    } catch (error) {
                        notice.replaceChildren(problem(t("error.server", { message: error.message })));
                    }
                });
                actions.append(" ", remove);
            }
            return actions;
        }],
    ], listed.users));
    if (listed.invitations.length) {
        parts.push(el("p", { class: "hint", text: t("people.invited", {
            names: listed.invitations.map((i) => `${i.user} (${t(`role.${i.role}`)})`).join(", ") }) }));
    }
    parts.push(notice);
    if (listed.may_change) {
        const [nameField, name] = field("invite-name", t("column.name"), t("people.name_hint"), { maxlength: 64 });
        const role = el("select", { id: "invite-role" },
                        roles.map((r) => el("option", { value: r, text: t(`role.${r}`) })));
        role.value = "member";
        const made = el("div", { role: "status" });
        const invite = el("button", { type: "submit", class: "primary", text: t("people.invite") });
        const form = el("form", { novalidate: true }, nameField,
                        el("div", { class: "field" }, el("label", { for: "invite-role", text: t("people.role") }), role),
                        invite, made);
        form.addEventListener("submit", async (event) => {
            event.preventDefault();
            try {
                const answer = await api("POST", "people", { invite: name.value.trim(), role: role.value });
                const box = el("textarea", { readonly: true, rows: 2, class: "id",
                                             "aria-label": t("people.link_for", { name: answer.user }) });
                box.value = answer.link;
                made.replaceChildren(el("p", { text: t("people.link_for", { name: answer.user }) }), box,
                                     el("p", { class: "hint", text: t("people.link_hint", {
                                         time: timeText(answer.expires) }) }));
            } catch (error) {
                made.replaceChildren(problem(t("error.server", { message: error.message })));
            }
        });
        parts.push(el("h2", { text: t("people.invite_title") }), form);
    }
    show(...parts);
}

/// What an enrolled person may do, chosen in plain words, then approved in
/// up to three taps: their actor, their passkeys, the delegation.
function approvePersonScreen(u, listed) {
    const defaults = listed.defaults[u.role === "owner" ? "admin" : u.role] ?? listed.defaults.member;
    const box = (key, label) => {
        const input = el("input", { type: "checkbox", id: `may-${key}`, checked: Boolean(defaults[key]) });
        return [input, el("div", {}, el("label", { for: `may-${key}` }, input, " ", label))];
    };
    const words = ["register", "endorse", "revoke", "act", "rules", "people"]
        .filter((k) => k !== "people" || u.role === "admin" || u.role === "owner")
        .map((k) => [k, ...box(k, t(`people.may.${k === "register" ? "register" : k}`))]);
    const choose = (items, allLabel, id) => {
        const all = el("input", { type: "checkbox", id: `${id}-all`, checked: true });
        const each = items.map((item) => {
            const input = el("input", { type: "checkbox", value: item.value, checked: true, disabled: true });
            return [input, el("div", {}, el("label", {}, input, " ", item.label))];
        });
        all.addEventListener("change", () => each.forEach(([input]) => { input.disabled = all.checked; }));
        return { all, each, view: el("fieldset", {}, el("legend", { text: allLabel }),
                                     el("div", {}, el("label", { for: `${id}-all` }, all, " ", t("people.all"))),
                                     each.map(([, v]) => v)) };
    };
    const kinds = choose(listed.kinds.map((k) => ({ value: k.type, label: k.name })), t("people.which_kinds"), "kinds");
    const rules = choose(listed.contracts.map((c) => ({ value: c.id, label: c.name ?? `${c.id.slice(0, 12)}...` })),
                         t("people.which_rules"), "rules");
    const [untilField, until] = field("may-until", t("people.until"), t("people.until_hint"), { type: "date" });
    // Others approve what they sign under it (spec v0.20): how many, of
    // whom, within how many days; in person only, unless chosen otherwise.
    const needs = el("input", { type: "checkbox", id: "may-approvals" });
    const count = el("input", { type: "number", id: "approvals-k", min: 1, max: 16, value: 2, inputmode: "numeric" });
    const days = el("input", { type: "number", id: "approvals-days", min: 1, max: 30, value: 7, inputmode: "numeric" });
    const anyway = el("input", { type: "checkbox", id: "approvals-open" });
    const boxes = new Map();
    const pick = el("fieldset", {});
    const drawPeople = () => {
        pick.replaceChildren(el("legend", { text: t("people.approvers") }),
            ...(listed.actors ?? []).filter((a) => a.kind === 1 || anyway.checked).map((a) => {
                const box = boxes.get(a.id) ?? el("input", { type: "checkbox", value: a.id });
                boxes.set(a.id, box);
                return el("div", {}, el("label", {}, box, " ",
                    a.kind === 1 ? a.name : t(a.kind === 2 ? "people.approver_agent" : "people.approver_device", { name: a.name })));
            }));
    };
    drawPeople();
    anyway.addEventListener("change", drawPeople);
    const detail = el("div", { hidden: true },
        el("div", { class: "field" }, el("label", { for: "approvals-k", text: t("people.approvals_k") }), count),
        pick,
        el("div", { class: "field" }, el("label", { for: "approvals-days", text: t("people.approvals_days") }), days,
           el("span", { class: "hint", text: t("people.approvals_days_hint") })),
        el("div", {}, el("label", { for: "approvals-open" }, anyway, " ", t("people.approvals_open"))),
        el("p", { class: "hint", text: t("people.approvals_open_warning") }));
    needs.addEventListener("change", () => { detail.hidden = !needs.checked; });
    const approvalsPart = el("fieldset", {}, el("legend", { text: t("people.approvals_title") }),
                             el("div", {}, el("label", { for: "may-approvals" }, needs, " ", t("people.approvals_needed"))),
                             el("p", { class: "hint", text: t("people.approvals_hint") }), detail);
    const notice = el("div", { role: "status" });
    const go = el("button", { type: "submit", class: "primary", text: t("people.approve_steps", {
        n: { actor: 3, presence: 2, delegation: 1 }[u.step] ?? 1 }) });
    const form = el("form", { novalidate: true },
                    el("fieldset", {}, el("legend", { text: t("people.what_they_may") }), words.map(([, , v]) => v)),
                    kinds.view, rules.view, untilField, approvalsPart, notice, go, " ", backButton(t("approve.cancel")));
    form.addEventListener("submit", async (event) => {
        event.preventDefault();
        const picked = (c) => (c.all.checked ? null : c.each.filter(([i]) => i.checked).map(([i]) => i.value));
        const may = Object.fromEntries(words.map(([k, input]) => [k, input.checked]));
        may.kinds = picked(kinds);
        may.contracts = picked(rules);
        may.until = until.value ? Date.parse(`${until.value}T23:59:59Z`) : null;
        if (needs.checked) {
            may.approvals = {
                k: Number(count.value),
                approvers: [...boxes.entries()].filter(([, box]) => box.checked && box.isConnected).map(([id]) => id),
                within: Number(days.value) * 86400000,
                without_presence: anyway.checked,
            };
        }
        const steps = [
            ...(u.step === "actor" ? [{ action: "person.register", user: u.name }] : []),
            ...(u.step === "actor" || u.step === "presence" ? [{ action: "person.presence", user: u.name }] : []),
            { action: "person.delegate", user: u.name, may },
        ];
        const run = async (index) => {
            const prepared = await api("POST", "prepare", steps[index]);
            prepared.progress = { index: index + 1, of: steps.length };
            await approveScreen(prepared, new Map(), async () => {
                if (index + 1 < steps.length) {
                    await run(index + 1);
                    return TAKEN;
                }
                return el("p", { class: "notice", text: t("people.approved", { name: u.name }) });
            });
        };
        try {
            await run(0);
        } catch (error) {
            notice.replaceChildren(problem(t("error.server", { message: error.message })));
        }
    });
    show(el("h1", { text: t("people.approve_title", { name: u.name }) }),
         el("p", { class: "hint", text: t("people.approve_intro") }), form);
}

// --- Rules --------------------------------------------------------------------------

/// The rules sheet's shape, which the form follows. Each key holds a piece
/// of Bo text as written (names, types, values, conditions, in any
/// language), a piece that may stay empty, a yes or no, a choice, a list, or
/// a group of its own; `rules.CONTEXT.KEY` is its label in the catalogs (a
/// list's items `.item`, its button `.add`, a hint `.hint`). The compiler
/// checks the source the sheet writes, so the page checks nothing but what
/// is missing.
const OUTCOMES = ["done", "fails", "expires"];
const piece = { kind: "piece" };
const maybe = { kind: "maybe" };
const yes = { kind: "yes" };
/// A whole number from 1: how many approvals a line asks.
const wholeNumber = { kind: "count" };
const choice = (values, optional = false) => ({ kind: "choice", values, optional });
const listOf = (of) => ({ kind: "list", of });
const group = (context, keys) => ({ kind: "group", context, keys });

const ASSIGN = group("assign", [["name", piece], ["value", piece]]);
const REQUEST = group("request", [["kind", piece], ["to", maybe], ["with", listOf(ASSIGN)],
                                  ["within", piece]]);
const EFFECTS = [["from", listOf(piece), "effects"], ["to_state", maybe, "effects"],
                 ["set", listOf(ASSIGN), "effects"], ["requests", listOf(REQUEST), "effects"]];
const SHEET = group("sheet", [
    ["contract", piece],
    ["parties", listOf(piece)],
    ["thing", group("thing", [
        ["word", piece], ["name", piece],
        ["fields", listOf(group("field", [["name", piece], ["type", piece], ["default", maybe]]))],
    ])],
    ["actions", listOf(group("action", [
        ["action", piece], ["by", maybe], ["to", maybe],
        ["inputs", listOf(group("input", [["name", piece], ["type", piece]]))],
        ["requires", listOf(piece)], ["consent_of", listOf(piece)], ["in_person", yes],
        ["in_person_over", maybe],
        // Requirements of approvals: how many people of the home, of whom,
        // in person or not, within how long, above what (Bo).
        ["approvals", listOf(group("approval", [["count", wholeNumber], ["by", maybe], ["in_person", yes],
                                                ["within", piece], ["guard", maybe]]))],
        ["agents_propose", yes], ["agents_approve", yes], ...EFFECTS,
    ]))],
    ["rules", listOf(group("rule", [["when", piece], ["do", listOf(piece)], ...EFFECTS]))],
    ["answers", listOf(group("answer", [["kind", piece], ["outcome", choice(OUTCOMES)],
                                        ["do", listOf(piece)], ...EFFECTS]))],
    ["tests", listOf(group("test", [
        ["name", maybe],
        ["steps", listOf(group("step", [
            ["party", piece], ["action", piece], ["outcome", choice(OUTCOMES, true)],
            ["args", listOf(piece)], ["to", maybe], ["by", maybe], ["with", listOf(ASSIGN)],
            ["expect", maybe],
        ]))],
    ]))],
]);

const RULES_INPUT = 256 * 1024;
const RULES_DRAFT = "kanhe.rules";

/// The editor's draft, kept in this tab (sessionStorage) so that a reload
/// does not lose it.
function saveDraft(draft) {
    store(sessionStorage, RULES_DRAFT, JSON.stringify({
        sheet: sheetToSend(draft.sheet), source: draft.source, view: draft.view,
        language: draft.language, name: draft.name ?? null,
    }));
}

function loadDraft() {
    try {
        const saved = JSON.parse(stored(sessionStorage, RULES_DRAFT) ?? "null");
        if (saved === null || typeof saved !== "object" || typeof saved.source !== "string") {
            return null;
        }
        return { sheet: openedSheet(saved.sheet ?? {}), source: saved.source,
                 view: saved.view === "text" ? "text" : "form", problems: [], packs: undefined,
                 language: LANGUAGES.includes(saved.language) ? saved.language : state.language,
                 name: typeof saved.name === "string" ? saved.name : undefined };
    } catch {
        return null;
    }
}
const mayWriteRules = () => state.who.role === "owner" || state.who.role === "admin";

function blank(desc) {
    switch (desc.kind) {
    case "piece":
        return "";
    case "maybe":
        return null;
    case "yes":
        return false;
    case "count":
        return 1;
    case "choice":
        return desc.optional ? null : desc.values[0];
    case "list":
        return [];
    default:
        return Object.fromEntries(desc.keys.map(([key, d]) => [key, blank(d)]));
    }
}

/// A sheet read from the compiler or a file, every key the form shows filled in.
function filled(desc, value) {
    switch (desc.kind) {
    case "list":
        return Array.isArray(value) ? value.map((v) => filled(desc.of, v)) : [];
    case "group": {
        const object = value !== null && typeof value === "object" ? value : {};
        return Object.fromEntries(desc.keys.map(([key, d]) => [key, filled(d, object[key])]));
    }
    case "yes":
        return value === true;
    case "count":
        return Number.isInteger(value) && value > 0 ? value : 1;
    case "piece":
        return typeof value === "string" ? value : "";
    default:
        return typeof value === "string" ? value : blank(desc);
    }
}

function openedSheet(value) {
    const sheet = { packs: Array.isArray(value.packs) ? [...value.packs] : [],
                    ...filled(SHEET, value) };
    if (sheet.thing.word === "") {
        sheet.thing.word = "thing";
    }
    return sheet;
}

function newSheet() {
    return openedSheet({ parties: [""] });
}

/// What the compiler gets: pieces without spaces at either end, empty
/// optional pieces left out, and no kind block when the kind has no name
/// and no fields.
function sendable(desc, value) {
    switch (desc.kind) {
    case "piece":
        return value.trim();
    case "maybe": {
        const text = (value ?? "").trim();
        return text === "" ? null : text;
    }
    case "list":
        return value.map((v) => sendable(desc.of, v));
    case "group":
        return Object.fromEntries(desc.keys.map(([key, d]) => [key, sendable(d, value[key])]));
    default:
        return value;
    }
}

function sheetToSend(sheet) {
    const out = { sheet: 1, kind: "rules", packs: sheet.packs, ...sendable(SHEET, sheet) };
    if (out.thing.name === "" && out.thing.fields.length === 0) {
        out.thing = null;
    }
    return out;
}

/// The pieces left empty that must be filled in.
function missingPieces(sheet) {
    const out = [];
    const walk = (desc, value, path) => {
        if (desc.kind === "piece" && value.trim() === "") {
            out.push({ path, message: t("rules.required") });
        } else if (desc.kind === "list") {
            value.forEach((v, i) => walk(desc.of, v, `${path}/${i}`));
        } else if (desc.kind === "group") {
            desc.keys.forEach(([key, d]) => walk(d, value[key], `${path}/${key}`));
        }
    };
    const kind = sheetToSend(sheet).thing !== null;
    for (const [key, d] of SHEET.keys) {
        if (key !== "thing" || kind) {
            walk(d, sheet[key], `/${key}`);
        }
    }
    return out;
}

/// A sheet path in the reader's words: "Action 1 › Condition 2".
function placeOf(path) {
    const names = [];
    let desc = SHEET;
    let labelKey = null;
    const parts = (path ?? "").split("/").slice(1);
    for (let i = 0; i < parts.length; i++) {
        if (desc.kind === "group") {
            const entry = desc.keys.find(([key]) => key === parts[i]);
            if (!entry) {
                if (parts[i] === "packs") {
                    names.push(t("rules.packs"));
                }
                break;
            }
            labelKey = `rules.${entry[2] ?? desc.context}.${parts[i]}`;
            desc = entry[1];
            if (desc.kind !== "list" || i === parts.length - 1) {
                names.push(t(labelKey));
            }
        } else if (desc.kind === "list") {
            names.push(t(`${labelKey}.item`, { n: Number(parts[i]) + 1 }));
            desc = desc.of;
        } else {
            break;
        }
    }
    return names.join(" › ");
}

function hintOf(labelKey, id) {
    const key = `${labelKey}.hint`;
    return state.english[key] === undefined ? null
                                             : el("span", { id, class: "hint", text: t(key) });
}

/// The form for one key of a group (or one item of a list): its inputs
/// write into the sheet as the person types; adding or removing an item
/// draws the form again, focused on `path`.
function formPart(desc, holder, key, path, labelKey, redraw) {
    const value = holder[key];
    const id = `rules${path.replace(/\//g, "-")}`;
    switch (desc.kind) {
    case "piece":
    case "maybe": {
        const hint = hintOf(labelKey, `${id}-hint`);
        const input = el("input", { id, value: value ?? "", spellcheck: "false",
                                    autocomplete: "off", maxlength: 4096,
                                    "aria-describedby": hint ? `${id}-hint` : null });
        input.addEventListener("input", () => {
            holder[key] = input.value;
        });
        return el("div", { class: "field", "data-path": path },
                  el("label", { for: id, text: t(labelKey) }), input, hint);
    }
    case "yes": {
        const box = el("input", { type: "checkbox", id, checked: value });
        box.addEventListener("change", () => {
            holder[key] = box.checked;
        });
        return el("label", { class: "check", "data-path": path }, box, " ", t(labelKey));
    }
    case "count": {
        const hint = hintOf(labelKey, `${id}-hint`);
        const input = el("input", { id, type: "number", min: 1, max: 16, value: String(value),
                                    inputmode: "numeric", "aria-describedby": hint ? `${id}-hint` : null });
        input.addEventListener("input", () => {
            const n = Number(input.value);
            holder[key] = Number.isInteger(n) && n > 0 ? n : 1;
        });
        return el("div", { class: "field", "data-path": path },
                  el("label", { for: id, text: t(labelKey) }), input, hint);
    }
    case "choice": {
        const select = el("select", { id },
                          desc.optional ? el("option", { value: "", text: t("rules.outcome.none") })
                                        : null,
                          desc.values.map((v) => el("option", { value: v, selected: value === v,
                                                                text: t(`rules.outcome.${v}`) })));
        select.addEventListener("change", () => {
            holder[key] = select.value === "" ? null : select.value;
        });
        return el("div", { class: "field", "data-path": path },
                  el("label", { for: id, text: t(labelKey) }), select);
    }
    case "list": {
        const items = value.map((item, i) => {
            const itemPath = `${path}/${i}`;
            const name = t(`${labelKey}.item`, { n: i + 1 });
            const remove = el("button", { type: "button", class: "remove", text: t("rules.remove"),
                                          "aria-label": t("rules.remove_label", { what: name }) });
            remove.addEventListener("click", () => {
                value.splice(i, 1);
                redraw(path);
            });
            if (desc.of.kind === "group") {
                return groupPart(desc.of, item, itemPath, name, redraw, remove);
            }
            const input = el("input", { id: `rules${itemPath.replace(/\//g, "-")}`, value: item,
                                        spellcheck: "false", autocomplete: "off", maxlength: 4096,
                                        "aria-label": name });
            input.addEventListener("input", () => {
                value[i] = input.value;
            });
            return el("div", { class: "item", "data-path": itemPath }, input, remove);
        });
        const add = el("button", { type: "button", class: "add", text: t(`${labelKey}.add`) });
        add.addEventListener("click", () => {
            value.push(blank(desc.of));
            redraw(`${path}/${value.length - 1}`);
        });
        return el("fieldset", { class: "list", "data-path": path },
                  el("legend", { text: t(labelKey) }), hintOf(labelKey), items, add);
    }
    default:
        return groupPart(desc, value, path, t(labelKey), redraw);
    }
}

function groupPart(desc, value, path, legend, redraw, extra = null) {
    return el("fieldset", { class: "group", "data-path": path }, el("legend", { text: legend }),
              desc.keys.map(([key, d, context]) =>
                  formPart(d, value, key, `${path}/${key}`, `rules.${context ?? desc.context}.${key}`,
                           redraw)),
              extra);
}

/// The packs, as boxes to tick: a pack's words mean something only where
/// its box is ticked.
function packsPart(draft) {
    const boxes = (draft.packs ?? []).map((pack) => {
        const box = el("input", { type: "checkbox", checked: draft.sheet.packs.includes(pack.id) });
        box.addEventListener("change", () => {
            const others = draft.sheet.packs.filter((id) => id !== pack.id);
            draft.sheet.packs = box.checked ? [...others, pack.id] : others;
        });
        return el("label", { class: "check" }, box, " ",
                  t("rules.pack", { name: pack.name ?? pack.id, words: pack.words }));
    });
    return el("fieldset", { class: "list", "data-path": "/packs" },
              el("legend", { text: t("rules.packs") }),
              el("p", { class: "hint", text: t("rules.packs_hint") }), boxes);
}

/// Each problem shown on the part of the form it belongs to (or on the
/// nearest part that holds it).
function markProblems(area, problems) {
    problems.forEach((problem, n) => {
        let path = problem.path ?? "";
        let target = null;
        while (path !== "") {
            target = area.querySelector(`[data-path="${CSS.escape(path)}"]`);
            if (target) {
                break;
            }
            path = path.slice(0, path.lastIndexOf("/"));
        }
        if (!target) {
            return;
        }
        const id = `rules-problem-${n}`;
        const note = el("p", { id, class: problem.severity === "warning" ? "problem warning" : "problem",
                               text: t(problem.severity === "warning" ? "rules.warning" : "rules.error",
                                       { message: problem.message }) });
        const legend = target.querySelector(":scope > legend");
        if (legend) {
            legend.after(note);
        } else {
            target.append(note);
        }
        const input = target.querySelector(":scope > input, :scope > select, :scope > label > input");
        if (input) {
            input.setAttribute("aria-invalid", "true");
            const described = input.getAttribute("aria-describedby");
            input.setAttribute("aria-describedby", described ? `${described} ${id}` : id);
        }
    });
}

/// The sheet's form, drawn again whenever an item comes or goes (its
/// problems then forgotten: their places have moved).
function sheetForm(draft, moved) {
    const area = el("div", { class: "rules-form" });
    const redraw = (focus) => {
        draft.problems = [];
        moved();
        draw(focus);
    };
    const draw = (focus) => {
        const sheet = draft.sheet;
        area.replaceChildren(packsPart(draft),
                             ...SHEET.keys.map(([key, d]) =>
                                 formPart(d, sheet, key, `/${key}`, `rules.sheet.${key}`, redraw)));
        markProblems(area, draft.problems);
        if (focus) {
            const target = area.querySelector(`[data-path="${CSS.escape(focus)}"]`);
            const control = target?.querySelector("input, select") ?? target;
            const list = focus.match(/\/\d+$/) ? null : target?.querySelector(":scope > button.add");
            (list ?? control)?.focus();
        }
    };
    draw();
    area.redraw = () => draw();
    return area;
}

/// A problem in the list above the results: where (a place in the form, or
/// a line of the text), and a button that goes there.
function problemsPanel(problems, go) {
    if (problems.length === 0) {
        return null;
    }
    const errors = problems.some((p) => p.severity !== "warning");
    return el("div", { class: errors ? "error" : "notice", role: "alert" },
              el("strong", { text: t("rules.problems", { n: problems.length }) }),
              el("ul", {}, problems.map((p) => {
                  const where = p.line ? t("rules.at_line", { line: p.line, message: p.message })
                      : p.path ? t("rules.at_place", { place: placeOf(p.path), message: p.message })
                      : p.message;
                  const button = el("button", { type: "button", class: "link", text: where });
                  button.addEventListener("click", () => go(p));
                  return el("li", { class: p.severity === "warning" ? null : "bad" }, button);
              })));
}

/// The compiler's problems in the page's terms.
const problemsOf = (diagnostics, withLines) => (diagnostics ?? []).map((d) => ({
    path: d.path ?? null, severity: d.severity, message: d.message,
    line: withLines && d.span?.line > 0 ? d.span.line : null,
}));

function languageName(language) {
    return document.querySelector(`#language option[value="${language}"]`)?.textContent ?? language;
}

function slug(text) {
    return text.trim().toLowerCase().replace(/[^\p{L}\p{N}]+/gu, "-").replace(/^-|-$/g, "") || "rules";
}

/// The rules on this ledger, and retiring them.
async function rulesScreen() {
    const listed = await api("GET", "rules");
    const writes = mayWriteRules();
    const rows = table(t("rules.deployed"), [
        ["column.name", (c) => c.name ?? short(c.id).text],
        ["column.functions", (c) => c.functions.join(", ")],
        ["column.instances", (c) => String(c.instances)],
        ["thing.entry", (c) => String(c.index)],
        ["column.state", (c) => t(c.retired ? "value.retired" : "value.active")],
        ["column.id", (c) => short(c.id)],
        ...(state.who.role !== "viewer" ? [["column.actions", (c) => {
            if (c.retired) {
                return t("value.none");
            }
            const name = c.name ?? short(c.id).text;
            const create = el("a", { href: `#/create/${c.id}`, class: "button",
                                     text: t("thing.create"),
                                     "aria-label": t("thing.create_label", { name }) });
            if (!writes) {
                return create;
            }
            const button = el("button", { type: "button", text: t("rules.retire"),
                                          "aria-label": t("rules.retire_label", { name }) });
            button.addEventListener("click", () => retireScreen(c));
            return el("div", { class: "toolbar" }, create, button);
        }]] : []),
    ], listed.contracts);
    show(keysNotice(), el("h1", { text: t("rules.title") }),
         el("p", { class: "hint", text: t("rules.hint") }),
         writes ? el("p", {}, el("a", { href: "#/rules/new", class: "button", text: t("rules.write") }))
                : null,
         ...rows);
}

function retireScreen(contract) {
    const name = contract.name ?? short(contract.id).text;
    const [reasonField, reason] = field("retire-reason", t("rules.retire_reason"),
                                        t("rules.retire_reason_hint"), { maxlength: 200 });
    const notice = el("div");
    const form = el("form", { novalidate: true }, reasonField, notice,
                    el("button", { type: "submit", class: "primary", text: t("act.prepare") }),
                    " ", backButton(t("approve.cancel")));
    form.addEventListener("submit", async (event) => {
        event.preventDefault();
        try {
            await approveScreen(await api("POST", "prepare", {
                action: "contract.retire", contract: contract.id, reason: reason.value.trim(),
            }));
        } catch (error) {
            notice.replaceChildren(problem(error.status === 423 ? t("keys.locked")
                                                                : passkeyProblem(error)));
        }
    });
    show(el("h1", { text: t("rules.retire_title", { name }) }),
         el("p", { text: t("rules.retire_intro") }), el("p", { class: "id", text: contract.id }), form);
}

/// Saves text as a file in the browser.
function saveText(text, name, type) {
    const url = URL.createObjectURL(new Blob([text], { type }));
    const link = el("a", { href: url, download: name });
    document.body.append(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
}

/// The rules editor: the form and the Bo text are two views of the same
/// rules; the compiler, in the console, checks, explains, and tests them,
/// and a deploy is approved with a passkey. The draft lives as long as the
/// page.
async function rulesEditor() {
    if (!mayWriteRules()) {
        show(el("h1", { text: t("rules.editor_title") }), el("p", { text: t("rules.read_only") }));
        return;
    }
    const draft = state.rules ??= loadDraft() ?? { sheet: newSheet(), source: "", view: "form",
                                                   problems: [], packs: undefined,
                                                   language: state.language };
    if (draft.packs === undefined) {
        try {
            draft.packs = (await api("GET", "rules/packs")).packs.filter((p) => p.id !== "core");
        } catch (error) {
            if (error instanceof ApiError && error.status === 501) {
                show(el("h1", { text: t("rules.editor_title") }),
                     el("p", { text: t("rules.no_compiler") }));
                return;
            }
            throw error;
        }
    }
    const view = el("div");
    const problems = el("div");
    const results = el("div", { "aria-live": "polite" });
    let form = null;
    let text = null;

    const formButton = el("button", { type: "button", text: t("rules.view_form") });
    const textButton = el("button", { type: "button", text: t("rules.view_text") });
    const actions = ["check", "explain", "test", "deploy"].map((what) =>
        el("button", { type: "button", class: what === "deploy" ? "primary" : null,
                       text: t(`rules.${what}`) }));
    const [check, explain, test, deploy] = actions;
    const opener = el("input", { id: "rules-open", type: "file", accept: ".bo,.json,text/plain,application/json",
                                 "aria-describedby": "rules-open-hint" });
    const download = el("button", { type: "button", text: t("rules.download") });
    const buttons = [formButton, textButton, ...actions, download, opener];

    const goTo = (p) => {
        if (draft.view === "text" && p.line && text) {
            const lines = text.value.split("\n");
            const start = lines.slice(0, p.line - 1).reduce((n, l) => n + l.length + 1, 0);
            text.focus();
            text.setSelectionRange(start, start + (lines[p.line - 1]?.length ?? 0));
            return;
        }
        let path = p.path ?? "";
        while (path !== "" && form) {
            const target = form.querySelector(`[data-path="${CSS.escape(path)}"]`);
            if (target) {
                (target.querySelector("input, select, button") ?? target).focus();
                return;
            }
            path = path.slice(0, path.lastIndexOf("/"));
        }
    };
    const setProblems = (list) => {
        draft.problems = list;
        problems.replaceChildren(problemsPanel(list, goTo) ?? "");
        if (form) {
            form.redraw();
        }
    };

    const drawView = () => {
        saveDraft(draft);
        formButton.setAttribute("aria-pressed", String(draft.view === "form"));
        textButton.setAttribute("aria-pressed", String(draft.view === "text"));
        if (draft.view === "form") {
            text = null;
            form = sheetForm(draft, () => problems.replaceChildren());
            view.replaceChildren(form);
            return;
        }
        form = null;
        text = el("textarea", { id: "rules-source", class: "source", rows: 24, spellcheck: "false",
                                autocomplete: "off", wrap: "off", "aria-describedby": "rules-source-hint" });
        text.value = draft.source;
        text.addEventListener("input", () => {
            draft.source = text.value;
        });
        const language = el("select", { id: "rules-language" },
                            LANGUAGES.map((l) => el("option", { value: l, lang: l, text: languageName(l),
                                                                selected: l === draft.language })));
        language.addEventListener("change", () => busy(async () => {
            const answer = await api("POST", "rules/fmt", { source: text.value, language: language.value });
            if (answer.ok) {
                draft.language = language.value;
                draft.source = answer.source;
                text.value = answer.source;
                setProblems([]);
            } else {
                language.value = draft.language;
                setProblems(problemsOf(answer.diagnostics, true));
            }
        }));
        view.replaceChildren(
            el("div", { class: "field wide" }, el("label", { for: "rules-source", text: t("rules.source") }),
               text, el("span", { id: "rules-source-hint", class: "hint", text: t("rules.source_hint") })),
            el("div", { class: "field" }, el("label", { for: "rules-language", text: t("rules.write_in") }),
               language));
    };

    let working = false;
    async function busy(work) {
        if (working) {
            return;
        }
        working = true;
        buttons.forEach((b) => { b.disabled = true; });
        status(t("status.working"));
        try {
            await work();
        } catch (error) {
            results.replaceChildren(problem(
                error.status === 423 ? t("keys.locked")
                    : error.status === 501 ? t("rules.no_compiler")
                    : t("error.server", { message: error.message })));
        } finally {
            working = false;
            buttons.forEach((b) => { b.disabled = false; });
            status("");
        }
    }

    /// The source the form writes, checked, with each problem on its field;
    /// null if it does not check.
    const fromForm = async () => {
        const missing = missingPieces(draft.sheet);
        if (missing.length > 0) {
            setProblems(missing);
            return null;
        }
        const answer = await api("POST", "rules/form", { sheet: sheetToSend(draft.sheet),
                                                        language: state.language });
        if (answer.source === undefined) {
            setProblems([{ path: answer.path, message: answer.error }]);
            return null;
        }
        draft.language = state.language;
        setProblems(problemsOf(answer.diagnostics, false));
        return answer;
    };
    /// The source in either view, checked; null if it does not check.
    const checkedSource = async () => {
        if (draft.view === "form") {
            const answer = await fromForm();
            return answer?.ok ? answer.source : null;
        }
        draft.source = text.value;
        const answer = await api("POST", "rules/check", { source: draft.source, language: state.language });
        setProblems(problemsOf(answer.diagnostics, true));
        return answer.ok ? draft.source : null;
    };

    formButton.addEventListener("click", () => busy(async () => {
        if (draft.view === "form") {
            return;
        }
        draft.source = text.value;
        const answer = await api("POST", "rules/from", { source: draft.source });
        if (!answer.fits) {
            setProblems([{ severity: "warning", line: answer.line ?? null,
                           message: t("rules.unfit", { reason: answer.reason }) },
                         ...problemsOf(answer.diagnostics, true)]);
            return;
        }
        draft.sheet = openedSheet(answer.sheet);
        draft.view = "form";
        setProblems([]);
        drawView();
    }));
    textButton.addEventListener("click", () => busy(async () => {
        if (draft.view === "text") {
            return;
        }
        const answer = await fromForm();
        if (answer === null) {
            return;
        }
        draft.source = answer.source;
        draft.view = "text";
        // The lines' problems, now that the lines show.
        setProblems(problemsOf(answer.diagnostics, true));
        drawView();
    }));
    check.addEventListener("click", () => busy(async () => {
        results.replaceChildren();
        if (await checkedSource() !== null && draft.problems.length === 0) {
            results.replaceChildren(el("p", { class: "notice", role: "status", text: t("rules.no_problems") }));
        }
    }));
    explain.addEventListener("click", () => busy(async () => {
        results.replaceChildren();
        const source = await checkedSource();
        if (source === null) {
            return;
        }
        // One at a time: the console runs one compiler per session.
        const columns = [];
        for (const language of LANGUAGES) {
            const answer = await api("POST", "rules/explain", { source, language });
            columns.push(el("article", { class: "explained", lang: language },
                            el("h3", { text: languageName(language) }),
                            el("pre", { text: answer.text ?? "" })));
        }
        results.replaceChildren(el("h2", { text: t("rules.explain_title") }),
                                el("p", { class: "hint", text: t("rules.explain_hint") }),
                                el("div", { class: "explained-all" }, columns));
    }));
    test.addEventListener("click", () => busy(async () => {
        results.replaceChildren();
        const source = await checkedSource();
        if (source === null) {
            return;
        }
        const answer = await api("POST", "rules/test", { source, language: state.language });
        if (!answer.built) {
            setProblems(problemsOf(answer.diagnostics, draft.view === "text"));
            return;
        }
        const tests = answer.tests ?? [];
        results.replaceChildren(
            el("h2", { text: t("rules.tests_title") }),
            el("p", { role: "status", class: answer.failed > 0 ? "error" : "notice",
                      text: tests.length === 0 ? t("rules.no_tests")
                                               : t("rules.tests_summary", { passed: answer.passed,
                                                                            total: answer.total }) }),
            tests.length === 0 ? null : el("ul", {}, tests.map((x, i) => el("li", {
                class: x.passed ? null : "bad",
                text: t(x.passed ? "rules.test_passed" : "rules.test_failed",
                        { name: x.name ?? t("rules.test_unnamed", { n: i + 1 }) }),
            }))),
            tests.length === 0 ? null : el("details", {}, el("summary", { text: t("rules.test_steps") }),
                                           el("pre", { text: answer.text ?? "" })));
    }));
    deploy.addEventListener("click", () => busy(async () => {
        results.replaceChildren();
        const source = await checkedSource();
        if (source === null) {
            return;
        }
        await approveScreen(await api("POST", "prepare", { action: "contract.deploy", source }));
    }));
    download.addEventListener("click", () => {
        const name = slug(draft.sheet.contract || draft.name || "");
        if (draft.view === "form") {
            saveText(`${JSON.stringify(sheetToSend(draft.sheet), null, 2)}\n`, `${name}.json`,
                     "application/json");
        } else {
            saveText(text.value, `${name}.bo`, "text/plain");
        }
    });
    opener.addEventListener("change", () => busy(async () => {
        const file = opener.files[0];
        opener.value = "";
        if (!file) {
            return;
        }
        if (file.size > RULES_INPUT) {
            throw new ApiError(413, t("rules.too_large", { name: file.name }));
        }
        const content = await file.text();
        draft.name = file.name.replace(/\.[^.]*$/, "");
        results.replaceChildren();
        if (file.name.endsWith(".json")) {
            let parsed = null;
            try {
                parsed = JSON.parse(content);
            } catch {
                // Not JSON: said below.
            }
            if (parsed?.kind !== "rules") {
                throw new ApiError(400, t("rules.not_a_sheet", { name: file.name }));
            }
            draft.sheet = openedSheet(parsed);
            draft.view = "form";
            setProblems([]);
            drawView();
            return;
        }
        // A source opens in the form if it fits, and as text if not.
        draft.source = content;
        const answer = await api("POST", "rules/from", { source: content });
        if (answer.fits) {
            draft.sheet = openedSheet(answer.sheet);
            draft.view = "form";
            setProblems([]);
        } else {
            draft.view = "text";
            draft.sheet = newSheet();
            setProblems([{ severity: "warning", line: answer.line ?? null,
                           message: t("rules.unfit", { reason: answer.reason }) },
                         ...problemsOf(answer.diagnostics, true)]);
        }
        drawView();
    }));

    drawView();
    problems.replaceChildren(problemsPanel(draft.problems, goTo) ?? "");
    // Every change kept in this tab: typing, ticking, adding, removing.
    for (const type of ["input", "change"]) {
        view.addEventListener(type, () => saveDraft(draft));
    }
    view.addEventListener("click", () => setTimeout(() => saveDraft(draft)));
    for (const b of buttons) {
        b.addEventListener("click", () => setTimeout(() => saveDraft(draft)));
    }
    show(keysNotice(), el("h1", { text: t("rules.editor_title") }),
         el("p", { class: "hint", text: t("rules.editor_intro") }),
         el("div", { class: "toolbar", role: "group", "aria-label": t("rules.view") },
            formButton, textButton),
         el("div", { class: "field" },
            el("label", { for: "rules-open", text: t("rules.open") }), opener,
            el("span", { id: "rules-open-hint", class: "hint", text: t("rules.open_hint") })),
         view, problems,
         el("div", { class: "toolbar" }, ...actions, download),
         results);
}

// --- Things with rules --------------------------------------------------------

/// A value a call takes, as an input of the form: drawn by its type (the
/// compiler's encoded type, with its words in the reader's language), read
/// back as the compiler takes it (a text as typed, yes or no, a ledger id, a
/// list one item a line, anything else written as Bo writes it).
function valueInput(input, id, ledger) {
    const type = input.type;
    const hintId = `${id}-hint`;
    const label = el("label", { for: id, text: input.optional ? t("thing.optional", { name: input.label })
                                                             : input.label });
    const hint = el("span", { id: hintId, class: "hint",
                              text: input.initial ? t("thing.type_default", { type: input.type_text,
                                                                               initial: input.initial })
                                                  : input.type_text });
    let control;
    let read;
    if (type === "yes_no") {
        control = el("select", { id, "aria-describedby": hintId },
                     input.optional ? el("option", { value: "", text: "" }) : null,
                     el("option", { value: "yes", text: t("value.yes") }),
                     el("option", { value: "no", text: t("value.no") }));
        read = () => (control.value === "" ? undefined : control.value === "yes");
    } else if (type === "party") {
        const other = el("input", { id: `${id}-other`, spellcheck: "false", autocomplete: "off",
                                    maxlength: 64, "aria-label": t("thing.ledger_id", { name: input.label }),
                                    placeholder: t("thing.ledger_id_hint") });
        control = el("select", { id, "aria-describedby": hintId },
                     input.optional ? el("option", { value: "", text: "" }) : null,
                     el("option", { value: ledger.id, text: t("thing.this_ledger", { name: ledger.name }) }),
                     el("option", { value: "other", text: t("thing.other_ledger") }));
        other.hidden = true;
        control.addEventListener("change", () => {
            other.hidden = control.value !== "other";
        });
        read = () => (control.value === "" ? undefined
            : control.value === "other" ? other.value.trim().toLowerCase() : control.value);
        return { element: el("div", { class: "field", "data-name": input.name }, label, control, other, hint),
                 read, name: input.name };
    } else if (type.startsWith("list ")) {
        control = el("textarea", { id, rows: 3, spellcheck: "false", "aria-describedby": hintId });
        read = () => {
            const items = control.value.split("\n").map((l) => l.trim()).filter((l) => l !== "");
            return input.optional && items.length === 0 ? undefined : items;
        };
        hint.textContent = t("thing.list_hint", { type: input.type_text });
    } else {
        control = el("input", { id, type: type === "date" ? "date" : "text", spellcheck: "false",
                                autocomplete: "off", maxlength: 1000, "aria-describedby": hintId,
                                placeholder: type === "text" ? null : t(`thing.example.${type.split(" ")[0]}`) });
        read = () => (control.value.trim() === "" && input.optional ? undefined
            : type === "text" ? control.value : control.value.trim());
    }
    return { element: el("div", { class: "field", "data-name": input.name }, label, control, hint),
             read, name: input.name };
}

/// The values of a call's inputs, by name (those left out are not sent).
function valuesOf(inputs) {
    const values = {};
    for (const i of inputs) {
        const v = i.read();
        if (v !== undefined) {
            values[i.name] = v;
        }
    }
    return values;
}

/// Why a call is not prepared, on the inputs it names and in a notice: the
/// values that do not go in, the consents it waits for, or the contract's
/// refusal.
function callProblem(error, form, notice, ask = null) {
    for (const p of form.querySelectorAll(".problem")) {
        p.remove();
    }
    const answer = error.answer ?? {};
    if (Array.isArray(answer.problems) && answer.problems.length > 0) {
        for (const p of answer.problems) {
            const name = String(p.name ?? "").split("/")[0];
            const target = form.querySelector(`[data-name="${CSS.escape(name)}"]`);
            const message = t(`thing.problem.${p.code}`, { type: p.type_text ?? "" });
            if (target) {
                target.append(el("p", { class: "problem", text: t("rules.error", { message }) }));
            }
        }
        notice.replaceChildren(problem(t("thing.values_problem")));
        return;
    }
    const run = answer.dry_run;
    if (run?.verdict === "needs") {
        notice.replaceChildren(problem(t("thing.needs_consent", {
            ledgers: run.needs.map((l) => `${l.slice(0, 12)}...`).join(", "),
        })), ask ? askByFile(ask) : null);
        return;
    }
    if (run?.verdict === "refuse") {
        notice.replaceChildren(problem(t("thing.refused", { reason: run.reason })));
        return;
    }
    notice.replaceChildren(problem(error.status === 423 ? t("keys.locked")
                                                        : t("error.server", { message: error.message })));
}

/// A form for one call: its inputs, then Prepare, which runs it on the
/// ledger's state and, if the contract takes it, opens the approval.
function callForm(call, intent, ledger, idPrefix) {
    const inputs = call.inputs.map((input, n) => valueInput(input, `${idPrefix}-${n}`, ledger));
    const notice = el("div");
    const prepare = el("button", { type: "submit", class: "primary", text: t("act.prepare") });
    const form = el("form", { novalidate: true, class: "call" }, inputs.map((i) => i.element), notice,
                    prepare);
    form.addEventListener("submit", async (event) => {
        event.preventDefault();
        prepare.disabled = true;
        status(t("status.working"));
        try {
            const prepared = await api("POST", "prepare", {
                ...intent, values: valuesOf(inputs), language: state.language,
            });
            await approveScreen(prepared);
        } catch (error) {
            callProblem(error, form, notice,
                        intent.action === "contract.call" ? () => ({ ...intent, values: valuesOf(inputs) })
                                                          : null);
        } finally {
            prepare.disabled = false;
            status("");
        }
    });
    return form;
}

/// Asking for the consents a call waits for, by file: a note, then the
/// proposal file to send by any channel.
function askByFile(intentOf) {
    const id = `ask-note-${Math.random().toString(36).slice(2, 8)}`;
    const [noteField, note] = field(id, t("exchange.note"), t("exchange.note_hint"), { maxlength: 1000 });
    const made = el("div", { role: "status" });
    const button = el("button", { type: "button", class: "primary", text: t("exchange.ask") });
    button.addEventListener("click", async () => {
        button.disabled = true;
        status(t("status.working"));
        try {
            const name = await saveDownload("exchange/proposal", {
                method: "POST", headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ ...intentOf(), note: note.value.trim(), language: state.language }),
            }, "proposal.kanhe");
            made.replaceChildren(el("p", { class: "notice", text: t("exchange.proposal_made", { name }) }));
        } catch (error) {
            made.replaceChildren(problem(t("error.server", { message: error.message })));
        } finally {
            button.disabled = false;
            status("");
        }
    });
    // Online: this ledger's registrar holds the call, and records it once
    // the consents come in from the other ledgers.
    const online = el("button", { type: "button", text: t("exchange.propose") });
    online.addEventListener("click", async () => {
        online.disabled = true;
        status(t("status.working"));
        try {
            const held = await api("POST", "exchange/propose", { ...intentOf(), language: state.language });
            made.replaceChildren(el("p", { class: "notice", text: t("exchange.proposed", {
                until: timeText(held.until), call: String(held.call ?? "").slice(0, 12),
            }) }));
        } catch (error) {
            made.replaceChildren(problem(error.status === 501 || error.status === 503
                ? t("exchange.no_registrar") : t("error.server", { message: error.message })));
        } finally {
            online.disabled = false;
            status("");
        }
    });
    return el("section", { class: "kind", "aria-label": t("exchange.ask") },
              el("p", { text: t("exchange.ask_intro") }), noteField,
              el("div", { class: "toolbar" }, button, online), made);
}

/// The parties this console works with: inviting one, accepting an
/// invitation (which invites back), and the parties connected.
async function partiesScreen() {
    const [listed, access, witnesses, relay] = await Promise.all([
        api("GET", "parties"), api("GET", "access"), api("GET", "witnesses"), api("GET", "relay")]);
    const parts = [flash(), el("h1", { text: t("parties.title") }), el("p", { class: "hint", text: t("parties.intro") }),
                   el("p", { text: t("parties.our_fingerprint", { fingerprint: listed.fingerprint }) })];
    // Witnessing: the size each side last cosigned of the other's ledger.
    const cosigned = (w) => (!w ? t("value.none")
        : w.size ? t("parties.cosigned_size", { size: w.size }) : t("parties.not_yet"));
    parts.push(...table(t("parties.connected"), [
        ["column.name", (p) => p.name],
        ["parties.fingerprint", (p) => p.fingerprint],
        ["parties.online", (p) => yesNo(p.online)],
        ["parties.witnesses_us", (p) => cosigned(p.witnesses_us)],
        ["parties.we_witness", (p) => cosigned(p.we_witness)],
        ["column.id", (p) => short(p.ledger)],
    ], listed.peers));
    for (const p of listed.peers) {
        if (p.we_witness?.refused) {
            parts.push(problem(t("parties.refused", { name: p.name, message: p.we_witness.refused })));
        }
        if (p.witnesses_us?.problem) {
            parts.push(el("p", { class: "hint", text: t("parties.not_cosigned", {
                name: p.name, message: p.witnesses_us.problem }) }));
        }
    }
    if (listed.waiting.length) {
        parts.push(el("p", { class: "hint", text: t("parties.waiting_answer", { names: listed.waiting.join(", ") }) }));
    }
    parts.push(...documentsView(access, listed.peers.filter((p) => p.online)));
    parts.push(...witnessesView(witnesses), ...relayView(relay));
    if (!listed.may_change) {
        show(...parts);
        return;
    }
    // Invite: a name, then the code to send them.
    const [nameField, name] = field("party-name", t("parties.name"), t("parties.name_hint"), { maxlength: 64 });
    const invited = el("div", { role: "status" });
    const invite = el("button", { type: "submit", class: "primary", text: t("parties.invite") });
    const inviteForm = el("form", { novalidate: true }, nameField, invite, invited);
    inviteForm.addEventListener("submit", async (event) => {
        event.preventDefault();
        try {
            const made = await api("POST", "parties", { invite: name.value.trim() });
            invited.replaceChildren(codeView(made.code, t("parties.code_for", { name: made.name }),
                                             made.fingerprint));
        } catch (error) {
            invited.replaceChildren(problem(t("error.server", { message: error.message })));
        }
    });
    // Accept: their code and what to call them; an answer code to send back.
    const code = el("textarea", { id: "party-code", rows: 3, spellcheck: "false", "aria-describedby": "party-code-hint" });
    const [acceptNameField, acceptName] = field("party-accept-name", t("parties.name"), t("parties.accept_name_hint"), { maxlength: 64 });
    const accepted = el("div", { role: "status" });
    const accept = el("button", { type: "submit", class: "primary", text: t("parties.accept") });
    const acceptForm = el("form", { novalidate: true },
                          el("div", { class: "field" }, el("label", { for: "party-code", text: t("parties.code") }), code,
                             el("span", { id: "party-code-hint", class: "hint", text: t("parties.code_hint") })),
                          acceptNameField, accept, accepted);
    acceptForm.addEventListener("submit", async (event) => {
        event.preventDefault();
        try {
            const done = await api("POST", "parties", { accept: code.value.trim(), name: acceptName.value.trim() });
            accepted.replaceChildren(el("p", { class: "notice", text: t("parties.accepted", {
                name: done.name, organization: done.organization, fingerprint: done.fingerprint,
            }) }), done.reply ? codeView(done.reply, t("parties.reply_for", { name: done.name }), listed.fingerprint)
                              : null);
        } catch (error) {
            accepted.replaceChildren(problem(t("error.server", { message: error.message })));
        }
    });
    parts.push(el("h2", { text: t("parties.invite_title") }), inviteForm,
               el("h2", { text: t("parties.accept_title") }), acceptForm);
    show(...parts);
}

/// The public witnesses this ledger asks to cosign its checkpoints: who,
/// what they cosigned, and, for an owner or admin, asking another (one
/// this build knows, or any by its URL and key) and stopping one.
function witnessesView(listed) {
    const parts = [el("h2", { text: t("witnesses.title") }),
                   el("p", { class: "hint", text: t("witnesses.intro") })];
    const said = el("div", { role: "status" });
    const ask = async (body, button) => {
        button.disabled = true;
        status(t("status.working"));
        try {
            const added = await api("POST", "witnesses", body);
            state.flash = t("witnesses.added", added);
            route();
        } catch (error) {
            said.replaceChildren(problem(t("error.server", { message: error.message })));
        } finally {
            button.disabled = false;
            status("");
        }
    };
    if (listed.witnesses.length === 0) {
        parts.push(el("p", { text: t("witnesses.none") }));
    } else {
        parts.push(...table(t("witnesses.used"), [
            ["column.name", (w) => w.name],
            ["parties.fingerprint", (w) => w.fingerprint],
            ["parties.witnesses_us", (w) => (w.cosigned ? t("parties.cosigned_size", { size: w.cosigned.size })
                                                         : t("parties.not_yet"))],
            ["witnesses.stop", (w) => {
                if (!listed.may_change) {
                    return t("value.none");
                }
                const stop = el("button", { type: "button", text: t("witnesses.stop"),
                                            "aria-label": t("witnesses.stop_label", { name: w.name }) });
                stop.addEventListener("click", async () => {
                    stop.disabled = true;
                    try {
                        await api("POST", "witnesses", { remove: w.name });
                        state.flash = t("witnesses.stopped", { name: w.name });
                        route();
                    } catch (error) {
                        said.replaceChildren(problem(t("error.server", { message: error.message })));
                        stop.disabled = false;
                    }
                });
                return stop;
            }],
        ], listed.witnesses));
        for (const w of listed.witnesses) {
            if (w.problem) {
                parts.push(el("p", { class: "hint", text: t("parties.not_cosigned", {
                    name: w.name, message: w.problem }) }));
            }
        }
    }
    if (!listed.may_change) {
        return parts;
    }
    // Known ones are offered, never chosen for the person.
    for (const w of listed.known) {
        const use = el("button", { type: "button", text: t("witnesses.use", { name: w.name }) });
        use.addEventListener("click", () => ask({ url: w.url, key: w.key }, use));
        parts.push(el("p", {}, use, " ", el("span", { class: "hint", text: t("witnesses.known_key", {
            fingerprint: w.fingerprint }) })));
    }
    const [urlField, url] = field("witness-url", t("witnesses.url"), t("witnesses.url_hint"),
                                  { type: "url", placeholder: "https://" });
    const [keyField, key] = field("witness-key", t("witnesses.key"), t("witnesses.key_hint"),
                                  { spellcheck: "false" });
    const add = el("button", { type: "submit", text: t("witnesses.add") });
    const form = el("form", { novalidate: true }, urlField, keyField, add, said);
    form.addEventListener("submit", (event) => {
        event.preventDefault();
        ask({ url: url.value.trim(), key: key.value.trim() }, add);
    });
    parts.push(el("h3", { text: t("witnesses.add_title") }), form);
    return parts;
}

/// How parties reach this console: directly, or through a relay (the
/// server of a public witness it asks), for a console on a laptop.
function relayView(relay) {
    const parts = [el("h2", { text: t("relay.title") }), el("p", { class: "hint", text: t("relay.intro") })];
    const said = el("div", { role: "status" });
    if (relay.relay) {
        parts.push(el("p", { text: t("relay.through", { url: relay.relay.url }) }));
    } else {
        parts.push(el("p", { text: t("relay.direct") }));
    }
    if (relay.problem) {
        parts.push(el("p", { class: "problem warning", text: t("relay.problem", { message: relay.problem }) }));
    }
    if (!relay.may_change) {
        return parts;
    }
    const post = async (body, button, done) => {
        button.disabled = true;
        status(t("status.working"));
        try {
            const answer = await api("POST", "relay", body);
            state.flash = done(answer);
            route();
        } catch (error) {
            said.replaceChildren(problem(t("error.server", { message: error.message })));
            button.disabled = false;
        } finally {
            status("");
        }
    };
    for (const c of relay.candidates) {
        const use = el("button", { type: "button", text: t("relay.use", { name: c.name }) });
        use.addEventListener("click", () => post({ use: c.url }, use,
                                                 () => t("relay.used", { name: c.name })));
        parts.push(el("p", {}, use));
    }
    if (relay.candidates.length === 0 && !relay.relay) {
        parts.push(el("p", { class: "hint", text: t("relay.none_possible") }));
    }
    if (relay.relay) {
        const stop = el("button", { type: "button", text: t("relay.stop") });
        stop.addEventListener("click", () => post({ stop: true }, stop, () => t("relay.stopped")));
        parts.push(el("p", {}, stop));
    }
    parts.push(said);
    return parts;
}

// --- Documents between parties --------------------------------------------------

/// What the parties asked of this ledger and what came for its requests:
/// the part of Home that waits on someone here.
async function accessInto(area) {
    let listed;
    try {
        listed = await api("GET", "access");
    } catch {
        return;
    }
    const asked = listed.asked_of_us.filter((r) => !r.problem && !r.granted);
    const came = listed.asked_by_us.filter((r) => r.status === "delivered");
    const parts = [];
    if (asked.length) {
        parts.push(el("h2", { text: t("access.asked_of_you") }),
                   el("ul", {}, asked.map((r) => el("li", {}, t(r.condition ? "access.asks_whether" : "access.asks", {
                       peer: r.peer, purpose: r.purpose, condition: r.condition,
                   }), " ", el("a", { href: `#/access/request/${r.request}`, text: t("access.look"),
                                      "aria-label": t("access.look_label", { peer: r.peer }) })))));
    }
    if (came.length) {
        parts.push(el("h2", { text: t("access.delivered") }),
                   el("ul", {}, came.map((r) => el("li", {}, t(r.condition ? "access.came_answer" : "access.came", {
                       peer: r.peer, purpose: r.purpose,
                   }), " ", el("a", { href: `#/access/delivery/${r.request}`, text: t("access.open"),
                                      "aria-label": t("access.open_label", { peer: r.peer }) })))));
    }
    area.replaceChildren(...parts);
}

const accessStatus = (s) => t(`access.status.${s}`);

/// The Parties screen's documents: asking a party for one, and what was
/// asked and shared either way.
function documentsView(access, online) {
    const parts = [];
    const action = (text, label, run) => {
        const button = el("button", { type: "button", text, "aria-label": label });
        button.disabled = !access.may_act;
        button.addEventListener("click", async () => {
            button.disabled = true;
            status(t("status.working"));
            try {
                await run();
            } catch (error) {
                button.after(problem(t("error.server", { message: error.message })));
                button.disabled = false;
            } finally {
                status("");
            }
        });
        return button;
    };
    const asking = (r) => (r.condition ? `${r.purpose} (${t("access.whether", { condition: r.condition })})` : r.purpose);
    parts.push(...table(t("access.asked_of_them"), [
        ["access.party", (r) => r.peer || short(r.ledger).text],
        ["access.purpose", asking],
        ["access.document", (r) => short(r.record)],
        ["column.status", (r) => accessStatus(r.status)],
        ["column.actions", (r) => (r.status === "delivered" || r.status === "accepted"
            ? el("a", { href: `#/access/delivery/${r.request}`, text: t("access.open"),
                        "aria-label": t("access.open_label", { peer: r.peer }) })
            : r.status === "waiting" && r.online
                ? action(t("access.send_again"), t("access.send_again_label", { peer: r.peer }), async () => {
                    await api("POST", "access/send", { record: r.request });
                    state.flash = t("access.sent", { peer: r.peer });
                    route();
                })
                : "")],
    ], access.asked_by_us));
    parts.push(...table(t("access.asked_of_you"), [
        ["access.party", (r) => r.peer ?? ""],
        ["access.purpose", (r) => r.problem ?? asking(r)],
        ["access.document", (r) => (r.record ? short(r.record) : "")],
        ["column.status", (r) => (r.problem ? t("access.status.unreadable")
            : accessStatus(r.granted ? (r.condition ? "answered" : "granted") : "waiting"))],
        ["column.actions", (r) => (r.problem ? "" : el("a", {
            href: `#/access/request/${r.request}`, text: t("access.look"),
            "aria-label": t("access.look_label", { peer: r.peer }) }))],
    ], access.asked_of_us));
    parts.push(...table(t("access.shared"), [
        ["access.party", (g) => g.peer],
        ["access.document", (g) => short(g.record)],
        ["access.fields", (g) => (g.fields.length ? g.fields.join(", ") : t("value.none"))],
        ["access.files", (g) => (g.files.length ? g.files.join(", ") : t("value.none"))],
        ["column.status", (g) => accessStatus(g.status)],
        ["column.actions", (g) => (g.status === "withdrawn" || g.status === "expired" ? "" : el("span", {},
            g.status === "not_delivered" ? action(t("access.deliver"), t("access.deliver_label", { peer: g.peer }), async () => {
                await api("POST", "access/deliver", { grant: g.grant });
                state.flash = t("access.delivered_ok", { peer: g.peer });
                route();
            }) : null, " ",
            action(t("access.withdraw"), t("access.withdraw_label", { peer: g.peer }), async () => {
                const prepared = await api("POST", "prepare", { action: "record.revoke", record: g.grant,
                                                                 reason: t("access.withdraw_reason") });
                await approveScreen(prepared);
            })))],
    ], access.granted));
    parts.push(...table(t("access.answered"), [
        ["access.party", (c) => c.peer],
        ["access.document", (c) => short(c.record)],
        ["access.answer", (c) => (c.holds ? c.text : t("access.not_holding", { condition: c.text }))],
        ["column.status", (c) => accessStatus(c.status)],
        ["column.actions", (c) => (c.status === "withdrawn" ? "" : el("span", {},
            c.status === "not_delivered" ? action(t("access.deliver"), t("access.deliver_label", { peer: c.peer }), async () => {
                await api("POST", "access/deliver", { claim: c.claim });
                state.flash = t("access.answered_ok", { peer: c.peer });
                route();
            }) : null, " ",
            action(t("access.withdraw"), t("access.withdraw_label", { peer: c.peer }), async () => {
                const prepared = await api("POST", "prepare", { action: "record.revoke", record: c.claim,
                                                                 reason: t("access.withdraw_reason") });
                await approveScreen(prepared);
            })))],
    ], access.answered ?? []));
    // Answering by itself: an owner lets the console's machine answer the
    // questions each kind allows, when they hold.
    if (access.answers_by_console) {
        parts.push(el("p", { class: "hint", text: t("access.by_console") }));
    } else if (access.may_allow_answers) {
        const allow = el("button", { type: "button", text: t("access.allow_console") });
        allow.addEventListener("click", async () => {
            try {
                await approveScreen(await api("POST", "prepare", { action: "machine.answer" }));
            } catch (error) {
                allow.after(problem(t("error.server", { message: error.message })));
            }
        });
        parts.push(el("p", { class: "hint", text: t("access.allow_console_hint") }), el("p", {}, allow));
    }
    if (!access.may_act || online.length === 0) {
        return parts;
    }
    // Asking: a party reached online, the document's id, and why.
    const party = el("select", { id: "access-party" }, online.map((p) => el("option", { value: p.name, text: p.name })));
    const [recordField, record] = field("access-record", t("access.document"), t("access.document_hint"),
                                        { spellcheck: "false", class: "id", maxlength: 64 });
    const [purposeField, purpose] = field("access-purpose", t("access.purpose"), t("access.purpose_hint"), { maxlength: 500 });
    const [fieldsField, fields] = field("access-fields", t("access.fields"), t("access.fields_hint"));
    const files = el("input", { id: "access-files", type: "checkbox", checked: true });
    const [daysField, days] = field("access-days", t("access.days"), t("access.days_hint"),
                                    { type: "number", min: 1, max: 366, value: 30 });
    const notice = el("div", { role: "status" });
    const ask = el("button", { type: "submit", class: "primary", text: t("access.ask") });
    const form = el("form", { novalidate: true },
                    el("div", { class: "field" }, el("label", { for: "access-party", text: t("access.party") }), party),
                    recordField, purposeField, fieldsField,
                    el("div", { class: "field" }, el("label", {}, files, " ", t("access.files_too"))),
                    daysField, notice, ask);
    form.addEventListener("submit", async (event) => {
        event.preventDefault();
        const names = fields.value.split(",").map((n) => n.trim()).filter((n) => n);
        try {
            const prepared = await api("POST", "prepare", {
                action: "access.request", peer: party.value, record: record.value.trim().toLowerCase(),
                purpose: purpose.value.trim(), fields: names.length ? names : null,
                files: files.checked ? null : [], days: Number(days.value) || 30,
            });
            const peer = party.value;
            await approveScreen(prepared, new Map(), async (done) => {
                await api("POST", "access/send", { record: done.statement_id });
                return el("p", { class: "notice", text: t("access.sent", { peer }) });
            });
        } catch (error) {
            notice.replaceChildren(problem(t("error.server", { message: error.message })));
        }
    });
    parts.push(el("h2", { text: t("access.ask_title") }), el("p", { class: "hint", text: t("access.ask_intro") }), form);
    parts.push(...questionForm(online));
    return parts;
}

/// Asking a party whether conditions hold in one of its documents (spec
/// v0.15): it answers with a claim, never with the fields.
function questionForm(online) {
    const party = el("select", { id: "question-party" }, online.map((p) => el("option", { value: p.name, text: p.name })));
    const [recordField, record] = field("question-record", t("access.document"), t("access.document_hint"),
                                        { spellcheck: "false", class: "id", maxlength: 64 });
    const [purposeField, purpose] = field("question-purpose", t("access.purpose"), t("access.purpose_hint"), { maxlength: 500 });
    const { rows, more, read } = conditionRows(null);
    const [daysField, days] = field("question-days", t("access.days"), t("access.question_days_hint"),
                                    { type: "number", min: 1, max: 366, value: 30 });
    const notice = el("div", { role: "status" });
    const ask = el("button", { type: "submit", class: "primary", text: t("access.ask") });
    const form = el("form", { novalidate: true },
                    el("div", { class: "field" }, el("label", { for: "question-party", text: t("access.party") }), party),
                    recordField, purposeField, rows, more,
                    el("p", { class: "hint", text: t("claim.value_hint") }), daysField, notice, ask);
    form.addEventListener("submit", async (event) => {
        event.preventDefault();
        try {
            const prepared = await api("POST", "prepare", {
                action: "access.request", peer: party.value, record: record.value.trim().toLowerCase(),
                purpose: purpose.value.trim(), conditions: read(), days: Number(days.value) || 30,
            });
            const peer = party.value;
            await approveScreen(prepared, new Map(), async (done) => {
                await api("POST", "access/send", { record: done.statement_id });
                return el("p", { class: "notice", text: t("access.question_sent", { peer }) });
            });
        } catch (error) {
            notice.replaceChildren(problem(t("error.server", { message: error.message })));
        }
    });
    return [el("h2", { text: t("access.question_title") }), el("p", { class: "hint", text: t("access.question_intro") }), form];
}

/// A request a party sent: what it asks, and what to share, granted with a tap.
async function accessRequestScreen(id) {
    const r = await api("GET", `access/requests/${id}`);
    const parts = [el("h1", { text: t(r.condition ? "access.question_from" : "access.request_title", { peer: r.peer ?? "" }) })];
    if (r.problem) {
        show(...parts, problem(t("access.unreadable", { message: r.problem })), goButton(t("nav.parties"), "#/parties"));
        return;
    }
    const facts = el("dl", { class: "facts" });
    const fact = (key, value, attributes = {}) => {
        facts.append(el("dt", { text: t(key) }), el("dd", { text: String(value), ...attributes }));
    };
    const names = (list) => (list === null ? t("access.all") : list.length ? list.join(", ") : t("value.none"));
    fact("access.from", r.from);
    fact("access.purpose", r.purpose);
    fact("exchange.until", timeText(r.until));
    fact("access.document", r.record, { class: "id" });
    if (r.kind || r.record_type) {
        fact("column.type", r.kind ?? r.record_type);
    }
    if (r.condition) {
        fact("access.asks_if", r.condition);
    } else {
        fact("access.asked_fields", names(r.asked_fields));
        fact("access.asked_files", names(r.asked_files));
    }
    parts.push(facts);
    if (!r.missing) {
        parts.push(el("p", {}, el("a", { href: `#/thing/${r.record}`, text: t("access.see_document") })));
    }
    const notice = el("div", { role: "status" });
    const dismiss = el("button", { type: "button", text: t("access.dismiss") });
    dismiss.disabled = state.who.role === "viewer";
    dismiss.addEventListener("click", async () => {
        try {
            await api("POST", "access/dismiss", { request: r.request });
            state.flash = t("access.dismissed");
            location.hash = "#/parties";
        } catch (error) {
            notice.replaceChildren(problem(t("error.server", { message: error.message })));
        }
    });
    if (r.granted) {
        parts.push(el("p", { class: "notice", text: t(r.condition ? "access.answered_already" : "access.granted_already") }));
    }
    if (r.condition) {
        answerForm(r, parts, notice, dismiss);
        return;
    }
    if (r.missing || !r.may_grant) {
        parts.push(el("p", { class: "hint", text: t(r.missing ? "access.missing"
            : r.locked ? "home.locked" : "access.cannot_grant") }), notice, dismiss);
        show(...parts);
        return;
    }
    // What to share: what was asked, of what this ledger has (files only
    // where a copy is kept).
    const choice = (name, asked, available, why) => {
        const box = el("input", { type: "checkbox", value: name, checked: asked && available });
        box.disabled = !asked || !available;
        return [box, el("label", {}, box, " ", name, why ? el("span", { class: "hint", text: ` (${why})` }) : null)];
    };
    const fieldBoxes = r.fields.map((f) => choice(f.name, f.asked, true, f.asked ? "" : t("access.not_asked")));
    const fileBoxes = r.files.map((f) => choice(f.name, f.asked, f.kept,
        !f.asked ? t("access.not_asked") : !f.kept ? t("access.not_kept") : sizeText(f.size)));
    const group = (legend, boxes) => el("fieldset", {}, el("legend", { text: legend }),
        boxes.length ? boxes.map(([, label]) => el("div", {}, label)) : el("p", { text: t("value.none") }));
    const [daysField, days] = field("grant-days", t("access.days"), t("access.grant_days_hint"),
                                    { type: "number", min: 1, max: 366, value: 30 });
    const grant = el("button", { type: "submit", class: "primary", text: t("access.grant") });
    const form = el("form", { novalidate: true }, group(t("access.share_fields"), fieldBoxes),
                    group(t("access.share_files"), fileBoxes), daysField, notice, grant, " ", dismiss);
    form.addEventListener("submit", async (event) => {
        event.preventDefault();
        const chosen = (boxes) => boxes.filter(([box]) => box.checked).map(([box]) => box.value);
        try {
            const prepared = await api("POST", "prepare", {
                action: "access.grant", request: r.request, fields: chosen(fieldBoxes),
                files: chosen(fileBoxes), days: Number(days.value) || 30,
            });
            await approveScreen(prepared, new Map(), async (done) => {
                await api("POST", "access/deliver", { grant: done.statement_id });
                return el("p", { class: "notice", text: t("access.delivered_ok", { peer: r.peer }) });
            });
        } catch (error) {
            notice.replaceChildren(problem(t("error.server", { message: error.message })));
        }
    });
    parts.push(el("h2", { text: t("access.share_title") }), form);
    show(...parts);
}

/// The answer to a party's question: whether it holds in the document as it
/// stands, then a claim approved with a tap and kept for the party to fetch.
/// A condition that does not hold is answered only if the person asks.
function answerForm(r, parts, notice, dismiss) {
    if (r.missing || !r.may_answer) {
        parts.push(el("p", { class: "hint", text: t(r.missing ? "access.missing"
            : r.replaced ? "access.replaced" : r.locked ? "home.locked" : "access.cannot_answer") }), notice, dismiss);
        show(...parts);
        return;
    }
    parts.push(el("p", { class: "notice", role: "status",
                         text: t(r.holds ? "access.holds_now" : "access.does_not_hold_now") }));
    const [subjectField, subject] = field("answer-subject", t("claim.subject"), t("claim.subject_hint"),
                                          { maxlength: 256 });
    const [untilField, until] = field("answer-until", t("claim.until"), t("claim.until_hint"), { type: "date" });
    const allowNo = el("input", { type: "checkbox", id: "answer-allow-no" });
    const answer = el("button", { type: "submit", class: "primary", text: t("access.answer_it") });
    const form = el("form", { novalidate: true }, subjectField, untilField,
                    r.holds ? null : el("label", { class: "check" }, allowNo, " ", t("access.answer_no")),
                    notice, answer, " ", dismiss);
    form.addEventListener("submit", async (event) => {
        event.preventDefault();
        try {
            const prepared = await api("POST", "prepare", {
                action: "access.answer", request: r.request, subject: subject.value.trim(),
                until: until.value ? Date.parse(`${until.value}T23:59:59Z`) : null,
                allow_no: allowNo.checked,
            });
            await approveScreen(prepared, new Map(), async (done) => {
                await api("POST", "access/deliver", { claim: done.statement_id });
                return el("p", { class: "notice", text: t("access.answered_ok", { peer: r.peer }) });
            });
        } catch (error) {
            notice.replaceChildren(problem(t("error.server", { message: error.message })));
        }
    });
    parts.push(el("h2", { text: t("access.answer_title") }), el("p", { class: "hint", text: t("access.answer_intro") }), form);
    show(...parts);
}

/// What a party shared for one of this ledger's requests: opened and
/// verified here, and accepted with a tap (the receipt goes back).
async function accessDeliveryScreen(request) {
    let d;
    try {
        d = await api("GET", `access/deliveries/${request}`);
    } catch (error) {
        if (error instanceof ApiError && error.status === 422) {
            show(el("h1", { text: t("access.delivery_title", { peer: "" }) }),
                 problem(t("access.not_verified", { message: error.message })),
                 goButton(t("nav.parties"), "#/parties"));
            return;
        }
        throw error;
    }
    const facts = el("dl", { class: "facts" });
    const fact = (key, value, attributes = {}) => {
        if (value !== undefined && value !== null) {
            facts.append(el("dt", { text: t(key) }), el("dd", { text: String(value), ...attributes }));
        }
    };
    if (d.kind === "claim") {
        // The answer to a question: what the claim says, never the fields.
        fact("access.organization", d.organization);
        fact("access.answered_by", d.answered_by);
        fact("column.type", d.record_type);
        fact("access.document", d.record, { class: "id" });
        fact("claim.subject", d.subject);
        fact("claim.as_of", timeText(d.as_of));
        fact("claim.until", d.until ? timeText(d.until) : null);
        const parts = [el("h1", { text: t("access.answer_from", { peer: d.peer }) }),
                       el("p", { class: "notice", role: "status", text: t(d.holds ? "access.confirms" : "access.says_not", {
                           organization: d.organization, condition: d.text }) }), facts];
        acceptPart(d, request, parts);
        return;
    }
    fact("access.organization", d.organization);
    fact("column.type", d.record_type);
    fact("column.state", d.state);
    fact("access.document", d.record, { class: "id" });
    fact("exchange.until", timeText(d.until));
    const parts = [el("h1", { text: t("access.delivery_title", { peer: d.peer }) }),
                   el("p", { class: "notice", role: "status", text: t("access.verified", {
                       by: d.granted_by, organization: d.organization }) }), facts];
    parts.push(el("h2", { text: t("thing.fields_title") }),
               d.fields.length ? el("dl", { class: "facts" }, d.fields.map((f) => [
                   el("dt", { text: f.name }), el("dd", { text: f.value })]).flat())
                               : el("p", { text: t("value.none") }));
    const notice = el("div", { role: "status" });
    parts.push(el("h2", { text: t("access.files") }),
               d.files.length ? el("ul", {}, d.files.map((f) => {
                   const save = el("button", { type: "button", text: t("access.save"),
                                               "aria-label": t("access.save_label", { name: f.name }) });
                   save.addEventListener("click", async () => {
                       try {
                           await saveDownload(`access/deliveries/${request}/files/${f.index}`, { method: "GET" }, f.name);
                       } catch (error) {
                           notice.replaceChildren(problem(t("error.server", { message: error.message })));
                       }
                   });
                   return el("li", {}, `${f.name} (${sizeText(f.size)}) `, save);
               })) : el("p", { text: t("value.none") }));
    acceptPart(d, request, parts, notice);
}

/// Accepting what came with a tap: a receipt on this ledger, sent back.
function acceptPart(d, request, parts, notice = el("div", { role: "status" })) {
    if (d.accepted) {
        parts.push(el("p", { class: "notice", text: t("access.accepted_already", { receipt: d.receipt.slice(0, 12) }) }), notice);
        show(...parts);
        return;
    }
    const accept = el("button", { type: "button", class: "primary", text: t("access.accept") });
    accept.disabled = state.who.role === "viewer";
    accept.addEventListener("click", async () => {
        try {
            const prepared = await api("POST", "prepare", { action: "access.receipt", request });
            await approveScreen(prepared, new Map(), async (done) => {
                await api("POST", "access/send", { record: done.statement_id });
                return el("p", { class: "notice", text: t("access.accepted", { peer: d.peer }) });
            });
        } catch (error) {
            notice.replaceChildren(problem(t("error.server", { message: error.message })));
        }
    });
    parts.push(el("p", { class: "hint", text: t("access.accept_hint") }), notice, accept);
    show(...parts);
}

/// A code to send to one party: shown once, to copy.
function codeView(code, label, fingerprint) {
    const box = el("textarea", { readonly: true, rows: 3, class: "id", "aria-label": label });
    box.value = code;
    return el("div", { class: "kind" }, el("p", { text: label }), box,
              el("p", { class: "hint", text: t("parties.code_secret", { fingerprint }) }));
}

/// Proposals and consents that came as files: read here, verified, then
/// consented to or recorded with a tap. `opened` names one opened on this
/// computer (console open FILE, as a double-click runs it), read at once.
function exchangeScreen(opened) {
    const input = el("input", { id: "exchange-file", type: "file", accept: ".kanhe,application/cbor" });
    const result = el("section", { "aria-live": "polite" });
    const read = async (from) => {
        status(t("status.working"));
        try {
            const body = { ...(await from()), language: state.language };
            const shown = await api("POST", "exchange/read", body);
            result.replaceChildren(...(shown.kind === "proposal" ? proposalView(shown, shown.upload)
                                                                  : consentView(shown, shown.upload)));
        } catch (error) {
            result.replaceChildren(problem(t("exchange.unreadable", { message: error.message })));
        } finally {
            status("");
        }
    };
    input.addEventListener("change", async () => {
        const file = input.files[0];
        if (file) {
            await read(async () => ({ upload: await uploadFile(file) }));
        }
    });
    show(el("h1", { text: t("exchange.title") }), el("p", { class: "hint", text: t("exchange.intro") }),
         el("div", { class: "field" }, el("label", { for: "exchange-file", text: t("exchange.file") }),
            input),
         result);
    if (opened) {
        // Taken once: a reload shows the plain screen.
        history.replaceState(null, "", `${location.pathname}#/exchange`);
        read(async () => ({ opened }));
    }
}

const ledgerText = (id, name) => (name ? `${name} (${id.slice(0, 12)}...)` : `${id.slice(0, 12)}...`);

function proposalView(read, upload) {
    const facts = el("dl", { class: "facts" });
    const fact = (key, value, attributes = {}) => {
        facts.append(el("dt", { text: t(key) }), el("dd", { text: String(value), ...attributes }));
    };
    fact("exchange.from", ledgerText(read.home, read.home_name || read.home_organization));
    fact("column.contract", read.contract ?? t("value.none"));
    fact("column.state", read.state?.state || read.status || t("value.none"));
    fact("column.id", read.instance, { class: "id" });
    fact("approve.function", read.call?.label ?? read.function);
    fact("approve.arguments", read.arguments, { class: "id" });
    if (read.note) {
        fact("exchange.note", read.note);
    }
    const parts = [el("h2", { text: t("exchange.proposal_title", { name: read.home_organization }) }),
                   el("p", { class: "notice", role: "status", text: t("exchange.verified") }), facts];
    if (read.state?.fields?.length) {
        parts.push(el("h3", { text: t("thing.fields_title") }),
                   el("dl", { class: "facts" }, read.state.fields.map((f) => [
                       el("dt", { text: f.field }), el("dd", { text: f.value })]).flat()));
    }
    if (read.call?.clauses?.length) {
        parts.push(el("h3", { text: t("thing.what_it_does") }),
                   el("ul", {}, read.call.clauses.map((c) => el("li", { text: c }))));
    }
    if (!read.asks_us) {
        parts.push(el("p", { class: "hint", text: t("exchange.not_asked") }));
        return parts;
    }
    const notice = el("div");
    const consent = el("button", { type: "button", class: "primary", text: t("exchange.consent") });
    consent.disabled = state.who.role === "viewer";
    consent.addEventListener("click", async () => {
        try {
            const prepared = await api("POST", "prepare", { action: "contract.consent", upload });
            await approveScreen(prepared, new Map(), async (done) => {
                // Online, the consent goes to the home's registrar; from a
                // file, a consent file is saved to send back.
                if (read.online) {
                    const sent = await api("POST", "exchange/send", { record: done.statement_id, upload });
                    const recorded = sent.home?.status !== "waiting";
                    return el("p", { class: "notice", text: t(recorded ? "parties.sent_recorded"
                                                                       : "parties.sent_waiting",
                                                              { name: read.home_organization }) });
                }
                const name = await saveDownload("exchange/consent", {
                    method: "POST", headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ record: done.statement_id, upload }),
                }, "consent.kanhe");
                return el("p", { class: "notice", text: t("exchange.consent_made", { name }) });
            });
        } catch (error) {
            notice.replaceChildren(problem(error.status === 423 ? t("keys.locked")
                                                                : t("error.server", { message: error.message })));
        }
    });
    parts.push(el("p", { text: t("exchange.consent_intro") }), notice, consent);
    return parts;
}

function consentView(read, upload) {
    const facts = el("dl", { class: "facts" });
    const fact = (key, value, attributes = {}) => {
        facts.append(el("dt", { text: t(key) }), el("dd", { text: String(value), ...attributes }));
    };
    fact("exchange.from", ledgerText(read.from, read.from_name || read.from_organization));
    fact("approve.function", read.function);
    fact("approve.arguments", read.arguments, { class: "id" });
    fact("column.id", read.instance, { class: "id" });
    fact("exchange.until", timeText(read.until));
    fact("exchange.in_person", yesNo(read.in_person));
    const parts = [el("h2", { text: t("exchange.consent_title", { name: read.from_organization }) }),
                   el("p", { class: "notice", role: "status", text: t("exchange.consent_verified") }),
                   facts];
    if (!read.for_us) {
        parts.push(problem(t("exchange.not_ours")));
        return parts;
    }
    if (!read.current || read.lapsed) {
        parts.push(problem(t(read.lapsed ? "exchange.lapsed" : "exchange.moved_on")));
        return parts;
    }
    const notice = el("div");
    const record = el("button", { type: "button", class: "primary", text: t("exchange.record") });
    record.disabled = state.who.role === "viewer";
    record.addEventListener("click", async () => {
        try {
            await approveScreen(await api("POST", "prepare", {
                action: "contract.call", consents: [upload], language: state.language,
            }));
        } catch (error) {
            notice.replaceChildren(problem(error.answer?.dry_run?.reason
                ? t("thing.refused", { reason: error.answer.dry_run.reason })
                : t("error.server", { message: error.message })));
        }
    });
    parts.push(el("p", { text: t("exchange.record_intro") }), notice, record);
    return parts;
}

async function ledgerFacts() {
    const home = await api("GET", "home");
    return { id: home.ledger.id, name: home.ledger.organization };
}

/// Putting a new thing under deployed rules.
async function createScreen(contractId) {
    const [page, ledger] = await Promise.all([
        api("GET", `rules/${contractId}?language=${encodeURIComponent(state.language)}`),
        ledgerFacts(),
    ]);
    const name = page.contract.name ?? short(page.contract.id).text;
    const creation = (page.calls ?? []).find((c) => c.kind === "create");
    if (!creation) {
        show(el("h1", { text: t("thing.create_title", { name }) }), el("p", { text: t("thing.no_calls") }));
        return;
    }
    show(el("h1", { text: t("thing.create_title", { name }) }),
         el("p", { class: "hint", text: t("thing.create_intro") }),
         creation.clauses.length ? el("details", {}, el("summary", { text: t("thing.what_it_does") }),
                                      el("ul", {}, creation.clauses.map((c) => el("li", { text: c }))))
                                 : null,
         callForm(creation, { action: "contract.create", contract: page.contract.id,
                              function: creation.function }, ledger, "create"),
         backButton(t("approve.cancel")));
}

const timeText = (ms) => new Intl.DateTimeFormat(state.language, { dateStyle: "medium", timeStyle: "short" })
    .format(new Date(ms));

/// A thing with rules: what it is now, what may be done with it, what is
/// due, the requests waiting for an answer, and its history.
/// A link that opens one action of a thing for whoever signs in (it carries
/// no secret: the action is checked and approved as any other), with its
/// QR code for a phone to scan.
function actionLink(instance, call) {
    const area = el("div");
    const open = el("button", { type: "button", text: t("thing.action_link"),
                                "aria-label": t("thing.action_link_label", { action: call.label }) });
    open.addEventListener("click", async () => {
        const link = `${location.origin}${location.pathname}#/act/${instance}/${encodeURIComponent(call.function)}`;
        const box = el("input", { type: "text", readonly: true, class: "id",
                                  "aria-label": t("thing.action_link_for", { action: call.label }) });
        box.value = link;
        const parts = [box, el("p", { class: "hint", text: t("thing.action_link_hint") })];
        try {
            const blob = await fetchBlob(`qr?text=${encodeURIComponent(link)}`);
            parts.push(el("img", { class: "qr", src: URL.createObjectURL(blob),
                                   alt: t("thing.action_qr", { action: call.label }) }));
        } catch (error) {
            parts.push(problem(t("error.server", { message: error.message })));
        }
        area.replaceChildren(...parts);
        open.hidden = true;
    });
    return el("div", {}, open, area);
}

/// Fetches a file of the console's with the session's token, as a blob.
async function fetchBlob(path) {
    const headers = {};
    const token = stored(sessionStorage, SESSION);
    if (token) {
        headers.Authorization = `Bearer ${token}`;
    }
    const response = await fetch(`api/${path}`, { headers, credentials: "omit", cache: "no-store" });
    if (!response.ok) {
        const answer = await response.json().catch(() => ({}));
        throw new ApiError(response.status, answer?.error?.message ?? String(response.status));
    }
    return response.blob();
}

/// An action link: the thing's page, at that action's form.
async function actionLinkScreen(instance, action) {
    await instanceScreen(instance);
    const section = [...document.querySelectorAll("section[data-function]")]
        .find((s) => s.dataset.function === action);
    if (!section) {
        document.getElementById("main").prepend(problem(t("thing.action_unavailable", { action })));
        return;
    }
    section.classList.add("focused");
    section.scrollIntoView({ block: "start" });
    section.querySelector("input, select, button")?.focus();
}

async function instanceScreen(id) {
    const [view, ledger] = await Promise.all([
        api("GET", `instances/${id}?language=${encodeURIComponent(state.language)}`),
        ledgerFacts(),
    ]);
    const thing = view.instance;
    const facts = el("dl", { class: "facts" });
    const fact = (key, value, attributes = {}) => {
        facts.append(el("dt", { text: t(key) }), el("dd", { text: String(value), ...attributes }));
    };
    fact("column.contract", thing.contract_name ?? short(thing.contract).text);
    fact("column.state", view.state?.state || thing.status || t("value.none"));
    fact("column.final", yesNo(thing.final));
    fact("thing.entry", thing.created_by);
    fact("column.id", thing.id, { class: "id" });
    for (const p of thing.parties) {
        facts.append(el("dt", { text: t("thing.party", { role: p.role }) }),
                     el("dd", { class: p.ours ? null : "id",
                                text: p.ours ? t("thing.this_ledger", { name: p.label }) : p.ledger }));
    }
    const parts = [keysNotice(), el("h1", { text: thing.contract_name ?? t("thing.title") }), facts];
    if (view.state?.fields?.length) {
        parts.push(el("h2", { text: t("thing.fields_title") }),
                   el("dl", { class: "facts" }, view.state.fields.map((f) => [
                       el("dt", { text: f.field }), el("dd", { text: f.value })]).flat()));
    }
    const acting = view.may_act && !thing.final;
    // Proposals waiting for approvals (Bo, requirements of approvals): in
    // the contract's words, with Approve for those who may.
    if (view.proposals?.length) {
        const words = view.state?.proposals ?? [];
        parts.push(el("h2", { text: t("thing.proposals_title") }),
                   el("ul", { class: "approvals" }, view.proposals.map((p, n) => {
                       const notice = el("div");
                       const approve = el("button", { type: "button", class: "primary", text: t("approvals.approve"),
                                                      "aria-label": t("approvals.approve_label", { function: p.function }) });
                       approve.disabled = !acting || !p.may_approve;
                       approve.addEventListener("click", () => approveProposal(p, notice));
                       return el("li", { class: "kind" },
                                 el("h3", { text: t("approvals.proposal_title", { function: p.function,
                                                                                  rules: thing.contract_name ?? "" }) }),
                                 el("p", { text: words[n]?.text ?? (p.by ? t("approvals.proposed_by", {
                                     name: nameOf(p.by), time: timeText(p.proposed_at) }) : t("approvals.proposed_by_agent")) }),
                                 p.approvals.length ? el("p", { text: t("approvals.so_far", {
                                     names: p.approvals.map((a) => (a.in_person ? t("approvals.in_person_name", { name: nameOf(a) })
                                                                                : nameOf(a))).join(t("approvals.separator")) }) }) : null,
                                 el("p", { class: "hint", text: p.may_approve
                                     ? t(p.completes ? "approvals.completes" : "approvals.records") : p.reason ?? "" }),
                                 notice, approve);
                   })));
    }
    const calls = view.calls ?? [];
    // The actions, each a form; a call the contract refuses says why.
    const actions = calls.filter((c) => c.kind === "action");
    if (acting && actions.length) {
        parts.push(el("h2", { text: t("thing.actions_title") }),
                   el("p", { class: "hint", text: t("thing.actions_hint") }));
        actions.forEach((call, n) => {
            const bound = new Set(thing.parties.map((p) => p.role));
            // A role already bound need not be named again (unless the
            // action binds it on every call).
            const shown = { ...call, inputs: call.inputs.filter((i) => !(i.place === "role" && bound.has(i.name) && !i.each_call)) };
            parts.push(el("section", { class: "kind", "aria-labelledby": `action-${n}`, "data-function": call.function },
                          el("h3", { id: `action-${n}`, text: call.label }),
                          call.clauses.length ? el("details", {},
                                                   el("summary", { text: t("thing.what_it_does") }),
                                                   el("ul", {}, call.clauses.map((c) => el("li", { text: c }))))
                                              : null,
                          callForm(shown, { action: "contract.call", instance: thing.id,
                                            function: call.function }, ledger, `action-${n}`),
                          actionLink(thing.id, call)));
        });
    } else if (!view.calls) {
        parts.push(el("p", { class: "hint", text: t("thing.no_calls") }));
    }
    // Time rules whose time has come: the keeper would call them; the
    // person may call one now.
    if (view.due.length) {
        parts.push(el("h2", { text: t("thing.due_title") }));
        for (const rule of view.due) {
            const notice = el("div");
            const run = el("button", { type: "button", text: t("thing.run_now"),
                                       "aria-label": t("thing.run_now_label", { rule: rule.function }) });
            run.disabled = !acting;
            run.addEventListener("click", async () => {
                try {
                    await approveScreen(await api("POST", "prepare", {
                        action: "contract.call", instance: thing.id, function: rule.function,
                        values: {}, language: state.language,
                    }));
                } catch (error) {
                    callProblem(error, el("form"), notice);
                }
            });
            parts.push(el("div", { class: "kind" },
                          el("p", { text: t("thing.due_rule", { rule: rule.function }) }), notice, run));
        }
    }
    // Calls this ledger's registrar holds online, waiting for consents.
    if (view.held?.length) {
        parts.push(el("h2", { text: t("exchange.held_title") }),
                   el("ul", {}, view.held.map((h) => el("li", {
                       text: t("exchange.held", {
                           function: h.function, arguments: h.arguments,
                           missing: h.missing.map((l) => `${l.slice(0, 12)}...`).join(", ") ||
                                    t("value.none"),
                           until: timeText(h.until),
                       }),
                   }))));
    }
    // Requests waiting for an answer, answered by hand.
    if (view.requests.length) {
        parts.push(el("h2", { text: t("thing.requests_title") }),
                   el("p", { class: "hint", text: t("thing.requests_hint") }));
        view.requests.forEach((r, n) => {
            const notice = el("div");
            const [reasonField, reason] = field(`answer-reason-${n}`, t("thing.answer_reason"),
                                                t("thing.answer_reason_hint"), { maxlength: 64 });
            const answer = (status) => async () => {
                try {
                    await approveScreen(await api("POST", "prepare", {
                        action: "request.answer", request: r.id, status,
                        reason: status === "done" ? "" : reason.value.trim(), language: state.language,
                    }));
                } catch (error) {
                    callProblem(error, el("form"), notice);
                }
            };
            const buttons = ["done", "failed", ...(r.overdue ? ["expired"] : [])].map((s) => {
                const b = el("button", { type: "button", text: t(`thing.answer.${s}`),
                                         "aria-label": t(`thing.answer_label.${s}`, { kind: r.kind }) });
                b.disabled = !acting;
                b.addEventListener("click", answer(s));
                return b;
            });
            parts.push(el("section", { class: "kind" },
                          el("h3", { text: t("thing.request", { kind: r.kind }) }),
                          el("p", { text: t(r.overdue ? "thing.request_overdue" : "thing.request_due",
                                            { time: timeText(r.deadline) }) }),
                          el("p", { class: "id", text: r.params }),
                          reasonField, notice, el("div", { class: "toolbar" }, buttons)));
        });
    }
    parts.push(el("h2", { text: t("thing.history_title") }),
               el("ol", { class: "events" }, view.history.map((h) => el("li", {
                   text: t(h.in_person ? "thing.history_person" : "thing.history_machine", {
                       function: h.function ?? "?", who: h.by ?? "?", time: timeText(h.time),
                       index: h.index,
                   }),
               }))));
    const share = el("button", { type: "button", text: t("share.button") });
    const shared = el("div", { role: "status" });
    share.addEventListener("click", async () => {
        share.disabled = true;
        try {
            const name = await saveDownload("proof", {
                method: "POST", headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ instance: thing.id }),
            }, `proof-${thing.id.slice(0, 12)}.cbor`);
            shared.replaceChildren(el("p", { text: t("share.made", { name }) }),
                                   el("p", { class: "hint", text: t("share.send") }));
        } catch (error) {
            shared.replaceChildren(problem(t("error.server", { message: error.message })));
        } finally {
            share.disabled = false;
        }
    });
    parts.push(el("h2", { text: t("share.title") }), el("p", { text: t("thing.share_intro") }), share,
               shared);
    show(...parts);
}

// --- The checks in this browser --------------------------------------------------

/// The core, compiled to WebAssembly and served by the console, decodes what a
/// passkey is about to approve and computes its challenge here; without it
/// (a console built without Emscripten), the page says so.
let checker;

async function loadChecker() {
    if (checker !== undefined) {
        return checker;
    }
    try {
        const { default: create } = await import("./wasm/kanhe-console.mjs");
        const module = await create();
        const call = (name, bytes, ...rest) => {
            const pointer = module._malloc(Math.max(bytes.length, 1));
            module.HEAPU8.set(bytes, pointer);
            const pointers = [pointer];
            const args = rest.map((r) => {
                if (r instanceof Uint8Array) {
                    const p = module._malloc(Math.max(r.length, 1));
                    module.HEAPU8.set(r, p);
                    pointers.push(p);
                    return [p, r.length];
                }
                return [r];
            }).flat();
            const out = module[name](pointer, bytes.length, ...args);
            const text = module.UTF8ToString(out);
            module._kanhe_free(out);
            pointers.forEach((p) => module._free(p));
            return JSON.parse(text);
        };
        checker = {
            describe: (payload) => call("_kanhe_describe_payload", payload),
            challenge: (payload, kid, hash) =>
                call("_kanhe_presence_challenge", payload, kid, hash),
            // Someone else's statement, waiting for approvals: its id from
            // its signed bytes, what it says, and the fields shown with it.
            statementId: (signedStatement, fields, hash) =>
                call("_kanhe_statement_id", signedStatement, fields, hash),
            approvalChallenge: (payload, kid, hash) =>
                call("_kanhe_approval_challenge", payload, kid, hash),
            // A proof file, with the files it may check, the ledger it
            // should come from, and a challenge its range proofs must carry
            // (hex, or empty for none).
            verify: (proof, files, ledger, challenge = "") => {
                module._kanhe_proof_reset();
                for (const [name, content] of files) {
                    const label = new TextEncoder().encode(name);
                    const n = module._malloc(Math.max(label.length, 1));
                    const d = module._malloc(Math.max(content.length, 1));
                    module.HEAPU8.set(label, n);
                    module.HEAPU8.set(content, d);
                    module._kanhe_proof_attachment(n, label.length, d, content.length);
                    module._free(n);
                    module._free(d);
                }
                if (challenge) {
                    const hex = new TextEncoder().encode(challenge);
                    const h = module._malloc(Math.max(hex.length, 1));
                    module.HEAPU8.set(hex, h);
                    const taken = module._kanhe_proof_range_context(h, hex.length);
                    module._free(h);
                    if (taken !== 0) {
                        return { verified: false, error: t("verify.challenge_bad") };
                    }
                }
                return call("_kanhe_proof_verify", proof, new TextEncoder().encode(ledger));
            },
            fieldRoot: (request) => call("_kanhe_field_root",
                                         new TextEncoder().encode(JSON.stringify(request))),
            commitment: (content, salt, hash) =>
                call("_kanhe_attachment_commitment", content, salt, hash),
            digest: (content, hash) => call("_kanhe_digest", content, hash),
        };
    } catch {
        checker = null;
    }
    return checker;
}

/// What the page decoded itself agrees with what the console described.
function agrees(decoded, summary) {
    return decoded.ok && decoded.type === summary.type && decoded.record === summary.record &&
           (decoded.contract ?? null) === (summary.contract ?? null) &&
           (decoded.role ?? null) === (summary.role ?? null) &&
           (decoded.reason ?? null) === (summary.reason ?? null);
}

/// A call's bytes are the call the page shows: its function, what it acts
/// on, at which head, with which arguments (as the compiler built them), an
/// answer's request and status, and no consents.
function callAgrees(decoded, summary) {
    const same = (key) => (decoded[key] ?? null) === (summary[key] ?? null);
    return decoded.ok && decoded.type === "contract-call" &&
           decoded.consents === (summary.consents ?? 0) &&
           ["function", "contract", "instance", "head", "arguments", "request", "status"].every(same);
}

/// A deploy's bytes carry the code the console built: its size and digest
/// computed here from the bytes, its name, its language, and its functions.
function deployAgrees(decoded, summary) {
    return decoded.ok && decoded.type === "contract-deploy" &&
           (decoded.name ?? null) === (summary.name ?? null) &&
           decoded.language === summary.language && decoded.code_size === summary.code_size &&
           decoded.code_sha256 === summary.code_sha256 &&
           JSON.stringify(decoded.functions) === JSON.stringify(summary.functions);
}

/// A registration's bytes commit to what the page shows: the fields' root
/// from the values and salts shown, the public metadata, and each file's
/// commitment from the file this page uploaded.
function registrationAgrees(check, decoded, prepared, files) {
    const summary = prepared.summary;
    if (!decoded.ok || decoded.type !== "record-register" ||
        decoded.record_type !== summary.record_type ||
        decoded.field_count !== summary.fields.length ||
        (decoded.supersedes ?? null) !== (summary.supersedes ?? null) ||
        JSON.stringify(decoded.metadata ?? {}) !==
            JSON.stringify(Object.fromEntries(Object.entries(summary.metadata).sort()))) {
        return false;
    }
    const root = check.fieldRoot({ hash: prepared.hash, fields: summary.fields });
    if (!root.ok || root.root !== decoded.field_root) {
        return false;
    }
    // A consent's terms are the proposal's the page showed.
    if (Boolean(decoded.consent) !== Boolean(summary.consent) ||
        (summary.consent && !["ledger", "instance", "function", "arguments", "head", "until"]
            .every((k) => decoded.consent[k] === summary.consent[k]))) {
        return false;
    }
    // A claim's terms are the ones the page showed (v0.14).
    if (Boolean(decoded.claim) !== Boolean(summary.claim) ||
        (summary.claim && canonical(decoded.claim) !== canonical(summary.claim))) {
        return false;
    }
    // An access record's terms are the ones the page showed.
    if (!sameTerms(decoded.access, summary.access)) {
        return false;
    }
    // The records it was made from, and a script's approval: the files'
    // digests this page computed (v0.18).
    const named = (summary.sources ?? []).map(({ ledger, record }) => ({ ledger, record }));
    if (canonical(decoded.sources ?? []) !== canonical(named) ||
        Boolean(decoded.script_approval) !== Boolean(summary.script_approval) ||
        (summary.script_approval && canonical(decoded.script_approval) !== canonical(summary.script_approval))) {
        return false;
    }
    // Its provable values (v0.22): each commitment computed here from the
    // value shown and its opening.
    if (!provableAgrees(check, decoded, summary)) {
        return false;
    }
    if (decoded.attachments.length !== summary.files.length) {
        return false;
    }
    return summary.files.every((f, i) => {
        const a = decoded.attachments[i];
        const content = files.get(f.upload);
        if (!content || a.name !== f.name || a.size !== f.size || a.media_type !== f.media_type) {
            return false;
        }
        const own = check.commitment(content, new Uint8Array(fromBase64url(f.salt)), prepared.hash);
        return own.ok && own.commitment === a.commitment;
    });
}

/// A registration's provable values, by field and encoding only.
const provableNames = (list) => canonical((list ?? []).map(({ field, encoding }) => ({ field, encoding })));

/// A value as its encoding reads it (spec v0.22, section 6), as a BigInt:
/// a date as its days from 1970-01-01; a number or an amount times
/// 10^scale. Null if it does not read: then the page refuses.
function provableX(encoding, value) {
    const text = String(value).trim();
    if (encoding.type === "date") {
        const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(text);
        if (!m) {
            return null;
        }
        const [y, month, d] = [Number(m[1]), Number(m[2]), Number(m[3])];
        const leap = (y % 4 === 0 && y % 100 !== 0) || y % 400 === 0;
        const length = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][month - 1];
        if (y < 1 || !length || d < 1 || d > length) {
            return null;
        }
        // Days from the civil date, in the proleptic Gregorian calendar.
        const yy = month <= 2 ? y - 1 : y;
        const era = Math.floor(yy / 400);
        const yoe = yy - era * 400;
        const doy = Math.floor((153 * (month > 2 ? month - 3 : month + 9) + 2) / 5) + d - 1;
        const doe = yoe * 365 + Math.floor(yoe / 4) - Math.floor(yoe / 100) + doy;
        return BigInt(era * 146097 + doe - 719468);
    }
    const scale = encoding.scale ?? 0;
    const m = /^(-?)(\d+)(?:\.(\d+))?$/.exec(text);
    if (!m || (m[3] ?? "").length > scale) {
        return null;
    }
    const x = BigInt(m[2] + (m[3] ?? "").padEnd(scale, "0"));
    return m[1] ? -x : x;
}

/// The provable values in a registration's bytes are those the console
/// describes, each committing to the value shown: SHA-256("Kanhe range v1"
/// || salt || x + 2^63 as 8 bytes, big-endian), on every ledger.
function provableAgrees(check, decoded, summary) {
    const provable = decoded.provable ?? [];
    const openings = summary.openings ?? [];
    if (provableNames(provable) !== provableNames(summary.provable) ||
        openings.length !== provable.length) {
        return false;
    }
    return provable.every((p, i) => {
        const opening = openings[i];
        const shown = summary.fields.find((f) => f.name === p.field);
        const salt = new Uint8Array(fromBase64url(opening.salt));
        const x = shown ? provableX(p.encoding, shown.value) : null;
        if (opening.field !== p.field || x === null || x !== BigInt(opening.x) || salt.length !== 32) {
            return false;
        }
        const message = new Uint8Array(14 + 32 + 8);
        message.set(new TextEncoder().encode("Kanhe range v1"));
        message.set(salt, 14);
        let v = BigInt.asUintN(64, x + (1n << 63n));
        for (let k = 7; k >= 0; k--) {
            message[46 + k] = Number(v & 0xffn);
            v >>= 8n;
        }
        const own = check.digest(message, -16);
        return own.ok && own.digest === p.commitment;
    });
}

/// The fields of each people statement that its bytes must hold as shown.
const PEOPLE_KEYS = {
    "actor-register": ["kind", "display_name", "key", "responsible", "model"],
    "actor-set-presence": ["subject", "credentials"],
    "delegation-grant": ["grantee", "scope"],
    "delegation-revoke": ["delegation", "reason"],
};

/// A value as text with its objects' keys in order, whichever order its
/// writer kept them in (the WASM keeps the order it wrote, the console sorts).
function canonical(value) {
    const sorted = (v) => (Array.isArray(v) ? v.map(sorted)
        : v !== null && typeof v === "object"
            ? Object.fromEntries(Object.keys(v).sort().map((k) => [k, sorted(v[k])])) : v);
    return JSON.stringify(sorted(value ?? null));
}

function peopleAgrees(decoded, summary) {
    return decoded.ok && decoded.type === summary.type &&
           PEOPLE_KEYS[summary.type].every((k) => canonical(decoded[k]) === canonical(summary[k]));
}

/// Two sets of terms, key by key (both absent counts as the same).
function sameTerms(a, b) {
    if (!a || !b) {
        return !a && !b;
    }
    const keys = new Set([...Object.keys(a), ...Object.keys(b)]);
    return [...keys].every((k) => canonical(a[k]) === canonical(b[k]));
}

// --- Approvals: words and checks ------------------------------------------------

/// A window in words: 7 days, 12 hours, 90 minutes.
function windowText(ms) {
    const day = 86400000;
    const hour = 3600000;
    if (ms % day === 0) {
        return t("window.days", { n: ms / day });
    }
    if (ms % hour === 0) {
        return t("window.hours", { n: ms / hour });
    }
    return t("window.minutes", { n: Math.round(ms / 60000) });
}

/// An actor as a held statement or a proposal lists it: its name, or the
/// start of its id.
const nameOf = (a) => a?.name ?? (a?.id ? `${a.id.slice(0, 12)}...` : "?");

/// A rule in words: "2 of Chan Tai Man, Lee Ka Yan, Ho Wing, within 7 days".
function ruleText(rule) {
    return t(rule.without_presence ? "approvals.rule_any" : "approvals.rule", {
        k: rule.k, names: rule.approvers.map(nameOf).join(t("approvals.separator")),
        window: windowText(rule.within ?? rule.within_ms),
    });
}

/// Where a rule comes from, in words.
const ruleSource = (r) => t(r.source === "delegation" ? "approvals.source.delegation"
    : r.source === "new_guardians" ? "approvals.source.new_guardians" : "approvals.source.guardians");

/// How an approval was given, in words.
function approvalWords(a) {
    return t(a.presence === "hardware-key" ? "approvals.by_key"
        : a.presence === "passkey" ? "approvals.by_passkey" : "approvals.by_signature",
             { name: nameOf(a.approver), time: timeText(a.approved_at) });
}

/// A held statement's progress (spec v0.20): each rule with what it still
/// needs, the approvals given and how, declines (hints for whoever sent
/// it), approvals that stopped counting, and when it lapses or what became
/// of it.
function heldProgress(h) {
    const facts = el("dl", { class: "facts" });
    const fact = (key, value) => facts.append(el("dt", { text: t(key) }), el("dd", { text: String(value) }));
    for (const r of h.rules ?? []) {
        fact("approvals.rule_label", `${ruleText(r)} (${ruleSource(r)})`);
        fact("approvals.missing", r.missing > 0 ? t("approvals.more", { n: r.missing }) : t("approvals.met"));
    }
    if (h.signer_verified && (h.rules ?? []).some((r) => r.signer_counts)) {
        fact("approvals.signer_counts", t("approvals.signer_counts_line", { name: nameOf(h.signer) }));
    }
    for (const a of h.approvals ?? []) {
        fact("approvals.approved_by", approvalWords(a));
    }
    for (const d of h.declines ?? []) {
        fact("approvals.declined_by", t("approvals.declined_line", { name: nameOf(d.approver), time: timeText(d.at) }));
    }
    for (const d of h.dropped ?? []) {
        fact("approvals.dropped", t("approvals.dropped_line", { name: nameOf(d.approver), reason: d.reason }));
    }
    if ((h.state ?? "open") === "open") {
        fact("approvals.lapses", timeText(h.lapses_at));
    } else {
        fact("column.state", t(`approvals.state.${h.state}`, { index: h.index ?? "" }));
    }
    if (h.note) {
        fact("approvals.note", h.note);
    }
    return facts;
}

/// The fields of other statements that their bytes must hold as shown.
const HELD_KEYS = {
    "actor-rotate-key": ["subject", "key", "algorithm"],
    "actor-revoke": ["subject", "reason"],
    "ledger-rotate-log-key": ["key", "algorithm"],
    "ledger-set-guardians": ["guardians", "guarded"],
    "record-transition": ["record", "from_state", "to_state"],
};

/// A held registration's bytes are the one the console describes: its
/// type, field count, version, metadata or terms, sources, and its files by
/// name, size, and type (the files themselves are not here to check).
function heldRegistrationAgrees(decoded, summary) {
    const named = (summary.sources ?? []).map(({ ledger, record }) => ({ ledger, record }));
    const same = (key) => Boolean(decoded[key]) === Boolean(summary[key]) &&
        (!summary[key] || canonical(decoded[key]) === canonical(summary[key]));
    const consent = Boolean(decoded.consent) === Boolean(summary.consent) &&
        (!summary.consent || ["ledger", "instance", "function", "arguments", "head", "until"]
            .every((k) => decoded.consent[k] === summary.consent[k]));
    const files = summary.files ?? [];
    return decoded.record_type === summary.record_type && decoded.field_count === summary.field_count &&
        (decoded.supersedes ?? null) === (summary.supersedes ?? null) &&
        canonical(decoded.metadata ?? {}) === canonical(summary.metadata ?? {}) &&
        canonical(decoded.sources ?? []) === canonical(named) &&
        sameTerms(decoded.access, summary.access) && consent && same("claim") && same("script_approval") &&
        provableNames(decoded.provable) === provableNames(summary.provable) &&
        decoded.attachments.length === files.length &&
        files.every((f, i) => decoded.attachments[i].name === f.name && decoded.attachments[i].size === f.size &&
                               decoded.attachments[i].media_type === f.media_type);
}

/// What this page decoded of someone else's statement agrees with what the
/// console says of it.
function heldAgrees(decoded, summary) {
    if (!decoded.ok || decoded.type !== summary.type ||
        (decoded.script ?? null) !== (summary.script ?? null)) {
        return false;
    }
    if (summary.type === "record-register") {
        return heldRegistrationAgrees(decoded, summary);
    }
    if (summary.type === "contract-deploy") {
        return deployAgrees(decoded, summary);
    }
    if (summary.type === "contract-call") {
        return callAgrees(decoded, summary);
    }
    if (PEOPLE_KEYS[summary.type]) {
        return peopleAgrees(decoded, summary);
    }
    if (HELD_KEYS[summary.type]) {
        return HELD_KEYS[summary.type].every((k) => canonical(decoded[k]) === canonical(summary[k]));
    }
    return agrees(decoded, summary);
}

// --- Acting, approved with a passkey ---------------------------------------------

/// Back to the list (the address is still #/things, so a link would not move).
function backButton(text) {
    const button = el("button", { type: "button", text });
    button.addEventListener("click", () => route());
    return button;
}

/// To a screen, even the one the address already names.
function goButton(text, hash) {
    const button = el("button", { type: "button", text });
    button.addEventListener("click", () => {
        if (location.hash === hash) {
            route();
        } else {
            location.hash = hash;
        }
    });
    return button;
}

/// What to do with a record: the person chooses, the console prepares it.
function actScreen(record) {
    const endorse = el("input", { type: "radio", name: "act", id: "act-endorse", value: "endorse",
                                  checked: true });
    const revoke = el("input", { type: "radio", name: "act", id: "act-revoke", value: "revoke" });
    const [roleField, role] = field("act-role", t("act.role"), t("act.role_hint"),
                                    { maxlength: 64 });
    const [reasonField, reason] = field("act-reason", t("act.reason"), t("act.reason_hint"),
                                        { maxlength: 200 });
    const notice = el("div");
    const form = el("form", { novalidate: true },
                    el("fieldset", {}, el("legend", { text: t("act.what") }),
                       el("label", {}, endorse, " ", t("act.endorse")),
                       el("label", {}, revoke, " ", t("act.revoke"))),
                    roleField, reasonField, notice,
                    el("button", { type: "submit", class: "primary", text: t("act.prepare") }),
                    " ", backButton(t("approve.cancel")));
    form.addEventListener("submit", async (event) => {
        event.preventDefault();
        const intent = endorse.checked
            ? { action: "record.endorse", record: record.id, role: role.value.trim() }
            : { action: "record.revoke", record: record.id, reason: reason.value.trim() };
        try {
            await approveScreen(await api("POST", "prepare", intent));
        } catch (error) {
            notice.replaceChildren(problem(error.status === 423 ? t("keys.locked")
                                                                : passkeyProblem(error)));
        }
    });
    show(el("h1", { text: t("act.title") }),
         el("p", { class: "id", text: `${record.type} ${record.id}` }), form);
}

/// What a statement says, for the person about to confirm it or to approve
/// it: its action and the fields of its body, in the reader's words.
function statementFacts(summary) {
    const deploying = summary.type === "contract-deploy";
    const calling = summary.type === "contract-call";
    const facts = el("dl", { class: "facts" });
    const fact = (key, value) => {
        if (value !== undefined && value !== null) {
            facts.append(el("dt", { text: t(key) }), el("dd", { text: String(value) }));
        }
    };
    const consenting = summary.record_type === "kanhe.contract-consent/1";
    const access = summary.access;
    const machine = summary.type === "actor-register" && summary.kind !== 1;
    fact("approve.action", t(summary.script_approval ? "approve.type.script-approve"
        : summary.withdraws ? "approve.type.script-withdraw"
        : consenting ? "approve.type.consent"
        : summary.claim ? (summary.claim.answers ? "approve.type.access_answer" : "approve.type.claim")
        : access ? (access.condition ? "approve.type.access_question" : `approve.type.access_${access.kind}`)
        : calling && summary.function === "approve" ? "approve.type.proposal-approve"
        : machine ? "approve.type.machine-register" : `approve.type.${summary.type}`));
    if (access) {
        const names = (list) => (list === null ? t("access.all")
            : list.length ? list.join(", ") : t("value.none"));
        fact("access.document", access.record);
        fact("access.purpose", access.purpose);
        if (access.condition) {
            fact("access.asks_if", access.condition);
            fact("exchange.until", timeText(access.until));
        } else if (access.kind !== "receipt") {
            fact("access.fields", names(access.fields));
            fact("access.files", names(access.attachments));
            fact("exchange.until", timeText(access.until));
        } else {
            fact("access.grant_id", access.grant);
        }
    }
    if (summary.claim) {
        fact("claim.confirms", summary.claim.text);
        fact("claim.answer", t(summary.claim.holds ? "claim.holds" : "claim.does_not_hold"));
        fact("claim.subject", summary.claim.subject);
        fact("claim.until", summary.claim.until ? timeText(summary.claim.until) : null);
        fact("claim.source", summary.claim.source);
        fact("claim.answers", summary.claim.answers);
    }
    if (consenting && summary.consent) {
        fact("approve.function", summary.consent.function);
        fact("column.id", summary.consent.instance);
        fact("exchange.until", timeText(summary.consent.until));
    }
    fact("column.type", summary.record_type);
    // Values it lets be proven later without showing them (v0.22).
    if (summary.provable?.length) {
        fact("ranges.provable_fact", provableList(summary.provable));
    }
    fact("register.replaces", summary.supersedes);
    fact("approve.name", summary.name);
    fact("column.id", summary.record ?? summary.contract);
    if (calling) {
        const run = summary.dry_run ?? {};
        fact("approve.function", summary.function);
        fact("approve.arguments", summary.arguments);
        if (summary.request) {
            fact("approve.answer", t(`thing.answer.${["", "done", "failed", "expired"][summary.status]}`));
        }
        // What the rules decide, when the console ran the call (not for
        // someone else's call, waiting for approvals).
        if (summary.dry_run) {
            fact("approve.after", run.status ?? t("value.none"));
        }
        if (run.events?.length) {
            fact("approve.events", run.events.join(", "));
        }
        if (summary.dry_run) {
            fact("column.final", yesNo(run.final));
        }
        if (run.requests) {
            fact("approve.requests", run.requests);
        }
        if (summary.consents) {
            fact("approve.consents", summary.consents);
        }
    }
    if (deploying) {
        fact("approve.language", summary.language);
        fact("approve.code_size", sizeText(summary.code_size));
        fact("approve.functions", summary.functions.join(", "));
        fact("approve.code_sha256", summary.code_sha256);
    }
    if (summary.by_organization) {
        fact("approve.signer", t(summary.long_term ? "long_term.signer" : "approve.by_organization"));
    }
    fact("act.role", summary.role);
    fact("act.reason", summary.reason);
    if (summary.type === "actor-register") {
        fact(summary.kind === 1 ? "people.person" : summary.kind === 2 ? "automation.agent"
                                                                       : "automation.device",
             summary.display_name);
        fact("automation.responsible", summary.responsible_name ?? summary.responsible);
        fact("automation.model", summary.model);
        fact(summary.kind === 1 ? "people.new_key" : "automation.new_key", `${summary.key.slice(0, 16)}...`);
    } else if (summary.type === "actor-set-presence") {
        fact("people.person", summary.subject_name ?? summary.subject);
        fact("people.passkeys", summary.credentials.map((c) => c.label ?? c.rp_id).join(", "));
    } else if (summary.type === "delegation-grant") {
        fact("people.person", summary.grantee_name ?? summary.grantee);
        if (summary.scope.request_kinds) {
            fact("automation.answers", summary.scope.request_kinds.join(", "));
            fact("column.contract", (summary.scope.contracts ?? []).join(", "));
            fact("automation.functions", summary.scope.functions?.join(", ") ?? t("access.all"));
        } else {
            fact("people.may", mayWords(summary.may, { kinds: [], contracts: [], actors: summary.approvers ?? [] }));
        }
        fact("automation.in_person", yesNo(summary.scope.require_presence));
    } else if (summary.type === "delegation-revoke") {
        fact("people.delegation", summary.delegation);
    }
    if (summary.script_approval) {
        // A script's approval: what will be on the ledger, file by file.
        const a = summary.script_approval;
        fact("scripts.name", a.name);
        fact("scripts.version", a.version);
        fact("scripts.deterministic", yesNo(a.deterministic));
        fact("scripts.runtime", a.runtime);
        for (const f of a.files) {
            facts.append(el("dt", { text: t("scripts.file") }),
                         el("dd", {}, `${f.path}, ${sizeText(f.size)} `, el("span", { class: "id", text: f.digest })));
        }
    }
    if (summary.withdraws) {
        fact("scripts.script", `${summary.withdraws.name} ${summary.withdraws.version}`);
    }
    // Where it comes from (v0.18).
    if (summary.script) {
        fact("approve.made_by", summary.script_name ?? summary.script);
    }
    for (const s of summary.sources ?? []) {
        fact("approve.made_from", sourceText(s));
    }
    if (summary.type === "ledger-set-guardians") {
        // The organization's guardians (spec v0.20).
        if (summary.guardians) {
            fact("guardians.who", summary.guardian_names.join(t("approvals.separator")));
            fact("guardians.k", t("guardians.k_of", { k: summary.guardians.k, n: summary.guardians.approvers.length }));
            fact("guardians.within", windowText(summary.guardians.within));
            fact("guardians.guard", summary.guarded
                ? summary.guarded.map((type) => t(`approve.type.${type}`)).join(t("approvals.separator"))
                : t("guardians.everything"));
        } else {
            fact("guardians.who", t("guardians.none_after"));
        }
    } else if (summary.type === "actor-rotate-key" || summary.type === "actor-revoke") {
        fact("approvals.whose", summary.subject_name ?? summary.subject);
        if (summary.key) {
            fact("approvals.new_key", newKeyText(summary));
        }
    } else if (summary.type === "ledger-rotate-log-key") {
        fact("approvals.new_key", newKeyText(summary));
    } else if (summary.type === "record-transition") {
        fact("approvals.moves", t("approvals.moves_line", { from: summary.from_state, to: summary.to_state }));
    }
    // One of the steps that prepare the ledger for the long term.
    if (summary.long_term) {
        fact("long_term.fact", t(`long_term.step.${summary.long_term}`));
    }
    return facts;
}

/// A rotation's new key: its algorithm (long-term or not) and its start.
function newKeyText(summary) {
    const kind = summary.algorithm
        ? t(postQuantum(summary.algorithm) ? "long_term.key_long" : "long_term.key_today",
            { algorithm: summary.algorithm })
        : "";
    return `${kind}${kind ? " " : ""}${summary.key.slice(0, 16)}...`;
}

/// What the person confirms, as the console prepared it and this page
/// decoded it, then the tap.
/// What an approval's `after` answers when it has gone on to another
/// screen (the next of several taps): the Done screen is not shown.
const TAKEN = Symbol("taken");

async function approveScreen(prepared, files = new Map(), after = null) {
    const summary = prepared.summary;
    const registering = summary.type === "record-register";
    const deploying = summary.type === "contract-deploy";
    const rules = deploying || summary.type === "contract-retire";
    const calling = summary.type === "contract-call";
    const check = await loadChecker();
    let challenge = prepared.public_key.challenge;
    let checkedHere = false;
    if (check) {
        const payload = new Uint8Array(fromBase64url(prepared.payload));
        const decoded = check.describe(payload);
        const own = check.challenge(payload, new Uint8Array(fromBase64url(prepared.kid)),
                                    prepared.hash);
        const matches = (registering ? registrationAgrees(check, decoded, prepared, files)
            : deploying ? deployAgrees(decoded, summary)
            : calling ? callAgrees(decoded, summary)
            : PEOPLE_KEYS[summary.type] ? peopleAgrees(decoded, summary)
            // The organization's guardians, and other statements (spec v0.20).
            : HELD_KEYS[summary.type] ? decoded.ok && decoded.type === summary.type &&
                HELD_KEYS[summary.type].every((k) => canonical(decoded[k]) === canonical(summary[k]))
            : agrees(decoded, summary)) &&
            // The script its provenance names, if any (v0.18).
            (decoded.script ?? null) === (summary.script ?? null);
        if (!matches || !own.ok || own.challenge !== challenge) {
            show(el("h1", { text: t("approve.title") }), problem(t("approve.mismatch")),
                 backButton(t("nav.things")));
            return;
        }
        challenge = own.challenge;
        checkedHere = true;
    }
    const facts = statementFacts(summary);
    const consenting = summary.record_type === "kanhe.contract-consent/1";
    const access = summary.access;
    if (registering) {
        for (const f of summary.fields) {
            facts.append(el("dt", { text: t("register.private_field", { name: f.name }) }),
                         el("dd", { text: f.value }));
        }
        for (const [name, value] of Object.entries(summary.metadata)) {
            facts.append(el("dt", { text: t("register.public_field", { name }) }),
                         el("dd", { text: value }));
        }
        for (const f of summary.files) {
            facts.append(el("dt", { text: t("register.file") }),
                         el("dd", { text: t(summary.keep_files ? "register.file_kept"
                                                               : "register.file_not_kept",
                                            { name: f.name, size: sizeText(f.size) }) }));
        }
    }
    // Others must approve it too (spec v0.20): said before the tap, and it
    // is held until they do instead of registered.
    const needs = summary.approvals ?? { needed: false, rules: [] };
    const sending = Boolean(needs.needed);
    const note = sending ? el("textarea", { id: "approval-note", rows: 2, maxlength: 1000 }) : null;
    const shown = sending && registering && summary.fields.length
        ? el("input", { type: "checkbox", id: "approval-show-fields", checked: true }) : null;
    const sendPart = sending ? el("section", { class: "notice", "aria-labelledby": "approval-needs" },
        el("p", { id: "approval-needs", text: t("approve.needs", {
            rules: needs.rules.filter((r) => r.missing > 0)
                .map((r) => `${ruleText(r)}${r.signer_counts ? t("approvals.you_count") : ""}`)
                .join(t("approvals.rule_separator")),
        }) }),
        el("p", { class: "hint", text: t("approve.needs_hint", { time: timeText(needs.lapses_at) }) }),
        el("div", { class: "field" }, el("label", { for: "approval-note", text: t("approve.note") }), note,
           el("span", { class: "hint", text: t("approve.note_hint") })),
        shown ? el("div", {}, el("label", { for: "approval-show-fields" }, shown, " ", t("approve.show_fields")),
                   el("p", { class: "hint", text: t("approve.show_fields_hint") })) : null) : null;
    // A call the contract keeps as a proposal, waiting for approvals (Bo).
    const proposing = calling && (summary.dry_run?.events ?? []).includes("propose");
    const button = el("button", { type: "button", class: "primary",
                                  text: t(sending ? "approve.button_send" : "approve.button") });
    const notice = el("div");
    button.addEventListener("click", async () => {
        button.disabled = true;
        status(t("status.working"));
        try {
            const options = prepared.public_key;
            const credential = await navigator.credentials.get({
                publicKey: {
                    challenge: fromBase64url(challenge),
                    rpId: options.rpId,
                    allowCredentials: options.allowCredentials.map((c) => ({
                        type: c.type, id: fromBase64url(c.id),
                    })),
                    userVerification: options.userVerification,
                    timeout: options.timeout,
                },
            });
            const done = await api("POST", "approve", {
                prepared: prepared.prepared,
                credential_id: toBase64url(credential.rawId),
                authenticator_data: toBase64url(credential.response.authenticatorData),
                client_data_json: toBase64url(credential.response.clientDataJSON),
                signature: toBase64url(credential.response.signature),
                ...(sending ? { note: note.value.trim(), show_fields: Boolean(shown?.checked) } : {}),
            });
            if (done.status === "waiting") {
                // Held until enough of them approve: what follows waits too.
                const machineSteps = summary.type === "actor-register" && summary.kind !== 1;
                const continues = prepared.continues
                    ?? (machineSteps ? "approvals.machine_continues" : prepared.progress ? "approvals.steps_wait" : null);
                show(el("h1", { text: t("approvals.sent_title_done") }),
                     el("p", { role: "status", text: t("approvals.sent_done", { time: timeText(done.lapses_at) }) }),
                     continues ? el("p", { class: "hint", text: t(continues) }) : null,
                     el("p", { class: "id", text: done.id }), heldProgress(done),
                     goButton(t("approvals.open_list"), "#/approvals"));
                return;
            }
            const followed = after ? await after(done).catch((e) => problem(
                t("error.server", { message: e.message }))) : null;
            if (followed === TAKEN) {
                return;
            }
            show(el("h1", { text: t("approve.done_title") }),
                 el("p", { role: "status", text: t("approve.done", { index: done.index }) }),
                 el("p", { class: "id", text: done.statement_id }), followed,
                 proposing ? el("p", { class: "notice", text: t("approve.proposed") }) : null,
                 summary.script_approval ? el("p", {}, el("a", { href: `#/script/${done.statement_id}`,
                                                                 text: t("scripts.open") }))
                 : registering && !consenting && !access ? el("p", {}, el("a", { href: `#/thing/${done.statement_id}`,
                                                     text: t("register.open") }))
                             : null,
                 rules ? goButton(t("rules.done"), "#/rules")
                 : summary.script_approval || summary.withdraws ? goButton(t("nav.scripts"), "#/scripts")
                 : access ? goButton(t("nav.parties"), "#/parties")
                 : PEOPLE_KEYS[summary.type] ? goButton(t("nav.people"), "#/people")
                 : summary.long_term ? goButton(t("nav.settings"), "#/settings")
                 : calling ? goButton(t("thing.open"),
                                      `#/instance/${summary.instance ?? done.statement_id}`)
                 : backButton(t("nav.things")));
        } catch (error) {
            // An answer from the console ends this approval: the console
            // takes what it prepared once, refused or not, so the same tap
            // cannot work again. A passkey not used, or no answer at all,
            // may be tried again.
            const answered = error instanceof ApiError;
            notice.replaceChildren(problem(passkeyProblem(error)),
                                   ...(answered ? [el("p", { class: "hint", text: t("approve.prepare_again") })] : []));
            button.disabled = answered;
        } finally {
            status("");
        }
    });
    show(el("h1", { text: t("approve.title") }),
         prepared.progress ? el("p", { class: "notice", text: t("approve.progress", prepared.progress) }) : null,
         el("p", { text: t("approve.intro") }), facts,
         el("p", { class: "hint", text: t(checkedHere ? "approve.checked_here"
                                                      : "approve.checked_by_console") }),
         proposing ? el("p", { class: "notice", text: t("approve.will_propose") }) : null,
         sendPart, notice, button, " ", backButton(t("approve.cancel")));
}

// --- Approvals ---------------------------------------------------------------------

/// A held statement in a list: what it is, who sent it and when, its rules,
/// who approved it, what is missing, and its time left.
function heldItem(h, time) {
    const what = t(`approve.type.${h.type}`) === `approve.type.${h.type}` ? h.summary : t(`approve.type.${h.type}`);
    const left = h.state === "open" && h.lapses_at > time
        ? t("approvals.time_left", { time: timeText(h.lapses_at) }) : null;
    return el("li", { class: "kind", "data-statement": h.id },
              el("h3", {}, el("a", { href: `#/approval/${h.id}`, text: what })),
              el("p", { text: t("approvals.asked_by", { name: nameOf(h.signer), time: timeText(h.held_at) }) }),
              left ? el("p", { class: "hint", text: left }) : null,
              heldProgress(h));
}

/// Prepares the person's own `approve` of a contract's proposal, then the
/// confirmation, as any call (Bo).
async function approveProposal(p, notice) {
    try {
        await approveScreen(await api("POST", "prepare", {
            action: "contract.approve", instance: p.instance, function: p.function,
            arguments: p.arguments_cbor, language: state.language,
        }));
    } catch (error) {
        callProblem(error, el("form"), notice);
    }
}

/// A contract's proposal in a list: the action, who proposed it and when,
/// who approved it so far, and Approve.
function proposalItem(p) {
    const notice = el("div");
    const approve = el("button", { type: "button", class: "primary", text: t("approvals.approve"),
                                   "aria-label": t("approvals.approve_label", { function: p.function }) });
    approve.disabled = !p.may_approve;
    approve.addEventListener("click", () => approveProposal(p, notice));
    return el("li", { class: "kind", "data-instance": p.instance },
              el("h3", {}, el("a", { href: `#/instance/${p.instance}`,
                                     text: t("approvals.proposal_title", { function: p.function,
                                                                           rules: p.contract_name ?? short(p.contract).text }) })),
              el("p", { text: p.by ? t("approvals.proposed_by", { name: nameOf(p.by), time: timeText(p.proposed_at) })
                                   : t("approvals.proposed_by_agent") }),
              el("p", { class: "id", text: p.arguments }),
              p.approvals.length ? el("p", { text: t("approvals.so_far", {
                  names: p.approvals.map((a) => (a.in_person ? t("approvals.in_person_name", { name: nameOf(a) }) : nameOf(a)))
                      .join(t("approvals.separator")) }) }) : null,
              p.may_approve ? el("p", { class: "hint", text: t(p.completes ? "approvals.completes" : "approvals.records") })
                            : el("p", { class: "hint", text: p.reason ?? "" }),
              notice, approve);
}

/// Waiting for your approval, and what you sent for approval.
async function approvalsScreen() {
    const listed = await api("GET", `approvals?language=${encodeURIComponent(state.language)}`);
    const parts = [flash(), el("h1", { text: t("approvals.title") }), el("p", { class: "hint", text: t("approvals.intro") })];
    parts.push(el("h2", { text: t("approvals.waiting_title") }));
    if (!listed.actor) {
        parts.push(el("p", { class: "hint", text: t("approvals.no_actor") }));
    } else if (listed.waiting.length === 0 && listed.proposals.length === 0) {
        parts.push(el("p", { text: t("approvals.none_waiting") }));
    } else {
        parts.push(el("ul", { class: "approvals" }, listed.waiting.map((h) => heldItem(h, listed.time)),
                      listed.proposals.map(proposalItem)));
    }
    parts.push(el("h2", { text: t("approvals.sent_title") }));
    const sent = [...listed.sent].sort((a, b) => b.held_at - a.held_at);
    if (sent.length === 0) {
        parts.push(el("p", { text: t("approvals.none_sent") }));
    } else {
        const notice = el("div", { role: "status" });
        parts.push(notice, el("ul", { class: "approvals" }, sent.map((h) => {
            const item = heldItem(h, listed.time);
            if (h.state === "open") {
                const withdraw = el("button", { type: "button", text: t("approvals.withdraw"),
                                                "aria-label": t("approvals.withdraw_label", { what: t(`approve.type.${h.type}`) }) });
                withdraw.addEventListener("click", async () => {
                    withdraw.disabled = true;
                    try {
                        await api("DELETE", `approvals/${h.id}`);
                        state.flash = t("approvals.withdrawn");
                        route();
                    } catch (error) {
                        withdraw.disabled = false;
                        notice.replaceChildren(problem(t("error.server", { message: error.message })));
                    }
                });
                item.append(el("p", { class: "hint", text: t("approvals.withdraw_hint") }), withdraw);
            }
            return item;
        })));
    }
    show(...parts);
}

/// Someone else's statement, waiting for approvals: decoded here from its
/// bytes (its id recomputed, its shown fields checked against its field
/// root), compared with what the console says of it, then approved with a
/// passkey tap, declined, or withdrawn.
async function approvalScreen(id) {
    const [view, check] = await Promise.all([api("GET", `approvals/${id}`), loadChecker()]);
    const held = view.held;
    const summary = view.summary;
    if (!summary) {
        show(el("h1", { text: t("approvals.review_title") }), problem(t("approvals.not_yours", { why: view.why_not ?? "" })),
             goButton(t("approvals.open_list"), "#/approvals"));
        return;
    }
    let checkedHere = false;
    let fields = null;
    let decoded = null;
    if (check) {
        const statement = new Uint8Array(fromBase64url(view.statement));
        const shown = view.fields ? new Uint8Array(fromBase64url(view.fields)) : new Uint8Array(0);
        const read = check.statementId(statement, shown, view.hash);
        decoded = read.ok ? read.statement : null;
        if (!read.ok || read.id !== id || held.id !== id || !heldAgrees(decoded, summary) ||
            (decoded.actor ?? null) !== (held.signer?.id ?? null) ||
            (decoded.delegation ?? null) !== (held.delegation ?? null) || decoded.issued_at !== held.issued_at) {
            show(el("h1", { text: t("approvals.review_title") }), problem(t("approvals.mismatch")),
                 goButton(t("approvals.open_list"), "#/approvals"));
            return;
        }
        fields = read.fields;
        checkedHere = true;
    }
    const facts = statementFacts(summary);
    const fact = (key, value) => facts.append(el("dt", { text: t(key) }), el("dd", { text: String(value) }));
    fact(summary.by_organization ? "approvals.signed_by_org" : "approvals.signed_by", nameOf(held.signer));
    fact("approvals.issued", timeText(held.issued_at));
    fact("approvals.sent", timeText(held.held_at));
    for (const f of fields ?? []) {
        facts.append(el("dt", { text: t("register.private_field", { name: f.name }) }), el("dd", { text: f.value }));
    }
    for (const [name, value] of Object.entries(summary.metadata ?? {})) {
        facts.append(el("dt", { text: t("register.public_field", { name }) }), el("dd", { text: value }));
    }
    for (const f of summary.files ?? []) {
        facts.append(el("dt", { text: t("register.file") }), el("dd", { text: `${f.name}, ${sizeText(f.size)}` }));
    }
    const parts = [el("h1", { text: t("approvals.review_title") }), el("p", { text: t("approvals.review_intro") }), facts,
                   el("p", { class: "id", text: id }),
                   el("p", { class: "hint", text: t(checkedHere ? "approvals.checked_here" : "approve.checked_by_console") })];
    if (summary.type === "record-register" && summary.field_count > 0) {
        parts.push(el("p", { class: "hint", text: t(fields ? "approvals.fields_shown" : "approvals.fields_sealed") }));
    }
    parts.push(el("h2", { text: t("approvals.progress_title") }), heldProgress(held));
    const notice = el("div", { role: "status" });
    const buttons = [];
    if (view.may_approve) {
        const approve = el("button", { type: "button", class: "primary", text: t("approvals.button") });
        approve.addEventListener("click", async () => {
            approve.disabled = true;
            status(t("status.working"));
            try {
                const prepared = await api("POST", `approvals/${id}/prepare`, {});
                let challenge = prepared.public_key.challenge;
                if (check) {
                    // The approval's own challenge, from the payload the
                    // console prepared: for this statement, by this person.
                    const own = check.approvalChallenge(new Uint8Array(fromBase64url(prepared.payload)),
                                                        new Uint8Array(fromBase64url(prepared.kid)), prepared.hash);
                    if (!own.ok || own.challenge !== challenge || own.statement !== id ||
                        own.approver !== view.approver || own.ledger !== decoded.ledger) {
                        notice.replaceChildren(problem(t("approvals.mismatch")));
                        return;
                    }
                    challenge = own.challenge;
                }
                const options = prepared.public_key;
                const credential = await navigator.credentials.get({
                    publicKey: {
                        challenge: fromBase64url(challenge),
                        rpId: options.rpId,
                        allowCredentials: options.allowCredentials.map((c) => ({ type: c.type, id: fromBase64url(c.id) })),
                        userVerification: options.userVerification,
                        timeout: options.timeout,
                    },
                });
                const done = await api("POST", `approvals/${id}/approve`, {
                    prepared: prepared.prepared,
                    credential_id: toBase64url(credential.rawId),
                    authenticator_data: toBase64url(credential.response.authenticatorData),
                    client_data_json: toBase64url(credential.response.clientDataJSON),
                    signature: toBase64url(credential.response.signature),
                });
                show(el("h1", { text: t("approvals.done_title") }),
                     el("p", { role: "status", text: done.statement_id ? t("approvals.registered", { index: done.index })
                                                                       : t("approvals.kept") }),
                     el("p", { class: "id", text: id }),
                     done.statement_id ? null : heldProgress(done),
                     goButton(t("approvals.open_list"), "#/approvals"));
            } catch (error) {
                notice.replaceChildren(problem(passkeyProblem(error)));
            } finally {
                approve.disabled = false;
                status("");
            }
        });
        const decline = el("button", { type: "button", text: t("approvals.decline") });
        decline.addEventListener("click", async () => {
            decline.disabled = true;
            try {
                await api("POST", `approvals/${id}/decline`, {});
                notice.replaceChildren(el("p", { text: t("approvals.declined") }));
            } catch (error) {
                decline.disabled = false;
                notice.replaceChildren(problem(t("error.server", { message: error.message })));
            }
        });
        buttons.push(approve, " ", decline);
        parts.push(el("p", { class: "hint", text: t("approvals.decline_hint") }));
    } else if (view.why_not) {
        parts.push(el("p", { class: "hint", text: t("approvals.not_yours", { why: view.why_not }) }));
    }
    if (view.may_withdraw) {
        const withdraw = el("button", { type: "button", text: t("approvals.withdraw") });
        withdraw.addEventListener("click", async () => {
            withdraw.disabled = true;
            try {
                await api("DELETE", `approvals/${id}`);
                state.flash = t("approvals.withdrawn");
                location.hash = "#/approvals";
            } catch (error) {
                withdraw.disabled = false;
                notice.replaceChildren(problem(t("error.server", { message: error.message })));
            }
        });
        buttons.push(" ", withdraw);
    }
    show(...parts, notice, ...buttons, " ", goButton(t("approvals.open_list"), "#/approvals"));
}

// --- Navigation ------------------------------------------------------------------

/// Folds the menu of a phone's bar (see console.css), or opens it.
function setMenu(open) {
    document.querySelector("header.bar").classList.toggle("open", open);
    document.getElementById("menu").setAttribute("aria-expanded", String(open));
}

function chrome() {
    setMenu(false);
    const signedIn = state.who !== null;
    document.getElementById("nav").hidden = !signedIn;
    document.getElementById("sign-out").hidden = !signedIn;
    const who = document.getElementById("who");
    who.hidden = !signedIn;
    who.textContent = signedIn
        ? t("session.signed_in_as", { user: state.who.user, role: t(`role.${state.who.role}`) })
        : "";
    const hash = location.hash;
    const current = hash.startsWith("#/things") || hash.startsWith("#/new") || hash.startsWith("#/renew") ||
                    hash.startsWith("#/thing/") || hash.startsWith("#/instance/") ||
                    hash.startsWith("#/act/") ? "things"
        : hash.startsWith("#/create/") ? "rules"
        : hash.startsWith("#/exchange") ? "home"
        : hash.startsWith("#/parties") || hash.startsWith("#/access/") ? "parties"
        : hash.startsWith("#/people") ? "people"
        : hash.startsWith("#/automation") ? "automation"
        : hash.startsWith("#/scripts") || hash.startsWith("#/script/") ? "scripts"
        : hash.startsWith("#/approval") ? "approvals"
        : hash.startsWith("#/reports") ? "reports"
        : hash.startsWith("#/kinds") ? "kinds"
        : hash.startsWith("#/rules") ? "rules"
        : hash.startsWith("#/verify") ? "verify"
        : hash.startsWith("#/settings") ? "settings" : "home";
    for (const link of document.querySelectorAll("nav a")) {
        if (link.dataset.route === current) {
            link.setAttribute("aria-current", "page");
        } else {
            link.removeAttribute("aria-current");
        }
    }
}

async function route() {
    const hash = location.hash;
    // An invitation's code is read once and taken out of the address bar and
    // the history at once.
    const enroll = hash.match(/^#\/enroll\/(khi_[A-Za-z0-9_-]{43})$/);
    if (enroll) {
        history.replaceState(null, "", `${location.pathname}#/enroll`);
        state.pendingCode = enroll[1];
    }
    if (hash.startsWith("#/enroll") && state.pendingCode) {
        state.who = null;
        chrome();
        enrollScreen(state.pendingCode);
        return;
    }
    if (state.who === null && stored(sessionStorage, SESSION)) {
        try {
            const me = await api("GET", "session");
            state.who = { user: me.user, role: me.role, keys: me.keys ?? "none" };
        } catch {
            store(sessionStorage, SESSION, null);
        }
    }
    chrome();
    if (hash.startsWith("#/verify")) {
        verifyScreen();
        return;
    }
    if (state.who === null) {
        if (hash.startsWith("#/recover")) {
            recoverScreen();
        } else {
            signInScreen();
        }
        return;
    }
    try {
        const thing = hash.match(/^#\/thing\/([0-9a-f]{64})$/);
        const newVersion = hash.match(/^#\/new\/([0-9a-f]{64})$/);
        const instance = hash.match(/^#\/instance\/([0-9a-f]{64})$/);
        const script = hash.match(/^#\/script\/([0-9a-f]{64})$/);
        const create = hash.match(/^#\/create\/([0-9a-f]{64})$/);
        const act = hash.match(/^#\/act\/([0-9a-f]{64})\/([^/]+)$/);
        const asked = hash.match(/^#\/access\/request\/([0-9a-f]{64})$/);
        const delivered = hash.match(/^#\/access\/delivery\/([0-9a-f]{64})$/);
        const opened = hash.match(/^#\/exchange\/opened\/([0-9a-f]{24})$/);
        const approval = hash.match(/^#\/approval\/([0-9a-f]{64})$/);
        await (thing ? thingScreen(thing[1])
            : act ? actionLinkScreen(act[1], decodeURIComponent(act[2]))
            : asked ? accessRequestScreen(asked[1])
            : delivered ? accessDeliveryScreen(delivered[1])
            : instance ? instanceScreen(instance[1])
            : script ? scriptScreen(script[1])
            : approval ? approvalScreen(approval[1])
            : hash.startsWith("#/approvals") ? approvalsScreen()
            : hash.startsWith("#/scripts") ? scriptsScreen()
            : create ? createScreen(create[1])
            : opened ? exchangeScreen(opened[1])
            : hash.startsWith("#/exchange") ? exchangeScreen()
            : hash.startsWith("#/parties") ? partiesScreen()
            : hash.startsWith("#/people") ? peopleScreen()
            : hash.startsWith("#/automation") ? automationScreen()
            : hash.startsWith("#/things") ? thingsScreen()
            : hash.startsWith("#/renew") ? renewScreen()
            : hash.startsWith("#/reports") ? reportsScreen()
            : newVersion ? newDocumentScreen(newVersion[1])
            : hash.startsWith("#/new") ? newDocumentScreen()
            : hash.startsWith("#/kinds") ? kindsScreen()
            : hash.startsWith("#/certificates") ? certificatesScreen()
            : hash.startsWith("#/rules/new") ? rulesEditor()
            : hash.startsWith("#/rules") ? rulesScreen()
            : hash.startsWith("#/settings") ? settingsScreen() : homeScreen());
    } catch (error) {
        if (error instanceof ApiError && error.status === 401) {
            state.who = null;
            store(sessionStorage, SESSION, null);
            chrome();
            signInScreen();
            return;
        }
        show(problem(t("error.server", { message: error.message })));
    }
}

async function signOut() {
    try {
        await api("DELETE", "session");
    } catch {
        // Signed out anyway: the token is forgotten here.
    }
    store(sessionStorage, SESSION, null);
    state.who = null;
    state.rules = undefined;
    store(sessionStorage, RULES_DRAFT, null);
    home();
}

async function start() {
    state.english = await catalog("en");
    try {
        const begun = await api("GET", "start");
        state.firstRun = begun.first_run;
        state.defaultLanguage = begun.language;
    } catch {
        // An older console, or one starting: the defaults do.
    }
    const saved = LANGUAGES.includes(stored(localStorage, LANGUAGE));
    await setLanguage(preferredLanguage(), saved);
    document.getElementById("language").addEventListener("change", async (event) => {
        await setLanguage(event.target.value);
        route();
    });
    document.getElementById("sign-out").addEventListener("click", signOut);
    document.getElementById("menu").addEventListener("click", () => {
        setMenu(!document.querySelector("header.bar").classList.contains("open"));
    });
    // Any entry closes it, the page already shown too (no hash change then).
    document.getElementById("nav").addEventListener("click", (event) => {
        if (event.target.closest("a")) setMenu(false);
    });
    window.addEventListener("hashchange", route);
    route();
}

start();
