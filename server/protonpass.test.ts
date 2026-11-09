import { existsSync, mkdtempSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it, vi } from "vitest";

import { addHeldSecretScrubber, redactSecretsInText } from "../shared/redact.ts";
import { BotLogins } from "./bot-logins.ts";
import { fillLogin } from "./login-fill.ts";
import { HeldSecrets, LOGINS_FILE, VaultStore } from "./vault-store.ts";
import { isOnePasswordLoginId, OnePasswordLogins, sdkOnePasswordClient } from "./onepassword.ts";
import { cliProtonPassClient, isProtonPassLoginId, PROTON_PASS_NO_TOTP, ProtonPassError, ProtonPassLogins, protonPassLogins, protonPassPassword, protonPassProblem } from "./protonpass.ts";
import { removeTempDir } from "./testing/cleanup.ts";
import { FakeLoginPage, LOGIN_FORM } from "./testing/fake-login-page.ts";
import { fakeOnePasswordSdk } from "./testing/fake-onepassword.ts";
import { fakeProtonPassClient } from "./testing/fake-protonpass.ts";

const TOKEN = "pst_fake-token::FAKE";
const PASSWORD = "fake-proton-password";
const CODE = "029384";
const dirs: string[] = [];
let page: FakeLoginPage | null = null;
const scrubbers: Array<() => void> = [];
afterEach(async () => {
  page?.close(); page = null;
  for (const remove of scrubbers.splice(0)) remove();
  vi.restoreAllMocks(); vi.unstubAllEnvs();
  for (const dir of dirs.splice(0)) await removeTempDir(dir);
});

function directory(): string {
  const dir = mkdtempSync(join(tmpdir(), "omb protonpass-"));
  dirs.push(dir);
  return dir;
}

function setup(now?: () => number) {
  const dir = directory();
  const store = new VaultStore({ dataDir: dir });
  store.setProtonPassToken(TOKEN);
  const client = fakeProtonPassClient();
  const connect = vi.fn(async (_token: string) => client);
  const source = new ProtonPassLogins({ token: () => store.protonPassToken(), saveToken: (token) => store.setProtonPassToken(token),
    grants: () => store.protonPassGrants(), connect, now });
  return { dir, store, client, connect, source };
}

function cliFixture(options: { timeoutMs?: number; maxBuffer?: number } = {}) {
  const dir = directory();
  const cli = join(dir, "pass-cli.ts");
  writeFileSync(cli, readFileSync(fileURLToPath(new URL("./testing/fake-protonpass-cli.ts", import.meta.url))), { mode: 0o700 });
  vi.stubEnv("FAKE_PROTONPASS_HOME", dir);
  const client = () => cliProtonPassClient({ token: TOKEN, dataDir: dir, cli, ...options });
  const calls = (): Array<{ args: string[]; session: string; keyProvider: string; tokenMatches: boolean; logLevel: string; protonEnvNames: string[] }> =>
    existsSync(join(dir, "calls.jsonl")) ? readFileSync(join(dir, "calls.jsonl"), "utf8").trim().split("\n").map((line) => JSON.parse(line)) : [];
  const mode = (value: string) => writeFileSync(join(dir, "mode"), value);
  return { dir, client, calls, mode };
}

describe("Proton Pass output", () => {
  it("parses the bulk list, keeps only non-secret fields and ignores unknown keys and inactive or non-login items", () => {
    const login = { email: "", username: "alice", password: PASSWORD, urls: ["https://a.example"], totp_uri: "otpauth://secret", passkeys: [] };
    const item = { id: "i1", share_id: "v1", state: "Active", content: { title: "Example", content: { Login: login } } };
    const parsed = protonPassLogins({ items: [{ ...item, extra: { unknown: true } }, { ...item, id: "i2", state: "Trashed" },
      { ...item, id: "i3", content: { title: "Note", content: { Note: {} } } },
      { ...item, id: "i4", content: { title: "Email only", content: { Login: { ...login, username: "", email: "e@example.com", urls: undefined } } } }], folders: [], extra: true }, "v1");
    expect(parsed).toEqual([{ id: "i1", title: "Example", username: "alice", urls: ["https://a.example"] }, { id: "i4", title: "Email only", username: "e@example.com", urls: [] }]);
    expect(JSON.stringify(parsed)).not.toContain(PASSWORD);
    expect(JSON.stringify(parsed)).not.toContain("otpauth");
    expect(protonPassLogins({ items: [] }, "v1")).toEqual([]);
  });

  const listed = (patch: Record<string, unknown>) => ({ items: [{ id: "i1", share_id: "v1", content: { title: "A", content: { Login: { username: "u", urls: [] } } }, ...patch }] });
  it.each([null, [], { items: {} }, { items: [null] }, listed({ share_id: "wrong" }), listed({ content: { title: {}, content: { Login: {} } } }),
    listed({ content: { title: "A", content: { Login: { urls: "https://a.example" } } } }), { items: [], folders: {} }])("rejects an unexpected list shape without its contents", (value) => {
    expect(() => protonPassLogins(value, "v1")).toThrow("Unexpected Proton Pass output");
  });

  it("validates every consumed view field and the identity of the item", () => {
    const value = (password: unknown) => ({ item: { id: "i1", share_id: "v1", content: { content: { Login: { password, future: true } } } }, future: true });
    expect(protonPassPassword(value(PASSWORD), "v1", "i1")).toBe(PASSWORD);
    for (const output of [null, {}, { item: null }, value(123), value({ secret: PASSWORD })]) {
      expect(() => protonPassPassword(output, "v1", "i1")).toThrow("Unexpected Proton Pass output");
    }
    expect(() => protonPassPassword(value(PASSWORD), "v2", "i1")).toThrow("Unexpected Proton Pass output");
    expect(() => protonPassPassword(value(""), "v1", "i1")).toThrow("does not have the requested field");
    expect(protonPassProblem(new Error(`${TOKEN} ${PASSWORD} ${CODE}`))).not.toContain(TOKEN);
  });
});

describe("the pass-cli adapter", () => {
  it("keeps only non-secret fields from discovery, with the token only in a private child environment", async () => {
    const { dir, client, calls } = cliFixture();
    vi.stubEnv("PROTON_PASS_SESSION_DIR", join(dir, "untrusted"));
    vi.stubEnv("PROTON_PASS_KEY_PROVIDER", "keyring");
    vi.stubEnv("PROTON_PASS_ENVIRONMENT", "https://untrusted.example");
    const log = vi.spyOn(console, "log");
    const warn = vi.spyOn(console, "warn");
    const cli = client();
    await cli.info();
    expect(await cli.vaults()).toEqual([{ id: "v1", title: "Bots" }, { id: "v2", title: "Finance" }]);
    expect(await cli.loginItems("v1")).toEqual([{ id: "i1", title: "Fixture login" }]);
    expect(await cli.metadata("v1", "i1")).toEqual({ username: "alice@example.com", urls: ["https://accounts.example.com/login", "https://login.example.org"] });
    // One list call per vault; listed logins need no per-item views.
    expect(calls().filter((call) => call.args[0] === "item" && call.args[1] === "list").map((call) => call.args.includes("--show-secrets"))).toEqual([true]);
    expect(calls().filter((call) => call.args[1] === "view")).toEqual([]);
    expect(await cli.metadata("v2", "i1")).toEqual({ username: "treasurer", urls: ["https://bank.example.net"] });
    expect(calls().filter((call) => call.args[1] === "view").map((call) => call.args[2])).toEqual(["pass://v2/i1/username", "pass://v2/i1/urls"]);
    expect(calls().every((call) => call.tokenMatches && call.keyProvider === "fs" && call.logLevel === "off")).toBe(true);
    expect(calls().every((call) => JSON.stringify(call.protonEnvNames) === JSON.stringify(["PROTON_PASS_KEY_PROVIDER", "PROTON_PASS_PERSONAL_ACCESS_TOKEN", "PROTON_PASS_SESSION_DIR"]))).toBe(true);
    const session = calls()[0]!.session;
    expect(dirname(dirname(session))).toBe(dir);
    expect(session).not.toBe(process.env.PROTON_PASS_SESSION_DIR);
    expect(existsSync(process.env.PROTON_PASS_SESSION_DIR!)).toBe(false);
    if (process.platform !== "win32") expect(statSync(session).mode & 0o777).toBe(0o700);
    const exposed = JSON.stringify({ calls: calls(), log: log.mock.calls, warn: warn.mock.calls });
    for (const secret of [TOKEN, PASSWORD, CODE]) expect(exposed).not.toContain(secret);
    expect(process.env.PROTON_PASS_PERSONAL_ACCESS_TOKEN).not.toBe(TOKEN);
    expect(await cli.password("v1", "i1")).toBe(PASSWORD);
    expect(await cli.totp("v1", "i1")).toBe(CODE);
    await cli.logout();
    expect(existsSync(session)).toBe(false);
  });

  it("reuses an app session after restart and logs in again once after expiry", async () => {
    const { dir, client, calls } = cliFixture();
    const first = client();
    await first.vaults();
    const second = client();
    await second.info();
    expect(calls().filter((call) => call.args[0] === "login")).toHaveLength(1);
    writeFileSync(join(dir, "expire-once"), "");
    expect(await second.vaults()).toHaveLength(2);
    expect(calls().filter((call) => call.args[0] === "login")).toHaveLength(2);
    expect(calls().filter((call) => call.args[0] === "vault")).toHaveLength(3);
  });

  it.each(["revoked", "always-expired", "revoked-vault"])("bounds auth retries for %s and never echoes diagnostics", async (failure) => {
    const { client, calls, mode } = cliFixture();
    mode(failure);
    const cli = client();
    const failed = failure === "revoked-vault" ? cli.loginItems("v1") : cli.vaults();
    await expect(failed).rejects.toThrow("did not accept the token");
    expect(calls().filter((call) => call.args[0] === "login").length).toBeLessThanOrEqual(2);
    await expect(failed).rejects.not.toThrow(TOKEN);
  });

  it.each(["bad-json", "bad-shape", "bad-view", "diagnostics"])("sanitizes %s output", async (failure) => {
    const { client, mode } = cliFixture();
    const cli = client();
    await cli.info();
    mode(failure);
    const result = failure === "bad-view" ? cli.password("v1", "i1") : cli.vaults();
    await expect(result).rejects.toThrow(failure === "diagnostics" ? "could not be read" : "Unexpected Proton Pass output");
    for (const secret of [TOKEN, PASSWORD, CODE]) await expect(result).rejects.not.toThrow(secret);
  });

  it("handles missing username fields as email logins and an empty token-visible vault set", async () => {
    const { client, mode } = cliFixture();
    const cli = client();
    mode("email-only");
    expect((await cli.metadata("v1", "i1")).username).toBe("email-user@example.com");
    mode("empty");
    expect(await cli.vaults()).toEqual([]);
  });

  it("reports a missing CLI", async () => {
    const client = cliProtonPassClient({ token: TOKEN, dataDir: directory(), cli: join(directory(), "missing-pass-cli") });
    await expect(client.info()).rejects.toThrow("CLI is not installed");
  });

  it("limits command duration", async () => {
    const { client, mode } = cliFixture({ timeoutMs: 100 });
    mode("timeout");
    await expect(client().info()).rejects.toThrow("took too long");
  });

  it("caps output and removes the private session even when logout fails", async () => {
    const { client, calls, mode } = cliFixture({ maxBuffer: 1024 });
    const cli = client();
    await cli.info();
    const session = calls()[0]!.session;
    mode("overflow");
    await expect(cli.vaults()).rejects.toThrow("too much output");
    await expect(cli.logout()).rejects.toThrow("too much output");
    expect(existsSync(session)).toBe(false);
  });
});

describe("Proton Pass logins", () => {
  it("discovers every readable vault without passwords or codes, leaving TOTP unknown", async () => {
    const { source, client } = setup();
    expect(await source.refresh()).toEqual({ connected: true, items: 2, vaults: [
      { id: "v1", title: "Bots", items: 1, bots: "all" }, { id: "v2", title: "Finance", items: 1, bots: "all" },
    ] });
    expect(source.list()).toHaveLength(3);
    expect(source.list().every((row) => row.hasTotp === undefined && row.source === "protonpass")).toBe(true);
    expect(client.password).not.toHaveBeenCalled(); expect(client.totp).not.toHaveBeenCalled();
    expect(source.candidates("accounts.example.com.evil.test", "pepper")).toEqual([]);
    const [candidate] = source.candidates("accounts.example.com", "pepper");
    expect(await candidate!.secrets()).toEqual({ password: PASSWORD, totp: null });
    expect(client.totp).not.toHaveBeenCalled();
    expect(await candidate!.oneTimeCode!()).toBe(CODE);
  });

  it("keeps grants across reconnects, restricts browser mates and namespaces identical 1Password ids", async () => {
    const { source, store, client } = setup(() => 123);
    const { sdk } = fakeOnePasswordSdk({ token: "ops_fake", vaults: { v1: { title: "Bots", items: [
      { id: "i1", title: "Example", urls: ["https://accounts.example.com"], username: "1password-user", password: "fake-other-password" },
    ] } } });
    const onePassword = new OnePasswordLogins({ token: () => "ops_fake", connect: (token) => sdkOnePasswordClient(sdk, token, "0.0.0") });
    const bots = new BotLogins(store, onePassword, () => [{ id: "pepper", browserProfile: "shared" }, { id: "quill", browserProfile: "shared" }], [source]);
    await source.refresh();
    const candidates = await bots.candidates("pepper", "accounts.example.com");
    expect(candidates).toHaveLength(2);
    const ids = candidates.map((candidate) => candidate.id);
    expect(new Set(ids).size).toBe(2);
    expect(ids.map(isProtonPassLoginId)).toEqual([false, true]);
    expect(ids.map(isOnePasswordLoginId)).toEqual([true, false]);
    bots.markUsed(ids[1]!);
    expect(source.list().find((row) => row.id === ids[1])?.lastUsedAt).toBe(123);
    expect(onePassword.list()[0]!.lastUsedAt).toBeUndefined();
    store.setProtonPassGrant("v1", ["pepper"]);
    expect((await bots.candidates("pepper", "accounts.example.com"))).toHaveLength(1);
    expect(source.sitesFor(["pepper", "quill"])).toHaveLength(1);
    const stale = candidates[1]!;
    await expect(stale.secrets()).rejects.toThrow("connection changed");
    expect(client.password).not.toHaveBeenCalled();
    await source.connectToken(TOKEN);
    expect(source.status().vaults?.[0]?.bots).toEqual(["pepper"]);
  });

  it("bounds discovery to 500 items and four concurrent metadata reads", async () => {
    const { source, client } = setup();
    client.loginItems.mockResolvedValue(Array.from({ length: 700 }, (_, index) => ({ id: `i${index}`, title: "Login" })));
    let active = 0; let maximum = 0;
    let started!: () => void;
    const ready = new Promise<void>((resolve) => { started = resolve; });
    let release!: () => void;
    const gate = new Promise<void>((resolve) => { release = resolve; });
    client.metadata.mockImplementation(async () => {
      active++; maximum = Math.max(maximum, active);
      if (active === 4) started();
      await gate;
      active--;
      return { username: "user", urls: ["https://example.com"] };
    });
    const refreshing = source.refresh();
    await ready;
    expect(client.metadata).toHaveBeenCalledTimes(4);
    release();
    await refreshing;
    expect(maximum).toBe(4);
    expect(client.metadata).toHaveBeenCalledTimes(500);
    expect(source.status().items).toBe(500);
    expect(client.password).not.toHaveBeenCalled(); expect(client.totp).not.toHaveBeenCalled();
  });

  it("refreshes stale metadata once and fails closed if vault access is revoked", async () => {
    let now = 0;
    const { source, client } = setup(() => now);
    await Promise.all([source.fresh(), source.fresh()]);
    expect(client.vaults).toHaveBeenCalledTimes(1);
    now = 5 * 60_000; await source.fresh();
    expect(client.vaults).toHaveBeenCalledTimes(1);
    now = 11 * 60_000; await source.fresh();
    expect(client.vaults).toHaveBeenCalledTimes(2);
    client.vaults.mockRejectedValue(new ProtonPassError("auth"));
    expect(await source.refresh()).toMatchObject({ connected: true, error: expect.stringContaining("did not accept the token") });
    expect(source.list()).toEqual([]);
  });

  it("reports a discovery failure to fill_login without exposing diagnostics", async () => {
    const { source, client, store } = setup();
    const onePassword = new OnePasswordLogins({ token: () => null, connect: async () => { throw new Error("not configured"); } });
    const logins = new BotLogins(store, onePassword, () => [], [source]);
    client.info.mockRejectedValue(new ProtonPassError("missing"));
    page = new FakeLoginPage("https://accounts.example.com/login", LOGIN_FORM);
    const result = await fillLogin({ candidates: (host) => logins.candidates("pepper", host), available: async () => logins.sitesFor("pepper"), vaultTrouble: () => logins.vaultTrouble() }, {
      engine: (args) => page!.engine(args), insertText: (text) => page!.insertText(text), press: (key) => page!.press(key), click: (selector) => page!.click(selector), remember: () => {},
    });
    expect(result).toMatchObject({ ok: false, text: expect.stringContaining("Proton Pass CLI is not installed") });
    expect(client.password).not.toHaveBeenCalled(); expect(client.totp).not.toHaveBeenCalled();
  });

  it("does not reinstate disconnected metadata or allow a captured candidate to read secrets", async () => {
    const { source, store, client } = setup();
    await source.refresh();
    const candidate = source.candidates("accounts.example.com", "pepper")[0]!;
    let release!: () => void;
    let started!: () => void;
    const ready = new Promise<void>((resolve) => { started = resolve; });
    client.vaults.mockImplementation(async () => { started(); return new Promise((resolve) => { release = () => resolve([{ id: "v1", title: "Bots" }]); }); });
    const refresh = source.refresh();
    await ready;
    const disconnect = source.disconnect();
    expect(store.protonPassToken()).toBeNull();
    release();
    await Promise.all([refresh, disconnect]);
    expect(source.status()).toEqual({ connected: false }); expect(source.list()).toEqual([]);
    await expect(candidate.secrets()).rejects.toThrow("connection changed");
    expect(client.password).not.toHaveBeenCalled(); expect(client.logout).toHaveBeenCalledTimes(1);
  });

  it("keeps a rejected replacement out of the encrypted store and errors", async () => {
    const { source, store, connect } = setup();
    await source.refresh();
    connect.mockRejectedValue(new Error(`failed ${TOKEN} ${PASSWORD}`));
    await expect(source.connectToken("pst_replacement")).rejects.toThrow("could not be read");
    expect(store.protonPassToken()).toBe(TOKEN);
    expect(source.list()).toHaveLength(3);
  });

  it.each([false, true])("fills and masks passwords; asks for TOTP only on a code page (%s)", async (withCode) => {
    const { source, store, client, dir } = setup();
    await source.refresh();
    const held = new HeldSecrets(store);
    scrubbers.push(addHeldSecretScrubber((text) => held.scrub(text)));
    page = new FakeLoginPage("https://accounts.example.com/login", LOGIN_FORM + (withCode ? '<input name="otp" autocomplete="one-time-code">' : ""));
    const result = await fillLogin({ submit: false, candidates: async (host) => source.candidates(host, "pepper"), available: async () => source.sitesFor("pepper") }, {
      engine: (args) => page!.engine(args), insertText: (text) => page!.insertText(text), press: (key) => page!.press(key), click: (selector) => page!.click(selector),
      remember: (value, kind) => held.remember(value, kind),
    });
    expect(result.ok).toBe(true);
    expect(result.text).toContain("from Proton Pass");
    expect(page.field("#password").value).toBe(PASSWORD);
    expect(client.totp).toHaveBeenCalledTimes(withCode ? 1 : 0);
    if (withCode) expect(page.field("input[name=otp]").value).toBe(CODE);
    for (const secret of [TOKEN, PASSWORD, ...(withCode ? [CODE] : [])]) {
      expect(JSON.stringify(result)).not.toContain(secret);
      expect(JSON.stringify(page.engineCalls)).not.toContain(secret);
      expect(redactSecretsInText(JSON.stringify({ text: secret, event: secret, tool: secret }))).not.toContain(secret);
      expect(readFileSync(join(dir, LOGINS_FILE)).includes(Buffer.from(secret))).toBe(false);
    }
  });

  it("reads only a code on a code-only page, and gives a fixed error when no code is available", async () => {
    const { source, client } = setup();
    await source.refresh();
    page = new FakeLoginPage("https://accounts.example.com/code", '<input name="otp" autocomplete="one-time-code">');
    const input = { submit: false, candidates: async (host: string) => source.candidates(host, "pepper"), available: async () => source.sitesFor("pepper") };
    const deps = { engine: (args: string[]) => page!.engine(args), insertText: (text: string) => page!.insertText(text), press: (key: string) => page!.press(key), click: (selector: string) => page!.click(selector), remember: () => {} };
    expect(await fillLogin(input, deps)).toMatchObject({ ok: true, filled: ["code"] });
    expect(client.password).not.toHaveBeenCalled();
    for (const failure of [new Error(`${TOKEN} ${PASSWORD} ${CODE}`), null]) {
      if (failure) client.totp.mockRejectedValue(failure);
      else client.totp.mockResolvedValue("");
      await expect(fillLogin(input, deps)).rejects.toThrow(PROTON_PASS_NO_TOTP);
      expect(page.field("input[name=otp]").value).toBe("");
    }
  });
});
