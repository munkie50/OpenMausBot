import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";

import { loginMatchesHost, loginUsableBy, type LoginBots } from "../shared/logins.ts";
import { BotLogins } from "./bot-logins.ts";
import { fillLogin } from "./login-fill.ts";
import { VaultStore } from "./vault-store.ts";
import type { VaultSource } from "./login-vault-source.ts";
import { OnePasswordLogins, sdkOnePasswordClient } from "./onepassword.ts";
import { removeTempDir } from "./testing/cleanup.ts";
import { FakeLoginPage, LOGIN_FORM } from "./testing/fake-login-page.ts";
import { fakeOnePasswordSdk } from "./testing/fake-onepassword.ts";
import { parseTotpKey, totpCode } from "./totp.ts";

const dirs: string[] = [];
let page: FakeLoginPage | null = null;
afterEach(async () => {
  page?.close();
  page = null;
  for (const dir of dirs.splice(0)) await removeTempDir(dir);
});

async function setup(bots: LoginBots = "all") {
  const dir = mkdtempSync(join(tmpdir(), "omb-vault-source-"));
  dirs.push(dir);
  const store = new VaultStore({ dataDir: dir });
  const item = { id: "i1", title: "Example", urls: ["https://accounts.example.com"], username: "first@example.com", password: "fake-first-password" };
  const { sdk, calls } = fakeOnePasswordSdk({ token: "ops_fake-source-token", vaults: { v1: { title: "Bots", items: [item] } } });
  const onePassword = new OnePasswordLogins({ token: () => "ops_fake-source-token", connect: (token) => sdkOnePasswordClient(sdk, token, "0.0.0"), grants: () => ({ v1: bots }), now: () => 123 });
  await onePassword.fresh();
  const row = { ...onePassword.list()[0]!, id: "test-vault:v1:i1:example.com", username: "second@example.com", hasTotp: true };
  const key = parseTotpKey("JBSWY3DPEHPK3PXP")!;
  const secrets = vi.fn(async () => ({ password: "fake-second-password", totp: key }));
  const other = {
    idPrefix: "test-vault:",
    status: () => ({ connected: true }),
    refresh: async () => ({ connected: true }),
    fresh: vi.fn(async () => {}),
    list: () => [row],
    sitesFor: (botId) => loginUsableBy(row, botId) ? [row] : [],
    candidates: (host, botId) => loginUsableBy(row, botId) && loginMatchesHost(row, host) ? [{ ...row, secrets }] : [],
    markUsed: vi.fn(),
  } satisfies VaultSource;
  const logins = new BotLogins(store, onePassword, () => [
    { id: "first", browserProfile: "shared" }, { id: "mate", browserProfile: "shared" }, { id: "alone" },
  ], [other]);
  calls.length = 0;
  return { store, onePassword, other, logins, calls, secrets, item, key };
}

describe("login vault sources", () => {
  it("keeps identical vault and item ids distinct, lists every source, and defers secret reads", async () => {
    const { logins, onePassword, other, calls, secrets } = await setup();
    const ids = ["1password:v1:i1:example.com", "test-vault:v1:i1:example.com"];
    const listed = logins.routes(() => true).list();
    expect(listed.map((login) => login.id)).toEqual(ids);
    expect(listed.map((login) => login.id.startsWith(onePassword.idPrefix))).toEqual([true, false]);
    expect(other.status()).toEqual(onePassword.status().connected ? { connected: true } : { connected: false });
    expect(logins.sitesFor("first").map((login) => login.username)).toEqual(["first@example.com", "second@example.com"]);
    expect((await logins.candidates("first", "accounts.example.com")).map((login) => login.id)).toEqual(ids);
    expect(other.fresh).toHaveBeenCalled();
    expect(secrets).not.toHaveBeenCalled();
    expect(calls).toEqual([]);
    expect(JSON.stringify(listed)).not.toContain("fake-first-password");
    expect(JSON.stringify(listed)).not.toContain("fake-second-password");
  });

  it("passes every browser mate and the page host to every source", async () => {
    const { logins } = await setup(["first"]);
    expect(logins.sitesFor("first")).toEqual([]);
    expect(await logins.candidates("first", "accounts.example.com")).toEqual([]);
    expect(logins.sitesFor("alone")).toEqual([]);
    expect(await logins.candidates("alone", "accounts.example.com")).toEqual([]);
    const shared = await setup(["first", "mate"]);
    expect(await shared.logins.candidates("first", "accounts.example.com")).toHaveLength(2);
    expect(await shared.logins.candidates("first", "accounts.example.com.evil.test")).toEqual([]);
  });

  it.each(["first@example.com", "second@example.com"])("fills %s through its owning source", async (username) => {
    const { logins, calls, secrets, item, key } = await setup();
    item.password = "fake-rotated-first-password";
    page = new FakeLoginPage("https://accounts.example.com/login", `${LOGIN_FORM}<input name="otp" autocomplete="one-time-code">`);
    const remembered: string[] = [];
    const now = 1_700_000_010_000;
    const outcome = await fillLogin({
      username, submit: false,
      candidates: (host) => logins.candidates("first", host),
      available: async () => logins.sitesFor("first"),
    }, {
      engine: (args) => page!.engine(args), insertText: (text) => page!.insertText(text), press: (pressed) => page!.press(pressed), click: (selector) => page!.click(selector),
      remember: (value) => { remembered.push(value); }, now: () => now,
    });
    const second = username === "second@example.com";
    const password = second ? "fake-second-password" : item.password;
    expect(outcome).toMatchObject({ ok: true, loginId: `${second ? "test-vault" : "1password"}:v1:i1:example.com` });
    expect(page.field("#email").value).toBe(username);
    expect(page.field("#password").value).toBe(password);
    expect(secrets).toHaveBeenCalledTimes(second ? 1 : 0);
    expect(calls).toEqual(second ? [] : ["items.getAll v1 i1"]);
    if (second) {
      expect(page.field("input[name=otp]").value).toBe(totpCode(key, now));
      expect(remembered).toContain(totpCode(key, now));
    }
    expect(remembered).toContain(password);
    expect(JSON.stringify(outcome)).not.toContain(password);
    expect(JSON.stringify(page.engineCalls)).not.toContain(password);
  });

  it("marks usage only in the source that owns the login id, including saved logins", async () => {
    const { logins, store, onePassword, other } = await setup();
    const local = store.create({ site: "example.com", hosts: ["example.com"], exactHost: false, username: "saved", password: "fake-saved-password", source: "settings", bots: "all" });
    const firstUsed = vi.spyOn(onePassword, "markUsed");
    const savedUsed = vi.spyOn(store, "markUsed");
    logins.markUsed("test-vault:v1:i1:example.com");
    expect(other.markUsed).toHaveBeenCalledExactlyOnceWith("test-vault:v1:i1:example.com");
    expect(firstUsed).not.toHaveBeenCalled();
    expect(savedUsed).not.toHaveBeenCalled();
    logins.markUsed("1password:v1:i1:example.com");
    expect(firstUsed).toHaveBeenCalledExactlyOnceWith("1password:v1:i1:example.com");
    expect(onePassword.list()[0]!.lastUsedAt).toBe(123);
    expect(savedUsed).not.toHaveBeenCalled();
    logins.markUsed(local.id);
    expect(savedUsed).toHaveBeenCalledExactlyOnceWith(local.id);
    expect(other.markUsed).toHaveBeenCalledTimes(1);
    expect(firstUsed).toHaveBeenCalledTimes(1);
  });
});
