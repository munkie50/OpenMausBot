import { mkdtempSync } from "node:fs";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";

import { BotLogins } from "../bot-logins.ts";
import { json, readBody } from "../harness/http.ts";
import { LoginStore } from "../login-store.ts";
import { OnePasswordLogins } from "../onepassword.ts";
import { ProtonPassLogins } from "../protonpass.ts";
import { requiredScope, type RequestAuth } from "../request-auth.ts";
import { removeTempDir } from "../testing/cleanup.ts";
import { fakeProtonPassClient } from "../testing/fake-protonpass.ts";
import { createLoginRoutes } from "./logins.ts";
import { dispatchRoutes } from "./table.ts";

const TOKEN = "pst_fake-token::FAKE";
const dirs: string[] = [];
const servers: Server[] = [];
afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => new Promise((resolve) => server.close(resolve))));
  for (const dir of dirs.splice(0)) await removeTempDir(dir);
});

async function serve() {
  const dir = mkdtempSync(join(tmpdir(), "omb-protonpass-routes-"));
  dirs.push(dir);
  const store = new LoginStore({ dataDir: dir });
  const client = fakeProtonPassClient();
  const connect = vi.fn(async (token: string) => {
    if (token !== TOKEN) throw new Error(`rejected ${token}`);
    return client;
  });
  const source = new ProtonPassLogins({ token: () => store.protonPassToken(), saveToken: (token) => store.setProtonPassToken(token),
    grants: () => store.protonPassGrants(), connect });
  const onePassword = new OnePasswordLogins({ token: () => null, connect: async () => { throw new Error("not configured"); } });
  const logins = new BotLogins(store, onePassword, () => [], [source]);
  const routes = [createLoginRoutes(logins.routes((id) => ["pepper", "quill"].includes(id), source))];
  const server = createServer(async (req, res) => {
    const url = new URL(req.url ?? "/", "http://localhost");
    const auth = { kind: "loopback", scopes: ["admin"] } as unknown as RequestAuth;
    if (!await dispatchRoutes(routes, { req, res, url, path: url.pathname, method: req.method ?? "GET", auth, json, readBody })) json(res, 404, {});
  });
  servers.push(server);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  const answers: string[] = [];
  const call = async (method: string, path: string, body?: unknown, type = "application/json") => {
    const response = await fetch(base + path, { method, headers: { "content-type": type }, ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
    const text = await response.text();
    answers.push(text);
    return { status: response.status, body: JSON.parse(text), cache: response.headers.get("cache-control") };
  };
  return { call, answers, store, source, client, connect, logins };
}

describe("Proton Pass login routes", () => {
  it("keeps status, token changes and vault grants admin-only", () => {
    for (const method of ["GET", "POST", "DELETE"]) expect(requiredScope(method, "/api/logins/protonpass")).toBe("admin");
    expect(requiredScope("POST", "/api/logins/protonpass/refresh")).toBe("admin");
    expect(requiredScope("PATCH", "/api/logins/protonpass/vaults/v1")).toBe("admin");
  });

  it("connects with a checked write-only token, lists metadata, refreshes and disconnects", async () => {
    const { call, answers, store, client } = await serve();
    expect(await call("GET", "/api/logins/protonpass")).toMatchObject({ status: 200, cache: "no-store", body: { protonPass: { connected: false } } });
    expect(await call("POST", "/api/logins/protonpass", { token: TOKEN })).toMatchObject({ status: 200,
      body: { protonPass: { connected: true, items: 2, vaults: [{ id: "v1", title: "Bots", items: 1, bots: "all" }, { id: "v2", title: "Finance", items: 1, bots: "all" }] } } });
    expect(store.protonPassToken()).toBe(TOKEN);
    const listed = await call("GET", "/api/logins");
    expect(listed.body.protonPass.connected).toBe(true);
    expect(listed.body.onePassword).toEqual({ connected: false });
    expect(listed.body.logins).toHaveLength(3);
    expect(listed.body.logins.every((row: Record<string, unknown>) => row.source === "protonpass" && !("hasTotp" in row))).toBe(true);
    const id = listed.body.logins[0].id as string;
    for (const method of ["PATCH", "DELETE"]) {
      expect(await call(method, `/api/logins/${encodeURIComponent(id)}`, method === "PATCH" ? { password: "fake-new-password" } : undefined))
        .toMatchObject({ status: 409, body: { error: "This login is in Proton Pass. Change or remove it there." } });
    }
    expect((await call("POST", "/api/logins/protonpass/refresh", {})).body.protonPass.items).toBe(2);
    expect(await call("DELETE", "/api/logins/protonpass")).toMatchObject({ status: 200, body: { protonPass: { connected: false } } });
    expect(store.protonPassToken()).toBeNull();
    expect((await call("GET", "/api/logins")).body.logins).toEqual([]);
    expect(client.logout).toHaveBeenCalledTimes(1);
    expect(client.password).not.toHaveBeenCalled(); expect(client.totp).not.toHaveBeenCalled();
    for (const secret of [TOKEN, "fake-proton-password", "029384"]) expect(answers.join("\n")).not.toContain(secret);
  });

  it("validates tokens without echoing bad credentials or accepting cross-origin forms", async () => {
    const { call, store, connect, answers } = await serve();
    for (const token of ["", "ops_fake-token", "pst_bad token", "pst_" + "x".repeat(8193), null, 123]) {
      expect((await call("POST", "/api/logins/protonpass", { token })).status).toBe(400);
    }
    expect(connect).not.toHaveBeenCalled();
    expect((await call("POST", "/api/logins/protonpass", { token: "pst_rejected-fake-secret" })).body.error).toContain("could not be read");
    expect(store.protonPassToken()).toBeNull();
    expect(answers.join("\n")).not.toContain("pst_rejected-fake-secret");
    expect((await call("POST", "/api/logins/protonpass", { token: TOKEN }, "text/plain")).status).toBe(415);
    expect((await call("PATCH", "/api/logins/protonpass", {})).status).toBe(405);
    expect((await call("GET", "/api/logins/protonpass/unknown")).status).toBe(405);
  });

  it("persists vault grants separately from 1Password and checks visible vaults and bot ids", async () => {
    const { call, store, logins } = await serve();
    await call("POST", "/api/logins/protonpass", { token: TOKEN });
    expect(await call("PATCH", "/api/logins/protonpass/vaults/v1", { bots: ["quill", "quill"] }))
      .toMatchObject({ status: 200, body: { protonPass: { vaults: [{ id: "v1", bots: ["quill"] }, { id: "v2", bots: "all" }] } } });
    expect(store.protonPassGrants()).toEqual({ v1: ["quill"] });
    expect(store.onePasswordGrants()).toEqual({});
    expect(await logins.candidates("pepper", "accounts.example.com")).toEqual([]);
    expect(await logins.candidates("quill", "accounts.example.com")).toHaveLength(1);
    for (const bots of [undefined, ["missing"], "quill", null]) {
      expect((await call("PATCH", "/api/logins/protonpass/vaults/v1", { bots })).status).toBe(400);
    }
    expect((await call("PATCH", "/api/logins/protonpass/vaults/missing", { bots: "all" })).status).toBe(404);
    await call("DELETE", "/api/logins/protonpass");
    await call("POST", "/api/logins/protonpass", { token: TOKEN });
    expect(store.protonPassGrants()).toEqual({ v1: ["quill"] });
    await call("PATCH", "/api/logins/protonpass/vaults/v1", { bots: "all" });
    expect(store.protonPassGrants()).toEqual({});
  });
});
