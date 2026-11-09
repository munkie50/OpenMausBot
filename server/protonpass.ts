import { createHash } from "node:crypto";
import { chmodSync, lstatSync, mkdirSync, rmSync } from "node:fs";
import { join } from "node:path";

import { loginMatchesHost, loginSite, loginUsableBy, normalizeLoginHost, type LoginBots, type LoginPlace, type LoginSummary, type ProtonPassStatus, type ProtonPassVault } from "../shared/logins.ts";
import { augmentedPath } from "./env-path.ts";
import type { VaultStore } from "./vault-store.ts";
import type { FillCandidate, VaultSource } from "./login-vault-source.ts";
import { execCli } from "./procs.ts";

export interface ProtonPassItem { id: string; title: string }
export interface ProtonPassMetadata { username: string; urls: string[] }

export interface ProtonPassClient {
  info(): Promise<void>;
  vaults(): Promise<Array<{ id: string; title: string }>>;
  loginItems(vaultId: string): Promise<ProtonPassItem[]>;
  metadata(vaultId: string, itemId: string): Promise<ProtonPassMetadata>;
  password(vaultId: string, itemId: string): Promise<string>;
  totp(vaultId: string, itemId: string): Promise<string>;
  logout(): Promise<void>;
}

const MESSAGES = {
  auth: "Proton Pass did not accept the token: it may have expired, been revoked, or lost access. Paste a new personal access token.",
  missing: "Proton Pass CLI is not installed. Install the official pass-cli on this server, then connect again.",
  timeout: "Proton Pass took too long to answer. Try refreshing again.",
  output: "Proton Pass returned too much output. Reduce the token's vault access and refresh again.",
  unexpected: "Unexpected Proton Pass output. Check the installed pass-cli version and try again.",
  field: "This Proton Pass item does not have the requested field.",
  private: "Proton Pass could not open its private session folder. Check the app data directory's permissions.",
  changed: "The Proton Pass connection changed. Try again.",
  other: "Proton Pass could not be read. Check the connection and try again.",
} as const;

export const PROTON_PASS_NO_TOTP = "No TOTP for this login. Ask the person to enter the one-time code.";

export class ProtonPassError extends Error {
  readonly kind: keyof typeof MESSAGES;

  constructor(kind: keyof typeof MESSAGES) {
    super(MESSAGES[kind]);
    this.name = "ProtonPassError";
    this.kind = kind;
  }
}

export function protonPassProblem(error: unknown): string {
  return error instanceof ProtonPassError ? MESSAGES[error.kind] : MESSAGES.other;
}

function object(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new ProtonPassError("unexpected");
  return value as Record<string, unknown>;
}

function string(value: unknown): string {
  if (typeof value !== "string") throw new ProtonPassError("unexpected");
  return value;
}

function id(value: unknown): string {
  const text = string(value);
  if (!/^[\w=-]{1,256}$/u.test(text)) throw new ProtonPassError("unexpected");
  return text;
}

function array(value: unknown): unknown[] {
  if (!Array.isArray(value)) throw new ProtonPassError("unexpected");
  return value;
}

function json(text: string): unknown {
  try { return JSON.parse(text); } catch { throw new ProtonPassError("unexpected"); }
}

/** Reads one vault's logins from `item list --show-secrets`; keeps only the title, username and URLs. */
export function protonPassLogins(value: unknown, vaultId: string): Array<ProtonPassItem & ProtonPassMetadata> {
  const output = object(value);
  if (output.folders !== undefined) array(output.folders);
  return array(output.items).flatMap((value) => {
    const item = object(value);
    const itemId = id(item.id);
    if (id(item.share_id) !== vaultId) throw new ProtonPassError("unexpected");
    const state = item.state === undefined ? "active" : string(item.state).toLowerCase();
    if (state !== "active" && state !== "trashed") throw new ProtonPassError("unexpected");
    const content = object(item.content);
    const login = object(content.content).Login;
    if (state !== "active" || login === undefined) return [];
    const fields = object(login);
    const optional = (field: unknown) => field === undefined ? "" : string(field);
    return [{ id: itemId, title: string(content.title), username: optional(fields.username) || optional(fields.email),
      urls: fields.urls === undefined ? [] : array(fields.urls).map(string) }];
  });
}

export function protonPassPassword(value: unknown, vaultId: string, itemId: string): string {
  const item = object(object(value).item);
  if (id(item.id) !== itemId || id(item.share_id) !== vaultId) throw new ProtonPassError("unexpected");
  const content = object(object(item.content).content);
  const password = string(object(content.Login).password);
  if (!password) throw new ProtonPassError("field");
  return password;
}

function privateDirectory(path: string): void {
  mkdirSync(path, { recursive: true, mode: 0o700 });
  const info = lstatSync(path);
  if (!info.isDirectory() || info.isSymbolicLink()) throw new ProtonPassError("private");
  if (process.platform === "win32") return;
  if (typeof process.getuid === "function" && info.uid !== process.getuid()) throw new ProtonPassError("private");
  chmodSync(path, 0o700);
}

const LIST_MAX_BUFFER = 32 * 1_048_576;

export function cliProtonPassClient(options: { token: string; dataDir: string; cli?: string; timeoutMs?: number; maxBuffer?: number }): ProtonPassClient {
  return new CliProtonPassClient(options);
}

class CliProtonPassClient implements ProtonPassClient {
  private readonly root: string;
  private readonly sessionDir: string;
  private readonly options: { token: string; cli: string; timeoutMs: number; maxBuffer: number };
  private ready = false;
  private sessionVersion = 0;
  private authenticating: Promise<void> | null = null;
  private closed = false;
  private readonly listed = new Map<string, ProtonPassMetadata>();

  constructor(options: { token: string; dataDir: string; cli?: string; timeoutMs?: number; maxBuffer?: number }) {
    this.root = join(options.dataDir, "proton-pass");
    // Token-scoped sessions prevent a replacement token from reusing a previous token's broader access.
    this.sessionDir = join(this.root, createHash("sha256").update(options.token).digest("hex"));
    this.options = { token: options.token, cli: options.cli ?? "pass-cli", timeoutMs: options.timeoutMs ?? 15_000, maxBuffer: options.maxBuffer ?? 1_048_576 };
  }

  private async run(args: string[], maxBuffer = this.options.maxBuffer): Promise<string> {
    if (this.closed) throw new ProtonPassError("changed");
    try { privateDirectory(this.root); privateDirectory(this.sessionDir); }
    catch { throw new ProtonPassError("private"); }
    const env: NodeJS.ProcessEnv = {};
    for (const [key, value] of Object.entries(process.env)) {
      if (!/^PROTON_PASS_/iu.test(key) && !/^(?:PASS_LOG_LEVEL|PATH)$/iu.test(key)) env[key] = value;
    }
    Object.assign(env, {
      PATH: augmentedPath(), PASS_LOG_LEVEL: "off",
      PROTON_PASS_PERSONAL_ACCESS_TOKEN: this.options.token,
      PROTON_PASS_SESSION_DIR: this.sessionDir, PROTON_PASS_KEY_PROVIDER: "fs",
    });
    return new Promise((resolve, reject) => {
      try {
        execCli(this.options.cli, args, { env, shell: false, timeout: this.options.timeoutMs, maxBuffer }, (error, stdout, stderr) => {
          if (!error) { resolve(stdout); return; }
          const failure = error as NodeJS.ErrnoException & { killed?: boolean };
          // CLI diagnostics can contain secrets. Only fixed error messages may leave this adapter.
          const text = `${stderr ?? ""}\n${stdout}`;
          const kind = failure.code === "ENOENT" ? "missing"
            : failure.code === "ERR_CHILD_PROCESS_STDIO_MAXBUFFER" ? "output"
            : failure.killed ? "timeout"
            : /field does not exist:/iu.test(text) ? "field"
            : /not logged in|no (?:active |valid )?session|session.*(?:expir|invalid|not found)|invalid current session|unauthori[sz]ed|authenticat|invalid.*token|token.*(?:expir|revok|invalid)|\b40[13]\b/iu.test(text) ? "auth"
            : "other";
          reject(new ProtonPassError(kind));
        });
      } catch { reject(new ProtonPassError("other")); }
    });
  }

  private session(recoverVersion?: number): Promise<void> {
    if (this.authenticating) return this.authenticating;
    if (this.ready && (recoverVersion === undefined || recoverVersion !== this.sessionVersion)) return Promise.resolve();
    const run = (async () => {
      if (recoverVersion === undefined) {
        try { await this.run(["info"]); this.ready = true; return; }
        catch (error) { if (!(error instanceof ProtonPassError) || error.kind !== "auth") throw error; }
      }
      this.ready = false;
      await this.run(["logout", "--force"]);
      await this.run(["login"]);
      this.sessionVersion++;
      this.ready = true;
    })().finally(() => { this.authenticating = null; });
    this.authenticating = run;
    return run;
  }

  private async command(args: string[], maxBuffer?: number): Promise<string> {
    await this.session();
    const version = this.sessionVersion;
    try { return await this.run(args, maxBuffer); }
    catch (error) {
      if (!(error instanceof ProtonPassError) || error.kind !== "auth") throw error;
      await this.session(version);
      return this.run(args, maxBuffer);
    }
  }

  async info(): Promise<void> { await this.command(["info"]); }

  async vaults(): Promise<Array<{ id: string; title: string }>> {
    return array(object(json(await this.command(["vault", "list", "--output", "json"]))).vaults).map((value) => {
      const vault = object(value);
      return { id: id(vault.share_id), title: string(vault.name) };
    });
  }

  async loginItems(vaultId: string): Promise<ProtonPassItem[]> {
    // One list call per vault instead of one view per login: a few hundred logins otherwise take minutes.
    // The output includes passwords; only the title, username and URLs are kept, and nothing is logged.
    const logins = protonPassLogins(json(await this.command(["item", "list", "--share-id", id(vaultId), "--filter-type", "login",
      "--filter-state", "active", "--output", "json", "--show-secrets"], Math.max(this.options.maxBuffer, LIST_MAX_BUFFER))), vaultId);
    for (const key of this.listed.keys()) if (key.startsWith(`${vaultId}/`)) this.listed.delete(key);
    for (const login of logins) this.listed.set(`${vaultId}/${login.id}`, { username: login.username, urls: login.urls });
    return logins.map(({ id, title }) => ({ id, title }));
  }

  private uri(vaultId: string, itemId: string): string { return `pass://${id(vaultId)}/${id(itemId)}`; }

  private async field(vaultId: string, itemId: string, field: "username" | "email" | "urls"): Promise<string> {
    try {
      // pass-cli's field views print plain text even with --output json; URL fields are joined with ", ".
      return (await this.command(["item", "view", `${this.uri(vaultId, itemId)}/${field}`, "--output", "json"])).replace(/\r?\n$/u, "");
    } catch (error) {
      if (error instanceof ProtonPassError && error.kind === "field") return "";
      throw error;
    }
  }

  async metadata(vaultId: string, itemId: string): Promise<ProtonPassMetadata> {
    const listed = this.listed.get(`${vaultId}/${itemId}`);
    if (listed) return { username: listed.username, urls: [...listed.urls] };
    const username = await this.field(vaultId, itemId, "username") || await this.field(vaultId, itemId, "email");
    const urls = await this.field(vaultId, itemId, "urls");
    return { username, urls: urls ? urls.split(", ") : [] };
  }

  async password(vaultId: string, itemId: string): Promise<string> {
    return protonPassPassword(json(await this.command(["item", "view", this.uri(vaultId, itemId), "--output", "json"])), vaultId, itemId);
  }

  async totp(vaultId: string, itemId: string): Promise<string> {
    const output = object(json(await this.command(["item", "totp", `${this.uri(vaultId, itemId)}/totp`, "--output", "json"])));
    const code = string(output.totp);
    if (!/^\d{6,8}$/u.test(code)) throw new ProtonPassError("unexpected");
    return code;
  }

  async logout(): Promise<void> {
    try { await this.run(["logout", "--force"]); }
    finally {
      this.closed = true;
      this.listed.clear();
      this.ready = false;
      rmSync(this.sessionDir, { recursive: true, force: true });
    }
  }
}

interface Entry extends LoginPlace {
  id: string;
  vaultId: string;
  itemId: string;
  username: string;
}

const ID_PREFIX = "protonpass:";
const MAX_ITEMS = 500;
const METADATA_CONCURRENCY = 4;
const REFRESH_BUDGET_MS = 60_000;
const STALE_MS = 10 * 60_000;

export function isProtonPassLoginId(id: string): boolean { return id.startsWith(ID_PREFIX); }

export function createProtonPassLogins(store: VaultStore, dataDir: string): ProtonPassLogins {
  const source = new ProtonPassLogins({ token: () => store.protonPassToken(), saveToken: (token) => store.setProtonPassToken(token),
    grants: () => store.protonPassGrants(), connect: async (token) => cliProtonPassClient({ token, dataDir }) });
  if (store.protonPassToken()) void source.refresh();
  return source;
}

export class ProtonPassLogins implements VaultSource {
  readonly idPrefix = ID_PREFIX;
  private readonly options: {
    token: () => string | null; saveToken: (token: string | null) => void;
    connect: (token: string) => Promise<ProtonPassClient>;
    grants?: () => Record<string, LoginBots>; now?: () => number;
  };
  private client: { token: string; value: ProtonPassClient } | null = null;
  private entries: Entry[] = [];
  private vaults: Array<Omit<ProtonPassVault, "bots">> = [];
  private refreshedAt: number | null = null;
  private error: string | undefined;
  private queue: Promise<unknown> = Promise.resolve();
  private refreshing: Promise<ProtonPassStatus> | null = null;
  private generation = 0;
  private readonly lastUsed = new Map<string, number>();

  constructor(options: ProtonPassLogins["options"]) { this.options = options; }

  private serial<T>(run: () => Promise<T>): Promise<T> {
    const next = this.queue.then(run);
    this.queue = next.catch(() => {});
    return next;
  }

  private now(): number { return (this.options.now ?? Date.now)(); }
  private botsFor(vaultId: string): LoginBots { return this.options.grants?.()[vaultId] ?? "all"; }

  status(): ProtonPassStatus {
    return this.options.token() ? this.connected() : { connected: false };
  }

  private connected(): ProtonPassStatus {
    return { connected: true, items: this.vaults.reduce((sum, vault) => sum + vault.items, 0),
      vaults: this.vaults.map((vault) => ({ ...vault, bots: this.botsFor(vault.id) })), ...(this.error ? { error: this.error } : {}) };
  }

  hasVault(vaultId: string): boolean { return Boolean(this.options.token()) && this.vaults.some((vault) => vault.id === vaultId); }

  private async clientFor(token: string): Promise<ProtonPassClient> {
    return this.client?.token === token ? this.client.value : this.options.connect(token);
  }

  private async load(client: ProtonPassClient): Promise<{ entries: Entry[]; vaults: Array<Omit<ProtonPassVault, "bots">> }> {
    const deadline = Date.now() + REFRESH_BUDGET_MS;
    const check = () => { if (Date.now() >= deadline) throw new ProtonPassError("timeout"); };
    await client.info();
    check();
    const vaults = await client.vaults();
    check();
    const counted: Array<Omit<ProtonPassVault, "bots">> = [];
    const entries: Entry[] = [];
    let remaining = MAX_ITEMS;
    for (const vault of vaults) {
      check();
      const items = remaining ? (await client.loginItems(vault.id)).slice(0, remaining) : [];
      remaining -= items.length;
      let index = 0;
      let failed = false;
      const rows: Entry[][] = [];
      const workers = await Promise.allSettled(Array.from({ length: Math.min(METADATA_CONCURRENCY, items.length) }, async () => {
        while (!failed && index < items.length) {
          try {
            check();
            const at = index++;
            const item = items[at]!;
            const metadata = await client.metadata(vault.id, item.id);
            const sites = new Map<string, string[]>();
            for (const host of new Set(metadata.urls.flatMap((url) => normalizeLoginHost(url) ?? []))) {
              const site = loginSite(host);
              sites.set(site, [...(sites.get(site) ?? []), host]);
            }
            rows[at] = [...sites].map(([site, hosts]) => ({ id: `${ID_PREFIX}${vault.id}:${item.id}:${site}`,
              vaultId: vault.id, itemId: item.id, username: metadata.username, site, hosts, exactHost: false }));
          } catch (error) { failed = true; throw error; }
        }
      }));
      for (const worker of workers) if (worker.status === "rejected") throw worker.reason;
      check();
      counted.push({ ...vault, items: rows.filter((row) => row.length > 0).length });
      entries.push(...rows.flat());
    }
    return { entries: entries.sort((a, b) => a.site.localeCompare(b.site) || a.username.localeCompare(b.username)),
      vaults: counted.sort((a, b) => a.title.localeCompare(b.title)) };
  }

  private apply(data: Awaited<ReturnType<ProtonPassLogins["load"]>>): void {
    this.entries = data.entries;
    this.vaults = data.vaults;
    this.refreshedAt = this.now();
    this.error = undefined;
  }

  connectToken(token: string): Promise<ProtonPassStatus> {
    const generation = ++this.generation;
    return this.serial(async () => {
      const previous = this.client;
      let client: ProtonPassClient | null = null;
      try {
        client = await this.clientFor(token);
        const data = await this.load(client);
        if (generation !== this.generation) throw new ProtonPassError("changed");
        this.options.saveToken(token);
        this.client = { token, value: client };
        this.apply(data);
      } catch (error) {
        if (client && client !== previous?.value) await client.logout().catch(() => {});
        throw new ProtonPassError(error instanceof ProtonPassError ? error.kind : "other");
      }
      if (previous && previous.value !== client) await previous.value.logout().catch(() => {});
      return this.status();
    });
  }

  refresh(): Promise<ProtonPassStatus> {
    if (this.refreshing) return this.refreshing;
    const generation = this.generation;
    const run = this.serial(async () => {
      const token = this.options.token();
      if (!token || generation !== this.generation) return this.status();
      try {
        const client = await this.clientFor(token);
        this.client = { token, value: client };
        const data = await this.load(client);
        if (generation === this.generation && this.options.token() === token) this.apply(data);
      } catch (error) {
        if (generation === this.generation) {
          this.entries = []; this.vaults = []; this.refreshedAt = null;
          this.error = protonPassProblem(error);
        }
      }
      return this.status();
    }).finally(() => { if (this.refreshing === run) this.refreshing = null; });
    this.refreshing = run;
    return run;
  }

  async disconnect(): Promise<ProtonPassStatus> {
    const token = this.options.token();
    this.generation++;
    this.options.saveToken(null);
    this.entries = []; this.vaults = []; this.refreshedAt = null; this.error = undefined;
    this.lastUsed.clear();
    return this.serial(async () => {
      try {
        const client = this.client?.value ?? (token ? await this.options.connect(token) : null);
        this.client = null;
        await client?.logout();
      }
      catch (error) { return { connected: false, error: protonPassProblem(error) }; }
      return this.status();
    });
  }

  async fresh(): Promise<void> {
    if (this.options.token() && (this.refreshedAt === null || this.now() - this.refreshedAt > STALE_MS)) await this.refresh();
  }

  list(): LoginSummary[] {
    if (!this.options.token()) return [];
    // pass-cli lists omit login metadata. Read only username/URLs during discovery; TOTP stays unknown until fill.
    return this.entries.map((entry) => ({ id: entry.id, site: entry.site, hosts: [...entry.hosts], exactHost: false,
      username: entry.username, source: "protonpass", bots: this.botsFor(entry.vaultId), createdAt: 0,
      ...(this.lastUsed.has(entry.id) ? { lastUsedAt: this.lastUsed.get(entry.id)! } : {}) }));
  }

  private usable(botId: string | readonly string[]): Entry[] {
    return this.options.token() ? this.entries.filter((entry) => loginUsableBy({ bots: this.botsFor(entry.vaultId) }, botId)) : [];
  }

  sitesFor(botId: string | readonly string[]): Array<LoginPlace & { username: string }> {
    return this.usable(botId).map((entry) => ({ site: entry.site, hosts: [...entry.hosts], exactHost: false, username: entry.username }));
  }

  candidates(pageHost: string, botId: string | readonly string[]): FillCandidate[] {
    const token = this.options.token();
    const generation = this.generation;
    const read = <T>(entry: Entry, action: (client: ProtonPassClient) => Promise<T>) => this.serial(async () => {
      if (!token || token !== this.options.token() || generation !== this.generation
        || !loginUsableBy({ bots: this.botsFor(entry.vaultId) }, botId)) throw new ProtonPassError("changed");
      try {
        const result = await action(await this.clientFor(token));
        if (generation !== this.generation || token !== this.options.token()
          || !loginUsableBy({ bots: this.botsFor(entry.vaultId) }, botId)) throw new ProtonPassError("changed");
        return result;
      } catch (error) { throw new Error(protonPassProblem(error)); }
    });
    return this.usable(botId).filter((entry) => loginMatchesHost(entry, pageHost)).map((entry) => ({
      id: entry.id, site: entry.site, hosts: [...entry.hosts], exactHost: false, username: entry.username, source: "protonpass",
      secrets: () => read(entry, async (client) => {
        const password = await client.password(entry.vaultId, entry.itemId);
        if (!password) throw new ProtonPassError("field");
        return { password, totp: null };
      }),
      oneTimeCode: async () => {
        try {
          return await read(entry, async (client) => {
            const code = await client.totp(entry.vaultId, entry.itemId);
            if (!/^\d{6,8}$/u.test(code)) throw new ProtonPassError("unexpected");
            return code;
          });
        } catch { throw new Error(PROTON_PASS_NO_TOTP); }
      },
    }));
  }

  markUsed(loginId: string): void {
    if (this.entries.some((entry) => entry.id === loginId)) this.lastUsed.set(loginId, this.now());
  }
}
