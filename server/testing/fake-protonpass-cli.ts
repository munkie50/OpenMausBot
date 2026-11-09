#!/usr/bin/env node
import { appendFileSync, existsSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const root = process.env.FAKE_PROTONPASS_HOME!;
const session = process.env.PROTON_PASS_SESSION_DIR!;
const args = process.argv.slice(2);
const token = process.env.PROTON_PASS_PERSONAL_ACCESS_TOKEN ?? "";
const mode = existsSync(join(root, "mode")) ? readFileSync(join(root, "mode"), "utf8") : "";
const sessionFile = join(session, "fake-session");
const password = "fake-proton-password";
const code = "029384";
appendFileSync(join(root, "calls.jsonl"), JSON.stringify({ args, session, keyProvider: process.env.PROTON_PASS_KEY_PROVIDER,
  tokenMatches: token === "pst_fake-token::FAKE", logLevel: process.env.PASS_LOG_LEVEL,
  protonEnvNames: Object.keys(process.env).filter((key) => /^PROTON_PASS_/iu.test(key)).sort() }) + "\n");

function fail(text: string): never { process.stderr.write(text); process.exit(1); }
function json(value: unknown): void { process.stdout.write(JSON.stringify(value)); }

if (!token || process.env.PROTON_PASS_KEY_PROVIDER !== "fs" || !session) fail("Missing private environment");
if (mode === "timeout") setInterval(() => {}, 1000);
else if (mode === "overflow") process.stdout.write("x".repeat(2_000_000));
else if (args[0] === "logout") {
  rmSync(sessionFile, { force: true });
} else if (args[0] === "login") {
  if (mode === "revoked") fail(`Unauthorized: ${token} ${password} ${code}`);
  writeFileSync(sessionFile, "signed-in");
} else if (!existsSync(sessionFile)) fail("Not logged in: no session");
else if (mode === "diagnostics") fail(`Network failure: ${token} ${password} ${code}`);
else if (args[0] === "info") process.stdout.write("Personal access token: fake\n");
else if (args[0] === "vault") {
  if (existsSync(join(root, "expire-once"))) {
    rmSync(join(root, "expire-once"));
    fail(`Session expired: ${token}`);
  }
  if (mode === "always-expired") fail("Session expired");
  if (mode === "bad-json") process.stdout.write(`{malformed ${token}`);
  else if (mode === "bad-shape") json({ vaults: { secret: token } });
  else if (mode === "empty") json({ vaults: [] });
  else json({ vaults: [{ share_id: "v1", vault_id: "vault1", name: "Bots" }, { share_id: "v2", vault_id: "vault2", name: "Finance" }], future: true });
} else if (args[0] === "item" && args[1] === "list") {
  const vaultId = args[args.indexOf("--share-id") + 1];
  if (mode === "revoked-vault") fail(`Forbidden 403: ${token}`);
  if (args.includes("--show-secrets")) json({ items: [{ id: "i1", share_id: vaultId, vault_id: "vault", state: "Active", future: true,
    content: { title: "Fixture login", note: "", content: { Login: { email: "", username: vaultId === "v1" ? "alice@example.com" : "treasurer", password,
      urls: vaultId === "v1" ? ["https://accounts.example.com/login", "https://login.example.org"] : ["https://bank.example.net"], totp_uri: "fake-secret-not-for-discovery", passkeys: [] } } } }], folders: [], future: true });
  else json({ items: [{ id: "i1", share_id: vaultId, title: "Fixture login", item_type: "login", state: "Active", future: true }], folders: [], future: true });
} else if (args[0] === "item" && args[1] === "view") {
  const uri = /^pass:\/\/([^/]+)\/([^/]+)(?:\/(.+))?$/u.exec(args[2] ?? "");
  if (!uri) fail("Unknown URI");
  const [, vaultId, itemId, field] = uri;
  if (field === "username") {
    if (mode === "email-only") fail("Field does not exist: username");
    process.stdout.write(`${vaultId === "v1" ? "alice@example.com" : "treasurer"}\n`);
  } else if (field === "email") process.stdout.write("email-user@example.com\n");
  else if (field === "urls") process.stdout.write(`${vaultId === "v1" ? "https://accounts.example.com/login, https://login.example.org" : "https://bank.example.net"}\n`);
  else if (field) fail("Unexpected field read");
  else if (mode === "bad-view") json({ item: { id: itemId, share_id: vaultId, content: { content: { Login: { password: { secret: password } } } } } });
  else json({ item: { id: itemId, share_id: vaultId, content: { title: "Example", content: { Login: { username: "alice@example.com", password, totp_uri: "fake-secret-not-for-discovery" } } } }, attachments: [], future: true });
} else if (args[0] === "item" && args[1] === "totp") {
  if (mode === "no-totp") fail(`No TOTP fields found in this item: ${token} ${password}`);
  json({ totp: mode === "empty-totp" ? "" : mode === "bad-totp" ? { secret: code } : code });
} else fail("Unexpected command");
