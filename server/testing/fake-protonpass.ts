import { vi } from "vitest";

import type { ProtonPassClient } from "../protonpass.ts";

export function fakeProtonPassClient() {
  return {
    info: vi.fn(async () => {}),
    vaults: vi.fn(async () => [{ id: "v1", title: "Bots" }, { id: "v2", title: "Finance" }]),
    loginItems: vi.fn(async (_vaultId: string) => [{ id: "i1", title: "Example" }]),
    metadata: vi.fn(async (vaultId: string, _itemId: string) => ({ username: vaultId === "v1" ? "alice@example.com" : "treasurer",
      urls: vaultId === "v1" ? ["https://accounts.example.com", "https://login.example.org"] : ["https://bank.example.net"] })),
    password: vi.fn(async (_vaultId: string, _itemId: string) => "fake-proton-password"),
    totp: vi.fn(async (_vaultId: string, _itemId: string) => "029384"),
    logout: vi.fn(async () => {}),
  } satisfies ProtonPassClient;
}
