import { describe, expect, it } from "vitest";

import type { Message } from "@/state/store";
import { isSettledSkillNotice, withoutSkillNotices } from "./skill-notices";

const skillRequest = { version: 1, requestId: "s", botId: "b", threadId: "t", stagedId: "x", action: "create", name: "file-expense", gist: "", warnings: [], createdAt: 1 };
const msg = (id: string, card?: Record<string, unknown>): Message =>
  ({ id, role: "bot", kind: card ? "card" : "text", text: "", ts: 1, ...(card ? { card } : {}) }) as unknown as Message;

describe("skill notices", () => {
  const applied = msg("applied", { requestId: "s", tool: "stage_skill", skillRequest, answered: "allow", autoApplied: true });
  const declined = msg("declined", { requestId: "s2", tool: "stage_skill", skillRequest, answered: "deny" });
  const expired = msg("expired", { requestId: "s3", tool: "stage_skill", skillRequest, expired: true });
  const pending = msg("pending", { requestId: "s4", tool: "stage_skill", skillRequest });
  const routine = msg("routine", { requestId: "r", tool: "schedule_routine", answered: "allow" });
  const text = msg("text");

  it("treats only settled skill cards as notices", () => {
    expect(isSettledSkillNotice(applied)).toBe(true);
    expect(isSettledSkillNotice(declined)).toBe(true);
    expect(isSettledSkillNotice(expired)).toBe(true);
    expect(isSettledSkillNotice(pending)).toBe(false);
    expect(isSettledSkillNotice(routine)).toBe(false);
    expect(isSettledSkillNotice(text)).toBe(false);
  });

  it("drops them only when hiding is on, and keeps a pending request", () => {
    const all = [text, applied, pending, routine, declined];
    expect(withoutSkillNotices(all, false)).toBe(all);
    expect(withoutSkillNotices(all, true).map((m) => m.id)).toEqual(["text", "pending", "routine"]);
  });
});
