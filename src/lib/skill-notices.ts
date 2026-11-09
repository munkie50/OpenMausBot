import type { Message } from "@/state/store";

/**
 * A skill card that no longer needs the person: added, updated, declined or expired. With "Hide skill notices" on,
 * these drop out of the transcript; a skill request still waiting for an answer always stays, or it could never be
 * approved.
 */
export function isSettledSkillNotice(message: Message): boolean {
  const card = message.card;
  if (!card?.skillRequest) return false;
  return Boolean(card.answered || card.dismissed || card.expired);
}

export function withoutSkillNotices(messages: Message[], hide: boolean): Message[] {
  return hide ? messages.filter((message) => !isSettledSkillNotice(message)) : messages;
}
