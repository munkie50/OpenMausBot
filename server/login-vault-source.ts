import type { LoginPlace, LoginSource, LoginSummary } from "../shared/logins.ts";
import type { TotpKey } from "./totp.ts";

/** Its secrets are read only when it is about to be filled. */
export interface FillCandidate extends LoginPlace {
  id: string;
  username: string;
  source: LoginSource;
  secrets(): Promise<{ password: string; totp: TotpKey | null }>;
}

export interface VaultStatus {
  connected: boolean;
  error?: string;
}

export interface VaultSource {
  readonly idPrefix: `${string}:`;
  status(): VaultStatus;
  refresh(): Promise<VaultStatus>;
  fresh(): Promise<void>;
  list(): LoginSummary[];
  sitesFor(botId: string | readonly string[]): Array<LoginPlace & { username: string }>;
  candidates(pageHost: string, botId: string | readonly string[]): FillCandidate[];
  markUsed(id: string): void;
}
