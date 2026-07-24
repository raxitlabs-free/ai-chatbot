import type { UserType } from "@/app/(auth)/auth";
import type { ToolName } from "@/lib/ai/tools/authorize";

type Entitlements = {
  maxMessagesPerHour: number;
  // Allow-list of tools this user type may dispatch. The tool-dispatch
  // reference monitor (`lib/ai/tools/authorize.ts`) denies anything not
  // listed here, so this set is the single source of truth for tool ACLs.
  // Tighten a user type (for example drop the document-mutation tools for
  // guests) by removing entries here — no other code change is required.
  allowedTools: Set<ToolName>;
};

export const entitlementsByUserType: Record<UserType, Entitlements> = {
  guest: {
    maxMessagesPerHour: 10,
    allowedTools: new Set<ToolName>([
      "getWeather",
      "createDocument",
      "editDocument",
      "updateDocument",
      "requestSuggestions",
    ]),
  },
  regular: {
    maxMessagesPerHour: 10,
    allowedTools: new Set<ToolName>([
      "getWeather",
      "createDocument",
      "editDocument",
      "updateDocument",
      "requestSuggestions",
    ]),
  },
};
