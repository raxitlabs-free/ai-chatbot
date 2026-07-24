import type { UserType } from "@/app/(auth)/auth";
import { entitlementsByUserType } from "@/lib/ai/entitlements";

export type ToolName =
  | "getWeather"
  | "createDocument"
  | "editDocument"
  | "updateDocument"
  | "requestSuggestions";

export const ALL_TOOL_NAMES: ToolName[] = [
  "getWeather",
  "createDocument",
  "editDocument",
  "updateDocument",
  "requestSuggestions",
];

export type ToolAuthInput = {
  userId: string | null | undefined;
  userType: UserType | undefined;
  toolName: ToolName;
};

export type ToolAuthDecision = {
  effect: "permit" | "deny";
  reason: "allowed" | "unauthenticated" | "unknown-user-type" | "not-in-policy";
};

/**
 * Reference monitor for tool dispatch.
 *
 * Sits between the LLM's tool selection and every tool `execute()` handler so
 * that no tool runs without an explicit authorization decision. It is
 * deny-by-default: a call is permitted only when the caller is authenticated
 * AND the tool is explicitly present in that user type's allow-list
 * (`entitlementsByUserType[userType].allowedTools`). Every other case — an
 * unauthenticated caller, an unknown user type, or a tool that is not on the
 * allow-list (for example one an injected prompt tried to reach) — is denied.
 *
 * The entitlements table is read at call time, so tightening the policy in
 * `entitlements.ts` takes effect without a restart; no decision is cached at
 * module scope.
 */
export const toolPolicy = {
  /**
   * Audit-logged authorization decision. Call this at the point a tool is
   * actually dispatched (as the first statement of each tool's `execute()`),
   * so every dispatch attempt produces one structured record.
   */
  authorize(input: ToolAuthInput): ToolAuthDecision {
    const decision = decide(input);
    logToolAuthDecision(input, decision);
    return decision;
  },

  /**
   * Side-effect-free predicate. Use when a boolean is enough — for example when
   * building the active tool surface for a request — so it is safe to call for
   * every tool without emitting an audit record per candidate.
   */
  isAuthorized(input: ToolAuthInput): boolean {
    return decide(input).effect === "permit";
  },
};

function decide(input: ToolAuthInput): ToolAuthDecision {
  const { userId, userType, toolName } = input;

  const entitlements = userType ? entitlementsByUserType[userType] : undefined;

  if (!userId) {
    return { effect: "deny", reason: "unauthenticated" };
  }
  if (!entitlements) {
    return { effect: "deny", reason: "unknown-user-type" };
  }
  if (entitlements.allowedTools.has(toolName)) {
    return { effect: "permit", reason: "allowed" };
  }
  return { effect: "deny", reason: "not-in-policy" };
}

function logToolAuthDecision(input: ToolAuthInput, decision: ToolAuthDecision) {
  // Structured, queryable audit record for every dispatch attempt. Durable
  // persistence to a ToolAuthLog store is tracked separately (spec RAI-ACC-01).
  console.info({
    event: "tool_authorization",
    userId: input.userId ?? null,
    userType: input.userType ?? null,
    toolName: input.toolName,
    decision: decision.effect === "permit" ? "APPROVED" : "DENIED",
    reason: decision.reason,
    timestamp: new Date().toISOString(),
  });
}
