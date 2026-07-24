import assert from "node:assert/strict";
import { test } from "node:test";
import { type ToolName, toolPolicy } from "@/lib/ai/tools/authorize";

// A tool name that is not registered in any user type's allow-list — stands in
// for a tool an injected/hijacked prompt might try to reach.
const UNKNOWN_TOOL = "exfiltrateSecrets" as unknown as ToolName;

test("permits an authenticated user calling an allow-listed tool", () => {
  const decision = toolPolicy.authorize({
    userId: "user-1",
    userType: "regular",
    toolName: "createDocument",
  });
  assert.equal(decision.effect, "permit");
  assert.equal(decision.reason, "allowed");
});

test("denies a caller with no user id (unauthenticated)", () => {
  const decision = toolPolicy.authorize({
    userId: undefined,
    userType: "regular",
    toolName: "createDocument",
  });
  assert.equal(decision.effect, "deny");
  assert.equal(decision.reason, "unauthenticated");
});

test("denies a tool that is not on the policy allow-list (deny-by-default)", () => {
  const decision = toolPolicy.authorize({
    userId: "user-1",
    userType: "regular",
    toolName: UNKNOWN_TOOL,
  });
  assert.equal(decision.effect, "deny");
  assert.equal(decision.reason, "not-in-policy");
});

test("denies an unknown user type (missing policy entry)", () => {
  const decision = toolPolicy.authorize({
    userId: "user-1",
    userType: "superadmin" as unknown as "regular",
    toolName: "createDocument",
  });
  assert.equal(decision.effect, "deny");
  assert.equal(decision.reason, "unknown-user-type");
});

test("isAuthorized mirrors authorize as a side-effect-free boolean", () => {
  assert.equal(
    toolPolicy.isAuthorized({
      userId: "user-1",
      userType: "guest",
      toolName: "getWeather",
    }),
    true
  );
  assert.equal(
    toolPolicy.isAuthorized({
      userId: "user-1",
      userType: "guest",
      toolName: UNKNOWN_TOOL,
    }),
    false
  );
  assert.equal(
    toolPolicy.isAuthorized({
      userId: undefined,
      userType: "guest",
      toolName: "getWeather",
    }),
    false
  );
});
