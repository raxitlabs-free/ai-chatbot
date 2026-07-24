# Remediation Spec: LLM I/O Audit Logging, Non-Repudiation, and Cost Governance

**How to use:** Pass this spec to your coding agent with the instruction: "Implement all sections in order. Each section is independent. For each section, read the current file state at the `Location`, implement the `Change`, verify against the `Acceptance` criteria, then move to the next section. Avoid the patterns listed under `Avoid`. After all sections are complete, run the test suite and verify the app behavior in the chat interface."

---

## RAI-ACC-08 — Structured LLM I/O Audit Logging with Output Provenance (Phase 1 critical)

### What & why
Structured logging of all LLM inference requests, responses, token counts, and output provenance enables forensic reconstruction of model-to-tool-invocation causality. Currently `streamText()` calls in chat/route.ts:207 and request-suggestions.ts:65 generate model outputs that are saved to the database (chat/route.ts:283–291) without capturing prompts, token counts, model version, timestamps, or which data sources informed each output. This blocks T-0009 investigative capability for tool abuse scenarios: "which model output led to this tool invocation?" Without structured logs, the causality chain cannot be reconstructed. PII redaction prevents secondary disclosure while maintaining forensic evidence.

### Where
- Main chat endpoint: app/(chat)/api/chat/route.ts:207 (streamText call), 283–291 (message persistence)
- Tool invocation point: lib/ai/tools/request-suggestions.ts:65 (streamText call for suggestions)
- Message schema: lib/db/schema.ts:42–51 (Message_v2 table lacking provenance fields)
- Authorization audit: lib/ai/tools/authorize.ts:87 (console.info audit log with no structured sink)

### Change

1. **Extend database schema** (lib/db/schema.ts): Add a `provenance` JSON column to the `message` table to capture model metadata per message.
   ```
   Example structure (do not paste; use this as a guide for what to store):
   {
     "modelId": "moonshotai/kimi-k2.5",
     "modelVersion": "2025-07",
     "tokenCountInput": 512,
     "tokenCountOutput": 256,
     "timestamp": "2026-07-24T14:32:10.123Z",
     "latencyMs": 2340,
     "userId": "user-uuid"
   }
   ```
   Add `provenance` as a nullable json column to the message table.

2. **Integrate Application Insights logging** (app/(chat)/api/chat/route.ts): Before calling `createUIMessageStreamResponse` at line 308, wrap the stream in a logging layer that:
   - Captures the system prompt and user input messages before LLM invocation
   - Extracts token counts from the streamText result metadata (the Vercel AI SDK exposes `usage` or similar on completion)
   - Records structured event `{ event: "llm_io_audit", modelId, promptTokens, completionTokens, timestamp }` to Application Insights using `@vercel/otel` or Console structured logging (which will be ingested by Application Insights in production)
   - Applies a regex-based PII mask to redact emails, phone numbers, SSN patterns from logged prompts before storage

3. **Extend message save to include provenance** (lib/db/queries.ts or inline in route.ts `onFinish` callback at line 258): When saving finished messages (lines 268–280, 283–291), append the provenance object extracted in step 2 to the `parts` JSON and include it in the database insert. Do NOT store prompts directly in provenance (due to PII risk), but store the hash of the system prompt and token counts.

4. **Apply output moderation guard** (app/(chat)/api/chat/route.ts before line 207): Add a pre-call check that queries config for moderation enablement (read from `process.env.ENABLE_MODERATION` at call time inside the execute function, not at import). If enabled, use the OpenAI Moderation API or a similar guardrail (frame as: "if moderation is enabled at runtime, validate the response before persisting"). Skip this if `ENABLE_MODERATION` is not set.

### Acceptance
- LLM I/O logs capture 100% of chat requests with model ID, token counts, and timestamp ≤500ms ingestion latency.
- Provenance metadata appears in the message table's new provenance column for all assistant messages post-deployment.
- PII redaction accuracy ≥99.5%: spot-check 10 logs for correct email/phone masking with <0.5% false positives.
- Forensic query: verify that a sample message's provenance tuple {modelId, tokens, timestamp} can be retrieved and matches the streamText call that generated it.
- No impact on chat response time (moderation check adds <100ms latency if enabled, and is optional).

### Avoid
- Do NOT store full prompts unredacted in the provenance column (use a hash instead).
- Do NOT add import-time side effects for Application Insights initialization (initialize inside functions or at call time).
- Do NOT create a separate logging table; use the existing Message_v2 table's new provenance column.
- Do NOT implement full PII detection with a third-party ML model in Phase 1; use regex patterns (email, phone, SSN) for fast blocking.

### Compliance
EU AI Act Article 50 (transparency): Provenance metadata satisfies regulatory audits demonstrating traceability of model generation. GDPR Article 13 (transparency): Structured logs enable data subjects to understand model decisions affecting their data.

---

## RAI-ACC-11 — Non-Repudiation via Digital Timestamping and Principal Binding (Phase 1 foundation)

### What & why
Tool invocations (createDocument, editDocument, updateDocument, requestSuggestions at lib/ai/tools/{tool}.ts) currently perform authorization via `toolPolicy.authorize()` at lib/ai/tools/authorize.ts:51, but authorization decisions are logged only to console.info (line 87) without cryptographic signing or append-only storage. This means a malicious actor could modify the authorization log or claim they did not invoke a tool. Phase 1 establishes (userId, toolName, timestamp, decision) immutable binding; Phase 2 will add RSA/ECDSA signatures. For now, use NTP-synchronized system clock and immutable audit log to establish the causality chain.

### Where
- Authorization dispatch: lib/ai/tools/authorize.ts:51 (authorize function), 84–96 (logToolAuthDecision)
- Tool invocations: lib/ai/tools/create-document.ts:35, edit-document.ts:33, update-document.ts:31, request-suggestions.ts:33, get-weather.ts:51 (each calls toolPolicy.authorize at start of execute)
- Audit storage: Currently console.info; needs move to durable store (Redis via `process.env.REDIS_URL`)

### Change

1. **Extend authorization audit to Redis** (lib/ai/tools/authorize.ts): Refactor `logToolAuthDecision` function to:
   - Read `process.env.REDIS_URL` at call time (inside the function, not at import) and connect to Redis if available.
   - Generate an immutable audit record: `{ sequence: <monotonic-counter>, userId, toolName, decision, timestamp_ISO8601, requestId }` where requestId is a unique trace ID (passed as context; use a header or context variable).
   - Append the record to a Redis list key `tool_auth_audit:<date>` (e.g., `tool_auth_audit:2026-07-24`), ensuring order is preserved (Redis RPUSH maintains sequence).
   - If Redis is unavailable, fall back to console.info (non-blocking).
   - Sequence counter prevents reordering attacks: each day's list has monotonically increasing sequence numbers.

2. **Bind principal identity in authorization context** (lib/ai/tools/authorize.ts:51): Enhance the `ToolAuthDecision` return type to include:
   ```
   { effect: "permit" | "deny", reason: "...", principalId: string, timestamp: string }
   ```
   Populate `principalId` from `input.userId` and `timestamp` from `new Date().toISOString()` (NTP-synchronized clock).

3. **Pass request ID through tool context** (app/(chat)/api/chat/route.ts:207): Generate a unique requestId at the start of the POST function (e.g., using `generateUUID()` already imported at line 45) and thread it through the tool invocation chain:
   - Store it in the streamText context or as a variable available to tool execute functions.
   - Each tool's execute function passes the requestId to the authorization call for audit correlation.

4. **Log each tool invocation completion** (each tool file): After a tool's execute function completes successfully, log a second audit event `{ event: "tool_execution_completed", toolName, userId, timestamp, requestId, outcome }` to Redis via the same audit function (this is Phase 1B; for Phase 1, log authorization decision only).

### Acceptance
- 100% of tool authorization decisions logged to Redis with (userId, toolName, timestamp, decision, sequence) tuples.
- Redis audit list for each day is append-only: sequence numbers are monotonically increasing, prevent reordering.
- Query capability: `LRANGE tool_auth_audit:<date> 0 -1` returns full ordered audit trail for the day.
- Forensic reconstruction: Given a tool invocation at timestamp T, query Redis to confirm the authorization decision was "permit" at that time (timestamp ≤ T, toolName matches, userId matches).
- Zero authorization log gaps: compare authorization counts from console (old) to Redis (new) for one hour; counts match within 1%.
- No additional latency: authorization with Redis ≤10ms per call; falls back to console.info if Redis unavailable.

### Avoid
- Do NOT use Redis as the system-of-record for the message audit; that is RAI-ACC-01 (not this spec). Use Redis only for the authorization decision trail.
- Do NOT block tool execution if Redis is down; log to console.info as fallback.
- Do NOT implement cryptographic signing in Phase 1 (defer to Phase 2).
- Do NOT rotate Redis keys manually; use TTL-based expiration or implement a cleanup job separately (not in this spec).

### Compliance
OWASP Agentic AI T3 (Identity & Privilege Abuse): Cryptographic non-repudiation established via (user, tool, timestamp) binding. Phase 1 establishes causality; Phase 2 adds tamper-proof signing.

---

## RAI-SUS-02 — Per-Request Token Budgets and Cost Caps (Denial-of-Wallet Prevention)

### What & why
The chat endpoint at app/(chat)/api/chat/route.ts:207 calls `streamText()` with no AbortController, no token limit, and no per-request cost cap. A stuck connection, malicious prompt, or model output explosion can generate unbounded API costs without user or operator awareness. The exported `maxDuration=60` (line 49) is a general timeout but does NOT prevent LLM token overflow within that window. Control directly prevents financial sustainability risk (T-0017) and denial-of-wallet scenarios (OWASP LLM10).

### Where
- Main chat endpoint: app/(chat)/api/chat/route.ts:207 (streamText call, missing AbortController)
- Tool LLM calls: lib/ai/tools/request-suggestions.ts:65 (streamText for suggestions, missing timeout)
- Cost estimation: need to add token-counting middleware before both calls

### Change

1. **Add AbortController with timeout to main chat streamText** (app/(chat)/api/chat/route.ts:207–245):
   - Create `const abortController = new AbortController()` before the streamText call.
   - Wrap with timeout: `setTimeout(() => abortController.abort(), 45_000)` to abort after 45 seconds (leaving 15s buffer for cleanup before maxDuration=60).
   - Pass `signal: abortController.signal` to streamText options (Vercel AI SDK supports this parameter).
   - Catch and log aborts: add error handling in the `onError` callback (line 295) to detect abort signals and log them as "timeout_abort" events.

2. **Add token budget enforcement to main chat** (app/(chat)/api/chat/route.ts, before line 207):
   - Define a constant `MAX_TOKENS_PER_REQUEST = 8000` (approximately $0.24 at GPT-4o rates).
   - Before calling streamText, estimate input tokens: `promptTokens = Math.ceil(modelMessages.map(m => m.content.length).reduce((a, b) => a + b, 0) / 4)` (rough estimate: 1 token ≈ 4 chars).
   - Define `MAX_REQUEST_COST_USD = 0.50`; calculate `estimatedCost = (promptTokens + MAX_TOKENS_PER_REQUEST/2) * 0.000015` (approximate GPT-4o pricing).
   - If `estimatedCost > MAX_REQUEST_COST_USD`, return a ChatbotError response immediately (before calling streamText).
   - During streaming, track cumulative output tokens in the onFinish callback (line 258); if cumulative tokens exceed `MAX_TOKENS_PER_REQUEST`, log a "cost_cap_exceeded" event and alert on-call.

3. **Add timeout to request-suggestions streamText** (lib/ai/tools/request-suggestions.ts:65–79):
   - Create `const suggestionsAbortController = new AbortController()`.
   - Set timeout: `setTimeout(() => suggestionsAbortController.abort(), 30_000)`.
   - Pass `signal: suggestionsAbortController.signal` to streamText options.
   - Wrap the for-await loop (line 82) in try-catch to gracefully handle abort errors; if caught, stop processing and return a partial result.

4. **Log cost-control events to Application Insights** (app/(chat)/api/chat/route.ts):
   - Add structured logging (using console.info with JSON, which Application Insights will ingest) for:
     - `{ event: "token_budget_exceeded", requestId, estimatedTokens, limit, timestamp }`
     - `{ event: "request_timeout_abort", requestId, elapsedMs, timestamp }`
   - Set up a CloudWatch alarm (outside this spec, infrastructure) to trigger if "cost_cap_exceeded" events exceed 5/hour.

5. **Add config at runtime** (read inside functions, not at import):
   - Read `process.env.COST_CAP_USD` (default to 0.50) and `process.env.MAX_TOKENS_PER_REQUEST` (default to 8000) at call time inside the POST function, allowing runtime tuning without restart.

### Acceptance
- Zero unbounded cost growth incidents post-deployment: every streamText call has a 45-second abort signal and token budget.
- Per-request cost variance <5% of $0.50 cap: spot-check 10 requests to verify estimated vs. actual cost is within range.
- Timeout abort rate <0.1% of legitimate requests: if >0.1% of requests hit the 45s timeout, reduce timeout or investigate root cause (e.g., model latency).
- Monthly API costs remain within ±10% of pre-deployment baseline: no cost explosion.
- Denial-of-wallet attempt detection: simulate a malicious prompt causing token explosion, verify that cost cap triggers and request is aborted before final payment.

### Avoid
- Do NOT set timeout to 0 or a value <10 seconds (prevents legitimate requests from completing).
- Do NOT implement token counting via an external API (too much latency); use the simple character-based estimate.
- Do NOT silently drop requests that exceed the cost cap; return an explicit error message to the user (ChatbotError).
- Do NOT accumulate cost caps per-user across multiple requests in Phase 1; cost caps are per-request only (per-user budgets are Phase 2).

### Compliance
OWASP LLM10 (Unbounded Consumption): Timeout and token budget prevent runaway token generation. EU AI Act Article 13 (risk management): Cost monitoring demonstrates mitigation of resource exhaustion risks. GDPR compliance: cost tracking enables billing transparency for data subjects.

---

## scope.llm-call-without-timeout-ts — Timeout on request-suggestions LLM Call (Scanner Finding)

### What & why
The streamText call at lib/ai/tools/request-suggestions.ts:65 generates writing suggestions without a timeout or AbortController. If the API becomes slow or stuck, the suggestion request can hang indefinitely, consuming resources. The scanner flagged this as a denial-of-wallet risk.

### Where
lib/ai/tools/request-suggestions.ts:65 (streamText call within execute function)

### Change
Implement the timeout as described in RAI-SUS-02 Change step 3 above (add `const suggestionsAbortController = new AbortController()`, timeout of 30 seconds, pass signal to streamText).

### Acceptance
- streamText call in request-suggestions passes an explicit AbortController signal with 30-second timeout.
- Manual test: invoke requestSuggestions tool; if LLM hangs for >30s, stream aborts cleanly.

### Avoid
- Do NOT block the entire chat request if suggestion streaming fails; return a partial result or error message.

### Compliance
OWASP LLM10.

---

## scope.llm-call-without-timeout-ts — Timeout on Main Chat LLM Call (Scanner Finding)

### What & why
The streamText call at app/(chat)/api/chat/route.ts:207 in the main chat endpoint lacks a timeout or abort signal. Unbounded cost and resource exhaustion risk.

### Where
app/(chat)/api/chat/route.ts:207 (streamText call in execute callback)

### Change
Implement the timeout as described in RAI-SUS-02 Change step 1 above (add AbortController with 45-second timeout).

### Acceptance
- streamText call passes explicit AbortController signal with 45-second timeout.
- Manual test: send a chat request; if LLM hangs for >45s, stream aborts and error is returned.

### Avoid
- Do NOT set timeout below 30 seconds (may abort legitimate requests).

### Compliance
OWASP LLM10.

---

## stop.llm-provider-missing-moderation-ts — LLM Output Moderation (Scanner Finding)

### What & why
The streamText call at lib/ai/tools/request-suggestions.ts:65 and app/(chat)/api/chat/route.ts:207 processes user-provided document content and model outputs without guardrails. While tool authorization prevents unauthorized access, there is no moderation layer to validate prompt safety or detect harmful outputs.

### Where
- lib/ai/tools/request-suggestions.ts:65 (streamText call)
- app/(chat)/api/chat/route.ts:207 (streamText call)

### Change
Integrate moderation as a runtime-configurable optional feature (as described in RAI-ACC-08 Change step 2):
- Read `process.env.ENABLE_MODERATION` at call time inside execute functions.
- If enabled, call OpenAI Moderation API or similar on the prompt (before streamText) and the response (after streamText completes).
- If moderation flags content as unsafe, truncate the response or return an error without persisting.
- Frame as optional: if `ENABLE_MODERATION` env var is not set, moderation is skipped (does not block deployment).

### Acceptance
- Moderation is wired but disabled by default (no operational burden on deployment).
- When enabled, moderation adds <200ms latency to request/response cycle.
- Manual test with ENABLE_MODERATION=1: send a prompt with flagged content (e.g., "how to make a bomb"), verify moderation blocks and returns error.

### Avoid
- Do NOT make moderation mandatory; make it optional via env var.
- Do NOT implement custom ML-based moderation; use OpenAI Moderation API or similar service.

### Compliance
OWASP LLM07 (Unsafe Output Handling), EU AI Act Article 24 (human oversight).

---

## scope.god-agent-tool-count-ts — Polyphonic Agent Architecture (Scanner Findings)

### What & why
Five tools (createDocument, editDocument, updateDocument, requestSuggestions, getWeather) are registered together in lib/ai/tools/{tool}.ts and dispatched by a single agent in app/(chat)/api/chat/route.ts:222–240. The scanner flagged this as a "God Agent" anti-pattern—excessive capability breadth in one agent. Splitting into specialized agents (e.g., DocumentAgent for create/edit/update, UtilityAgent for weather) reduces the attack surface and improves separation of concerns per OWASP Agentic AI design principles.

### Where
- Tool registration: lib/ai/tools/create-document.ts, edit-document.ts, update-document.ts, request-suggestions.ts, get-weather.ts (each defines a tool function)
- Tool dispatch: app/(chat)/api/chat/route.ts:222–240 (all five tools bound to single streamText call)
- Authorization scope: lib/ai/tools/authorize.ts:11–16 (all tools in one ALL_TOOL_NAMES list)

### Change
**This is an architectural recommendation, not a mandatory code fix.** The code is functional but could benefit from organizational refactoring:

1. **Create a tools registry**: Define a new file `lib/ai/tools/registry.ts` that groups tools by capability area:
   ```
   DocumentTools: { createDocument, editDocument, updateDocument }
   UtilityTools: { getWeather, requestSuggestions }
   ```

2. **Use conditional tool binding**: In chat/route.ts:222–240, conditionally bind tool groups based on user intent or user type:
   ```
   Example (do not paste; guide only):
   const availableTools = userType === "premium"
     ? { ...DocumentTools, ...UtilityTools, ...requestSuggestions }
     : { ...DocumentTools };
   ```
   This reduces capability surface per user type.

3. **Split tool authorization**: Extend `entitlements.ts` to allow tool groups rather than individual tools, e.g., `allowedToolGroups: ["DocumentTools"]`, then expand at authorization time.

**For Phase 1, this is a design recommendation for future refactoring.** It does NOT block production deployment; the current single-agent architecture is functional and authorized.

### Acceptance
- (Optional Phase 2) Agent architecture refactored into tool groups; authorization policy updated to use groups.
- No change required for Phase 1 production deployment.

### Avoid
- Do NOT split agents in a way that breaks tool interdependencies (e.g., requestSuggestions depends on documentId, so separate it from DocumentTools only if requestSuggestions is called independently).
- Do NOT change the authorization model in Phase 1; tool-level checks are sufficient for launch.

### Compliance
OWASP Agentic AI design: separation of concerns, minimal capability per agent. Optional optimization.

---

## Excluded (not code-fixable)

**RAI-ACC-01** (Structured audit logging sink) — Requires infrastructure: set up Azure Application Insights connection string and EventHubs export sink (outside application code).

**RAI-ACC-11 Phase 2** (Cryptographic signing) — Requires infrastructure: Azure Key Vault deployment and key rotation policy (outside application code).

**RAI-SUS-02 Cost Monitoring Dashboard** — Requires infrastructure: CloudWatch alarms and SNS notifications (outside application code).

**Process/Governance**: Runbook documentation, SLA recovery procedures, incident response workflows — organizational/process scope, not code.