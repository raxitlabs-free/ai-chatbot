# AI Security and Compliance Remediation Spec

**How to use this spec:** Hand to your coding agent with explicit feature and file boundaries. The agent should implement each change in priority order (RAI-PS-22 first, then RAI-PS-24, etc.), testing each control independently. Verify tool authorization is enforced before LLM output dispatch, audit trails are immutable, and no state leaks across requests.

## RAI-PS-22 — Prompt Injection Defense & Input/Output Validation (CRITICAL)

### What & why
Implement comprehensive input validation on user prompts and LLM-generated tool-call JSON to prevent adversarial prompt injection (OWASP-LLM01, LLM06). Malicious prompts can craft arbitrary editDocument parameters; LLM output flows directly to tool handlers without schema validation, content filtering, or injection fence. This control adds parameter whitelisting, max-length bounds, and anomaly detection on tool-call sequences to reject craft attacks before execution.

### Where
- **LLM tool dispatch:** app/(chat)/api/chat/route.ts:194–240 (streamText call with tools array)
- **Tool handlers:** lib/ai/tools/edit-document.ts:31 (execute), lib/ai/tools/create-document.ts:33, lib/ai/tools/get-weather.ts:43, lib/ai/tools/update-document.ts:29, lib/ai/tools/request-suggestions.ts:31
- **Parameter validation entry point:** Before tool.execute() is called, add validation middleware

### Change
1. **Input validation on tool-call payloads** (app/(chat)/api/chat/route.ts, before streamText result dispatch):
   - Add middleware that intercepts LLM-generated tool calls before handler execution
   - Validate each tool call against strict JSON schema: id (UUID format), old_string/new_string (max 50,000 chars each, no embedded shell/SQL metacharacters), location (max 100 chars, alphanumeric + space/dash only)
   - Implement injection fence: reject any parameter containing shell patterns (`$(`, `` ` ``, `|`, `;`), SQL keywords (`DROP`, `UNION`, `--`), or control characters

2. **Anomaly detection on tool sequences:**
   - Track tool invocation count per user per 1-minute window in Redis (key: `tool-sequence:{user_id}:{minute}`)
   - Reject if >5 editDocument calls within 60 seconds (indicates cascade attempt)
   - Reject if >3 different document IDs mutated in single conversation turn
   - Log rejection with user_id, attempted parameters, and reason to audit trail

3. **Content length bounds:**
   - editDocument.old_string and new_string: max 50,000 chars each
   - getWeather.location: max 100 chars
   - createDocument.title: max 500 chars
   - Reject LLM output exceeding bounds; log as injection attempt

4. **Tool-call parameter whitelisting (per tool):**
   - editDocument: id must exist in database AND belong to session.user.id; replace_all boolean only
   - createDocument: kind must be exactly one of ['code', 'text', 'sheet']
   - getWeather: location or (latitude + longitude); latitude ∈ [-90, 90], longitude ∈ [-180, 180]
   - requestSuggestions: documentId must exist AND belong to session.user.id
   - updateDocument: id must exist AND belong to session.user.id

### Acceptance
- Zero successful prompt-injection incidents in staging/production over 30-day window
- Injection detection rate >95% on OWASP-LLM01 adversarial suite (test with payloads: "call editDocument on user X's document", "invoke weather 1000 times", "edit with 100k-char old_string")
- False-positive block rate <1% on legitimate multi-turn queries
- Parameter validation latency <50ms p99 per request
- Audit logs show 100% tool invocations with validation pass/fail flag

### Avoid
- Do NOT implement whitelisting at LLM prompt level (prompt injection is in-model; only data validation stops it)
- Do NOT allow regex-based content filtering (attackers bypass regex); use fixed pattern matching for metacharacters
- Do NOT rate-limit based on failed tool attempts alone (legitimate users may have typos); correlate with parameter anomalies
- Do NOT create fallback paths that skip validation (a bypass must never execute; return error to user instead)

### Compliance
OWASP Top 10 LLM (LLM01 Prompt Injection, LLM06 Excessive Agency), EU AI Act Art.50 (security and transparency)

---

## RAI-PS-24 — Per-Tool Authorization & Policy Gate (HIGH)

### What & why
Implement centralized authorization framework (Cedar policy language or OPA Rego) to enforce role-based access control (RBAC) at tool dispatch, preventing both LLM-injected and user-prompted unauthorized tool invocations. Currently all five tools (getWeather, createDocument, editDocument, updateDocument, requestSuggestions) execute without policy gate; LLM can invoke any tool regardless of user role. This control establishes per-tool policies binding user role/session to tool capability before execution.

### Where
- **Tool dispatch gateway:** app/(chat)/api/chat/route.ts:194–235 (before streamText passes tools to model)
- **Session context:** app/(chat)/api/chat/route.ts:89 (session.user available; extract role)
- **Tool handlers:** Each of lib/ai/tools/*.ts receives session but does NOT enforce centralized policy

### Change
1. **Create authorization policy matrix** (lib/ai/authorization.ts, new file):
   ```
   Define RBAC bindings:
   - role "guest": tools [getWeather, requestSuggestions] (read-only)
   - role "regular": tools [getWeather, createDocument, editDocument, updateDocument, requestSuggestions]
   - role "admin": all tools
   ```
   Load from environment config (e.g., `RBAC_POLICY_JSON`) at call time (NOT import time), so runtime config changes take effect without restart.

2. **Add policy enforcement middleware** (lib/ai/authorization.ts):
   - Before tool dispatch in streamText call (route.ts:194), check authorization
   - For each tool in experimental_activeTools array, validate: user role has permission for tool
   - If unauthorized, remove tool from activeTools (graceful degradation; LLM cannot invoke it)
   - Log authorization decision to audit trail: user_id, tool_name, role, allowed/denied, timestamp

3. **Per-tool quota enforcement** (rate limits):
   - editDocument: max 10 calls/hour per user (store in Redis key `tool-quota:edit:{user_id}:hour`)
   - createDocument: max 50 calls/day per user
   - getWeather: max 100 calls/hour per user (external API constraint)
   - Implement via Redis INCR + EXPIRE (similar to existing IP rate limit in lib/ratelimit.ts)
   - Reject quota-exceeded invocations with graceful LLM response

4. **Tool authorization check in each handler** (defensive layer):
   - After policy gate at dispatch, re-validate user context in each tool execute() method
   - If session.user.id mismatches document.userId (or stateless tools), reject with "Forbidden"
   - This prevents context-swapping attacks within multi-step execution

### Acceptance
- Zero unauthorized tool invocations reach execution layer (policy gate blocks all non-permitted calls)
- Audit trail shows 100% of tool dispatch attempts with user_id, role, tool_name, policy decision, timestamp
- Authorization decision latency <20ms p99 across all tools
- Quota enforcement: zero tool calls exceeding per-tool limits in production over 30 days
- Test: attempt to invoke createDocument as "guest" role; verify tool removed from activeTools, LLM cannot call it

### Avoid
- Do NOT implement per-tool checks scattered across handlers without centralized policy gate (policy drift risk)
- Do NOT make authorization decisions at import time (config must be read at call time per repository facts)
- Do NOT mix authorization with business logic in tool handlers (keep policy gate separate and testable)
- Do NOT allow authorization bypass via error messages or LLM reasoning (gateway must be airtight)

### Compliance
OWASP A01:2021 (Broken Access Control), GDPR Art.6 (lawfulness of processing), EU AI Act Art.50 (transparency and security)

---

## RAI-SAF-08 — Output Validation & Moderation (HIGH)

### What & why
Implement output validation and moderation on LLM-generated tool-call parameters before dispatch to external APIs. The getWeather tool (lib/ai/tools/get-weather.ts:43) and other stateless tools lack parameter validation; LLM can craft malicious coordinates (latitude 999, longitude -999), extreme requests, or parameter patterns triggering DOS on downstream APIs. Moderation gate prevents these attacks by validating parameters against strict schema and filtering high-risk patterns.

### Where
- **LLM output moderation:** app/(chat)/api/chat/route.ts:194–240 (after streamText returns, before dataStream processes tool results)
- **getWeather tool:** lib/ai/tools/get-weather.ts:43–77 (execute function with coordinate/city parameters)
- **All stateless tools:** Any tool making external API calls without input validation

### Change
1. **Add output validation middleware** (lib/ai/moderation.ts, new file):
   - Before any tool result is processed, validate LLM-generated parameters
   - For getWeather: validate latitude ∈ [-90, 90], longitude ∈ [-180, 180], city name against whitelist
   - Load city whitelist from environment (e.g., `APPROVED_CITIES_JSON`: `["New York", "London", "Tokyo", ...]`)
   - Reject coordinates outside valid range; reject cities not in whitelist; log as moderation block

2. **Parameter schema enforcement:**
   - getWeather requires: (city: string, max 100 chars) OR (latitude: number, longitude: number)
   - Validate types, lengths, and ranges before tool execution
   - Return error to LLM if parameters invalid (graceful failure; no external API call)

3. **Anomaly detection on parameter patterns:**
   - Detect repeated requests with extreme values (e.g., latitude=90 multiple times = pole-seeking attack)
   - Detect rapid iteration over coordinate space (lat += 0.1 in loop = grid scan attack)
   - Log anomalies to audit trail; block if >5 anomalies in 1-minute window

4. **Integration with streamText result processing:**
   - Add callback on tool result: before dataStream.write() emits result, validate parameters used
   - Log validation decision (passed/rejected) in audit trail with tool name, parameters, user_id

### Acceptance
- 100% of getWeather calls match approved schema (city in whitelist or coordinates in [-90,90] x [-180,180])
- Zero malformed API calls reach open-meteo API (validation blocks all out-of-spec parameters)
- Moderation latency <20ms per tool invocation (schema validation + whitelist lookup)
- Audit logs show 100% of tool calls with moderation decision (passed/rejected)
- Adversarial test: attempt "latitude=999", "city=foo", rapid grid scan → all rejected before API dispatch

### Avoid
- Do NOT implement moderation only at LLM-prompt level (reasoning can bypass prompt constraints)
- Do NOT use probabilistic/ML-based anomaly detection without fallback hard rules (ML may not catch targeted DOS patterns)
- Do NOT allow partial validation (all parameters must pass before tool execution; no lenient fallbacks)
- Do NOT skip validation for "stateless" tools (stateless = no user auth, not exempt from parameter validation)

### Compliance
OWASP LLM05 (Improper Output Handling), OWASP A05:2021 (Injection), EU AI Act Art.50 (security)

---

## RAI-SAF-13 — Emergency Stop Mechanism (HIGH)

### What & why
Implement emergency halt capability enabling operators to immediately stop all tool dispatch and terminate in-flight LLM inference when cascade patterns or malicious activity detected. Current architecture has 60-second timeout (maxDuration=60) but no graceful halt; if cascade detected at T=30, operator cannot stop, allowing 30+ more seconds of mutations. Emergency stop enables <100ms halt, in-flight transaction rollback, and operator control for critical incidents.

### Where
- **Chat API POST handler:** app/(chat)/api/chat/route.ts:60–322 (request processing, tool dispatch at line 194)
- **Tool dispatch loop:** Within streamText() result processing (line 242–244)
- **Halt state storage:** Redis key `halt_execution:{chat_id}` for per-chat halt, or global `halt_execution_global` for system-wide halt

### Change
1. **Add halt state check at tool dispatch** (lib/ai/tools/index.ts or middleware, new file):
   - Before each tool.execute() is invoked, check Redis key `halt_execution:{user_id}` or `halt_execution_global`
   - If key exists (boolean true), immediately throw error "System halted by operator" without executing tool
   - Return graceful error to LLM: "Tool execution halted; chat terminated"

2. **Implement emergency-stop API endpoint** (app/(chat)/api/emergency-stop/route.ts, new file):
   - POST /api/emergency-stop with body: { reason: string } (required, logged for audit)
   - Require RBAC authorization: only admin/operator role
   - On successful POST:
     - Set Redis key `halt_execution_global = true` with TTL 3600 seconds (1 hour)
     - Log halt event: operator_id, timestamp, reason, affected_user_ids (all active chats), number of in-flight operations
     - Return 200 with { halted: true, message: "All tool execution halted" }

3. **Graceful in-flight transaction handling:**
   - For any database write already in progress (e.g., saveDocument), catch halt signal and ROLLBACK
   - Tools that queued async writes must cancel them if halt detected
   - Log rollback events to audit trail

4. **UI/Dashboard integration:**
   - Add admin dashboard button: "🛑 Emergency Stop" (requires confirm + reason entry)
   - On click, POST to /api/emergency-stop with reason from admin
   - Dashboard displays: active chats halted, in-flight operations rolled back, halt timestamp

5. **Recovery procedure:**
   - After halt expires (TTL 1 hour) or operator manually clears, halt key is deleted
   - Halted chats can resume (new POST request must be made; no auto-resume)
   - Log recovery event: who cleared halt, timestamp

### Acceptance
- Emergency stop halts all tool dispatch <100ms after API call (measure via audit log timestamp - halt request timestamp)
- In-flight database transactions rollback cleanly (no orphaned locks; verify via pg_locks query)
- Zero tool calls execute after halt triggered (audit trail shows 0 post-halt executions)
- Halt event logged with operator_id, reason, timestamp, affected_user_count
- Test scenario: Trigger cascade (5 editDocument calls), manually halt at T=30s, verify only 3 mutations applied

### Avoid
- Do NOT implement halt as passive timeout (timeout ≠ halt; operator cannot trigger on-demand)
- Do NOT allow tools to ignore halt signal (check must be non-bypassable, before execute())
- Do NOT leave halt state in-memory only (must be Redis-backed for distributed system; Vercel edge deployments)
- Do NOT implement auto-recovery (manual restart ensures operator oversight of incident)

### Compliance
OWASP Agentic AI T6 (Intent Breaking), T7 (Deceptive Behaviors), EU AI Act Art.50 (oversight and control)

---

## RAI-BF-06 — Fairness Monitoring & Bias Detection (MEDIUM)

### What & why
Instrument tool dispatcher to detect discriminatory routing patterns across user demographics. Single-agent tool dispatch (route.ts:194–240) lacks fairness metrics; LLM reasoning can be manipulated to preferentially route certain user cohorts to lower-quality paths (e.g., always route "budget" users to getWeather only, never createDocument). RAI-BF-06 monitors invocation distribution by demographic to detect statistical bias, triggering alerts for >5% disparity in tool routing across cohorts.

### Where
- **Tool dispatcher:** app/(chat)/api/chat/route.ts:194–240 (experimental_activeTools array, tool invocation loop)
- **Audit logging:** lib/db/queries.ts (extend logging to capture demographic attributes)
- **Bias detection logic:** lib/ai/fairness.ts (new file)

### Change
1. **Demographic attribute tracking:**
   - At POST handler entry (route.ts:89), extract user cohort from session metadata (e.g., user_type: "guest" vs "regular", or custom demographic tag if stored)
   - Pass cohort identifier through to tool invocation logging

2. **Tool invocation logging with demographics** (lib/ai/fairness.ts, new file):
   - Before streamText() executes, log: user_id, cohort, enabled_tools (experimental_activeTools array)
   - After each tool result, log: tool_name, success/failure, cohort, user_id, timestamp
   - Store in audit table or Redis stream for rolling-window analysis

3. **Bias detection on 7-day rolling window:**
   - Every hour, compute tool routing distribution per cohort:
     - For cohort A: % of users who invoked createDocument, editDocument, getWeather, etc.
     - For cohort B: % of users who invoked each tool
     - Compare distributions; compute max divergence
   - Alert if max divergence > 5% (e.g., cohort A has 40% createDocument rate, cohort B has 35%, delta=5% → threshold)
   - Log alert with affected cohorts, metrics, timestamp

4. **Integration with monitoring platform:**
   - Send bias detection metrics to Azure Application Insights or Datadog: metric name `tool_routing_disparity_percent`, cohort tags, value
   - Configure alert rule: trigger when disparity > 5% sustained for >1 hour
   - Dashboard: display tool routing distribution by cohort over time

### Acceptance
- Tool routing disparity <5% across all cohorts over 30-day production window
- Zero bias-driven routing anomalies detected in monitoring alerts
- Audit trail logs 100% of tool invocations with user cohort and tool name
- Bias detection latency: 1-hour rolling window computed within 5 minutes of period close
- Test: Manually create cohort A with different tool enablement logic, verify disparity detection triggers

### Avoid
- Do NOT use real-time per-request bias checks (too noisy; use 7-day rolling window)
- Do NOT assign demographic categories without consent/transparency (use only explicitly stored user attributes)
- Do NOT threshold bias at 0% (legitimate preference variation exists; use 5% threshold per guidance)
- Do NOT disable tools based on bias alerts alone (alerts inform investigation; humans decide remediation)

### Compliance
GDPR Art.5(f) (fairness principle), EU AI Act Art.50 (transparency and fairness), NIST AI RMF (fairness & bias mitigation)

---

## RAI-BF-02 — Anti-Discrimination Governance Framework (MEDIUM)

### What & why
Establish organizational governance and remediation policies for fairness issues identified by RAI-BF-06 and other controls. Technical controls (monitoring, logging) are necessary but insufficient; governance ensures discrimination risks are systematically addressed through process, policy, and accountability. This control is organizational/process-driven but requires operational procedures and documentation tied to the system.

### Where
- **Policy ownership:** Legal/Compliance team (define anti-discrimination policy)
- **Operations:** Ops/Platform team (incident response runbook)
- **Implementation tracking:** Governance dashboard or ticket tracking (Jira/Linear)

### Change
This control is primarily non-code (policy, governance, process). However, application code supports it by:

1. **Audit trail integration:** All bias alerts (RAI-BF-06) must be logged with full context (cohort, metrics, timestamp) to audit table for compliance review
   - Extend lib/db/schema.ts to include governance_audit table for bias alerts and remediation actions
   - Log schema: { id, alert_id, cohort_affected, disparity_percent, timestamp, investigation_status, remediation_action, resolved_date }

2. **Remediation action documentation:**
   - Update chat route to support metadata: when bias alert triggers, store in governance_audit table with investigation_status="pending"
   - Ops team can update investigation_status → "investigating" → "resolved" via admin API
   - Log remediation_action taken (e.g., "retrained model", "adjusted routing logic", "dismissed as false positive")

**Process (non-code) components:**
   - Month 1: Policy Development — Legal + Product define anti-discrimination policy; document fairness thresholds (5% max routing disparity), accessibility requirements, remediation pathways
   - Month 2: Remediation Playbook — Map RAI-BF-06 alerts to remediation actions; e.g., disparity >5% → investigate model reasoning; >10% → escalate to model review + possible retraining
   - Month 3: Operationalization — Establish quarterly fairness audit cadence (cross-functional review: product, eng, compliance, customer success); publish transparency report
   - Month 4+: Ongoing — Maintain annual policy review; incident log for GDPR accountability

### Acceptance
- Anti-discrimination policy documented and approved by legal/compliance (Month 2)
- 100% of fairness alerts (RAI-BF-06) mapped to remediation playbooks in governance_audit table
- Zero bias-related incidents escalated without documented investigation + action
- Quarterly fairness audits completed on schedule with 100% of findings resolved within SLA
- Transparency report published (summary of fairness metrics, incidents, actions taken)

### Avoid
- Do NOT implement fairness governance only in code (requires policy + process; code is enforcement layer)
- Do NOT investigate fairness issues without cross-functional collaboration (involves product, legal, eng, ops)
- Do NOT dismiss fairness alerts as "model behavior" without human review (anomalies may indicate real discrimination)
- Do NOT release system to production without published anti-discrimination policy (compliance requirement)

### Compliance
GDPR Art.5(f) (fairness principle), Art.22 (automated decision-making), EU AI Act Art.50 (transparency), EU AI Act Art.6 (risk-based governance)

---

## RAI-ACC-01 — Immutable Audit Trail for Tool Invocations (HIGH)

### What & why
Implement append-only, immutable audit trail for all AI tool invocations to enable forensic investigation and compliance audit. Current system saves messages and documents to database but does NOT log tool invocations themselves; if LLM-injected editDocument call mutates document, audit trail shows document changed but NOT which LLM reasoning triggered it or what parameters were used. Immutable audit log (CloudTrail or write-ahead log) captures complete invocation record: user, tool, parameters, outcome, timestamp—enabling auditors to reconstruct exactly what happened and prove causality.

### Where
- **Tool dispatch:** app/(chat)/api/chat/route.ts:194–240 (before and after streamText tool execution)
- **Audit storage:** lib/db/schema.ts (new audit_log table)
- **Audit write:** Each tool handler in lib/ai/tools/*.ts

### Change
1. **Create immutable audit table** (lib/db/schema.ts, new table):
   ```typescript
   export const auditLog = pgTable("AuditLog", {
     id: uuid("id").primaryKey().notNull().defaultRandom(),
     timestamp: timestamp("timestamp").notNull().defaultNow(),
     userId: uuid("userId").notNull().references(() => user.id),
     toolName: varchar("toolName").notNull(),  // "editDocument", "createDocument", etc.
     parameters: json("parameters").notNull(),  // Full LLM-generated parameters
     outcome: varchar("outcome").notNull(),  // "success", "failure", "rejected"
     errorMessage: text("errorMessage"),  // If failed
     ipAddress: varchar("ipAddress"),  // From request
   }, (table) => ({
     pk: primaryKey({ columns: [table.id] }),
     userIdIndex: index("idx_audit_userId").on(table.userId),
     timestampIndex: index("idx_audit_timestamp").on(table.timestamp),
   }));
   ```
   Make this table immutable: configure database to DENY DELETE, UPDATE on auditLog (enforce at database layer via PostgreSQL row-level security or policy)

2. **Log all tool invocations** (lib/ai/tools/index.ts or middleware, new file):
   - Create helper function logToolInvocation(userId, toolName, parameters, outcome, errorMessage)
   - Before each tool.execute() is called, log invocation with outcome="pending"
   - After tool completes, update outcome to "success" or "failure" + error details
   - Call from each tool handler in lib/ai/tools/*.ts:31 (editDocument), :33 (createDocument), etc.

3. **Immutable storage enforcement:**
   - Verify CloudTrail configuration (if using AWS): S3 bucket with immutable storage (S3 Object Lock)
   - Or: Implement database trigger to log deletions to separate immutable_delete_attempts table (prove malicious deletion attempts)
   - Document immutability guarantee: "Audit logs cannot be deleted or modified by any user, including admins"

4. **Retention policy:**
   - Retain audit logs for minimum 7 years (GDPR Art.32, compliance requirement)
   - Archive to cold storage (AWS Glacier) after 90 days for cost efficiency
   - Verify retention via quarterly compliance check

### Acceptance
- 100% of tool invocations logged with complete parameter set within 100ms
- Zero successful DELETE/UPDATE attempts on immutable audit log (verify via database audit)
- Auditors can reconstruct complete tool-invocation timeline for any user within 30 minutes using audit logs
- Retention: logs present for minimum 7 years; latest logs in hot database, older in archive
- Test: Attempt to delete/update audit log entry as admin; verify rejection by storage layer

### Avoid
- Do NOT store audit logs in-memory or in mutable cache (must be immutable at rest)
- Do NOT log only successful operations (must log failures, rejections, errors)
- Do NOT exclude sensitive parameters from audit logs (log full parameters; redact PII separately per RAI-ACC-08)
- Do NOT allow audit log purge based on user request (retention is mandatory, unalterable by application)

### Compliance
GDPR Art.32 (security measures), Art.5(f) (accountability principle), EU AI Act Art.50 (documentation and transparency), SOC 2 Type II (audit trail requirement)

---

## RAI-ACC-08 — Structured LLM I/O Logging with PII Redaction (HIGH)

### What & why
Implement structured logging of LLM inference requests and responses (prompts, outputs, token counts, model ID, latency) with automated PII detection and redaction before immutable storage. Current system streams LLM output directly but does NOT log what prompts were sent to the model or what it returned; without this, auditors cannot link document mutations to specific LLM reasoning steps or prove model behavior. Structured logging with PII redaction enables compliance investigators to retrieve exact prompt/output pairs for incident analysis while protecting user data.

### Where
- **LLM inference:** app/(chat)/api/chat/route.ts:194 (streamText call)
- **LLM response processing:** app/(chat)/api/chat/route.ts:242–244 (dataStream.merge result)
- **Logging implementation:** lib/ai/llm-logging.ts (new file)

### Change
1. **Structured LLM logging middleware** (lib/ai/llm-logging.ts, new file):
   - Wrap streamText() call to capture before/after:
     - **Request:** Full prompt text, model identifier (e.g., "claude-3-5-sonnet"), temperature, maxTokens, system prompt
     - **Response:** Full LLM output text, input token count, output token count, latency (ms), stop reason
     - **Metadata:** ISO 8601 timestamp, chat_id, user_id, session_id
   - Store in structured JSON format, not free-form logs

2. **PII detection and redaction** (lib/ai/llm-logging.ts):
   - Before logging, scan prompt + output for PII patterns:
     - Email: `[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`
     - Phone: `\d{3}-\d{3}-\d{4}` or `\+\d{1,3}\s\d{1,14}`
     - Document IDs: `DOC-\d+`, `/documents/[a-f0-9-]{36}`
     - Session tokens: `session_[a-f0-9]{64}`, `auth_[a-zA-Z0-9_-]{128}`
   - Replace matched PII with placeholder: `<EMAIL>`, `<PHONE>`, `<DOC_ID>`, `<SESSION_TOKEN>`
   - Log redaction events to separate audit_pii_redaction table: { timestamp, pattern_matched, count, user_id }

3. **Integration with streamText call** (app/(chat)/api/chat/route.ts:194):
   ```typescript
   const llmLogger = createLLMLogger({ userId: session.user.id, chatId: id });
   const result = streamText({
     model: getLanguageModel(chatModel),
     system: systemPrompt(...),
     messages: modelMessages,
     ...
   });
   llmLogger.logRequest({ prompt: systemPrompt + messages, model: chatModel });
   // After response:
   llmLogger.logResponse({ output, inputTokens, outputTokens, latency });
   ```

4. **Storage backend:**
   - Log to CloudTrail (AWS) or similar immutable append-only service (30-day archive)
   - After 30 days, rotate to database (lib/db/schema.ts llm_inference_logs table)
   - Retention: 7 years minimum (GDPR compliance)

### Acceptance
- 100% of LLM inferences logged with complete metadata: prompt, output, token counts, model ID, latency
- Zero PII strings appear unredacted in audit logs (weekly scan confirms)
- PII detection accuracy: >99% recall on test patterns (email, phone, document IDs, session tokens)
- Auditors can retrieve exact prompt/output pair for any document mutation within 5 minutes
- Test: Inject test PII into prompt (dummy@example.com, DOC-12345), verify redaction in audit log

### Avoid
- Do NOT log without redaction (PII must be removed before storage)
- Do NOT use only regex-based PII detection (must also check against known user data, e.g., user email from session)
- Do NOT log to mutable storage (must be immutable append-only)
- Do NOT sample LLM logs (log 100% of inferences; sampling breaks forensic trail)

### Compliance
GDPR Art.32 (security), Art.6 (lawfulness + transparency), Art.30 (processing records), Data Protection Agreement (DPA) vendor requirements

---

## RAI-ACC-11 — Cryptographic Non-Repudiation Signing (HIGH)

### What & why
Implement cryptographic signing of tool invocations to create unforgeable proof that a specific LLM output—bound to agent identity, timestamp, and parameter hash—triggered each tool execution. Current audit logs (RAI-ACC-01) record what happened but NOT cryptographic proof of causality; attacker could deny responsibility or claim system malfunction. Non-repudiation signing (HMAC or RSA signature) over tool parameters + metadata prevents attacker repudiation and enables auditors to prove causality mathematically.

### Where
- **Tool dispatcher/middleware:** Before each tool.execute() call (apply across all 5 tools)
- **Signature generation:** lib/ai/signing.ts (new file)
- **Audit logging:** Extend lib/db/schema.ts auditLog table to include signature + verification status

### Change
1. **Create signing utility** (lib/ai/signing.ts, new file):
   - Function signToolInvocation(toolName, parameters, userId, timestamp, modelId) → signature
   - Compute SHA-256 hash over: `toolName || modelId || userId || timestamp || JSON.stringify(parameters)`
   - Sign hash with private key (HMAC-SHA256 or RSA-2048) from Azure Key Vault
   - Read key at CALL time (not import time): `const key = await getPrivateKeyFromVault()`
   - Return signature + verification proof

2. **Integrate into tool dispatch** (lib/ai/tools/index.ts middleware, new file):
   - Before each tool.execute(), call signToolInvocation()
   - Include signature in tool context: `{ ...params, _signature: signature, _verified: true }`
   - Store signature in auditLog table (extend schema)

3. **Verification on forensic investigation** (lib/ai/forensics.ts, new file):
   - Auditors/incident response call verifyToolSignature(auditLogEntry) 
   - Verify: timestamp within acceptable window (e.g., 60s of signature creation time)
   - Verify: signature matches current parameters + metadata
   - Return verification status: true/false + reason if failed
   - Log verification attempt to separate forensics_verification table

4. **Key rotation** (ops process, supported by code):
   - Monthly key rotation: new private key issued by Azure Key Vault
   - Old signatures remain valid (multiple keys tracked)
   - Tool dispatch reads latest key; forensics can verify against any valid key

5. **Extend audit schema** (lib/db/schema.ts):
   ```typescript
   export const auditLog = pgTable("AuditLog", {
     ...existing fields...,
     signature: varchar("signature").notNull(),  // Hex-encoded HMAC/RSA signature
     signatureAlgorithm: varchar("signatureAlgorithm").notNull(),  // "HMAC-SHA256" or "RSA-2048"
     keyVersion: integer("keyVersion").notNull(),  // Which key was used to sign
     verified: boolean("verified"),  // Forensics verification result
   });
   ```

### Acceptance
- 100% of tool invocations signed with valid cryptographic signature
- Zero signature verification failures for legitimate invocations (all signatures verify on audit check)
- Auditors can cryptographically prove non-repudiation for any tool call (no "system malfunction" defense possible)
- Key rotation: monthly rotation executed without interruption to tool execution (<10ms signing latency impact)
- Test: Sign tool invocation, tamper with parameters, verify signature fails; then reverify original → pass

### Avoid
- Do NOT use weak signing (MD5, SHA1); use HMAC-SHA256 minimum or RSA-2048
- Do NOT store private keys in code/environment variables (must be in Azure Key Vault, read at call time)
- Do NOT sign without timestamp (prevents replay attacks; timestamp is part of signed data)
- Do NOT keep old keys forever (rotate monthly to limit blast radius of key compromise)

### Compliance
EU AI Act Art.50 (non-repudiation for autonomous agent accountability), SOC 2 Type II (non-repudiation controls)

---

## RAI-ACC-10 — AI-Specific Incident Forensics Capabilities (MEDIUM)

### What & why
Establish forensics query infrastructure to correlate immutable audit trail (RAI-ACC-01), structured LLM logs (RAI-ACC-08), and cryptographic signatures (RAI-ACC-11) for incident root-cause analysis. When disputes arise (e.g., "why did LLM mutate document X?"), incident response needs to trace backward from document mutation → tool invocation → LLM inference → user input, reconstructing complete causal chain. Forensics layer provides tooling to reconstruct this timeline and prove causality.

### Where
- **Forensics query API:** app/(chat)/api/forensics/query/route.ts (new endpoint, admin-only)
- **Data correlation:** lib/ai/forensics.ts (new file, queries across auditLog + llm_inference_logs + signatures)
- **CLI tool:** Support forensics queries from command line for incident response automation

### Change
1. **Forensics query API** (app/(chat)/api/forensics/query/route.ts, new endpoint):
   - POST /api/forensics/query with body: { tool?: string, userId?: string, documentId?: string, timeRange: [start, end], queryType: "chain-reconstruction" | "hallucination-trace" | "cascade-detection" }
   - Require RBAC authorization: admin/operator role only
   - Execute query within SLA: 5 minutes for 30-day window

2. **Prompt chain reconstruction** (lib/ai/forensics.ts):
   - Input: documentId, timestamp of mutation
   - Query auditLog table: find tool invocation matching documentId + timestamp window
   - Query llm_inference_logs: find LLM inference that preceded tool invocation
   - Query messages table: find user input that triggered the conversation
   - Return timeline: user_input → LLM_inference → tool_invocation → document_mutation
   - Include: timestamps, model version, token counts, user_id, signature verification status

3. **Hallucination source tracing:**
   - Input: LLM inference ID, output text
   - Compare LLM output against RAG context (if applicable) + system prompt
   - Flag any facts in LLM output NOT present in context → likely hallucination
   - Query documents referenced in tool parameters: verify they exist + belong to correct user
   - Return: hallucination probability, source analysis, detected inconsistencies

4. **Cascade detection** (lib/ai/forensics.ts):
   - Input: userId, time range
   - Count tool invocations per minute; detect spikes (>5 edits in 60s = cascade pattern)
   - Correlate with LLM reasoning: were invocations driven by legitimate user requests or LLM loop?
   - Return: cascade timeline, detected anomalies, manual halt decision recommendation

5. **Dashboard & CLI**:
   - Grafana dashboard: display forensics query results; timeline visualization
   - CLI tool: `forensics query --tool=edit-document --user=alice --time-range=2024-01-15T10:00:00Z/2024-01-15T10:30:00Z`
   - Output: JSON with correlated timeline, signatures, verification status

### Acceptance
- Forensics query latency: 5 minutes for incident spanning 30 days of audit data
- Prompt chain reconstruction accuracy: 100% of traces correctly identify LLM output as root cause
- Hallucination detection: false-positive rate <2% (few false alarms), false-negative rate <5% (catches most hallucinations)
- MTTR improvement: Mean-time-to-resolution for LLM-related incidents reduced by >50% vs. pre-control baseline
- Test: Trigger malicious mutation, query forensics; verify complete chain reconstructed and hallucination detected

### Avoid
- Do NOT implement forensics queries without cross-system correlation (must tie audit + LLM logs + signatures together)
- Do NOT make forensics available to non-admin users (sensitive incident data; restrict to operators/investigators)
- Do NOT rely on ML-based hallucination detection alone (pair with rule-based fact verification against context)
- Do NOT delay forensics queries for hours (SLA must be <5 minutes for incident response effectiveness)

### Compliance
GDPR Art.32 (security incident investigation), EU AI Act Art.50 (incident documentation)

---

## RAI-SUS-02 — Per-Request & Per-Workflow Token Budgets (HIGH)

### What & why
Enforce per-request and per-workflow token budget caps to prevent denial-of-wallet attacks via prompt injection. At Claude 3.5 Sonnet rates (~$3 per 1M tokens), unrationed LLM calls in streamText() can escalate costs to $500+ per attack within hours if attacker triggers 100K-token inference loops. RAI-SUS-02 implements hard limits: max 50K tokens per request, max 500K per workflow, gracefully degrading when budget exhausted. This directly prevents OWASP LLM10 (Unbounded Consumption) and LLM06 (Excessive Agency) cost escalation vectors.

### Where
- **LLM inference call:** app/(chat)/api/chat/route.ts:194–240 (streamText call, maxTokens parameter)
- **Budget tracking:** Redis key `token-budget:{chat_id}:daily` for per-workflow budget
- **Cost calculation:** lib/ai/token-budget.ts (new file)

### Change
1. **Per-request token limit** (app/(chat)/api/chat/route.ts:194):
   - Add maxTokens: 50000 to streamText() call (currently absent)
   - Limits single Claude 3.5 Sonnet inference to 50K tokens max
   - Model stops generation at 50K, returning partial output gracefully

2. **Per-workflow token budget tracking** (lib/ai/token-budget.ts, new file):
   - On chat creation (route.ts:112), initialize Redis key: `token-budget:{chat_id}:daily = 500000` (500K tokens/workflow)
   - After each streamText() completes, retrieve token counts from result: inputTokens + outputTokens
   - Decrement budget: `await redis.decrby('token-budget:{chat_id}:daily', inputTokens + outputTokens)`
   - On next request, check remaining budget: if < 10K, return cached response or fallback instead of new inference

3. **Graceful degradation** (lib/ai/token-budget.ts):
   - If per-workflow budget exhausted, return canned response: "Chat has reached daily token limit. Please start a new chat tomorrow."
   - Do NOT error; do NOT block user; do NOT charge additional tokens
   - Log budget exhaustion to audit trail: user_id, chat_id, timestamp, tokens_consumed

4. **Cost calculation and alerting** (lib/ai/token-budget.ts):
   - Compute cost: tokens * ($3 / 1M tokens)
   - Per-request cost threshold: 50K tokens * $3/1M = $0.15 per request
   - Per-workflow cost threshold: 500K tokens * $3/1M = $1.50 per chat
   - Alert to ops if single request costs >$0.20 (20% overage indicates prompt injection)
   - Alert if daily LLM spend > 2x projected budget

5. **Test canary** (before production):
   - Simulate prompt injection: "call streamText 100 times with 5K-token prompts each"
   - Verify: per-request capped at 50K, per-workflow capped at 500K, total cost <$2.00/attack
   - No runaway costs or budget breach

### Acceptance
- Zero token budget breaches over 30-day production window (all requests respect 50K/request, 500K/workflow limits)
- Cost predictability: monthly LLM spend stays within annual budget envelope (100K-500K annual = 8.3K-41.7K/month)
- Canary test pass: injection payloads terminated at budget boundary, graceful fallback returned
- Alert accuracy: ops receives 0 false positives on budget exhaustion alerts
- No impact to legitimate users: 99% of requests use <20K tokens; only injection attacks hit 50K limit

### Avoid
- Do NOT implement token budgeting at prompt level (prompt can be rewritten; only inference-time limits work)
- Do NOT allow budget override without explicit admin approval logged to audit trail
- Do NOT charge user if budget exceeded (cost is sunk at inference time; prevent future inference instead)
- Do NOT use per-user daily budgets (use per-chat/per-session; prevents cross-chat budget consumption)

### Compliance
OWASP LLM10 (Unbounded Consumption), LLM06 (Excessive Agency), EU AI Act Art.50 (safety and cost governance)

---

## RAI-GOV-44 — AI-Specific RBAC with Policy Enforcement (HIGH)

### What & why
Implement granular role-based access control (RBAC) with policy matrices and privilege escalation prevention for AI tool access. Currently tools are enabled/disabled only at model capability level (experimental_activeTools); no policy gate validates user permission for each tool. This control establishes configuration-driven RBAC matrices binding roles to tools, with centralized policy enforcement at dispatch boundary, preventing privilege escalation and enabling runtime policy changes without redeployment.

### Where
- **Policy configuration:** Environment config or policy management service (read at call time)
- **Policy enforcement:** app/(chat)/api/chat/route.ts:194–235 (before tools passed to streamText)
- **RBAC matrix:** lib/ai/rbac.ts (new file)
- **Audit logging:** Extend lib/db/schema.ts auditLog to include authorization decision

### Change
1. **Define RBAC policy matrix** (lib/ai/rbac.ts, new file):
   - Load from environment: `RBAC_POLICY_JSON` (JSON string, read at call time NOT import time)
   - Policy structure:
     ```json
     {
       "guest": {
         "tools": ["getWeather", "requestSuggestions"],
         "quotas": { "getWeather": 100, "requestSuggestions": 10 }
       },
       "regular": {
         "tools": ["getWeather", "createDocument", "editDocument", "updateDocument", "requestSuggestions"],
         "quotas": { "getWeather": 100, "createDocument": 50, "editDocument": 10, "updateDocument": 5, "requestSuggestions": 10 }
       },
       "admin": {
         "tools": ["getWeather", "createDocument", "editDocument", "updateDocument", "requestSuggestions"],
         "quotas": { "getWeather": 1000, "createDocument": 1000, "editDocument": 1000, "updateDocument": 1000, "requestSuggestions": 1000 }
       }
     }
     ```

2. **Policy enforcement middleware** (lib/ai/rbac.ts):
   - Function authorizeTools(userRole, requestedTools) → { allowedTools, deniedTools }
   - For each tool in experimental_activeTools, check if userRole has permission in policy matrix
   - Return only permitted tools to streamText
   - Log authorization decision: user_id, role, requested_tools, allowed_tools, denied_tools, timestamp

3. **Integrate into chat route** (app/(chat)/api/chat/route.ts, before line 194):
   ```typescript
   const userRole = session.user.type; // "guest" or "regular"
   const requestedTools = ["getWeather", "createDocument", ...];
   const { allowedTools, deniedTools } = await authorizeTools(userRole, requestedTools);
   
   const result = streamText({
     ...
     experimental_activeTools: allowedTools,  // Filtered by policy
     ...
   });
   ```

4. **Quota enforcement** (lib/ai/ratelimit.ts, extend existing):
   - For each tool + user, check daily/hourly quota from RBAC policy
   - Store in Redis: `tool-quota:{user_id}:{tool_name}:day` for daily quotas
   - Before LLM tool dispatch, check if quota exceeded; if yes, remove tool from activeTools
   - Log quota decision: user_id, tool, quota_limit, current_usage, allowed/denied

5. **Denied tool handling** (graceful degradation):
   - If tool denied, do NOT expose error to LLM (prevents tool-discovery via errors)
   - Simply omit denied tools from experimental_activeTools
   - LLM cannot invoke denied tools (they don't exist in available tool set)

6. **Policy audit trail** (extend auditLog table):
   - Log authorization decision on every tool dispatch attempt
   - Include: user_id, role, tool_name, auth_decision (allowed/denied), reason_if_denied (policy mismatch or quota exceeded), timestamp

### Acceptance
- Phase 1 canary (staging, 5 days): Zero false rejections on legitimate authorized tool invocations (100% success rate on permitted tools)
- Phase 1 production: All five tools enforce authorization checks; ast-grep detects zero 'stop.tool-dispatcher-without-policy-gate' findings
- Audit log shows >99.9% of tool authorization attempts with authorization decision recorded
- Quota enforcement: Zero tool calls exceeding per-tool limits over 30-day window
- Test: Attempt createDocument as "guest" role; tool removed from activeTools, LLM cannot invoke

### Avoid
- Do NOT implement authorization checks scattered across individual tool handlers (centralized policy gate required)
- Do NOT make authorization decisions at import time (policy must be read at CALL time for runtime updates)
- Do NOT allow authorization bypass via LLM reasoning or error messages (policy gate is immutable from LLM perspective)
- Do NOT implement overly-complex policy language (keep RBAC simple: role → tool list + quotas)

### Compliance
OWASP A01:2021 (Broken Access Control), GDPR Art.6 (lawfulness), EU AI Act Art.50 (security and transparency)

---

## RAI-GOV-21 — Inter-Agent Authentication & Principal Context Binding (MEDIUM)

### What & why
Establish per-agent (per-tool in single-agent context) identity verification and principal context binding to prevent impersonation attacks where LLM could invoke tools on behalf of different users. Current implementation uses NextAuth session for user context but does NOT bind this context to tool execution or re-validate at execution boundaries. Control ensures user identity from session is propagated through tool invocation and re-validated within each handler, preventing context-swapping where LLM could manipulate context to escalate privileges.

### Where
- **Session context capture:** app/(chat)/api/chat/route.ts:89 (session.user.id available)
- **Tool invocation:** Passed to tool handlers via session parameter (lib/ai/tools/*.ts)
- **Context validation:** Each tool handler execute() method (lines 31, 33, 29, 43, etc.)

### Change
1. **Principal context object** (lib/ai/context.ts, new file):
   - Create type ExecutionContext = { userId: string, userRole: string, sessionId: string, timestamp: Date, requestId: string }
   - Derive from NextAuth session at route.ts:89: `const context = { userId: session.user.id, userRole: session.user.type, sessionId: request.headers.get('x-session-id'), timestamp: new Date(), requestId: request.id }`
   - Pass context through to all tool handlers

2. **Propagate context to tool handlers** (app/(chat)/api/chat/route.ts:217–235):
   - When instantiating tool functions, pass context as parameter (already passing session, extend with explicit context)
   - Each tool receives: `{ session, context, dataStream }`

3. **Validate context at execution boundary** (each tool, e.g., lib/ai/tools/edit-document.ts:31):
   ```typescript
   execute: async ({ id, old_string, new_string, replace_all }) => {
     // Re-validate principal context
     if (!context.userId || typeof context.userId !== 'string') {
       throw new Error('Invalid execution context');
     }
     
     const document = await getDocumentById({ id });
     if (document.userId !== context.userId) {
       // Log security event: context mismatch
       await logSecurityEvent('context_mismatch', { documentUserId: document.userId, contextUserId: context.userId });
       return { error: 'Forbidden' };
     }
     
     // Rest of execution with validated context
   }
   ```

4. **Log context validation** (extend auditLog):
   - On each tool invocation, log: user_id from context, user_id from document/resource, match status (matched/mismatched)
   - Mismatches indicate potential privilege escalation attempt; flag as security event

5. **Multi-step execution context re-validation:**
   - For tools that call other tools internally (e.g., requestSuggestions calls streamText), re-validate context at each boundary
   - Prevent context swapping mid-execution via LLM loop

### Acceptance
- Each tool invocation includes authenticated user ID in execution context
- Context validation occurs at every tool execution boundary (100% of handlers re-validate)
- Audit log associates 100% of tool invocations with verified principal (user_id from context matches document owner)
- Zero cross-user tool invocations detected (user A cannot trigger actions on user B's documents via LLM injection)
- Test: Attempt prompt injection to invoke tool under different user context; execution must fail with audit alert

### Avoid
- Do NOT propagate session.user blindly to tools without re-validation (session can be manipulated in-memory)
- Do NOT skip context validation for "trusted" tools (all tools must validate principal)
- Do NOT allow tool to override context (context is read-only within execution)
- Do NOT log context validation only on failure (log all validations for complete audit trail)

### Compliance
EU AI Act Art.50 (principal accountability), SOC 2 Type II (access control audit)

---

## stop.tool-dispatcher-without-policy-gate — Tool Authorization Not Enforced (5 findings)

### What & why
Scanner detected tool dispatch without centralized policy gate across all five tools: requestSuggestions (lib/ai/tools/request-suggestions.ts:30), updateDocument (lib/ai/tools/update-document.ts:28), getWeather (lib/ai/tools/get-weather.ts:42), editDocument (lib/ai/tools/edit-document.ts:30), createDocument (lib/ai/tools/create-document.ts:32). Individual handlers validate document ownership or session but lack unified authorization framework. LLM-generated tool calls bypass broader policy enforcement (role checks, quota enforcement, audit logging). Control requires centralized reference monitor at tool dispatch boundary (before handlers execute).

### Where
- **Root cause:** app/(chat)/api/chat/route.ts:194–235 (tools passed to streamText without authorization filtering)
- **Individual findings:**
  - lib/ai/tools/request-suggestions.ts:30 (execute handler, line 31 entry)
  - lib/ai/tools/update-document.ts:28 (execute handler, line 29 entry)
  - lib/ai/tools/get-weather.ts:42 (execute handler, line 43 entry)
  - lib/ai/tools/edit-document.ts:30 (execute handler, line 31 entry)
  - lib/ai/tools/create-document.ts:32 (execute handler, line 33 entry)

### Change
**Same as RAI-GOV-44 above.** Implement centralized RBAC policy gate at app/(chat)/api/chat/route.ts:194 (before streamText receives tools array), filtering experimental_activeTools based on user role and policy matrix. This single upstream fix addresses all five findings.

Implementation specifics:
1. Create lib/ai/rbac.ts with authorizeTools(userRole, requestedTools) function
2. Before streamText call (line 194), filter: `experimental_activeTools = allowedTools`
3. Log authorization decision to audit trail (user_id, role, tools_allowed/denied)
4. Tools not in allowedTools array are invisible to LLM (cannot be invoked)

### Acceptance
- Zero unauthorized tool invocations from LLM output
- All five tool handlers inherit authorization constraint from dispatcher (no per-handler overrides)
- Audit log shows authorization decision on every tool dispatch attempt
- ast-grep "stop.tool-dispatcher-without-policy-gate" returns zero findings post-deployment

### Avoid
- Do NOT add authorization checks to individual tool handlers as primary defense (fixing at dispatcher prevents bypass)
- Do NOT leave tools in experimental_activeTools if user lacks permission (must filter upstream)
- Do NOT implement separate policy gates for each tool (single unified gate required)

### Compliance
OWASP A01:2021 (Broken Access Control), GDPR Art.6 (lawfulness)

---

# Excluded (not code-fixable)

The following controls are non-code and require organizational/infrastructure changes outside application scope:

- **RAI-BF-02 (partial):** Anti-discrimination governance framework is organizational policy + process; code supports it via audit logging, but policy development, remediation playbooks, quarterly audits, and transparency reporting are governance decisions requiring legal/compliance/product alignment (see RAI-BF-02 section for process components)
- **RAI-ACC-10 (partial):** Incident forensics dashboard and CLI tooling are operational/analytics infrastructure; code provides data correlation, but incident response runbook, MTTR targets, and cross-functional escalation procedures are ops decisions
- **Deployment monitoring & alerting:** While controls log to audit trails, setting up Azure Application Insights, Datadog, or CloudTrail configurations is infrastructure/deployment scope (not application code)
- **Data retention & archival policy:** Configuring database backups, CloudTrail S3 bucket immutability, and 7-year retention schedules is DevOps/compliance scope (not application code)
- **Key rotation automation:** While code supports cryptographic signing, automated monthly key rotation via Azure Key Vault is infrastructure (not application code)