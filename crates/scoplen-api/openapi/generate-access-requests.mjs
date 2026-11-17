// SPDX-License-Identifier: Apache-2.0
// D-150 exact single-Host access-request contract.
import { isDeepStrictEqual } from "node:util";

const ref = name => ({ $ref: `#/components/schemas/${name}` });
const responseRef = name => ({ $ref: `#/components/responses/${name}` });
const object = (properties, request = false) => ({ type: "object", additionalProperties: !request, required: Object.keys(properties), properties });
const nullable = schema => ({ anyOf: [schema, { type: "null" }] });
const uuid = { type: "string", format: "uuid", pattern: "^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$" };
const etag = { type: "string", pattern: '^"[!#-~]*"$', minLength: 2, maxLength: 256 };
const timestamp = { type: "string", format: "date-time", pattern: "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-5][0-9](\\.[0-9]+)?Z$", description: "A valid UTC calendar timestamp; preserve optional fractional seconds without rounding or truncation." };
const grantTime = { type: "string", format: "date-time", pattern: "^[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])T([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]Z$", minLength: 20, maxLength: 20, description: "Valid whole-second UTC calendar timestamp with Unix seconds 0..253402300799; no fraction, offset or leap second." };
const headers = {
  "Cache-Control": { required: true, schema: { type: "string", const: "no-store" } },
  Pragma: { required: true, schema: { type: "string", const: "no-cache" } },
  "X-Request-ID": { required: true, schema: { type: "string", minLength: 1 } },
};
const org = { name: "org", in: "path", required: true, schema: uuid };
const id = { name: "id", in: "path", required: true, schema: uuid };
const idempotency = { name: "Idempotency-Key", in: "header", required: true, schema: uuid };
const ifMatch = { name: "If-Match", in: "header", required: true, schema: etag, description: "Exactly one original strong ETag; reject weak validators, wildcard and multiple values. Never silently refresh or substitute it." };
const request = schema => ({ required: true, description: "Complete strict UTF-8 JSON <=4096 bytes including whitespace. Reject BOM, recursive duplicate names, unknown, missing, null and mistyped fields.", content: { "application/json": { schema: ref(schema) } } });
const success = (schema, maximum, individual = false) => ({
  description: `Complete encoded UTF-8 JSON <=${maximum} bytes including whitespace and bounded extensions; reject recursive duplicate names.${individual ? " HTTP ETag exactly equals body etag; bind id to the captured request." : ""}`,
  headers: { ...headers, ...(individual ? { ETag: { required: true, schema: etag, description: "Strong validator exactly equal to body etag." } } : {}) },
  content: { "application/json": { schema: ref(schema) } },
});
const storage = mutation => ({
  description: mutation ? "Confirmed rollback is changed=false/retryable=true. Unconfirmed COMMIT is organization.commit_outcome_unknown, changed=true/retryable=true, permitting only explicit original-key, original-payload and original-If-Match confirmation within 24 hours with fresh DPoP; no automatic retry, replacement ETag or success claim." : "Storage or evaluation failure is changed=false/retryable=true; never return a false eligibility answer or a partial success.",
  headers,
  content: { "application/problem+json": { schema: mutation ? { oneOf: [ref("OrganizationStorageUnavailableProblem"), ref("OrganizationCommitOutcomeUnknownProblem")] } : ref("OrganizationStorageUnavailableProblem") } },
});
const failures = (mutation = false) => ({
  "400": responseRef("OrganizationInvalidRequest"), "401": responseRef("OrganizationAuthenticationRequired"),
  "403": responseRef("OrganizationDenied"), "404": responseRef("OrganizationNotFound"),
  ...(mutation ? { "409": responseRef("OrganizationConflict") } : {}),
  "503": storage(mutation),
  default: { description: "Shared complete problem <=4096 encoded bytes with no sensitive request payload.", headers, content: { "application/problem+json": { schema: ref("ProblemDetails") } } },
});
const bodyFailures = { "413": responseRef("AccessRequestBodyTooLarge"), "415": responseRef("OrganizationContentType") };
const conditionalFailures = { "412": responseRef("OrganizationPreconditionFailed"), "428": responseRef("OrganizationPreconditionRequired") };
const base = "Require HTTPS, current active Account and Device or real Account-browser family, exact operation scope, token-bound actual-method/trusted-URL DPoP with durable replay protection, and current active same-team Membership. JWT snapshots and historical requester ids grant no authority. Foreign, missing and unreadable resources share the static Organization 404 boundary. Browser credentials=omit; supplied Origin must match the trusted deployment origin. No cookie authentication, synthetic Device or refresh-cookie read/change. ";
const eligibility = "Require one live same-team Host, independent current view_inventory and complete request_access evaluation with submitted duration/reason. Validate and bind the exact remote_user; the existing request_access schema has no remote_user context and does not constrain it. No connect decision, policy solver, other-principal evaluation, approver directory/count, reservation or authority is returned. ";
const routing = "Current routing requires complete approve_access Allow on the trusted stored AccessRequest projection, independent Host view_inventory and caller inequality with the requester, including for Owner. No view_policy is required. ";
const receipt = "Check current caller identity, scope and Organization authority before protected preconditions or receipt lookup. A 24-hour original UUIDv7 receipt binds trusted origin, Account, original Device or real browser family, actual method/path, id, canonical typed payload and original If-Match when required. Exact confirmation returns immutable original bytes without another request, decision, Grant or audit; changed binding/payload or reused id without its receipt conflicts. Never resurrect state, recreate a withdrawn Grant or issue/renew a certificate. ";
const collection = "/orgs/{org}/access-requests";
const item = `${collection}/{id}`;

export function accessRequestDefinitions() {
  const fields = object({
    host: uuid,
    remote_user: { type: "string", minLength: 1, maxLength: 255, "x-scoplen-max-utf8-bytes": 255, description: "Exact SSH remote username, 1..255 UTF-8 bytes with no Unicode control characters; preserve without trimming or normalization." },
    duration_seconds: { type: "integer", minimum: 1, maximum: 86400, description: "Requested finite access interval, not a promise of one certificate of this length." },
    reason: { type: "string", minLength: 1, maxLength: 2048, "x-scoplen-max-utf8-bytes": 2048, description: "1..2048 UTF-8 bytes with a non-whitespace character; reject Unicode control characters except LF/TAB. Preserve text without trimming or normalization; do not log it." },
  }, true);
  const schemas = {
    AccessRequestFields: fields,
    AccessRequestCheckRequest: { ...object({ data: ref("AccessRequestFields") }, true), "x-scoplen-max-bytes": 4096 },
    AccessRequestCheckResponse: { ...object({ allowed: { type: "boolean" } }), "x-scoplen-max-bytes": 4096 },
    AccessRequestCreateRequest: { ...object({ id: uuid, data: ref("AccessRequestFields") }, true), "x-scoplen-max-bytes": 4096 },
    AccessRequestDecisionRequest: { ...object({ decision: { type: "string", enum: ["approve", "deny"] } }, true), "x-scoplen-max-bytes": 4096 },
    AccessRequestStatus: { type: "string", pattern: "^[a-z][a-z0-9_]*$", minLength: 1, maxLength: 64, description: "Initial emitted states: pending, approved, denied, expired, cancelled. revoked is reserved for a later profile. Preserve bounded unknown text as Unknown with no mutation or authority; approved history does not establish current permission." },
    AccessRequestView: { type: "string", enum: ["mine", "approvals"] },
    AccessRequestDecision: object({ outcome: { type: "string", enum: ["approve", "deny"] }, actor_account_id: uuid, decided_at: timestamp }),
    AccessRequestGrant: { ...object({ id: uuid, valid_from: grantTime, valid_until: grantTime }), description: "Original finite D-147 Grant history. valid_from equals floor(decision.decided_at to a whole Unix second); valid_until equals valid_from + duration_seconds, with checked calendar arithmetic. Current Grant and certificate authority must still be reread before Connect." },
    AccessRequestResource: {
      ...object({ id: uuid, etag, created_at: timestamp, updated_at: timestamp, data: object({
        requester_account_id: uuid, requester_membership_id: uuid, ...fields.properties,
        expires_at: timestamp, status: ref("AccessRequestStatus"),
        decision: nullable(ref("AccessRequestDecision")), grant: nullable(ref("AccessRequestGrant")),
      }) }),
      "x-scoplen-max-bytes": 8192,
      description: "Require expires_at = created_at +86400 seconds, preserving the exact fractional instant without rounding/truncation. pending/expired/cancelled have null decision and grant; denied has a deny decision and null grant; approved has an approve decision and finite bound Grant. Readers and encoders enforce these cross-field invariants, including approval-time anchoring, not merely interval length. Unknown status is inert. Persisted pending status/ETag can remain after its deadline until worker expiry; deadline independently disables actions. Pending references guard Host deletion; terminal request history alone does not. An approved current Grant retains its independent lifecycle guards.",
    },
    AccessRequestPage: {
      ...object({ items: { type: "array", maxItems: 500, items: ref("AccessRequestResource"), description: "Distinct ascending UUIDv7 ids beyond the captured cursor; each original encoded item, including extensions and whitespace, is <=8192 bytes. A shorter nonempty prefix may satisfy the complete Page budget." }, next_cursor: { ...nullable(uuid), description: "Non-null only when more eligible items exist and exactly equal to the nonempty Page's final id." } }),
      "x-scoplen-max-bytes": 4194304,
    },
    AccessRequestBodyTooLargeProblem: { allOf: [ref("ProblemDetails"), { type: "object", properties: { status: { const: 413 }, code: { const: "organization.invalid_request" }, changed: { const: false }, retryable: { const: false } } }] },
  };
  const responses = {
    AccessRequestCheckResponse: success("AccessRequestCheckResponse", 4096),
    AccessRequestResource: success("AccessRequestResource", 8192, true),
    AccessRequestPage: success("AccessRequestPage", 4194304),
    AccessRequestBodyTooLarge: { description: "413 organization.invalid_request; changed=false/retryable=false. Complete problem <=4096 encoded bytes.", headers, content: { "application/problem+json": { schema: ref("AccessRequestBodyTooLargeProblem") } } },
  };
  const operation = (operationId, scope, maximum, description, parameters, response, mutation = false) => ({
    operationId, "x-scoplen-required-device-scope": scope, "x-scoplen-required-browser-scope": scope,
    "x-scoplen-response-max-bytes": maximum, description: base + description, parameters,
    responses: { [response === "AccessRequestCreated" ? "201" : "200"]: responseRef(response === "AccessRequestCreated" ? "AccessRequestResource" : response), ...failures(mutation) },
    security: [{ accessToken: [], dpopProof: [] }, { accountBrowserAccess: [], dpopProof: [] }],
    "x-scoplen-fetch-credentials": "omit", "x-scoplen-problem-max-bytes": 4096,
  });
  const check = operation("checkOrganizationAccessRequest", "access-requests:write", 4096,
    eligibility + "A complete policy Deny returns allowed=false; evaluation/storage failure remains a problem. Creation rechecks eligibility. Reject every query, If-Match and Idempotency-Key.", [org], "AccessRequestCheckResponse");
  const create = operation("createOrganizationAccessRequest", "access-requests:write", 8192,
    eligibility + receipt + "New creation rechecks eligibility under its committing transaction; Deny is 403 policy.denied. Persist one pending request, original receipt and attributable authorization audit atomically. The fixed pending deadline is exactly creation +86400 seconds. Historical confirmation requires current requester read authority and does not recheck fresh creation eligibility or replace current status. No approver pre-discovery is required. Reject every query and If-Match.", [org, idempotency], "AccessRequestCreated", true);
  const list = operation("listOrganizationAccessRequests", "access-requests:read", 4194304,
    routing + "Required view=mine selects only the current Account's requests. view=approvals selects only unexpired pending requests satisfying current routing. No directory/count leakage or generic filter/sort. Reject body, duplicate/unknown query names, If-Match and Idempotency-Key.", [org,
      { name: "view", in: "query", required: true, schema: ref("AccessRequestView") },
      { name: "limit", in: "query", required: false, schema: { type: "integer", minimum: 1, maximum: 500, default: 50 } },
      { name: "cursor", in: "query", required: false, schema: uuid },
    ], "AccessRequestPage");
  const read = operation("getOrganizationAccessRequest", "access-requests:read", 8192,
    routing + "Return only to the current requester Account or a caller satisfying current routing. Historical requester Membership/id is not authority. Reject body, every query, If-Match and Idempotency-Key.", [org, id], "AccessRequestResource");
  const decide = operation("decideOrganizationAccessRequest", "access-requests:decide", 8192,
    routing + receipt + "Recheck the requester's current active Account, exact original active Membership, live same-team Host, requester view_inventory and request_access with original duration/reason in the committing transaction. Never substitute the request tuple or allow self-approval. Only pending before its deadline can receive a first decision; stale eligibility, terminal state or deadline is 409 organization.conflict. Approve atomically creates exactly one finite D-147 Grant for original Membership/Host/remote_user, trusted approval time floored to a whole Unix second plus duration, view revision, receipt and both request-approved/Grant-created audit events. No manage_policy permission is needed. Deny creates no Grant or view revision. Required audit failure rolls back all changes. Exact confirmation still requires current routing and never reissues access. Reject every query.", [org, id, ifMatch, idempotency], "AccessRequestResource", true);
  const cancel = operation("cancelOrganizationAccessRequest", "access-requests:write", 8192,
    receipt + "Only the current requester Account may cancel its own pending intent before the deadline; current request_access and Host visibility are not required. Terminal/deadline conflict is 409 organization.conflict. Commit cancellation, original receipt and one attributable audit atomically, with no Grant or view revision. Exact confirmation requires current requester authority. No request edit/delete, new notification event, immediate certificate revocation or session termination. Reject body and every query.", [org, id, ifMatch, idempotency], "AccessRequestResource", true);
  for (const [entry, schema] of [[check, "AccessRequestCheckRequest"], [create, "AccessRequestCreateRequest"], [decide, "AccessRequestDecisionRequest"]]) {
    entry["x-scoplen-request-max-bytes"] = 4096;
    entry.requestBody = request(schema);
    Object.assign(entry.responses, bodyFailures);
  }
  for (const entry of [decide, cancel]) Object.assign(entry.responses, conditionalFailures);
  check["x-scoplen-cedar-action"] = "request_access";
  create["x-scoplen-cedar-action"] = "request_access";
  decide["x-scoplen-cedar-action"] = "approve_access";
  return { schemas, responses, paths: { [collection]: { get: list, post: create }, [item]: { get: read }, [`${collection}/check`]: { post: check }, [`${item}/decisions`]: { post: decide }, [`${item}/cancel`]: { post: cancel } } };
}

export function generateAccessRequestTypes(document) {
  const expected = accessRequestDefinitions();
  for (const name of ["AccessRequest", "AccessDecision", "DecisionRequest"]) if (Object.hasOwn(document.components?.schemas ?? {}, name)) throw new Error(`D-150 provisional ${name} schema retained`);
  if (!isDeepStrictEqual(Object.keys(document.paths ?? {}).filter(path => path.startsWith(collection)).sort(), Object.keys(expected.paths).sort())) throw new Error("D-150 access-request path coverage differs");
  for (const [section, values] of Object.entries(expected)) {
    const actual = section === "paths" ? document.paths : document.components?.[section];
    for (const [name, value] of Object.entries(values)) if (!isDeepStrictEqual(actual?.[name], value)) throw new Error(`D-150 ${section}.${name} differs from its exact access-request contract`);
  }
  return [
    "export interface AccessRequestFields { host: string; remote_user: string; duration_seconds: number; reason: string; }",
    "export interface AccessRequestCheckRequest { data: AccessRequestFields; }",
    "export interface AccessRequestCheckResponse { allowed: boolean; [extension: string]: unknown; }",
    "export interface AccessRequestCreateRequest { id: string; data: AccessRequestFields; }",
    'export interface AccessRequestDecisionRequest { decision: "approve" | "deny"; }',
    "/** Preserve unknown bounded status text for display only; it supplies no action or authority. */",
    'export type AccessRequestStatus = "pending" | "approved" | "denied" | "expired" | "cancelled" | (string & {});',
    'export type AccessRequestView = "mine" | "approvals";',
    'export interface AccessRequestDecision { outcome: "approve" | "deny"; actor_account_id: string; decided_at: string; [extension: string]: unknown; }',
    "/** Finite approval history, never evidence of current Grant or certificate authority. */",
    "export interface AccessRequestGrant { id: string; valid_from: string; valid_until: string; [extension: string]: unknown; }",
    "/** Cross-field time/state invariants are validated by the shared codec, not these structural types. */",
    "export interface AccessRequestResource {",
    "  id: string; etag: string; created_at: string; updated_at: string;",
    "  data: AccessRequestFields & { requester_account_id: string; requester_membership_id: string; expires_at: string; status: AccessRequestStatus; decision: AccessRequestDecision | null; grant: AccessRequestGrant | null; [extension: string]: unknown };",
    "  [extension: string]: unknown;", "}",
    "export interface AccessRequestPage { items: AccessRequestResource[]; next_cursor: string | null; [extension: string]: unknown; }",
    "export interface AccessRequestListQuery { view: AccessRequestView; limit?: number; cursor?: string; }",
    'export type AccessRequestBodyTooLargeProblem = ProblemDetails & { status: 413; code: "organization.invalid_request"; changed: false; retryable: false; };', "",
  ].join("\n");
}
