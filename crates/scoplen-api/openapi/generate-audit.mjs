// SPDX-License-Identifier: Apache-2.0
import { isDeepStrictEqual } from "node:util";

const ref = name => ({ $ref: `#/components/schemas/${name}` });
const object = properties => ({ type: "object", additionalProperties: true, required: Object.keys(properties), properties });
const nullable = schema => ({ anyOf: [schema, { type: "null" }] });
const uuid = { type: "string", format: "uuid", pattern: "^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$" };
const sequence = { type: "string", pattern: "^[1-9][0-9]{0,19}$", maxLength: 20, description: "Canonical positive uint64 decimal string <=18446744073709551615; never a JSON number." };
const count = { ...sequence, pattern: "^(0|[1-9][0-9]{0,19})$", description: "Canonical uint64 decimal string including zero; never rounded through a JavaScript number." };
const hash = { type: "string", pattern: "^[0-9a-f]{64}$", minLength: 64, maxLength: 64 };
const timestamp = { type: "string", format: "date-time", pattern: "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-5][0-9](\\.[0-9]{0,2}[1-9])?Z$", maxLength: 24, description: "Valid UTC calendar; exact integer Unix milliseconds. Omit zero fraction; otherwise trim only trailing zeroes from three millisecond digits. No rounding, offsets, leap seconds or sub-millisecond precision. Stored event and checkpoint instants are positive." };
const eventClass = { type: "string", minLength: 1, maxLength: 128, pattern: "^[a-z][a-z0-9_-]*(\\.[a-z][a-z0-9_-]*)+$" };
const outcomes = ["success", "failure", "unknown"];
const kinds = ["organization", "invitation", "membership", "host", "host_group", "access_profile", "route", "trust_record", "snippet", "gateway_network", "group", "policy", "grant", "access_request", "auth_connection_draft", "certificate_authority", "certificate"];
const headers = {
  "Cache-Control": { required: true, schema: { type: "string", const: "no-store" } },
  Pragma: { required: true, schema: { type: "string", const: "no-cache" } },
  "X-Request-ID": { required: true, schema: { type: "string", minLength: 1 } },
};

export function auditDefinitions() {
  const schemas = {
    AuditResource: object({ kind: { type: "string", enum: kinds }, id: uuid }),
    AuditEvent: { ...object({
      organization_id: uuid, sequence, occurred_at: timestamp,
      category: { type: "string", enum: ["authentication", "authorization", "account_change", "scoplen", "unknown"] },
      event_class: nullable(eventClass), outcome: { type: "string", enum: outcomes },
      actor_account_id: nullable(uuid), actor_device_id: nullable(uuid), actor_browser_family_id: nullable(uuid),
      resource: nullable(ref("AuditResource")), previous_hash: hash, event_hash: hash,
    }), "x-scoplen-max-bytes": 2048, description: "Organization plus sequence is identity. Safe immutable projection, never raw original event/request bytes, secrets or current-directory identity inference. Missing/unclassified historical metadata remains null/unknown; no cryptographic claim is derived from this JSON." },
    AuditPage: { ...object({ items: { type: "array", maxItems: 500, items: ref("AuditEvent") }, next_cursor: nullable(sequence) }), "x-scoplen-max-bytes": 1048576, description: "Strictly decreasing unique sequences, below requested cursor and within requested filters/Organization/limit. Each original item including extensions/whitespace <=2048 bytes. Nonnull continuation equals the last nonempty item only when more matching rows exist." },
    AuditCheckpoint: object({ sequence, head_hash: hash, signed_at: timestamp, signature: { type: "string", minLength: 86, maxLength: 86, pattern: "^[A-Za-z0-9_-]{85}[AQgw]$", description: "Original 64-byte Ed25519 signature, canonical unpadded base64url. Verify using the already configured independent audit key; no key from this response." } }),
    AuditVerification: { ...object({ organization_id: uuid, from_sequence: sequence, to_sequence: sequence,
      checked_events: count, valid: { type: "boolean" }, failure_sequence: nullable(sequence),
      previous_hash: nullable(hash), head_hash: nullable(hash), checkpoint: nullable(ref("AuditCheckpoint")),
      uncheckpointed_from_sequence: nullable(sequence),
    }), "x-scoplen-max-bytes": 4096, description: "Bind Organization/range to request. Success has full inclusive checked count, null failure, both hashes and interval-only checkpoint coverage. Failure has first failed selected sequence, checked_events=failure-from and null hashes/checkpoint/coverage. Predecessor failure is from/count0. Highest included checkpoint determines unsigned suffix; absence does not prove no later checkpoint exists. Genesis predecessor is zero; ending checkpoint equals head_hash. Storage failure is a problem." },
  };
  const responses = {};
  for (const [name, status, code, retryable] of [
    ["AuditInvalidRequest", 400, "organization.invalid_request", false],
    ["AuditTooLarge", 413, "organization.invalid_request", false],
    ["AuditDenied", 403, "policy.denied", false],
    ["AuditNotFound", 404, "organization.not_found", false],
    ["AuditStorageUnavailable", 503, "organization.storage_unavailable", true],
  ]) responses[name] = { description: "Read failure; no business-state mutation. Unknown historical metadata is retained, not a storage error. Query mandatory transport metadata failures are whole-request 503; determined range integrity failures return a negative result.", headers, "x-scoplen-response-max-bytes": 4096, content: { "application/problem+json": { schema: { allOf: [ref("ProblemDetails"), { properties: { status: { const: status }, code: { const: code }, changed: { const: false }, retryable: { const: retryable } } }] } } } };
  const failures = { "400": { $ref: "#/components/responses/AuditInvalidRequest" }, "401": { $ref: "#/components/responses/AccountEntryAuthenticationRequired" }, "403": { $ref: "#/components/responses/AuditDenied" }, "404": { $ref: "#/components/responses/AuditNotFound" }, "413": { $ref: "#/components/responses/AuditTooLarge" }, "429": { $ref: "#/components/responses/AccountEntryRateLimited" }, "503": { $ref: "#/components/responses/AuditStorageUnavailable" }, default: { $ref: "#/components/responses/Problem" } };
  const common = {
    tags: ["Audit"], security: [{ accessToken: [], dpopProof: [] }, { accountBrowserAccess: [], dpopProof: [] }],
    "x-scoplen-required-device-scope": "audit:read", "x-scoplen-required-browser-scope": "audit:read",
    "x-scoplen-problem-max-bytes": 4096, "x-scoplen-fetch-credentials": "omit",
    description: "Require exact audit:read, fresh token-bound actual-method/URL DPoP, current Account/Device or browser family, active same-Organization Membership and trusted Cedar view_audit. Existing Owner/Security auditor permits remain; Administrator has no implicit permit. Operator/deployment/Personal-history access is excluded. Reject body, unknown/repeated query names, If-Match and Idempotency-Key; cookie authentication is forbidden. Supplied Origin must equal trusted deployment origin. No refresh cookie is read/set/changed; older refresh ceilings never widen. Recursive duplicate fields, malformed UTF-8/BOM and complete-body overflow fail locally. No export, event mutation or signed cursor.",
  };
  const org = { name: "org", in: "path", required: true, schema: uuid };
  const paths = {
    "/orgs/{org}/audit-events": { get: { ...common, operationId: "listAuditEvents",
      "x-scoplen-query-max-bytes": 4096, "x-scoplen-response-max-bytes": 1048576,
      parameters: [org,
        { name: "limit", in: "query", required: false, schema: { type: "integer", minimum: 1, maximum: 500, default: 50 } },
        { name: "cursor", in: "query", required: false, schema: sequence },
        { name: "sort", in: "query", required: false, schema: { type: "string", const: "-sequence" } },
        { name: "filter", in: "query", required: false, schema: { type: "string", maxLength: 2048 }, description: 'Decoded ASCII, <=6 AND-only clauses joined by exactly " and ". Exact single spaces and quoted values, no escapes. occurred_at ge/lt "<normalized UTC>"; actor_account_id eq "<UUIDv7>"; resource eq "<kind>:<UUIDv7>"; event_class eq "<safe class>"; outcome eq "success|failure|unknown". Each field/operator once, upper time later than lower. No OR, parentheses, free text or inference. Decode URL once and use typed parameterized queries.' },
      ], responses: { "200": { description: "Bounded immutable audit Page, request-bound descending continuation.", headers, content: { "application/json": { schema: ref("AuditPage") } } }, ...failures },
    } },
    "/orgs/{org}/audit-events/verify": { get: { ...common, operationId: "verifyAuditChain",
      "x-scoplen-query-max-bytes": 128, "x-scoplen-response-max-bytes": 4096,
      "x-scoplen-max-range-events": 4096, "x-scoplen-max-original-event-bytes": 16777216,
      description: common.description + " Exactly from_sequence/to_sequence; contiguous inclusive range, no filtered-row verification. Snapshot chain extent includes checkpoint positions. Stream original rows and immediate predecessor under both bounds, check genesis, gaps, hashes/links and every included checkpoint's exact original signed payload. Exceeding either bound is 413 without partial evidence. Adjacent successful chunks join only at consecutive positions and equal boundary hashes; coverage remains interval-only. No whole-chain collection, new trust roots, jobs or receipts.",
      parameters: [org, ...["from_sequence", "to_sequence"].map(name => ({ name, in: "query", required: true, schema: sequence }))],
      responses: { "200": { description: "Bounded request-bound integrity result with honest included-checkpoint coverage.", headers, content: { "application/json": { schema: ref("AuditVerification") } } }, ...failures },
    } },
  };
  return { schemas, responses, paths };
}

export function generateAuditTypes(document) {
  const expected = auditDefinitions();
  for (const [section, values] of Object.entries(expected)) {
    const actual = section === "paths" ? document.paths : document.components?.[section];
    for (const [name, value] of Object.entries(values)) if (!isDeepStrictEqual(actual?.[name], value)) throw new Error(`D-144 ${section}.${name} drift`);
  }
  if (document.paths["/orgs/{org}/audit-events/{id}"] || document.components.schemas.Verification) throw new Error("D-144 provisional mutable/UUID audit API retained");
  return [
    `export type AuditResourceKind = ${kinds.map(k => JSON.stringify(k)).join(" | ")};`,
    'export type AuditCategory = "authentication" | "authorization" | "account_change" | "scoplen" | "unknown";',
    'export type AuditOutcome = "success" | "failure" | "unknown";',
    "export interface AuditResource { kind: AuditResourceKind; id: string; [extension: string]: unknown; }",
    "/** Sequence values are exact decimal strings. This safe projection supplies no cryptographic proof. */",
    "export interface AuditEvent { organization_id: string; sequence: string; occurred_at: string; category: AuditCategory; event_class: string | null; outcome: AuditOutcome; actor_account_id: string | null; actor_device_id: string | null; actor_browser_family_id: string | null; resource: AuditResource | null; previous_hash: string; event_hash: string; [extension: string]: unknown; }",
    "export interface AuditPage { items: AuditEvent[]; next_cursor: string | null; [extension: string]: unknown; }",
    "export interface AuditListQuery { limit?: number; cursor?: string; sort?: \"-sequence\"; filter?: string; }",
    "export interface AuditRangeQuery { from_sequence: string; to_sequence: string; }",
    "/** Uses the deployment's existing audit key; signed_at preserves the exact integer signed milliseconds. */",
    "export interface AuditCheckpoint { sequence: string; head_hash: string; signed_at: string; signature: string; [extension: string]: unknown; }",
    "/** Coverage refers only to checkpoints included in the checked interval. */",
    "export interface AuditVerification { organization_id: string; from_sequence: string; to_sequence: string; checked_events: string; valid: boolean; failure_sequence: string | null; previous_hash: string | null; head_hash: string | null; checkpoint: AuditCheckpoint | null; uncheckpointed_from_sequence: string | null; [extension: string]: unknown; }", "",
  ].join("\n");
}
