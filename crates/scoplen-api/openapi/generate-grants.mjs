// SPDX-License-Identifier: Apache-2.0
// D-147 named-Membership Host grants; these DTOs establish no current authority.
import { isDeepStrictEqual } from "node:util";

const ref = name => ({ $ref: `#/components/schemas/${name}` });
const responseRef = name => ({ $ref: `#/components/responses/${name}` });
const object = (properties, request = false) => ({ type: "object", additionalProperties: !request, required: Object.keys(properties), properties });
const uuid = { type: "string", format: "uuid", pattern: "^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$" };
const etag = { type: "string", pattern: '^"[!#-~]*"$', minLength: 2, maxLength: 256 };
const metadataTime = { type: "string", format: "date-time", pattern: "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-5][0-9](\\.[0-9]+)?Z$", description: "A valid UTC calendar timestamp." };
const validityTime = { type: "string", format: "date-time", pattern: "^[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])T([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]Z$", minLength: 20, maxLength: 20, description: "Valid Gregorian UTC whole-second YYYY-MM-DDTHH:MM:SSZ, Unix seconds 0..253402300799 inclusive; no fraction, offset or leap second." };
const remoteUser = { type: "string", minLength: 1, maxLength: 255, "x-scoplen-max-utf8-bytes": 255, description: "1..255 UTF-8 bytes without Unicode control characters; preserve exact text without trimming or normalization." };
const fields = {
  membership: { ...uuid, description: "Current active same-Organization Membership, never an Account id or username." },
  host: { ...uuid, description: "Current live same-Organization Host." },
  remote_user: remoteUser,
  valid_from: validityTime,
  valid_until: { anyOf: [validityTime, { type: "null" }], description: "Mandatory explicit null for no expiry, otherwise strictly later than valid_from. Future and expired intervals are accepted; no arbitrary duration maximum." },
};
const headers = {
  "Cache-Control": { required: true, schema: { type: "string", const: "no-store" } },
  Pragma: { required: true, schema: { type: "string", const: "no-cache" } },
  "X-Request-ID": { required: true, schema: { type: "string", minLength: 1 } },
};
const org = { name: "org", in: "path", required: true, schema: uuid };
const id = { name: "id", in: "path", required: true, schema: uuid };
const key = { name: "Idempotency-Key", in: "header", required: true, schema: uuid };
const match = { name: "If-Match", in: "header", required: true, description: "Exactly one captured original strong ETag, never weak, wildcard or multiple; no automatic ETag substitution or resubmission.", schema: etag };
const request = name => ({ required: true, description: "Complete UTF-8 JSON <=4096 bytes, including whitespace; reject recursive duplicate names and unknown, missing, mistyped or null fields except valid_until.", content: { "application/json": { schema: ref(name) } } });
const success = (name, individual) => ({
  description: `Complete JSON <=${individual ? 4096 : 2097152} bytes, including extensions and whitespace; require all known fields and tolerate bounded extensions. ${individual ? "HTTP ETag exactly equals body etag." : "Each original embedded Resource including extensions and whitespace remains <=4096 bytes."}`,
  headers: { ...headers, ...(individual ? { ETag: { required: true, schema: etag } } : {}) },
  content: { "application/json": { schema: ref(name) } },
});
const failures = (mutation = false, create = false) => ({
  "400": responseRef("OrganizationInvalidRequest"), "401": responseRef("OrganizationAuthenticationRequired"),
  "403": responseRef("OrganizationDenied"), "404": responseRef("OrganizationNotFound"),
  ...(mutation ? { "409": responseRef("OrganizationConflict"), "429": responseRef("GroupPolicyRateLimited") } : {}),
  "503": {
    description: mutation ? (create ? "Confirmed rollback: changed=false/retryable=true. Unknown COMMIT: changed=true/retryable=true; only explicit original-key and payload confirmation within the original 24 hours with fresh DPoP." : "Confirmed rollback: changed=false/retryable=true. Unknown COMMIT: changed=true/retryable=false; refresh and review, never automatically resubmit or replace the ETag.") : "Read failure: changed=false/retryable=true; no partial success.",
    headers,
    content: { "application/problem+json": { schema: mutation ? { oneOf: [ref("OrganizationStorageUnavailableProblem"), ref(create ? "OrganizationCommitOutcomeUnknownProblem" : "OrganizationUpdateCommitOutcomeUnknownProblem")] } : ref("OrganizationStorageUnavailableProblem") } },
  },
  default: { description: "Existing Organization RFC 9457 problem, at most 4096 complete bytes.", headers, content: { "application/problem+json": { schema: ref("ProblemDetails") } } },
});
const preconditions = { "412": responseRef("OrganizationPreconditionFailed"), "428": responseRef("OrganizationPreconditionRequired") };
const bodyFailures = { "413": responseRef("GrantBodyTooLarge"), "415": responseRef("OrganizationContentType") };
const base = "HTTPS, actual-method/trusted-URL fresh DPoP and current Account plus Device or real Account-browser family are required. A browser uses its exact trusted Origin, credentials=omit and no synthetic Device. Never read or change refresh cookies. Require current same-team active Membership and transaction-current authority before protected preconditions. Inaccessible, foreign and missing resources share the fixed Organization 404 boundary. ";
const write = "Require policies:write and manage_policy; use existing independent durable team-operation rate admission. Commit row, Organization authorization/view revision and attributable authorization audit atomically, then use existing content-free notification. Grants confer connect permission only; independent view_inventory remains required. ";
const liveReferences = "New creation and PUT require active Membership/live Host references in this Organization; absent and foreign references share organization.invalid_request. ";
const reads = { "x-scoplen-required-device-scope": "policies:read", "x-scoplen-required-browser-scope": "policies:read", "x-scoplen-cedar-action": "view_policy" };
const writes = { "x-scoplen-required-device-scope": "policies:write", "x-scoplen-required-browser-scope": "policies:write", "x-scoplen-cedar-action": "manage_policy" };

export function grantDefinitions() {
  const schemas = {
    GrantFields: { ...object(fields, true), description: "Named-member Host connection authority only, without visibility. Only explicit hosts certificate issuance may use Host Grants; host_groups issuance retains ordinary policies and cannot gain a HostGroup principal from a Host Grant." },
    GrantCreateRequest: { ...object({ id: uuid, data: ref("GrantFields") }, true), "x-scoplen-max-bytes": 4096 },
    GrantReplaceRequest: { ...object({ data: ref("GrantFields") }, true), "x-scoplen-max-bytes": 4096 },
    GrantResource: { ...object({ id: uuid, etag, created_at: metadataTime, updated_at: metadataTime, data: object(fields) }), "x-scoplen-max-bytes": 4096, description: "Current unwithdrawn Grants, including future and expired intervals, prevent referenced Host deletion with 409 organization.conflict until withdrawal or retargeting. Retained withdrawn rows and original receipts do not prevent deletion." },
    GrantPage: { ...object({ items: { type: "array", maxItems: 500, items: ref("GrantResource"), description: "Distinct ascending UUIDv7 ids beyond the captured cursor; each complete original item <=4096 bytes. A shorter nonempty prefix may satisfy the complete Page byte bound." }, next_cursor: { anyOf: [uuid, { type: "null" }], description: "Non-null only when more eligible items remain and equal to the nonempty Page's final id." } }), "x-scoplen-max-bytes": 2097152 },
    GrantBodyTooLargeProblem: { allOf: [ref("ProblemDetails"), { type: "object", properties: { status: { const: 413 }, code: { const: "organization.invalid_request" }, changed: { const: false }, retryable: { const: false } } }] },
  };
  const responses = {
    GrantResource: success("GrantResource", true), GrantPage: success("GrantPage", false),
    GrantBodyTooLarge: { description: "413 organization.invalid_request; changed=false/retryable=false. Problem <=4096 complete bytes.", headers, content: { "application/problem+json": { schema: ref("GrantBodyTooLargeProblem") } } },
  };
  const collection = "/orgs/{org}/grants", item = `${collection}/{id}`;
  const paths = {
    [collection]: {
      get: {
        operationId: "listOrganizationGrants", ...reads, "x-scoplen-response-max-bytes": 2097152,
        description: `${base}Require policies:read and view_policy. Return current unwithdrawn Grants, including expired intervals. Reject body, filter, sort, unknown query, If-Match and Idempotency-Key. Bind Page to original cursor and limit.`,
        parameters: [org, { name: "limit", in: "query", required: false, schema: { type: "integer", minimum: 1, maximum: 500, default: 50 } }, { name: "cursor", in: "query", required: false, schema: uuid }],
        responses: { "200": responseRef("GrantPage"), ...failures() },
      },
      post: {
        operationId: "createOrganizationGrant", ...writes, "x-scoplen-request-max-bytes": 4096, "x-scoplen-response-max-bytes": 4096,
        description: `${base}${write}One original UUIDv7 Idempotency-Key binds trusted origin, Account, original Device or real browser family, actual method/path, id and canonical five-field payload for 24 hours. After current management authority, look up the exact original receipt before validating live referenced Membership/Host. Exact historical confirmation may succeed after Grant withdrawal, Membership change or Host deletion; return immutable original bytes without another mutation or audit, never reviving a changed or withdrawn Grant. ${liveReferences}Changed binding/payload or reused id without the exact receipt conflicts. Reject every query and If-Match.`,
        parameters: [org, key], requestBody: request("GrantCreateRequest"),
        responses: { "201": responseRef("GrantResource"), ...failures(true, true), ...bodyFailures },
      },
    },
    [item]: {
      get: {
        operationId: "getOrganizationGrant", ...reads, "x-scoplen-response-max-bytes": 4096,
        description: `${base}Require policies:read and view_policy. Bind the Resource id to the captured request. Withdrawn rows are absent; expired unwithdrawn Grants remain readable. Reject body, every query, If-Match and Idempotency-Key.`,
        parameters: [org, id], responses: { "200": responseRef("GrantResource"), ...failures() },
      },
      put: {
        operationId: "replaceOrganizationGrant", ...writes, "x-scoplen-request-max-bytes": 4096, "x-scoplen-response-max-bytes": 4096,
        description: `${base}${write}${liveReferences}Replace all five fields using the original If-Match; equal fields are a no-op without revision or audit. Immutable id and Organization cannot change. Reject every query and Idempotency-Key.`,
        parameters: [org, id, match], requestBody: request("GrantReplaceRequest"),
        responses: { "200": responseRef("GrantResource"), ...failures(true), ...bodyFailures, ...preconditions },
      },
      delete: {
        operationId: "deleteOrganizationGrant", ...writes,
        description: `${base}${write}Withdraw using original If-Match; retain a private marker, used id, audit and original receipt, with no public lifecycle field. Current readers and authorization exclude withdrawn rows. Reject body, every query and Idempotency-Key.`,
        parameters: [org, id, match], responses: { "204": { description: "Withdrawn; no body.", headers }, ...failures(true), ...preconditions },
      },
    },
  };
  for (const path of Object.values(paths)) for (const operation of Object.values(path)) {
    operation.security = [{ accessToken: [], dpopProof: [] }, { accountBrowserAccess: [], dpopProof: [] }];
    operation["x-scoplen-fetch-credentials"] = "omit";
    operation["x-scoplen-problem-max-bytes"] = 4096;
  }
  return { schemas, responses, paths };
}

export function generateGrantTypes(document) {
  const expected = grantDefinitions();
  if (document.components?.schemas?.Grant !== undefined) throw new Error("D-147 retired generic Grant schema");
  const paths = Object.keys(document.paths ?? {}).filter(path => path.startsWith("/orgs/{org}/grants"));
  if (!isDeepStrictEqual(paths.sort(), Object.keys(expected.paths).sort())) throw new Error("D-147 Grant route coverage drift");
  for (const [section, values] of Object.entries(expected)) {
    const actual = section === "paths" ? document.paths : document.components?.[section];
    for (const [name, value] of Object.entries(values)) {
      if (!isDeepStrictEqual(actual?.[name], value)) throw new Error(`D-147 ${section}.${name} differs from its exact Grant contract`);
    }
  }
  return [
    "export interface GrantFields {",
    "  membership: string; host: string; remote_user: string;",
    "  valid_from: string; valid_until: string | null;", "}",
    "export interface GrantCreateRequest { id: string; data: GrantFields; }",
    "export interface GrantReplaceRequest { data: GrantFields; }",
    "export interface GrantResource {",
    "  id: string; etag: string; created_at: string; updated_at: string;",
    "  data: GrantFields & { [extension: string]: unknown };",
    "  [extension: string]: unknown;", "}",
    "export interface GrantPage { items: GrantResource[]; next_cursor: string | null; [extension: string]: unknown; }",
    "export interface GrantListQuery { limit?: number; cursor?: string; }",
    'export type GrantBodyTooLargeProblem = ProblemDetails & { status: 413; code: "organization.invalid_request"; changed: false; retryable: false; };', "",
  ].join("\n");
}
