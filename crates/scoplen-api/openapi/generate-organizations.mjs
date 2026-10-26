// SPDX-License-Identifier: Apache-2.0
// D-130 exact team creation and caller-membership discovery contract.
import { isDeepStrictEqual } from "node:util";

const uuid = { type: "string", format: "uuid", pattern: "^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$" };
const object = (properties, request = false) => ({ type: "object", additionalProperties: !request, required: Object.keys(properties), properties });
const name = { type: "string", minLength: 1, maxLength: 128, "x-scoplen-max-utf8-bytes": 128, description: "1..128 UTF-8 bytes, no Unicode control or leading/trailing Unicode whitespace; preserve without normalization." };
const headers = {
  "Cache-Control": { required: true, schema: { type: "string", const: "no-store" } },
  Pragma: { required: true, schema: { type: "string", const: "no-cache" } },
  "X-Request-ID": { required: true, schema: { type: "string", minLength: 1 } },
};
const etag = { type: "string", pattern: '^"[!#-~]*"$', minLength: 2, maxLength: 256 };
const timestamp = { type: "string", format: "date-time", pattern: "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-5][0-9](\\.[0-9]+)?Z$", description: "A valid UTC calendar timestamp." };
const resourceResponse = (schema, individual) => ({
  description: individual ? "Caller-specific Resource, complete body <=4096 bytes; ETag exactly equals body etag. No inventory, other member or Account secret." : "Current Account's live ascending team Page, complete body <=2097152 bytes; each original item <=4096 bytes including extensions and whitespace.",
  headers: { ...headers, ...(individual ? { ETag: { required: true, description: "Strong entity tag exactly equal to body etag.", schema: etag } } : {}) },
  content: { "application/json": { schema: { $ref: `#/components/schemas/${schema}` } } },
});

export function organizationDefinitions() {
  const schemas = {
    OrganizationCreateRequest: object({ data: object({ name }, true) }, true),
    OrganizationMembership: object({ id: uuid, account_id: uuid, roles: { type: "array", minItems: 1, maxItems: 32, uniqueItems: true, items: { type: "string", pattern: "^[a-z][a-z0-9_]{0,63}$" }, description: "Writer sorts bytewise; reader accepts distinct order. Unknown identifiers remain display metadata and grant no authority." } }),
    OrganizationResource: { ...object({ id: uuid, etag, created_at: timestamp, updated_at: timestamp, data: object({ name, membership: { $ref: "#/components/schemas/OrganizationMembership" } }) }), "x-scoplen-max-bytes": 4096 },
    OrganizationPage: { ...object({ items: { type: "array", maxItems: 500, items: { $ref: "#/components/schemas/OrganizationResource" }, description: "Distinct ascending Organization ids beyond the requested cursor; only caller's active memberships." }, next_cursor: { anyOf: [uuid, { type: "null" }], description: "Non-null only when more eligible items exist, equal to the nonempty page's final id." } }), "x-scoplen-max-bytes": 2097152 },
  };
  const responses = {};
  for (const [suffix, status, code, changed, retryable] of [
    ["InvalidRequest", 400, "organization.invalid_request", false, false],
    ["ContentType", 415, "organization.invalid_request", false, false],
    ["AuthenticationRequired", 401, "auth.authentication_required", false, false],
    ["Denied", 403, "policy.denied", false, false],
    ["NotFound", 404, "organization.not_found", false, false],
    ["Conflict", 409, "organization.conflict", false, false],
    ["StorageUnavailable", 503, "organization.storage_unavailable", false, true],
    ["CommitOutcomeUnknown", 503, "organization.commit_outcome_unknown", true, true],
  ]) {
    const problemName = `Organization${suffix}Problem`;
    schemas[problemName] = { allOf: [{ $ref: "#/components/schemas/ProblemDetails" }, { type: "object", properties: { status: { const: status }, code: { const: code }, changed: { const: changed }, retryable: { const: retryable } } }] };
    responses[`Organization${suffix}`] = { description: `${status} ${code}; changed=${changed}; retryable=${retryable}. Complete problem <=4096 bytes.`, headers, content: { "application/problem+json": { schema: { $ref: `#/components/schemas/${problemName}` } } } };
  }
  const problem = suffix => ({ $ref: `#/components/responses/Organization${suffix}` });
  const storage = create => ({ description: "Confirmed rollback uses organization.storage_unavailable, changed=false/retryable=true. Creation COMMIT uncertainty uses organization.commit_outcome_unknown, changed=true/retryable=true; retain original key/payload and use fresh DPoP within original 24 hours.", headers, content: { "application/problem+json": { schema: create ? { oneOf: [{ $ref: "#/components/schemas/OrganizationStorageUnavailableProblem" }, { $ref: "#/components/schemas/OrganizationCommitOutcomeUnknownProblem" }] } : { $ref: "#/components/schemas/OrganizationStorageUnavailableProblem" } } } });
  const failures = create => ({ "400": problem("InvalidRequest"), "401": problem("AuthenticationRequired"), "403": problem("Denied"), "503": storage(create), default: { description: "Bounded shared problem with no-store/no-cache/X-Request-ID.", headers, content: { "application/problem+json": { schema: { $ref: "#/components/schemas/ProblemDetails" } } } } });
  const paths = {
    "/orgs": {
      get: {
        operationId: "listCurrentAccountOrganizations", "x-scoplen-required-device-scope": "orgs:read", "x-scoplen-response-max-bytes": 2097152,
        description: "Current Account self-membership discovery under current Device/Account/DPoP/replay authorization. JWT org snapshots and inventory permissions do not authorize this route. Reject bodies, duplicate/unknown query names, If-Match and Idempotency-Key. No refresh cookie authentication or mutation.",
        parameters: [{ name: "limit", in: "query", required: false, schema: { type: "integer", minimum: 1, maximum: 500, default: 50 } }, { name: "cursor", in: "query", required: false, schema: uuid }],
        responses: { "200": resourceResponse("OrganizationPage", false), ...failures(false) },
      },
      post: {
        operationId: "createOrganization", "x-scoplen-required-device-scope": "orgs:create", "x-scoplen-request-max-bytes": 1024, "x-scoplen-response-max-bytes": 4096,
        description: "Current Account self-service under organizations.allow_creation; atomic Organization, initial active owner Membership, Organization audit and 24-hour Account/method/path/canonical-payload receipt. Reject query and If-Match. Exact same-key replay rechecks current Account/Device/membership and returns current projection without a second team/audit, even if creation is now disabled. No caller-selected ids/roles/keys or refresh cookie authentication/mutation. Unknown result retries retain original key/payload with fresh DPoP only within original 24 hours; never automatically switch key after expiry.",
        parameters: [{ name: "Idempotency-Key", in: "header", required: true, schema: uuid }],
        requestBody: { required: true, description: "Complete UTF-8 JSON <=1024 bytes; reject unknown/duplicate fields recursively.", content: { "application/json": { schema: { $ref: "#/components/schemas/OrganizationCreateRequest" } } } },
        responses: { "201": resourceResponse("OrganizationResource", true), ...failures(true), "404": problem("NotFound"), "409": problem("Conflict"), "415": problem("ContentType") },
      },
    },
    "/orgs/{org}": { get: {
      operationId: "getCurrentAccountOrganization", "x-scoplen-required-device-scope": "orgs:read", "x-scoplen-response-max-bytes": 4096,
      description: "Current Account own active membership projection. Reject bodies, every query, If-Match and Idempotency-Key; require current Device/Account/DPoP/replay authorization. Absent/foreign/inactive share one static 404 with no existence signal. No refresh cookie authentication or mutation.",
      parameters: [{ name: "org", in: "path", required: true, schema: uuid }],
      responses: { "200": resourceResponse("OrganizationResource", true), ...failures(false), "404": problem("NotFound") },
    } },
  };
  return { schemas, responses, paths };
}

export function generateOrganizationTypes(document) {
  const expected = organizationDefinitions();
  for (const [section, values] of Object.entries(expected)) {
    const actual = section === "paths" ? document.paths : document.components?.[section];
    for (const [name, value] of Object.entries(values)) {
      if (!isDeepStrictEqual(actual?.[name], value)) throw new Error(`D-130 ${section}.${name} differs from its exact contract`);
    }
  }
  const lines = [
    "export interface OrganizationCreateRequest { data: { name: string }; }",
    "export interface OrganizationMembership {",
    "  id: string;", "  account_id: string;", "  roles: string[];", "  [extension: string]: unknown;", "}",
    "export interface OrganizationResource {",
    "  id: string;", "  etag: string;", "  created_at: string;", "  updated_at: string;",
    "  data: { name: string; membership: OrganizationMembership; [extension: string]: unknown };",
    "  [extension: string]: unknown;", "}",
    "export interface OrganizationPage {",
    "  items: OrganizationResource[];", "  next_cursor: string | null;", "  [extension: string]: unknown;", "}", "",
  ];
  for (const [name, schema] of Object.entries(expected.schemas).filter(([, value]) => value.allOf)) {
    const fields = Object.entries(schema.allOf[1].properties).map(([key, value]) => `${key}: ${JSON.stringify(value.const)}`).join("; ");
    lines.push(`export type ${name} = ProblemDetails & { ${fields}; };`, "");
  }
  return lines.join("\n");
}
