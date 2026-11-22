// SPDX-License-Identifier: Apache-2.0
import { isDeepStrictEqual } from "node:util";

const ref = (kind, name) => ({ $ref: `#/components/${kind}/${name}` });
const schema = name => ref("schemas", name);
const response = name => ref("responses", name);
const uuid = { type: "string", format: "uuid", pattern: "^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$" };
const tag = { type: "string", pattern: '^"[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"$' };
const strongTag = { type: "string", pattern: '^"[!#-~]*"$', minLength: 2, maxLength: 256 };
const time = { type: "string", format: "date-time", pattern: "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-5][0-9](\\.[0-9]+)?Z$" };
const issuer = { type: "string", format: "iri", pattern: "^[Hh][Tt][Tt][Pp][Ss]://", maxLength: 2048, "x-scoplen-max-utf8-bytes": 2048, description: "Exact absolute HTTPS issuer with a host and no user information, query, fragment, backslash, whitespace or control characters. Preserve path and trailing slash. No discovery or activation." };
const object = (properties, extensible) => ({ type: "object", additionalProperties: extensible, required: Object.keys(properties), properties });
const header = (name, value) => ({ name, in: "header", required: true, schema: value });
const org = { name: "org", in: "path", required: true, schema: uuid };
const key = header("Idempotency-Key", uuid);
const headers = {
  "Cache-Control": { required: true, schema: { type: "string", const: "no-store" } },
  Pragma: { required: true, schema: { type: "string", const: "no-cache" } },
  "X-Request-ID": { required: true, schema: { type: "string", minLength: 1 } },
};
const profile = {
  security: [{ accessToken: [], dpopProof: [] }, { accountBrowserAccess: [], dpopProof: [] }],
  "x-scoplen-required-device-scope": "auth-drafts:manage",
  "x-scoplen-required-browser-scope": "auth-drafts:manage",
  "x-scoplen-cedar-action": "manage_organization",
  "x-scoplen-required-membership-roles-any": ["owner", "administrator"],
  "x-scoplen-fetch-credentials": "omit",
  "x-scoplen-problem-max-bytes": 4096,
};
const failures = {
  400: response("OrganizationInvalidRequest"), 401: response("OrganizationAuthenticationRequired"),
  403: response("OrganizationDenied"), 404: response("OrganizationNotFound"),
  default: { description: "Bounded Organization problem without issuer or draft metadata.", headers,
    content: { "application/problem+json": { schema: schema("ProblemDetails") } } },
};
const currentAuthority = "Require an active Account and enrolled Device or live Account-browser family, actual-method and trusted-URL DPoP, durable proof replay protection, active same-Organization membership, Owner or Administrator role and current manage_organization Cedar permit. Recheck current authority before receipt lookup, slot lookup or conditional comparison. ";
const writeFailures = {
  ...failures, 409: response("OrganizationConflict"), 412: response("OrganizationPreconditionFailed"),
  428: response("OrganizationPreconditionRequired"), 429: response("GroupPolicyRateLimited"),
  503: { description: "Confirmed rollback or unconfirmed COMMIT; recheck the original authorized writer, condition, key and payload.", headers,
    content: { "application/problem+json": { schema: { oneOf: [schema("OrganizationStorageUnavailableProblem"), schema("OrganizationCommitOutcomeUnknownProblem")] } } } },
};
const resource = { description: "Original generation, UTC timestamps and exact issuer. The strong HTTP ETag equals the body etag and quotes the generation UUID. Read the singleton for its current status.", headers: { ...headers, ETag: { required: true, schema: tag } }, content: { "application/json": { schema: schema("AuthConnectionDraftResource") } } };

export function authDraftDefinitions() {
  const schemas = {
    AuthConnectionDraftCreate: { ...object({ data: object({ issuer }, false) }, false), "x-scoplen-max-bytes": 4096 },
    AuthConnectionDraftResource: { ...object({ id: uuid, etag: tag, created_at: time, updated_at: time, data: object({ organization_id: uuid, issuer }, true) }, true), "x-scoplen-max-bytes": 8192 },
  };
  const paths = { "/orgs/{org}/auth-connection-draft": {
    post: { operationId: "createOrganizationAuthConnectionDraft", ...profile, "x-scoplen-request-max-bytes": 4096, "x-scoplen-response-max-bytes": 8192,
      description: currentAuthority + "Create only in an empty slot. No query or If-Match. A browser must send its exact trusted Origin. Atomically audit and bind the original writer's 24-hour receipt. Exact replay confirms the initial generation even after cancellation.",
      parameters: [org, key, header("If-None-Match", { type: "string", const: "*" })],
      requestBody: { required: true, content: { "application/json": { schema: schema("AuthConnectionDraftCreate") } } },
      responses: { 201: resource, ...writeFailures, 413: response("GrantBodyTooLarge"), 415: response("OrganizationContentType") } },
    get: { operationId: "getOrganizationAuthConnectionDraft", ...profile, "x-scoplen-response-max-bytes": 8192,
      description: currentAuthority + "Recover the current generation. A supplied browser Origin must equal the trusted Origin. Reject query, body, conditionals and Idempotency-Key. Missing draft or inaccessible Organization uses the same not-found response.",
      parameters: [org], responses: { 200: resource, ...failures, 503: response("OrganizationStorageUnavailable") } },
    delete: { operationId: "cancelOrganizationAuthConnectionDraft", ...profile, "x-scoplen-response-max-bytes": 0,
      description: currentAuthority + "Cancel only the originally reviewed generation. A browser must send its exact trusted Origin. No query, body or If-None-Match. The original writer may explicitly confirm the original 204 within 24 hours, including after the creation of a later generation.",
      parameters: [org, key, header("If-Match", strongTag)],
      responses: { 204: { description: "Original cancellation confirmation with an empty body.", headers }, ...writeFailures } },
  } };
  return { schemas, paths };
}

export function generateAuthDraftTypes(document) {
  const { schemas, paths } = authDraftDefinitions();
  for (const [name, value] of Object.entries(schemas)) if (!isDeepStrictEqual(document.components.schemas[name], value)) throw new Error(`D-166 schema drift: ${name}`);
  for (const [name, value] of Object.entries(paths)) if (!isDeepStrictEqual(document.paths[name], value)) throw new Error(`D-166 operation drift: ${name}`);
  return `export interface AuthConnectionDraftCreate { data: { issuer: string } }
export interface AuthConnectionDraftResource {
  id: string;
  etag: string;
  created_at: string;
  updated_at: string;
  data: { organization_id: string; issuer: string; [key: string]: unknown };
  [key: string]: unknown;
}
`;
}
