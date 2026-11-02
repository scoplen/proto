// SPDX-License-Identifier: Apache-2.0
// D-137 initial public local-user-CA metadata; signing custody remains server-internal.
import { isDeepStrictEqual } from "node:util";

const uuid = { type: "string", format: "uuid", pattern: "^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$" };
const ref = name => ({ $ref: `#/components/schemas/${name}` });
const object = (properties, request = false) => ({ type: "object", additionalProperties: !request, required: Object.keys(properties), properties });
const etag = { type: "string", minLength: 2, maxLength: 256, pattern: '^"[!#-~]*"$' };
const timestamp = { type: "string", format: "date-time", pattern: "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-5][0-9](\\.[0-9]+)?Z$", description: "A valid UTC calendar timestamp; no leap seconds or offset aliases." };
const headers = {
  "Cache-Control": { required: true, schema: { type: "string", const: "no-store" } },
  Pragma: { required: true, schema: { type: "string", const: "no-cache" } },
  "X-Request-ID": { required: true, schema: { type: "string", minLength: 1 } },
};
const org = { name: "org", in: "path", required: true, schema: uuid };
const security = [{ accessToken: [], dpopProof: [] }];
const problem = suffix => ({ $ref: `#/components/responses/Organization${suffix}` });
const success = (schema, individual = false) => ({
  description: individual ? "Public local user-CA Resource, complete JSON <=16384 bytes. HTTP ETag exactly equals body etag. Ignore bounded response extensions; reject recursive duplicate names." : "Live ascending public CA Page, complete JSON <=1048576 bytes, each original Resource <=16384 bytes including extensions/whitespace. May return a shorter nonempty prefix to stay within the Page budget.",
  headers: { ...headers, ...(individual ? { ETag: { required: true, description: "Exactly the body's strong etag.", schema: etag } } : {}) },
  content: { "application/json": { schema: ref(schema) } },
});
const storage = mutation => ({
  description: mutation ? "Confirmed rollback: 503 organization.storage_unavailable, changed=false/retryable=true. Unconfirmed COMMIT: 503 organization.commit_outcome_unknown, changed=true/retryable=true; explicit confirmation only with the original key/body and fresh DPoP within 24 hours, after current authorization. Never replace the key automatically." : "503 organization.storage_unavailable, changed=false/retryable=true. No partial success or false absence.",
  headers,
  content: { "application/problem+json": { schema: mutation ? { oneOf: [ref("OrganizationStorageUnavailableProblem"), ref("OrganizationCommitOutcomeUnknownProblem")] } : ref("OrganizationStorageUnavailableProblem") } },
});
const failures = mutation => ({
  "400": problem("InvalidRequest"), "401": problem("AuthenticationRequired"), "403": problem("Denied"), "404": problem("NotFound"),
  ...(mutation ? { "409": problem("Conflict"), "413": { $ref: "#/components/responses/TeamBodyTooLarge" }, "415": problem("ContentType"), "429": { $ref: "#/components/responses/TeamRateLimited" } } : {}),
  "503": storage(mutation),
  default: { description: "Shared bounded problem <=4096 bytes, with no-store/no-cache/X-Request-ID. No private key, Account data or foreign-tenant existence signal.", headers, content: { "application/problem+json": { schema: ref("ProblemDetails") } } },
});
const authority = "Require current Account/Device and active same-Organization membership, actual-method/trusted-URL token-bound DPoP and durable replay protection. JWT Organization snapshots, cached metadata and roles never supply current authority. No refresh cookie is read or changed. ";
const readBoundary = "Public trust reads require ca:read and current membership; they grant no inventory visibility or certificate issuance. Retain the authenticated origin/Account/Organization/Device request provenance: the Resource has no echoed Organization field. Missing, foreign and inaccessible resources use the same static organization.not_found. ";

export function userCaDefinitions() {
  const schemas = {
    UserCaCreateRequest: { ...object({ id: uuid, data: object({ kind: { type: "string", const: "user" }, backend: { type: "string", const: "local" } }, true) }, true), "x-scoplen-max-bytes": 16384 },
    UserCaResource: {
      ...object({
        id: uuid, etag, created_at: timestamp, updated_at: timestamp,
        data: object({
          kind: { type: "string", const: "user" }, backend: { type: "string", const: "local" }, state: { type: "string", const: "active" },
          public_key: { type: "string", maxLength: 8192, pattern: "^ssh-ed25519 [A-Za-z0-9+/]+={0,2}$", description: "Canonical raw ssh-ed25519 OpenSSH key line: exactly one ASCII space and canonical standard Base64 with required padding. The complete decoded blob parses without trailing bytes and its algorithm agrees. No comment, options, newline, certificate or private key." },
          fingerprint: { type: "string", minLength: 50, maxLength: 50, pattern: "^SHA256:[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]$", description: "Exactly SHA256: plus unpadded standard Base64 of SHA-256 over public_key's complete decoded OpenSSH blob, never its text or bare Ed25519 bytes; must match public_key." },
        }),
      }),
      "x-scoplen-max-bytes": 16384,
      description: "Only public metadata for the initial active Organization user CA with the local signer. Origin/tenant ownership comes from the authenticated request, never this locator alone. Contains no signing seed or private key handle.",
    },
    UserCaPage: {
      ...object({
        items: { type: "array", maxItems: 500, "x-scoplen-max-item-bytes": 16384, items: ref("UserCaResource"), description: "Distinct ascending CA ids strictly beyond the requested cursor, at most the requested limit. Every original raw item's complete JSON, including ignored extensions and whitespace, obeys its independent 16384-byte budget." },
        next_cursor: { anyOf: [uuid, { type: "null" }], description: "Non-null only if more eligible items exist; equals the last returned id of a nonempty Page." },
      }),
      "x-scoplen-max-bytes": 1048576,
    },
  };
  const paths = {
    "/orgs/{org}/certificate-authorities": {
      get: {
        operationId: "listUserCertificateAuthorities", security, "x-scoplen-required-device-scope": "ca:read", "x-scoplen-response-max-bytes": 1048576,
        description: `${authority}${readBoundary}Accept only the standard limit/cursor query; reject duplicate/unknown query names, bodies, If-Match and Idempotency-Key. Cursor is an ascending locator, never authority. An empty eligible directory is a valid empty Page.`,
        parameters: [org, { name: "limit", in: "query", required: false, schema: { type: "integer", minimum: 1, maximum: 500, default: 50 } }, { name: "cursor", in: "query", required: false, schema: uuid }],
        responses: { "200": success("UserCaPage"), ...failures(false) },
      },
      post: {
        operationId: "createUserCertificateAuthority", security, "x-scoplen-required-device-scope": "ca:write", "x-scoplen-cedar-action": "manage_ca", "x-scoplen-request-max-bytes": 16384, "x-scoplen-response-max-bytes": 16384,
        description: `${authority}Require ca:write and current manage_ca. Provision one independent Ed25519 local user CA, with a server-generated seed encrypted under the existing deployment KMS key and Organization/CA/purpose binding. Reject query, If-Match and every unknown request field, including caller keys/seed/state. One initial active user CA per Organization; a different create while it exists conflicts. Bind one canonical UUIDv7 Idempotency-Key for 24 hours to the original origin/Account/Device/Organization, method/path, id and canonical payload. Atomically commit CA, encrypted seed, immutable owner, audit and receipt; return only after confirmed commit. Exact original-key/body replay rechecks current authority and returns the retained create Resource without a second key or audit. No rotation, remote signer, host CA or KRL distribution is supplied by this operation.`,
        parameters: [org, { name: "Idempotency-Key", in: "header", required: true, schema: uuid }],
        requestBody: { required: true, description: "Exactly {id,data:{kind:\"user\",backend:\"local\"}}, complete UTF-8 JSON <=16384 bytes, including whitespace/escapes. Reject recursive duplicate names and unknown fields.", content: { "application/json": { schema: ref("UserCaCreateRequest") } } },
        responses: { "201": success("UserCaResource", true), ...failures(true) },
      },
    },
    "/orgs/{org}/certificate-authorities/{id}": {
      get: {
        operationId: "getUserCertificateAuthority", security, "x-scoplen-required-device-scope": "ca:read", "x-scoplen-response-max-bytes": 16384,
        description: `${authority}${readBoundary}Reject body, every query, If-Match and Idempotency-Key. Validate the Resource id against the captured requested CA id and its HTTP ETag before use. Another Organization's CA never satisfies this team's trust.`,
        parameters: [org, { name: "id", in: "path", required: true, schema: uuid }],
        responses: { "200": success("UserCaResource", true), ...failures(false) },
      },
    },
  };
  return { schemas, responses: {}, paths };
}

export function generateUserCaTypes(document) {
  const expected = userCaDefinitions();
  for (const [section, values] of Object.entries(expected)) {
    const actual = section === "paths" ? document.paths : document.components?.[section];
    for (const [name, value] of Object.entries(values)) {
      if (!isDeepStrictEqual(actual?.[name], value)) throw new Error(`D-137 user-CA ${section}.${name} differs from its exact contract`);
    }
  }
  return [
    'export interface UserCaCreateRequest { id: string; data: { kind: "user"; backend: "local" }; }',
    "/** Authenticated request provenance supplies Organization ownership; parsing alone never establishes CA trust. */",
    "export interface UserCaResource {",
    "  id: string; etag: string; created_at: string; updated_at: string;",
    '  data: { kind: "user"; backend: "local"; state: "active"; public_key: string; fingerprint: string; [extension: string]: unknown };',
    "  [extension: string]: unknown;", "}",
    "export interface UserCaPage { items: UserCaResource[]; next_cursor: string | null; [extension: string]: unknown; }", "",
  ].join("\n");
}
