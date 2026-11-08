// SPDX-License-Identifier: Apache-2.0
// D-137 public local-user-CA metadata and D-141 revocation; signing custody remains internal.
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

const certificateProblems = [
  ["CertificateRevokedProblem", 409, "certificate.revoked"],
  ["CertificateQuotaExceededProblem", 413, "certificate.quota_exceeded"],
  ["CertificateBodyTooLargeProblem", 413, "certificate.invalid_request"],
];

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
    UserCaKrl: {
      type: "string", format: "binary", maxLength: 4194304,
      description: "Complete raw OpenSSH KRL v1 subset, <=4194304 bytes. Positive persistent uint64 version, uint64 generation Unix seconds, zero flags and empty reserved/comment. Empty set: 44-byte header only. Nonempty: one exact Ed25519 CA certificate section and one ascending unique positive uint64 serial list, <=100000 entries (800113 bytes). No wildcard CA, other sections or trailing bytes. Authenticated request provenance and captured CA supply binding, including the header-only case; parsing grants no current authority. No KRL signatures, JSON wrapper or new HTTP version field.",
    },
  };
  for (const [name, status, code] of certificateProblems) {
    schemas[name] = { allOf: [ref("ProblemDetails"), { type: "object", properties: {
      status: { const: status }, code: { const: code }, changed: { const: false }, retryable: { const: false },
    } }] };
  }
  const responses = {
    CertificateConflict: {
      description: "409 organization.conflict for mismatched original receipt bindings, or certificate.revoked for a strictly bound original receipt whose serial was revoked, after current Device/member/target authorization. The revoked response makes no new issuance; it does not claim the historical issuance never committed. Retain the receipt; never return, re-sign or extend its old certificate. Only a captured source-bound definite response terminates that pending client operation, with an explicit new connection required.",
      headers, content: { "application/problem+json": { schema: { oneOf: [ref("OrganizationConflictProblem"), ref("CertificateRevokedProblem")] } } },
    },
    CertificateTooLarge: {
      description: "413 certificate.invalid_request for a complete request over 16384 bytes, or certificate.quota_exceeded when 100000 unexpired certificates already exist for the CA, including revoked entries. Current authority and exact nonrevoked receipt replay precede the cap. Quota refusal allocates no serial and writes no certificate/receipt/issuance audit. Both have changed=false/retryable=false; consumers inspect the exact code rather than HTTP status alone.",
      headers, content: { "application/problem+json": { schema: { oneOf: [ref("CertificateBodyTooLargeProblem"), ref("CertificateQuotaExceededProblem")] } } },
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
    "/orgs/{org}/certificate-authorities/{id}/krl": {
      get: {
        operationId: "getUserCaKrl", security, "x-scoplen-required-device-scope": "ca:read", "x-scoplen-response-max-bytes": 4194304,
        description: `${authority}Require exactly ca:read and active same-Organization membership, not manage_ca or an inventory permit. Reject body, every query, If-Match and Idempotency-Key. Return only the complete persisted snapshot; no partial response, 304 or HTTP ETag. Capture origin/Account/Organization/Device/CA provenance and compare the embedded public CA when present. Missing/foreign CA, inactive/removed membership and dissolved Organization share the static organization.not_found boundary. Missing, corrupt, unsupported, oversized or incompletely read snapshots are organization.storage_unavailable, never an empty KRL. GET preserves version/time/bytes. Membership suspension/removal/self-leave and dissolution atomically persist CA-scoped serial revocations; restoration/rejoin never clears old revocations. This Device operation accepts no Account-browser or Operator substitute and supplies no host-agent delivery, post-dissolution read or existing-session termination.`,
        parameters: [org, { name: "id", in: "path", required: true, schema: uuid }],
        responses: {
          "200": { description: "Complete persisted raw KRL <=4194304 bytes, application/octet-stream; header version/time belong to this CA. No-store; an authenticated empty snapshot is not a missing snapshot.", headers, content: { "application/octet-stream": { schema: ref("UserCaKrl") } } },
          ...failures(false),
        },
      },
    },
  };
  return { schemas, responses, paths };
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
    "/** Complete raw binary KRL, not JSON; authenticated request and captured CA supply provenance. */",
    "export type UserCaKrl = Uint8Array;",
    ...certificateProblems.map(([name, status, code]) =>
      `export interface ${name} extends ProblemDetails { status: ${status}; code: "${code}"; changed: false; retryable: false; }`), "",
  ].join("\n");
}
