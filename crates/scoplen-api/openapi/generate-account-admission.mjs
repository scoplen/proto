// SPDX-License-Identifier: Apache-2.0
// Exact D-128 native JSON surface; protected CBOR remains the Rust/public-vector boundary.
import { isDeepStrictEqual } from "node:util";

const uuid = { type: "string", format: "uuid", pattern: "^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$" };
const decimal = { type: "string", pattern: "^[1-9][0-9]*$", maxLength: 20, "x-scoplen-uint64-maximum": "18446744073709551615" };
const bytes = (n, exact = true) => ({ type: "string", pattern: "^[A-Za-z0-9_-]+$", contentEncoding: "base64url", minLength: exact ? Math.ceil(4 * n / 3) : 1, maxLength: Math.ceil(4 * n / 3), "x-scoplen-decoded-bytes": { minimum: exact ? n : 1, maximum: n } });
const object = (properties, request) => ({ type: "object", additionalProperties: !request, required: Object.keys(properties), properties });
const kind = { type: "string", enum: ["register", "admit"] }, intent = { type: "string", enum: ["submit", "confirm"] };
const protectedBytes = n => ({ ...bytes(n, false), contentMediaType: "application/cbor", description: "Exact deterministic version-one protected CBOR; reject unknown/duplicate fields, nonshortest forms, indefinite lengths and trailing bytes. Sign the original decoded bytes." });
const requestFields = limit => ({ intent, payload: protectedBytes(limit), account_signature: bytes(64), attempt_id: bytes(32), nonce: bytes(32), device_proof: bytes(64) });

export function accountAdmissionDefinitions() {
  const schemas = {
    AccountRequestChallengeRequest: object({ kind, intent, operation_id: uuid, device_id: uuid }, true),
    AccountRequestChallengeResponse: object({ attempt_id: bytes(32), nonce: bytes(32), expires_at_ms: decimal }, false),
    AccountPasswordOptionsRequest: object({ username: { type: "string", minLength: 3, maxLength: 64, pattern: "^[a-z0-9][a-z0-9._-]*$" } }, true),
    AccountPasswordOptionsResponse: object({ attempt_id: bytes(32), profile: { type: "integer", const: 1 }, salt: bytes(16), expires_at_ms: decimal }, false),
    AccountPasswordLoginRequest: object({ attempt_id: bytes(32), auth_secret: bytes(32) }, true),
    AccountPasswordLoginResponse: object({ admission_token: bytes(32), expires_at_ms: decimal, snapshot: protectedBytes(9437184) }, false),
    AccountRegistrationRequest: object(requestFields(262144), true),
    AccountDeviceAdmissionRequest: {
      ...object({ ...requestFields(4325376), admission_token: { anyOf: [bytes(32), { type: "null" }] } }, true),
      allOf: [
        { if: { properties: { intent: { const: "submit" } }, required: ["intent"] }, then: { properties: { admission_token: bytes(32) } } },
        { if: { properties: { intent: { const: "confirm" } }, required: ["intent"] }, then: { properties: { admission_token: { type: "null" } } } },
      ],
    },
    AccountCommittedConfirmation: object({ outcome: { type: "string", const: "committed" }, kind, operation_id: uuid, request_digest: bytes(32), account_id: uuid, personal_vault_id: uuid, device_id: uuid, admitted_key_revision: decimal }, false),
  };
  const headers = { "Cache-Control": { required: true, schema: { type: "string", const: "no-store" } }, Pragma: { required: true, schema: { type: "string", const: "no-cache" } } };
  const problem = name => ({ $ref: `#/components/responses/${name}` });
  const paths = {};
  for (const [suffix, id, request, response, requestLimit, responseLimit] of [
    ["requests/challenge", "accountRequestChallenge", "AccountRequestChallengeRequest", "AccountRequestChallengeResponse", 512, 1024],
    ["register", "registerAccount", "AccountRegistrationRequest", "AccountCommittedConfirmation", 524288, 1024],
    ["password/options", "accountPasswordOptions", "AccountPasswordOptionsRequest", "AccountPasswordOptionsResponse", 256, 1024],
    ["password/login", "accountPasswordLogin", "AccountPasswordLoginRequest", "AccountPasswordLoginResponse", 512, 12587008],
    ["device-admissions", "admitAccountDevice", "AccountDeviceAdmissionRequest", "AccountCommittedConfirmation", 6291456, 1024],
  ]) {
    const terminal = response === "AccountCommittedConfirmation";
    const success = status => ({ description: `${status === 201 ? "New mutation committed" : terminal ? "Exact original receipt confirmed" : "Successful native response"}; at most ${responseLimit} complete encoded bytes.`, headers, content: { "application/json": { schema: { $ref: `#/components/schemas/${response}` } } } });
    paths[`/auth/accounts/${suffix}`] = { post: {
      operationId: id, security: [], tags: ["Account authentication"],
      description: "Native HTTPS only; reject redirects, Authorization, DPoP, Cookie, Idempotency-Key, If-Match and every query parameter. Origin may be absent; when supplied it must exactly equal the trusted canonical origin. Require application/json optionally charset=utf-8, strict UTF-8 without BOM and absent/identity content encoding. Reject unknown request fields and duplicate names recursively. Canonical unpadded base64url, lowercase UUIDv7 and positive decimal uint64 strings. No cookies, CORS or ordinary session tokens. Confirm is receipt-only and never falls through to submit. Bind every returned confirmation to the retained original payload/signature; missing receipt leaves the previous outcome unknown.",
      "x-scoplen-request-max-bytes": requestLimit, "x-scoplen-response-max-bytes": responseLimit,
      "x-scoplen-request-attempt-lifetime-ms": 120000,
      ...(suffix === "password/login" ? { "x-scoplen-admission-lifetime-ms": 300000 } : {}),
      requestBody: { required: true, description: `At most ${requestLimit} complete encoded UTF-8 bytes, including whitespace.`, content: { "application/json": { schema: { $ref: `#/components/schemas/${request}` } } } },
      responses: {
        "200": success(200), ...(terminal ? { "201": success(201) } : {}),
        "400": problem("AccountEntryInvalidRequest"), "401": problem("AccountEntryAuthenticationRequired"), "403": problem("AccountEntryPolicyDenied"),
        ...(terminal ? { "409": problem(suffix === "register" ? "AccountEntryRegistrationDenied" : "AccountEntryAdmissionConflict") } : {}),
        "413": problem(terminal ? "AccountEntryTooLarge" : "AccountEntryBodyTooLarge"), "415": problem("AccountEntryMediaType"), "429": problem("AccountEntryRateLimited"), "503": problem(terminal ? "AccountEntryStorageFailure" : "AccountEntryStorageUnavailable"), default: problem("AccountEntryProblem"),
      },
    } };
  }
  const responses = {};
  for (const [name, status, code, changed, retryable] of [
    ["InvalidRequest", 400, "auth.invalid_request", false, false], ["AuthenticationRequired", 401, "auth.authentication_required", false, false],
    ["PolicyDenied", 403, "policy.denied", false, false], ["MediaType", 415, "auth.invalid_request", false, false],
    ["RateLimited", 429, "auth.rate_limited", false, true],
    ["RegistrationDenied", 409, "auth.registration_denied", false, false],
    ["AdmissionConflict", 409, "auth.admission_conflict", false, false],
    ["BodyTooLarge", 413, "auth.invalid_request", false, false],
    ["StorageUnavailable", 503, "auth.storage_unavailable", false, true],
  ]) {
    const schemaName = `AccountEntry${name}Problem`;
    schemas[schemaName] = { allOf: [{ $ref: "#/components/schemas/ProblemDetails" }, { type: "object", properties: { status: { const: status }, code: { const: code }, changed: { const: changed }, retryable: { const: retryable } } }] };
    responses[`AccountEntry${name}`] = { description: "Bounded generic Account entry problem; no credentials, keys, ids or protocol bytes are echoed.", headers: { ...headers, ...(status === 429 ? {
      "Retry-After": { required: true, schema: { type: "string", pattern: "^(?:[1-9]|[1-9][0-9]|[12][0-9]{2}|300)$" } },
      "RateLimit-Policy": { required: true, schema: { type: "string", const: '"authentication";q=30;w=60' } },
      RateLimit: { required: true, schema: { type: "string", pattern: '^"authentication";r=0;t=(?:[1-9]|[1-9][0-9]|[12][0-9]{2}|300)$' } },
    } : {}) }, "x-scoplen-response-max-bytes": 4096, content: { "application/problem+json": { schema: { $ref: `#/components/schemas/${schemaName}` } } } };
  }
  for (const [name, status, codes, mutation] of [["TooLarge", 413, ["auth.invalid_request", "auth.quota_exceeded"], false], ["StorageFailure", 503, ["auth.storage_unavailable", "auth.commit_outcome_unknown"], true]]) {
    const variants = codes.map(code => ({ allOf: [{ $ref: "#/components/schemas/ProblemDetails" }, { type: "object", properties: { status: { const: status }, code: { const: code }, changed: { const: mutation && code === "auth.commit_outcome_unknown" }, retryable: { const: code === "auth.storage_unavailable" } } }] }));
    responses[`AccountEntry${name}`] = { description: "Exact D-128 failure profile; an unknown business COMMIT requires explicit fresh-proof confirm. Receipt-only confirmation and login cannot make a new business mutation and use unchanged storage failure when unconfirmed.", headers, "x-scoplen-response-max-bytes": 4096, content: { "application/problem+json": { schema: { oneOf: variants } } } };
  }
  responses.AccountEntryProblem = { description: "RFC 9457 problem, at most 4096 complete encoded bytes.", headers, "x-scoplen-response-max-bytes": 4096, content: { "application/problem+json": { schema: { $ref: "#/components/schemas/ProblemDetails" } } } };
  return { schemas, paths, responses };
}

export function generateAccountAdmissionTypes(document) {
  const expected = accountAdmissionDefinitions();
  for (const [name, schema] of Object.entries(expected.schemas)) if (!isDeepStrictEqual(document.components?.schemas?.[name], schema)) throw new Error(`D-128 schema ${name} differs from the frozen native wire`);
  for (const [path, operation] of Object.entries(expected.paths)) if (!isDeepStrictEqual(document.paths?.[path], operation)) throw new Error(`D-128 route ${path} differs from the frozen native wire`);
  for (const [name, response] of Object.entries(expected.responses)) if (!isDeepStrictEqual(document.components?.responses?.[name], response)) throw new Error(`D-128 failure ${name} differs from the frozen native wire`);
  for (const path of Object.keys(document.paths)) if (path.startsWith("/auth/pairings") || ["/auth/personal-enroll", "/admin/personal-invitations"].includes(path)) throw new Error("retired Account entry route remains registered");
  const lines = [];
  for (const [name, schema] of Object.entries(expected.schemas).filter(([, value]) => value.properties)) {
    if (name === "AccountDeviceAdmissionRequest") {
      lines.push("export type AccountDeviceAdmissionRequest =", '  | (AccountDeviceAdmissionFields & { intent: "submit"; admission_token: string })', '  | (AccountDeviceAdmissionFields & { intent: "confirm"; admission_token: null });', "", "export interface AccountDeviceAdmissionFields {");
    } else lines.push(`export interface ${name} {`);
    for (const [field, prop] of Object.entries(schema.properties)) {
      if (name === "AccountDeviceAdmissionRequest" && ["intent", "admission_token"].includes(field)) continue;
      const type = prop.const !== undefined ? JSON.stringify(prop.const) : prop.enum ? prop.enum.map(v => JSON.stringify(v)).join(" | ") : prop.type === "integer" ? "number" : "string";
      lines.push(`  ${field}: ${type};`);
    }
    if (schema.additionalProperties) lines.push("  [extension: string]: unknown;");
    lines.push("}", "");
  }
  const problemType = schema => {
    const properties = schema.allOf[1].properties;
    return `ProblemDetails & { ${Object.entries(properties).map(([key, value]) => `${key}: ${JSON.stringify(value.const)}`).join("; ")}; }`;
  };
  for (const [name, schema] of Object.entries(expected.schemas).filter(([, value]) => value.allOf?.[0]?.$ref === "#/components/schemas/ProblemDetails")) lines.push(`export type ${name} = ${problemType(schema)};`, "");
  for (const name of ["TooLarge", "StorageFailure"]) {
    const variants = expected.responses[`AccountEntry${name}`].content["application/problem+json"].schema.oneOf;
    lines.push(`export type AccountEntry${name}Problem =`, ...variants.map((schema, index) => `  | (${problemType(schema)})${index === variants.length - 1 ? ";" : ""}`), "");
  }
  lines.push("export interface AccountEntryRateLimitHeaders {", '  "Retry-After": string;', '  "RateLimit-Policy": \'"authentication";q=30;w=60\';', "  RateLimit: string;", '  "Cache-Control": "no-store";', '  Pragma: "no-cache";', "}", "");
  return `${lines.join("\n")}\n`;
}
