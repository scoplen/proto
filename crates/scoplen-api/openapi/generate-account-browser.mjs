// SPDX-License-Identifier: Apache-2.0
// D-140 reuses native password/browser DTOs while enforcing an independent endpoint profile.
import { isDeepStrictEqual } from "node:util";

export const initialAccountBrowserScope = "account:read inventory:read inventory:write orgs:create orgs:read orgs:write policies:read policies:write teams:join teams:manage";

export function accountBrowserOperations() {
  const operations = [];
  const add = (method, path, scopes, writerReceipt = false) => operations.push({ method, path, scopes, writerReceipt });
  add("GET", "/api/v1/accounts/me", ["account:read"]);
  add("POST", "/api/v1/orgs", ["orgs:create"]);
  add("GET", "/api/v1/orgs", ["orgs:read"]);
  add("GET", "/api/v1/orgs/{org}", ["orgs:read"]);
  add("PATCH", "/api/v1/orgs/{org}", ["orgs:write"]);
  for (const [method, path, scopes] of [
    ["POST", "invitations", ["teams:manage"]], ["GET", "invitations", ["teams:manage"]],
    ["GET", "invitations/{invitation}", ["teams:join", "teams:manage"]],
    ["POST", "invitations/{invitation}/accept", ["teams:join"]],
    ["DELETE", "invitations/{invitation}", ["teams:manage"]],
    ["GET", "members", ["teams:manage"]], ["GET", "members/{membership}", ["teams:manage"]],
    ["PATCH", "members/{membership}", ["teams:manage"]],
    ["DELETE", "members/{membership}", ["teams:join", "teams:manage"]],
    ["POST", "dissolve", ["teams:manage"]],
  ]) add(method, `/api/v1/orgs/{org}/${path}`, scopes);
  for (const kind of ["hosts", "host-groups", "access-profiles", "routes", "groups", "policies"]) {
    for (const [method, suffix] of [["GET", ""], ["GET", "/{id}"], ["POST", ""], ["PUT", "/{id}"], ["DELETE", "/{id}"]]) {
      const scope = ["groups", "policies"].includes(kind)
        ? method === "GET" ? "policies:read" : kind === "groups" ? "teams:manage" : "policies:write"
        : method === "GET" ? "inventory:read" : "inventory:write";
      add(method, `/api/v1/orgs/{org}/${kind}${suffix}`, [scope], method === "POST");
    }
  }
  return operations;
}

export function accountBrowserDefinitions() {
  const ref = name => ({ $ref: `#/components/schemas/${name}` });
  const schemas = {
    AccountBrowserPasswordOptionsRequest: ref("AccountPasswordOptionsRequest"),
    AccountBrowserPasswordOptionsResponse: ref("AccountPasswordOptionsResponse"),
    AccountBrowserPasswordLoginRequest: ref("AccountPasswordLoginRequest"),
    AccountBrowserRefreshRequest: ref("BrowserAuthRefreshRequest"),
    AccountBrowserLogoutRequest: ref("OperatorLogoutRequest"),
    AccountBrowserLogoutResponse: ref("OperatorLogoutResponse"),
  };
  for (const [name, initial] of [["AccountBrowserPasswordLoginResponse", true], ["AccountBrowserRefreshResponse", false]]) {
    schemas[name] = { allOf: [ref("BrowserAuthTokenResponse"), {
      type: "object", properties: {
        access_token: { type: "string", pattern: "^ab1_[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$", minLength: 47, maxLength: 47 },
        expires_in: { type: "integer", const: 600 },
        refresh_expires_in: initial ? { type: "integer", const: 2592000 } : { type: "integer", minimum: 1, maximum: 2592000 },
      }, not: { anyOf: ["refresh_token", "admission_token", "snapshot"].map(name => ({ required: [name] })) },
    }] };
  }
  const headers = { "Cache-Control": { required: true, schema: { const: "no-store" } }, Pragma: { required: true, schema: { const: "no-cache" } }, "X-Request-Id": { required: true, schema: { type: "string", minLength: 1 } } };
  const cookie = "__Secure-spl-account-refresh=<token>; Path=/api/v1/auth/accounts/browser/refresh; HttpOnly; Secure; SameSite=Strict";
  const paths = {};
  for (const [suffix, stem, requestLimit, responseLimit, credentials] of [
    ["password/options", "PasswordOptions", 256, 1024, "omit"],
    ["password/login", "PasswordLogin", 512, 8192, "same-origin"],
    ["refresh", "Refresh", 256, 8192, "same-origin"],
    ["logout", "Logout", 256, 256, "omit"],
  ]) {
    const logout = stem === "Logout", session = ["PasswordLogin", "Refresh"].includes(stem);
    paths[`/auth/accounts/browser/${suffix}`] = { post: {
      operationId: `accountBrowser${stem}`, tags: ["Account browser authentication"],
      security: [{ ...(logout ? { accountBrowserAccess: [] } : {}), dpopProof: [] }],
      description: `D-140 independent current Account/browser family, never a Device or Operator. Exact trusted Origin and one fresh bounded ES256 DPoP proof are required; ${logout ? "token-bound ath over the exact ab1_ credential" : "no ath and no Authorization"}. Reject query, If-Match, Idempotency-Key, redirects, BOM, compression except identity, unknown request fields and recursive duplicate names. JSON/UTF-8 only. Browser credentials=${credentials}. ${stem === "Refresh" ? "Exactly one ar1_ Account refresh cookie; reject mixed native/Operator credentials; no cookie/body fallback. Rotate once without widening scope or extending absolute family expiry." : "Ignore cookies for authentication and identity selection."} ${session ? "Only confirmed COMMIT discloses credentials; uncertain COMMIT is changed=true, retryable=false and returns no credentials/cookie. Never automatically replay." : logout ? "Confirmed-only true terminal result; already-revoked fresh-proof confirmation grants no general authorization. Unknown revocation permits explicit retained-token/fresh-proof retry while eligible; no cookie is read, set or cleared." : "Attempt purpose/JKT/origin is browser-bound; native/browser attempts never cross. Share native password admission debt and stable synthetic salt behavior."}`,
      "x-scoplen-request-max-bytes": requestLimit, "x-scoplen-response-max-bytes": responseLimit,
      "x-scoplen-problem-max-bytes": 4096, "x-scoplen-fetch-credentials": credentials,
      ...(session ? { "x-scoplen-initial-browser-scope": initialAccountBrowserScope } : {}),
      parameters: [{ name: "Origin", in: "header", required: true, schema: { type: "string", format: "uri", minLength: 1 } }],
      requestBody: { required: true, description: `At most ${requestLimit} complete encoded UTF-8 bytes including whitespace.`, content: { "application/json": { schema: ref(`AccountBrowser${stem}Request`) } } },
      responses: {
        "200": { description: `At most ${responseLimit} complete encoded bytes. ${session ? "Only four browser session fields; access lasts exactly 600 seconds and family expires absolutely 2592000 seconds after login." : "Request-bound response."}`, headers: { ...headers, ...(session ? { "Set-Cookie": { required: true, description: `${cookie}; no Domain; Max-Age equals returned remaining family seconds. Never overwrite __Secure-spl-refresh. Refresh token is ar1_ plus canonical unpadded base64url of 32 independent random bytes.`, schema: { type: "string" } } } : {}) }, content: { "application/json": { schema: ref(`AccountBrowser${stem}Response`) } } },
        "400": { $ref: "#/components/responses/AccountEntryInvalidRequest" },
        "401": { $ref: "#/components/responses/AccountEntryAuthenticationRequired" },
        "403": { $ref: "#/components/responses/AccountEntryPolicyDenied" },
        "413": { $ref: "#/components/responses/AccountEntryBodyTooLarge" },
        "415": { $ref: "#/components/responses/AccountEntryMediaType" },
        "429": { $ref: "#/components/responses/AccountEntryRateLimited" },
        "503": { $ref: `#/components/responses/${logout ? "AccountBrowserLogoutStorageFailure" : session ? "AccountBrowserSessionStorageFailure" : "AccountEntryStorageUnavailable"}` },
        default: { $ref: "#/components/responses/AccountEntryProblem" },
      },
    } };
  }
  const responses = {};
  for (const [name, retryable] of [["AccountBrowserLogoutStorageFailure", true], ["AccountBrowserSessionStorageFailure", false]]) {
    responses[name] = { description: "Known precommit rollback versus unconfirmed COMMIT. Unknown result establishes no success.", headers, "x-scoplen-response-max-bytes": 4096, content: { "application/problem+json": { schema: { oneOf: [
      { allOf: [ref("ProblemDetails"), { properties: { status: { const: 503 }, code: { const: "auth.storage_unavailable" }, changed: { const: false }, retryable: { const: true } } }] },
      { allOf: [ref("ProblemDetails"), { properties: { status: { const: 503 }, code: { const: "auth.commit_outcome_unknown" }, changed: { const: true }, retryable: { const: retryable } } }] },
    ] } } } };
  }
  const security = { type: "apiKey", in: "header", name: "Authorization", description: "Exactly DPoP ab1_<canonical base64url of 32 random bytes>. Lexical parsing grants no identity; check current digest/family/Account/generation/JKT/origin/scope. Never accept Device/Operator JWTs." };
  return { schemas, paths, responses, security, operations: accountBrowserOperations() };
}

export function generateAccountBrowserTypes(document) {
  const expected = accountBrowserDefinitions();
  for (const [name, schema] of Object.entries(expected.schemas)) if (!isDeepStrictEqual(document.components?.schemas?.[name], schema)) throw new Error(`D-140 schema drift: ${name}`);
  for (const [path, operation] of Object.entries(expected.paths)) if (!isDeepStrictEqual(document.paths?.[path], operation)) throw new Error(`D-140 endpoint drift: ${path}`);
  for (const [name, response] of Object.entries(expected.responses)) if (!isDeepStrictEqual(document.components?.responses?.[name], response)) throw new Error(`D-140 problem drift: ${name}`);
  if (!isDeepStrictEqual(document.components?.securitySchemes?.accountBrowserAccess, expected.security) || !isDeepStrictEqual(document["x-scoplen-account-browser-operations"], expected.operations)) throw new Error("D-140 principal/operation drift");
  for (const { method, path } of expected.operations) if (!document.paths?.[path.slice(7)]?.[method.toLowerCase()]) throw new Error(`D-140 mapped operation is missing: ${method} ${path}`);
  return `export type AccountBrowserPasswordOptionsRequest = AccountPasswordOptionsRequest;
export type AccountBrowserPasswordOptionsResponse = AccountPasswordOptionsResponse;
export type AccountBrowserPasswordLoginRequest = AccountPasswordLoginRequest;
export type AccountBrowserRefreshRequest = BrowserAuthRefreshRequest;
export type AccountBrowserLogoutRequest = OperatorLogoutRequest;
export type AccountBrowserLogoutResponse = OperatorLogoutResponse;
export type AccountBrowserRefreshResponse = Omit<BrowserAuthTokenResponse, "access_token" | "expires_in"> & { access_token: \`ab1_\${string}\`; expires_in: 600; admission_token?: never; snapshot?: never };
export type AccountBrowserPasswordLoginResponse = AccountBrowserRefreshResponse & { refresh_expires_in: 2592000 };
export const initialAccountBrowserScope = ${JSON.stringify(initialAccountBrowserScope)} as const;
export const accountBrowserOperations = ${JSON.stringify(expected.operations, null, 2)} as const;
`;
}
