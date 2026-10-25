// SPDX-License-Identifier: Apache-2.0
// D-111/D-124 finite Operator contract checks and TypeScript projection.
export function generateOperatorTypes(document) {
  const schemas = document.components.schemas;
  const shapes = {
    OperatorSetupOptionsRequest: ["setup_token"],
    OperatorSetupFinishRequest: ["setup_token", "ceremony_id", "credential_id", "client_data_json", "attestation_object"],
    OperatorLoginOptionsRequest: [],
    OperatorLoginFinishRequest: ["ceremony_id", "credential_id", "client_data_json", "authenticator_data", "signature", "user_handle"],
    OperatorSetupOptionsResponse: ["ceremony_id", "expires_at", "public_key"],
    OperatorLoginOptionsResponse: ["ceremony_id", "expires_at", "public_key"],
    OperatorSetupFinishResponse: ["operator_id"],
    OperatorCreationOptions: ["rp", "user", "challenge", "pubKeyCredParams", "timeout", "excludeCredentials", "authenticatorSelection", "attestation"],
    OperatorRequestOptions: ["challenge", "timeout", "rpId", "allowCredentials", "userVerification"],
    OperatorLogoutRequest: [],
    OperatorLogoutResponse: ["revoked"],
  };
  const bounds = { setup_token: [32, 32], credential_id: [1, 1023], client_data_json: [1, 4096], attestation_object: [1, 16384], authenticator_data: [37, 4096], signature: [8, 72], user_handle: [16, 16], challenge: [32, 32] };
  for (const [name, fields] of Object.entries(shapes)) {
    const schema = schemas[name];
    const closed = name.endsWith("Request") || name === "OperatorLogoutResponse";
    if (schema?.type !== "object" || schema.additionalProperties !== !closed ||
        JSON.stringify(schema.required) !== JSON.stringify(fields) ||
        JSON.stringify(Object.keys(schema.properties)) !== JSON.stringify(fields)) throw new Error(`${name} shape differs from D-111`);
    for (const [field, value] of Object.entries(schema.properties)) {
      if (field in bounds) {
        const [min, max] = bounds[field];
        if (value.type !== "string" || value.minLength !== Math.ceil(min * 8 / 6) || value.maxLength !== Math.ceil(max * 8 / 6) ||
            value.pattern !== "^[A-Za-z0-9_-]+$" || value["x-scoplen-decoded-bytes"]?.minimum !== min || value["x-scoplen-decoded-bytes"]?.maximum !== max) throw new Error(`${name}.${field} byte bound differs from D-111`);
      }
    }
  }
  const creation = schemas.OperatorCreationOptions.properties;
  const request = schemas.OperatorRequestOptions.properties;
  if (creation.rp.properties.name.const !== "Scoplen" || creation.user.properties.displayName.const !== "Deployment operator" ||
      creation.user.properties.id["x-scoplen-decoded-bytes"]?.minimum !== 16 ||
      creation.user.properties.id["x-scoplen-decoded-bytes"]?.maximum !== 16 ||
      creation.pubKeyCredParams.minItems !== 1 || creation.pubKeyCredParams.maxItems !== 1 ||
      creation.pubKeyCredParams.items.properties.type.const !== "public-key" || creation.pubKeyCredParams.items.properties.alg.const !== -7 ||
      creation.timeout.minimum !== 1000 || creation.timeout.maximum !== 300000 || creation.timeout.multipleOf !== 1000 ||
      creation.excludeCredentials.maxItems !== 0 || creation.attestation.const !== "none" ||
      creation.authenticatorSelection.properties.residentKey.const !== "required" || creation.authenticatorSelection.properties.requireResidentKey.const !== true ||
      creation.authenticatorSelection.properties.userVerification.const !== "required" ||
      request.allowCredentials.maxItems !== 0 || request.timeout.const !== 300000 || request.userVerification.const !== "required") throw new Error("Operator WebAuthn policy differs from D-111");
  const headers = { "Cache-Control": "no-store", Pragma: "no-cache", "Referrer-Policy": "no-referrer" };
  const assertHeaders = (actual) => {
    if (!Object.entries(headers).every(([name, value]) => actual?.[name]?.required === true && actual[name].schema?.const === value)) throw new Error("Operator response cache/referrer profile differs from D-111");
  };
  for (const [path, requestName, responseName, status, limit, output] of [
    ["setup/options", "OperatorSetupOptionsRequest", "OperatorSetupOptionsResponse", "200", 256, 4096],
    ["setup/finish", "OperatorSetupFinishRequest", "OperatorSetupFinishResponse", "201", 32768, 256],
    ["login/options", "OperatorLoginOptionsRequest", "OperatorLoginOptionsResponse", "200", 256, 4096],
    ["login/finish", "OperatorLoginFinishRequest", "BrowserAuthTokenResponse", "200", 16384, 8192],
  ]) {
    const operation = document.paths[`/auth/operator/${path}`]?.post;
    const success = operation?.responses?.[status];
    if (JSON.stringify(operation?.security) !== '[{"dpopProof":[]}]' || operation["x-scoplen-request-max-bytes"] !== limit || operation["x-scoplen-response-max-bytes"] !== output ||
        operation.requestBody?.required !== true || operation.requestBody.content?.["application/json"]?.schema?.$ref !== `#/components/schemas/${requestName}` ||
        success?.content?.["application/json"]?.schema?.$ref !== `#/components/schemas/${responseName}` ||
        !operation.description.includes("8192 ASCII") || !operation.description.includes("Idempotency-Key") ||
        !operation.description.includes("embedded client-data JSON, CBOR and signature bytes remain opaque")) throw new Error(`Operator ${path} request/response differs from D-111`);
    assertHeaders(success.headers);
    for (const [code, response] of [[400, "OperatorInvalidRequest"], [401, "OperatorAuthenticationRequired"], [403, "OperatorOriginDenied"], [413, "OperatorBodyTooLarge"], [415, "OperatorContentType"], [429, "OperatorRateLimited"], [503, path.endsWith("finish") ? "OperatorStorageFailure" : "OperatorStorageUnavailable"]]) {
      if (operation.responses[code]?.$ref !== `#/components/responses/${response}`) throw new Error(`Operator ${path} status ${code} differs from D-111`);
      assertHeaders(document.components.responses[response].headers);
    }
    if (path === "login/finish" && success.headers["Set-Cookie"]?.required !== true) throw new Error("Operator login requires the browser refresh cookie");
    if (path !== "login/finish" && success.headers["Set-Cookie"]) throw new Error("Only Operator login finish issues a session");
  }
  const jwks = document.paths["/.well-known/operator-jwks.json"]?.get;
  if (JSON.stringify(jwks?.servers) !== '[{"url":"/"}]' || JSON.stringify(jwks.security) !== "[]" ||
      jwks.responses?.["200"]?.content?.["application/json"]?.schema?.$ref !== "#/components/schemas/AuthJwks" ||
      document.paths["/admin/personal-invitations"]) throw new Error("Operator key source or retired-scope boundary differs from D-111/D-125");
  const problemNames = ["OperatorInvalidRequestProblem", "OperatorInvalidDpopProblem", "OperatorOriginDeniedProblem", "OperatorBodyTooLargeProblem", "OperatorContentTypeProblem"];
  for (const [name, status, code] of [[problemNames[0], 400, "auth.invalid_request"], [problemNames[1], 400, "auth.invalid_dpop_proof"], [problemNames[2], 403, "policy.denied"], [problemNames[3], 413, "auth.invalid_request"], [problemNames[4], 415, "auth.invalid_request"]]) {
    const constraint = schemas[name]?.allOf?.[1]?.properties;
    if (constraint?.status?.const !== status || constraint?.code?.const !== code || constraint?.changed?.const !== false || constraint?.retryable?.const !== false) throw new Error(`${name} error profile differs from D-111`);
  }
  const logoutPath = "/auth/operator/logout";
  const logout = document.paths[logoutPath]?.post;
  if (JSON.stringify(Object.keys(document.paths[logoutPath] ?? {})) !== '["post"]' ||
      logout?.operationId !== "operatorLogout" ||
      JSON.stringify(logout.security) !== '[{"accessToken":[],"dpopProof":[]}]' ||
      logout["x-scoplen-operator-requirement"] !== "self-session-termination" ||
      Object.hasOwn(logout, "x-scoplen-required-operator-scope") ||
      Object.hasOwn(logout, "x-scoplen-required-device-scope") ||
      logout["x-scoplen-request-max-bytes"] !== 256 ||
      logout["x-scoplen-response-max-bytes"] !== 256 ||
      logout["x-scoplen-problem-max-bytes"] !== 4096 ||
      logout.requestBody?.required !== true ||
      JSON.stringify(Object.keys(logout.requestBody.content ?? {})) !== '["application/json"]' ||
      logout.requestBody.content["application/json"].schema?.$ref !== "#/components/schemas/OperatorLogoutRequest" ||
      logout.responses?.["200"]?.content?.["application/json"]?.schema?.$ref !== "#/components/schemas/OperatorLogoutResponse" ||
      JSON.stringify(Object.keys(logout.responses ?? {})) !== '["200","400","401","403","413","415","429","503","default"]' ||
      JSON.stringify(schemas.OperatorLogoutResponse.properties.revoked) !== '{"type":"boolean","const":true}') {
    throw new Error("Operator logout wire or intrinsic requirement differs from D-124");
  }
  const origin = logout.parameters;
  if (origin?.length !== 1 || origin[0].name !== "Origin" || origin[0].in !== "header" ||
      origin[0].required !== true ||
      JSON.stringify(origin[0].schema) !== '{"type":"string","format":"uri","minLength":1}') {
    throw new Error("Operator logout trusted Origin requirement differs from D-124");
  }
  for (const phrase of [
    "HTTPS only", "unexpired spl-operator-access+jwt", "spl-admin/1", "4096 ASCII", "8192 ASCII",
    "token-bound ath", "durable cross-instance replay claim", "/api/v1/auth/operator/logout",
    "CORS allows only that exact origin, POST and Authorization/DPoP/Content-Type", "credentials=omit",
    "Cookie headers are ignored", "every response omits Set-Cookie", "query parameters and Idempotency-Key",
    "independent logout admission profile", "source quota 30 and verified-Operator quota 10 per 60-second window",
    "active current Operator and authenticating credential", "trusted-origin/RP binding",
    "scope/original ceiling/JKT/identity/audience", "absolute family expiry", "after lock waits and before commit",
    "revocation and mandatory deployment audit commit atomically", "retain all digests and every other family/identity",
    "equally eligible already-revoked", "never produces general authorization evidence", "Same-proof replay still fails",
    "explicit fresh-proof retry", "never automatic refresh/replay or cookie fallback", "Another login cannot confirm",
  ]) {
    if (!logout.description?.includes(phrase)) throw new Error(`Operator logout omits D-124 rule: ${phrase}`);
  }
  for (const [path, methods] of Object.entries(document.paths)) {
    for (const [method, operation] of Object.entries(methods)) {
      if (operation?.["x-scoplen-operator-requirement"] === "self-session-termination" &&
          (path !== logoutPath || method !== "post")) {
        throw new Error("D-124 intrinsic termination must match only exact Operator logout");
      }
    }
  }
  for (const [status, name] of [
    ["200", undefined], ["400", "OperatorInvalidRequest"], ["401", "OperatorLogoutAuthenticationRequired"],
    ["403", "OperatorOriginDenied"], ["413", "OperatorBodyTooLarge"], ["415", "OperatorContentType"],
    ["429", "OperatorRateLimited"], ["503", "OperatorLogoutStorageFailure"], ["default", "OperatorProblem"],
  ]) {
    const response = name ? document.components.responses[name] : logout.responses[status];
    if (name && logout.responses[status]?.$ref !== `#/components/responses/${name}`) {
      throw new Error(`Operator logout ${status} response differs from D-124`);
    }
    assertHeaders(response?.headers);
    if (Object.keys(response.headers).some((name) => name.toLowerCase() === "set-cookie")) {
      throw new Error("Operator logout must never set or clear a cookie under D-124");
    }
  }
  const logoutProblems = [
    ["OperatorLogoutAuthenticationRequiredProblem", 401, "auth.authentication_required", false, false],
    ["OperatorLogoutCommitOutcomeUnknownProblem", 503, "auth.commit_outcome_unknown", true, true],
  ];
  for (const [name, status, code, changed, retryable] of [
    ...logoutProblems,
    ["AuthStorageUnavailableProblem", 503, "auth.storage_unavailable", false, true],
    ["AuthRateLimitedProblem", 429, "auth.rate_limited", false, true],
  ]) {
    const expected = [
      { $ref: "#/components/schemas/ProblemDetails" },
      { type: "object", properties: {
        status: { const: status }, code: { const: code },
        changed: { const: changed }, retryable: { const: retryable },
      } },
    ];
    if (JSON.stringify(schemas[name]?.allOf) !== JSON.stringify(expected)) {
      throw new Error(`${name} error flags differ from D-124`);
    }
  }
  for (const [name, problem] of [
    ["OperatorLogoutAuthenticationRequired", "OperatorLogoutAuthenticationRequiredProblem"],
    ["OperatorLogoutStorageFailure", "OperatorLogoutStorageFailureProblem"],
    ["OperatorRateLimited", "AuthRateLimitedProblem"],
  ]) {
    if (document.components.responses[name].content?.["application/problem+json"]?.schema?.$ref !== `#/components/schemas/${problem}`) {
      throw new Error(`${name} problem binding differs from D-124`);
    }
  }
  const failureMembers = ["AuthStorageUnavailableProblem", "OperatorLogoutCommitOutcomeUnknownProblem"];
  if (JSON.stringify(schemas.OperatorLogoutStorageFailureProblem?.oneOf) !==
      JSON.stringify(failureMembers.map((name) => ({ $ref: `#/components/schemas/${name}` })))) {
    throw new Error("Operator logout must distinguish retryable unknown commit from rollback under D-124");
  }
  const rate = document.components.responses.OperatorRateLimited.headers;
  if (rate["Retry-After"]?.required !== true || rate["Retry-After"].schema?.pattern !== "^(?:[1-9]|[1-9][0-9]|[12][0-9]{2}|300)$" ||
      rate["RateLimit-Policy"]?.required !== true || rate["RateLimit-Policy"].schema?.const !== '\"authentication\";q=30;w=60' ||
      rate.RateLimit?.required !== true || rate.RateLimit.schema?.pattern !== '^\"authentication\";r=0;t=(?:[1-9]|[1-9][0-9]|[12][0-9]{2}|300)$') {
    throw new Error("Operator logout rate headers differ from D-124 authentication profile");
  }
  problemNames.push(...logoutProblems.map(([name]) => name));
  function type(schema) {
    if (schema.$ref) return schema.$ref.split("/").at(-1);
    if (Object.hasOwn(schema, "const")) return JSON.stringify(schema.const);
    if (schema.type === "string") return "string";
    if (schema.type === "integer") return "number";
    if (schema.type === "array") return schema.maxItems === 0 ? "[]" : `Array<${type(schema.items)}>`;
    if (schema.type === "object") return `{ ${Object.entries(schema.properties).map(([name, value]) => `${name}: ${type(value)};`).join(" ")}${schema.additionalProperties ? " [extension: string]: unknown;" : ""} }`;
    throw new Error(`Unsupported Operator schema ${JSON.stringify(schema)}`);
  }
  const lines = [];
  for (const name of Object.keys(shapes)) {
    const schema = schemas[name];
    if (schema.required.length === 0) { lines.push(`export type ${name} = Record<string, never>;`, ""); continue; }
    lines.push(`export interface ${name} {`);
    for (const [field, value] of Object.entries(schema.properties)) {
      if (value.description) lines.push(`  /** ${value.description} */`);
      lines.push(`  ${field}: ${type(value)};`);
    }
    if (schema.additionalProperties) lines.push("  [extension: string]: unknown;");
    lines.push("}", "");
  }
  for (const name of problemNames) {
    lines.push(`export type ${name} = Omit<ProblemDetails, "status" | "code" | "changed" | "retryable"> & ${type(schemas[name].allOf[1])};`, "");
  }
  lines.push(`export type OperatorLogoutStorageFailureProblem = ${failureMembers.join(" | ")};`, "");
  return lines.join("\n");
}
