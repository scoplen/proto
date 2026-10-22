// SPDX-License-Identifier: Apache-2.0
// D-111 finite Operator contract checks and TypeScript projection.
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
  };
  const bounds = { setup_token: [32, 32], credential_id: [1, 1023], client_data_json: [1, 4096], attestation_object: [1, 16384], authenticator_data: [37, 4096], signature: [8, 72], user_handle: [16, 16], challenge: [32, 32] };
  for (const [name, fields] of Object.entries(shapes)) {
    const schema = schemas[name];
    if (schema?.type !== "object" || schema.additionalProperties !== !name.endsWith("Request") ||
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
      document.paths["/admin/personal-invitations"].post["x-scoplen-required-operator-scope"] !== "personal-invitation:issue") throw new Error("Operator key source or scope differs from D-111");
  const problemNames = ["OperatorInvalidRequestProblem", "OperatorInvalidDpopProblem", "OperatorOriginDeniedProblem", "OperatorBodyTooLargeProblem", "OperatorContentTypeProblem"];
  for (const [name, status, code] of [[problemNames[0], 400, "auth.invalid_request"], [problemNames[1], 400, "auth.invalid_dpop_proof"], [problemNames[2], 403, "policy.denied"], [problemNames[3], 413, "auth.invalid_request"], [problemNames[4], 415, "auth.invalid_request"]]) {
    const constraint = schemas[name]?.allOf?.[1]?.properties;
    if (constraint?.status?.const !== status || constraint?.code?.const !== code || constraint?.changed?.const !== false || constraint?.retryable?.const !== false) throw new Error(`${name} error profile differs from D-111`);
  }
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
  return lines.join("\n");
}
