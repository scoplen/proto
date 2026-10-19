// SPDX-License-Identifier: Apache-2.0
// The authored v1.yaml is JSON-compatible YAML, so generation needs no
// network-installed toolchain. This script checks the contract and emits the
// deterministic path-name fragment and problem type consumed by @scoplen/api.
import { readFile, writeFile } from "node:fs/promises";

const root = new URL(".", import.meta.url);
const document = JSON.parse(await readFile(new URL("v1.yaml", root), "utf8"));
if (document.openapi !== "3.1.0") throw new Error("expected OpenAPI 3.1.0");
const paths = Object.keys(document.paths ?? {}).sort();
if (paths.length < 30) throw new Error(`control-plane contract has only ${paths.length} paths`);
for (const path of paths) {
  if (!path.startsWith("/")) throw new Error(`invalid path: ${path}`);
  const operations = document.paths[path];
  if (!Object.keys(operations).some((method) => ["get", "post", "patch", "delete"].includes(method))) {
    throw new Error(`path has no HTTP operation: ${path}`);
  }
}
const requiredProblemFields = ["type", "title", "status", "detail", "instance", "code", "changed", "retryable"];
const problem = document.components?.schemas?.ProblemDetails;
if (problem?.type !== "object" || problem.additionalProperties !== true) {
  throw new Error("ProblemDetails must allow response extensions");
}
if (!Array.isArray(problem.required) ||
    JSON.stringify([...problem.required].sort()) !== JSON.stringify([...requiredProblemFields].sort())) {
  throw new Error("ProblemDetails must require the eight shared error fields");
}
const problemTypes = { type: "string", title: "string", status: "integer", detail: "string", instance: "string", code: "string", changed: "boolean", retryable: "boolean" };
for (const field of ["type", "title", "detail", "instance"]) {
  if (problem.properties?.[field]?.minLength !== 1) {
    throw new Error(`ProblemDetails.${field} must be non-empty`);
  }
}
if (problem.properties.status.minimum !== 100 || problem.properties.status.maximum !== 599 ||
    problem.properties.code.pattern !== "^[a-z0-9_]+\\.[a-z0-9_]+$") {
  throw new Error("ProblemDetails status or code constraints differ from the shared error contract");
}
const problemLines = ["export interface ProblemDetails {"];
for (const field of requiredProblemFields) {
  if (problem.properties?.[field]?.type !== problemTypes[field]) {
    throw new Error(`ProblemDetails.${field} has the wrong type`);
  }
  problemLines.push(`  ${field}: ${problemTypes[field] === "integer" ? "number" : problemTypes[field]};`);
}
problemLines.push("  [extension: string]: unknown;", "}");

const authShapes = {
  AuthChallengeRequest: ["device_id"],
  AuthChallengeResponse: ["nonce", "server_time"],
  AuthDeviceRequest: ["device_id", "nonce", "signature"],
  AuthRefreshRequest: ["refresh_token"],
  BrowserAuthRefreshRequest: [],
  AuthTokenResponse: ["access_token", "token_type", "expires_in", "refresh_token", "refresh_expires_in"],
  BrowserAuthTokenResponse: ["access_token", "token_type", "expires_in", "refresh_expires_in"],
};
const authPatterns = {
  device_id: "^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
  nonce: "^[0-9a-f]{64}$",
  signature: "^[0-9a-f]{128}$",
  server_time: "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-5][0-9](\\.[0-9]+)?Z$",
};
const authLines = [];
for (const [name, fields] of Object.entries(authShapes)) {
  const schema = document.components?.schemas?.[name];
  if (schema?.type !== "object" ||
      schema.additionalProperties !== !name.endsWith("Request") ||
      JSON.stringify(schema.required) !== JSON.stringify(fields) ||
      JSON.stringify(Object.keys(schema.properties ?? {})) !== JSON.stringify(fields)) {
    throw new Error(`${name} differs from the shared authentication shape`);
  }
  if (name === "BrowserAuthRefreshRequest") {
    authLines.push("export type BrowserAuthRefreshRequest = Record<string, never>;", "");
    continue;
  }
  authLines.push(`export interface ${name} {`);
  for (const field of fields) {
    const property = schema.properties[field];
    const expectedType = field.endsWith("_in") ? "integer" : "string";
    if (property.type !== expectedType ||
        (field in authPatterns && property.pattern !== authPatterns[field]) ||
        (["device_id", "server_time"].includes(field) &&
          property.format !== (field === "device_id" ? "uuid" : "date-time")) ||
        (field === "token_type" && property.const !== "DPoP") ||
        (["access_token", "refresh_token"].includes(field) && property.minLength !== 1) ||
        (expectedType === "integer" && property.minimum !== 1)) {
      throw new Error(`${name}.${field} differs from the shared authentication contract`);
    }
    authLines.push(`  ${field}: ${field === "token_type" ? '"DPoP"' : expectedType === "integer" ? "number" : "string"};`);
  }
  if (name === "AuthRefreshRequest" &&
      !schema.properties.refresh_token.description?.includes("2048 UTF-8 bytes")) {
    throw new Error("AuthRefreshRequest must document its UTF-8 credential limit");
  }
  if (name === "BrowserAuthTokenResponse") {
    if (JSON.stringify(schema.not) !== JSON.stringify({ required: ["refresh_token"] })) {
      throw new Error("BrowserAuthTokenResponse must reject native refresh_token presence");
    }
    authLines.push("  refresh_token?: never;");
  }
  if (schema.additionalProperties) authLines.push("  [extension: string]: unknown;");
  authLines.push("}", "");
}
for (const [path, requestName, responseName, maxBytes] of [
  ["/auth/challenge", "AuthChallengeRequest", "AuthChallengeResponse", 256],
  ["/auth/device", "AuthDeviceRequest", "AuthTokenResponse", 4096],
]) {
  const operation = document.paths?.[path]?.post;
  const request = operation?.requestBody;
  if (JSON.stringify(operation?.security) !== "[]" || request?.required !== true ||
      !request.description?.includes(`${maxBytes} bytes`) ||
      request.content?.["application/json"]?.schema?.$ref !== `#/components/schemas/${requestName}` ||
      operation.responses?.["200"]?.content?.["application/json"]?.schema?.$ref !== `#/components/schemas/${responseName}` ||
      !["400", "413", "default"].every((status) => operation.responses?.[status]?.$ref === "#/components/responses/Problem")) {
    throw new Error(`${path} differs from the shared authentication endpoint`);
  }
}
if (document.paths["/auth/device"].post.responses?.["401"]?.$ref !== "#/components/responses/Problem") {
  throw new Error("/auth/device must describe authentication failure");
}
const refresh = document.paths?.["/auth/refresh"]?.post;
const refreshRequest = refresh?.requestBody;
const refs = (schema) => schema?.oneOf?.map((member) => member.$ref);
if (JSON.stringify(refresh?.security) !== JSON.stringify([{ dpopProof: [] }]) ||
    refreshRequest?.required !== true ||
    !refreshRequest.description?.includes("4096 bytes") ||
    !refreshRequest.description?.includes("2048 UTF-8 bytes") ||
    JSON.stringify(refs(refreshRequest.content?.["application/json"]?.schema)) !==
      JSON.stringify(["#/components/schemas/AuthRefreshRequest", "#/components/schemas/BrowserAuthRefreshRequest"]) ||
    JSON.stringify(refs(refresh.responses?.["200"]?.content?.["application/json"]?.schema)) !==
      JSON.stringify(["#/components/schemas/AuthTokenResponse", "#/components/schemas/BrowserAuthTokenResponse"]) ||
    !refresh.responses?.["200"]?.headers?.["Set-Cookie"] ||
    refresh.responses?.["400"]?.content?.["application/problem+json"]?.schema?.$ref !==
      "#/components/schemas/ProblemDetails" ||
    !refresh.responses?.["400"]?.headers?.["DPoP-Nonce"] ||
    !["401", "403", "413", "415", "default"].every((status) =>
      refresh.responses?.[status]?.$ref === "#/components/responses/Problem")) {
  throw new Error("/auth/refresh differs from the shared refresh contract");
}

const typesUrl = new URL("types.ts", root);
const existingTypes = (await readFile(typesUrl, "utf8")).replaceAll("\r\n", "\n");
const start = "// BEGIN GENERATED ProblemDetails\n";
const end = "// END GENERATED ProblemDetails";
const startIndex = existingTypes.indexOf(start);
const endIndex = existingTypes.indexOf(end, startIndex + start.length);
if (startIndex < 0 || endIndex < 0) throw new Error("types.ts is missing its generated problem section");
const generatedTypes = `${existingTypes.slice(0, startIndex + start.length)}${problemLines.join("\n")}\n${existingTypes.slice(endIndex)}`;
const authStart = "// BEGIN GENERATED Authentication\n";
const authEnd = "// END GENERATED Authentication";
const authStartIndex = generatedTypes.indexOf(authStart);
const authEndIndex = generatedTypes.indexOf(authEnd, authStartIndex + authStart.length);
if (authStartIndex < 0 || authEndIndex < 0) throw new Error("types.ts is missing its generated authentication section");
const allGeneratedTypes = `${generatedTypes.slice(0, authStartIndex + authStart.length)}${authLines.join("\n")}${generatedTypes.slice(authEndIndex)}`;
const gatewayShapes = {
  GatewayTicketRequest: { fields: ["host", "remote_user", "ssh_public_key"], extensions: false },
  GatewayEdgeAddress: { fields: ["host", "port"], extensions: true },
  GatewayTicketResponse: { fields: ["ticket", "edge_addresses", "gateway_host_ca_public_key"], extensions: true },
};
const gatewayTypes = {
  host: "string",
  remote_user: "string",
  ssh_public_key: "string",
  port: "number",
  ticket: "string",
  edge_addresses: "GatewayEdgeAddress[]",
  gateway_host_ca_public_key: "string",
};
const gatewayLines = [];
for (const [name, { fields, extensions }] of Object.entries(gatewayShapes)) {
  const schema = document.components?.schemas?.[name];
  if (schema?.type !== "object" || schema.additionalProperties !== extensions ||
      JSON.stringify(schema.required) !== JSON.stringify(fields) ||
      JSON.stringify(Object.keys(schema.properties ?? {})) !== JSON.stringify(fields)) {
    throw new Error(`${name} differs from the gateway-ticket contract`);
  }
  gatewayLines.push(`export interface ${name} {`);
  for (const field of fields) {
    const property = schema.properties[field];
    const expected = gatewayTypes[field];
    if ((expected === "GatewayEdgeAddress[]" &&
         (property.type !== "array" || property.items?.$ref !== "#/components/schemas/GatewayEdgeAddress")) ||
        (expected !== "GatewayEdgeAddress[]" && property.type !== (expected === "number" ? "integer" : "string"))) {
      throw new Error(`${name}.${field} differs from the gateway-ticket contract`);
    }
    gatewayLines.push(`  ${field}: ${expected};`);
  }
  if (extensions) gatewayLines.push("  [extension: string]: unknown;");
  gatewayLines.push("}", "");
}
const gatewayRequest = document.components.schemas.GatewayTicketRequest.properties;
const gatewayResponse = document.components.schemas.GatewayTicketResponse.properties;
const gatewayEdge = document.components.schemas.GatewayEdgeAddress.properties;
if (gatewayRequest.host.pattern !== authPatterns.device_id ||
    gatewayRequest.remote_user.minLength !== 1 ||
    !gatewayRequest.remote_user.description?.includes("255 UTF-8 bytes") ||
    gatewayRequest.ssh_public_key.maxLength !== 8192 ||
    gatewayResponse.ticket.maxLength !== 4096 ||
    gatewayResponse.edge_addresses.minItems !== 1 ||
    gatewayResponse.edge_addresses.maxItems !== 16 ||
    gatewayResponse.gateway_host_ca_public_key.maxLength !== 8192 ||
    gatewayEdge.host.maxLength !== 253 ||
    gatewayEdge.port.minimum !== 1 || gatewayEdge.port.maximum !== 65535) {
  throw new Error("gateway-ticket field bounds differ from D-84");
}
const gatewayPath = document.paths?.["/orgs/{org}/gateway-tickets"];
const gatewayPost = gatewayPath?.post;
if (!gatewayPath || JSON.stringify(Object.keys(gatewayPath)) !== JSON.stringify(["post"]) ||
    document.paths["/orgs/{org}/gateway-tickets/{id}"] ||
    gatewayPost.operationId !== "issueGatewayTicket" ||
    JSON.stringify(gatewayPost.parameters) !== JSON.stringify([{ $ref: "#/components/parameters/org" }]) ||
    !gatewayPost.description?.includes("Idempotency-Key is forbidden") ||
    gatewayPost.requestBody?.required !== true ||
    !gatewayPost.requestBody.description?.includes("16384 bytes") ||
    gatewayPost.requestBody.content?.["application/json"]?.schema?.$ref !== "#/components/schemas/GatewayTicketRequest" ||
    gatewayPost.responses?.["200"]?.content?.["application/json"]?.schema?.$ref !== "#/components/schemas/GatewayTicketResponse" ||
    !gatewayPost.responses["200"].description?.includes("32768 bytes") ||
    gatewayPost.responses["200"].headers?.["Cache-Control"]?.schema?.const !== "no-store" ||
    gatewayPost.responses["200"].headers?.Pragma?.schema?.const !== "no-cache" ||
    !["400", "413", "default"].every((status) => gatewayPost.responses?.[status]?.$ref === "#/components/responses/Problem")) {
  throw new Error("gateway-ticket endpoint differs from D-84");
}
const gatewayStart = "// BEGIN GENERATED GatewayTicket\n";
const gatewayEnd = "// END GENERATED GatewayTicket";
const gatewayStartIndex = allGeneratedTypes.indexOf(gatewayStart);
const gatewayEndIndex = allGeneratedTypes.indexOf(gatewayEnd, gatewayStartIndex + gatewayStart.length);
if (gatewayStartIndex < 0 || gatewayEndIndex < 0) throw new Error("types.ts is missing its generated gateway-ticket section");
const gatewayGeneratedTypes = `${allGeneratedTypes.slice(0, gatewayStartIndex + gatewayStart.length)}${gatewayLines.join("\n")}${allGeneratedTypes.slice(gatewayEndIndex)}`;
const certificatePost = document.paths?.["/orgs/{org}/certificates"]?.post;
const certificate = document.components.schemas.CertificateRequest;
const certificateVariants = ["CertificateHostRequest", "CertificateHostGroupRequest"];
if (certificatePost?.operationId !== "createCertificates" ||
    JSON.stringify(certificatePost.parameters) !== JSON.stringify([
      { $ref: "#/components/parameters/org" },
      { $ref: "#/components/parameters/idempotency" },
    ]) ||
    certificatePost.requestBody?.required !== true ||
    !certificatePost.requestBody.description?.includes("16384 bytes") ||
    certificatePost.requestBody.content?.["application/json"]?.schema?.$ref !== "#/components/schemas/CertificateRequest" ||
    !certificatePost.responses?.["201"]?.description?.includes("131072 bytes") ||
    certificatePost.responses?.["201"]?.content?.["application/json"]?.schema?.$ref !==
      "#/components/schemas/CertificateIssuanceResponse" ||
    certificatePost.responses?.["201"]?.headers?.ETag?.required !== true ||
    !certificatePost.responses?.["201"]?.headers?.ETag?.description?.includes("exactly equal") ||
    certificatePost.responses?.["201"]?.headers?.["Cache-Control"]?.schema?.const !== "no-store" ||
    certificatePost.responses?.["201"]?.headers?.Pragma?.schema?.const !== "no-cache" ||
    !["400", "413", "default"].every((status) => certificatePost.responses?.[status]?.$ref === "#/components/responses/Problem") ||
    JSON.stringify(refs(certificate)) !== JSON.stringify(certificateVariants.map((name) => `#/components/schemas/${name}`))) {
  throw new Error("certificate issuance endpoint differs from D-88");
}
const certificateLines = [];
for (const [name, selector] of [[certificateVariants[0], "hosts"], [certificateVariants[1], "host_groups"]]) {
  const schema = document.components.schemas[name];
  const fields = ["public_key", selector, "remote_user", "ttl_seconds"];
  const properties = schema?.properties;
  if (schema?.type !== "object" || schema.additionalProperties !== false ||
      JSON.stringify(schema.required) !== JSON.stringify(fields) ||
      JSON.stringify(Object.keys(properties ?? {})) !== JSON.stringify(fields) ||
      properties.public_key.type !== "string" || properties.public_key.minLength !== 1 ||
      properties.public_key.maxLength !== 8192 ||
      properties.remote_user.type !== "string" || properties.remote_user.minLength !== 1 ||
      !properties.remote_user.description?.includes("255 UTF-8 bytes") ||
      properties[selector].type !== "array" || properties[selector].minItems !== 1 ||
      properties[selector].maxItems !== 64 || properties[selector].uniqueItems !== true ||
      properties[selector].items?.pattern !== authPatterns.device_id ||
      properties.ttl_seconds.type !== "integer" || properties.ttl_seconds.minimum !== 1 ||
      properties.ttl_seconds.maximum !== 86400) {
    throw new Error(`${name} differs from the bounded certificate request`);
  }
  const otherSelector = selector === "hosts" ? "host_groups" : "hosts";
  certificateLines.push(
    `export interface ${name} {`,
    "  public_key: string;",
    `  ${selector}: string[];`,
    `  ${otherSelector}?: never;`,
    "  remote_user: string;",
    "  ttl_seconds: number;",
    "}",
    "",
  );
}
certificateLines.push("export type CertificateRequest = CertificateHostRequest | CertificateHostGroupRequest;", "");
const certificateStart = "// BEGIN GENERATED CertificateRequest\n";
const certificateEnd = "// END GENERATED CertificateRequest";
const certificateStartIndex = gatewayGeneratedTypes.indexOf(certificateStart);
const certificateEndIndex = gatewayGeneratedTypes.indexOf(certificateEnd, certificateStartIndex + certificateStart.length);
if (certificateStartIndex < 0 || certificateEndIndex < 0) throw new Error("types.ts is missing its generated certificate-request section");
const requestGeneratedTypes = `${gatewayGeneratedTypes.slice(0, certificateStartIndex + certificateStart.length)}${certificateLines.join("\n")}${gatewayGeneratedTypes.slice(certificateEndIndex)}`;
const responseSchema = document.components.schemas.CertificateIssuanceResponse;
const responseFields = ["id", "etag", "created_at", "updated_at", "data"];
const responseProperties = responseSchema?.properties;
const responseData = responseProperties?.data;
if (responseSchema?.type !== "object" || responseSchema.additionalProperties !== true ||
    JSON.stringify(responseSchema.required) !== JSON.stringify(responseFields) ||
    JSON.stringify(Object.keys(responseProperties ?? {})) !== JSON.stringify(responseFields) ||
    responseProperties.id.pattern !== authPatterns.device_id ||
    responseProperties.etag.pattern !== '^"[!#-~]*"$' ||
    responseProperties.etag.minLength !== 2 || responseProperties.etag.maxLength !== 256 ||
    !["created_at", "updated_at"].every((field) =>
      responseProperties[field]?.type === "string" &&
      responseProperties[field]?.format === "date-time" &&
      responseProperties[field]?.pattern === authPatterns.server_time) ||
    responseData?.type !== "object" || responseData.additionalProperties !== true ||
    JSON.stringify(responseData.required) !== JSON.stringify(["certificate"]) ||
    JSON.stringify(Object.keys(responseData.properties ?? {})) !== JSON.stringify(["certificate"]) ||
    responseData.properties.certificate.type !== "string" ||
    responseData.properties.certificate.maxLength !== 90112 ||
    !responseData.properties.certificate.description?.includes("65536 bytes")) {
  throw new Error("certificate issuance response differs from D-90");
}
const responseLines = [
  "export interface CertificateIssuanceResponse {",
  "  id: string;",
  "  etag: string;",
  "  created_at: string;",
  "  updated_at: string;",
  "  data: CertificateIssuanceData;",
  "  [extension: string]: unknown;",
  "}",
  "",
  "export interface CertificateIssuanceData {",
  "  certificate: string;",
  "  [extension: string]: unknown;",
  "}",
];
const responseStart = "// BEGIN GENERATED CertificateIssuanceResponse\n";
const responseEnd = "// END GENERATED CertificateIssuanceResponse";
const responseStartIndex = requestGeneratedTypes.indexOf(responseStart);
const responseEndIndex = requestGeneratedTypes.indexOf(responseEnd, responseStartIndex + responseStart.length);
if (responseStartIndex < 0 || responseEndIndex < 0) throw new Error("types.ts is missing its generated certificate-response section");
const finalGeneratedTypes = `${requestGeneratedTypes.slice(0, responseStartIndex + responseStart.length)}${responseLines.join("\n")}\n${requestGeneratedTypes.slice(responseEndIndex)}`;
const accountGet = document.paths?.["/accounts/me"]?.get;
const accountSchema = document.components?.schemas?.AccountProfile;
const accountProperties = accountSchema?.properties;
const accountData = accountProperties?.data;
const accountFields = ["id", "etag", "created_at", "updated_at", "data"];
if (accountGet?.operationId !== "getCurrentAccount" || accountGet.requestBody ||
    !accountGet.description?.includes("4096 bytes") ||
    accountGet.responses?.["200"]?.content?.["application/json"]?.schema?.$ref !== "#/components/schemas/AccountProfile" ||
    accountGet.responses["200"].headers?.ETag?.required !== true ||
    !accountGet.responses["200"].headers.ETag.description?.includes("exactly equal") ||
    accountGet.responses["200"].headers.ETag.schema?.pattern !== '^"[!#-~]*"$' ||
    accountGet.responses["200"].headers.ETag.schema?.minLength !== 2 ||
    accountGet.responses["200"].headers.ETag.schema?.maxLength !== 256 ||
    accountGet.responses["200"].headers?.["Cache-Control"]?.required !== true ||
    accountGet.responses["200"].headers?.["Cache-Control"]?.schema?.const !== "no-store" ||
    accountGet.responses["200"].headers?.Pragma?.required !== true ||
    accountGet.responses["200"].headers?.Pragma?.schema?.const !== "no-cache" ||
    accountGet.responses?.default?.$ref !== "#/components/responses/Problem" ||
    accountSchema?.type !== "object" || accountSchema.additionalProperties !== true ||
    JSON.stringify(accountSchema.required) !== JSON.stringify(accountFields) ||
    JSON.stringify(Object.keys(accountProperties ?? {})) !== JSON.stringify(accountFields) ||
    accountProperties.id.pattern !== authPatterns.device_id ||
    accountProperties.etag.pattern !== '^"[!#-~]*"$' ||
    accountProperties.etag.minLength !== 2 || accountProperties.etag.maxLength !== 256 ||
    !["created_at", "updated_at"].every((field) =>
      accountProperties[field]?.type === "string" &&
      accountProperties[field]?.format === "date-time" &&
      accountProperties[field]?.pattern === authPatterns.server_time) ||
    accountData?.type !== "object" || accountData.additionalProperties !== true ||
    JSON.stringify(accountData.required) !== JSON.stringify(["email"]) ||
    JSON.stringify(Object.keys(accountData.properties ?? {})) !== JSON.stringify(["email"]) ||
    JSON.stringify(accountData.properties.email.type) !== JSON.stringify(["string", "null"]) ||
    accountData.properties.email.minLength !== 1 ||
    accountData.properties.email.maxLength !== 320 ||
    !accountData.properties.email.description?.includes("320 UTF-8 bytes")) {
  throw new Error("current-account profile differs from D-99");
}
const accountLines = [
  "export interface AccountProfile {",
  "  id: string;",
  "  etag: string;",
  "  created_at: string;",
  "  updated_at: string;",
  "  data: AccountProfileData;",
  "  [extension: string]: unknown;",
  "}",
  "",
  "export interface AccountProfileData {",
  "  email: string | null;",
  "  [extension: string]: unknown;",
  "}",
];
const accountStart = "// BEGIN GENERATED AccountProfile\n";
const accountEnd = "// END GENERATED AccountProfile";
const accountStartIndex = finalGeneratedTypes.indexOf(accountStart);
const accountEndIndex = finalGeneratedTypes.indexOf(accountEnd, accountStartIndex + accountStart.length);
if (accountStartIndex < 0 || accountEndIndex < 0) throw new Error("types.ts is missing its generated account-profile section");
const completeGeneratedTypes = `${finalGeneratedTypes.slice(0, accountStartIndex + accountStart.length)}${accountLines.join("\n")}\n${finalGeneratedTypes.slice(accountEndIndex)}`;
const personalShapes = {
  PersonalInvitationRequest: [],
  PersonalInvitationResponse: ["invitation_url", "expires_at"],
  PersonalEnrollmentRequest: ["invitation_token", "account_id", "personal_vault_id", "account_signing_public_key", "account_kem_public_key", "key_bundle_update", "device_certificate", "wrapped_personal_vault_key", "device_signature"],
  PersonalEnrollmentResponse: ["account_id", "device_id", "personal_vault_id"],
};
const personalLines = [];
for (const [name, fields] of Object.entries(personalShapes)) {
  const schema = document.components?.schemas?.[name];
  const isRequest = name.endsWith("Request");
  if (schema?.type !== "object" || schema.additionalProperties !== !isRequest ||
      JSON.stringify(schema.required) !== JSON.stringify(fields) ||
      JSON.stringify(Object.keys(schema.properties ?? {})) !== JSON.stringify(fields)) {
    throw new Error(`${name} differs from D-101`);
  }
  if (fields.length === 0) {
    personalLines.push(`export type ${name} = Record<string, never>;`, "");
    continue;
  }
  personalLines.push(`export interface ${name} {`);
  for (const field of fields) {
    const property = schema.properties[field];
    if (property.type !== "string" ||
        (["account_id", "device_id", "personal_vault_id"].includes(field) &&
          (property.format !== "uuid" || property.pattern !== authPatterns.device_id)) ||
        (field === "expires_at" && (property.format !== "date-time" || property.pattern !== authPatterns.server_time)) ||
        (["invitation_token", "account_signing_public_key", "account_kem_public_key"].includes(field) &&
          (property.minLength !== 43 || property.maxLength !== 43 || property.pattern !== "^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$")) ||
        (field === "device_signature" && (property.minLength !== 86 || property.maxLength !== 86 || property.pattern !== "^[A-Za-z0-9_-]{85}[AQgw]$")) ||
        (["device_certificate", "wrapped_personal_vault_key"].includes(field) && property.maxLength !== 87382) ||
        (field === "key_bundle_update" && !property.description?.includes("K-4")) ||
        (field === "invitation_url" && (property.maxLength !== 2105 || !property.description?.includes("bearer credential")))) {
      throw new Error(`${name}.${field} differs from D-101`);
    }
    personalLines.push(`  ${field}: string;`);
  }
  if (!isRequest) personalLines.push("  [extension: string]: unknown;");
  personalLines.push("}", "");
}
for (const [path, operationId, request, response, maxRequest, maxResponse, referrer] of [
  ["/admin/personal-invitations", "issuePersonalInvitation", "PersonalInvitationRequest", "PersonalInvitationResponse", 256, 4096, true],
  ["/auth/personal-enroll", "enrollPersonalDevice", "PersonalEnrollmentRequest", "PersonalEnrollmentResponse", 1048576, 256, false],
]) {
  const operation = document.paths?.[path]?.post;
  const success = operation?.responses?.["201"];
  if (operation?.operationId !== operationId ||
      (path.includes("/auth/") && JSON.stringify(operation.security) !== "[]") ||
      !operation.description?.includes("Idempotency-Key") ||
      (path.includes("/auth/") && !operation.description?.includes("401 auth.enrollment_denied")) ||
      operation.requestBody?.required !== true ||
      !operation.requestBody.description?.includes(`${maxRequest} bytes`) ||
      operation.requestBody.content?.["application/json"]?.schema?.$ref !== `#/components/schemas/${request}` ||
      !success?.description?.includes(`${maxResponse} bytes`) ||
      success.content?.["application/json"]?.schema?.$ref !== `#/components/schemas/${response}` ||
      success.headers?.["Cache-Control"]?.schema?.const !== "no-store" ||
      success.headers?.Pragma?.schema?.const !== "no-cache" ||
      (referrer && success.headers?.["Referrer-Policy"]?.schema?.const !== "no-referrer") ||
      !["400", "401", "403", "413", "415", "503", "default"].every((status) =>
        operation.responses?.[status]?.$ref === "#/components/responses/Problem")) {
    throw new Error(`${path} differs from D-101`);
  }
}
const personalStart = "// BEGIN GENERATED PersonalEnrollment\n";
const personalEnd = "// END GENERATED PersonalEnrollment";
const personalStartIndex = completeGeneratedTypes.indexOf(personalStart);
const personalEndIndex = completeGeneratedTypes.indexOf(personalEnd, personalStartIndex + personalStart.length);
if (personalStartIndex < 0 || personalEndIndex < 0) throw new Error("types.ts is missing its generated Personal enrollment section");
const completePersonalTypes = `${completeGeneratedTypes.slice(0, personalStartIndex + personalStart.length)}${personalLines.join("\n")}${completeGeneratedTypes.slice(personalEndIndex)}`;
const generatedPaths = `// SPDX-License-Identifier: Apache-2.0\n// Generated by openapi/generate.mjs.\nexport const controlPlanePaths = ${JSON.stringify(paths, null, 2)} as const;\n`;
const outputs = [[new URL("generated-paths.ts", root), generatedPaths], [typesUrl, completePersonalTypes]];
if (process.argv.includes("--check")) {
  for (const [url, expected] of outputs) {
    const actual = (await readFile(url, "utf8")).replaceAll("\r\n", "\n");
    if (actual !== expected) throw new Error(`${url.pathname} is stale; run the OpenAPI generator`);
  }
} else {
  for (const [url, generated] of outputs) {
    const existing = (await readFile(url, "utf8")).replaceAll("\r\n", "\n");
    if (existing !== generated) await writeFile(url, generated);
  }
}
console.log(`validated OpenAPI 3.1 contract with ${paths.length} paths`);
