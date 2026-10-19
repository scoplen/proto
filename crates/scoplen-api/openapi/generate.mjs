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
  AuthTokenResponse: ["access_token", "token_type", "expires_in", "refresh_token", "refresh_expires_in"],
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
const generatedPaths = `// SPDX-License-Identifier: Apache-2.0\n// Generated by openapi/generate.mjs.\nexport const controlPlanePaths = ${JSON.stringify(paths, null, 2)} as const;\n`;
const outputs = [[new URL("generated-paths.ts", root), generatedPaths], [typesUrl, allGeneratedTypes]];
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
